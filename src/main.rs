use crate::dns_types::{Packet, Question, RecordType, ResponseCode};
use anyhow::{Result};
use async_recursion::async_recursion;
use rand::Rng;

use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::task;
use tokio::task::JoinSet;

use crate::cache_utils::ResponseExpiry;
use moka::future::Cache;

mod cache_utils;
mod dns_types;
mod parsing;
mod serialization;

const DEFAULT_DNS_SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(198, 41, 0, 4), 53);
const CACHE_CAPACITY: u64 = 1_000_000;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cache = Cache::builder()
        .max_capacity(CACHE_CAPACITY)
        .expire_after(ResponseExpiry)
        .build();

    let socket = Box::leak(Box::new(UdpSocket::bind(("127.0.0.1", 53)).await?));
    println!("Started server");

    let local = task::LocalSet::new();

    local
        .run_until(async {
            let mut set = JoinSet::new();

            loop {
                let mut request_bytes = [0; 512];
                let src = match socket.recv_from(&mut request_bytes).await {
                    Ok((_size, src)) => {
                        println!("Received query from '{src}'");
                        src
                    }
                    Err(e) => {
                        println!("Failed to receive request from socket, error: {:#?}", e);
                        continue;
                    }
                };

                set.spawn_local(handle_request(request_bytes, src, socket, cache.clone()));

                if let Some(Ok(res)) = set.join_next().await {
                    match res {
                        Ok(()) => println!("Query for '{src}' fulfilled."),
                        Err(e) => println!("Couldn't fulfill query, error: {:#?}", e),
                    }
                }
            }
        })
        .await;

    Ok(())
}

async fn handle_request(
    request_bytes: [u8; 512],
    src: SocketAddr,
    socket: &UdpSocket,
    cache: Cache<Question, Packet>,
) -> Result<()> {
    let response = resolve_request(&request_bytes, cache).await;

    let response_bytes = match response.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            println!(
                "Failed to serialize response {:#?} with error: {:#?}",
                response, e
            );

            response.servfail_bytes()
        }
    };

    socket.send_to(&response_bytes, src).await?;
    println!("Responded to '{src}'");

    Ok(())
}

async fn resolve_request(request_bytes: &[u8; 512], cache: Cache<Question, Packet>) -> Packet {
    let mut response = Packet::empty();
    response.header.is_response = true;
    response.header.recursion_desired = true;
    response.header.recursion_available = true;

    let request = match Packet::from_bytes(request_bytes) {
        Ok(packet) => packet,
        Err(e) => {
            let mut rng = rand::thread_rng();
            response.header.id = rng.gen();
            println!("Couldn't deserialize request. Error: {:#?}", e);
            response.header.rcode = ResponseCode::FormatError;
            return response;
        }
    };

    response.header.id = request.header.id;

    if !request.header.recursion_desired {
        response.header.rcode = ResponseCode::Refused;
        return response;
    }

    if request.questions.len() != 1 {
        println!(
            "Got a request with multiple questions, not implemented: {:#?}",
            request
        );
        response.header.rcode = ResponseCode::NotImplemented;
        return response;
    }

    let question = &request.questions[0];
    if let Some(mut recorded_response) = cache.get(question).await {
        recorded_response.header.id = request.header.id;
        return recorded_response;
    }

    let mut response = match resolve(question, DEFAULT_DNS_SERVER).await {
        Ok(mut resolved) => {
            resolved.header.id = request.header.id;
            println!("Resolved question {:#?}", question);

            resolved
        }
        Err(e) => {
            println!("Failed to resolve request. Error: {:#?}", e);
            response.header.rcode = ResponseCode::ServerFailure;

            response
        }
    };

    cache.insert(question.to_owned(), response.clone()).await;

    response
}

#[async_recursion(? Send)]
pub async fn resolve(question: &Question, start_server: (Ipv4Addr, u16)) -> Result<Packet> {
    let mut server = start_server;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut rng = rand::thread_rng();

    loop {
        let response = {
            let mut packet = Packet::empty();
            packet.header.id = rng.gen();
            packet.questions.push(question.clone());

            socket.connect(server).await?;
            socket.send(&packet.to_bytes()?).await?;
            let mut buf = [0u8; 512];
            socket.recv_from(&mut buf).await?;

            Packet::from_bytes(&buf)?
        };

        if !response.answers.is_empty() && response.header.rcode == ResponseCode::NoError {
            return Ok(response);
        }

        if !response.authorities.is_empty() && response.header.rcode == ResponseCode::NoError && question.name == "." && question.record_type == RecordType::Address {
            return Ok(response);
        }

        if response.header.rcode == ResponseCode::NameError {
            return Ok(response);
        }

        if let Some(new_ns) = response.first_resolved_authority_for(&question.name).next() {
            server = (new_ns.to_owned(), 53);
            continue;
        }

        let first_authority = {
            let mut authorities = response.authorities_for(&question.name);
            authorities.next()
        };

        let new_ns_name = match first_authority {
            Some((name, _host)) => name.to_string(),
            None => return Ok(response),
        };

        let response_for_ns = resolve(
            &Question::new(new_ns_name, RecordType::Address),
            DEFAULT_DNS_SERVER,
        )
            .await?;

        server = match response_for_ns.first_ipv4_address() {
            Some(addr) => (addr, 53),
            None => return Ok(response),
        };
    }
}
