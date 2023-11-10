use crate::dns_types::{Packet, Query, RecordType, ResponseCode};
use anyhow::Result;
use async_recursion::async_recursion;
use rand::Rng;

use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::task;

use crate::cache_utils::ResponseExpiry;
use moka::future::Cache;

mod cache_utils;
mod dns_types;
mod parsing;
mod serialization;

const DEFAULT_DNS_SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(198, 41, 0, 4), 53);
const CACHE_CAPACITY: u64 = 1_000_000;

#[tokio::main]
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

                local.spawn_local(handle_request(request_bytes, src, socket, cache.clone()));
            }
        })
        .await;

    Ok(())
}

async fn handle_request(
    request_bytes: [u8; 512],
    src: SocketAddr,
    socket: &UdpSocket,
    cache: Cache<Query, Packet>,
) {
    let response = resolve_request(&request_bytes, cache).await;
    dbg!(&response);

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

    if let Err(e) = socket.send_to(&response_bytes, src).await {
        println!("Couldn't respond to '{src}', error: {:#?}", e);
    } else {
        println!("Responded to '{src}'");
    }
}

async fn resolve_request(request_bytes: &[u8; 512], cache: Cache<Query, Packet>) -> Packet {
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

    if request.queries.len() != 1 {
        println!(
            "Got a request with multiple queries, not implemented: {:#?}",
            request
        );
        response.header.rcode = ResponseCode::NotImplemented;
        return response;
    }

    let query = &request.queries[0];
    if let Some(mut recorded_response) = cache.get(query).await {
        recorded_response.header.id = request.header.id;
        return recorded_response;
    }

    let response = match resolve(query, DEFAULT_DNS_SERVER).await {
        Ok(mut resolved) => {
            resolved.header.id = request.header.id;
            println!("Resolved query {:#?}", query);

            resolved
        }
        Err(e) => {
            println!("Failed to resolve request. Error: {:#?}", e);
            response.header.rcode = ResponseCode::ServerFailure;

            response
        }
    };

    cache.insert(query.to_owned(), response.clone()).await;

    response
}

#[async_recursion(? Send)]
pub async fn resolve(query: &Query, start_server: (Ipv4Addr, u16)) -> Result<Packet> {
    let mut server = start_server;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut rng = rand::thread_rng();

    loop {
        let response = {
            let mut packet = Packet::empty();
            packet.header.id = rng.gen();
            packet.queries.push(query.clone());

            socket.connect(server).await?;
            socket.send(&packet.to_bytes()?).await?;
            let mut buf = [0u8; 512];
            socket.recv_from(&mut buf).await?;

            Packet::from_bytes(&buf)?
        };

        if !response.answers.is_empty() && response.header.rcode == ResponseCode::NoError {
            return Ok(response);
        }

        if response.header.rcode == ResponseCode::NameError {
            return Ok(response);
        }

        if let Some(new_ns) = response.resolved_authorities_for(&query.name).next() {
            server = (new_ns.to_owned(), 53);
            continue;
        }

        let first_authority = {
            let mut authorities = response.authorities_for(&query.name);

            authorities.next()
        };

        let new_ns_name = match first_authority {
            Some((_name, host)) => host.to_string(),
            None => return Ok(response),
        };

        let response_for_ns = resolve(
            &Query::new(new_ns_name, RecordType::Address),
            DEFAULT_DNS_SERVER,
        )
        .await?;

        server = match response_for_ns.first_answer() {
            Some(addr) => (addr, 53),
            None => return Ok(response),
        };
    }
}
