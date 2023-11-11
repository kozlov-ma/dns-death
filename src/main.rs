use crate::dns_types::{Packet, Query, Record, RecordData, RecordType, ResponseCode};
use anyhow::Result;
use async_recursion::async_recursion;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::task;

use crate::cache_utils::DnsResultExpiry;
use moka::future::Cache;

mod cache_utils;
mod dns_types;
mod parsing;
mod serialization;

const ROOT_DNS_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53);
const CACHE_CAPACITY: u64 = 1_000_000;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cache = Cache::builder()
        .max_capacity(CACHE_CAPACITY)
        .expire_after(DnsResultExpiry)
        .build();

    let socket = Box::leak(Box::new(UdpSocket::bind(("127.0.0.1", 53)).await?));
    println!("Started server");

    let mut set = task::JoinSet::new();

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

        set.spawn(respond(request_bytes, src, socket, cache.clone()));
    }
}

async fn respond(
    request_bytes: [u8; 512],
    src: SocketAddr,
    socket: &UdpSocket,
    cache: Cache<Query, DnsResult>,
) {
    let response = response_from_bytes(&request_bytes, cache).await;
    let response_bytes = match response.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            println!(
                "Couldn't serialize response {:#?}, error: {:#?}",
                response, e
            );
            response.error_bytes(response.header.id, ResponseCode::ServerFailure)
        }
    };

    if let Err(e) = socket.send_to(&response_bytes, src).await {
        println!("Couldn't respond to '{src}', error: {:#?}", e);
    } else {
        println!("Responded to '{src}'");
    }
}

async fn response_from_bytes(request_bytes: &[u8; 512], cache: Cache<Query, DnsResult>) -> Packet {
    let request = match Packet::from_bytes(request_bytes) {
        Err(e) => {
            println!("Couldn't parse request, error: {:#?}", e);
            return Packet::error(
                (request_bytes[0] as u16) << 8 & (request_bytes[1]) as u16,
                ResponseCode::FormatError,
            );
        }
        Ok(request) => request,
    };

    create_response(&request, cache)
        .await
        .unwrap_or(Packet::error(
            request.header.id,
            ResponseCode::ServerFailure,
        ))
}

async fn create_response(request: &Packet, cache: Cache<Query, DnsResult>) -> Result<Packet> {
    if request.queries.len() != 1 {
        return Ok(Packet::error(
            request.header.id,
            ResponseCode::NotImplemented,
        ));
    }

    if !request.header.recursion_desired {
        return Ok(Packet::error(request.header.id, ResponseCode::Refused));
    }

    let query = &request.queries[0];
    match resolve_query(query.clone(), ROOT_DNS_SERVER, cache).await? {
        DnsResult::Answers(answers) => {
            let response = Packet::answers(request.header.id, request.queries.clone(), answers);
            Ok(response)
        }
        DnsResult::NameError => Ok(Packet::error(request.header.id, ResponseCode::NameError)),
        DnsResult::ServerFailure => Ok(Packet::error(
            request.header.id,
            ResponseCode::ServerFailure,
        )),
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum DnsResult {
    Answers(Vec<Record>),
    NameError,
    ServerFailure,
}

#[async_recursion]
async fn resolve_query(
    query: Query,
    server: SocketAddr,
    cache: Cache<Query, DnsResult>,
) -> Result<DnsResult> {
    if let Some(res) = cache.get(&query).await {
        return Ok(res);
    }

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let response = {
        let packet = Packet::query(query.clone());

        socket.connect(server).await?;

        socket.send(&packet.to_bytes()?).await?;
        let mut buf = [0u8; 512];
        socket.recv_from(&mut buf).await?;

        Packet::from_bytes(&buf)?
    };

    if !response.answers.is_empty() && response.header.rcode == ResponseCode::NoError {
        let res = DnsResult::Answers(response.answers);
        cache.insert(query.clone(), res.clone()).await;
        return Ok(res);
    }

    if response.header.rcode == ResponseCode::NameError {
        let res = DnsResult::NameError;
        cache.insert(query.clone(), res.clone()).await;
        return Ok(res);
    }

    for authority in response.resolved_authorities_for(&query.domain_name) {
        if let Ok(res) = resolve_query(
            query.clone(),
            SocketAddr::new(IpAddr::V4(authority), 53),
            cache.clone(),
        )
        .await
        {
            cache.insert(query.clone(), res.clone()).await;
            return Ok(res);
        }
    }

    for unresolved_authority in response.authorities_for(&query.domain_name) {
        let (_, host) = unresolved_authority;
        let authority_query = Query::new(host.to_string(), RecordType::Address);

        if let Ok(DnsResult::Answers(auth_records)) =
            resolve_query(authority_query, ROOT_DNS_SERVER, cache.clone()).await
        {
            let addresses = auth_records.iter().filter_map(|r| match r.data {
                RecordData::Address(addr) => Some(SocketAddr::new(IpAddr::V4(addr), 53)),
                RecordData::Ipv6Address(addr) => Some(SocketAddr::new(IpAddr::V6(addr), 53)),
                _ => None,
            });

            for auth_addr in addresses {
                if let Ok(res) = resolve_query(query.clone(), auth_addr, cache.clone()).await {
                    cache.insert(query.clone(), res.clone()).await;
                    return Ok(res);
                }
            }
        }
    }

    Ok(DnsResult::NameError)
}
