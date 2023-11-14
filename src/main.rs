#![feature(let_chains)]
#![feature(async_closure)]

use crate::dns_types::{Packet, Query, ResponseCode};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::task;

use crate::cache_utils::DnsResultExpiry;
use crate::resolve::DnsResult;
use moka::future::Cache;

mod cache_utils;
mod dns_types;
mod parsing;
mod resolve;
mod serialization;

pub const ROOT_DNS_SERVER: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53);
pub const CACHE_CAPACITY: u64 = 1_000_000;

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

    match create_response(&request, cache).await {
        Ok(r) => r,
        Err(e) => {
            println!("Couldn't create response for request, with error: {:#?}", e);
            Packet::error(request.header.id, ResponseCode::ServerFailure)
        }
    }
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
    let res = resolve::query(query.clone(), cache).await?;

    Ok(request.response_from_dns_result(res))
}
