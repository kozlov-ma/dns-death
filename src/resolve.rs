use crate::dns_types::{Packet, Query, Record, RecordData, RecordType, ResponseCode};
use crate::ROOT_DNS_SERVER;
use anyhow::Result;
use async_recursion::async_recursion;
use moka::future::Cache;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum DnsResult {
    Answers(Vec<Record>),
    NameError,
}

pub async fn query(query: Query, cache: Cache<Query, DnsResult>) -> Result<DnsResult> {
    let res = cached(query.clone(), cache).await?;
    let answers = match res {
        DnsResult::Answers(ans) => ans,
        dns_error => return Ok(dns_error),
    };

    Ok(DnsResult::Answers(answers))
}

async fn cached(query: Query, cache: Cache<Query, DnsResult>) -> Result<DnsResult> {
    if let Some(res) = cache.get(&query).await {
        return Ok(res);
    }

    let res = recursive(&query, ROOT_DNS_SERVER, cache.clone()).await?;
    cache.insert(query, res.clone()).await;

    Ok(res)
}

#[async_recursion]
async fn recursive(
    query: &Query,
    server: SocketAddr,
    cache: Cache<Query, DnsResult>,
) -> Result<DnsResult> {
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
        return Ok(res);
    }

    if response.header.rcode == ResponseCode::NameError {
        let res = DnsResult::NameError;
        return Ok(res);
    }

    from_authorities(query, &response, cache.clone()).await
}

#[async_recursion]
async fn from_authorities(
    query: &Query,
    response: &Packet,
    cache: Cache<Query, DnsResult>,
) -> Result<DnsResult> {
    for authority in response.resolved_authorities_for(&query.domain_name) {
        if let Ok(res) = recursive(&query, authority, cache.clone()).await {
            return Ok(res);
        }
    }

    let mut resolves = JoinSet::new();

    for unresolved_authority in response.authorities_for(&query.domain_name) {
        let host = unresolved_authority;
        let authority_query = Query::new(host.to_string(), RecordType::Address);

        let resolve_task = cached(authority_query, cache.clone());
        resolves.spawn(resolve_task);
    }

    while let Some(res) = resolves.join_next().await {
        if let Ok(DnsResult::Answers(auth_records)) = res? {
            let addresses = auth_records.iter().filter_map(|r| match r.data {
                RecordData::Address(addr) => Some(SocketAddr::new(IpAddr::V4(addr), 53)),
                RecordData::Ipv6Address(addr) => Some(SocketAddr::new(IpAddr::V6(addr), 53)),
                _ => None,
            });

            for auth_addr in addresses {
                if let Ok(res) = recursive(query, auth_addr, cache.clone()).await {
                    return Ok(res);
                }
            }
        }
    }

    Ok(DnsResult::NameError)
}
