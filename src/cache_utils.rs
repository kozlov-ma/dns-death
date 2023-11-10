use crate::dns_types::{Packet, Query};
use moka::Expiry;
use std::time::{Duration, Instant};

pub(crate) struct ResponseExpiry;

impl Expiry<Query, Packet> for ResponseExpiry {
    fn expire_after_create(
        &self,
        _key: &Query,
        value: &Packet,
        _created_at: Instant,
    ) -> Option<Duration> {
        let secs = value.answers.iter().map(|r| r.ttl).min()?;

        Some(Duration::from_secs(secs as u64))
    }
}
