use crate::dns_types::{Packet, Question};
use moka::Expiry;
use std::time::{Duration, Instant};

pub(crate) struct ResponseExpiry;

impl Expiry<Question, Packet> for ResponseExpiry {
    fn expire_after_create(
        &self,
        _key: &Question,
        value: &Packet,
        _created_at: Instant,
    ) -> Option<Duration> {
        let secs = value.answers.iter().map(|r| r.ttl).min()?;

        Some(Duration::from_secs(secs as u64))
    }
}
