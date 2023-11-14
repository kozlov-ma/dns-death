use crate::dns_types::Query;
use crate::DnsResult;
use moka::Expiry;
use std::time::{Duration, Instant};

pub(crate) struct DnsResultExpiry;

impl Expiry<Query, DnsResult> for DnsResultExpiry {
    fn expire_after_create(
        &self,
        _key: &Query,
        value: &DnsResult,
        _created_at: Instant,
    ) -> Option<Duration> {
        let secs = match value {
            DnsResult::Answers(records) => records.iter().map(|r| r.ttl).min()?,
            DnsResult::NameError => 60,
        };

        Some(Duration::from_secs(secs as u64))
    }
}
