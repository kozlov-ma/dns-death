use int_enum::IntEnum;

use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Eq, PartialEq, Debug, Hash, Copy, Clone, IntEnum)]
#[repr(u8)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Header {
    pub id: u16,

    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub is_response: bool,

    pub rcode: ResponseCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: u8,
    pub recursion_available: bool,

    pub queries: u16,
    pub answers: u16,
    pub authorities: u16,
    pub additional: u16,
}

impl Header {
    pub fn empty() -> Header {
        Header {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            is_response: false,

            rcode: ResponseCode::NoError,
            checking_disabled: false,
            authed_data: false,
            z: 0,
            recursion_available: false,

            queries: 0,
            answers: 0,
            authorities: 0,
            additional: 0,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum RecordType {
    Unknown(u16),
    Address = 1,
    NameServer = 2,
    CanonicalName = 5,
    Ipv6Address = 28,
}

impl From<&RecordType> for u16 {
    fn from(value: &RecordType) -> Self {
        match value {
            RecordType::Unknown(code) => *code,
            RecordType::Address => 1,
            RecordType::NameServer => 2,
            RecordType::CanonicalName => 5,
            RecordType::Ipv6Address => 28,
        }
    }
}

impl RecordType {
    pub fn from_int(value: u16) -> RecordType {
        match value {
            1 => RecordType::Address,
            2 => RecordType::NameServer,
            5 => RecordType::CanonicalName,
            28 => RecordType::Ipv6Address,
            v => RecordType::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Query {
    pub domain_name: String,
    pub record_type: RecordType,
}

impl Query {
    pub fn new(name: String, record_type: RecordType) -> Self {
        Self {
            domain_name: name,
            record_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum RecordData {
    Unknown(u16, Vec<u8>) = 0,
    Address(Ipv4Addr) = 1,
    NameServer(String) = 2,
    CanonicalName(String) = 5,
    Ipv6Address(Ipv6Addr) = 28,
}

impl From<&RecordData> for u16 {
    fn from(value: &RecordData) -> Self {
        match value {
            RecordData::Unknown(code, ..) => *code,
            RecordData::Address(..) => 1,
            RecordData::NameServer(..) => 2,
            RecordData::CanonicalName(..) => 5,
            RecordData::Ipv6Address(..) => 28,
        }
    }
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Hash, Ord, Eq)]
pub struct Record {
    pub domain_name: String,
    pub data: RecordData,
    pub ttl: u32,
}

impl Record {
    pub fn new(domain_name: String, data: RecordData, ttl: u32) -> Self {
        Record {
            domain_name,
            data,
            ttl,
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Packet {
    pub header: Header,
    pub queries: Vec<Query>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Packet {
    pub fn empty() -> Self {
        Packet {
            header: Header::empty(),
            queries: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn query(query: Query) -> Self {
        let mut rng = rand::thread_rng();

        let mut packet = Packet::empty();
        packet.queries.push(query);
        packet.header.id = rng.gen();
        packet.header.is_response = false;
        packet.header = packet.actual_header();

        packet
    }

    pub fn response(id: u16) -> Self {
        let mut header = Header::empty();
        header.id = id;
        header.recursion_available = true;
        header.recursion_desired = true;
        header.is_response = true;

        let mut packet = Packet::empty();
        packet.header = header;

        packet
    }

    pub fn answers(id: u16, queries: Vec<Query>, answers: Vec<Record>) -> Self {
        let mut packet = Packet::response(id);
        packet.queries = queries;
        packet.answers = answers;

        packet
    }

    pub fn authorities(
        id: u16,
        queries: Vec<Query>,
        authorities: Vec<Record>,
        additional: Vec<Record>,
    ) -> Self {
        let mut packet = Packet::response(id);
        packet.queries = queries;
        packet.authorities = authorities;
        packet.additional = additional;

        packet
    }

    pub fn error(id: u16, rcode: ResponseCode) -> Self {
        let mut packet = Packet::response(id);
        packet.header.rcode = rcode;

        packet
    }

    pub fn error_bytes(&self, id: u16, rcode: ResponseCode) -> Vec<u8> {
        let packet = Packet::error(id, rcode);

        packet
            .to_bytes()
            .expect("This packet is guaranteed to be serializable.")
    }

    /// Returns a new header with the exact values as current header, but changes qdcount, ancount, nscount and arcount to their actual values
    pub fn actual_header(&self) -> Header {
        let mut header = self.header.clone();
        header.queries = self.queries.len() as u16;
        header.answers = self.answers.len() as u16;
        header.authorities = self.authorities.len() as u16;
        header.additional = self.additional.len() as u16;

        header
    }

    pub fn authorities_for<'a>(
        &'a self,
        domain_name: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|r| match r.data {
                RecordData::NameServer(ref host) => Some((r.domain_name.as_str(), host.as_str())),
                _ => None,
            })
            .filter(|(domain, _host)| domain_name.ends_with(*domain))
            .filter(|(_domain, host)| **host != *domain_name)
    }

    pub fn resolved_authorities_for<'a>(
        &'a self,
        domain_name: &'a str,
    ) -> impl Iterator<Item = Ipv4Addr> + 'a {
        self.authorities_for(domain_name).flat_map(|(_, host)| {
            self.additional.iter().filter_map(move |r| match r.data {
                RecordData::Address(addr) if r.domain_name == host => Some(addr),
                _ => None,
            })
        })
    }

    pub fn first_answer(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|r| match r.data {
                RecordData::Address(addr) => Some(addr),
                _ => None,
            })
            .next()
    }
}
