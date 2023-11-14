use crate::dns_types::{Header, Packet, Query, Record, RecordData, RecordType, ResponseCode};
use anyhow::{ensure, Result};
use bit_vec::BitVec;
use int_enum::IntEnum;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Copy, Clone, Debug)]
struct DnsParser<'a> {
    pub packet: &'a [u8; 512],
    pos: usize,
}

impl<'a> DnsParser<'a> {
    pub fn new(packet: &'a [u8; 512]) -> DnsParser<'a> {
        DnsParser {
            packet,
            pos: 0usize,
        }
    }

    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn step(&mut self, num_bytes: usize) -> Result<()> {
        self.seek(self.pos + num_bytes)?;

        Ok(())
    }

    #[inline]
    pub fn seek(&mut self, new_pos: usize) -> Result<()> {
        ensure!(
            new_pos < 512usize,
            "Tried to seek to impossible position {new_pos}, should be less than 512."
        );
        self.pos = new_pos;
        Ok(())
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        let val = self.packet[self.pos];
        self.step(1)?;

        Ok(val)
    }

    #[inline]
    pub fn at(&self, idx: usize) -> Result<u8> {
        ensure!(
            idx < 512usize,
            "Wrong index: tried to get byte at {idx}. Should be less than 512."
        );

        Ok(self.packet[idx])
    }

    #[inline]
    pub fn read_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        let end = start + len;
        ensure!(
            end < 512usize,
            "Wrong range: ends at {end}, should be less than 512."
        );

        Ok(&self.packet[start..(start + len)])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let first = self.read_u8()? as u16;
        let second = self.read_u8()? as u16;

        Ok(first << 8 | second)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let first = self.read_u16()? as u32;
        let second = self.read_u16()? as u32;

        Ok(first << 16 | second)
    }

    pub fn read_domain_name(&mut self) -> Result<String> {
        const JUMPS_LIMIT: usize = 30;

        let mut labels = Vec::new();

        let mut local_pos = self.pos();
        let mut jumps = 0;

        loop {
            // avoid the infinite loop in corrupted messages
            ensure!(
                jumps <= JUMPS_LIMIT,
                "Tried to make more than {JUMPS_LIMIT} jumps when reading domain name."
            );

            let len = self.at(local_pos)?;

            // two most significant bits are set => it is a continuation pointer
            if (len & 0xC0) == 0xC0 {
                if jumps == 0 {
                    self.seek(local_pos + 2)?;
                }

                let len2 = self.at(local_pos + 1)? as u16;
                let jump_idx = (((len as u16) ^ 0xC0) << 8) | len2;
                local_pos = jump_idx as usize;

                jumps += 1;

                continue;
            } else {
                local_pos += 1;

                if len == 0 {
                    break;
                }

                let str_buffer = self.read_range(local_pos, len as usize)?;
                labels.push(String::from_utf8_lossy(str_buffer).to_lowercase());

                local_pos += len as usize;
            }
        }

        if jumps == 0 {
            self.seek(local_pos)?;
        }

        if !labels.is_empty() {
            Ok(itertools::free::join(labels, "."))
        } else {
            Ok(String::from("."))
        }
    }

    pub fn read_query(&mut self) -> Result<Query> {
        let name = self.read_domain_name()?;
        let type_code = self.read_u16()?;
        let record_type = RecordType::from_int(type_code);
        let _cls = self.read_u16()?;

        Ok(Query::new(name, record_type))
    }

    pub fn read_header(&mut self) -> Result<Header> {
        let mut header = Header::empty();

        header.id = self.read_u16()?;
        let first = self.read_u8()?;
        let second = self.read_u8()?;

        let flags = BitVec::from_bytes(&[first, second]);

        header.is_response = flags[0];
        header.opcode = (first >> 3) & 0x0F;

        header.authoritative_answer = flags[5];
        header.truncated_message = flags[6];
        header.recursion_desired = flags[7];
        header.recursion_available = flags[8];
        header.z = second << 4 & 0b0111;
        header.rcode = ResponseCode::from_int(second & 0x0F)?;

        header.queries = self.read_u16()?;
        header.answers = self.read_u16()?;
        header.authorities = self.read_u16()?;
        header.additional = self.read_u16()?;

        Ok(header)
    }

    pub fn read_record(&mut self) -> Result<Record> {
        let domain = self.read_domain_name()?;

        let type_code = self.read_u16()?;
        let record_type = RecordType::from_int(type_code);
        let _class = self.read_u16()?;
        let ttl = self.read_u32()?;
        let data_len = self.read_u16()?;

        let data = match record_type {
            RecordType::Address => {
                let raw_addr = self.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                RecordData::Address(addr)
            }
            RecordType::Ipv6Address => {
                let raw_addr1 = self.read_u32()?;
                let raw_addr2 = self.read_u32()?;
                let raw_addr3 = self.read_u32()?;
                let raw_addr4 = self.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                RecordData::Ipv6Address(addr)
            }
            RecordType::NameServer => {
                let ns = self.read_domain_name()?;

                RecordData::NameServer(ns)
            }
            RecordType::CanonicalName => {
                let cname = self.read_domain_name()?;

                RecordData::CanonicalName(cname)
            }
            RecordType::Unknown(code) => {
                // let mut bytes = Vec::with_capacity(data_len as usize);
                // for _ in 0..data_len {
                //     bytes.push(self.read_u8()?);
                // }
                //
                RecordData::Unknown(code)
            }
        };

        Ok(Record::new(domain, data, ttl))
    }

    pub fn read_packet(&mut self) -> Result<Packet> {
        let mut result = Packet::empty();
        result.header = self.read_header()?;

        for _ in 0..result.header.queries {
            result.queries.push(self.read_query()?);
        }

        for _ in 0..result.header.answers {
            let record = match self.read_record() {
                Ok(r) => r,
                Err(e) => {
                    println!("Failed to read record, error: {:#?}", e);
                    return Ok(result);
                }
            };

            result.answers.push(record);
        }
        for _ in 0..result.header.authorities {
            let record = match self.read_record() {
                Ok(r) => r,
                Err(e) => {
                    println!("Failed to read record, error: {:#?}", e);
                    return Ok(result);
                }
            };

            result.authorities.push(record);
        }
        for _ in 0..result.header.additional {
            let record = match self.read_record() {
                Ok(r) => r,
                Err(e) => {
                    println!("Failed to read record, error: {:#?}", e);
                    return Ok(result);
                }
            };

            result.additional.push(record);
        }

        Ok(result)
    }
}

impl Packet {
    pub fn from_bytes(from: &[u8; 512]) -> Result<Self> {
        let mut parser = DnsParser::new(from);
        parser.read_packet()
    }
}
