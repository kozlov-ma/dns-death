use crate::dns_types::{Header, Packet, Query, Record, RecordData, RecordType};
use anyhow::{ensure, Result};

#[derive(Clone, Debug)]
struct DnsSerializer {
    packet: [u8; 512],
    pos: usize,
}

impl DnsSerializer {
    pub fn new() -> Self {
        DnsSerializer {
            packet: [0; 512],
            pos: 0,
        }
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        ensure!(
            self.pos < 512,
            "End of packet was reached, tried to write another byte"
        );
        self.packet[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write_u8((val >> 8) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write_u16(((val >> 16) & 0x00FF) as u16)?;
        self.write_u16((val & 0x00FF) as u16)?;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.packet[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_str(&mut self, val: &str) -> Result<()> {
        for b in val.as_bytes() {
            self.write_u8(*b)?;
        }

        Ok(())
    }

    pub fn write_domain_name(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            ensure!(len <= 63, "Label '{label}' of QName '{qname}' was of length {len}, but no more than 63 is allowed.");

            self.write_u8(len as u8)?;
            self.write_str(label)?;
        }

        self.write_u8(0)?;

        Ok(())
    }

    pub fn write_header(&mut self, header: &Header) -> Result<()> {
        self.write_u16(header.id)?;

        self.write_u8(
            (header.recursion_desired as u8)
                | ((header.truncated_message as u8) << 1)
                | ((header.authoritative_answer as u8) << 2)
                | (header.opcode << 3)
                | ((header.is_response as u8) << 7),
        )?;

        self.write_u8(
            (header.rcode as u8)
                | ((header.checking_disabled as u8) << 4)
                | ((header.authed_data as u8) << 5)
                | (header.z << 6)
                | ((header.recursion_available as u8) << 7),
        )?;

        self.write_u16(header.queries)?;
        self.write_u16(header.answers)?;
        self.write_u16(header.authorities)?;
        self.write_u16(header.additional)?;

        Ok(())
    }

    pub fn write_query(&mut self, query: &Query) -> Result<()> {
        ensure!(
            query.record_type != RecordType::Unknown(0),
            "Invalid Query/Record type: '0"
        );

        self.write_domain_name(&query.domain_name)?;

        self.write_u16((&query.record_type).into())?;
        self.write_u16(1)?;

        Ok(())
    }

    pub fn write_record(&mut self, record: &Record) -> Result<usize> {
        if let RecordData::Unknown(..) = record.data {
            println!("Skipped serializing an unknown record: {:?}", record);
            return Ok(0);
        }
        let start_pos = self.pos;

        self.write_domain_name(&record.domain_name)?;
        self.write_u16((&record.data).into())?;
        self.write_u16(1)?;
        self.write_u32(record.ttl)?;

        match record.data {
            RecordData::Address(addr) => {
                self.write_u16(4)?;
                for octet in addr.octets() {
                    self.write_u8(octet)?;
                }
            }
            RecordData::Ipv6Address(ref addr) => {
                self.write_u16(16)?;
                for octet in &addr.segments() {
                    self.write_u16(*octet)?;
                }
            }
            RecordData::NameServer(ref host) => {
                let pos = self.pos;
                self.write_u16(0)?;

                self.write_domain_name(host)?;

                let size = self.pos - (pos + 2);
                self.set_u16(pos, size as u16)?;
            }
            RecordData::CanonicalName(ref cname) => {
                let pos = self.pos;
                self.write_u16(0)?;

                self.write_domain_name(cname)?;

                let size = self.pos - (pos + 2);
                self.set_u16(pos, size as u16)?;
            }
            RecordData::Unknown(_code, ref _bytes) => unreachable!(),
        }

        Ok(self.pos - start_pos)
    }

    pub fn write_packet(&mut self, packet: &Packet) -> Result<()> {
        self.write_header(&packet.actual_header())?;

        for query in packet
            .queries
            .iter()
            .filter(|q| q.record_type != RecordType::Unknown(0))
        {
            self.write_query(query)?;
        }

        let all_records = packet
            .answers
            .iter()
            .chain(packet.authorities.iter())
            .chain(packet.additional.iter());
        for rec in all_records {
            self.write_record(rec)?;
        }

        Ok(())
    }

    #[inline]
    pub fn bytes(&self) -> Vec<u8> {
        self.packet[..self.pos].to_vec()
    }
}

impl Packet {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut serializer = DnsSerializer::new();
        serializer.write_packet(self)?;

        Ok(serializer.bytes())
    }
}
