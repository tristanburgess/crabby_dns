use std::net::Ipv4Addr;

use crate::buffer::{BytePacketBuffer, Deserialize, Result};
use crate::dns::DomainName;

/// Representation of a DNS resource record.
///
/// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1.3. Resource record format
///
/// A resource record has the following fields.
///
///                                    1  1  1  1  1  1
///      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5 (bit)
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                      NAME                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     CLASS                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TTL                      |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                   RDLENGTH                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
///     |                                               |
///     /                     RDATA                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```

#[derive(Debug)]
pub struct ResourceRecord {
    domain_name: DomainName,
    rrtype: RRType,
    rrclass: RRClass,
    ttl: u32,
    rrdata_len: u16,
    rrdata: RRData,
}

impl ResourceRecord {
    pub fn new() -> ResourceRecord {
        ResourceRecord {
            domain_name: DomainName::new(String::new()),
            rrtype: RRType::Unknown(0),
            rrclass: RRClass::Unknown(0),
            ttl: 0,
            rrdata_len: 0,
            rrdata: RRData::Unknown(0),
        }
    }
}

impl Default for ResourceRecord {
    fn default() -> Self {
        ResourceRecord::new()
    }
}

impl Deserialize for ResourceRecord {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn deserialize(buf: &mut Self::Buffer) -> Result<Self::Structure> {
        let mut rr = ResourceRecord::new();
        rr.domain_name = DomainName::deserialize(buf)?;
        rr.rrtype = buf.pop_u16()?.into();
        rr.rrclass = buf.pop_u16()?.into();
        rr.ttl = buf.pop_u32()?;
        rr.rrdata_len = buf.pop_u16()?;

        rr.rrdata = match rr.rrtype {
            RRType::A => {
                let octets = buf.pop_u32()?;
                let ip = Ipv4Addr::new(
                    ((octets >> 24) & 0xFF) as u8,
                    ((octets >> 16) & 0xFF) as u8,
                    ((octets >> 8) & 0xFF) as u8,
                    (octets & 0xFF) as u8,
                );
                RRData::A(ip)
            }
            RRType::Unknown(_) => RRData::Unknown(rr.rrdata_len),
        };

        Ok(rr)
    }
}

#[derive(Debug)]
pub enum RRType {
    A,
    Unknown(u16),
}

impl From<RRType> for u16 {
    fn from(val: RRType) -> Self {
        match val {
            RRType::A => 1,
            RRType::Unknown(inner_val) => inner_val,
        }
    }
}

impl From<u16> for RRType {
    fn from(val: u16) -> Self {
        match val {
            1 => RRType::A,
            _ => RRType::Unknown(val),
        }
    }
}

#[derive(Debug)]
pub enum RRClass {
    IN,
    Unknown(u16),
}

impl From<RRClass> for u16 {
    fn from(val: RRClass) -> Self {
        match val {
            RRClass::IN => 1,
            RRClass::Unknown(inner_val) => inner_val,
        }
    }
}

impl From<u16> for RRClass {
    fn from(val: u16) -> Self {
        match val {
            1 => RRClass::IN,
            _ => RRClass::Unknown(val),
        }
    }
}

#[derive(Debug)]
pub enum RRData {
    /// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
    ///
    /// ```text
    ///     3.4.1. A RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    ADDRESS                    |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// ADDRESS         A 32 bit Internet address.
    ///
    /// Hosts that have multiple Internet addresses will have multiple A
    /// records.
    ///
    /// A records cause no additional section processing.  The RDATA section of
    /// an A line in a master file is an Internet address expressed as four
    /// decimal numbers separated by dots without any imbedded spaces (e.g.,
    /// "10.2.0.52" or "192.0.5.6").
    /// ```
    A(Ipv4Addr),

    /// Unknown RRData will only consist of the length of the data
    /// associated with the unknown-typed resource record.
    Unknown(u16),
}
