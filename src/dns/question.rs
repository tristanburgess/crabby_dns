use crate::buffer::{BytePacketBuffer, Deserialize, Result, Serialize};
use crate::dns::{DomainName, RRClass, RRType};

/// Representation of a DNS message question.
///
/// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1.2. Question section format
///
/// The question section contains the following fields.
///
///                                    1  1  1  1  1  1
///      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5 (bit)
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                     QNAME                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QTYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QCLASS                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```

#[derive(Debug)]
pub struct Question {
    domain_name: DomainName,
    qtype: QueryType,
    qclass: QueryClass,
}

impl Question {
    pub fn new(domain_name: DomainName, qtype: QueryType, qclass: QueryClass) -> Question {
        Question {
            domain_name,
            qtype,
            qclass,
        }
    }
}

impl Deserialize for Question {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn deserialize(buf: &mut Self::Buffer) -> Result<Self::Structure> {
        let dn = DomainName::deserialize(buf)?;
        let qtype = buf.pop_u16()?.into();
        let qclass = buf.pop_u16()?.into();
        Ok(Question::new(dn, qtype, qclass))
    }
}

#[derive(Debug)]
pub enum QueryType {
    RRType(RRType),
    Unknown(u16),
}

impl From<u16> for QueryType {
    fn from(val: u16) -> Self {
        let rrtype = RRType::from(val);
        // NOTE(tristan): unknown RRType could still be a valid QueryType.
        // This matching would need to be broken out further if futher QTYPE
        // support were added.
        match rrtype {
            RRType::Unknown(inner_val) => QueryType::Unknown(inner_val),
            _ => QueryType::RRType(rrtype),
        }
    }
}

#[derive(Debug)]
pub enum QueryClass {
    RRClass(RRClass),
    Unknown(u16),
}

impl From<u16> for QueryClass {
    fn from(val: u16) -> Self {
        let rrclass = RRClass::from(val);
        // NOTE(tristan): unknown RRClass could still be a valid QueryClass.
        // This matching would need to be broken out further if futher QCLASS
        // support were added.
        match rrclass {
            RRClass::Unknown(inner_val) => QueryClass::Unknown(inner_val),
            _ => QueryClass::RRClass(rrclass),
        }
    }
}
