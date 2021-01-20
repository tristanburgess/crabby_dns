use std::net::Ipv4Addr;

pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authorities: Vec<ResourceRecord>,
    additionals: Vec<ResourceRecord>,
}

/// Representation of a DNS message header.
///
/// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
///
/// [RFC 4035 - Protocol Modifications for the DNS Security Extensions](https://tools.ietf.org/html/rfc4035)
///
/// ```text
/// 4.1.1. Header section format
///
/// The header contains the following fields for a total of 12 bytes.
///
///                                    1  1  1  1  1  1
///      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5 (bit)
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      ID                       |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    QDCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ANCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    NSCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ARCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
/// ...
/// Z               Reserved for future use.  Must be zero in all queries
///                 and responses.
/// ...
/// ```
///
pub struct Header {
    id: u16,
    message_type: MessageType,
    op_code: OpCode,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    checking_disabled: bool,
    response_code: ResponseCode,
    query_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

pub enum OpCode {
    Query,
    Unknown(u8),
}

impl From<u8> for OpCode {
    fn from(val: u8) -> Self {
        match val {
            0 => OpCode::Query,
            _ => OpCode::Unknown(val),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(val: OpCode) -> Self {
        match val {
            OpCode::Query => 0,
            OpCode::Unknown(inner_val) => inner_val,
        }
    }
}

pub enum MessageType {
    Query,
    Response,
}

pub enum ResponseCode {
    NoError,
    FormError,
    ServFail,
    NameError,
    NotImpl,
    Refused,
    Unknown(u8),
}

impl From<u8> for ResponseCode {
    fn from(val: u8) -> Self {
        match val {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormError,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImpl,
            5 => ResponseCode::Refused,
            _ => ResponseCode::Unknown(val),
        }
    }
}

impl From<ResponseCode> for u8 {
    fn from(val: ResponseCode) -> Self {
        match val {
            ResponseCode::NoError => 0,
            ResponseCode::FormError => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImpl => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Unknown(inner_val) => inner_val,
        }
    }
}

/// Representation of a DNS message question.
///
/// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1.2. Question section format
///
/// The question section contains the following fields for a total of 6 bytes.
///
///                                    1  1  1  1  1  1
///      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5 (bit)
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     |                     QNAME                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QTYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QCLASS                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
pub struct Question {
    domain_name: String,
    qtype: QueryType,
    qclass: QueryClass,
}

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

impl From<QueryType> for u16 {
    fn from(val: QueryType) -> Self {
        match val {
            QueryType::RRType(inner_val) => inner_val.into(),
            QueryType::Unknown(inner_val) => inner_val,
        }
    }
}

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

impl From<QueryClass> for u16 {
    fn from(val: QueryClass) -> Self {
        match val {
            QueryClass::RRClass(inner_val) => inner_val.into(),
            QueryClass::Unknown(inner_val) => inner_val,
        }
    }
}

/// Representation of a DNS resource record.
///
/// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1.3. Resource record format
///
/// A resource record has the following fields for a total of 12 bytes.
///                                    1  1  1  1  1  1
///      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5 (bit)
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     |                                               |
///     |                      NAME                     |
///     |                                               |
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
///     |                     RDATA                     |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
pub struct ResourceRecord {
    domain_name: String,
    rrtype: RRType,
    rrclass: RRClass,
    ttl: u32,
    rrdata_len: u16,
    rrdata: RRData,
}

pub enum RRData {
    A(Ipv4Addr),
    // NOTE(tristan): Unknown RRData will only consist of the length of the data
    // associated with the unknown-typed record.
    Unknown(u16),
}

pub enum RRType {
    A,
    Unknown(u16),
}

impl From<u16> for RRType {
    fn from(val: u16) -> Self {
        match val {
            1 => RRType::A,
            _ => RRType::Unknown(val),
        }
    }
}

impl From<RRType> for u16 {
    fn from(val: RRType) -> Self {
        match val {
            RRType::A => 1,
            RRType::Unknown(inner_val) => inner_val,
        }
    }
}

pub enum RRClass {
    IN,
    Unknown(u16),
}

impl From<u16> for RRClass {
    fn from(val: u16) -> Self {
        match val {
            1 => RRClass::IN,
            _ => RRClass::Unknown(val),
        }
    }
}

impl From<RRClass> for u16 {
    fn from(val: RRClass) -> Self {
        match val {
            RRClass::IN => 1,
            RRClass::Unknown(inner_val) => inner_val,
        }
    }
}
