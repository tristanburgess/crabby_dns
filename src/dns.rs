use std::net::Ipv4Addr;

use crate::buffer::{BytePacketBuffer, Result};

/// Representation of a DNS message.
///
/// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 4.1. Format
///
/// All communications inside of the domain protocol are carried in a single
/// format called a message.  The top level format of message is divided
/// into 5 sections (some of which are empty in certain cases) shown below:
///
///     +---------------------+
///     |        Header       |
///     +---------------------+
///     |       Question      | the question for the name server
///     +---------------------+
///     |        Answer       | RRs answering the question
///     +---------------------+
///     |      Authority      | RRs pointing toward an authority
///     +---------------------+
///     |      Additional     | RRs holding additional information
///     +---------------------+
///
/// The header section is always present.  The header includes fields that
/// specify which of the remaining sections are present, and also specify
/// whether the message is a query or a response, a standard query or some
/// other opcode, etc.
///
/// The names of the sections after the header are derived from their use in
/// standard queries.  The question section contains fields that describe a
/// question to a name server.  These fields are a query type (QTYPE), a
/// query class (QCLASS), and a query domain name (QNAME).  The last three
/// sections have the same format: a possibly empty list of concatenated
/// resource records (RRs).  The answer section contains RRs that answer the
/// question; the authority section contains RRs that point toward an
/// authoritative name server; the additional records section contains RRs
/// which relate to the query, but are not strictly answers for the
/// question.
/// ```

#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    pub fn new() -> Message {
        Message {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

impl crate::buffer::Deserialize for Message {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn deserialize(buf: &mut Self::Buffer) -> Result<Self::Structure> {
        let mut msg = Message::new();
        msg.header = Header::deserialize(buf)?;
        for _ in 0..msg.header.question_count {
            msg.questions.push(Question::deserialize(buf)?);
        }
        for _ in 0..msg.header.answer_count {
            msg.answers.push(ResourceRecord::deserialize(buf)?);
        }
        for _ in 0..msg.header.authority_count {
            msg.authorities.push(ResourceRecord::deserialize(buf)?);
        }
        for _ in 0..msg.header.additional_count {
            msg.additionals.push(ResourceRecord::deserialize(buf)?);
        }
        Ok(msg)
    }
}

#[derive(Debug)]
pub enum MessageType {
    Query,
    Response,
}

impl From<bool> for MessageType {
    fn from(val: bool) -> Self {
        match val {
            false => MessageType::Query,
            true => MessageType::Response,
        }
    }
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

#[derive(Debug)]
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
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl Header {
    pub fn new() -> Header {
        Header {
            id: 0,
            message_type: MessageType::Query,
            op_code: OpCode::Query,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }
}

impl crate::buffer::Deserialize for Header {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn deserialize(buf: &mut Self::Buffer) -> Result<Self::Structure> {
        let mut hdr = Header::new();
        hdr.id = buf.pop_u16()?;

        let flags = buf.pop_u16()?;
        hdr.message_type = ((flags & (0x1 << 15)) != 0).into();
        hdr.op_code = ((flags & (0xF << 11)) as u8).into();
        hdr.authoritative_answer = (flags & (0x1 << 10)) != 0;
        hdr.truncation = (flags & (0x1 << 9)) != 0;
        hdr.recursion_desired = (flags & (0x1 << 8)) != 0;
        hdr.recursion_available = (flags & (0x1 << 7)) != 0;
        hdr.authentic_data = (flags & (0x1 << 5)) != 0;
        hdr.checking_disabled = (flags & (0x1 << 4)) != 0;
        hdr.response_code = ((flags & 0xF) as u8).into();

        hdr.question_count = buf.pop_u16()?;
        hdr.answer_count = buf.pop_u16()?;
        hdr.authority_count = buf.pop_u16()?;
        hdr.additional_count = buf.pop_u16()?;

        Ok(hdr)
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
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

/// Representation of a DNS domain name
///
/// [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
/// ```text
/// 4.1.4. Message Compression
///
/// In order to reduce the size of messages, the domain system utilizes a
/// compression scheme which eliminates the repetition of domain names in a
/// message.  In this scheme, an entire domain name or a list of labels at
/// the end of a domain name is replaced with a pointer to a prior occurence
/// of the same name.
///
/// The pointer takes the form of a two octet sequence:
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     | 1  1|                OFFSET                   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// The first two bits are ones.  This allows a pointer to be distinguished
/// from a label, since the label must begin with two zero bits because
/// labels are restricted to 63 octets or less.  (The 10 and 01 combinations
/// are reserved for future use.)  The OFFSET field specifies an offset from
/// the start of the message (i.e., the first octet of the ID field in the
/// domain header).  A zero offset specifies the first byte of the ID field,
/// etc.
///
/// The compression scheme allows a domain name in a message to be
/// represented as either:
///
///    - a sequence of labels ending in a zero octet
///
///    - a pointer
///
///    - a sequence of labels ending with a pointer
/// ```
#[derive(Debug)]
pub struct DomainName(String);

impl DomainName {
    const DSER_MAX_JUMPS: usize = 5;

    pub fn new() -> DomainName {
        DomainName(String::new())
    }
}

impl crate::buffer::Deserialize for DomainName {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn deserialize(buf: &mut Self::Buffer) -> Result<Self::Structure> {
        let mut dn = DomainName::new();
        let mut jump_count: usize = 0;
        let starting_pos = buf.pos();

        loop {
            let len = buf.pop()?;

            if len == 0 {
                break;
            }

            if (len & 0xC0) == 0xC0 {
                jump_count += 1;
                if jump_count > Self::DSER_MAX_JUMPS {
                    // TODO(tristan) how is this error handled?
                    todo!();
                }
                let new_pos: u16 = ((len as u16) << 8 | buf.pop()? as u16) ^ 0xC000;
                buf.seek(new_pos as usize);
            } else {
                let label = buf.peek_range(buf.pos(), len as usize)?;
                dn.0.push_str(&String::from_utf8_lossy(label).to_lowercase());
                buf.step(len as usize);
                if buf.peek()? != 0 {
                    dn.0.push('.');
                }
            }
        }

        if jump_count > 0 {
            buf.seek(starting_pos + 2);
        }

        Ok(dn)
    }
}

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

impl crate::buffer::Deserialize for Question {
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
            domain_name: DomainName::new(),
            rrtype: RRType::Unknown(0),
            rrclass: RRClass::Unknown(0),
            ttl: 0,
            rrdata_len: 0,
            rrdata: RRData::Unknown(0),
        }
    }
}

impl crate::buffer::Deserialize for ResourceRecord {
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
