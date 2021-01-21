use std::net::Ipv4Addr;

use crate::buffer::{BytePacketBuffer, Result};

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

    pub fn deserialize(buf: &mut BytePacketBuffer) -> Result<Message> {
        let mut msg = Message::new();
        msg.header.deserialize(buf)?;
        for _ in 0..msg.header.question_count {
            let mut question = Question::new(
                DomainName::new(),
                QueryType::Unknown(0),
                QueryClass::Unknown(0),
            );
            question.deserialize(buf)?;
            msg.questions.push(question);
        }
        for _ in 0..msg.header.answer_count {
            let mut answer = ResourceRecord::new();
            answer.deserialize(buf)?;
            msg.answers.push(answer);
        }
        for _ in 0..msg.header.authority_count {
            let mut authority = ResourceRecord::new();
            authority.deserialize(buf)?;
            msg.authorities.push(authority);
        }
        for _ in 0..msg.header.additional_count {
            let mut additional = ResourceRecord::new();
            additional.deserialize(buf)?;
            msg.additionals.push(additional);
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

impl From<MessageType> for bool {
    fn from(val: MessageType) -> Self {
        match val {
            MessageType::Query => false,
            MessageType::Response => true,
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

    pub fn deserialize(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.id = buf.pop_u16()?;

        let flags = buf.pop_u16()?;
        self.message_type = ((flags & (0x1 << 15)) != 0).into();
        self.op_code = ((flags & (0xF << 11)) as u8).into();
        self.authoritative_answer = (flags & (0x1 << 10)) != 0;
        self.truncation = (flags & (0x1 << 9)) != 0;
        self.recursion_desired = (flags & (0x1 << 8)) != 0;
        self.recursion_available = (flags & (0x1 << 7)) != 0;
        self.authentic_data = (flags & (0x1 << 5)) != 0;
        self.checking_disabled = (flags & (0x1 << 4)) != 0;
        self.response_code = ((flags & 0xF) as u8).into();

        self.question_count = buf.pop_u16()?;
        self.answer_count = buf.pop_u16()?;
        self.authority_count = buf.pop_u16()?;
        self.additional_count = buf.pop_u16()?;

        Ok(())
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

impl From<OpCode> for u8 {
    fn from(val: OpCode) -> Self {
        match val {
            OpCode::Query => 0,
            OpCode::Unknown(inner_val) => inner_val,
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

    pub fn deserialize(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
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
                self.0
                    .push_str(&String::from_utf8_lossy(label).to_lowercase());
                buf.step(len as usize);
                if buf.peek()? != 0 {
                    self.0.push('.');
                }
            }
        }

        if jump_count > 0 {
            buf.seek(starting_pos + 2);
        }

        Ok(())
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

    pub fn deserialize(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.domain_name = DomainName::new();
        self.domain_name.deserialize(buf)?;
        self.qtype = buf.pop_u16()?.into();
        self.qclass = buf.pop_u16()?.into();
        Ok(())
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

impl From<QueryType> for u16 {
    fn from(val: QueryType) -> Self {
        match val {
            QueryType::RRType(inner_val) => inner_val.into(),
            QueryType::Unknown(inner_val) => inner_val,
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

    pub fn deserialize(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.domain_name = DomainName::new();
        self.domain_name.deserialize(buf)?;
        self.rrtype = buf.pop_u16()?.into();
        self.rrclass = buf.pop_u16()?.into();
        self.ttl = buf.pop_u32()?;
        self.rrdata_len = buf.pop_u16()?;

        self.rrdata = match self.rrtype {
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
            RRType::Unknown(inner_val) => RRData::Unknown(inner_val),
        };

        Ok(())
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

impl From<RRType> for u16 {
    fn from(val: RRType) -> Self {
        match val {
            RRType::A => 1,
            RRType::Unknown(inner_val) => inner_val,
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

impl From<RRClass> for u16 {
    fn from(val: RRClass) -> Self {
        match val {
            RRClass::IN => 1,
            RRClass::Unknown(inner_val) => inner_val,
        }
    }
}

#[derive(Debug)]
pub enum RRData {
    A(Ipv4Addr),
    // NOTE(tristan): Unknown RRData will only consist of the length of the data
    // associated with the unknown-typed record.
    Unknown(u16),
}
