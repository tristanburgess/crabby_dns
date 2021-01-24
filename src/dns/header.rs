use crate::buffer::{BytePacketBuffer, Deserialize, Result, Serialize};

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
    pub recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    checking_disabled: bool,
    response_code: ResponseCode,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
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

impl Default for Header {
    fn default() -> Self {
        Header::new()
    }
}

impl Serialize for Header {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn serialize(hdr: Self::Structure, buf: &mut Self::Buffer) -> Result<()> {
        buf.push_u16(hdr.id)?;

        let mut flags: u16 = 0;
        flags |= (bool::from(hdr.message_type) as u16) << 15;
        flags |= (u8::from(hdr.op_code) as u16) << 11;
        flags |= (hdr.authoritative_answer as u16) << 10;
        flags |= (hdr.truncation as u16) << 9;
        flags |= (hdr.recursion_desired as u16) << 8;
        flags |= (hdr.recursion_available as u16) << 7;
        flags |= (hdr.authentic_data as u16) << 5;
        flags |= (hdr.checking_disabled as u16) << 4;
        flags |= u8::from(hdr.response_code) as u16;
        buf.push_u16(flags)?;

        buf.push_u16(hdr.question_count)?;
        buf.push_u16(hdr.answer_count)?;
        buf.push_u16(hdr.authority_count)?;
        buf.push_u16(hdr.additional_count)?;

        Ok(())
    }
}

impl Deserialize for Header {
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
pub enum MessageType {
    Query,
    Response,
}

impl From<MessageType> for bool {
    fn from(val: MessageType) -> Self {
        match val {
            MessageType::Query => false,
            MessageType::Response => true,
        }
    }
}

impl From<bool> for MessageType {
    fn from(val: bool) -> Self {
        match val {
            false => MessageType::Query,
            true => MessageType::Response,
        }
    }
}

#[derive(Debug)]
pub enum OpCode {
    Query,
    Unknown(u8),
}

impl From<OpCode> for u8 {
    fn from(val: OpCode) -> Self {
        match val {
            OpCode::Query => 0,
            OpCode::Unknown(inner_val) => inner_val,
        }
    }
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
    FormatError,
    ServFail,
    NameError,
    NotImpl,
    Refused,
    Unknown(u8),
}

impl From<ResponseCode> for u8 {
    fn from(val: ResponseCode) -> Self {
        match val {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImpl => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Unknown(inner_val) => inner_val,
        }
    }
}

impl From<u8> for ResponseCode {
    fn from(val: u8) -> Self {
        match val {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImpl,
            5 => ResponseCode::Refused,
            _ => ResponseCode::Unknown(val),
        }
    }
}
