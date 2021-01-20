pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
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

pub struct Question {}

pub struct Record {}

pub enum OpCode {
    Query,
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
}

// NOTE(tristan), must account for DNS labels as well as jumps
fn read_qname() {
    unimplemented!();
}
