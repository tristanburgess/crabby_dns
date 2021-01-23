use crate::buffer::{BytePacketBuffer, Deserialize, Result, Serialize};
use crate::dns::{Header, Question, ResourceRecord};

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

    pub fn push_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.question_count += 1;
    }
}

impl Default for Message {
    fn default() -> Self {
        Message::new()
    }
}

impl<'a> Serialize<'a> for Message {
    type Buffer = &'a [u8];
    type Structure = Self;

    fn serialize(buf: Self::Structure) -> Self::Buffer {
        &[0u8][..]
    }
}

impl Deserialize for Message {
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
