use crate::buffer::{BytePacketBuffer, Deserialize, Result, Serialize};

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

    pub fn new(raw_dn: String) -> DomainName {
        DomainName(raw_dn)
    }
}

impl Serialize for DomainName {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn serialize(dn: Self::Structure, buf: &mut Self::Buffer) -> Result<()> {
        if dn.0.len() + 1 > 255 {
            todo!("How should this error be handled?");
        }

        for label in dn.0.split('.') {
            let len = label.len();
            if len > 63 {
                todo!("How should this error be handled?");
            }

            buf.push(len as u8)?;
            buf.push_slice(label.as_bytes())?;
        }

        buf.push(0)?;

        Ok(())
    }
}

impl Deserialize for DomainName {
    type Buffer = BytePacketBuffer;
    type Structure = Self;

    fn deserialize(buf: &mut Self::Buffer) -> Result<Self::Structure> {
        let mut dn = DomainName::new(String::new());
        let mut jump_count: usize = 0;
        // NOTE(tristan): The first jump begins a stack of potentially many further jumps,
        // so remember the entry point and move past it at the end if there were any jumps.
        // TODO(tristan): This has a bug if it is possible for two successive jumps at the root level
        // where the first jump does not result in the null terminator. Is it possible? Do we need to be
        // resillient against it anyways? Unit test it out with a constructed packet demonstrating the behavior.
        let mut first_jump_pos = None;

        loop {
            let cur_pos = buf.pos();
            let len = buf.pop()?;

            if len == 0 {
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if first_jump_pos == None {
                    first_jump_pos = Some(cur_pos);
                }
                jump_count += 1;
                if jump_count > Self::DSER_MAX_JUMPS {
                    // TODO(tristan) how is this error handled?
                    todo!();
                }
                let jump_pos: u16 = ((len as u16) << 8 | buf.pop()? as u16) ^ 0xC000;
                buf.seek(jump_pos as usize);
            } else {
                let label = buf.peek_slice(buf.pos(), len as usize)?;
                dn.0.push_str(&String::from_utf8_lossy(label).to_lowercase());
                buf.step(len as usize);
                if buf.peek()? != 0 {
                    dn.0.push('.');
                }
            }
        }

        if let Some(pos) = first_jump_pos {
            buf.seek(pos + 2);
        }

        Ok(dn)
    }
}
