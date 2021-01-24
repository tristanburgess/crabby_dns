use std::fs::File;
use std::io::prelude::*;

/// BytePacketBuffers currently have only a constant buffer size in bytes.
pub const BUF_SIZE: usize = 512;

#[derive(Debug)]
pub enum BufferError {
    IoError(std::io::Error),
    ReadOverrun,
    WriteOverrun,
}

impl From<std::io::Error> for BufferError {
    fn from(err: std::io::Error) -> Self {
        BufferError::IoError(err)
    }
}

pub type Result<T> = std::result::Result<T, BufferError>;

pub trait Serialize {
    type Buffer;
    type Structure;

    fn serialize(struc: Self::Structure, buf: &mut Self::Buffer) -> Result<()>;
}

pub trait Deserialize {
    type Buffer;
    type Structure;

    fn deserialize(buf: &mut Self::Buffer) -> Result<Self::Structure>;
}

pub struct BytePacketBuffer {
    pub buf: [u8; BUF_SIZE],
    pos: usize,
}

impl BytePacketBuffer {
    /// Create a new BytePacketBuffer with fixed size and initialized position cursor.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; BUF_SIZE],
            pos: 0,
        }
    }

    /// Fill a BytePacketBuffer starting at the beginning of the buffer with as much data
    /// from the input byte slice as possible.
    pub fn fill_from_slice(&mut self, in_buf: &[u8]) {
        if in_buf.len() < BUF_SIZE {
            self.buf[..in_buf.len()].copy_from_slice(&in_buf);
        } else {
            self.buf.copy_from_slice(&in_buf[..BUF_SIZE]);
        }
    }

    /// Fill a BytePacketBuffer starting at the beginning of the buffer with as much data
    /// from the input binary file as possible.
    // NOTE(tristan): this does not currently handle truncation, but for right now
    // we don't expect to be working with any DNS datagrams larger than 512 bytes.
    #[allow(clippy::unused_io_amount)]
    pub fn fill_from_file(&mut self, path: &str) -> Result<()> {
        let mut f = File::open(path)?;
        f.read(&mut self.buf)?;

        Ok(())
    }

    /// Retrieves the current position of the cursor into the buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Increments the cursor `num_steps` bytes.
    pub fn step(&mut self, num_steps: usize) {
        self.pos += num_steps;
    }

    /// Sets the cursor to `new_pos`.
    pub fn seek(&mut self, new_pos: usize) {
        self.pos = new_pos
    }

    /// Returns the byte in the buffer at the cursor position if the read won't overrun.
    pub fn peek(&self) -> Result<u8> {
        if self.pos >= BUF_SIZE {
            return Err(BufferError::ReadOverrun);
        }

        Ok(self.buf[self.pos])
    }

    /// Returns a byte slice of size `len` starting at byte `start` if the read won't overrun.
    pub fn peek_slice(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= BUF_SIZE {
            return Err(BufferError::ReadOverrun);
        }

        Ok(&self.buf[start..start + len])
    }

    /// Returns the byte in the buffer at the cursor position if the read won't overrun.
    /// Increments the cursor by one.
    pub fn pop(&mut self) -> Result<u8> {
        if self.pos >= BUF_SIZE {
            return Err(BufferError::ReadOverrun);
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Returns the u16 in the buffer at the cursor position if the read won't overrun.
    /// Increments the cursor by two.
    /// Parses in network byte order (big endian).
    pub fn pop_u16(&mut self) -> Result<u16> {
        let res = ((self.pop()? as u16) << 8) | (self.pop()? as u16);

        Ok(res)
    }

    /// Returns the u32 in the buffer at the cursor position if the read won't overrun.
    /// Increments the cursor by four.
    /// Parses in network byte order (big endian).
    pub fn pop_u32(&mut self) -> Result<u32> {
        let res = ((self.pop()? as u32) << 24)
            | ((self.pop()? as u32) << 16)
            | ((self.pop()? as u32) << 8)
            | (self.pop()? as u32);

        Ok(res)
    }

    pub fn push(&mut self, data: u8) -> Result<()> {
        if self.pos >= BUF_SIZE {
            return Err(BufferError::WriteOverrun);
        }

        self.buf[self.pos] = data;
        self.pos += 1;

        Ok(())
    }

    pub fn push_slice(&mut self, data: &[u8]) -> Result<()> {
        if self.pos + data.len() >= BUF_SIZE {
            return Err(BufferError::WriteOverrun);
        }

        for b in data {
            self.push(*b)?;
        }

        Ok(())
    }

    pub fn push_u16(&mut self, data: u16) -> Result<()> {
        self.push(((data >> 8) & (0xFF)) as u8)?;
        self.push((data & (0xFF)) as u8)?;

        Ok(())
    }

    pub fn push_u32(&mut self, data: u32) -> Result<()> {
        self.push(((data >> 24) & (0xFF)) as u8)?;
        self.push(((data >> 16) & (0xFF)) as u8)?;
        self.push(((data >> 8) & (0xFF)) as u8)?;
        self.push((data & (0xFF)) as u8)?;

        Ok(())
    }
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        BytePacketBuffer::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_slice_smaller() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(bin);
        assert_eq!(bin[..], buf.buf[..bin.len()]);
    }

    #[test]
    fn fill_slice_larger() {
        let bin = [1u8; BUF_SIZE + 8];
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(&bin[..]);
        assert_eq!(bin[..BUF_SIZE], buf.buf[..]);
    }

    #[test]
    fn peek_init_happy() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(bin);
        assert_eq!(0, buf.pos());
        assert_eq!(b"s"[0], buf.peek().unwrap());
    }

    #[test]
    fn step_happy() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(bin);
        buf.step(5);
        assert_eq!(5, buf.pos());
        assert_eq!(b"c"[0], buf.peek().unwrap());
    }

    #[test]
    fn step_err_buf_over() {
        let mut buf = BytePacketBuffer::new();
        buf.step(BUF_SIZE);
        assert_eq!(BUF_SIZE, buf.pos());
        let _err = buf.peek().err();
        assert!(matches!(Some(BufferError::ReadOverrun), _err));
    }

    #[test]
    fn seek_happy() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(bin);
        buf.seek(8);
        assert_eq!(8, buf.pos());
        buf.seek(2);
        assert_eq!(2, buf.pos());
        assert_eq!(b"p"[0], buf.peek().unwrap());
    }

    #[test]
    fn seek_err_buf_over() {
        let mut buf = BytePacketBuffer::new();
        buf.seek(BUF_SIZE + 5);
        assert_eq!(BUF_SIZE + 5, buf.pos());
        let _err = buf.peek().err();
        assert!(matches!(Some(BufferError::ReadOverrun), _err));
    }

    #[test]
    fn peek_slice_happy() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(bin);
        assert_eq!(b"cool"[..], *buf.peek_slice(5, 4).unwrap());
    }

    #[test]
    fn peek_slice_err_buf_over() {
        let buf = BytePacketBuffer::new();
        let _err = buf.peek_slice(BUF_SIZE - 5, 10).err();
        assert!(matches!(Some(BufferError::ReadOverrun), _err));
    }

    #[test]
    fn pop_happy() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(bin);
        assert_eq!(b"s"[0], buf.pop().unwrap());
        buf.seek(5);
        assert_eq!(b"c"[0], buf.pop().unwrap());
    }

    #[test]
    fn pop_err_buf_over() {
        let mut buf = BytePacketBuffer::new();
        buf.seek(BUF_SIZE);
        let _err = buf.pop().err();
        assert!(matches!(Some(BufferError::ReadOverrun), _err));
    }

    #[test]
    fn pop_u16_happy() {
        let bin: [u8; 4] = [0x1F, 0xFA, 0xCC, 0x37];
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(&bin[..]);
        assert_eq!(0x1FFA, buf.pop_u16().unwrap());
        assert_eq!(0xCC37, buf.pop_u16().unwrap());
        buf.seek(1);
        assert_eq!(0xFACC, buf.pop_u16().unwrap());
    }

    #[test]
    fn pop_u16_err_buf_over() {
        let bin: [u8; BUF_SIZE] = [0xFF; BUF_SIZE];
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(&bin[..]);
        buf.seek(BUF_SIZE - 1);
        let _err = buf.pop_u16().err();
        assert!(matches!(Some(BufferError::ReadOverrun), _err));
    }

    #[test]
    fn pop_u32_happy() {
        let bin: [u8; 8] = [0x1F, 0xFA, 0xCC, 0x37, 0x41, 0x1B, 0xFE, 0x12];
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(&bin[..]);
        assert_eq!(0x1FFACC37, buf.pop_u32().unwrap());
        assert_eq!(0x411BFE12, buf.pop_u32().unwrap());
        buf.seek(2);
        assert_eq!(0xCC37411B, buf.pop_u32().unwrap());
    }

    #[test]
    fn pop_u32_err_buf_over() {
        let bin: [u8; BUF_SIZE] = [0xFF; BUF_SIZE];
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_slice(&bin[..]);
        buf.seek(BUF_SIZE - 3);
        let _err = buf.pop_u32().err();
        assert!(matches!(Some(BufferError::ReadOverrun), _err));
    }
}
