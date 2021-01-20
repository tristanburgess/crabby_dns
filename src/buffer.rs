use std::fs::File;
use std::io::prelude::*;

const BUF_SIZE: usize = 512;

#[derive(Debug, PartialEq)]
pub enum BufferError {
    ReadOverrun,
}

type Result<T> = std::result::Result<T, BufferError>;

pub struct BytePacketBuffer {
    buf: [u8; BUF_SIZE],
    pos: usize,
}

// TODO(tristan): doc comments for these
impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; BUF_SIZE],
            pos: 0,
        }
    }

    pub fn fill_from_buffer(&mut self, in_buf: &[u8]) {
        if in_buf.len() < BUF_SIZE {
            self.buf[..in_buf.len()].copy_from_slice(&in_buf);
        } else {
            self.buf.copy_from_slice(&in_buf[..BUF_SIZE]);
        }
    }

    pub fn fill_from_file(&mut self, path: &str) -> std::io::Result<()> {
        let mut f = File::open(path)?;
        f.read(&mut self.buf)?;
        Ok(())
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, num_steps: usize) {
        self.pos += num_steps;
    }

    pub fn seek(&mut self, new_pos: usize) {
        self.pos = new_pos
    }

    pub fn peek(&self) -> Result<u8> {
        if self.pos >= BUF_SIZE {
            return Err(BufferError::ReadOverrun);
        }
        Ok(self.buf[self.pos])
    }

    pub fn peek_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= BUF_SIZE {
            return Err(BufferError::ReadOverrun);
        }
        Ok(&self.buf[start..start + len])
    }

    pub fn pop(&mut self) -> Result<u8> {
        if self.pos >= BUF_SIZE {
            return Err(BufferError::ReadOverrun);
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn pop_u16(&mut self) -> Result<u16> {
        let res = ((self.pop()? as u16) << 8) | (self.pop()? as u16);

        Ok(res)
    }

    pub fn pop_u32(&mut self) -> Result<u32> {
        let res = ((self.pop()? as u32) << 24)
            | ((self.pop()? as u32) << 16)
            | ((self.pop()? as u32) << 8)
            | (self.pop()? as u32);

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_init_happy() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_buffer(bin);
        assert_eq!(0, buf.pos());
        assert_eq!(b"s"[0], buf.peek().unwrap());
    }

    #[test]
    fn step_happy() {
        let bin = b"supercooltest";
        let mut buf = BytePacketBuffer::new();
        buf.fill_from_buffer(bin);
        buf.step(5);
        assert_eq!(5, buf.pos());
        assert_eq!(b"c"[0], buf.peek().unwrap());
    }

    #[test]
    fn step_err_buf_over() {
        let mut buf = BytePacketBuffer::new();
        buf.step(BUF_SIZE);
        assert_eq!(BUF_SIZE, buf.pos());
        assert_eq!(Some(BufferError::ReadOverrun), buf.peek().err());
    }

    // TODO(tristan): reorganize these after they're implemented
    /*
        #[test]
        fn seek_happy() {}

        #[test]
        fn seek_err_buf_over() {}

        #[test]
        fn peek_range_happy() {}

        #[test]
        fn peek_range_err_buf_over() {}

        #[test]
        fn pop_happy() {}

        #[test]
        fn pop_err_buf_over() {}

        #[test]
        fn pop_u16_happy() {}

        #[test]
        fn pop_u16_err_buf_over() {}

        #[test]
        fn pop_u32_happy() {}

        #[test]
        fn pop_u32_err_buf_over() {}

        #[test]
        fn fill_buf_smaller() {}

        #[test]
        fn fill_buf_larger() {}
    */
}
