const BUFF_SIZE: usize = 512;

pub struct BytePacketBuffer {
    buf: [u8; BUFF_SIZE],
    pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; BUFF_SIZE],
            pos: 0,
        }
    }

    fn pos() {
        unimplemented!()
    }

    fn step() {
        unimplemented!();
    }

    fn seek() {
        unimplemented!();
    }

    fn read() {
        unimplemented!();
    }

    fn peek() {
        unimplemented!();
    }

    fn peek_range() {
        unimplemented!();
    }

    fn read_u16() {
        unimplemented!();
    }

    fn read_u32() {
        unimplemented!();
    }
}
