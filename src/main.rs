use std::fs::File;
use std::io::prelude::*;

use rusty_dns_server::buffer::BytePacketBuffer;

/*struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
}
*/

// NOTE(tristan), must account for DNS labels as well as jumps
fn read_qname() {
    unimplemented!();
}

fn main() -> std::io::Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut b = BytePacketBuffer::new();
    //f.read(&mut b.buf)?;

    /*let packet = DnsPacket::from_buffer(&mut b)?;
    println!("{:#?}", packet.header);
    for q in packet.questions {
        println!("{:#?}", q);
    }
    for a in packet.answers {
        println!("{:#?}", a);
    }
    for auth in packet.authorities {
        println!("{:#?}", auth);
    }
    for adtl in packet.additionals {
        println!("{:#?}", adtl);
    }*/

    Ok(())
}
