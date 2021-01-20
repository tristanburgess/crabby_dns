#[macro_use]
extern crate clap;
use clap::{App, AppSettings};

use std::process;

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

fn parse_response_packet_file(file_path: &str) -> std::io::Result<()> {
    let mut b = BytePacketBuffer::new();
    b.fill_from_file(file_path)?;

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

fn main() -> std::io::Result<()> {
    let yaml = load_yaml!("../config/cli.yml");
    let matches = App::from_yaml(yaml)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    if let Some(stub) = matches.subcommand_matches("stub") {
        let path = stub.value_of("packet-file").unwrap();
        if let Err(e) = parse_response_packet_file(path) {
            eprintln!("Application error: {}", e);
            process::exit(2);
        }
    }

    Ok(())
}
