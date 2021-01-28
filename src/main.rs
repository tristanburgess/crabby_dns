#[macro_use]
extern crate clap;
use clap::{App, AppSettings};

use std::net::UdpSocket;
use std::process;

use crabby_dns::buffer::{BytePacketBuffer, Deserialize, Result, Serialize};
use crabby_dns::dns::{DomainName, Message, Question};

fn print_msg(msg: &Message) {
    println!("{:#?}", msg.header);
    for q in &msg.questions {
        println!("{:#?}", q);
    }
    for a in &msg.answers {
        println!("{:#?}", a);
    }
    for auth in &msg.authorities {
        println!("{:#?}", auth);
    }
    for adtl in &msg.additionals {
        println!("{:#?}", adtl);
    }
}

fn deserialize_message_file(file_path: &str) -> Result<()> {
    let mut buf = BytePacketBuffer::new();
    buf.fill_from_file(file_path)?;

    let message = Message::deserialize(&mut buf)?;

    println!("{:#>41}\n#\t\tDNS MESSAGE\t\t#\n{:#>41}", "#", "#");
    println!("{:#?}", message.header);
    for q in message.questions {
        println!("{:#?}", q);
    }
    for a in message.answers {
        println!("{:#?}", a);
    }
    for auth in message.authorities {
        println!("{:#?}", auth);
    }
    for adtl in message.additionals {
        println!("{:#?}", adtl);
    }

    Ok(())
}

fn stub_resolve(server_name: String, server_port: u16, question: Question) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    // TODO(tristan): this error should be better handled.
    // It doesn't make sense to have it use ? and capture a BufferError
    // as this socket is not part of our buffer management system.
    let conn = format!("{}:{}", server_name, server_port);
    socket.connect(&conn)?;
    println!(
        "Connected to {} from {}",
        conn,
        socket.local_addr().unwrap(),
    );
    println!("Working on the DNS transaction now...\n");

    println!("{:#>49}\n#\t\tDNS QUESTION MESSAGE\t\t#\n{:#>49}", "#", "#");
    let mut qmsg = Message::new();
    qmsg.header.recursion_desired = true;
    qmsg.push_question(question);
    print_msg(&qmsg);
    println!();

    let mut send_buf = BytePacketBuffer::new();
    Message::serialize(qmsg, &mut send_buf)?;
    socket.send(&send_buf.buf[..])?;

    let mut recv_buf = BytePacketBuffer::new();
    socket.recv(&mut recv_buf.buf[..])?;

    println!("{:#>49}\n#\t\tDNS RESPONSE MESSAGE\t\t#\n{:#>49}", "#", "#");
    let rmsg = Message::deserialize(&mut recv_buf)?;
    print_msg(&rmsg);

    Ok(())
}

fn main() {
    let yaml = load_yaml!("../config/cli.yml");
    let matches = App::from_yaml(yaml)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    if let Some(dser) = matches.subcommand_matches("deserialize") {
        let path = dser.value_of("message-file").unwrap();
        if let Err(e) = deserialize_message_file(path) {
            eprintln!("Application error: {:#?}", e);
            process::exit(2);
        }
    }

    if let Some(stub) = matches.subcommand_matches("stub") {
        let sn = stub.value_of("server-name").unwrap();
        let sp: u16 = stub
            .value_of("server-port")
            .unwrap_or("53")
            .parse::<u16>()
            .unwrap_or_else(|e| {
                eprintln!("Could not parse server port: {:#?}", e);
                process::exit(1);
            });

        let dn = DomainName::new(String::from(stub.value_of("domain-name").unwrap()));
        let qt: u16 = stub
            .value_of("query-type")
            .unwrap_or("1")
            .parse::<u16>()
            .unwrap_or_else(|e| {
                eprintln!("Could not parse query type {:#?}", e);
                process::exit(1);
            });
        let qc: u16 = stub
            .value_of("query-class")
            .unwrap_or("1")
            .parse::<u16>()
            .unwrap_or_else(|e| {
                eprintln!("Could not parse query class: {:#?}", e);
                process::exit(1);
            });

        let question = Question::new(dn, qt.into(), qc.into());
        if let Err(e) = stub_resolve(sn.into(), sp, question) {
            eprintln!("Application error: {:#?}", e);
            process::exit(2);
        }
    }
}
