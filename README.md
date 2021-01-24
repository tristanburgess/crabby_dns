# rusty_dns_server
A simple DNS server in Rust to help contribute further understanding to my team's office hours discussions.

I made significant reference to the following projects and/or documents in building this:
- [dnsguide](https://github.com/EmilHernvall/dnsguide)
- [trust-dns](https://github.com/bluejekyll/trust-dns)
- [IETF RFC 1035](https://tools.ietf.org/html/rfc1035)

# How to build it
- Use [rustup](https://rustup.rs/) to install the rust toolchain on your local machine.
- Navigate to your checked out repo and run `cargo build`

# How to get oriented with the crate
- Use `cargo doc --open` to generate crate documentation and view it.

# How to run it
- The unit test suite can be run using `cargo test`
- For actually running it, see what you can do with `cargo run -- --help` as well as the sections below.
## DNS Stub Resolver
Right now the rusty_dns stub resolver implements some of the most basic relevant pieces of
[IETF RFC 1035](https://tools.ietf.org/html/rfc1035), and probably not even that correctly. 
Only `A` RRs of class `IN` are currently supported.

Via the CLI, you specify a query domain name, and optionally a query type and query class.
The stub resolver will delegate interface address binding and port selection for the UDP socket to the OS.
Your query will be serialized into a DNS protocol message of query type with a header and question section and sent to the configured DNS server.
The response will then be listened for (blocking) and deserialized into a DNS protocol message of response type with whatever sections + data the server responded with.

- Invoke subcommand-specific help via `cargo run -- stub --help`
### Example
```
$ cargo run -- stub -@ 8.8.8.8 -d google.com
Connected to 8.8.8.8:53 from 10.0.2.15:43506
Working on the DNS transaction now...

#################################################
#               DNS QUESTION MESSAGE            #
#################################################
Header {
    id: 0,
    message_type: Query,
    op_code: Query,
    authoritative_answer: false,
    truncation: false,
    recursion_desired: true,
    recursion_available: false,
    authentic_data: false,
    checking_disabled: false,
    response_code: NoError,
    question_count: 1,
    answer_count: 0,
    authority_count: 0,
    additional_count: 0,
}
Question {
    domain_name: DomainName(
        "google.com",
    ),
    qtype: RRType(
        A,
    ),
    qclass: RRClass(
        IN,
    ),
}

#################################################
#               DNS RESPONSE MESSAGE            #
#################################################
Header {
    id: 0,
    message_type: Response,
    op_code: Query,
    authoritative_answer: false,
    truncation: false,
    recursion_desired: true,
    recursion_available: true,
    authentic_data: false,
    checking_disabled: false,
    response_code: NoError,
    question_count: 1,
    answer_count: 1,
    authority_count: 0,
    additional_count: 0,
}
Question {
    domain_name: DomainName(
        "google.com",
    ),
    qtype: RRType(
        A,
    ),
    qclass: RRClass(
        IN,
    ),
}
ResourceRecord {
    domain_name: DomainName(
        "google.com",
    ),
    rrtype: A,
    rrclass: IN,
    ttl: 102,
    rrdata_len: 4,
    rrdata: A(
        172.217.3.110,
    ),
}
```
## DNS datagram deserializer
- Invoke subcommand-specific help via `cargo run -- deserialize --help`
- You'll need a DNS datagram to feed into the program. Examples of a query and its response in raw form are provided in the `/data` folder
- You can generate a query of your own by using netcat to listen on a port where no DNS server is listening, and then dig on that port. 
    - `nc -u -l 1053 > query.pkt` in one terminal
    - `dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com` in another
- You can generate a response from this query by using netcat to redirect the query UDP datagram as input to a DNS resolver like Google's 8.8.8.8 and redirect the response to a capturing file.
    - `nc -u 8.8.8.8 53 < query.pkt > response.pkt`
- You can view the packet captures as hex if desired
    - `hexdump -C response.pkt`
- Tying it all togetherm you can then invoke rusty_dns
    - `cargo run -- deserialize -f ./response.pkt`
### Example
```
$ nc -u -l 1053 > query.pkt &
[2] 28112

$ dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com

; <<>> DiG 9.16.1-Ubuntu <<>> +retry -p 1053 @127.0.0.1 +noedns google.com
; (1 server found)
;; global options: +cmd
;; connection timed out; no servers could be reached


$ kill 28112
[2]-  Terminated              nc -u -l 1053 > query.pkt

$ nc -u 8.8.8.8 53 < query.pkt > response.pkt
^C

$ hexdump -C response.pkt
00000000  6e 04 81 80 00 01 00 01  00 00 00 00 06 67 6f 6f  |n............goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01 c0 0c 00 01  |gle.com.........|
00000020  00 01 00 00 00 15 00 04  ac d9 0c ae              |............|
0000002c

$ cargo run -- deserialize -f ./response.pkt
#########################################
#		DNS MESSAGE		#
#########################################
Header {
    id: 28164,
    message_type: Response,
    op_code: Query,
    authoritative_answer: false,
    truncation: false,
    recursion_desired: true,
    recursion_available: true,
    authentic_data: false,
    checking_disabled: false,
    response_code: NoError,
    question_count: 1,
    answer_count: 1,
    authority_count: 0,
    additional_count: 0,
}
Question {
    domain_name: DomainName(
        "google.com",
    ),
    qtype: RRType(
        A,
    ),
    qclass: RRClass(
        IN,
    ),
}
ResourceRecord {
    domain_name: DomainName(
        "google.com",
    ),
    rrtype: A,
    rrclass: IN,
    ttl: 21,
    rrdata_len: 4,
    rrdata: A(
        172.217.12.174,
    ),
}
```
