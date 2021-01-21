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
## Stub Resolver
Right now the rusty_dns stub resolver is just a simple DNS datagram deserializer that implements some of the relevant pieces of
[IETF RFC 1035](https://tools.ietf.org/html/rfc1035). 
Soon it will be turned into a stub resolver capable of 
- generating a DNS query message based on input parameters.
- serializing the query.
- sending the serialized query to a DNS resolver.
- receiving and deserializing the response.
### DNS datagram deserializer
- You'll need a DNS datagram to feed into the program. Examples of a query and its response in raw form are provided in the `/data` folder
- You can generate a query of your own by using netcat to listen on a port where no DNS server is listening, and then dig on that port. 
    - `nc -u -l 1053 > query.pkt` in one terminal
    - `dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com` in another
- You can generate a response from this query by using netcat to redirect the query UDP datagram as input to a DNS resolver like Google's 8.8.8.8 and redirect the response to a capturing file.
    - `nc -u 8.8.8.8 53 < query.pkt > response.pkt`
- You can view the packet captures as hex if desired
    - `hexdump -C response.pkt`
- Tying it all togetherm you can then invoke rusty_dns
    - `cargo run -- stub -f ./response.pkt`

