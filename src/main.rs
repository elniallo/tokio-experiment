extern crate byteorder;
extern crate bytes;
#[macro_use]
extern crate futures;
extern crate cryptonight;
extern crate openssl;
extern crate rand;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_proto;

pub mod serialization;
pub mod server;
pub mod traits;
pub mod util;

fn main() {
    let args: Vec<String> = ::std::env::args().collect();
    println!("Args: {}", args.len());
    if args.len() >= 2 {
        match &args[1][..] {
            "server" => return server::server::run(args).unwrap(),
            _ => (),
        }
    }

    println!("usage: {} [client | server] ADDRESS", args[0]);
}
