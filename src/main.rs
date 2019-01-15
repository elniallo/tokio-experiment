extern crate bytes;
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_proto;

pub mod protocol;
pub mod serialization;
pub mod server;

fn main() {
    let args: Vec<String> = ::std::env::args().collect();
    if args.len() >= 2 {
        match &args[1][..] {
            "server" => return server::server::main(),
            _ => (),
        }
    }

    println!("usage: {} [client | server] ADDRESS", args[0]);
}
