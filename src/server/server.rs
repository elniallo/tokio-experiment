use crate::server::socket_parser::SocketParser;
use bytes::{BufMut, BytesMut};
use futures::stream::{self, Stream};
use futures::Future;
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::io::{BufReader, Error, ErrorKind};
use std::iter;
use std::net::ToSocketAddrs;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;
use tokio_io::codec::Decoder;
use tokio_io::io;
use tokio_io::AsyncRead;

use crate::server::network_manager::NetworkManager;

pub fn main(args: Vec<String>) -> Result<(), Box<std::io::Error>> {
    // let args: Vec<String> = ::std::env::args().collect();
    println!("Args: {:?}", args);
    let addr = args[2]
        .to_socket_addrs()
        .unwrap()
        .next()
        .expect("could not parse address");
    let mut core = Core::new()?;
    let handle = core.handle();
    let socket = TcpListener::bind(&addr, &handle)?;
    println!("Server listening on: {}", addr);

    let connections = Rc::new(RefCell::new(HashMap::new()));

    let srv = socket.incoming().for_each(move |(stream, addr)| {
        stream.set_nodelay(true)?;
        println!("New Connection: {}", addr);
        let (reader, writer) = stream.split();
        let (tx, rx) = futures::sync::mpsc::unbounded();
        let tx1 = tx.clone();
        let parser = Arc::new(Mutex::new(SocketParser::new(tx)));
        let parser_clone = parser.clone();
        connections.borrow_mut().insert(addr, parser);
        let connections_inner = connections.clone();
        let reader = BufReader::new(reader);
        let iter = stream::iter_ok::<_, Error>(iter::repeat(()));
        let socket_reader = iter.fold(reader, move |reader, _| {
            let tx_inner = tx1.clone();
            let p = parser_clone.clone();
            let line = io::read_until(reader, b'\n', Vec::new());
            let line = line.and_then(|(reader, vec)| {
                if vec.len() == 0 {
                    Err(Error::new(ErrorKind::BrokenPipe, "Broken Pipe"))
                } else {
                    Ok((reader, vec))
                }
            });
            line.map(move |(reader, vec)| {
                let mut bytes = BytesMut::new();
                bytes.extend_from_slice(&vec);
                let mut guard = p.lock();
                let socket_parser = guard.as_mut().unwrap();
                match socket_parser.parse(&bytes.to_vec()) {
                    Ok(parse_result) => {
                        if let Some(parsed) = parse_result {
                            println!("Parsed: {:?}", parsed);
                            let decoded = NetworkManager::decode(&parsed).unwrap();
                            println!("Decoded and returned");
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
                drop(guard);
                reader
            })
        });

        let socket_writer = rx.fold(writer, |writer, msg: BytesMut| {
            let amt = io::write_all(writer, msg);
            let amt = amt.map(|(writer, _)| writer);
            amt.map_err(|_| ())
        });

        let connections = connections.clone();
        let socket_reader = socket_reader.map_err(|_| ());
        let connection = socket_reader.map(|_| ()).select(socket_writer.map(|_| ()));
        handle.spawn(connection.then(move |_| {
            // connections.borrow_mut().remove(&addr);
            // println!("Connection {} closed.", addr);
            Ok(())
        }));
        Ok(())
    });
    Ok(core.run(srv).unwrap())
}
