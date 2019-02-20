use crate::server::socket_parser::SocketParser;

use bytes::{BufMut, BytesMut};
use futures::stream::Stream;
use std::time::{Duration, Instant};
use tokio::io;
use tokio::net::TcpStream;
use tokio::prelude::*;

pub struct BaseSocket {
    socket: TcpStream,
    rd: BytesMut,
    wr: BytesMut,
    parser: SocketParser,
    last_received: Instant,
}
impl BaseSocket {
    pub fn new(socket: TcpStream) -> Self {
        Self {
            socket,
            rd: BytesMut::new(),
            wr: BytesMut::new(),
            parser: SocketParser::new(),
            last_received: Instant::now(),
        }
    }
    pub fn buffer(&mut self, line: &[u8]) {
        self.wr.reserve(line.len());
        self.wr.put(line)
    }

    pub fn poll_flush(&mut self) -> Poll<(), io::Error> {
        while !self.wr.is_empty() {
            let n = try_ready!(self.socket.poll_write(&self.wr));
            assert!(n > 0);
            let _ = self.wr.split_to(n);
        }
        Ok(Async::Ready(()))
    }

    pub fn fill_read_buf(&mut self) -> Poll<(), io::Error> {
        loop {
            self.rd.reserve(1024);
            let n = try_ready!(self.socket.read_buf(&mut self.rd));
            if n == 0 || self.rd.len() > 0 {
                return Ok(Async::Ready(()));
            }
        }
    }

    pub fn get_socket(&self) -> &TcpStream {
        &self.socket
    }

    pub fn get_parser_mut(&mut self) -> &mut SocketParser {
        &mut self.parser
    }
}

impl Stream for BaseSocket {
    type Item = (Vec<(BytesMut, u32)>);
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let sock_closed = self.fill_read_buf()?.is_ready();
        if self.rd.len() > 0 {
            self.last_received = Instant::now();
            let (parse_result, parsed) = self.parser.parse(&mut self.rd.to_vec()).unwrap();
            match parse_result {
                Some(msg) => {
                    self.rd.split_to(parsed);
                    let mut ret = Vec::with_capacity(msg.len());
                    for (buf, route) in msg {
                        ret.push((BytesMut::from(buf), route));
                    }
                    return Ok(Async::Ready(Some(ret)));
                }
                None => {
                    self.rd.split_to(parsed);
                }
            }
        }
        if sock_closed {
            if Instant::now().duration_since(self.last_received).as_secs() > 60 {
                println!("Socket disconnecting: time since last message > 60 secs");
                Ok(Async::Ready(None))
            } else {
                Ok(Async::NotReady)
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}
