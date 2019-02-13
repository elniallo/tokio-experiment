use crate::server::socket_parser::SocketParser;
use crate::server::Encode;
use bytes::{BufMut, Bytes, BytesMut};
use futures::future::{self, Either};
use futures::stream::Stream;
use futures::sync::mpsc;
use protobuf::Message;
use std::collections::HashMap;
use std::io::Error;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use crate::serialization::network::{self, Network_oneof_request};
use crate::server::network_manager::{NetworkManager, NetworkMessage};

type Tx = mpsc::UnboundedSender<Bytes>;
type Rx = mpsc::UnboundedReceiver<Bytes>;

enum PeerStatus {
    Disconnected,
    Connected(crate::serialization::network::Status),
}
struct Peer {
    addr: SocketAddr,
    srv: Arc<Mutex<Server>>,
    socket: BaseSocket,
    receiver: Rx,
    status: PeerStatus,
}

impl Peer {
    fn new(
        srv: Arc<Mutex<Server>>,
        socket: BaseSocket,
        status: crate::serialization::network::Status,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let addr = socket.socket.peer_addr().unwrap();
        srv.lock().unwrap().peers.insert(addr, tx);
        Self {
            addr,
            srv,
            socket,
            receiver: rx,
            status: PeerStatus::Connected(status),
        }
    }

    fn return_status(&self) -> crate::serialization::network::Status {
        let mut status = crate::serialization::network::Status::new();
        status.set_guid(self.srv.lock().unwrap().guid.clone());
        status.set_version(self.srv.lock().unwrap().version.clone());
        status.set_port(3553);
        status.set_publicPort(3553);
        status.set_networkid("ouroboros".to_string());
        status
    }
}

impl Future for Peer {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<(), Error> {
        match self.receiver.poll().unwrap() {
            Async::Ready(Some(v)) => {
                self.socket.buffer(&v);
                task::current().notify();
            }
            _ => {}
        }
        let _ = self.socket.poll_flush()?;
        while let Async::Ready(data) = self.socket.poll()? {
            if let Some(messages) = data {
                for (bytes, route) in messages {
                    let parsed = NetworkManager::decode(&bytes.to_vec()).unwrap();
                    match &parsed.message_type {
                        Network_oneof_request::getPeers(n) => {
                            let mut peer_return = network::GetPeersReturn::new();
                            peer_return.set_success(true);
                            peer_return.set_peers(::protobuf::RepeatedField::from(Vec::new()));
                            let net_msg = NetworkMessage::new(
                                Network_oneof_request::getPeersReturn(peer_return),
                            );
                            let bytes = self
                                .socket
                                .parser
                                .prepare_packet(route, &net_msg.encode().unwrap());
                            match bytes {
                                Ok(msg) => {
                                    self.socket.buffer(&msg);
                                    self.socket.poll_flush()?;
                                }
                                Err(e) => println!("Error: {}", e),
                            }
                        }
                        Network_oneof_request::getPeersReturn(_) => {
                            println!("get peers return");
                        }
                        Network_oneof_request::getTip(_v) => {
                            let mut tip_return = network::GetTipReturn::new();
                            tip_return.set_height(0);
                            tip_return.set_success(true);
                            tip_return.set_hash(vec![
                                167, 196, 139, 41, 65, 52, 154, 132, 218, 236, 238, 209, 119, 24,
                                195, 185, 74, 193, 125, 161, 51, 205, 18, 11, 115, 28, 81, 195,
                                181, 95, 204, 235,
                            ]);
                            tip_return.set_totalwork(1.5);
                            let net_msg = NetworkMessage::new(Network_oneof_request::getTipReturn(
                                tip_return,
                            ));
                            let bytes = self
                                .socket
                                .parser
                                .prepare_packet(route, &net_msg.encode().unwrap());
                            match bytes {
                                Ok(msg) => {
                                    self.socket.buffer(&msg);
                                    self.socket.poll_flush()?;
                                }
                                Err(e) => println!("Error: {}", e),
                            }
                        }
                        Network_oneof_request::getTipReturn(_) => {
                            println!("get tip return");
                        }
                        Network_oneof_request::putBlock(block) => {
                            println!("Block Received: {:?}", block);
                        }
                        Network_oneof_request::putBlockReturn(_) => {
                            println!("Put block return");
                        }
                        Network_oneof_request::getTxs(_txs) => {
                            println!("Get Txs");
                        }
                        Network_oneof_request::getTxsReturn(_) => {
                            println!("get txs return");
                        }
                        Network_oneof_request::getHash(_h) => {
                            println!("Get Hash");
                        }
                        Network_oneof_request::getHashReturn(_h) => {
                            println!("Get hash return");
                        }
                        Network_oneof_request::getBlockTxs(_) => {
                            println!("Get block txs");
                        }
                        Network_oneof_request::getBlockTxsReturn(_) => {
                            println!("get block txs return");
                        }
                        Network_oneof_request::status(_) => {
                            println!("status");
                        }
                        Network_oneof_request::statusReturn(_) => {
                            println!("status return");
                        }
                        Network_oneof_request::getBlocksByHash(_) => {
                            println!("get blocks by hash");
                        }
                        Network_oneof_request::getBlocksByHashReturn(_) => {
                            println!("Get blocks by hash return");
                        }
                        Network_oneof_request::getBlocksByRange(_) => {
                            println!("Get blocks by range");
                        }
                        Network_oneof_request::getBlocksByRangeReturn(_) => {
                            println!("get blocks by range return");
                        }
                        Network_oneof_request::getHeadersByHash(_) => {
                            println!("get headers by hash");
                        }
                        Network_oneof_request::getHeadersByHashReturn(_) => {
                            println!("get headers by hash return");
                        }
                        Network_oneof_request::getHeadersByRange(_) => {
                            println!("Get headers by range");
                        }
                        Network_oneof_request::getHeadersByRangeReturn(_) => {
                            println!("Get Headers by range return");
                        }
                        Network_oneof_request::ping(_) => {
                            println!("Ping");
                        }
                        Network_oneof_request::pingReturn(_) => {
                            println!("Ping return");
                        }
                        Network_oneof_request::putHeaders(_) => {
                            println!("put headers");
                        }
                        Network_oneof_request::putHeadersReturn(_) => {
                            println!("put headers return");
                        }
                        Network_oneof_request::putTx(_) => {
                            println!("put tx");
                        }
                        Network_oneof_request::putTxReturn(_) => {
                            println!("put tx return");
                        }
                    }
                }
            } else {
                return Ok(Async::Ready(()));
            }
        }
        Ok(Async::NotReady)
    }
}
struct Server {
    peers: HashMap<SocketAddr, Tx>,
    guid: String,
    version: u32,
}

impl Server {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            guid: String::from("MyRustyGuid"),
            version: 14,
        }
    }
}

struct BaseSocket {
    socket: TcpStream,
    rd: BytesMut,
    wr: BytesMut,
    parser: SocketParser,
}
impl BaseSocket {
    fn new(socket: TcpStream) -> Self {
        Self {
            socket,
            rd: BytesMut::new(),
            wr: BytesMut::new(),
            parser: SocketParser::new(),
        }
    }
    fn buffer(&mut self, line: &[u8]) {
        self.wr.reserve(line.len());
        self.wr.put(line)
    }

    fn poll_flush(&mut self) -> Poll<(), io::Error> {
        while !self.wr.is_empty() {
            let n = try_ready!(self.socket.poll_write(&self.wr));
            assert!(n > 0);
            let _ = self.wr.split_to(n);
        }
        Ok(Async::Ready(()))
    }

    fn fill_read_buf(&mut self) -> Poll<(), io::Error> {
        loop {
            self.rd.reserve(1024);
            let n = try_ready!(self.socket.read_buf(&mut self.rd));
            if n == 0 || self.rd.len() > 0 {
                return Ok(Async::Ready(()));
            }
        }
    }
}

impl Stream for BaseSocket {
    type Item = (Vec<(BytesMut, u32)>);
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let sock_closed = self.fill_read_buf()?.is_ready();
        if self.rd.len() > 0 {
            let (parse_result, parsed) = self.parser.parse(&mut self.rd.to_vec()).unwrap();
            match parse_result {
                Some((msg)) => {
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
            Ok(Async::Ready(None))
        } else {
            Ok(Async::NotReady)
        }
    }
}

fn process_socket(socket: TcpStream, server: Arc<Mutex<Server>>) {
    let base = BaseSocket::new(socket);
    let connection = base
        .into_future()
        .map_err(|(e, _)| e)
        .and_then(move |(message, base)| {
            if let Some(msg) = message {
                let (message, route) = &msg[0];
                let parsed = NetworkManager::decode(&message.to_vec()).unwrap();
                match &parsed.message_type {
                    Network_oneof_request::status(v) => {
                        let mut peer = Peer::new(server, base, v.clone());
                        let status = peer.return_status();
                        let mut status_return = network::StatusReturn::new();
                        status_return.set_status(status);
                        let net_msg =
                            NetworkMessage::new(Network_oneof_request::statusReturn(status_return));
                        let bytes = peer
                            .socket
                            .parser
                            .prepare_packet(*route, &net_msg.encode().unwrap());
                        match bytes {
                            Ok(msg) => {
                                peer.socket.buffer(&msg);
                            }
                            Err(e) => println!("Error: {}", e),
                        }
                        return Either::B(peer);
                    }
                    _ => {
                        println!("Other Request");
                    }
                }
                return Either::A(future::ok(()));
            } else {
                return Either::A(future::ok(()));
            }
        })
        .map_err(|e| {
            println!("Connection Error {:?}", e);
        });
    tokio::spawn(connection);
}

pub fn run(args: Vec<String>) -> Result<(), Box<std::error::Error>> {
    let srv = Arc::new(Mutex::new(Server::new()));
    let addr = args[2]
        .to_socket_addrs()
        .unwrap()
        .next()
        .expect("could not parse address");
    let socket = TcpListener::bind(&addr)?;
    let server = socket
        .incoming()
        .for_each(move |socket| {
            process_socket(socket, srv.clone());
            Ok(())
        })
        .map_err(|err| {
            println!("Accept error = {:?}", err);
        });
    println!("Server Running on {:?}", &addr);
    tokio::run(server);
    Ok(())
}
