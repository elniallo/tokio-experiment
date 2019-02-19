use bytes::Bytes;
use futures::future::{self, Either};
use futures::stream::Stream;
use futures::sync::mpsc;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::timer::Interval;

use crate::serialization::network::{self, Network_oneof_request};
use crate::server::base_socket::BaseSocket;
use crate::server::network_manager::{NetworkManager, NetworkMessage};
use crate::server::peer::Peer;
use crate::server::peer_database::{DBPeer, PeerDatabase};
use crate::server::socket_parser::SocketParser;
use crate::traits::{Encode, ToDBType};
pub enum NotificationType<T> {
    Inbound(T),
    Disconnect(T),
    Peers(Vec<T>),
}
type Tx = mpsc::UnboundedSender<Bytes>;

pub struct PeerDBFuture {
    db: PeerDatabase<SocketAddr, DBPeer>,
    srv: Arc<Mutex<Server>>,
    interval: Interval,
}

impl PeerDBFuture {
    pub fn new(db: PeerDatabase<SocketAddr, DBPeer>, srv: Arc<Mutex<Server>>) -> Self {
        let interval = Interval::new_interval(Duration::from_millis(30000));
        Self { db, srv, interval }
    }
}

impl Future for PeerDBFuture {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        while let Async::Ready(data) = self.db.poll()? {
            if let Some(addr) = data {
                println!("Address: {:?}", addr);
                let srv_clone = self.srv.clone();
                let fut = TcpStream::connect(&addr)
                    .and_then(|mut stream| {
                        let mut get_status_message = network::Status::new();
                        get_status_message.set_guid(srv_clone.lock().unwrap().get_guid().clone());
                        get_status_message
                            .set_version(srv_clone.lock().unwrap().get_version().clone());
                        get_status_message.set_port(3553);
                        get_status_message.set_publicPort(3553);
                        get_status_message.set_networkid("hycon".to_string());
                        let msg =
                            NetworkMessage::new(Network_oneof_request::status(get_status_message));
                        let parsed =
                            SocketParser::prepare_packet_default(0, &msg.encode().unwrap());
                        match parsed {
                            Ok(message) => {
                                stream.poll_write(&message).unwrap();
                            }
                            Err(e) => {
                                println!("Parsing error: {:?}", e);
                            }
                        }
                        process_socket(stream, srv_clone);
                        Ok(())
                    })
                    .map_err(|e| println!("error connecting: {:?}", e));
                tokio::spawn(fut);
            }
        }
        match self.interval.poll() {
            Ok(v) => match v {
                Async::Ready(_) => {
                    let mut get_peers_message = network::GetPeers::new();
                    get_peers_message.set_count(20);
                    let msg =
                        NetworkMessage::new(Network_oneof_request::getPeers(get_peers_message));
                    let parsed = SocketParser::prepare_packet_default(0, &msg.encode().unwrap());
                    match parsed {
                        Ok(message) => {
                            for tx in self.srv.lock().unwrap().get_peers_mut().values() {
                                tx.unbounded_send(Bytes::from(message.clone()));
                            }
                        }
                        Err(e) => {
                            println!("Parsing error: {:?}", e);
                        }
                    }
                }
                Async::NotReady => {}
            },
            Err(e) => {
                println!("Interval Error: {:?}", e);
            }
        }
        Ok(Async::NotReady)
    }
}
pub struct Server {
    active_peers: HashMap<SocketAddr, Tx>,
    guid: String,
    version: u32,
    peer_channel: mpsc::UnboundedSender<NotificationType<DBPeer>>,
    peer_db: Option<PeerDatabase<SocketAddr, DBPeer>>,
    block_count: usize,
}

impl Server {
    pub fn new(transmitter: mpsc::UnboundedSender<NotificationType<DBPeer>>) -> Self {
        Self {
            active_peers: HashMap::new(),
            guid: String::from("MyRustyGuid"),
            version: 14,
            peer_channel: transmitter,
            peer_db: None,
            block_count: 0,
        }
    }

    pub fn get_peers_mut(&mut self) -> &mut HashMap<SocketAddr, Tx> {
        &mut self.active_peers
    }

    pub fn get_guid(&self) -> &String {
        &self.guid
    }
    pub fn get_version(&self) -> &u32 {
        &self.version
    }

    pub fn notify_channel(&self, msg: NotificationType<DBPeer>) {
        let res = self.peer_channel.unbounded_send(msg);
        match res {
            Ok(_) => {}
            Err(e) => {
                println!("Error: {:?}", e);
            }
        }
    }

    pub fn remove_peer(&mut self, peer: DBPeer) {
        self.active_peers.remove(peer.get_addr());
        println!("Active Peers: {:?}", self.active_peers.len());
        self.notify_channel(NotificationType::Disconnect(peer));
    }

    pub fn update_peer_db(&mut self, peer_db: PeerDatabase<SocketAddr, DBPeer>) {
        self.peer_db = Some(peer_db)
    }

    pub fn increment_block_count(&mut self) {
        self.block_count += 1;
        println!("Blocks received: {:?}", self.block_count);
    }
}

pub fn process_socket(socket: TcpStream, server: Arc<Mutex<Server>>) {
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
                            .get_socket()
                            .get_parser_mut()
                            .prepare_packet(*route, &net_msg.encode().unwrap());
                        match bytes {
                            Ok(msg) => {
                                peer.get_socket().buffer(&msg);
                            }
                            Err(e) => println!("Error: {}", e),
                        }
                        peer.get_srv()
                            .lock()
                            .unwrap()
                            .notify_channel(NotificationType::Inbound(peer.to_db_type()));
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
    let (tx, rx) = mpsc::unbounded::<NotificationType<DBPeer>>();
    let srv = Arc::new(Mutex::new(Server::new(tx)));
    let peer_database = PeerDatabase::new(rx);
    let addr = args[2]
        .to_socket_addrs()
        .unwrap()
        .next()
        .expect("could not parse address");
    let socket = TcpListener::bind(&addr)?;
    let peer_db = PeerDBFuture::new(peer_database, srv.clone()).map_err(|e| {
        println!("Error: {:?}", e);
    });
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
    tokio::run(server.join(peer_db).map(|(_, _)| ()));
    Ok(())
}
