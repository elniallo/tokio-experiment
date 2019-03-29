use bytes::Bytes;
use futures::future::{self, Either};
use futures::stream::Stream;
use futures::sync::mpsc;
use slog::{Drain, Logger};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::timer::Interval;

use crate::consensus::consensus::Consensus;
use crate::consensus::state_processor::StateProcessor;
use crate::consensus::worldstate::WorldState;
use crate::database::block_db::BlockDB;
use crate::database::dbkeys::DBKeys;
use crate::database::state_db::StateDB;
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
    logger: Logger,
}

impl PeerDBFuture {
    pub fn new(
        db: PeerDatabase<SocketAddr, DBPeer>,
        srv: Arc<Mutex<Server>>,
        logger: Logger,
    ) -> Self {
        let interval = Interval::new_interval(Duration::from_millis(30000));
        Self {
            db,
            srv,
            interval,
            logger,
        }
    }
}

impl Future for PeerDBFuture {
    type Item = ();
    type Error = Box<std::error::Error>;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        while let Async::Ready(data) = self.db.poll()? {
            if let Some(addr) = data {
                info!(self.logger, "Address: {:?}", addr);
                let srv_clone = self.srv.clone();
                let logger = self.logger.clone();
                let logger_2 = logger.clone();
                let fut = TcpStream::connect(&addr)
                    .and_then(move |mut stream| {
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
                                error!(logger, "Parsing error: {:?}", e);
                            }
                        }
                        process_socket(stream, srv_clone);
                        Ok(())
                    })
                    .map_err(move |e| warn!(logger_2, "error connecting: {:?}", e));
                tokio::spawn(fut);
            }
        }
        match self.interval.poll() {
            Ok(v) => match v {
                Async::Ready(_) => {
                    let mut get_peers_message = network::GetPeers::new();
                    get_peers_message.set_count(20);
                    let peer_count = self.srv.lock().unwrap().get_peer_count();
                    info!(self.logger, "Peers Count: {}", peer_count);
                    let msg =
                        NetworkMessage::new(Network_oneof_request::getPeers(get_peers_message));
                    let parsed = SocketParser::prepare_packet_default(0, &msg.encode().unwrap());
                    match parsed {
                        Ok(message) => {
                            for tx in self.srv.lock().unwrap().get_peers_mut().values() {
                                tx.unbounded_send(Bytes::from(message.clone()))?;
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
    seen_messages: HashSet<Vec<u8>>,
    seen_message_vec: VecDeque<Vec<u8>>,
    logger: Logger,
}

impl Server {
    pub fn new(
        transmitter: mpsc::UnboundedSender<NotificationType<DBPeer>>,
        logger: Logger,
    ) -> Self {
        Self {
            active_peers: HashMap::new(),
            guid: String::from("MyRustyGuid"),
            version: 14,
            peer_channel: transmitter,
            peer_db: None,
            block_count: 0,
            seen_messages: HashSet::new(),
            seen_message_vec: VecDeque::with_capacity(1000),
            logger,
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
                error!(self.logger, "Error: {:?}", e);
            }
        }
    }

    pub fn remove_peer(&mut self, peer: DBPeer) {
        self.active_peers.remove(peer.get_addr());
        info!(self.logger, "Active Peers: {:?}", self.active_peers.len());
        self.notify_channel(NotificationType::Disconnect(peer));
    }

    pub fn update_peer_db(&mut self, peer_db: PeerDatabase<SocketAddr, DBPeer>) {
        self.peer_db = Some(peer_db)
    }

    pub fn increment_block_count(&mut self) {
        self.block_count += 1;
        info!(self.logger, "Blocks received: {:?}", self.block_count);
    }

    pub fn get_peer_count(&self) -> usize {
        self.active_peers.len()
    }
    pub fn new_data(&mut self, msg: Vec<u8>) -> bool {
        let res = self.seen_messages.insert(msg.clone());
        if res {
            self.seen_message_vec.push_back(msg);
            while self.seen_message_vec.len() >= 1000 {
                if let Some(v) = self.seen_message_vec.pop_front() {
                    self.seen_messages.remove(&v);
                }
            }
        }
        res
    }

    pub fn get_logger(&self) -> &Logger {
        &self.logger
    }
}

pub fn process_socket(socket: TcpStream, server: Arc<Mutex<Server>>) {
    let base = BaseSocket::new(socket);
    let base_logger = server.lock().unwrap().get_logger().clone();
    let logger = base_logger.clone();
    let peer_logger = logger.new(o!());
    let connection = base
        .into_future()
        .map_err(|(e, _)| e)
        .and_then(move |(message, base)| {
            if let Some(msg) = message {
                let (message, route) = &msg[0];
                let parsed = NetworkManager::decode(&message.to_vec()).unwrap();
                match &parsed.message_type {
                    Network_oneof_request::status(v) => {
                        let mut peer = Peer::new(server, base, v.clone(), peer_logger.clone());
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
                            Err(e) => error!(logger, "Error: {}", e),
                        }
                        peer.get_srv()
                            .lock()
                            .unwrap()
                            .notify_channel(NotificationType::Inbound(peer.to_db_type()));
                        return Either::B(peer);
                    }
                    _ => {
                        info!(logger, "Other Request");
                    }
                }
                return Either::A(future::ok(()));
            } else {
                return Either::A(future::ok(()));
            }
        })
        .map_err(move |e| {
            error!(base_logger, "Connection Error {:?}", e);
        });
    tokio::spawn(connection);
}

pub fn run(args: Vec<String>) -> Result<(), Box<std::error::Error>> {
    // Set up logger
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();
    let root_logger = Logger::root(drain, o!("version" => "1.0"));
    info!(root_logger, "Application started");
    // Set up Consensus
    let state_path = PathBuf::from("state");
    let block_path = PathBuf::from("blocks");
    let file_path = PathBuf::from("blockfile");
    let keys = DBKeys::default();
    let mut block_db = BlockDB::new(block_path, file_path, &keys, None).unwrap();
    let state_db = StateDB::new(state_path, None).unwrap();
    let world_state = WorldState::new(state_db, 20).unwrap();
    let state_processor = StateProcessor::new(&mut block_db, world_state);
    let _consensus = Consensus::new(state_processor).unwrap();

    //Set up Blockchain Server
    let (tx, rx) = mpsc::unbounded::<NotificationType<DBPeer>>();
    let srv = Arc::new(Mutex::new(Server::new(tx, root_logger.clone())));

    // Set Up Peer DB
    let cloned = root_logger.clone();
    let peer_db_logger = root_logger.new(o!());
    let peer_database = PeerDatabase::new(rx, peer_db_logger);
    let peer_db =
        PeerDBFuture::new(peer_database, srv.clone(), root_logger.clone()).map_err(move |e| {
            error!(cloned, "Error: {:?}", e);
        });

    // Initialise TCP listener
    let second_clone = root_logger.clone();
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
        .map_err(move |err| {
            error!(root_logger.clone(), "Accept error = {:?}", err);
        });
    info!(second_clone, "Server Running on {:?}", &addr);

    // Pass futures to Tokio Execution environment
    tokio::run(server.join(peer_db).map(|(_, _)| ()));
    Ok(())
}
