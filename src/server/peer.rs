use bytes::Bytes;
use futures::sync::mpsc;
use futures::Future;
use slog::Logger;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::prelude::*;
use tokio::timer::{DelayQueue, Interval};

use crate::common::block::Block;
use crate::common::block_status::BlockStatus;
use crate::consensus::consensus::HyconConsensus;
use crate::serialization::network::{self, Network_oneof_request};
use crate::server::base_socket::BaseSocket;
use crate::server::network_manager::{NetworkManager, NetworkMessage};
use crate::server::peer_database::DBPeer;
use crate::server::server::{NotificationType, Server};
use crate::traits::{Encode, Exception, Proto, ToDBType};
use crate::util::hash::hash;

type IntervalStream = tokio::timer::Interval;

type Rx = mpsc::UnboundedReceiver<Bytes>;
#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus {
    Disconnected,
    Connected(crate::serialization::network::Status),
}

pub struct Peer {
    remote_height: u32,
    reply_id: u32,
    reply_map: DelayQueue<u32>,
    key_map: HashMap<u32, tokio::timer::delay_queue::Key>,
    addr: SocketAddr,
    srv: Arc<Mutex<Server>>,
    socket: BaseSocket,
    receiver: Rx,
    status: PeerStatus,
    logger: Logger,
    interval: IntervalStream,
}

impl Peer {
    pub fn new(
        srv: Arc<Mutex<Server>>,
        socket: BaseSocket,
        status: crate::serialization::network::Status,
        logger: Logger,
    ) -> Self {
        let reply_id = 2u32.pow(30);
        let reply_map = DelayQueue::new();
        let key_map = HashMap::new();
        let (tx, rx) = mpsc::unbounded();
        let addr = socket.get_socket().peer_addr().unwrap().ip();
        let peer_addr = SocketAddr::new(addr, status.get_port() as u16);
        srv.lock().unwrap().get_peers_mut().insert(peer_addr, tx);
        info!(logger, "Peer Connected: {:?}", &status);
        let interval = Interval::new(
            Instant::now() + Duration::from_millis(5000),
            Duration::from_millis(1000),
        );
        Self {
            remote_height: 0u32,
            reply_id,
            reply_map,
            key_map,
            addr: peer_addr,
            srv,
            socket: socket,
            receiver: rx,
            status: PeerStatus::Connected(status),
            logger,
            interval,
        }
    }

    pub fn return_status(&self) -> crate::serialization::network::Status {
        let mut status = crate::serialization::network::Status::new();
        status.set_guid(self.srv.lock().unwrap().get_guid().clone());
        status.set_version(self.srv.lock().unwrap().get_version().clone());
        status.set_port(3553);
        status.set_publicPort(3553);
        status.set_networkid("hycon".to_string());
        status
    }

    pub fn get_socket(&mut self) -> &mut BaseSocket {
        &mut self.socket
    }

    pub fn get_addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn get_status(&self) -> &PeerStatus {
        &self.status
    }

    pub fn get_srv(&self) -> Arc<Mutex<Server>> {
        self.srv.clone()
    }

    pub fn get_remote_height(&self) -> &u32 {
        &self.remote_height
    }

    fn update_remote_height(&mut self, new_height: &u32) {
        if new_height > &self.remote_height {
            self.remote_height = *new_height;
        }
    }

    fn get_reply_id(&mut self) -> u32 {
        if self.reply_id == u32::max_value() {
            self.reply_id = 2u32.pow(30);
        }
        self.reply_id += 1;
        self.reply_id - 1
    }

    fn common_search(
        &self,
        remote_height: &u32,
        block_status_header: BlockStatus,
    ) -> Result<u32, Box<Error>> {
        let local_height = self
            .srv
            .lock()
            .map_err(|_| Exception::new("Poison Error"))?
            .get_consensus()
            .get_header_tip_height()?;
        let mut donthave = local_height;
        let have = 600000;
        Ok(local_height)
    }
}

impl Future for Peer {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<(), Self::Error> {
        match self.reply_map.poll().unwrap() {
            Async::Ready(timeout) => {
                if timeout.is_some() {
                    return Ok(Async::Ready(()));
                }
            }
            _ => {}
        }
        match self.receiver.poll().unwrap() {
            Async::Ready(Some(v)) => {
                self.socket.buffer(&v);
                task::current().notify();
            }
            _ => {}
        }
        match self
            .interval
            .poll()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "interval broken"))?
        {
            Async::Ready(_) => {
                let reply = self.get_reply_id();
                let mut tip_message = network::GetTip::new();
                tip_message.set_dummy(1);
                tip_message.set_header(false);
                let net_msg = NetworkMessage::new(Network_oneof_request::getTip(tip_message));
                let key = self.reply_map.insert(reply, Duration::from_secs(4));
                self.key_map.insert(reply, key);
                let bytes = self
                    .socket
                    .get_parser_mut()
                    .prepare_packet(reply, &net_msg.encode().unwrap());
                match bytes {
                    Ok(msg) => {
                        self.socket.buffer(&msg);
                        self.socket.poll_flush()?;
                    }
                    Err(e) => error!(self.logger, "Error: {}", e),
                }
            }
            _ => {}
        }
        let _ = self.socket.poll_flush()?;
        while let Async::Ready(data) = self.socket.poll()? {
            if let Some(messages) = data {
                for (bytes, route) in messages {
                    let msg_vec = hash(&bytes.to_vec(), 32);
                    let parsed = NetworkManager::decode(&bytes.to_vec()).unwrap();
                    match &parsed.message_type {
                        Network_oneof_request::getPeers(_n) => {
                            let mut peer_return = network::GetPeersReturn::new();
                            peer_return.set_success(true);
                            peer_return.set_peers(::protobuf::RepeatedField::from(Vec::new()));
                            let net_msg = NetworkMessage::new(
                                Network_oneof_request::getPeersReturn(peer_return),
                            );
                            let bytes = self
                                .socket
                                .get_parser_mut()
                                .prepare_packet(route, &net_msg.encode().unwrap());
                            match bytes {
                                Ok(msg) => {
                                    self.socket.buffer(&msg);
                                    self.socket.poll_flush()?;
                                }
                                Err(e) => error!(self.logger, "Error: {}", e),
                            }
                        }
                        Network_oneof_request::getPeersReturn(p) => {
                            let mut vec = Vec::with_capacity(p.get_peers().len());
                            for peer in p.get_peers() {
                                let ip: IpAddr = peer.get_host().parse().unwrap();
                                let addr = SocketAddr::new(ip, peer.get_port() as u16);
                                vec.push(DBPeer::from_net_peer(&addr));
                            }
                            if vec.len() > 0 {
                                self.srv
                                    .lock()
                                    .unwrap()
                                    .notify_channel(NotificationType::Peers(vec));
                            }
                        }
                        Network_oneof_request::getTip(_v) => {
                            let height;
                            let hash;
                            let total_work;
                            {
                                height = self
                                    .srv
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::new(io::ErrorKind::Other, "Poison error")
                                    })?
                                    .get_consensus()
                                    .get_block_tip_height()
                                    .unwrap_or(0);
                                hash = self
                                    .srv
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::new(io::ErrorKind::Other, "Poison error")
                                    })?
                                    .get_consensus()
                                    .get_tip_hash()
                                    .map_err(|e| {
                                        io::Error::new(io::ErrorKind::Other, e.to_string())
                                    })?;
                                total_work = self
                                    .srv
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::new(io::ErrorKind::Other, "Poison error")
                                    })?
                                    .get_consensus()
                                    .get_block_tip_total_work()
                                    .unwrap_or(0.0);
                            }
                            let mut tip_return = network::GetTipReturn::new();
                            tip_return.set_height(height as u64);
                            tip_return.set_success(true);
                            tip_return.set_hash(hash);
                            tip_return.set_totalwork(total_work);
                            let net_msg = NetworkMessage::new(Network_oneof_request::getTipReturn(
                                tip_return,
                            ));
                            let bytes = self
                                .socket
                                .get_parser_mut()
                                .prepare_packet(route, &net_msg.encode().unwrap());
                            match bytes {
                                Ok(msg) => {
                                    self.socket.buffer(&msg);
                                    self.socket.poll_flush()?;
                                }
                                Err(e) => error!(self.logger, "Error: {}", e),
                            }
                        }
                        Network_oneof_request::getTipReturn(tip) => {
                            self.update_remote_height(&(tip.height as u32));
                            // Cancel timeout reply received
                            if let Some(key) = &self.key_map.get(&route) {
                                self.reply_map.remove(key);
                            }
                            self.key_map.remove(&route);
                        }
                        Network_oneof_request::putBlock(block) => {
                            let mut put_block_return = network::PutBlockReturn::new();
                            put_block_return
                                .set_statusChanges(::protobuf::RepeatedField::from(Vec::new()));
                            let net_msg = NetworkMessage::new(
                                Network_oneof_request::putBlockReturn(put_block_return),
                            );
                            let bytes = self
                                .socket
                                .get_parser_mut()
                                .prepare_packet(route, &net_msg.encode().unwrap());
                            match bytes {
                                Ok(msg) => {
                                    self.socket.buffer(&msg);
                                    self.socket.poll_flush()?;
                                }
                                Err(e) => error!(self.logger, "Error: {}", e),
                            }
                            if self.srv.lock().unwrap().new_data(msg_vec) {
                                self.srv.lock().unwrap().increment_block_count();
                                for block in block.clone().take_blocks().into_iter() {
                                    match self
                                        .srv
                                        .lock()
                                        .unwrap()
                                        .process_block(&Block::from_proto(&block).unwrap())
                                    {
                                        Ok(_) => {}
                                        Err(e) => {
                                            error!(self.logger, "Header Processing Error: {:?}", e)
                                        }
                                    }
                                }
                                info!(self.logger, "Block Received: {:?}", &block);
                            }
                        }
                        Network_oneof_request::putBlockReturn(_) => {
                            info!(self.logger, "Put block return");
                        }
                        Network_oneof_request::getTxs(_txs) => {
                            info!(self.logger, "Get Txs");
                        }
                        Network_oneof_request::getTxsReturn(_) => {
                            info!(self.logger, "get txs return");
                        }
                        Network_oneof_request::getHash(_h) => {
                            info!(self.logger, "Get Hash");
                        }
                        Network_oneof_request::getHashReturn(_h) => {
                            info!(self.logger, "Get hash return");
                        }
                        Network_oneof_request::getBlockTxs(_) => {
                            info!(self.logger, "Get block txs");
                        }
                        Network_oneof_request::getBlockTxsReturn(_) => {
                            info!(self.logger, "get block txs return");
                        }
                        Network_oneof_request::status(_) => {
                            info!(self.logger, "status");
                        }
                        Network_oneof_request::statusReturn(_) => {
                            info!(self.logger, "status return");
                        }
                        Network_oneof_request::getBlocksByHash(_) => {
                            info!(self.logger, "get blocks by hash");
                        }
                        Network_oneof_request::getBlocksByHashReturn(_) => {
                            info!(self.logger, "Get blocks by hash return");
                        }
                        Network_oneof_request::getBlocksByRange(_) => {
                            info!(self.logger, "Get blocks by range");
                        }
                        Network_oneof_request::getBlocksByRangeReturn(_) => {
                            info!(self.logger, "get blocks by range return");
                        }
                        Network_oneof_request::getHeadersByHash(_) => {
                            info!(self.logger, "get headers by hash");
                        }
                        Network_oneof_request::getHeadersByHashReturn(_) => {
                            info!(self.logger, "get headers by hash return");
                        }
                        Network_oneof_request::getHeadersByRange(_) => {
                            info!(self.logger, "Get headers by range");
                        }
                        Network_oneof_request::getHeadersByRangeReturn(_) => {
                            info!(self.logger, "Get Headers by range return");
                        }
                        Network_oneof_request::ping(_) => {
                            info!(self.logger, "Ping");
                        }
                        Network_oneof_request::pingReturn(_) => {
                            info!(self.logger, "Ping return");
                        }
                        Network_oneof_request::putHeaders(_) => {
                            info!(self.logger, "put headers");
                        }
                        Network_oneof_request::putHeadersReturn(_) => {
                            info!(self.logger, "put headers return");
                        }
                        Network_oneof_request::putTx(_) => {
                            let mut put_tx_return = network::PutTxReturn::new();
                            put_tx_return.set_success(true);
                            let net_msg = NetworkMessage::new(Network_oneof_request::putTxReturn(
                                put_tx_return,
                            ));
                            let bytes = self
                                .socket
                                .get_parser_mut()
                                .prepare_packet(route, &net_msg.encode().unwrap());
                            match bytes {
                                Ok(msg) => {
                                    self.socket.buffer(&msg);
                                    self.socket.poll_flush()?;
                                }
                                Err(e) => error!(self.logger, "Error: {}", e),
                            }
                        }
                        Network_oneof_request::putTxReturn(_) => {
                            info!(self.logger, "put tx return");
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

impl ToDBType<DBPeer> for Peer {
    fn to_db_type(&self) -> DBPeer {
        let peer = DBPeer::from_peer(self);
        peer
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        {
            self.srv
                .lock()
                .unwrap()
                .remove_peer(self.to_db_type().clone());
        }
        error!(self.logger, "Socket Dropped: {:?}", &self.status);
    }
}
