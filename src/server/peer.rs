use bytes::Bytes;
use futures::sync::mpsc;
use futures::Future;
use slog::Logger;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio::prelude::*;

use crate::common::block::Block;
use crate::serialization::network::{self, Network_oneof_request};
use crate::server::base_socket::BaseSocket;
use crate::server::network_manager::{NetworkManager, NetworkMessage};
use crate::server::peer_database::DBPeer;
use crate::server::server::{NotificationType, Server};
use crate::traits::{Encode, ToDBType};
use crate::util::hash::hash;

type Rx = mpsc::UnboundedReceiver<Bytes>;
#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus {
    Disconnected,
    Connected(crate::serialization::network::Status),
}
pub struct Peer {
    addr: SocketAddr,
    srv: Arc<Mutex<Server>>,
    socket: BaseSocket,
    receiver: Rx,
    status: PeerStatus,
    logger: Logger,
}

impl Peer {
    pub fn new(
        srv: Arc<Mutex<Server>>,
        socket: BaseSocket,
        status: crate::serialization::network::Status,
        logger: Logger,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let addr = socket.get_socket().peer_addr().unwrap().ip();
        let peer_addr = SocketAddr::new(addr, status.get_port() as u16);
        srv.lock().unwrap().get_peers_mut().insert(peer_addr, tx);
        info!(logger, "Peer Connected: {:?}", &status);
        Self {
            addr: peer_addr,
            srv,
            socket: socket,
            receiver: rx,
            status: PeerStatus::Connected(status),
            logger,
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
}

impl Future for Peer {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<(), Self::Error> {
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
                        Network_oneof_request::getTipReturn(_) => {
                            info!(self.logger, "get tip return");
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
                                info!(self.logger, "Block Received: {:?}", block);
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
