use crate::server::peer::{Peer, PeerStatus};
use crate::traits::PeerDB;
use futures::sync::mpsc;
use rand::seq::sample_iter;
use rand::thread_rng;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io;
use tokio::prelude::*;
use tokio::timer::Interval;

type Rx = mpsc::UnboundedReceiver<DBPeer>;

fn get_current_time() -> usize {
    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH).unwrap().as_millis() as usize
}

enum PeerConnectionType {
    Inbound,
    Outbound,
}
trait DBPeerTrait {
    fn get_fail_count_mut(&mut self) -> &mut usize;
}
#[derive(Clone, PartialEq, Debug)]
pub struct DBPeer {
    addr: SocketAddr,
    status: PeerStatus,
    success_out_count: usize,
    success_in_count: usize,
    last_seen: usize,
    fail_count: usize,
    last_attempt: usize,
}

impl DBPeer {
    pub fn from_peer(peer: &Peer) -> Self {
        let addr = peer.get_addr().clone();
        let status = peer.get_status().clone();
        let (success_in_count, success_out_count, last_seen, fail_count, last_attempt) =
            (0, 0, 0, 0, 0);
        Self {
            addr,
            status,
            success_in_count,
            success_out_count,
            last_seen,
            last_attempt,
            fail_count,
        }
    }
    pub fn get_fail_count(&self) -> &usize {
        &self.fail_count
    }
    pub fn get_mut_fail_count(&mut self) -> &mut usize {
        &mut self.fail_count
    }
    pub fn get_status(&self) -> &PeerStatus {
        &self.status
    }

    pub fn set_status(&mut self, status: PeerStatus) {
        self.status = status
    }

    pub fn get_addr(&self) -> &SocketAddr {
        &self.addr
    }
    pub fn get_last_seen(&self) -> &usize {
        &self.last_seen
    }

    pub fn set_last_seen(&mut self, last_seen: usize) {
        self.last_seen = last_seen
    }

    pub fn get_last_attempt(&self) -> &usize {
        &self.last_attempt
    }

    fn update_success_count(&mut self, connection_type: PeerConnectionType) {
        match connection_type {
            PeerConnectionType::Inbound => {
                self.success_in_count += 1;
            }
            PeerConnectionType::Outbound => {
                self.success_out_count += 1;
            }
        }
    }
}

pub struct PeerDatabase<SocketAddr, DBPeer> {
    db: HashMap<SocketAddr, DBPeer>,
    receiver: Rx,
}

impl PeerDatabase<SocketAddr, DBPeer> {
    pub fn new(rx: Rx) -> Self {
        Self {
            db: HashMap::new(),
            receiver: rx,
        }
    }
}
impl PeerDB<SocketAddr, DBPeer> for PeerDatabase<SocketAddr, DBPeer> {
    fn get(&self, key: &SocketAddr) -> Option<DBPeer> {
        if let Some(t) = self.db.get(key) {
            return Some(t.clone());
        } else {
            None
        }
    }

    fn get_all(&self) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let mut db_iter = self.db.values();
        while let Some(v) = db_iter.next() {
            vec.push(v.clone());
        }
        if vec.len() > 0 {
            Some(vec)
        } else {
            None
        }
    }

    fn get_multiple(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::with_capacity(limit);
        let mut db_iter = self.db.values();
        for _ in 0..limit {
            if let Some(v) = db_iter.next() {
                vec.push(v.clone());
            } else {
                break;
            }
        }
        if vec.len() > 0 {
            return Some(vec);
        }
        None
    }

    fn inbound_connection(&mut self, key: SocketAddr, value: DBPeer) -> Result<(), Box<Error>> {
        if let Some(peer) = self.db.get_mut(&key) {
            peer.set_last_seen(get_current_time());
            peer.update_success_count(PeerConnectionType::Inbound);
        } else {
            let mut peer = value.clone();
            peer.set_last_seen(get_current_time());
            peer.update_success_count(PeerConnectionType::Inbound);
            self.db.insert(key, peer);
        }
        Ok(())
    }

    fn outbound_connection(&mut self, key: SocketAddr, value: DBPeer) -> Result<(), Box<Error>> {
        if let Some(peer) = self.db.get_mut(&key) {
            peer.set_last_seen(get_current_time());
            peer.update_success_count(PeerConnectionType::Outbound);
        } else {
            let mut peer = value.clone();
            peer.set_last_seen(get_current_time());
            peer.update_success_count(PeerConnectionType::Outbound);
            self.db.insert(key, peer);
        }
        Ok(())
    }

    fn connection_failure(&mut self, key: &SocketAddr) -> Result<(), Box<Error>> {
        if let Some(peer) = self.db.get_mut(key) {
            let x = peer.get_mut_fail_count();
            *x += 1;
        }
        Ok(())
    }

    fn disconnect(&mut self, key: &SocketAddr) {
        if let Some(peer) = self.db.get_mut(key) {
            peer.set_status(PeerStatus::Disconnected);
            peer.set_last_seen(get_current_time());
        }
    }

    fn put_multiple(&mut self, values: Vec<(SocketAddr, DBPeer)>) -> Result<(), Box<Error>> {
        for (key, value) in values {
            self.db.insert(key, value);
        }
        Ok(())
    }

    fn get_recent(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let mut db_iter = self.db.values();
        while let Some(peer) = db_iter.next() {
            vec.push(peer.clone());
        }
        vec.sort_by(|a, b| a.last_attempt.cmp(&b.last_attempt).reverse());
        if vec.len() > 0 {
            if vec.len() < limit {
                return Some(vec);
            } else {
                let _ = vec.split_off(limit);
                return Some(vec);
            }
        }
        None
    }

    fn get_seen(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let mut db_iter = self.db.values();
        while let Some(peer) = db_iter.next() {
            vec.push(peer.clone());
        }
        vec.retain(|v| v.last_seen != 0);
        if vec.len() > 0 {
            if vec.len() < limit {
                return Some(vec);
            } else {
                let _ = vec.split_off(limit);
                return Some(vec);
            }
        }
        None
    }

    fn get_oldest(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let mut db_iter = self.db.values();
        while let Some(peer) = db_iter.next() {
            vec.push(peer.clone());
        }
        vec.sort_by(|a, b| a.last_attempt.cmp(&b.last_attempt));
        if vec.len() > 0 {
            if vec.len() < limit {
                return Some(vec);
            } else {
                let _ = vec.split_off(limit);
                return Some(vec);
            }
        }
        None
    }

    fn get_random(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let mut db_iter = self.db.values();
        while let Some(peer) = db_iter.next() {
            vec.push(peer.clone());
        }
        if vec.len() > 0 {
            if vec.len() < limit {
                return Some(vec);
            } else {
                let mut rng = thread_rng();
                let res = sample_iter(&mut rng, vec, limit);
                match res {
                    Ok(v) => {
                        return Some(v);
                    }
                    Err(_) => {
                        return None;
                    }
                }
            }
        }
        None
    }
}

impl Stream for PeerDatabase<SocketAddr, DBPeer> {
    type Item = SocketAddr;
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.receiver.poll().unwrap() {
            Async::Ready(Some(v)) => {
                self.inbound_connection(v.get_addr().clone(), v);
                println!("Incoming Connection");
                task::current().notify();
            }
            _ => {}
        }
        Ok(Async::NotReady)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::Rng;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    /// Creates a `Vec<(SocketAddr, DBPeer)>`.
    ///
    /// * `number:usize` - The number of DBPeers to create
    /// * `ordered:bool` - True if the ordering by last_attempt should be maintained, if false, the parameters will be random
    /// * `seen:bool` - True gives random last_seen values, False sets last_seen to zero
    ///
    /// # Usage
    /// ```rust
    /// let peers = peer_factory(10, false, true);```
    ///    Creates 10 peers with random internals
    ///
    /// ```rust
    /// let peers = peer_factory(10, true, false);```
    ///
    ///    Creates 10 peers with ordered 'last_attempt'
    ///
    /// ```rust
    /// let peers = peer_factory(10, false, false);
    /// ```
    ///    Creates 10 peers with `last_seen=0`
    ///  
    fn peer_factory(number: usize, ordered: bool, seen: bool) -> Vec<(SocketAddr, DBPeer)> {
        let mut vec = Vec::with_capacity(number);
        let mut rng = thread_rng();
        for i in 1..number + 1 {
            let socket_addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, rng.gen::<u8>(), rng.gen::<u8>())),
                rng.gen::<u16>(),
            );
            let mut last_attempt = 0;
            let mut last_seen = 0;
            if ordered {
                last_attempt = i;
            } else {
                last_attempt = rng.gen::<usize>();
            }
            if seen {
                last_seen = rng.gen::<usize>();
            }
            let db_peer = DBPeer {
                addr: socket_addr.clone(),
                status: PeerStatus::Disconnected,
                success_out_count: rng.gen::<usize>(),
                success_in_count: rng.gen::<usize>(),
                last_seen,
                fail_count: rng.gen::<usize>(),
                last_attempt,
            };
            vec.push((socket_addr, db_peer));
        }
        vec
    }
    #[test]
    fn it_inserts_and_retrieves_an_inbound_peer() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let socket_addr = SocketAddr::from_str("127.0.0.1:8148").unwrap();
        let db_peer = DBPeer {
            addr: socket_addr.clone(),
            status: PeerStatus::Disconnected,
            success_out_count: 0,
            success_in_count: 0,
            last_seen: 0,
            fail_count: 0,
            last_attempt: 0,
        };
        peer_db.inbound_connection(socket_addr, db_peer.clone());
        if let Some(peer) = peer_db.get(&socket_addr) {
            assert!(peer.get_last_seen() != &0);
            assert_eq!(peer.success_in_count, 1);
        } else {
            panic!("Couldn't retrieve a peer");
        }
    }

    #[test]
    fn it_inserts_and_retrieves_an_outbound_peer() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let socket_addr = SocketAddr::from_str("127.0.0.1:8148").unwrap();
        let db_peer = DBPeer {
            addr: socket_addr.clone(),
            status: PeerStatus::Disconnected,
            success_out_count: 0,
            success_in_count: 0,
            last_seen: 0,
            fail_count: 0,
            last_attempt: 0,
        };
        peer_db.outbound_connection(socket_addr, db_peer.clone());
        if let Some(peer) = peer_db.get(&socket_addr) {
            assert!(peer.get_last_seen() != &0);
            assert_eq!(peer.success_out_count, 1);
        } else {
            panic!("Couldn't retrieve a peer");
        }
    }

    #[test]
    fn it_inserts_multiple_peers() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let peers = peer_factory(20, false, true);
        peer_db.put_multiple(peers);
        assert_eq!(peer_db.db.len(), 20);
    }
    #[test]
    fn it_returns_all_peers() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let peers = peer_factory(20, false, true);
        let _ = peer_db.put_multiple(peers);
        assert_eq!(peer_db.db.len(), 20);
        if let Some(returned_peers) = peer_db.get_all() {
            assert_eq!(returned_peers.len(), 20);
        } else {
            panic!("No Peers returned")
        }
    }
    #[test]
    fn it_updates_the_fail_count() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let socket_addr = SocketAddr::from_str("127.0.0.1:8148").unwrap();
        let db_peer = DBPeer {
            addr: socket_addr.clone(),
            status: PeerStatus::Disconnected,
            success_out_count: 0,
            success_in_count: 0,
            last_seen: 0,
            fail_count: 0,
            last_attempt: 0,
        };
        peer_db.inbound_connection(socket_addr.clone(), db_peer.clone());
        peer_db.connection_failure(&socket_addr);
        if let Some(peer) = peer_db.get(&socket_addr) {
            assert_ne!(&peer, &db_peer);
            assert_eq!(peer.get_fail_count(), &1);
        } else {
            panic!("Peer Fail Count not Incremented")
        }
    }

    #[test]
    fn it_gets_multiple_peers_or_all_if_limit_exceeds_length() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let peers = peer_factory(20, false, true);
        let _ = peer_db.put_multiple(peers);
        if let Some(returned_peers) = peer_db.get_multiple(10) {
            assert_eq!(returned_peers.len(), 10);
        } else {
            panic!("No Peers returned")
        }
        if let Some(returned_peers) = peer_db.get_multiple(50) {
            assert_eq!(returned_peers.len(), 20);
        } else {
            panic!("No Peers returned")
        }
    }

    #[test]
    fn it_sets_a_peer_to_disconnected() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let socket_addr = SocketAddr::from_str("127.0.0.1:8148").unwrap();
        let db_peer = DBPeer {
            addr: socket_addr.clone(),
            status: PeerStatus::Connected(crate::serialization::network::Status::new()),
            success_out_count: 0,
            success_in_count: 0,
            last_seen: 0,
            fail_count: 0,
            last_attempt: 0,
        };
        peer_db.outbound_connection(socket_addr.clone(), db_peer);
        if let Some(peer) = peer_db.get(&socket_addr) {
            assert_ne!(peer.get_status(), &PeerStatus::Disconnected);
        } else {
            panic!("Peer not found")
        }
        peer_db.disconnect(&socket_addr);
        if let Some(peer) = peer_db.get(&socket_addr) {
            assert_eq!(peer.get_status(), &PeerStatus::Disconnected);
        } else {
            panic!("Peer not found")
        }
    }
    #[test]
    fn it_returns_peers_ordered_by_most_recent() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        // Forced ordered peer generation for easy validation of ordering
        let peers = peer_factory(20, true, true);
        let _ = peer_db.put_multiple(peers.clone());
        let mut expected_result = Vec::with_capacity(5);
        for i in 15..peers.len() {
            let (_, peer) = peers[i].clone();
            expected_result.push(peer);
        }
        expected_result.reverse();

        if let Some(db_peers) = peer_db.get_recent(5) {
            assert_eq!(db_peers, expected_result);
        } else {
            panic!("failed to get any peers");
        }
    }

    #[test]
    fn it_returns_peers_ordered_by_oldest() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        // Forced ordered peer generation for easy validation of ordering
        let peers = peer_factory(20, true, true);
        let _ = peer_db.put_multiple(peers.clone());
        let mut expected_result = Vec::with_capacity(5);
        for i in 0..5 {
            let (_, peer) = peers[i].clone();
            expected_result.push(peer);
        }
        if let Some(db_peers) = peer_db.get_oldest(5) {
            assert_eq!(db_peers, expected_result);
        } else {
            panic!("failed to get any peers");
        }
    }

    #[test]
    fn it_returns_seen_peers() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        // Forced ordered peer generation for easy validation of ordering
        let peers = peer_factory(20, true, true);
        let unseen_peers = peer_factory(20, false, false);
        let _ = peer_db.put_multiple(peers.clone());
        let _ = peer_db.put_multiple(unseen_peers.clone());
        if let Some(peers) = peer_db.get_seen(40) {
            assert_eq!(peers.len(), 20);
        } else {
            panic!("No peers returned")
        }
    }

    #[test]
    fn it_returns_random_peers() {
        let (_, rx) = mpsc::unbounded();
        let mut peer_db = PeerDatabase::new(rx);
        let peers = peer_factory(20, false, true);
        let _ = peer_db.put_multiple(peers);
        if let Some(returned_peers) = peer_db.get_random(10) {
            assert_eq!(returned_peers.len(), 10);
        } else {
            panic!("No Peers returned")
        }
        if let Some(returned_peers) = peer_db.get_multiple(50) {
            assert_eq!(returned_peers.len(), 20);
        } else {
            panic!("No Peers returned")
        }
    }
}
