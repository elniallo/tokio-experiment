use crate::server::peer::{Peer, PeerStatus};
use crate::traits::PeerDB;
use rand::seq::sample_iter;
use rand::thread_rng;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;

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
    fn get_fail_count(&self) -> &usize {
        &self.fail_count
    }
    fn get_mut_fail_count(&mut self) -> &mut usize {
        &mut self.fail_count
    }
    fn get_status(&self) -> &PeerStatus {
        &self.status
    }

    fn set_status(&mut self, status: PeerStatus) {
        self.status = status
    }

    fn get_addr(&self) -> &SocketAddr {
        &self.addr
    }
    fn get_last_seen(&self) -> &usize {
        &self.last_seen
    }

    fn get_last_attempt(&self) -> &usize {
        &self.last_attempt
    }
}

pub struct PeerDatabase<SocketAddr, DBPeer> {
    db: HashMap<SocketAddr, DBPeer>,
}

impl PeerDatabase<SocketAddr, DBPeer> {
    pub fn new() -> Self {
        Self { db: HashMap::new() }
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
        self.db.insert(key, value);
        Ok(())
    }

    fn outbound_connection(&mut self, key: SocketAddr, value: DBPeer) -> Result<(), Box<Error>> {
        self.db.insert(key, value);
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
    fn it_inserts_and_retrieves_a_peer() {
        let mut peer_db = PeerDatabase::new();
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
        assert_eq!(Some(db_peer), peer_db.get(&socket_addr));
    }
    #[test]
    fn it_inserts_multiple_peers() {
        let mut peer_db = PeerDatabase::new();
        let peers = peer_factory(20, false, true);
        peer_db.put_multiple(peers);
        assert_eq!(peer_db.db.len(), 20);
    }
    #[test]
    fn it_returns_all_peers() {
        let mut peer_db = PeerDatabase::new();
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
        let mut peer_db = PeerDatabase::new();
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
        let mut peer_db = PeerDatabase::new();
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
        let mut peer_db = PeerDatabase::new();
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
        let mut peer_db = PeerDatabase::new();
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
        let mut peer_db = PeerDatabase::new();
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
        let mut peer_db = PeerDatabase::new();
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
        let mut peer_db = PeerDatabase::new();
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
