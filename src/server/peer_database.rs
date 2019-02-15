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
#[derive(Clone)]
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

    fn get_mut_fail_count(&mut self) -> &mut usize {
        &mut self.fail_count
    }

    fn set_status(&mut self, status: PeerStatus) {
        self.status = status
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
    fn get(&self, key: SocketAddr) -> Option<DBPeer> {
        if let Some(t) = self.db.get(&key) {
            return Some(t.clone());
        } else {
            None
        }
    }

    fn get_all(&self) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let _ = self.db.values().map(|v| vec.push(v.clone()));
        if vec.len() > 0 {
            Some(vec)
        } else {
            None
        }
    }

    fn get_multiple(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::with_capacity(limit);
        let mut db_iter = self.db.iter();
        for _ in 0..limit {
            if let Some((_, v)) = db_iter.next() {
                vec.push(v.clone());
            } else {
                if vec.len() > 0 {
                    return Some(vec);
                } else {
                    break;
                }
            }
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

    fn connection_failure(&mut self, key: SocketAddr) -> Result<(), Box<Error>> {
        if let Some(peer) = self.db.get_mut(&key) {
            let x = peer.get_mut_fail_count();
            *x += 1;
        }
        Ok(())
    }

    fn disconnect(&mut self, key: SocketAddr) {
        if let Some(peer) = self.db.get_mut(&key) {
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
        let _ = self.db.values().map(|v| vec.push(v.clone()));
        vec.sort_by(|a, b| a.last_seen.cmp(&b.last_seen));
        if vec.len() > 0 {
            if vec.len() < limit {
                return Some(vec);
            } else {
                return Some(vec.split_off(limit));
            }
        }
        None
    }

    fn get_seen(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let _ = self.db.values().map(|v| vec.push(v.clone()));
        vec.retain(|v| v.last_seen != 0);
        vec.sort_by(|a, b| a.last_seen.cmp(&b.last_seen));
        if vec.len() > 0 {
            if vec.len() < limit {
                return Some(vec);
            } else {
                return Some(vec.split_off(limit));
            }
        }
        None
    }

    fn get_oldest(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let _ = self.db.values().map(|v| vec.push(v.clone()));
        vec.sort_by(|a, b| a.last_seen.cmp(&b.last_seen).reverse());
        if vec.len() > 0 {
            if vec.len() < limit {
                return Some(vec);
            } else {
                return Some(vec.split_off(limit));
            }
        }
        None
    }

    fn get_random(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        let _ = self.db.values().map(|v| vec.push(v.clone()));
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
    use std::str::FromStr;
    #[test]
    fn it_inserts_and_retrieves_a_peer() {
        let mut peer_db = PeerDatabase::new();
        let socket_addr = SocketAddr::from_str("127.0.0.1:8148");
    }
}
