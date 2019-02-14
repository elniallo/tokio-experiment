use crate::server::peer::{Peer, PeerStatus};
use crate::traits::{PeerDB, ToDBType};
use std::cmp::Eq;
use std::collections::HashMap;
use std::error::Error;
use std::hash::Hash;
use std::marker::PhantomData;
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
}

struct PeerDatabase<Peer, SocketAddr, DBPeer> {
    db: HashMap<String, DBPeer>,
    phantom: PhantomData<Peer>,
    sock: PhantomData<SocketAddr>,
}

impl<Peer, SocketAddr, DBPeer> PeerDatabase<Peer, SocketAddr, DBPeer> {
    fn new() -> Self {
        Self {
            db: HashMap::new(),
            phantom: PhantomData,
            sock: PhantomData,
        }
    }
}
impl PeerDB<Peer, SocketAddr, DBPeer> for PeerDatabase<Peer, SocketAddr, DBPeer> {
    fn get(&self, key: SocketAddr) -> Option<DBPeer> {
        if let Some(t) = self.db.get(&key.to_string()) {
            return Some(t.clone());
        } else {
            None
        }
    }

    fn get_all(&self) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::new();
        self.db.values().map(|v| vec.push(v.clone()));
        if vec.len() > 0 {
            Some(vec)
        } else {
            None
        }
    }

    fn get_multiple(&self, limit: usize) -> Option<Vec<DBPeer>> {
        let mut vec = Vec::with_capacity(limit);
        let mut db_iter = self.db.iter();
        for i in 0..limit {
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

    fn inbound_connection(&mut self, key: SocketAddr, value: Peer) -> Result<(), Box<Error>> {
        self.db.insert(key.to_string(), value.to_db_type()?);
        Ok(())
    }

    fn outbound_connection(&mut self, key: SocketAddr, value: Peer) -> Result<(), Box<Error>> {
        self.db.insert(key.to_string(), value.to_db_type()?);
        Ok(())
    }

    fn connection_failure(&mut self, key: SocketAddr) -> Result<(), Box<Error>> {
        if let Some(peer) = self.db.get_mut(&key.to_string()) {
            let mut x = peer.get_mut_fail_count();
            *x += 1;
        }
        Ok(())
    }
}
