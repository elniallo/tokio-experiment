use crate::account::db_state::DBState;
use crate::account::node_ref::NodeRef;
use crate::account::state_node::StateNode;
use crate::traits::Encode;
use crate::util::hash::hash;
use std::sync::mpsc::Sender;

use futures::future::Future;
use std::error::Error;
use tokio::prelude::*;
pub struct TreeNode {
    node: StateNode,
    location: Vec<u8>,
    futures: Vec<TreeNode>,
    tx: Sender<(Vec<u8>, DBState)>,
}

impl TreeNode {
    fn new(node: StateNode, location: Vec<u8>, tx: Sender<(Vec<u8>, DBState)>) -> Self {
        Self {
            node,
            location,
            futures: Vec::new(),
            tx,
        }
    }
}

impl Future for TreeNode {
    type Item = NodeRef;
    type Error = Box<Error>;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut removal_vec = Vec::with_capacity(self.futures.len());
        for (index, node) in &mut self.futures.iter_mut().enumerate() {
            if let Async::Ready(node_ref) = node.poll()? {
                // Node subtree has finished operation
                self.node
                    .node_refs
                    .insert(node_ref.node_location[0], node_ref);
                removal_vec.push(index);
            }
        }
        while removal_vec.len() > 0 {
            if let Some(index) = removal_vec.pop() {
                self.futures.remove(index);
            }
        }
        if self.futures.len() == 0 {
            let node_hash = hash(&self.node.encode()?, 32);
            let db_state = DBState::new(None, Some(self.node.clone()), 1);
            let node_ref = NodeRef::new(&self.location, &node_hash);
            self.tx.send((node_hash, db_state))?;
            return Ok(Async::Ready(node_ref));
        }
        Ok(Async::NotReady)
    }
}
