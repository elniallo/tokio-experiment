use crate::account::db_state::DBState;
use crate::account::node_ref::NodeRef;
use crate::account::state_node::StateNode;
use crate::traits::Encode;
use crate::util::hash::hash;
use std::sync::mpsc::Sender;

use futures::future::Future;
use std::error::Error;
use tokio::prelude::*;

#[derive(Clone, Debug)]
pub struct TreeNode {
    node: StateNode,
    location: Vec<u8>,
    futures: Vec<TreeNode>,
    tx: Sender<(Vec<u8>, DBState)>,
}

impl TreeNode {
    pub fn new(node: StateNode, location: Vec<u8>, tx: Sender<(Vec<u8>, DBState)>) -> Self {
        Self {
            node,
            location,
            futures: Vec::new(),
            tx,
        }
    }

    fn add_future(&mut self, tree_node: TreeNode) {
        self.futures.push(tree_node);
    }

    pub fn get_next_node_location(&self, key: u8) -> Option<&NodeRef> {
        if let Some(node_ref) = self.node.node_refs.get(&key) {
            Some(&node_ref)
        } else {
            None
        }
    }

    pub fn get_node(&self) -> &StateNode {
        &self.node
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::account::db_state::DBState;
    use std::sync::mpsc::channel;
    #[test]
    fn it_awaits_on_an_inner_future() {
        let (tx, rx) = channel::<(Vec<u8>, DBState)>();
        let node_ref_location = vec![0];
        let node_ref_child = vec![2];
        let node_ref = NodeRef::new(&node_ref_location, &node_ref_child);
        let state_node = StateNode::new(vec![node_ref]);
        let mut root_tree_node = TreeNode::new(state_node.clone(), vec![0], tx.clone());
        let second_tree_node = TreeNode::new(state_node.clone(), vec![1], tx.clone());
        root_tree_node.add_future(second_tree_node);
        let result = root_tree_node.wait();
        match result {
            Ok(_node) => {
                let mut results = Vec::new();
                results.push(rx.recv().unwrap());
                results.push(rx.recv().unwrap());
                assert_eq!(results.len(), 2);
            }
            Err(e) => {
                println!("Error: {:?}", e);
                unimplemented!()
            }
        }
    }
}
