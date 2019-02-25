use std::error::Error;

use crate::account::node_ref::NodeRef;
use crate::serialization::state::NodeRef as ProtoNodeRef;
use crate::serialization::state::StateNode as ProtoStateNode;
use crate::traits::{Decode, Encode, Proto};

use protobuf::{Message as ProtoMessage, RepeatedField};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct StateNode {
    pub node_refs: BTreeMap<Vec<u8>, NodeRef>,
}

impl StateNode {
    pub fn new(node_refs: Vec<NodeRef>) -> StateNode {
        let mut ref_map = BTreeMap::new();
        for node_ref in node_refs {
            ref_map.insert(vec![node_ref.node_location[0]], node_ref);
        }
        StateNode { node_refs: ref_map }
    }
}

impl Decode for StateNode {
    fn decode(buffer: &[u8]) -> Result<StateNode, Box<Error>> {
        let mut data_node = ProtoStateNode::new();
        data_node.merge_from_bytes(buffer)?;
        let mut refs: Vec<NodeRef> = vec![];
        for proto_node_ref in data_node.nodeRefs.into_iter() {
            let r = NodeRef::new(&proto_node_ref.address, &proto_node_ref.child);
            refs.push(r);
        }

        Ok(StateNode::new(refs))
    }
}

impl Proto for StateNode {
    type ProtoType = ProtoStateNode;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_state_node = Self::ProtoType::new();
        let mut proto_node_refs: Vec<ProtoNodeRef> = Vec::with_capacity(self.node_refs.len());
        for node_ref in &self.node_refs {
            match node_ref.1.to_proto() {
                Ok(proto_node_ref) => proto_node_refs.push(proto_node_ref),
                Err(_) => {}
            }
        }
        proto_state_node.set_nodeRefs(RepeatedField::from_vec(proto_node_refs));

        Ok(proto_state_node)
    }
}

impl Encode for StateNode {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_state_node = self.to_proto()?;
        Ok(proto_state_node.write_to_bytes()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_encodes_like_javascript_for_non_zero() {
        // When node_refs is empty
        let empty_vec = vec![];
        let state_node_with_empty_vec = StateNode::new(empty_vec);
        let encoding1 = state_node_with_empty_vec.encode().unwrap();
        let javascript_encoding1: Vec<u8> = vec![];
        assert_eq!(encoding1, javascript_encoding1);

        // When node_refs is not empty
        let addr_slice = vec![109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let child = vec![
            137, 28, 167, 193, 135, 226, 96, 56, 197, 123, 221, 237, 249, 5, 134, 194, 38, 184,
            100, 131, 41, 152, 47, 186, 185, 70, 18, 162, 105, 115, 14, 42,
        ];
        let node_ref = NodeRef::new(&addr_slice, &child);
        let node_refs = vec![node_ref];
        let state_node = StateNode::new(node_refs);
        let encoding2 = state_node.encode().unwrap();
        let javascript_encoding2 = vec![
            10, 56, 10, 20, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 32,
            137, 28, 167, 193, 135, 226, 96, 56, 197, 123, 221, 237, 249, 5, 134, 194, 38, 184,
            100, 131, 41, 152, 47, 186, 185, 70, 18, 162, 105, 115, 14, 42,
        ];
        assert_eq!(encoding2, javascript_encoding2);
    }

    #[test]
    fn it_encodes_like_javascript_for_zero() {
        let addr_slice = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];;
        let child = vec![
            0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0,
            186, 0, 70, 0, 162, 0, 115, 0, 42,
        ];
        let node_ref = NodeRef::new(&addr_slice, &child);
        let node_refs = vec![node_ref];
        let state_node = StateNode::new(node_refs);
        let encoding = state_node.encode().unwrap();
        let javascript_encoding = vec![
            10, 56, 10, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 32, 0,
            28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0,
            186, 0, 70, 0, 162, 0, 115, 0, 42,
        ];
        assert_eq!(encoding, javascript_encoding);
    }
}
