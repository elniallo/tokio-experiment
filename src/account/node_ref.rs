use common::{Encode, EncodingError, Proto};
use serialization::state::NodeRef as ProtoNodeRef;

use protobuf::Message as ProtoMessage;

#[derive(Clone, Debug, PartialEq)]
pub struct NodeRef {
    pub address: Option<Vec<u8>>,
    pub child: Option<Vec<u8>>,
}

impl NodeRef {
    pub fn new(address: Option<Vec<u8>>, child: Option<Vec<u8>>) -> NodeRef {
        NodeRef { address, child }
    }

    pub fn decode(proto_node_ref: ProtoNodeRef) -> NodeRef {
        let addr_slice = proto_node_ref.address;
        let child = proto_node_ref.child;

        NodeRef::new(Some(addr_slice), Some(child))
    }
}

impl Proto<EncodingError> for NodeRef {
    type ProtoType = ProtoNodeRef;
    fn to_proto(&self) -> Result<Self::ProtoType, EncodingError>
    where
        Self::ProtoType: ProtoMessage,
    {
        let mut proto_node_ref = ProtoNodeRef::new();
        match self.address {
            Some(ref addr_slice) => proto_node_ref.set_address(addr_slice.to_vec()),
            None => {}
        }
        match self.child {
            Some(ref child) => proto_node_ref.set_child(child.to_vec()),
            None => {}
        }

        Ok(proto_node_ref)
    }
}

impl Encode<EncodingError> for NodeRef {
    fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        let proto_node_ref = self.to_proto()?;
        match proto_node_ref.write_to_bytes() {
            Ok(data) => Ok(data),
            Err(e) => Err(EncodingError::Proto(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_encodes_like_javascript() {
        let addr_slice = vec![109];
        let child = vec![
            137, 28, 167, 193, 135, 226, 96, 56, 197, 123, 221, 237, 249, 5, 134, 194, 38, 184,
            100, 131, 41, 152, 47, 186, 185, 70, 18, 162, 105, 115, 14, 42,
        ];
        let node_ref = NodeRef::new(Some(addr_slice), Some(child));
        let encoding = node_ref.encode().unwrap();
        let expected_encoding = vec![
            10, 1, 109, 18, 32, 137, 28, 167, 193, 135, 226, 96, 56, 197, 123, 221, 237, 249, 5,
            134, 194, 38, 184, 100, 131, 41, 152, 47, 186, 185, 70, 18, 162, 105, 115, 14, 42,
        ];

        assert_eq!(encoding, expected_encoding);
    }
}
