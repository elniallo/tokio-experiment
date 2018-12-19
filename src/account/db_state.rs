use std::error::Error;

use account::Account;
use account::node_ref::NodeRef;
use account::state_node::StateNode;
use common::{Decode, Encode, Exception, Proto};
use common::address::Address;
use protobuf::Message as ProtoMessage;
use protobuf::RepeatedField;
use serialization::state::Account as ProtoAccount;
use serialization::state::NodeRef as ProtoNodeRef;
use serialization::state::StateNode as ProtoStateNode;
use serialization::state::{DBState as ProtoDBState, DBState_oneof_state};

#[derive(Clone, Debug, PartialEq)]
pub struct DBState {
    pub account: Option<Account>,
    pub node: Option<StateNode>,
    pub ref_count: u32,
}

impl DBState {
    pub fn new(account: Option<Account>, node: Option<StateNode>, ref_count: u32) -> DBState {
        DBState {
            account: account,
            node: node,
            ref_count: ref_count,
        }
    }
}

impl Decode for DBState {
    type ProtoType = ProtoDBState;
    fn decode(buffer: &Vec<u8>) -> Result<DBState, Box<Error>> {
        let mut proto_db_state = Self::ProtoType::new();
        proto_db_state.merge_from_bytes(buffer)?;
        let mut db_state = DBState::new(None, None, 0);
        let state = match proto_db_state.state {
            Some(state_node) => state_node,
            None => {
                return Err(Box::new(Exception::new("ProtoDBState has no state node")))
            }
        };

        match state {
            DBState_oneof_state::account(data_acc) => {
                db_state.account = Some(Account {
                    balance: data_acc.balance,
                    nonce: data_acc.nonce,
                });
            }
            DBState_oneof_state::node(data_node) => {
                let mut refs: Vec<NodeRef> = vec![];
                for proto_node_ref in data_node.nodeRefs.into_iter() {
                    let mut address = [0;20];
                    address.clone_from_slice(&proto_node_ref.address);
                    let r = NodeRef::new(&address, &proto_node_ref.child);     
                    refs.push(r);
                }
                db_state.node = Some(StateNode { node_refs: refs });
            }
        }
        db_state.ref_count = proto_db_state.refCount;

        Ok(db_state)
    }
}

impl Proto for DBState {
    type ProtoType = ProtoDBState;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut data = Self::ProtoType::new();
        match &self.account {
            Some(account) => {
                let mut proto_account = ProtoAccount::new();
                proto_account.set_balance(account.balance);
                proto_account.set_nonce(account.nonce);
                data.set_account(proto_account);
            }
            None => (),
        }

        match &self.node {
            Some(_node) => {
                let mut proto_state_node = ProtoStateNode::new();

                let mut proto_refs: Vec<ProtoNodeRef> = vec![];
                // fill the data
                match &self.node {
                    Some(data) => for tmp in &data.node_refs {
                        proto_refs.push(tmp.to_proto().unwrap());
                    },
                    None => (),
                }
                let refs = RepeatedField::from(proto_refs);
                proto_state_node.set_nodeRefs(refs);
                data.set_node(proto_state_node);
            }
            None => (),
        }

        data.refCount = self.ref_count;

        Ok(data)
    }
}

impl Encode for DBState {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_db_state = self.to_proto()?;

        Ok(proto_db_state.write_to_bytes()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_makes_a_dbstate() {
        let account = Account::new(10, 20);
        let dbstate = DBState::new(Some(account.clone()), None, 0);
        assert_eq!(dbstate.account, Some(account.clone()));
    }

    #[test]
    fn it_encodes_like_javascript_for_non_zero() {
        let addr_slice = [109,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let child = vec![
            137, 28, 167, 193, 135, 226, 96, 56, 197, 123, 221, 237, 249, 5, 134, 194, 38, 184,
            100, 131, 41, 152, 47, 186, 185, 70, 18, 162, 105, 115, 14, 42,
        ];
        let state_node = StateNode::new(vec![NodeRef::new(&addr_slice,&child)]);
        let dbstate: DBState = DBState::new(None, Some(state_node), 1);
        let encoding = dbstate.encode().unwrap();
        let javascript_encoding = vec![
            24, 1, 18, 58, 10, 56, 10, 20, 109,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 18, 32, 137, 28, 167, 193, 135, 226, 96, 56, 197,
            123, 221, 237, 249, 5, 134, 194, 38, 184, 100, 131, 41, 152, 47, 186, 185, 70, 18,
            162, 105, 115, 14, 42
        ];
        let decoding = DBState::decode(&encoding).unwrap();
        assert_eq!(encoding, javascript_encoding);
        assert_eq!(decoding.account, dbstate.account);
        assert_eq!(decoding.node, dbstate.node);
        assert_eq!(decoding.ref_count, dbstate.ref_count);
    }

    #[test]
    fn it_encodes_like_javascript_for_zero() {
        let addr_slice = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let child = vec![
            0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0,
            186, 0, 70, 0, 162, 0, 115, 0, 42,
        ];
        let state_node = StateNode::new(vec![NodeRef::new(&addr_slice, &child)]);
        let dbstate: DBState = DBState::new(None, Some(state_node), 0);
        let encoding = dbstate.encode().unwrap();
        let javascript_encoding = vec![
            24, 0, 18, 58, 10, 56, 10, 20, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 18, 32, 0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237,
            0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0, 186, 0, 70, 0, 162, 0, 115, 0, 42
        ];
        let decoding = DBState::decode(&encoding).unwrap();
        assert_eq!(encoding, javascript_encoding);
        assert_eq!(decoding.account, dbstate.account);
        assert_eq!(decoding.node, dbstate.node);
        assert_eq!(decoding.ref_count, dbstate.ref_count);
    }
}
