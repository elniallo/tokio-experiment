use crate::serialization::network::{Network as ProtoNetwork, Network_oneof_request};
use crate::traits::{Decode, Encode, Exception, Proto};
use protobuf::{CodedInputStream, Message as ProtoMessage};
use std::error::Error;
pub struct NetworkMessage {
    pub message_type: Network_oneof_request,
}

impl NetworkMessage {
    pub fn new(message_type: Network_oneof_request) -> Self {
        Self { message_type }
    }
}

impl Decode for NetworkMessage {
    fn decode(buffer: &[u8]) -> Result<Self, Box<Error>> {
        let mut message: ProtoNetwork = ProtoNetwork::new();
        if let Err(_) = message.merge_from(&mut CodedInputStream::from_bytes(buffer)) {
            // return Err(Box::new(Exception::new("Decoding fail")));
        }
        if let Some(message_type) = message.request {
            return Ok(Self { message_type });
        }
        Err(Box::new(Exception::new("Decode Failed")))
    }
}

impl Encode for NetworkMessage {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_message = self.to_proto()?;
        Ok(proto_message.write_to_bytes()?)
    }
}

impl Proto for NetworkMessage {
    type ProtoType = ProtoNetwork;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_message = Self::ProtoType::new();
        match self.message_type.clone() {
            Network_oneof_request::status(v) => {
                proto_message.set_status(v);
            }
            Network_oneof_request::statusReturn(v) => {
                proto_message.set_statusReturn(v);
            }
            Network_oneof_request::getPeersReturn(p) => {
                proto_message.set_getPeersReturn(p);
            }
            Network_oneof_request::getTipReturn(t) => {
                proto_message.set_getTipReturn(t);
            }
            Network_oneof_request::getPeers(n) => {
                proto_message.set_getPeers(n);
            }
            Network_oneof_request::putTxReturn(t) => {
                proto_message.set_putTxReturn(t);
            }
            Network_oneof_request::putBlockReturn(b) => {
                proto_message.set_putBlockReturn(b);
            }
            _ => {}
        }
        Ok(proto_message)
    }
}
#[derive(Clone)]
pub struct NetworkManager {}

impl NetworkManager {
    pub fn decode(bytes: &Vec<u8>) -> Result<NetworkMessage, Box<Error>> {
        NetworkMessage::decode(bytes)
    }
}
