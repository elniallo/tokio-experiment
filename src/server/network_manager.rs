use crate::serialization::network::{Network as ProtoNetwork, Network_oneof_request};
use crate::server::{Decode, Encode, Exception, Proto};
use bytes::BytesMut;
use protobuf::{CodedInputStream, Message as ProtoMessage};
use std::error::Error;
pub struct NetworkMessage {}

impl Decode for NetworkMessage {
    type ProtoType = ProtoNetwork;
    fn decode(buffer: &Vec<u8>) -> Result<Self, Box<Error>> {
        let mut message: ProtoNetwork = ProtoNetwork::new();
        if let Err(_) = message.merge_from(&mut CodedInputStream::from_bytes(buffer.as_slice())) {
            // return Err(Box::new(Exception::new("Decoding fail")));
        }
        if let Some(message_type) = message.request {
            match message_type {
                Network_oneof_request::status(_v) => {
                    println!("Status request");
                }
                _ => {}
            }
        }
        Ok(Self {})
    }
}
#[derive(Clone)]
pub struct NetworkManager {}

impl NetworkManager {
    pub fn decode(bytes: &Vec<u8>) -> Result<NetworkMessage, Box<Error>> {
        NetworkMessage::decode(bytes)
    }
}
