use crate::serialization::network::Network as ProtoNetwork;
use crate::server::{Decode, Encode, Proto};
use bytes::BytesMut;
use std::error::Error;
pub struct NetworkMessage {}

impl Decode for NetworkMessage {
    type ProtoType = ProtoNetwork;
    fn decode(buffer: &Vec<u8>) -> Result<Self, Box<Error>> {
        Ok(Self {})
    }
}
#[derive(Clone)]
pub struct NetworkManager {}

impl NetworkManager {
    pub fn decode(bytes: &BytesMut) -> Result<NetworkMessage, Box<Error>> {
        NetworkMessage::decode(&bytes.to_vec())
    }
}
