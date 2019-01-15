use crate::protocol::{Decode, Encode, Proto};
use crate::serialization::protocol::Protocol as ProtoProtocol;
use bytes::BytesMut;
use protobuf::Message as ProtoMessage;
use std::error::Error;
use tokio_io::codec::{Decoder, Encoder};
use tokio_proto::TcpServer;

pub struct Protocol {
    pub msg: String,
}

impl Protocol {
    pub fn new() -> Protocol {
        Protocol { msg: String::new() }
    }
}

impl Proto for Protocol {
    type ProtoType = ProtoProtocol;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_message = ProtoProtocol::new();
        proto_message.set_msg(self.msg.clone());
        Ok(proto_message)
    }
}

impl Decoder for Protocol {
    type Item = Protocol;
    type Error = Box<Error>;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Protocol>, Box<Error>> {
        let mut proto_protocol = ProtoProtocol::new();
        proto_protocol.merge_from_bytes(buf)?;
        Ok(Some(Protocol {
            msg: proto_protocol.msg,
        }))
    }
}

impl Encoder for Protocol {
    type Item = Protocol;
    type Error = Box<Error>;

    fn encode(&mut self, protocol: Protocol, buf: &mut BytesMut) -> Result<(), Box<Error>> {
        buf.clear();
        let proto_msg = protocol.to_proto()?;
        let bytes = proto_msg.write_to_bytes()?;
        buf.extend(bytes);
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn it_should_decode_a_buffer() {
        // TODO: actually implement decoding
        let mut msg = Protocol::new();
        let mut bytes = BytesMut::new();
        let buf = [
            10, 19, 73, 32, 99, 97, 110, 32, 101, 110, 99, 111, 100, 101, 32, 109, 121, 115, 101,
            108, 102,
        ];
        bytes.extend_from_slice(buf.as_ref());
        let decoded = &msg.decode(&mut bytes).unwrap();
        match decoded {
            Some(p) => assert_eq!(p.msg, "I can encode myself"),
            None => (),
        }
    }

    #[test]
    fn it_should_encode_to_a_buffer() {
        let mut protocol = Protocol {
            msg: String::from("I can encode myself"),
        };
        let mut bytes = BytesMut::new();
        let mut expected_bytes = BytesMut::new();
        let buf = [
            10, 19, 73, 32, 99, 97, 110, 32, 101, 110, 99, 111, 100, 101, 32, 109, 121, 115, 101,
            108, 102,
        ];
        expected_bytes.extend_from_slice(buf.as_ref());
        let mut man = Protocol::new();
        man.encode(protocol, &mut bytes);
        assert_eq!(bytes, expected_bytes);
    }
}
