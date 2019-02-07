use crate::server::Exception;
use byteorder::LittleEndian;
use bytes;
use bytes::ByteOrder;
use futures;
use std::cmp::min;
use std::error::Error;

const HEADER_ROUTE_LENGTH: usize = 4;
const HEADER_POSTFIX_LENGTH: usize = 4;
const HEADER_PREFIX: [u8; 4] = [172, 215, 103, 237];

#[derive(PartialEq, PartialOrd, Debug)]
enum ParseState {
    HeaderPrefix,
    HeaderRoute,
    HeaderBodyLength,
    Body,
}
pub struct SocketParser<T>
where
    T: Send + Sync + Clone,
{
    transmitter: T,
    buffer: Vec<u8>,
    state: ParseState,
    parse_index: usize,
}

impl<T> SocketParser<T>
where
    T: Send + Sync + Clone,
{
    pub fn new(tx: T) -> Self {
        Self {
            transmitter: tx,
            buffer: Vec::new(),
            state: ParseState::HeaderPrefix,
            parse_index: 0,
        }
    }

    pub fn parse(&mut self, bytes: &Vec<u8>) -> Result<(), Box<Error>> {
        let mut new_data_index = 0;
        while new_data_index < bytes.len() {
            match self.state {
                ParseState::HeaderPrefix => {
                    self.parse_header_prefix(bytes, &mut new_data_index)?;
                }
                ParseState::HeaderRoute => {
                    self.parse_header_route(bytes, &mut new_data_index)?;
                }
                ParseState::HeaderBodyLength => {
                    self.parse_body_length(bytes, &mut new_data_index)?;
                }
                ParseState::Body => {
                    self.parse_body(bytes, &mut new_data_index);
                }
            }
        }
        Ok(())
    }
    fn parse_header_prefix(
        &mut self,
        new_data: &Vec<u8>,
        new_data_index: &mut usize,
    ) -> Result<(), Box<Error>> {
        while new_data_index < &mut new_data.len() && self.parse_index < HEADER_PREFIX.len() {
            if new_data[*new_data_index] != HEADER_PREFIX[self.parse_index] {
                return Err(Box::new(Exception::new("Header Prefix Mismatch")));
            } else {
                self.parse_index += 1;
                *new_data_index += 1;
            }
        }
        self.state = ParseState::HeaderRoute;
        Ok(())
    }

    fn parse_header_route(
        &mut self,
        new_data: &Vec<u8>,
        new_data_index: &mut usize,
    ) -> Result<(), Box<Error>> {
        *new_data_index += 4;
        self.state = ParseState::HeaderBodyLength;
        Ok(())
    }

    fn parse_body_length(
        &mut self,
        new_data: &Vec<u8>,
        new_data_index: &mut usize,
    ) -> Result<(), Box<Error>> {
        *new_data_index += 4;
        self.state = ParseState::Body;
        Ok(())
    }

    fn parse_body(
        &mut self,
        new_data: &Vec<u8>,
        new_data_index: &mut usize,
    ) -> Result<(), Box<Error>> {
        while new_data_index < &mut new_data.len() {
            self.buffer.push(new_data[*new_data_index]);
            *new_data_index += 1;
        }
        Ok(())
    }

    fn parse_uint_32_le(&mut self, next_index: &mut usize, new_data: &Vec<u8>) -> Option<u32> {
        let new_bytes_available = new_data.len() - *next_index;
        if self.parse_index == 0 && new_bytes_available >= 4 {
            *next_index += 4;
            return Some(LittleEndian::read_u32(&new_data[0..4]));
        } else {
            let source_end = *next_index + min(new_bytes_available, 4 - self.parse_index);
        }
        None
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use futures::stream::{self, Stream};
    use futures::Future;
    #[derive(Clone)]
    struct Transmitter {}
    impl Transmitter {
        fn new() -> Self {
            Self {}
        }
    }
    unsafe impl Send for Transmitter {}
    unsafe impl Sync for Transmitter {}
    #[test]
    fn it_should_initialise_with_a_trasnsmitter_with_correct_traits() {
        let (tx, _rx): (
            futures::sync::mpsc::UnboundedSender<bytes::BytesMut>,
            futures::sync::mpsc::UnboundedReceiver<bytes::BytesMut>,
        ) = futures::sync::mpsc::unbounded();
        let mut parser = SocketParser::new(tx);
        let bytes1 = vec![172, 215, 103, 237, 0, 0, 0, 64, 60, 0, 0, 0, 10];
        let bytes2 = vec![
            58, 8, 13, 18, 5, 104, 121, 99, 111, 110, 40, 212, 63, 50, 44, 74, 65, 119, 115, 117,
            85, 69, 104, 116, 117, 53, 120, 65, 110, 87, 122, 72, 122, 75, 76, 67, 55, 78, 72, 86,
            86, 85, 87, 97, 57, 70, 83, 77, 69, 54, 69, 88, 97, 104, 97, 103, 113, 52, 122,
        ];
        let expected_out = vec![
            10, 58, 8, 13, 18, 5, 104, 121, 99, 111, 110, 40, 212, 63, 50, 44, 74, 65, 119, 115,
            117, 85, 69, 104, 116, 117, 53, 120, 65, 110, 87, 122, 72, 122, 75, 76, 67, 55, 78, 72,
            86, 86, 85, 87, 97, 57, 70, 83, 77, 69, 54, 69, 88, 97, 104, 97, 103, 113, 52, 122,
        ];
        parser.parse(&bytes1);
        assert_eq!(parser.state, ParseState::Body);
        parser.parse(&bytes2);
        assert_eq!(parser.buffer, expected_out);
    }
    #[test]

    fn it_should_return_an_error_from_a_mismatched_header_prefix() {
        let mut parser = SocketParser::new(Transmitter::new());
        let bytes1 = vec![172, 216, 103, 237, 0, 0, 0, 64, 60, 0, 0, 0, 10];
        let res = parser.parse(&bytes1);
        match res {
            Ok(_) => assert_eq!(1, 2),
            Err(e) => assert_eq!(1, 1),
        }
    }
}
