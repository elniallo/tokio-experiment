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
const MAX_PACKET_SIZE: usize = 1024 * 1024;

#[derive(PartialEq, PartialOrd, Debug)]
enum ParseState {
    HeaderPrefix,
    HeaderRoute,
    HeaderBodyLength,
    Body,
}
pub struct SocketParser {
    transmitter: futures::sync::mpsc::UnboundedSender<bytes::BytesMut>,
    buffer: Vec<u8>,
    state: ParseState,
    parse_index: usize,
    scrap_buffer: Vec<u8>,
    route: u32,
    body_length: u32,
}

impl SocketParser {
    pub fn new(tx: futures::sync::mpsc::UnboundedSender<bytes::BytesMut>) -> Self {
        Self {
            transmitter: tx,
            buffer: Vec::new(),
            state: ParseState::HeaderPrefix,
            parse_index: 0,
            scrap_buffer: Vec::with_capacity(4),
            route: 0,
            body_length: 0,
        }
    }

    fn reset_parser(&mut self) {
        self.buffer.clear();
        self.state = ParseState::HeaderPrefix;
        self.parse_index = 0;
        self.scrap_buffer.clear();
        self.route = 0;
        self.body_length = 0;
    }

    pub fn parse(&mut self, bytes: &Vec<u8>) -> Result<Option<Vec<u8>>, Box<Error>> {
        let mut new_data_index = 0;
        while new_data_index < bytes.len() {
            match self.state {
                ParseState::HeaderPrefix => {
                    println!("First");
                    self.parse_header_prefix(bytes, &mut new_data_index)?;
                }
                ParseState::HeaderRoute => {
                    println!("Second");
                    self.parse_header_route(bytes, &mut new_data_index)?;
                }
                ParseState::HeaderBodyLength => {
                    println!("Third");
                    self.parse_body_length(bytes, &mut new_data_index)?;
                }
                ParseState::Body => {
                    println!("Fourth");
                    self.parse_body(bytes, &mut new_data_index);
                }
            }
        }
        let mut opt = None;
        if self.buffer.len() == self.body_length as usize && self.state == ParseState::Body {
            opt = (Some(self.buffer.clone()));
            self.reset_parser();
        }
        Ok(opt)
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
        if self.parse_index == HEADER_PREFIX.len() {
            self.state = ParseState::HeaderRoute;
            self.parse_index = 0;
        }
        Ok(())
    }

    fn parse_header_route(
        &mut self,
        new_data: &Vec<u8>,
        new_data_index: &mut usize,
    ) -> Result<(), Box<Error>> {
        if let Some(route) = self.parse_uint_32_le(new_data_index, new_data) {
            self.state = ParseState::HeaderBodyLength;
            self.route = route;
            self.parse_index = 0;
        }
        Ok(())
    }

    fn parse_body_length(
        &mut self,
        new_data: &Vec<u8>,
        new_data_index: &mut usize,
    ) -> Result<(), Box<Error>> {
        if let Some(length) = self.parse_uint_32_le(new_data_index, new_data) {
            if length as usize > MAX_PACKET_SIZE {
                return Err(Box::new(Exception::new("Packet size exceeded")));
            }
            self.state = ParseState::Body;
            self.buffer = Vec::with_capacity(length as usize);
            self.parse_index = 0;
        }
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
            if self.buffer.len() == self.body_length as usize {
                break;
            }
        }
        Ok(())
    }

    fn parse_uint_32_le(&mut self, next_index: &mut usize, new_data: &Vec<u8>) -> Option<u32> {
        let new_bytes_available = new_data.len() - *next_index;
        if self.parse_index == 0 && new_bytes_available >= 4 {
            let num = LittleEndian::read_u32(&new_data[*next_index..*next_index + 4]);
            *next_index += 4;
            return Some(num);
        } else {
            let source_end = *next_index + min(new_bytes_available, 4 - self.parse_index);
            let bytes_copied = self.copy_bytes(&new_data[*next_index..source_end]);
            *next_index += bytes_copied;
            self.parse_index += bytes_copied;
            if self.parse_index == 4 {
                return Some(LittleEndian::read_u32(&self.scrap_buffer[0..4]));
            }
        }
        None
    }

    fn copy_bytes(&mut self, bytes_to_copy: &[u8]) -> usize {
        let mut bytes_copied = 0;
        for i in 0..bytes_to_copy.len() {
            self.scrap_buffer[self.parse_index] = bytes_to_copy[i];
            bytes_copied = i;
        }
        bytes_copied
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use futures::stream::{self, Stream};
    use futures::Future;
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
        println!("This one fired");
        parser.parse(&bytes2);
        assert_eq!(parser.buffer, expected_out);
    }

    #[test]
    fn it_should_return_an_error_from_a_mismatched_header_prefix() {
        let (tx, _rx): (
            futures::sync::mpsc::UnboundedSender<bytes::BytesMut>,
            futures::sync::mpsc::UnboundedReceiver<bytes::BytesMut>,
        ) = futures::sync::mpsc::unbounded();
        let mut parser = SocketParser::new(tx);
        let bytes1 = vec![172, 216, 103, 237, 0, 0, 0, 64, 60, 0, 0, 0, 10];
        let res = parser.parse(&bytes1);
        match res {
            Ok(_) => assert_eq!(1, 2),
            Err(e) => assert_eq!(1, 1),
        }
    }
}