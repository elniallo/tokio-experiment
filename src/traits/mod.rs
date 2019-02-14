use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
pub trait PeerDB<I, K, T>
where
    I: ToDBType<T>,
{
    fn get(&self, key: K) -> Option<T>;
    fn get_all(&self) -> Option<Vec<T>>;
    fn get_multiple(&self, limit: usize) -> Option<Vec<T>>;
    fn inbound_connection(&mut self, key: K, value: I) -> Result<(), Box<Error>>;
    fn outbound_connection(&mut self, key: K, value: I) -> Result<(), Box<Error>>;
    fn connection_failure(&mut self, key: K) -> Result<(), Box<Error>>;
    // fn disconnect(&mut self, key: K);
    // fn put_multiple(&mut self, values: Vec<T>);
    // fn get_recent(&self, limit: usize) -> Option<Vec<T>>;
    // fn get_seen(&self, limit: usize) -> Option<Vec<T>>;
    // fn get_oldest(&self, limit: usize) -> Option<Vec<T>>;
    // fn get_random(&self, limit: usize) -> Option<Vec<T>>;
}

pub trait ToDBType<T> {
    fn to_db_type(&self) -> Result<T, Box<Error>>;
}

pub trait Encode {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>>;
}

pub trait Decode {
    type ProtoType;
    fn decode(buffer: &Vec<u8>) -> Result<Self, Box<Error>>
    where
        Self: Sized;
}

pub trait Proto {
    type ProtoType;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>>;
}

#[derive(Debug)]
pub struct Exception {
    details: String,
}

impl Exception {
    pub fn new(details: &str) -> Exception {
        Exception {
            details: details.to_string(),
        }
    }
}

impl Display for Exception {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.details)
    }
}

impl Error for Exception {
    fn description(&self) -> &str {
        &self.details
    }
}
