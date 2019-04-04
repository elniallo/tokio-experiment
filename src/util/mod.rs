pub mod aes;
pub mod hash;
pub mod strict_math;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn random_bytes(len: usize) -> Vec<u8> {
    let bytes: Vec<u8> = (0..len - 1).map(|_| rand::random::<u8>()).collect();
    bytes
}
pub fn get_current_time() -> usize {
    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH).unwrap().as_millis() as usize
}
