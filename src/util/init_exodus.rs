use rust_base58::FromBase58;
use serde_json::from_str;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;

use crate::common::block_status::BlockStatus;
use crate::common::exodus_block::ExodusBlock;
use crate::common::genesis_header::GenesisHeader;
use crate::common::meta::Meta;
use crate::traits::{Decode, Exception};

pub fn init_exodus_block() -> Result<ExodusBlock, Box<Error>> {
    let mut path = env::current_dir()?;
    path.push("data/exodusBlock.dat");
    let mut exodus_file = File::open(path)?;
    let mut exodus_buf = Vec::new();
    exodus_file.read_to_end(&mut exodus_buf)?;
    ExodusBlock::decode(&exodus_buf)
}

pub fn init_exodus_meta() -> Result<(Meta<GenesisHeader>, Vec<u8>), Box<Error>> {
    let exodus_hash = "6yt4X2giLv73Jh2b2iGN1Ns7fBUQYUdAS7LpQxdtGQJq"
        .from_base58()
        .map_err(|e| Exception::new(&format!("Error: {:?}", e)))?;
    let mut path = env::current_dir()?;
    path.push("data/exodus_meta.json");
    let mut file = File::open(path)?;
    let mut buff = String::new();
    file.read_to_string(&mut buff)?;
    let json: serde_json::Value = from_str(&buff)?;
    let height: u32;
    match &json["height"] {
        serde_json::Value::Number(n) => {
            if let Some(block_height) = n.as_u64() {
                height = block_height as u32;
            } else {
                return Err(Box::new(Exception::new("Exodus Height not Found")));
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus Height not Found")));
        }
    }
    let t_ema: f64;
    match &json["tEMA"] {
        serde_json::Value::Number(n) => {
            if let Some(block_tema) = n.as_f64() {
                t_ema = block_tema;
            } else {
                return Err(Box::new(Exception::new("Exodus TEMA not Found")));
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus TEMA not Found")));
        }
    }
    let p_ema: f64;
    match &json["pEMA"] {
        serde_json::Value::Number(n) => {
            if let Some(block_pema) = n.as_f64() {
                p_ema = block_pema;
            } else {
                return Err(Box::new(Exception::new("Exodus pEMA not Found")));
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus pEMA not Found")));
        }
    }
    let next_difficulty: f64;
    match &json["nextDifficulty"] {
        serde_json::Value::Number(n) => {
            if let Some(next_diff) = n.as_f64() {
                next_difficulty = next_diff;
            } else {
                return Err(Box::new(Exception::new("Exodus nextDifficulty not Found")));
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus nextDifficulty not Found")));
        }
    }
    let total_work: f64;
    match &json["totalWork"] {
        serde_json::Value::Number(n) => {
            if let Some(tot_work) = n.as_f64() {
                total_work = tot_work;
            } else {
                return Err(Box::new(Exception::new("Exodus totalWork not Found")));
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus totalWork not Found")));
        }
    }
    let mut merkle_root: Vec<u8> = Vec::with_capacity(32);
    let mut state_root: Vec<u8> = Vec::with_capacity(32);
    match &json["header"]["merkleRoot"] {
        serde_json::Value::Array(vec) => {
            for num in vec {
                match num {
                    serde_json::Value::Number(n) => {
                        if let Some(val) = n.as_u64() {
                            merkle_root.push(val as u8);
                        } else {
                            return Err(Box::new(Exception::new("Exodus merkleRoot not found")));
                        }
                    }
                    _ => {
                        return Err(Box::new(Exception::new("Exodus merkleRoot not found")));
                    }
                }
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus merkleRoot not found")));
        }
    }
    match &json["header"]["stateRoot"] {
        serde_json::Value::Array(vec) => {
            for num in vec {
                match num {
                    serde_json::Value::Number(n) => {
                        if let Some(val) = n.as_u64() {
                            state_root.push(val as u8);
                        } else {
                            return Err(Box::new(Exception::new("Exodus stateRoot not found")));
                        }
                    }
                    _ => {
                        return Err(Box::new(Exception::new("Exodus stateRoot not found")));
                    }
                }
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus stateRoot not found")));
        }
    }
    let time_stamp;
    match &json["header"]["timeStamp"] {
        serde_json::Value::Number(n) => {
            if let Some(exodus_time_stamp) = n.as_u64() {
                time_stamp = exodus_time_stamp;
            } else {
                return Err(Box::new(Exception::new("Exodus TimeStampt not Found")));
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus Timestamp not Found")));
        }
    }
    let difficulty;
    match &json["header"]["difficulty"] {
        serde_json::Value::Number(n) => {
            if let Some(diff) = n.as_f64() {
                difficulty = diff;
            } else {
                return Err(Box::new(Exception::new("Exodus pEMA not Found")));
            }
        }
        _ => {
            return Err(Box::new(Exception::new("Exodus pEMA not Found")));
        }
    }
    let meta = Meta::new(
        height,
        GenesisHeader::new(merkle_root, time_stamp, difficulty, state_root),
        t_ema,
        p_ema,
        next_difficulty,
        total_work,
        None,
        None,
        None,
        BlockStatus::MainChain,
    );
    Ok((meta, exodus_hash))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn it_reads_exodus_meta() {
        assert!(init_exodus_meta().is_ok());
    }
    #[test]
    fn it_reads_exodus_block() {
        assert!(init_exodus_block().is_ok());
    }
}
