use rust_base58::FromBase58;
use serde_json::{from_str, from_value};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;

use crate::common::exodus_block::ExodusBlock;
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

pub fn init_exodus_meta() -> Result<(Meta, Vec<u8>), Box<Error>> {
    let exodus_hash = "6yt4X2giLv73Jh2b2iGN1Ns7fBUQYUdAS7LpQxdtGQJq"
        .from_base58()
        .map_err(|e| Exception::new(&format!("Error: {:?}", e)))?;
    let mut path = env::current_dir()?;
    path.push("data/exodus_meta.json");
    let mut file = File::open(path)?;
    let mut buff = String::new();
    file.read_to_string(&mut buff)?;
    let json: serde_json::Value = from_str(&buff)?;
    let difficulty = &json["header"]["difficulty"];
    match difficulty {
        serde_json::Value::Number(n) => {
            println!("Difficulty: {:?}", n.as_f64());
            unimplemented!();
        }
        _ => {
            unimplemented!();
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn it_reads_exodus_meta() {
        println!("{:?}", init_exodus_meta());
        unimplemented!();
    }
}
