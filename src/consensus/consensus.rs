use crate::common::header::{BlockHeader, Header};
use crate::common::meta::Meta;
use crate::consensus::difficulty_adjuster;
use crate::consensus::state_processor::StateProcessor;
use crate::consensus::BlockForkChoice;
use crate::database::block_db::BlockDB;
use crate::traits::Exception;
use crate::util::hash::hash_cryptonight;

use std::cmp::Ordering;
use std::error::Error;
use std::sync::{Arc, Mutex};

impl BlockForkChoice for Meta {
    fn fork_choice(&self, other: &Meta) -> Ordering {
        self.total_work.partial_cmp(&other.total_work).unwrap()
    }
}
pub struct Consensus {
    block_db: Arc<Mutex<BlockDB>>,
    state_processor: StateProcessor,
}

impl Consensus {
    pub fn new(
        state_processor: StateProcessor,
        block_db: Arc<Mutex<BlockDB>>,
    ) -> Result<Self, Box<Error>> {
        Ok(Self {
            block_db,
            state_processor,
        })
    }
}

impl HeaderProcessor<Header> for Consensus {
    fn process_header(&self, header: &Header) -> Result<(), Box<Error>> {
        let mut prehash = header.prehash()?;
        prehash.append(&mut header.nonce.to_le_bytes().to_vec());
        if difficulty_adjuster::acceptable(
            hash_cryptonight(&prehash, prehash.len()),
            difficulty_adjuster::get_target(header.difficulty, 32)?,
        )? {
            Ok(())
        } else {
            Err(Box::new(Exception::new(
                "Block rejected, hash does not match difficulty",
            )))
        }
    }
}

impl ForkChoice<Meta> for Consensus {
    fn fork_choice(tip: &Meta, new_block: &Meta) -> bool {
        match new_block.fork_choice(tip) {
            Ordering::Greater => true,
            _ => false,
        }
    }
}

pub trait ForkChoice<BlockType>
where
    BlockType: BlockForkChoice,
{
    fn fork_choice(tip: &BlockType, new_block: &BlockType) -> bool;
}

pub trait HeaderProcessor<HeaderType>
where
    HeaderType: BlockHeader,
{
    fn process_header(&self, header: &HeaderType) -> Result<(), Box<Error>>;
}

pub trait BlockProcessor<BlockType, HeaderType, TxType, MetaType, SignatureType>
where
    MetaType: BlockForkChoice,
{
    fn split_block(
        &self,
        block: &BlockType,
    ) -> (HeaderType, Vec<TxType>, MetaType, Vec<SignatureType>);
}

pub trait StateProcessorTrait<TxType> {
    fn process_txs(&self, txs: &[TxType]) -> Result<(), Box<Error>>;
}

pub trait TxProcessor<TxType> {
    fn check_signatures(&self, txs: &[TxType]) -> Result<(), Box<Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::address::{Address, ValidAddress};
    use crate::common::block_status::BlockStatus;
    use crate::consensus::worldstate::WorldState;
    use crate::database::block_db::BlockDB;
    use crate::database::dbkeys::DBKeys;
    use crate::database::state_db::StateDB;

    use rust_base58::FromBase58;
    use std::path::PathBuf;
    #[test]
    fn it_assigns_nonce_bytes_correctly() {
        let nonce: u64 = 9991999136134178034;
        let le_nonce = nonce.to_le_bytes();
        let expected_bytes = [242, 164, 73, 65, 70, 182, 170, 138];
        assert_eq!(le_nonce, expected_bytes);
    }

    #[test]
    fn it_correctly_checks_cn_hash_of_header() {
        //Set up consensus
        let state_path = PathBuf::from("state");
        let block_path = PathBuf::from("blocks");
        let file_path = PathBuf::from("blockfile");
        let keys = DBKeys::default();
        let block_db = BlockDB::new(block_path, file_path, keys, None).unwrap();
        let db_wrapper = Arc::new(Mutex::new(block_db));
        let state_db = StateDB::new(state_path, None).unwrap();
        let world_state = WorldState::new(state_db, 20).unwrap();
        let state_processor = StateProcessor::new(db_wrapper.clone(), world_state);
        let consensus = Consensus::new(state_processor, db_wrapper).unwrap();

        // Set up header - Block Number 864589
        let merkle_root = "xyw95Bsby3s4mt6f4FmFDnFVpQBAeJxBFNGzu2cX4dM"
            .from_base58()
            .unwrap();
        let state_root = "2TQHHSG8daQxYMCisMywUppz7a3YXb83VKzpMsZwQgLi"
            .from_base58()
            .unwrap();
        let time_stamp = 1553674416492;
        let difficulty = 0.00000004430078803796533 as f64;
        let nonce = 12610086967913974370;
        let miner = Address::from_string(&"H2zF9ZrneniGejpGSs7dpafiU7vJACFTW".to_string()).unwrap();
        let previous_hash = vec!["3u3jNwUbeMPiRBMCy2hHLRtGmiYQJmxMwyv1aUGV7AMN"
            .from_base58()
            .unwrap()];

        let header = Header::new(
            merkle_root.clone(),
            time_stamp,
            difficulty,
            state_root.clone(),
            previous_hash.clone(),
            nonce,
            miner,
        );
        let res = consensus.process_header(&header);
        assert!(res.is_ok());
    }

    #[test]
    fn it_chooses_the_correct_fork() {
        let height = 123456789;
        let t_ema = 1234.0;
        let p_ema = 0.1234;
        let next_difficulty = 0.012345;
        let total_work = 1e23;
        let offset = 123;
        let file_number = 234;
        let length = 345;
        let tip_meta = Meta::new(
            height,
            t_ema,
            p_ema,
            next_difficulty,
            total_work,
            Some(file_number),
            Some(offset),
            Some(length),
            BlockStatus::Header,
        );
        let second_tw = 1.000000000001e23;
        let new_meta = Meta::new(
            height,
            t_ema,
            p_ema,
            next_difficulty,
            second_tw,
            Some(file_number),
            Some(offset),
            Some(length),
            BlockStatus::Invalid,
        );
        assert!(Consensus::fork_choice(&tip_meta, &new_meta));
        assert_ne!(Consensus::fork_choice(&new_meta, &tip_meta), true);
    }
}
