use crate::common::block::Block;
use crate::common::block_status::BlockStatus;
use crate::common::header::Header;
use crate::common::meta::Meta;
use crate::common::signed_tx::SignedTx;
use crate::consensus::difficulty_adjuster;
use crate::consensus::state_processor::StateProcessor;
use crate::consensus::BlockForkChoice;
use crate::database::block_db::BlockDB;
use crate::traits::{BlockHeader, Encode, Exception};
use crate::util::hash::{hash, hash_cryptonight};

use std::cmp::Ordering;
use std::error::Error;
use std::sync::{Arc, Mutex};

const EMPTY_MERKLE_ROOT: [u8; 32] = [
    14, 87, 81, 192, 38, 229, 67, 178, 232, 171, 46, 176, 96, 153, 218, 161, 209, 229, 223, 71,
    119, 143, 119, 135, 250, 171, 69, 205, 241, 47, 227, 168,
];

type PutResult<T> = Result<T, Box<Error>>;

impl BlockForkChoice for Meta {
    fn fork_choice(&self, other: &Meta) -> Ordering {
        self.total_work.partial_cmp(&other.total_work).unwrap()
    }
}
/// Entry Point for Consensus related functionality
pub struct Consensus {
    tip_height: Option<usize>,
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
            tip_height: None,
        })
    }
}

impl HyconConsensus<Header, Block<Header, SignedTx>> for Consensus {
    fn init(&mut self) -> Result<(), Box<Error>> {
        if let Some(tip_height) = self.get_tip_height() {
            self.tip_height = Some(tip_height)
        } else {
            // init exodus
        }

        Ok(())
    }
    fn get_tip_height(&self) -> Option<usize> {
        self.tip_height
    }

    fn put(&mut self, header: Header, block: Option<Block<Header, SignedTx>>) -> PutResult<()> {
        Ok(())
    }
}

impl HeaderProcessor<Header> for Consensus {
    type UncleProcessResult = UncleResult;
    fn process_header(&self, header: &Header) -> Result<(), Box<Error>> {
        if header.previous_hash.len() == 0 {
            self.block_db
                .lock()
                .map_err(|_e| Exception::new("Poison Error"))?
                .set_block_status(&hash(&header.encode()?, 32), BlockStatus::Rejected)?;
            return Err(Box::new(Exception::new("Block Rejected: No previous hash")));
        }

        if header.previous_hash.len() > 11 {
            self.block_db
                .lock()
                .map_err(|_e| Exception::new("Poison Error"))?
                .set_block_status(&hash(&header.encode()?, 32), BlockStatus::Rejected)?;
            return Err(Box::new(Exception::new("Block Rejected: Too many uncles")));
        }

        match self
            .block_db
            .lock()
            .map_err(|_e| Exception::new("Poison Error"))?
            .get_block_status(&header.previous_hash[0])?
        {
            BlockStatus::Rejected => {
                return Err(Box::new(Exception::new(
                    "Block Ignored: Previous block rejected",
                )));
            }
            _ => {}
        }
        let mut prehash = header.prehash()?;
        prehash.append(&mut header.nonce.to_le_bytes().to_vec());
        if difficulty_adjuster::acceptable(
            hash_cryptonight(&prehash, prehash.len()),
            difficulty_adjuster::get_target(header.difficulty, 32)?,
        )? {
            let new_status;
            if header.get_merkle_root() == &EMPTY_MERKLE_ROOT {
                println!("empty merkle root");
                new_status = BlockStatus::Block;
            } else {
                new_status = BlockStatus::Header;
            }
            self.block_db
                .lock()
                .map_err(|_e| Exception::new("Poison Error"))?
                .set_block_status(&hash(&header.encode()?, 32), new_status)?;
            Ok(())
        } else {
            self.block_db
                .lock()
                .map_err(|_e| Exception::new("Poison Error"))?
                .set_block_status(&hash(&header.encode()?, 32), BlockStatus::Rejected)?;
            Err(Box::new(Exception::new(
                "Block rejected, hash does not match difficulty",
            )))
        }
    }

    fn process_uncles(&self, uncle_hashes: &[Vec<u8>]) -> Result<UncleResult, Box<Error>> {
        for hash in uncle_hashes {
            match self
                .block_db
                .lock()
                .map_err(|_e| Exception::new("Poison Error"))?
                .get_block_status(hash)
            {
                _ => {}
            }
        }
        Ok(UncleResult::Success)
    }
}

/// Enum representing the result of a processing uncle blocks
pub enum UncleResult {
    /// All uncles have passed validation
    Success,
    /// Insufficient Data, contains hashes of missing uncles
    Partial(Vec<Vec<u8>>),
    /// One or more Uncles have failed validation, contains failed uncles
    Failure(Vec<Vec<u8>>),
}

impl ForkChoice<Meta> for Consensus {
    fn fork_choice(tip: &Meta, new_block: &Meta) -> bool {
        match new_block.fork_choice(tip) {
            Ordering::Greater => true,
            _ => false,
        }
    }
}
/// # ForkChoice Trait
/// Defines how the blockchain behaves in the event of a forking event

pub trait ForkChoice<BlockType>
where
    BlockType: BlockForkChoice,
{
    ///
    /// Defines forking behavior for two blocks
    ///
    /// #### Arguments
    /// - `tip` - the current tip of the blockchain
    /// - `new_block` - the new block that should be added to the existing tip
    ///
    /// #### Return Value
    /// - `true` - if the block can be added to the chain
    /// - `false` - if the block should not extend the existing chain
    ///
    fn fork_choice(tip: &BlockType, new_block: &BlockType) -> bool;
}

/// # Header Processor Trait
/// Defines methods to be used in the processing of blockchain headers
/// ___

pub trait HeaderProcessor<HeaderType>
where
    HeaderType: BlockHeader,
{
    ///
    /// User defined type to contain the result of processing uncle blocks
    ///
    type UncleProcessResult;
    ///
    /// Defines how a header is processed
    ///
    /// #### Arguments
    /// `header` - a reference to the HeaderType being processed
    ///
    /// #### Return Value
    /// An empty `Result` denoting success
    ///
    fn process_header(&self, header: &HeaderType) -> Result<(), Box<Error>>;
    ///
    /// Defines how uncles are processed
    ///
    /// #### Arguments
    /// `uncle_hashes` - a slice of block hashes to be checked for validity as uncle blocks
    ///
    /// #### Return Value
    /// A `Result` containing the user defined UncleProcessResult type
    ///
    fn process_uncles(
        &self,
        uncle_hashes: &[Vec<u8>],
    ) -> Result<Self::UncleProcessResult, Box<Error>>;
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

/// # HyconConsensus Trait
/// Base trait containing various methods necessary for consensus implementation
pub trait HyconConsensus<HeaderType, BlockType>
where
    HeaderType: BlockHeader,
{
    ///
    /// Initialisation logic for consensus should be placed in here
    ///
    /// #### Return Value
    /// An empty `Result`
    ///
    fn init(&mut self) -> Result<(), Box<Error>>;
    ///
    /// The height of the current tip, essentially how many blocks have been added to the main chain since genesis
    ///
    /// #### Return Value
    /// An `Option` containing the current height, or `None` if this is a cold startup with an unitialised consensus
    ///
    fn get_tip_height(&self) -> Option<usize>;
    ///
    /// Entry point for putting a block (or just a header) onto the chain
    ///
    /// #### Arguments
    /// - `header` - the block header to be added to the chain, must implement BlockHeader trait
    /// - `block` - An optional parameter containing a block to be added to the chain
    ///
    /// #### Return Value
    /// An empty `Result`
    ///
    ///
    fn put(&mut self, header: HeaderType, block: Option<BlockType>) -> Result<(), Box<Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::address::Address;
    use crate::common::block_status::BlockStatus;
    use crate::consensus::worldstate::WorldState;
    use crate::database::block_db::BlockDB;
    use crate::database::dbkeys::DBKeys;
    use crate::database::state_db::StateDB;
    use crate::traits::ValidAddress;

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
