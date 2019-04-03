use crate::traits::Exception;
use std::error::Error;

#[derive(Debug, PartialEq, Clone, PartialOrd, Ord, Eq)]
pub enum BlockStatus {
    Rejected,
    Nothing,
    Header,
    Invalid,
    Block,
    MainChain,
}

pub trait EnumConverter {
    fn to_u8(&self) -> u8;
    fn from_u8(number: u8) -> Result<BlockStatus, Box<Error>>;
}

impl EnumConverter for BlockStatus {
    fn to_u8(&self) -> u8 {
        match self {
            BlockStatus::Rejected => return 0,
            BlockStatus::Nothing => return 1,
            BlockStatus::Header => return 2,
            BlockStatus::Invalid => return 3,
            BlockStatus::Block => return 4,
            BlockStatus::MainChain => return 5,
        }
    }

    fn from_u8(number: u8) -> Result<BlockStatus, Box<Error>> {
        match number {
            0 => return Ok(BlockStatus::Rejected),
            1 => return Ok(BlockStatus::Nothing),
            2 => return Ok(BlockStatus::Header),
            3 => return Ok(BlockStatus::Invalid),
            4 => return Ok(BlockStatus::Block),
            5 => return Ok(BlockStatus::MainChain),
            _ => Err(Box::new(Exception::new(&format!(
                "Enum does not exist for number {}",
                number
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::block_status::BlockStatus;

    #[test]
    fn it_gives_u8_value_from_enum() {
        let status = BlockStatus::Rejected;
        assert_eq!(status.to_u8(), 0)
    }

    #[test]
    fn it_gives_5_as_u8_from_block_status_main_chain() {
        let status = BlockStatus::MainChain;
        assert_eq!(status.to_u8(), 5)
    }

    #[test]
    fn it_gives_err_from_wrong_u8() {
        assert!(
            BlockStatus::from_u8(10).is_err(),
            "10 is not a value for BlockStatus"
        )
    }

    #[test]
    fn it_gives_err_from_wrong_value() {
        assert!(
            BlockStatus::from_u8(6).is_err(),
            "6 is not the value for BlockStatus"
        );
    }
    #[test]
    fn it_is_ordered_correctly() {
        assert!(BlockStatus::MainChain > BlockStatus::Block);
        assert!(BlockStatus::Block > BlockStatus::Invalid);
        assert!(BlockStatus::Invalid > BlockStatus::Header);
        assert!(BlockStatus::Header > BlockStatus::Nothing);
        assert!(BlockStatus::Nothing > BlockStatus::Rejected);
    }
}
