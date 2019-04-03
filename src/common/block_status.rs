use crate::traits::Exception;
use std::error::Error;
/// Enum for the status of a Block
#[derive(Debug, PartialEq, Clone, PartialOrd, Ord, Eq)]
pub enum BlockStatus {
    /// Block has Been Rejected
    Rejected,
    /// No information Exists for Block
    Nothing,
    /// Header has been processed
    Header,
    /// Failed validation for some reason, Header is valid
    Invalid,
    /// Block received but not added to longest chain
    Block,
    /// Block is part of the currently defined heaviest chain
    MainChain,
}
/// Performs a conversion on an enum
pub trait EnumConverter<OutputType> {
    /// Returns a representation of the Enum in the form of the OutputType
    fn to_output(&self) -> OutputType;
    /// Returns an Enum from an input of the Specified Type
    fn from_input(number: OutputType) -> Result<Self, Box<Error>>
    where
        Self: Sized;
}

impl EnumConverter<u8> for BlockStatus {
    fn to_output(&self) -> u8 {
        match self {
            BlockStatus::Rejected => return 0,
            BlockStatus::Nothing => return 1,
            BlockStatus::Header => return 2,
            BlockStatus::Invalid => return 3,
            BlockStatus::Block => return 4,
            BlockStatus::MainChain => return 5,
        }
    }

    fn from_input(number: u8) -> Result<BlockStatus, Box<Error>> {
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
        assert_eq!(status.to_output(), 0)
    }

    #[test]
    fn it_gives_5_as_u8_from_block_status_main_chain() {
        let status = BlockStatus::MainChain;
        assert_eq!(status.to_output(), 5)
    }

    #[test]
    fn it_gives_err_from_wrong_u8() {
        assert!(
            BlockStatus::from_input(10).is_err(),
            "10 is not a value for BlockStatus"
        )
    }

    #[test]
    fn it_gives_err_from_wrong_value() {
        assert!(
            BlockStatus::from_input(6).is_err(),
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
