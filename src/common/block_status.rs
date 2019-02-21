#[derive(Debug, PartialEq)]
pub enum BlockStatus {
    Rejected,
    Nothing,
    Header,
    Block,
    MainChain,
}

pub trait EnumConverter {
    fn to_u8(&self) -> u8;
    fn from_u8(number: u8) -> Option<BlockStatus>;
}

impl EnumConverter for BlockStatus {
    fn to_u8(&self) -> u8 {
        match self {
            BlockStatus::Rejected => return 0,
            BlockStatus::Nothing => return 1,
            BlockStatus::Header => return 2,
            BlockStatus::Block => return 3,
            BlockStatus::MainChain => return 4,
        }
    }

    fn from_u8(number: u8) -> Option<BlockStatus> {
        match number {
            0 => return Some(BlockStatus::Rejected),
            1 => return Some(BlockStatus::Nothing),
            2 => return Some(BlockStatus::Header),
            3 => return Some(BlockStatus::Block),
            4 => return Some(BlockStatus::MainChain),
            _ => None,
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
    fn it_gives_4_as_u8_from_block_status_main_chain() {
        let status = BlockStatus::MainChain;
        assert_eq!(status.to_u8(), 4)
    }

    #[test]
    fn it_gives_none_from_wrong_u8() {
        assert!(
            BlockStatus::from_u8(10).is_none(),
            "10 is not a value for BlockStatus"
        )
    }

    #[test]
    fn it_gives_none_from_wrong_value() {
        assert!(
            BlockStatus::from_u8(5).is_none(),
            "5 is not the value for BlockStatus"
        );
    }
}
