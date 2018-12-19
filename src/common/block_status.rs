
#[derive(Debug, PartialEq, Primitive)]
pub enum BlockStatus {
    Rejected=0,
    Nothing=1,
    Header=2,
    Block=3,
    MainChain=4,
}

#[cfg(test)]
mod tests {
    use num_traits::{FromPrimitive, ToPrimitive};
    use common::block_status::BlockStatus;

    #[test]
    fn it_gives_u8_value_from_enum(){
        let status = BlockStatus::Rejected;
        assert_eq!(status.to_u8(), Some(0))
    }

    #[test]
    fn it_gives_4_as_u8_from_block_status_main_chain(){
        let status = BlockStatus::MainChain;
        assert_eq!(status.to_u8(), Some(4))
    }

    #[test]
    fn it_gives_none_from_wrong_u8(){
        assert!(BlockStatus::from_u8(10).is_none(), "It is not a value for BlockStatus")
    }

    #[test]
    fn it_gives_none_from_wrong_value(){
        assert!(BlockStatus::from_i8(-1).is_none(), "-1 is not the value for BlockStatus");
    }

}