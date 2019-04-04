use crate::common::block_status::BlockStatus;
use crate::serialization::block::BlockDB as ProtoBlockDB;
use crate::traits::EnumConverter;
use crate::traits::{Decode, Encode, Proto};
use protobuf::Message as ProtoMessage;
use std::error::Error;

#[derive(Clone, Debug)]
pub struct Meta {
    pub height: u32,
    pub t_ema: f64,
    pub p_ema: f64,
    pub next_difficulty: f64,
    pub total_work: f64,
    pub file_number: Option<u32>,
    pub offset: Option<u64>,
    pub length: Option<u32>,
    pub status: BlockStatus,
}

impl Meta {
    pub fn new(
        height: u32,
        t_ema: f64,
        p_ema: f64,
        next_difficulty: f64,
        total_work: f64,
        file_number: Option<u32>,
        offset: Option<u64>,
        length: Option<u32>,
        status: BlockStatus,
    ) -> Meta {
        Meta {
            height,
            t_ema,
            p_ema,
            next_difficulty,
            total_work,
            file_number,
            offset,
            length,
            status,
        }
    }
}

impl Proto for Meta {
    type ProtoType = ProtoBlockDB;
    fn to_proto(&self) -> Result<Self::ProtoType, Box<Error>> {
        let mut proto_meta = Self::ProtoType::new();
        proto_meta.set_height(self.height);
        proto_meta.set_tEMA(self.t_ema);
        proto_meta.set_pEMA(self.p_ema);
        proto_meta.set_nextDifficulty(self.next_difficulty);
        proto_meta.set_totalWork(self.total_work);
        match self.file_number {
            Some(fd) => proto_meta.set_fileNumber(fd),
            None => {}
        }
        match self.offset {
            Some(offset) => proto_meta.set_offset(offset),
            None => {}
        }
        match self.length {
            Some(length) => proto_meta.set_length(length),
            None => {}
        }
        proto_meta.set_status(self.status.to_output() as u32);
        Ok(proto_meta)
    }

    fn from_proto(_prototype: &Self::ProtoType) -> Result<Self, Box<Error>> {
        unimplemented!()
    }
}

impl Encode for Meta {
    fn encode(&self) -> Result<Vec<u8>, Box<Error>> {
        let proto_meta = self.to_proto()?;
        Ok(proto_meta.write_to_bytes()?)
    }
}

impl Decode for Meta {
    fn decode(buffer: &[u8]) -> Result<Meta, Box<Error>> {
        let mut proto_meta = ProtoBlockDB::new();

        proto_meta.merge_from_bytes(buffer)?;
        let meta_info = Meta::new(
            proto_meta.height,
            proto_meta.tEMA,
            proto_meta.pEMA,
            proto_meta.nextDifficulty,
            proto_meta.totalWork,
            Some(proto_meta.fileNumber),
            Some(proto_meta.offset),
            Some(proto_meta.length),
            BlockStatus::from_input(proto_meta.status as u8)?,
        );
        Ok(meta_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_makes_meta_without_file_info() {
        let height = 150000;
        let t_ema = 30.00;
        let p_ema = 0.000001;
        let next_difficulty = 0.0001;
        let total_work = 1e15;
        let meta = Meta::new(
            height,
            t_ema,
            p_ema,
            next_difficulty,
            total_work,
            None,
            None,
            None,
            BlockStatus::Nothing,
        );

        assert_eq!(meta.height, height);
        assert_eq!(meta.t_ema, t_ema);
        assert_eq!(meta.p_ema, p_ema);
        assert_eq!(meta.total_work, total_work);
        assert_eq!(meta.file_number, None);
        assert_eq!(meta.offset, None);
        assert_eq!(meta.length, None);
    }

    #[test]
    fn it_makes_meta_with_file_info() {
        let height = 123456789;
        let t_ema = 1234.0;
        let p_ema = 0.1234;
        let next_difficulty = 0.012345;
        let total_work = 1e23;
        let offset = 123;
        let file_number = 234;
        let length = 345;
        let meta = Meta::new(
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

        assert_eq!(meta.height, height);
        assert_eq!(meta.t_ema, t_ema);
        assert_eq!(meta.p_ema, p_ema);
        assert_eq!(meta.next_difficulty, next_difficulty);
        assert_eq!(meta.total_work, total_work);
        assert_eq!(meta.offset.unwrap(), offset);
        assert_eq!(meta.file_number.unwrap(), file_number);
        assert_eq!(meta.length.unwrap(), length);
    }
}
