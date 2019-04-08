use std::path::PathBuf;

use crate::common::block_status::BlockStatus;
use crate::common::meta::Meta;
use crate::database::block_file::{BlockFile, BlockFileOps, PutResult as WriteLocation};
use crate::database::dbkeys::DBKeys;
use crate::database::{DBError, DBErrorType, DBResult, HashValue, IDB};
use crate::traits::{Decode, Encode, EnumConverter, Proto};

use byteorder::{BigEndian, ByteOrder};
use rocksdb::DB as RocksDB;

pub struct BlockDB<BlockFileType = BlockFile, DatabaseType = RocksDB>
where
    BlockFileType: BlockFileOps,
    DatabaseType: IDB,
{
    database: DatabaseType,
    block_file: BlockFileType,
    file_number: u32,
    db_keys: DBKeys,
}

impl<BlockFileType, DatabaseType, OptionType> BlockDB<BlockFileType, DatabaseType>
where
    BlockFileType: BlockFileOps,
    DatabaseType: IDB<OptionType = OptionType>,
{
    pub fn new(
        db_path: PathBuf,
        file_path: PathBuf,
        db_keys: DBKeys,
        options: Option<OptionType>,
    ) -> DBResult<Self> {
        let mut database = DatabaseType::open(db_path, options)?;
        let file_number = match database._get(&db_keys.file_number) {
            Ok(val) => BigEndian::read_u32(&val),
            Err(err) => match err.error_type {
                DBErrorType::NotFoundError => {
                    database.set(&db_keys.file_number, &vec![0; 4])?;
                    0
                }
                _ => return Err(err),
            },
        };
        let file_position = match database._get(&db_keys.file_position) {
            Ok(val) => BigEndian::read_u64(&val),
            Err(err) => match err.error_type {
                DBErrorType::NotFoundError => {
                    database.set(&db_keys.file_number, &vec![0; 8])?;
                    0
                }
                _ => return Err(err),
            },
        };
        let block_file;
        match BlockFileType::new(&file_path, file_number, file_position) {
            Ok(b) => block_file = b,
            Err(_) => return Err(Box::new(DBError::new(DBErrorType::NotFoundError))),
        }
        Ok(BlockDB {
            database,
            block_file,
            file_number,
            db_keys,
        })
    }

    pub fn get_header_tip_hash(&self) -> DBResult<HashValue> {
        self.database._get(&self.db_keys.header_tip)
    }

    fn set_header_tip_hash(&mut self, hash: &HashValue) -> DBResult<()> {
        self.database.set(&self.db_keys.header_tip, hash)
    }

    pub fn get_block_tip_hash(&self) -> DBResult<HashValue> {
        self.database._get(&self.db_keys.block_tip)
    }
    fn set_block_tip_hash(&mut self, hash: &HashValue) -> DBResult<()> {
        self.database.set(&self.db_keys.block_tip, hash)
    }

    fn set_hash_using_height(&mut self, height: u32, hash: &HashValue) -> DBResult<()> {
        let mut height_buf = vec![0; 4];
        BigEndian::write_u32(&mut height_buf, height);
        self.database.set(&height_buf, &hash)
    }

    fn get_hash_by_height(&self, height: u32) -> DBResult<HashValue> {
        let mut height_buf = vec![0; 4];
        BigEndian::write_u32(&mut height_buf, height);
        self.database._get(&height_buf)
    }

    fn set_meta(&mut self, hash: &HashValue, meta_info: &Meta) -> DBResult<()> {
        let mut hash_copy = hash.clone();
        hash_copy.insert(0, b"b"[0]);
        let encoded;
        match meta_info.encode() {
            Ok(v) => encoded = v,
            Err(_) => {
                return Err(Box::new(DBError::new(DBErrorType::UnexpectedError(
                    "Failed to encode metadata".to_string(),
                ))));
            }
        }
        self.database.set(hash_copy.as_ref(), &encoded)
    }

    pub fn get_meta(&self, hash: &HashValue) -> DBResult<Meta> {
        let mut hash_copy = hash.clone();
        hash_copy.insert(0, b"b"[0]);
        match self.database._get(&hash_copy) {
            Ok(value) => match Meta::decode(&value.to_vec()) {
                Ok(m) => return Ok(m),
                Err(_) => {
                    return Err(Box::new(DBError::new(DBErrorType::UnexpectedError(
                        "Failed to decode metadata".to_string(),
                    ))));
                }
            },
            Err(e) => return Err(e),
        }
    }

    fn set_block<T>(&mut self, block: &mut T) -> DBResult<WriteLocation>
    where
        T: Encode + Proto,
    {
        let write_location;
        match self.block_file.put::<T>(block) {
            Ok(w) => write_location = w,
            Err(_) => {
                return Err(Box::new(DBError::new(DBErrorType::UnexpectedError(
                    "Failed to put to block file".to_string(),
                ))));
            }
        }
        if self.file_number != write_location.file_number {
            self.file_number = write_location.file_number;
            let mut file_number_buf = vec![0; 4];
            BigEndian::write_u32(&mut file_number_buf, write_location.file_number);
            self.database
                .set(&self.db_keys.file_number, &file_number_buf)?;
        }
        let mut file_position_buf = vec![0; 8];
        BigEndian::write_u64(&mut file_position_buf, write_location.file_position);
        self.database
            .set(&self.db_keys.file_position, &file_position_buf)?;
        Ok(write_location)
    }

    fn get_blocks<T>(&mut self, from_height: u32, count: u32) -> DBResult<Vec<T>>
    where
        T: Decode + Clone,
    {
        let mut i = 0;
        let mut blocks = Vec::new();
        let _limit = count - 1;
        while i != _limit {
            blocks.push(self.get_block_by_height(from_height + i)?);
            i += 1;
        }
        Ok(blocks)
    }

    pub fn get_block<T>(&mut self, hash: &HashValue) -> DBResult<T>
    where
        T: Decode + Clone,
    {
        let meta_info = self.get_meta(hash)?;
        self.get_block_by_meta_info::<T>(meta_info)
    }

    pub fn get_block_by_height<T>(&mut self, height: u32) -> DBResult<T>
    where
        T: Decode + Clone,
    {
        let hash = self.get_hash_by_height(height)?;
        self.get_block::<T>(&hash)
    }

    fn get_block_by_meta_info<T>(&mut self, meta_info: Meta) -> DBResult<T>
    where
        T: Decode + Clone,
    {
        if meta_info.length == Some(0)
            || meta_info.file_number.is_none()
            || meta_info.offset.is_none()
            || meta_info.length.is_none()
        {
            return Err(Box::new(DBError::new(DBErrorType::UnexpectedError(
                "No meta information from block".to_string(),
            ))));
        }

        match self.block_file.get::<T>(
            meta_info.file_number.unwrap(),
            meta_info.offset.unwrap(),
            meta_info.length.unwrap() as usize,
        ) {
            Ok(b) => Ok(b),
            Err(_) => Err(Box::new(DBError::new(DBErrorType::UnexpectedError(
                "Failed to get block file".to_string(),
            )))),
        }
    }

    pub fn set_block_status(&mut self, hash: &Vec<u8>, status: BlockStatus) -> DBResult<()> {
        let mut hash_cpy = hash.clone();
        hash_cpy.insert(0, 's' as u8);

        let status_byte = status.to_output();

        self.database.set(&hash_cpy, &vec![status_byte])
    }

    pub fn get_block_status(&self, hash: &Vec<u8>) -> DBResult<BlockStatus> {
        let mut hash_cpy = hash.clone();
        hash_cpy.insert(0, 's' as u8);
        let status_u8: u8;
        if let Ok(num) = self.database._get(&hash_cpy) {
            status_u8 = num[0];
        } else {
            return Ok(BlockStatus::Nothing);
        }
        match BlockStatus::from_input(status_u8) {
            Ok(block_status) => Ok(block_status),
            Err(e) => Err(Box::new(DBError::new(DBErrorType::UnexpectedError(
                e.to_string(),
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::block::tests::create_test_block_without_meta;
    use crate::common::block::Block;
    use crate::common::header::Header;
    use crate::common::signed_tx::SignedTx;
    use crate::common::test_functions::common_tests::assert_block;
    use crate::database::block_file::BlockFileResult;
    use crate::database::mock::RocksDBMock;

    struct BlockFileMock {
        write_location: WriteLocation,
        encoded_block: Vec<u8>,
    }

    impl BlockFileMock {
        pub fn new(write_location: WriteLocation, encoded_block: Vec<u8>) -> BlockFileMock {
            BlockFileMock {
                write_location,
                encoded_block,
            }
        }
    }

    const MAX_MOCK_FILE_SIZE: u64 = 1000;

    impl BlockFileOps for BlockFileMock {
        fn new(_path: &PathBuf, _file_number: u32, _file_position: u64) -> BlockFileResult<Self> {
            let write_location = WriteLocation {
                file_number: 0,
                file_position: 0,
                offset: 0,
                length: 0,
            };
            Ok(BlockFileMock::new(write_location, vec![]))
        }
        fn get<T>(&mut self, _file_number: u32, _offset: u64, _length: usize) -> BlockFileResult<T>
        where
            T: Decode,
        {
            T::decode(&self.encoded_block)
        }
        fn put<T>(&mut self, any_block: &mut T) -> BlockFileResult<WriteLocation>
        where
            T: Encode + Proto,
        {
            let bytes = any_block.encode()?;
            let length = bytes.len() as u64;
            self.encoded_block = bytes.clone();

            let carry = if self.write_location.file_position + length > MAX_MOCK_FILE_SIZE {
                1
            } else {
                0
            };
            self.write_location.file_number = self.write_location.file_number + carry;
            self.write_location.file_position = if carry == 1 {
                length
            } else {
                self.write_location.file_position + length
            };
            self.write_location.offset = if carry == 1 {
                0
            } else {
                self.write_location.file_position - length
            };

            Ok(WriteLocation {
                file_number: self.write_location.file_number,
                file_position: self.write_location.file_position,
                offset: self.write_location.offset,
                length: length as u32,
            })
        }
    }

    #[test]
    fn it_set_block_status_and_get_from_db() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(db_keys);
        let mut hash = vec![167];
        let block_status = BlockStatus::Block;

        db.set_block_status(&hash, block_status).unwrap();
        let _status = db.get_block_status(&hash).unwrap();

        hash.push(123);
        match db.get_block_status(&hash) {
            Err(e) => assert_eq!(e.error_type, DBErrorType::NotFoundError),
            Ok(status) => assert_eq!(status, BlockStatus::Nothing),
        }
    }

    #[test]
    #[should_panic]
    fn it_set_hash_using_height_and_get_from_db() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(db_keys);
        let hash = vec![167, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let height = 0xFFFFFFFE;
        db.set_hash_using_height(height, &hash).unwrap();
        let db_hash = db.get_hash_by_height(height).unwrap();
        assert_eq!(db_hash, hash);

        db.get_hash_by_height(height + 1).unwrap();
    }

    #[test]
    fn it_set_header_tip_hash_and_get_from_db() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(db_keys);
        let hash = vec![13, 04, 05, 09];

        db.set_header_tip_hash(&hash).unwrap();

        let db_hash = db.get_header_tip_hash().unwrap();
        assert_eq!(db_hash, hash);
    }

    #[test]
    fn it_check_file_numbers_and_positions_when_it_set_and_get_many_blocks() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(db_keys);
        let mut hash = b"hash_for_test_meta".to_vec();
        let mut blocks = vec![];

        for i in 1..255 {
            if hash.len() > 50 {
                hash.pop();
            }
            hash.push(i as u8);

            db.set_hash_using_height(i, &hash).unwrap();
            assert_eq!(db.get_hash_by_height(i).unwrap(), hash);

            let mut block = create_test_block_without_meta();
            let write_location = db.set_block(&mut block).unwrap();
            let mut meta = create_meta_without_file_info();
            meta.file_number = Some(write_location.file_number);
            meta.offset = Some(write_location.offset);
            meta.length = Some((write_location.length) as u32);
            db.set_meta(&hash, &meta).unwrap();
            assert_meta(meta, db.get_meta(&hash).unwrap());
            let result_block = db.get_block(&hash);
            blocks.push(block.clone());
            assert_block(block, result_block.unwrap());
        }

        let database_blocks: Vec<Block<Header, SignedTx>> = db.get_blocks(1, 255).unwrap();
        let blocks_cnt = database_blocks.len();
        for i in 0..blocks_cnt - 1 {
            assert_block(
                blocks.get(i).unwrap().clone(),
                database_blocks.get(i).unwrap().clone(),
            );
        }
    }

    #[test]
    fn it_set_block_tip_hash_and_get_from_db() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(db_keys);
        let mut hash = vec![04, 05, 09, 13];
        for i in 0..255 {
            if hash.len() > 50 {
                hash.pop();
            }
            hash.push(i % 255 as u8);
            db.set_block_tip_hash(&hash).unwrap();
            let db_hash = db.get_block_tip_hash().unwrap();
            assert_eq!(db_hash, hash);
        }
    }

    #[test]
    fn it_set_meta_info_to_db_and_get() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(db_keys);
        let meta_info = create_meta();

        let mut hash = vec![
            218, 175, 98, 56, 136, 59, 157, 43, 178, 250, 66, 194, 50, 129, 87, 37, 147, 54, 157,
            79, 238, 83, 118, 209, 92, 202, 25, 32, 246, 230, 153, 39,
        ];

        db.set_meta(&hash, &meta_info).unwrap();

        match db.get_meta(&hash) {
            Ok(meta) => {
                assert_eq!(meta.height, meta_info.height);
                assert_eq!(meta.t_ema, meta_info.t_ema);
                assert_eq!(meta.p_ema, meta_info.p_ema);
                assert_eq!(meta.next_difficulty, meta_info.next_difficulty);
                assert_eq!(meta.total_work, meta_info.total_work);
                assert_eq!(meta.offset.unwrap(), meta_info.offset.unwrap());
                assert_eq!(meta.file_number.unwrap(), meta_info.file_number.unwrap());
                assert_eq!(meta.length.unwrap(), meta_info.length.unwrap());
            }
            Err(err) => panic!(format!(
                "meta data should be same as the original one {:?}",
                err
            )),
        }

        hash.insert(0, 't' as u8);
        match db.get_meta(&hash) {
            Ok(meta) => panic!(format!(
                "meta data with wrong hash should not be found from db {:?}",
                meta
            )),
            Err(e) => match e.error_type {
                DBErrorType::NotFoundError => {}
                _ => panic!("{:?}", e),
            },
        }
    }

    #[test]
    fn it_set_meta_info_without_file_info_to_db_and_get() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(db_keys);
        let meta_info = create_meta_without_file_info();

        let mut hash = vec![
            218, 1, 2, 3, 4, 5, 175, 98, 56, 136, 59, 157, 43, 178, 250, 66, 194, 50, 129,
        ];

        assert_eq!(meta_info.file_number, None);
        assert_eq!(meta_info.offset, None);
        assert_eq!(meta_info.length, None);
        db.set_meta(&hash, &meta_info).unwrap();

        match db.get_meta(&hash) {
            Ok(meta) => {
                assert_eq!(meta.height, meta_info.height);
                assert_eq!(meta.t_ema, meta_info.t_ema);
                assert_eq!(meta.p_ema, meta_info.p_ema);
                assert_eq!(meta.next_difficulty, meta_info.next_difficulty);
                assert_eq!(meta.total_work, meta_info.total_work);
                // protobuf encoding for BlockDB gives 0 for ()
                assert_eq!(meta.file_number, Some(0));
                assert_eq!(meta.offset, Some(0));
                assert_eq!(meta.length, Some(0));
            }
            Err(err) => panic!(format!(
                "meta data should be same as the original one {:?}",
                err
            )),
        }

        hash.insert(0, 't' as u8);
        match db.get_meta(&hash) {
            Ok(meta) => panic!(format!(
                "meta data with wrong hash should not be found from db {:?}",
                meta
            )),
            Err(e) => match e.error_type {
                DBErrorType::NotFoundError => {}
                _ => panic!("{:?}", e),
            },
        }
    }

    fn create_database(db_keys: DBKeys) -> BlockDB<BlockFileMock, RocksDBMock> {
        let mut path = PathBuf::new();
        let mut file_path = PathBuf::new();
        path.push("./test");
        file_path.push("./testFile");
        BlockDB::<BlockFileMock, RocksDBMock>::new(path, file_path, db_keys, None).unwrap()
    }

    fn create_meta_without_file_info() -> Meta {
        let height = 1234589;
        let t_ema = 134.0;
        let p_ema = 0.234;
        let next_difficulty = 0.01345;
        let total_work = 1e23;
        Meta::new(
            height,
            t_ema,
            p_ema,
            next_difficulty,
            total_work,
            None,
            None,
            None,
            BlockStatus::Block,
        )
    }

    fn create_meta() -> Meta {
        let mut meta = create_meta_without_file_info();
        meta.offset = Some(123);
        meta.file_number = Some(234);
        meta.length = Some(345);
        meta
    }

    fn assert_meta(meta1: Meta, meta2: Meta) {
        assert_eq!(meta1.height, meta1.height);
        assert_eq!(meta1.t_ema, meta2.t_ema);
        assert_eq!(meta1.p_ema, meta2.p_ema);
        assert_eq!(meta1.next_difficulty, meta2.next_difficulty);
        assert_eq!(meta1.total_work, meta2.total_work);
        assert_eq!(meta1.file_number, meta2.file_number);
        assert_eq!(meta1.offset, meta2.offset);
        assert_eq!(meta1.length, meta2.length);
    }
}
