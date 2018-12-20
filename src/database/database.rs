use rocksdb::{DB as RocksDB, Options as RocksDBOptions, BlockBasedOptions, BlockBasedIndexType, SliceTransform};
use database::DBError;
use database::dbkeys::DBKeys;
use common::meta::Meta;
use common::{Decode, Encode};
use database::block_file::{BlockFile, BlockFileOps, PutResult as WriteLocation};
use common::block_status::{BlockStatus, EnumConverter};
use byteorder::{ByteOrder, BigEndian};
use common::Proto;
use std::path::PathBuf;

type DBResult<T> = Result<T, DBError>;
type HashValue = Vec<u8>;

pub trait IDatabase<'a>: Sized {
    fn new(db_path: PathBuf, file_path: PathBuf, db_keys: &'a DBKeys, options: Option<RocksDBOptions>) -> DBResult<Self>;
    fn get_header_tip_hash(&self) -> DBResult<HashValue>;
    fn set_header_tip_hash(&mut self, hash: &HashValue) -> DBResult<()>;
    fn get_block_tip_hash(&self) -> DBResult<HashValue>;
    fn set_block_tip_hash(&mut self, hash: &HashValue) -> DBResult<()>;
    fn set_hash_using_height(&mut self, height: u32, hash: &HashValue) -> DBResult<()>;
    fn get_hash_by_height(&self, height: u32) -> DBResult<HashValue>;
    fn set_meta(&mut self, hash: &HashValue, meta_info: &Meta) -> DBResult<()>;
    fn get_meta(&self, hash: &HashValue) -> DBResult<Meta>;
    fn set_block<T>(&mut self, block: &mut T) -> DBResult<WriteLocation> where T: Encode + Proto;
    fn get_blocks<T>(&mut self, from_height: u32, count: u32) -> DBResult<Vec<T>> where T: Decode + Clone;
    fn get_block<T>(&mut self, hash: &HashValue) -> DBResult<T> where T: Decode + Clone;
    fn get_block_by_height<T>(&mut self, height: u32) -> DBResult<T> where T: Decode + Clone;
    fn get_block_by_meta_info<T>(&mut self, meta_info: Meta) -> DBResult<T> where T: Decode + Clone;
    fn set_block_status(&mut self, hash: &HashValue, status: BlockStatus) -> DBResult<()>;
    fn get_block_status(&self, hash: &HashValue) -> DBResult<BlockStatus>;
}

pub trait IDB {
    type OptionType;
    fn get_default_option() -> Self::OptionType;
    fn open(db_path: PathBuf, options: Option<RocksDBOptions>) -> DBResult<Self> where Self: Sized;
    fn destroy(db_path: PathBuf) -> DBResult<()> where Self: Sized;
    fn get(&self, key: &[u8]) -> DBResult<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &Vec<u8>) -> DBResult<()>;
}

impl IDB for RocksDB {
    type OptionType = RocksDBOptions;

    fn get_default_option() -> RocksDBOptions {
        let mut opts = RocksDBOptions::default();
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_index_type(BlockBasedIndexType::HashSearch);
        opts.set_block_based_table_factory(&block_opts);
        let prefix_extractor = SliceTransform::create_fixed_prefix(32);
        opts.set_prefix_extractor(prefix_extractor);
        opts.create_if_missing(true);
        opts
    }

    fn open(db_path: PathBuf, options: Option<RocksDBOptions>) -> DBResult<Self> {
        if let Some(opt) = options {
            return Ok(RocksDB::open(&opt, db_path)?);
        } else {
            let opt: RocksDBOptions = Self::get_default_option();
            return Ok(RocksDB::open(&opt, db_path)?);
        }
    }

    fn destroy(db_path: PathBuf) -> DBResult<()> {
        Ok(RocksDB::destroy(&(RocksDB::get_default_option()), db_path)?)
    }

    fn get(&self, key: &[u8]) -> DBResult<Vec<u8>> {
        match self.get(key) {
            Ok(Some(val)) => Ok(val.to_vec()),
            Ok(None) => Err(DBError::NotFoundError),
            Err(err) => Err(DBError::RocksDBError(err))
        }
    }

    fn set(&mut self, key: &[u8], value: &Vec<u8>) -> DBResult<()> {
        match self.put(key, value) {
            Ok(()) => Ok(()),
            Err(err) => Err(DBError::RocksDBError(err))
        }
    }
}


pub struct Database<'a, BlockFileType = BlockFile, DatabaseType = RocksDB>
    where BlockFileType: BlockFileOps, DatabaseType: IDB {
    database: DatabaseType,
    block_file: BlockFileType,
    file_number: u32,
    db_keys: &'a DBKeys,
}

impl<'a, BlockFileType, DatabaseType> IDatabase<'a> for Database<'a, BlockFileType, DatabaseType>
    where BlockFileType: BlockFileOps, DatabaseType: IDB {
    fn new(db_path: PathBuf, file_path: PathBuf, db_keys: &'a DBKeys, options: Option<RocksDBOptions>) -> DBResult<Self> {
        let mut database = DatabaseType::open(db_path, options)?;
        let file_number = match database.get(&db_keys.file_number) {
            Ok(val) => BigEndian::read_u32(&val),
            Err(DBError::NotFoundError) => {
                database.set(&db_keys.file_number, &vec![0; 4])?;
                0
            }
            Err(err) => return Err(err)
        };
        let file_position = match database.get(&db_keys.file_position) {
            Ok(val) => BigEndian::read_u64(&val),
            Err(DBError::NotFoundError) => {
                database.set(&db_keys.file_number, &vec![0; 8])?;
                0
            }
            Err(err) => return Err(err)
        };
        Ok(Database {
            database,
            block_file: BlockFileType::new(&file_path, file_number, file_position)?,
            file_number,
            db_keys,
        })
    }

    fn get_header_tip_hash(&self) -> DBResult<HashValue> {
        self.database.get(&self.db_keys.header_tip)
    }

    fn set_header_tip_hash(&mut self, hash: &HashValue) -> DBResult<()> {
        self.database.set(&self.db_keys.header_tip, hash)
    }

    fn get_block_tip_hash(&self) -> DBResult<HashValue> {
        self.database.get(&self.db_keys.block_tip)
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
        self.database.get(&height_buf)
    }

    fn set_meta(&mut self, hash: &HashValue, meta_info: &Meta) -> DBResult<()> {
        let mut hash_copy = hash.clone();
        hash_copy.insert(0, b"b"[0]);
        let encoded = meta_info.encode()?;
        self.database.set(hash_copy.as_ref(), &encoded)
    }

    fn get_meta(&self, hash: &HashValue) -> DBResult<Meta> {
        let mut hash_copy = hash.clone();
        hash_copy.insert(0, b"b"[0]);
        match self.database.get(&hash_copy) {
            Ok(value) => Ok(Meta::decode(&value.to_vec())?),
            Err(_err) => Err(_err),
        }
    }

    fn set_block<T>(&mut self, block: &mut T) -> DBResult<WriteLocation>
        where T: Encode + Proto, {
        let write_location = self.block_file.put::<T>(block)?;
        if self.file_number != write_location.file_number {
            self.file_number = write_location.file_number;
            let mut file_number_buf = vec![0; 4];
            BigEndian::write_u32(&mut file_number_buf, write_location.file_number);
            self.database.set(&self.db_keys.file_number, &file_number_buf)?;
        }
        let mut file_position_buf = vec![0; 8];
        BigEndian::write_u64(&mut file_position_buf, write_location.file_position);
        self.database.set(&self.db_keys.file_position, &file_position_buf)?;
        Ok(write_location)
    }

    fn get_blocks<T>(&mut self, from_height: u32, count: u32) -> DBResult<Vec<T>> where T: Decode + Clone {
        let mut i = 0;
        let mut blocks = Vec::new();
        let _limit = count - 1;
        while i != _limit {
            blocks.push(self.get_block_by_height(from_height + i)?);
            i += 1;
        }
        Ok(blocks)
    }

    fn get_block<T>(&mut self, hash: &HashValue) -> DBResult<T> where T: Decode + Clone {
        let meta_info = self.get_meta(hash)?;
        self.get_block_by_meta_info::<T>(meta_info)
    }

    fn get_block_by_height<T>(&mut self, height: u32) -> DBResult<T> where T: Decode + Clone {
        let hash = self.get_hash_by_height(height)?;
        self.get_block::<T>(&hash)
    }

    fn get_block_by_meta_info<T>(&mut self, meta_info: Meta) -> DBResult<T> where T: Decode + Clone {
        if meta_info.length == Some(0) || meta_info.file_number.is_none()
            || meta_info.offset.is_none() || meta_info.length.is_none() {
            return Err(From::from("No Block Information".to_string()));
        }

        Ok(self.block_file.get::<T>(meta_info.file_number.unwrap(), meta_info.offset.unwrap(),
                                    meta_info.length.unwrap() as usize)?)
    }


    fn set_block_status(&mut self, hash: &Vec<u8>, status: BlockStatus) -> DBResult<()> {
        let mut hash_cpy = hash.clone();
        hash_cpy.insert(0, 's' as u8);

        let status_byte = status.to_u8();

        self.database.set(&hash_cpy, &vec![status_byte])
    }

    fn get_block_status(&self, hash: &Vec<u8>) -> DBResult<BlockStatus> {
        let mut hash_cpy = hash.clone();
        hash_cpy.insert(0, 's' as u8);

        match BlockStatus::from_u8(self.database.get(&hash_cpy)?.to_vec()[0]) {
            Some(block_status) => Ok(block_status),
            None => Err(From::from("from data to BlockStatus error".to_string())),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use database::database::IDB;
    use common::block::Block;
    use common::header::Header;
    use common::signed_tx::SignedTx;
    use common::common_tests::common_tests::assert_block;
    use common::block::tests::create_test_block_without_meta;
    use std::collections::HashMap;
    use database::block_file::BlockFileResult;


    struct RocksDBMock {
        db: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl Default for RocksDBMock {
        fn default() -> Self {
            RocksDBMock {
                db: HashMap::new()
            }
        }
    }

    impl IDB for RocksDBMock {
        type OptionType = ();

        fn get_default_option() -> () {
            ()
        }
        fn open(_db_path: PathBuf, options: Option<RocksDBOptions>) -> DBResult<Self> {
            Ok(RocksDBMock::default())
        }

        fn destroy(_db_path: PathBuf) -> DBResult<()> {
            Ok(())
        }

        fn get(&self, key: &[u8]) -> DBResult<Vec<u8>> {
            match self.db.get(key) {
                Some(val) => Ok(val.clone()),
                None => Err(DBError::NotFoundError)
            }
        }

        fn set(&mut self, key: &[u8], value: &Vec<u8>) -> DBResult<()> {
            self.db.insert(key.to_vec(), value.clone());
            Ok(())
        }
    }

    struct BlockFileMock {
        write_location: WriteLocation,
        encoded_block: Vec<u8>,
    }

    impl Default for BlockFileMock {
        fn default() -> Self {
            BlockFileMock {
                write_location: WriteLocation {
                    file_number: 0,
                    file_position: 0,
                    offset: 0,
                    length: 0,
                },
                encoded_block: vec![],
            }
        }
    }

    const MAX_MOCK_FILE_SIZE: u64 = 1000;

    impl BlockFileOps for BlockFileMock {
        fn new(_path: &PathBuf, _file_number: u32, _file_position: u64) -> BlockFileResult<Self> {
            Ok(BlockFileMock::default())
        }
        fn get<T>(&mut self, _file_number: u32, _offset: u64, _length: usize) -> BlockFileResult<T>
            where T: Decode {
            T::decode(&self.encoded_block)
        }
        fn put<T>(&mut self, any_block: &mut T) -> BlockFileResult<WriteLocation>
            where T: Encode + Proto {
            let bytes = any_block.encode()?;
            let length = bytes.len() as u64;
            self.encoded_block = bytes.clone();

            let carry = if self.write_location.file_position + length > MAX_MOCK_FILE_SIZE { 1 } else { 0 };
            self.write_location.file_number = self.write_location.file_number + carry;
            self.write_location.file_position = if carry == 1 { length } else { self.write_location.file_position + length };
            self.write_location.offset = if carry == 1 { 0 } else { self.write_location.file_position - length };

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
        let mut db = create_database(&db_keys);
        let mut hash = vec![167];
        let block_status = BlockStatus::Block;

        match db.set_block_status(&hash, block_status) {
            Ok(()) => (),
            Err(err) => panic!(format!("BlockStatus::Block is not set {:?}", err)),
        }

        match db.get_block_status(&hash) {
            Ok(val) => assert_eq!(val, BlockStatus::Block),
            Err(err) => panic!(format!("It should have same BlockStatus::Block {:?}", err)),
        }
        hash.push(123);
        match db.get_block_status(&hash) {
            Err(DBError::NotFoundError) => {}
            _ => panic!("It should not exist {:?}"),
        }
    }


    #[test]
    fn it_set_hash_using_height_and_get_from_db() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(&db_keys);
        let hash = vec![167, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let height = 0xFFFFFFFE;
        match db.set_hash_using_height(height, &hash) {
            Ok(()) => (),
            Err(err) => panic!(format!("set_hash error {:?}", err)),
        }

        match db.get_hash_by_height(height) {
            Ok(val) => assert_eq!(val, hash),
            Err(err) => panic!(format!("get_hash failed {:?}", err)),
        }

        match db.get_hash_by_height(height + 1) {
            Ok(_val) => panic!("wrong key must give error"),
            Err(DBError::NotFoundError) => {}
            Err(_err) => panic!(format!("ERROR OCCURED : {:?}", _err)),
        }
    }

    #[test]
    fn it_set_header_tip_hash_and_get_from_db() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(&db_keys);
        let hash = vec![13, 04, 05, 09];

        match db.set_header_tip_hash(&hash) {
            Ok(()) => (),
            Err(err) => panic!(format!("set_header_tip_hash with {:?} failed {:?}", hash, err)),
        }

        match db.get_header_tip_hash() {
            Ok(val) => assert_eq!(val, hash),
            Err(err) => panic!(format!("get_header_tip_hash failed {:?}", err)),
        }
    }

    #[test]
    fn it_check_file_numbers_and_positions_when_it_set_and_get_many_blocks() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(&db_keys);
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
            assert_block(blocks.get(i).unwrap().clone(), database_blocks.get(i).unwrap().clone());
        }
    }

    #[test]
    fn it_set_block_tip_hash_and_get_from_db() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(&db_keys);
        let mut hash = vec![04, 05, 09, 13];
        for i in 0..255 {
            if hash.len() > 50 {
                hash.pop();
            }
            hash.push(i % 255 as u8);
            match db.set_block_tip_hash(&hash) {
                Ok(()) => (),
                Err(err) => panic!(format!("set_block_tip_hash with {:?} failed {:?}", hash, err)),
            }

            match db.get_block_tip_hash() {
                Ok(val) => assert_eq!(val, hash),
                Err(err) => panic!(format!("set_block_tip_hash failed {:?}", err)),
            }
        }
    }

    #[test]
    fn it_set_meta_info_to_db_and_get() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(&db_keys);
        let meta_info = create_meta();

        let mut hash = vec![218, 175, 98, 56, 136, 59, 157, 43, 178, 250, 66, 194, 50, 129, 87, 37,
                            147, 54, 157, 79, 238, 83, 118, 209, 92, 202, 25, 32, 246, 230, 153, 39];


        match db.set_meta(&hash, &meta_info) {
            Ok(()) => {}
            Err(err) => panic!(format!("meta data should be set into db {:?}", err))
        }

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
            Err(err) => panic!(format!("meta data should be same as the original one {:?}", err))
        }

        hash.insert(0, 't' as u8);
        match db.get_meta(&hash) {
            Ok(meta) => panic!(format!("meta data with wrong hash should not be found from db {:?}", meta)),
            Err(DBError::NotFoundError) => (),
            Err(_err) => panic!(format!("ERROR OCCURED : {:?}", _err)),
        }
    }

    #[test]
    fn it_set_meta_info_without_file_info_to_db_and_get() {
        let db_keys = DBKeys::new(b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec());
        let mut db = create_database(&db_keys);
        let meta_info = create_meta_without_file_info();

        let mut hash = vec![218, 1, 2, 3, 4, 5, 175, 98, 56, 136, 59, 157, 43, 178, 250, 66, 194, 50, 129];

        assert_eq!(meta_info.file_number, None);
        assert_eq!(meta_info.offset, None);
        assert_eq!(meta_info.length, None);
        match db.set_meta(&hash, &meta_info) {
            Ok(()) => {}
            Err(err) => panic!(format!("meta data should be set into db {:?}", err))
        }

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
            Err(err) => panic!(format!("meta data should be same as the original one {:?}", err))
        }

        hash.insert(0, 't' as u8);
        match db.get_meta(&hash) {
            Ok(meta) => panic!(format!("meta data with wrong hash should not be found from db {:?}", meta)),
            Err(DBError::NotFoundError) => (),
            Err(_err) => panic!(format!("ERROR OCCURED : {:?}", _err)),
        }
    }

    fn create_database<'a>(db_keys: &'a DBKeys) -> Database<'a, BlockFileMock, RocksDBMock> {
        let mut path = PathBuf::new();
        let mut file_path = PathBuf::new();
        path.push("./test");
        file_path.push("./testFile");
        Database::<'a, BlockFileMock, RocksDBMock>::new(path, file_path, db_keys, None).unwrap()
    }

    fn create_meta_without_file_info() -> Meta {
        let height = 1234589;
        let t_ema = 134.0;
        let p_ema = 0.234;
        let next_difficulty = 0.01345;
        let total_work = 1e23;
        Meta::new(height, t_ema, p_ema, next_difficulty, total_work, None, None, None)
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