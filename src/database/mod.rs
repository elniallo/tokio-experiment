pub mod block_db;
pub mod block_file;
pub mod dbkeys;
pub mod state_db;
use crate::account::db_state::DBState;
use crate::traits::{Decode, Encode};
use rocksdb::{
    BlockBasedIndexType, BlockBasedOptions, Error as RocksdbError, MergeOperands,
    Options as RocksDBOptions, SliceTransform, WriteBatch, DB as RocksDB,
};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io;
use std::path::PathBuf;

type DBResult<T> = Result<T, Box<DBError>>;
type HashValue = Vec<u8>;

pub fn merge_function(
    _new_key: &[u8],
    existing_value: Option<&[u8]>,
    operands: &mut MergeOperands,
) -> Option<Vec<u8>> {
    if let Some(value) = existing_value {
        let mut db_state: DBState = DBState::decode(value).unwrap();
        for _op in operands {
            db_state.ref_count += 1;
        }
        return Some(db_state.encode().unwrap());
    } else {
        let refs = operands.size_hint().0;
        if let Some(value) = operands.last() {
            let mut db_state: DBState = DBState::decode(value).unwrap();
            db_state.ref_count += refs as u32 - 1;
            return Some(db_state.encode().unwrap());
        } else {
            None
        }
    }
}

pub trait IDB {
    type OptionType;
    fn get_default_option() -> Self::OptionType;
    fn open(db_path: PathBuf, options: Option<Self::OptionType>) -> DBResult<Self>
    where
        Self: Sized;
    fn destroy(db_path: PathBuf) -> DBResult<()>
    where
        Self: Sized;
    fn _get(&self, key: &[u8]) -> DBResult<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &Vec<u8>) -> DBResult<()>;
    fn delete(&mut self, key: &[u8]) -> DBResult<()>;
    fn write_batch(&mut self, key_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> DBResult<()>;
}

impl IDB for RocksDB {
    type OptionType = RocksDBOptions;

    fn get_default_option() -> Self::OptionType {
        let mut opts = Self::OptionType::default();
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_index_type(BlockBasedIndexType::HashSearch);
        opts.set_block_based_table_factory(&block_opts);
        let prefix_extractor = SliceTransform::create_fixed_prefix(32);
        opts.set_prefix_extractor(prefix_extractor);
        opts.create_if_missing(true);
        opts
    }

    fn open(db_path: PathBuf, options: Option<Self::OptionType>) -> DBResult<Self> {
        if let Some(opt) = options {
            match RocksDB::open(&opt, db_path) {
                Ok(database) => return Ok(database),
                Err(e) => return Err(Box::new(DBError::new(DBErrorType::RocksDBError(e)))),
            }
        } else {
            let opt: Self::OptionType = Self::get_default_option();
            match RocksDB::open(&opt, db_path) {
                Ok(database) => return Ok(database),
                Err(e) => return Err(Box::new(DBError::new(DBErrorType::RocksDBError(e)))),
            }
        }
    }

    fn destroy(db_path: PathBuf) -> DBResult<()> {
        match RocksDB::destroy(&(RocksDB::get_default_option()), db_path) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(Box::new(DBError::new(DBErrorType::RocksDBError(e)))),
        }
    }

    fn _get(&self, key: &[u8]) -> DBResult<Vec<u8>> {
        match self.get(key) {
            Ok(Some(val)) => Ok(val.to_vec()),
            Ok(None) => Err(Box::new(DBError::new(DBErrorType::NotFoundError))),
            Err(err) => Err(Box::new(DBError::new(DBErrorType::RocksDBError(err)))),
        }
    }

    fn set(&mut self, key: &[u8], value: &Vec<u8>) -> DBResult<()> {
        match self.put(key, value) {
            Ok(()) => Ok(()),
            Err(err) => Err(Box::new(DBError::new(DBErrorType::RocksDBError(err)))),
        }
    }

    fn delete(&mut self, _key: &[u8]) -> DBResult<()> {
        Ok(())
    }

    fn write_batch(&mut self, key_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> DBResult<()> {
        let mut batch = WriteBatch::default();
        for (k, v) in key_pairs {
            match batch.merge(&k, &v) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Box::new(DBError::new(DBErrorType::RocksDBError(e))));
                }
            }
        }
        match self.write(batch) {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(DBError::new(DBErrorType::RocksDBError(e)))),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DBErrorType {
    RocksDBError(RocksdbError),
    NotFoundError,
    UnexpectedError(String),
}

#[derive(Debug)]
pub struct DBError {
    error_type: DBErrorType,
}

impl DBError {
    pub fn new(error_type: DBErrorType) -> DBError {
        DBError { error_type }
    }
}

impl Display for DBError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self.error_type {
            DBErrorType::RocksDBError(ref err) => err.fmt(f),
            DBErrorType::NotFoundError => write!(f, "Not Found"),
            DBErrorType::UnexpectedError(ref err) => write!(f, "Unexpected Error Occurs {}", err),
        }
    }
}
impl Error for DBError {
    fn description(&self) -> &str {
        match self.error_type {
            DBErrorType::RocksDBError(ref err) => err.description(),
            DBErrorType::NotFoundError => From::from("Not found error"),
            DBErrorType::UnexpectedError(ref err) => &err,
        }
    }
}

impl From<RocksdbError> for DBError {
    fn from(err: RocksdbError) -> Self {
        DBError::new(DBErrorType::RocksDBError(err))
    }
}

impl From<String> for DBError {
    fn from(err_msg: String) -> Self {
        DBError::new(DBErrorType::UnexpectedError(err_msg))
    }
}

impl From<Box<Error>> for DBError {
    fn from(err: Box<Error>) -> Self {
        DBError::new(DBErrorType::UnexpectedError(format!(
            "UNEXPECTED DB ERROR : {:?} ",
            err
        )))
    }
}

impl From<io::Error> for DBError {
    fn from(err: io::Error) -> Self {
        DBError::new(DBErrorType::UnexpectedError(format!(
            "UNEXPECTED DB ERROR : {:?} ",
            err
        )))
    }
}

pub mod mock {
    use super::*;
    use crate::account::db_state::DBState;
    use crate::traits::{Decode, Encode};
    use std::collections::HashMap;
    pub struct RocksDBMock {
        db: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl RocksDBMock {
        pub fn new(db: HashMap<Vec<u8>, Vec<u8>>) -> RocksDBMock {
            RocksDBMock { db }
        }
    }

    impl IDB for RocksDBMock {
        type OptionType = ();

        fn get_default_option() -> () {
            ()
        }
        fn open(_db_path: PathBuf, _options: Option<Self::OptionType>) -> DBResult<Self> {
            Ok(RocksDBMock::new(HashMap::with_capacity(50000)))
        }

        fn destroy(_db_path: PathBuf) -> DBResult<()> {
            Ok(())
        }

        fn _get(&self, key: &[u8]) -> DBResult<Vec<u8>> {
            match self.db.get(key) {
                Some(val) => Ok(val.clone()),
                None => Err(Box::new(DBError::new(DBErrorType::NotFoundError))),
            }
        }

        fn set(&mut self, key: &[u8], value: &Vec<u8>) -> DBResult<()> {
            self.db.insert(key.to_vec(), value.clone());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> DBResult<()> {
            self.db.remove(key);
            Ok(())
        }
        fn write_batch(&mut self, key_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> DBResult<()> {
            for (k, v) in key_pairs {
                self.db
                    .entry(k.to_vec())
                    .and_modify(|value| {
                        let mut db_state = DBState::decode(&value).unwrap();
                        db_state.ref_count += 1;
                        *value = db_state.encode().unwrap()
                    })
                    .or_insert(v.to_vec());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::account::Account;
    use crate::account::db_state::DBState;
    use crate::util::hash::hash;
    use std::path::PathBuf;
    #[test]
    fn it_performs_merge_operations_on_rocks_instance() {
        let mut options = RocksDB::get_default_option();
        options.set_merge_operator("Update Ref Count", merge_function, None);
        let path = PathBuf::from("./test/rocks");
        let db = RocksDB::open(&options, &path).unwrap();
        let account = Account::new(123, 123);
        let db_state = DBState::new(Some(account), None, 1);
        let encoded = db_state.encode().unwrap();
        let _ = db.delete(&hash(&encoded, 32));
        let res = db.merge(&hash(&encoded, 32), &encoded);
        match res {
            Ok(_) => {}
            Err(e) => {
                println!("Error: {:?}", e);
                unimplemented!();
            }
        }
        let retrieved = db.get(&hash(&encoded, 32)).unwrap();
        match retrieved {
            Some(v) => {
                let state = DBState::decode(&v).unwrap();
                assert_eq!(state.ref_count, 1u32);
            }
            None => {
                println!("Got nothing");
                unimplemented!();
            }
        }
        let new_res = db.merge(&hash(&encoded, 32), &encoded);
        match new_res {
            Ok(_) => {}
            Err(e) => {
                println!("Error: {:?}", e);
                unimplemented!();
            }
        }
        let new_retrieved = db.get(&hash(&encoded, 32)).unwrap();
        match new_retrieved {
            Some(v) => {
                let state = DBState::decode(&v).unwrap();
                assert_eq!(state.ref_count, 2u32);
            }
            None => {
                println!("Got nothing");
                unimplemented!();
            }
        }
    }
}
