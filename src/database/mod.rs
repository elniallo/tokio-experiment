
pub mod database;
pub mod block_file;
pub mod dbkeys;

use std::io;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use rocksdb::{Error as RocksdbError};

#[derive(Debug, PartialEq)]
pub enum DBErrorType {
    RocksDBError(RocksdbError),
    NotFoundError,
    UnexpectedError(String),
}

#[derive(Debug)]
pub struct DBError {
    error_type: DBErrorType
}

impl DBError {
    pub fn new(error_type: DBErrorType) -> DBError {
        DBError {
            error_type
        }
    }
}

impl Display for DBError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self.error_type {
            DBErrorType::RocksDBError(ref err) => err.fmt(f),
            DBErrorType::NotFoundError => write!(f, "Not Found"),
            DBErrorType::UnexpectedError(ref err) => write!(f, "Unexpected Error Occurs {}", err)
        }
    }
}
impl Error for DBError  {
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

impl From< Box<Error> > for DBError {
    fn from(err: Box<Error>) -> Self{
        DBError::new(DBErrorType::UnexpectedError(format!("UNEXPECTED DB ERROR : {:?} ", err)))
    }
}

impl From< io::Error> for DBError{
    fn from(err: io::Error) ->Self{
        DBError::new(DBErrorType::UnexpectedError(format!("UNEXPECTED DB ERROR : {:?} ", err)))
    }
}
