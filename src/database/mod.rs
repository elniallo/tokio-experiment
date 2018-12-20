
pub mod database;
pub mod block_file;
use std::io;
use std::ops::Deref;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use rocksdb::{Error as RocksdbError};


#[derive(Debug)]
pub enum DBError {
    RocksDBError(RocksdbError),
    NotFoundError,
    UnexpectedError(String),
}


impl Deref for DBError {
    type Target = DBError;
    fn deref(&self) -> &Self::Target {
        self
    }
}

impl Display for DBError{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            DBError::RocksDBError(ref err) => err.fmt(f),
            DBError::NotFoundError => write!(f, "Not Found"),
            DBError::UnexpectedError(ref err) => write!(f, "Unexpected Error Occurs {}", err)
        }
    }
}
impl Error for DBError  {
    fn description(&self) -> &str {
        match *self {
            DBError::RocksDBError(ref err) => err.description(),
            DBError::NotFoundError => From::from("Not found error"),
            DBError::UnexpectedError(ref err) => &err,
        }
    }
}

impl From<RocksdbError> for DBError {
    fn from(err: RocksdbError) -> Self {
        DBError::RocksDBError(err)
    }    
}

impl From<String> for DBError {
    fn from(err_msg: String) -> Self {
        DBError::UnexpectedError(err_msg)
    }    
}

impl From< Box<Error> > for DBError {
    fn from(err: Box<Error>) -> Self{
        DBError::UnexpectedError(format!("UNEXPECTED DB ERROR : {:?} ", err))
    }
}

impl From< io::Error> for DBError{
    fn from(err: io::Error) ->Self{
        DBError::UnexpectedError(format!("UNEXPECTED DB ERROR : {:?} ", err))
    }
}
