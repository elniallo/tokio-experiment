use std::error::Error;
use common::Exception;

type StrictMathResult<T> = Result<T, Box<Error>>;

pub fn strict_add(a: u64, b: u64) -> StrictMathResult<u64> {
    
}