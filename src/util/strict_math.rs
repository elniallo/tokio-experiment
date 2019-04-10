use std::convert::From;
use std::error::Error;
use std::ops::{Add, Sub};
use std::u64::MAX;

use crate::traits::Exception;

type StrictMathResult<T> = Result<T, Box<Error>>;
/// Strict math to prevent overflow/underflow
#[derive(Clone, Copy)]
pub struct StrictU64(u64);

impl StrictU64 {
    pub fn new(num: u64) -> StrictU64 {
        StrictU64(num)
    }
}

impl Add<StrictU64> for StrictU64 {
    type Output = StrictMathResult<StrictU64>;
    fn add(self, rhs: StrictU64) -> Self::Output {
        if self.0 > (MAX - rhs.0) || rhs.0 > (MAX - self.0) {
            return Err(Box::new(Exception::new(&format!(
                "Overflow: {} + {} will exceed maximum u64 size",
                self.0, rhs.0
            ))));
        }
        Ok(StrictU64(self.0 + rhs.0))
    }
}

impl Sub<StrictU64> for StrictU64 {
    type Output = StrictMathResult<StrictU64>;
    fn sub(self, rhs: StrictU64) -> Self::Output {
        if self.0 < rhs.0 {
            return Err(Box::new(Exception::new(&format!(
                "Underflow: {} - {} will assign a negative value to an unsigned integer",
                self.0, rhs.0
            ))));
        }
        Ok(StrictU64(self.0 - rhs.0))
    }
}

impl From<StrictU64> for u64 {
    fn from(strict_u64: StrictU64) -> Self {
        strict_u64.0
    }
}
