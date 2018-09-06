use std::f64::consts;
use std::num;
use std::error::Error;

use common::block::Block;
use common::header::BlockHeader;
use common::meta::Meta;
use common::Exception;

use byteorder::{ByteOrder, BigEndian, LittleEndian};

pub const TARGET_TIME: f64 = 30000.0 / consts::LN_2;
pub const MAX_DIFFICULTY: f64 = 1.0;
pub const MIN_DIFFICULTY: f64 = 8.636e-78; // 1 / 2^256
pub const ALPHA: f64 = 0.003;

pub fn calc_ema(new_value: f64, previous_value: f64, alpha: f64) -> f64 {
    alpha * new_value + (1.0 - alpha) * previous_value
}

pub fn adjust_difficulty<HeaderType, TxType>(previous_block: Block<HeaderType, TxType>, time_stamp: f64) -> Result<(f64, f64, f64), Box<Error>>
    where HeaderType: BlockHeader{
    let height: u32;
    let previous_time_ema: f64;
    let previous_difficulty_ema: f64;
    let difficulty: f64;
    match previous_block.meta {
        Some(meta) => {
            height = meta.height;
            previous_time_ema = meta.t_ema;
            previous_difficulty_ema = meta.p_ema;
            difficulty = meta.next_difficulty;
        },
        None => return Err(Box::new(Exception::new("Previous block is missing meta information")))
    }

    let time_delta: f64;
    if height > 0 {
        time_delta = time_stamp - previous_block.header.get_time_stamp() as f64;
    } else {
        time_delta = TARGET_TIME;
    }

    let time_ema = calc_ema(time_delta, previous_time_ema, ALPHA);
    let difficulty_ema = calc_ema(difficulty, previous_difficulty_ema, ALPHA);
    let mut next_difficulty = (time_ema * difficulty_ema ) / TARGET_TIME;
    if next_difficulty > MAX_DIFFICULTY {
        next_difficulty = MAX_DIFFICULTY;
    }
    else if next_difficulty < MIN_DIFFICULTY {
        next_difficulty = MIN_DIFFICULTY;
    }

    Ok((next_difficulty, time_ema, difficulty_ema))
}

pub fn get_target(difficulty: f64, length: usize) -> Result<Vec<u8>, Box<Error>> {
    let mut target = vec![0xFFu8; length];

    if difficulty == 1.0 {
        return Ok(target);
    } else if difficulty > MAX_DIFFICULTY || difficulty < MIN_DIFFICULTY {
        return Err(Box::new(Exception::new("Invalid difficulty value")))
    }

    let exponent = -1.0 * difficulty.log2();
    let mut index = (exponent / 8.0) as usize;
    if exponent != 0.0 && exponent % 8.0 == 0.0 {
        index -= 1;
    }

    if index + 8 > length {
        index = length - 8
    }

    let mut scaled_difficulty = difficulty;
    for i in 0..index {
        target[i] = 0;
        scaled_difficulty *= 2f64.powf(8.0);
    }
    let num = BigEndian::read_u64(&target[index..(index+8)]);
    let product = num as f64 * scaled_difficulty;
    let product_converted = product as u64 - 1;
//    println!("{}", product_converted);

    BigEndian::write_u64(&mut target[index..(index+8)], product_converted);

    Ok(target)
}

// The old version can produce delays of up to 2 hours due to inaccuracies in calculating the target.
//pub fn get_legacy_target(difficulty: f64, length: usize) -> Vec<u8> {
//    let mut target = vec![0xFF, length];
//    let carry = 0;
//    for i in 0..
//}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_calculates_a_target_for_powers_of_two() {
        let mut difficulty = 1.0;
        let length = 32;
        for exponent in 0..256 {
            difficulty = 1.0 / (2f64.powf(exponent as f64));
            let target = get_target(difficulty, length).unwrap();
            let mut index = exponent as usize / 8;
            let mut expected_value = (0xFF as f64 * 1.0 / 2f64.powf(exponent as f64 % 8.0)) as u8;
            if exponent != 0 && exponent % 8 == 0 {
                index -= 1;
                expected_value = 0;
            }

            assert_eq!(target[index], expected_value);
        }
    }

    #[test]
    fn it_calculates_a_target_for_powers_of_three() {
        let mut difficulty = 1.0;
        let length = 32;
        for exponent in 0..161 {
            println!("exponent: {}", exponent);
            difficulty = 1.0 / (3f64.powf(exponent as f64));
            println!("difficulty: {}", difficulty);
            let target = get_target(difficulty, length).unwrap();
            let mut index = (exponent / 8) as usize;
            if exponent != 0 && exponent % 8 == 0 {
                index -= 1;
            }

            if index + 8 > length {
                index = length - 8
            }

            let mut scaled_difficulty = difficulty;
            for i in 0..index {
                scaled_difficulty *= 2f64.powf(8.0);
            }
            let scale = -1 * difficulty.log2() as i64 / 8;
            println!("scale: {}", scale);
            println!("scaled_difficulty: {}", scaled_difficulty);
            let mut expected_value = 0xFFFFFFFFFFFFFFFFu64 as f64 * scaled_difficulty - 1.0;
            println!("expected_value: {}", expected_value);
            let value = BigEndian::read_u64(&target[index..index+8]);
            assert_eq!(value as f64, expected_value.ceil());
        }
    }
}