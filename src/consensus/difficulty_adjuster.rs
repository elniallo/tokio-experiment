use std::error::Error;
use std::f64::consts;

use crate::common::block::Block;

use crate::traits::{BlockHeader, Exception};

use byteorder::{ByteOrder, LittleEndian};

pub const TARGET_TIME: f64 = 30000.0 / consts::LN_2;
pub const MAX_DIFFICULTY: f64 = 1.0;
pub const MIN_DIFFICULTY: f64 = 8.636e-78; // 1 / 2^256
pub const ALPHA: f64 = 0.003;

pub fn calc_ema(new_value: f64, previous_value: f64, alpha: f64) -> f64 {
    alpha * new_value + (1.0 - alpha) * previous_value
}

pub fn adjust_difficulty<HeaderType, TxType>(
    previous_block: Block<HeaderType, TxType>,
    time_stamp: f64,
) -> Result<(f64, f64, f64), Box<Error>>
where
    HeaderType: BlockHeader,
{
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
        }
        None => {
            return Err(Box::new(Exception::new(
                "Previous block is missing meta information",
            )));
        }
    }

    let time_delta: f64;
    if height > 0 {
        time_delta = time_stamp - previous_block.header.get_time_stamp() as f64;
    } else {
        time_delta = TARGET_TIME;
    }

    let time_ema = calc_ema(time_delta, previous_time_ema, ALPHA);
    let difficulty_ema = calc_ema(difficulty, previous_difficulty_ema, ALPHA);
    let mut next_difficulty = (time_ema * difficulty_ema) / TARGET_TIME;
    if next_difficulty > MAX_DIFFICULTY {
        next_difficulty = MAX_DIFFICULTY;
    } else if next_difficulty < MIN_DIFFICULTY {
        next_difficulty = MIN_DIFFICULTY;
    }

    Ok((next_difficulty, time_ema, difficulty_ema))
}

pub fn get_target(difficulty: f64, length: usize) -> Result<Vec<u8>, Box<Error>> {
    if length < 8 {
        return Err(Box::new(Exception::new("Invalid length")));
    }

    let mut target = vec![0xFFu8; length];

    if difficulty == 1.0 {
        return Ok(target);
    } else if difficulty > MAX_DIFFICULTY || difficulty < MIN_DIFFICULTY {
        return Err(Box::new(Exception::new("Invalid difficulty value")));
    }

    let exponent = -1.0 * difficulty.log2();
    let mut index = length - ((exponent / 8.0) as usize);
    if exponent != 0.0 && exponent % 8.0 == 0.0 {
        index += 1;
    }

    if index < 8 {
        index = 8
    }

    let mut scaled_difficulty = difficulty;
    for i in (index..length).rev() {
        target[i] = 0;
        scaled_difficulty *= 2f64.powf(8.0);
    }
    let num = LittleEndian::read_u64(&target[index - 8..index]);
    let product = num as f64 * scaled_difficulty;
    let product_converted = product as u64 - 1;

    LittleEndian::write_u64(&mut target[index - 8..index], product_converted);

    Ok(target)
}

// The old version can produce delays of up to 2 hours due to inaccuracies in calculating the target.
pub fn get_legacy_target(difficulty: f64, length: usize) -> Vec<u8> {
    let mut adjusted_difficulty = difficulty;

    if difficulty > MAX_DIFFICULTY {
        adjusted_difficulty = 1.0;
    } else if difficulty < 256f64.powf(-1.0 * length as f64) {
        adjusted_difficulty = 256f64.powf(-1.0 * length as f64);
    }

    let mut target = vec![0x0u8; length];
    let mut carry = 0.0;
    for i in (0..length).rev() {
        carry = (0x100 as f64 * carry) + (adjusted_difficulty * 0xFF as f64);
        target[i] = (carry.floor() % 256.0) as u8;
        carry -= target[i] as f64;
    }
    target
}

pub fn acceptable(hash: Vec<u8>, target: Vec<u8>) -> Result<bool, Box<Error>> {
    if hash.len() != target.len() {
        return Err(Box::new(Exception::new(
            "Hash and target are of different lengths",
        )));
    }

    for i in (0..target.len()).rev() {
        if hash[i] < target[i] {
            return Ok(true);
        } else if hash[i] > target[i] {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::block_status::BlockStatus;
    use crate::common::header::Header;
    use crate::common::meta::Meta;
    use crate::common::signed_tx::SignedTx;
    use rand::prelude::*;
    use rand::{Rng, SeedableRng};

    #[test]
    fn it_adjusts_difficulty() {
        let previous_block_header = Header::new(
            vec![0u8; 32],
            0,
            0.5,
            vec![0u8; 32],
            vec![vec![0u8; 32]],
            0,
            [0u8; 20],
        );
        let meta = Meta::new(
            1,
            0.5,
            0.5,
            0.5,
            0.0,
            None,
            None,
            None,
            BlockStatus::Nothing,
        );
        let previous_block: Block<Header, SignedTx> =
            Block::new(previous_block_header, None, Some(meta));
        let (next_difficulty, time_ema, difficulty_ema) =
            adjust_difficulty(previous_block, 1.0).unwrap();
        let expected_next_difficulty = 0.000005793555184180208;
        let expected_time_ema = 0.5015;
        let expected_difficulty_ema = 0.5;
        assert_eq!(next_difficulty, expected_next_difficulty);
        assert_eq!(time_ema, expected_time_ema);
        assert_eq!(difficulty_ema, expected_difficulty_ema);
    }

    #[test]
    fn it_converges_to_a_correct_difficulty() {
        let merkle_root = vec![0u8; 32];
        let mut time_stamp = 1536298261602;
        let state_root = vec![0u8; 32];
        let previous_hash = vec![vec![0u8; 32]];
        let nonce = 0;
        let miner = [0u8; 20];
        let difficulty = 1.0;
        let mut previous_block_header = Header::new(
            merkle_root.clone(),
            time_stamp,
            difficulty,
            state_root.clone(),
            previous_hash.clone(),
            nonce,
            miner,
        );
        let height = 1;
        let mut t_ema = 0.5;
        let mut p_ema = 0.5;
        let mut next_difficulty = 1.0;
        let total_work = 0.0;
        let file_number = None;
        let offset = None;
        let length = None;
        let mut meta = Meta::new(
            height,
            t_ema,
            p_ema,
            next_difficulty,
            total_work,
            file_number,
            offset,
            length,
            BlockStatus::Block,
        );
        let mut block: Block<Header, SignedTx> =
            Block::new(previous_block_header, None, Some(meta));
        for _ in 0..30000 {
            time_stamp += TARGET_TIME as u64;
            let adjustment = adjust_difficulty(block, time_stamp as f64).unwrap();
            next_difficulty = adjustment.0;
            t_ema = adjustment.1;
            p_ema = adjustment.2;
            meta = Meta::new(
                height,
                t_ema,
                p_ema,
                next_difficulty,
                total_work,
                file_number,
                offset,
                length,
                BlockStatus::Block,
            );
            previous_block_header = Header::new(
                merkle_root.clone(),
                time_stamp,
                next_difficulty,
                state_root.clone(),
                previous_hash.clone(),
                nonce,
                miner,
            );
            block = Block::new(previous_block_header, None, Some(meta));
        }

        assert_eq!(block.meta.unwrap().t_ema.ceil(), TARGET_TIME.floor());
    }

    #[test]
    fn it_calculates_an_ema() {
        let new_value = 0.5;
        let old_value = 0.5;
        let alpha = 0.5;
        let ema = calc_ema(new_value, old_value, alpha);
        assert_eq!(ema, 0.5);
    }

    #[test]
    fn it_calculates_another_ema() {
        let new_value = 0.5;
        let old_value = 0.25;
        let alpha = 0.5;
        let ema = calc_ema(new_value, old_value, alpha);
        assert_eq!(ema, 0.375);
    }

    #[test]
    fn it_calculates_a_target_for_powers_of_two() {
        let mut difficulty: f64;
        let length = 32;
        for exponent in 0..256 {
            difficulty = 1.0 / (2f64.powf(exponent as f64));
            let target = get_target(difficulty, length).unwrap();
            let mut index = length - (exponent as usize / 8) - 1;
            let mut expected_value = (0xFF as f64 * 1.0 / 2f64.powf(exponent as f64 % 8.0)) as u8;
            if exponent != 0 && exponent % 8 == 0 {
                index += 1;
                expected_value = 0;
            }
            assert_eq!(target[index], expected_value);
        }
    }

    #[test]
    fn it_calculates_a_target_for_powers_of_three() {
        let mut difficulty: f64;
        let length = 32;
        for exponent in 0..161 {
            difficulty = 1.0 / (3f64.powf(exponent as f64));
            let target = get_target(difficulty, length).unwrap();
            let mut index = length - ((exponent / 8) as usize);
            if exponent != 0 && exponent % 8 == 0 {
                index += 1;
            }

            if index < 8 {
                index = 8
            }

            let mut scaled_difficulty = difficulty;
            for _ in (index..length).rev() {
                scaled_difficulty *= 2f64.powf(8.0);
            }
            let expected_value = 0xFFFF_FFFF_FFFF_FFFF_u64 as f64 * scaled_difficulty - 1.0;
            let value = LittleEndian::read_u64(&target[index - 8..index]);
            assert_eq!(value as f64, expected_value.ceil());
        }
    }

    #[test]
    fn it_calculates_a_target_for_fractional_values() {
        let seed = [0x27u8; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut difficulty: f64;
        let length = 32;
        for _ in 0..1000 {
            for base in 3..16 {
                let exponents = ((256.0 * 2f64.ln()) / (base as f64).ln()) as u64;
                for exponent in 1..exponents {
                    let coefficients = (base as f64).powf(exponent as f64) - 1.0;
                    let coefficient = rng.gen_range(1.0, coefficients).floor();
                    difficulty = coefficient / (base as f64).powf(exponent as f64);
                    let target = get_target(difficulty, length).unwrap();
                    let index = length - (-1.0 * difficulty.log2() / 8.0) as usize;

                    let mut scaled_difficulty = difficulty;
                    for _ in (index..length).rev() {
                        scaled_difficulty *= 2f64.powf(8.0);
                    }
                    let expected_value = 0xFFFF_FFFF_FFFF_FFFF_u64 as f64 * scaled_difficulty - 1.0;
                    let value = LittleEndian::read_u64(&target[index - 8..index]);
                    assert_eq!(value as f64, expected_value.ceil());
                }
            }
        }
    }

    #[test]
    fn it_calculates_a_basic_legacy_target() {
        let difficulty = 0.5;
        let length = 32;
        let target = get_legacy_target(difficulty, length);
        let expected_target = vec![
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ];
        assert_eq!(target, expected_target);
    }

    #[test]
    fn it_calculates_a_simple_legacy_target() {
        let difficulty = 0.0003;
        let length = 32;
        let target = get_legacy_target(difficulty, length);
        let expected_target = vec![
            51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 49, 51, 49, 51,
            51, 53, 97, 50, 85, 48, 42, 169, 19, 0,
        ];
        assert_eq!(target, expected_target);
    }

    #[test]
    fn it_calculates_a_random_legacy_target() {
        let difficulty = 0.5817765075630095;
        let length = 32;
        let target = get_legacy_target(difficulty, length);
        let expected_target = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 224, 224,
            112, 143, 32, 77, 238, 148,
        ];
        assert_eq!(target, expected_target);
    }

    #[test]
    fn it_accepts_a_valid_hash_on_edge() {
        let difficulty = 0.5;
        let target = get_target(difficulty, 32).unwrap();
        let solution = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0x7F,
        ];
        assert_eq!(acceptable(solution, target).unwrap(), true);
    }

    #[test]
    fn it_accepts_a_valid_hash() {
        let difficulty = 0.5;
        let target = get_target(difficulty, 32).unwrap();
        let solution = vec![
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0x7F,
        ];
        assert_eq!(acceptable(solution, target).unwrap(), true);
    }

    #[test]
    fn it_rejects_an_invalid_hash() {
        let difficulty = 0.5;
        let target = get_target(difficulty, 32).unwrap();
        let solution = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0x80,
        ];
        assert_eq!(acceptable(solution, target).unwrap(), false);
    }
}
