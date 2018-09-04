use std::f64::consts;

pub const TARGET_TIME: f64 = 30 / consts::LN_2;

pub fn calc_ema(new_value: f64, previous_value: f64, alpha: f64) -> f64 {
    alpha * new_value + (1 - alpha) * previous_value
}
