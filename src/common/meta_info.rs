pub struct MetaInfo {
    height: u32,
    tEMA: f64,
    pEMA: f64,
    next_difficulty: f64,
    total_work: f64,
    file_number: Option<u32>,
    offset: Option<u32>,
    length: Option<u32>,
}

pub trait A {
    fn get_height(&self) -> u32;
    fn get_tEMA(&self) -> f64;
    fn get_pEMA(&self) -> f64;
    fn get_next_difficulty(&self) -> f64;
    fn get_total_work(&self) -> f64;
}

pub trait B {
    fn get_file_number(&self) -> u32;
    fn get_offset(&self) -> u32;
    fn get_length(&self) -> u32;
}