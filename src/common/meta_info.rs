pub struct MetaInfo {
    pub height: u32,
    pub t_ema: f64,
    pub p_ema: f64,
    pub next_difficulty: f64,
    pub total_work: f64,
    file_number: Option<u32>,
    offset: Option<u32>,
    length: Option<u32>,
}

pub trait Saved {
    fn get_file_number(&self) -> u32;
    fn get_offset(&self) -> u32;
    fn get_length(&self) -> u32;
}

impl MetaInfo {
    pub fn new(height: u32, t_ema: f64, p_ema: f64, next_difficulty: f64, total_work: f64, file_number: Option<u32>, offset: Option<u32>, length: Option<u32>) -> MetaInfo {
        MetaInfo {
            height,
            t_ema,
            p_ema,
            next_difficulty,
            total_work,
            file_number,
            offset,
            length
        }
    }
}

impl Clone for MetaInfo {
    fn clone(&self) -> MetaInfo {
        let height = self.height;
        let t_ema = self.t_ema;
        let p_ema = self.p_ema;
        let next_difficulty = self.next_difficulty;
        let total_work = self.total_work;
        let file_number = self.file_number;
        let offset = self.offset;
        let length = self.length;
        MetaInfo {
            height,
            t_ema,
            p_ema,
            next_difficulty,
            total_work,
            file_number,
            offset,
            length
        }
    }
}