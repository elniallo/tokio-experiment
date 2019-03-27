use std::default::Default;
pub struct DBKeys {
    pub file_number: Vec<u8>,
    pub file_position: Vec<u8>,
    pub block_tip: Vec<u8>,
    pub header_tip: Vec<u8>,
}

impl DBKeys {
    pub fn new(
        file_number: Vec<u8>,
        file_position: Vec<u8>,
        block_tip: Vec<u8>,
        header_tip: Vec<u8>,
    ) -> DBKeys {
        DBKeys {
            file_number,
            file_position,
            block_tip,
            header_tip,
        }
    }
}

impl Default for DBKeys {
    fn default() -> Self {
        let file_number = "file".as_bytes().to_vec();
        let file_position = "fpos".as_bytes().to_vec();
        let block_tip = "btip".as_bytes().to_vec();
        let header_tip = "htip".as_bytes().to_vec();
        Self {
            file_number,
            file_position,
            block_tip,
            header_tip,
        }
    }
}
