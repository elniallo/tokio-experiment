
pub struct DBKeys{
    pub file_number: Vec<u8>,
    pub file_position: Vec<u8>,
    pub block_tip: Vec<u8>,
    pub header_tip: Vec<u8>,
}

impl DBKeys {
    pub fn new(file_number: Vec<u8>, file_position: Vec<u8>, block_tip: Vec<u8>, header_tip: Vec<u8>) -> DBKeys {
        DBKeys {
            file_number,
            file_position,
            block_tip,
            header_tip
        }
    }
}