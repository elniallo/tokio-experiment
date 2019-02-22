use crate::common::block::Block;
use crate::common::genesis_block::GenesisBlock;
use crate::common::header::Header;
use crate::common::signed_tx::SignedTx;
use crate::traits::{Decode, Encode, Exception, Proto};
use std::error::Error;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::result::Result;

const MAX_FILE_SIZE: u64 = 134217728; // 128 MB
const UNIT_TO_EXPAND: usize = 16777216; // 16 MB
const SIZE_OF_LENGTH: usize = 3;
const ENCODE_PREFIX_SIZE: usize = SIZE_OF_LENGTH;

pub type BlockFileResult<T> = Result<T, Box<Error>>;

pub trait MiscFileOp: Sized {
    fn create_raw_file(file_path: &PathBuf) -> BlockFileResult<Self>;
    fn open_raw_file(file_path: &PathBuf) -> BlockFileResult<Self>;
    fn get_file_size(&self) -> BlockFileResult<u64>;
    fn create_directory(dir_path: &PathBuf) -> BlockFileResult<()>;
}

impl MiscFileOp for File {
    fn create_raw_file(file_path: &PathBuf) -> BlockFileResult<File> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&file_path)?)
    }

    fn open_raw_file(file_path: &PathBuf) -> BlockFileResult<File> {
        Ok(OpenOptions::new().read(true).open(&file_path)?)
    }

    fn get_file_size(&self) -> BlockFileResult<u64> {
        Ok(self.metadata()?.len())
    }

    fn create_directory(dir_path: &PathBuf) -> BlockFileResult<()> {
        Ok(DirBuilder::new().recursive(true).create(dir_path)?)
    }
}

#[derive(Clone)]
pub struct PutResult {
    pub file_number: u32,
    pub file_position: u64,
    pub offset: u64,
    pub length: u32,
}

pub trait GetGenesisBlock {
    fn get_genesis_block(&mut self) -> Option<GenesisBlock>;
}

pub struct BlockFileIterator<RawFile = File> {
    dir_path: PathBuf,
    position: u64,
    file_number: u32,
    file: RawFile,
}

impl<RawFile> BlockFileIterator<RawFile>
where
    RawFile: Seek + Read + MiscFileOp,
{
    pub fn new(dir_path: PathBuf) -> BlockFileResult<BlockFileIterator<RawFile>> {
        let file = BlockFileIterator::open(&dir_path, 0)?;
        Ok(BlockFileIterator {
            dir_path,
            position: 0,
            file_number: 0,
            file,
        })
    }

    fn open(dir_path: &PathBuf, file_number: u32) -> BlockFileResult<RawFile> {
        let mut file_path = dir_path.clone();
        file_path.push(format!("blk{:05}.dat", file_number));
        let file_local = RawFile::open_raw_file(&file_path)?;
        return Ok(file_local);
    }

    fn read_encoded_block(&mut self) -> BlockFileResult<Vec<u8>> {
        let mut length_array = vec![0; SIZE_OF_LENGTH];

        if (self.file.get_file_size()? as i64 - self.position as i64) <= ENCODE_PREFIX_SIZE as i64 {
            self.file_number += 1;
            self.file = BlockFileIterator::open(&self.dir_path, self.file_number)?;
            self.position = 0;
        }
        self.file
            .seek(SeekFrom::Start(self.position))
            .or(Err(Box::new(Exception::new("Error while seeking"))))?;
        self.file
            .read(length_array.as_mut_slice())
            .or(Err(Box::new(Exception::new("Error while read length"))))?;

        let length = bytes_array_to_usize(length_array);
        if length == 0 {
            self.file_number += 1;
            self.file = BlockFileIterator::open(&self.dir_path, self.file_number)?;
            self.position = 0;
            return self.read_encoded_block();
        }
        let mut encoded_block = vec![0; length];
        self.file
            .read(encoded_block.as_mut_slice())
            .or(Err(Box::new(Exception::new(
                "Error while read block content",
            ))))?;
        self.position += (encoded_block.len() + ENCODE_PREFIX_SIZE) as u64;
        Ok(encoded_block)
    }
}

impl<RawFile> GetGenesisBlock for BlockFileIterator<RawFile>
where
    RawFile: Seek + Read + MiscFileOp,
{
    fn get_genesis_block(&mut self) -> Option<GenesisBlock> {
        if self.file_number != 0 || self.position != 0 {
            return None;
        }

        let encoded_block = self.read_encoded_block().ok()?;

        GenesisBlock::decode(&encoded_block).ok()
    }
}

impl<RawFile> Iterator for BlockFileIterator<RawFile>
where
    RawFile: Seek + Read + MiscFileOp,
{
    type Item = Block<Header, SignedTx>;
    fn next(&mut self) -> Option<Block<Header, SignedTx>> {
        let encoded_block = self.read_encoded_block().ok()?;
        Block::<Header, SignedTx>::decode(&encoded_block).ok()
    }
}

#[derive(Debug)]
pub struct BlockFile<RawFile = File> {
    file_number: u32,
    file_position: u64,
    path: PathBuf,
    file: Option<RawFile>,
}

fn usize_to_bytes_array(mut length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; SIZE_OF_LENGTH];
    for i in 0..SIZE_OF_LENGTH {
        bytes[i] = (length % 256) as u8;
        length = length >> 8;
    }
    bytes
}

fn bytes_array_to_usize(buffer: Vec<u8>) -> usize {
    let mut len_of_block: usize = 0;
    for i in 0..SIZE_OF_LENGTH {
        len_of_block += buffer[i] as usize * (256f64.powf(i as f64) as usize);
    }
    len_of_block
}

pub trait BlockFileOps: Sized {
    fn new(path: &PathBuf, file_number: u32, file_position: u64) -> BlockFileResult<Self>;
    fn get<T>(&mut self, file_number: u32, offset: u64, length: usize) -> BlockFileResult<T>
    where
        T: Decode;
    fn put<T>(&mut self, any_block: &mut T) -> BlockFileResult<PutResult>
    where
        T: Encode + Proto;
}
impl<RawFile> BlockFileOps for BlockFile<RawFile>
where
    RawFile: Read + Write + Seek + MiscFileOp,
{
    /// Create, initialise and return an object of BlockFile
    fn new(
        path: &PathBuf,
        file_number: u32,
        file_position: u64,
    ) -> BlockFileResult<BlockFile<RawFile>> {
        let dir_path = path.clone();
        if !dir_path.exists() {
            RawFile::create_directory(&dir_path)?;
        }
        let mut block_file = BlockFile {
            file_number,
            file_position,
            path: PathBuf::from(path),
            file: None,
        };
        block_file.open(file_number, true)?;
        Ok(block_file)
    }

    /// Retrieve an object of Block or GenesisBlock from the file system represented by this BlockFile object
    fn get<T>(&mut self, file_number: u32, offset: u64, length: usize) -> BlockFileResult<T>
    where
        T: Decode,
    {
        let mut file_to_read;
        if self.file_number != file_number {
            file_to_read = self
                .open(file_number, false)?
                .ok_or(Box::new(Exception::new("File Not Found")))?;
        } else {
            file_to_read = self
                .file
                .take()
                .ok_or(Box::new(Exception::new("File Not Found")))?;
        }

        let mut buffer: Vec<u8> = vec![0; length + ENCODE_PREFIX_SIZE];

        file_to_read.seek(SeekFrom::Start(offset))?;
        let number_of_bytes = file_to_read.read(buffer.as_mut_slice())?;

        if number_of_bytes != length + ENCODE_PREFIX_SIZE {
            return Err(Box::new(Exception::new(&format!(
                "Error reading file . count of bytes read: {}",
                number_of_bytes
            ))));
        }
        let len_of_block: usize = bytes_array_to_usize(buffer.clone());
        assert!(len_of_block == length); // TODO : remove

        if file_number == self.file_number {
            self.file = Some(file_to_read);
        }

        Ok(T::decode(&buffer[(ENCODE_PREFIX_SIZE)..].to_vec())?)
    }

    /// Write a Block or GenesisBlock object to the file system represented by this BlockFile object
    fn put<T>(&mut self, any_block: &mut T) -> BlockFileResult<PutResult>
    where
        T: Encode + Proto,
    {
        let file_size = self
            .file
            .as_ref()
            .ok_or(Box::new(Exception::new("File object not created")))?
            .get_file_size()?;
        let offset = self.file_position;
        let mut encoded_block = any_block.encode()?;
        let length = encoded_block.len();

        let mut bytes = usize_to_bytes_array(length);

        let mut encoded_data = vec![];
        encoded_data.append(&mut bytes);
        encoded_data.append(&mut encoded_block);

        if file_size < (self.file_position + encoded_data.len() as u64) {
            self.expand()?;
        }

        let file_to_write = self
            .file
            .as_mut()
            .ok_or(Box::new(Exception::new("Error while putting")))?;

        file_to_write.seek(SeekFrom::Start(self.file_position))?;
        let number_of_bytes_written = file_to_write.write(&encoded_data)?;
        if number_of_bytes_written != encoded_data.len() {
            return Err(Box::new(Exception::new("write size error")));
        }

        self.file_position += number_of_bytes_written as u64;
        return Ok(PutResult {
            file_number: self.file_number,
            file_position: self.file_position,
            offset,
            length: (number_of_bytes_written - ENCODE_PREFIX_SIZE) as u32,
        });
    }
}

impl<RawFile> BlockFile<RawFile>
where
    RawFile: Read + Write + Seek + MiscFileOp,
{
    /// Open a file with the given file descriptor. The flag ‘create_file’ creates the file if it does not exist.
    fn open(&mut self, file_number: u32, create_file: bool) -> BlockFileResult<Option<RawFile>> {
        let mut file_path = self.path.clone();
        file_path.push(format!("blk{:05}.dat", file_number));
        if create_file {
            let file_local = RawFile::create_raw_file(&file_path)?;
            self.file = Some(file_local);
            Ok(None)
        } else {
            let file_local = RawFile::open_raw_file(&file_path)?;
            Ok(Some(file_local))
        }
    }

    /// Open the next file
    fn next_file(&mut self) -> BlockFileResult<()> {
        let new_file_number = self.file_number + 1;
        self.open(new_file_number, true)?;
        self.file_number = new_file_number;
        Ok(())
    }

    fn expand(&mut self) -> BlockFileResult<()> {
        let file_size = self
            .file
            .as_ref()
            .ok_or(Box::new(Exception::new("File object not created")))?
            .get_file_size()?;

        if file_size > MAX_FILE_SIZE {
            self.next_file()?;
        }
        let file_now = self
            .file
            .as_mut()
            .ok_or(Box::new(Exception::new("File object not created")))?;
        let array_to_write = vec![0; UNIT_TO_EXPAND];
        file_now.seek(SeekFrom::End(0))?;
        file_now.write(array_to_write.as_slice())?;
        Ok(())
    }

    pub fn iterator_for(&mut self) -> BlockFileResult<BlockFileIterator<RawFile>> {
        Ok(BlockFileIterator::new(self.path.clone())?)
    }
}

#[cfg(test)]
mod tests {
    extern crate double;
    use super::*;
    use crate::common::block::tests::{
        create_expected_block_encoding, create_test_block_without_meta,
    };
    use crate::common::common_tests::common_tests::{assert_block, assert_genesis_block};
    use crate::common::genesis_block::tests::{
        create_expected_genesis_encoding, create_genesis_block,
    };
    use double::Mock;
    use std::fmt::{self, Display, Formatter};
    use std::io;

    macro_rules! impl_read {
        ($class_name:ident) => {
            impl Read for $class_name {
                fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                    let output: Vec<u8> = self.read.call(buf.len()).unwrap();
                    buf.copy_from_slice(output.as_slice());
                    Ok(output.len())
                }
            }
        };
    }

    macro_rules! impl_miscfileop {
        ($class_name:ident) => {
            impl MiscFileOp for $class_name {
                fn create_raw_file(_file_path: &PathBuf) -> BlockFileResult<Self> {
                    Ok($class_name::default())
                }

                fn open_raw_file(_file_path: &PathBuf) -> BlockFileResult<Self> {
                    Ok($class_name::default())
                }

                fn get_file_size(&self) -> BlockFileResult<u64> {
                    let get_file_size: u64 = self.get_file_size.call(()).unwrap();
                    Ok(get_file_size)
                }

                fn create_directory(_dir_path: &PathBuf) -> BlockFileResult<()> {
                    Ok(())
                }
            }
        };
    }

    macro_rules! impl_seek {
        ($class_name:ident) => {
            impl Seek for $class_name {
                fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                    if let SeekFrom::Start(file_position) = pos {
                        if let Err(_) = self.seek.call(file_position) {
                            panic!("Seek fail in mock file.");
                        }
                    }

                    Ok(0)
                }
            }
        };
    }

    macro_rules! impl_write {
        ($class_name:ident) => {
            impl Write for $class_name {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    let written_byte_len: usize = self.write.call(buf.to_vec()).unwrap();
                    if buf.len() == UNIT_TO_EXPAND {
                        self.get_file_size.return_value(Ok(
                            self.get_file_size.call(()).unwrap() + UNIT_TO_EXPAND as u64
                        ));
                    }
                    Ok(written_byte_len)
                }

                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
        };
    }

    #[derive(Debug, Clone)]
    struct CloneableError {
        pub kind: io::ErrorKind,
        pub description: String,
    }

    impl Error for CloneableError {
        fn description(&self) -> &str {
            self.description.as_ref()
        }
    }

    impl Display for CloneableError {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{}", self.description())
        }
    }

    #[derive(Debug, Clone)]
    struct MockFile {
        pub read: Mock<(usize), Result<Vec<u8>, CloneableError>>,
        pub seek: Mock<(u64), Result<u64, CloneableError>>,
        pub write: Mock<(Vec<u8>), Result<usize, CloneableError>>,
        pub get_file_size: Mock<(), Result<u64, CloneableError>>,
    }

    impl_read! {MockFile}

    impl_miscfileop! {MockFile}

    impl Default for MockFile {
        fn default() -> Self {
            let write_mock = Mock::new(Ok(0));
            write_mock.use_fn(|vec: Vec<u8>| Ok(vec.len()));
            MockFile {
                read: Mock::new(Ok(Vec::new())),
                seek: Mock::new(Ok(0)),
                write: write_mock,
                get_file_size: Mock::new(Ok(0 as u64)),
            }
        }
    }

    impl_seek! {MockFile}

    impl_write! {MockFile}

    #[test]
    fn it_returns_object() {
        let mut path = PathBuf::new();
        path.push("test");
        let block_file = BlockFile::<MockFile>::new(&path, 0, 0).unwrap_or_else(|e| {
            panic!(e.to_string());
        });
        assert_eq!(block_file.file_number, 0);
        assert_eq!(block_file.file_position, 0);
        assert_eq!(block_file.path, path);
        block_file
            .file
            .or_else(|| panic!("Object has invalid file."));
    }

    #[test]
    fn it_writes_encoded_block() {
        let mut test_block = create_test_block_without_meta();
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file = BlockFile::<MockFile>::new(&path, 0, 0).unwrap_or_else(|e| {
            panic!(e.to_string());
        });
        let put_result = block_file.put(&mut test_block).unwrap_or_else(|_| {
            panic!("block put fail");
        });
        let mut encode_data = create_expected_block_encoding();
        let encode_data_len = encode_data.len().clone();
        let mut encode_prefix = usize_to_bytes_array(encode_data_len);
        let mut write_bytes = vec![];
        write_bytes.append(&mut encode_prefix);
        write_bytes.append(&mut encode_data);
        assert!(block_file
            .file
            .unwrap()
            .write
            .called_with(write_bytes.clone()));
        assert_eq!(encode_data_len as u32, put_result.length);
    }

    #[test]
    fn it_writes_encoded_genesis_block() {
        let mut test_block = create_genesis_block();
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file = BlockFile::<MockFile>::new(&path, 0, 0).unwrap_or_else(|e| {
            panic!(e.to_string());
        });
        let put_result = block_file.put(&mut test_block).unwrap_or_else(|_| {
            panic!("genesis block put fail");
        });
        let mut encode_data = create_expected_genesis_encoding();
        let encode_data_len = encode_data.len().clone();
        let mut encode_prefix = usize_to_bytes_array(encode_data_len);
        let mut write_bytes = vec![];
        write_bytes.append(&mut encode_prefix);
        write_bytes.append(&mut encode_data);
        assert!(block_file
            .file
            .unwrap()
            .write
            .called_with(write_bytes.clone()));
        assert_eq!(encode_data_len as u32, put_result.length);
        assert_eq!(
            put_result.offset + ((put_result.length + (ENCODE_PREFIX_SIZE as u32)) as u64),
            put_result.file_position
        );
    }

    #[test]
    fn it_moves_to_next_file() {
        let mut test_block = create_genesis_block();
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file = BlockFile::<MockFile>::new(&path, 0, 0).unwrap_or_else(|e| {
            panic!(e.to_string());
        });
        block_file
            .file
            .clone()
            .and_then(|mockfile| {
                mockfile
                    .get_file_size
                    .return_value(Ok((MAX_FILE_SIZE + 1) as u64));
                block_file.file_position = mockfile.get_file_size().unwrap();
                Some(mockfile)
            })
            .or_else(|| {
                panic!("Mockfile Read return value set fail");
            });
        let put_result = block_file.put(&mut test_block).unwrap_or_else(|e| {
            panic!("genesis block put fail : {:?}", e);
        });
        let mut encode_data = create_expected_genesis_encoding();
        let encode_data_len = encode_data.len().clone();
        let mut encode_prefix = usize_to_bytes_array(encode_data_len);
        let mut write_bytes = vec![];
        write_bytes.append(&mut encode_prefix);
        write_bytes.append(&mut encode_data);
        block_file.file.as_ref().and_then(|mockfile| {
            assert!(mockfile
                .write
                .has_calls_exactly(vec![vec![0; UNIT_TO_EXPAND], write_bytes.clone()]));
            assert!(mockfile.get_file_size.called());
            return Some(mockfile);
        });
        assert_eq!(encode_data_len as u32, put_result.length);
        assert_ne!(block_file.file.unwrap().get_file_size().unwrap(), 0);
        assert_ne!(block_file.file_position, 0);
        assert_eq!(block_file.file_number, 1);
    }

    #[test]
    fn it_reads_encoded_block() {
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file =
            BlockFile::<MockFile>::new(&path, 0, 0).unwrap_or_else(|e| panic!(e.to_string()));
        let mut encode_data = create_expected_block_encoding();
        let encode_data_len = encode_data.len().clone();
        let mut encode_prefix = usize_to_bytes_array(encode_data_len);
        let mut read_bytes = vec![];
        read_bytes.append(&mut encode_prefix);
        read_bytes.append(&mut encode_data);
        if let Some(ref mockfile) = block_file.file {
            mockfile.read.return_value(Ok(read_bytes));
        }
        let get_result = block_file.get::<Block<Header, SignedTx>>(0, 0, 269);

        let anyblock = get_result.unwrap_or_else(|e| {
            panic!(
                "Any block doesn't have any block information. {}",
                e.to_string()
            )
        });

        if let Some(ref mockfile) = block_file.file {
            assert!(mockfile.read.called());
            assert!(mockfile.seek.called());
        }

        let block = anyblock;
        let compare_block = create_test_block_without_meta();
        assert_block(block, compare_block);
    }

    #[test]
    fn it_reads_encoded_genesis_block() {
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file = BlockFile::<MockFile>::new(&path, 0, 0).unwrap_or_else(|e| {
            panic!(e.to_string());
        });
        let mut encode_data = create_expected_genesis_encoding();
        let encode_data_len = encode_data.len().clone();
        let mut encode_prefix = usize_to_bytes_array(encode_data_len);
        let mut read_bytes = vec![];
        read_bytes.append(&mut encode_prefix);
        read_bytes.append(&mut encode_data);
        block_file.file.as_ref().and_then(|mockfile| {
            mockfile.read.return_value(Ok(read_bytes));
            Some(mockfile)
        });
        let get_result = block_file.get::<GenesisBlock>(0, 0, 698);
        let anyblock = get_result.unwrap_or_else(|e| {
            panic!(
                "Any block doesn't have any block information. {}",
                e.to_string()
            )
        });
        if let Some(ref mockfile) = block_file.file {
            assert!(mockfile.read.called());
            assert!(mockfile.seek.called());
        }
        let block = anyblock;
        let compare_genesis_block = create_genesis_block();
        assert_genesis_block(block, compare_genesis_block);
    }

    #[test]
    fn it_reads_genesis_block_from_file_using_iterator() {
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file_iterator = BlockFileIterator::<MockFile>::new(path).unwrap();

        let genesis_encode = create_expected_genesis_encoding();
        let genesis_block = create_genesis_block();
        let genesis_encode_len = genesis_encode.len();
        let mut encode_prefix = usize_to_bytes_array(genesis_encode_len);
        let mut length_bytes = vec![];
        length_bytes.append(&mut encode_prefix);

        let original_position = block_file_iterator.position;

        block_file_iterator
            .file
            .get_file_size
            .return_value(Ok((genesis_encode_len + ENCODE_PREFIX_SIZE) as u64));

        block_file_iterator
            .file
            .read
            .return_values(vec![Ok(length_bytes), Ok(genesis_encode)]);

        let genesis = block_file_iterator
            .get_genesis_block()
            .and_then(|block| {
                assert!(block_file_iterator.file.seek.called_with(original_position));
                assert!(block_file_iterator.file.read.called());
                Some(block)
            })
            .unwrap_or_else(|| panic!("get next block fail"));

        assert_genesis_block(genesis, genesis_block);

        assert_eq!(
            block_file_iterator.position,
            (genesis_encode_len + ENCODE_PREFIX_SIZE) as u64
        );
    }

    #[test]
    fn it_reads_next_block_from_file_using_iterator() {
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file_iterator = BlockFileIterator::<MockFile>::new(path).unwrap();

        let block_encode = create_expected_block_encoding();
        let block = create_test_block_without_meta();
        let block_encode_len = block_encode.len();
        let mut encode_prefix = usize_to_bytes_array(block_encode_len);
        let mut length_bytes = vec![];
        length_bytes.append(&mut encode_prefix);

        let original_position = block_file_iterator.position;
        block_file_iterator
            .file
            .get_file_size
            .return_value(Ok((block_encode_len + ENCODE_PREFIX_SIZE) as u64));
        block_file_iterator
            .file
            .read
            .return_values(vec![Ok(length_bytes), Ok(block_encode)]);

        let next_block = block_file_iterator
            .next()
            .and_then(|block| {
                assert!(block_file_iterator.file.seek.called_with(original_position));
                assert!(block_file_iterator.file.read.called());
                Some(block)
            })
            .unwrap_or_else(|| panic!("get next block fail"));

        assert_block(block, next_block);

        assert_eq!(
            block_file_iterator.position,
            (block_encode_len + ENCODE_PREFIX_SIZE) as u64
        );
    }

    #[derive(Debug, Clone)]
    struct MockFileForIterator {
        pub read: Mock<(usize), Result<Vec<u8>, CloneableError>>,
        pub seek: Mock<(u64), Result<u64, CloneableError>>,
        pub write: Mock<(Vec<u8>), Result<usize, CloneableError>>,
        pub get_file_size: Mock<(), Result<u64, CloneableError>>,
    }

    impl_read! {MockFileForIterator}
    impl_miscfileop! {MockFileForIterator}

    impl Default for MockFileForIterator {
        fn default() -> Self {
            let write_mock = Mock::new(Ok(0));
            write_mock.use_fn(|vec: Vec<u8>| Ok(vec.len()));
            let read_mock = Mock::new(Ok(Vec::new()));
            read_mock.use_fn(|length: usize| {
                let block_encode = create_expected_block_encoding();
                let block_encode_len = block_encode.len();
                let mut encode_prefix = usize_to_bytes_array(block_encode_len);
                let mut length_bytes = vec![];
                length_bytes.append(&mut encode_prefix);
                if length == 3 {
                    return Ok(length_bytes);
                } else {
                    return Ok(block_encode);
                }
            });
            MockFileForIterator {
                read: read_mock,
                seek: Mock::new(Ok(0)),
                write: write_mock,
                get_file_size: Mock::new(Ok(0 as u64)),
            }
        }
    }

    impl_seek! {MockFileForIterator}
    impl_write! {MockFileForIterator}

    #[test]
    fn it_reads_from_next_file_eof() {
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file_iterator = BlockFileIterator::<MockFileForIterator>::new(path).unwrap();

        let block_encode = create_expected_block_encoding();
        let block = create_test_block_without_meta();
        let block_encode_len = block_encode.len();

        block_file_iterator.position = (block_encode_len + ENCODE_PREFIX_SIZE) as u64;
        block_file_iterator
            .file
            .get_file_size
            .return_value(Ok((block_encode_len + ENCODE_PREFIX_SIZE) as u64));

        let next_block = block_file_iterator
            .next()
            .and_then(|block| {
                assert!(block_file_iterator.file.seek.called_with(0 as u64));
                assert!(block_file_iterator.file.read.called());
                Some(block)
            })
            .unwrap_or_else(|| panic!("get next block fail"));
        assert_block(block, next_block);

        assert_eq!(block_file_iterator.file_number, 1);
        assert_eq!(
            block_file_iterator.position,
            (block_encode_len + ENCODE_PREFIX_SIZE) as u64
        );
    }

    #[test]
    fn it_reads_from_next_file_insufficient_space_for_length() {
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file_iterator = BlockFileIterator::<MockFileForIterator>::new(path).unwrap();

        let block_encode = create_expected_block_encoding();
        let block = create_test_block_without_meta();
        let block_encode_len = block_encode.len();

        block_file_iterator.position = (block_encode_len + ENCODE_PREFIX_SIZE) as u64;
        block_file_iterator
            .file
            .get_file_size
            .return_value(Ok((block_encode_len + ENCODE_PREFIX_SIZE + 2) as u64));

        let next_block = block_file_iterator
            .next()
            .and_then(|block| {
                assert!(block_file_iterator.file.seek.called_with(0 as u64));
                assert!(block_file_iterator.file.read.called());
                Some(block)
            })
            .unwrap_or_else(|| panic!("get next block fail"));

        assert_block(block, next_block);

        assert_eq!(block_file_iterator.file_number, 1);
        assert_eq!(
            block_file_iterator.position,
            (block_encode_len + ENCODE_PREFIX_SIZE) as u64
        );
    }

    #[derive(Debug, Clone)]
    struct MockForIterException {
        pub read: Mock<(usize), Result<Vec<u8>, CloneableError>>,
        pub seek: Mock<(u64), Result<u64, CloneableError>>,
        pub write: Mock<(Vec<u8>), Result<usize, CloneableError>>,
        pub get_file_size: Mock<(), Result<u64, CloneableError>>,
    }

    impl_read! {MockForIterException}

    impl MiscFileOp for MockForIterException {
        fn create_raw_file(_file_path: &PathBuf) -> BlockFileResult<Self> {
            Ok(MockForIterException::default())
        }

        fn open_raw_file(_file_path: &PathBuf) -> BlockFileResult<Self> {
            let file_name = _file_path.to_str().unwrap();
            if file_name == "./test/blk00000.dat" {
                let read_mock = Mock::new(Ok(Vec::new()));
                read_mock.use_fn(|_: usize| {
                    let mut zero_encode_prefix = usize_to_bytes_array(0 as usize);
                    let mut zero_length_bytes = vec![];
                    zero_length_bytes.append(&mut zero_encode_prefix);
                    return Ok(zero_length_bytes);
                });
                return Ok(MockForIterException {
                    read: read_mock,
                    seek: Mock::new(Ok(0)),
                    write: Mock::new(Ok(0)),
                    get_file_size: Mock::new(Ok(MAX_FILE_SIZE)),
                });
            }
            Ok(MockForIterException::default())
        }

        fn get_file_size(&self) -> BlockFileResult<u64> {
            let get_file_size: u64 = self.get_file_size.call(()).unwrap();
            Ok(get_file_size)
        }

        fn create_directory(_dir_path: &PathBuf) -> BlockFileResult<()> {
            Ok(())
        }
    }

    impl Default for MockForIterException {
        fn default() -> Self {
            let write_mock = Mock::new(Ok(0));
            write_mock.use_fn(|vec: Vec<u8>| Ok(vec.len()));
            let read_mock = Mock::new(Ok(Vec::new()));
            read_mock.use_fn(|length: usize| {
                let block_encode = create_expected_block_encoding();
                let block_encode_len = block_encode.len();
                let mut encode_prefix = usize_to_bytes_array(block_encode_len);
                let mut length_bytes = vec![];
                length_bytes.append(&mut encode_prefix);
                if length == 3 {
                    return Ok(length_bytes);
                } else {
                    return Ok(block_encode);
                }
            });
            MockForIterException {
                read: read_mock,
                seek: Mock::new(Ok(0)),
                write: write_mock,
                get_file_size: Mock::new(Ok(MAX_FILE_SIZE)),
            }
        }
    }

    impl_seek! {MockForIterException}

    impl_write! {MockForIterException}

    #[test]
    fn it_causes_error_when_only_the_length_info_found() {
        let mut path = PathBuf::new();
        path.push("./test");
        let mut block_file_iterator = BlockFileIterator::<MockForIterException>::new(path).unwrap();

        let block_encode = create_expected_block_encoding();
        let block = create_test_block_without_meta();
        let block_encode_len = block_encode.len();

        let mut zero_encode_prefix = usize_to_bytes_array(0 as usize);
        let mut zero_length_bytes = vec![];
        zero_length_bytes.append(&mut zero_encode_prefix);

        let next_block = block_file_iterator
            .next()
            .and_then(|block| {
                assert!(block_file_iterator.file.seek.called_with(0 as u64));
                assert!(block_file_iterator.file.read.called());
                Some(block)
            })
            .unwrap_or_else(|| panic!("get next block fail"));

        assert_block(block, next_block);

        assert_eq!(block_file_iterator.file_number, 1);
        assert_eq!(
            block_file_iterator.position,
            (block_encode_len + ENCODE_PREFIX_SIZE) as u64
        );
    }

}
