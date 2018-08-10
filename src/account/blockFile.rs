pub struct BlockFile {
    n: u64,
    fd: u64,
    filePosition: u64,
    fileSize: u64,
    path: String,
}
