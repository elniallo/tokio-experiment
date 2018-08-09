use blake2_rfc::blake2b::blake2b;

pub fn hash(data: &[u8], size: usize) -> Vec<u8> {
        let hash_data = blake2b(size, &[], data);
        let mut hash_vec = vec![0; size];
        hash_vec.clone_from_slice(&hash_data.as_bytes()[..]);
        hash_vec
}