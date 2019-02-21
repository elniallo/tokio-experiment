use std::vec::Vec;
use blake2_rfc::blake2b::{ Blake2b, Blake2bResult};

const HASH_LENGTH:usize=32;
type HashValue = Blake2bResult;

/// A merkle tree
pub struct MerkleTree{
    tree: Vec<HashValue>
}

impl MerkleTree{
    /// Calculate and return the length of vector required to build a tree for the input vector length
    pub fn length_for(length: usize) -> usize {
        let mut len= length;
        let mut count = 1;
        while len > 1 {
            count += len;
            len = len - (len >> 1);
        }
        count

    }

    /// Calculate a hash value for the concatenated value of two hash values
    pub fn couple_hash(left: &HashValue, right: &HashValue)-> HashValue {
        let mut blake=Blake2b::new(HASH_LENGTH);
        blake.update(left.as_bytes());
        blake.update(right.as_bytes());
        blake.finalize()
    }

    /// Construct a tree that has only one element containing the hash value of empty byte vector
    pub fn empty_tree() -> MerkleTree {
        let mut tree=Vec::new();
        tree.push(Blake2b::new(HASH_LENGTH).finalize());
        MerkleTree { tree }
    }

    /// Construct the merkle tree containing the input vector and their ancestors that are built with couple_hash
    /// # Example
    /// 
    /// ```
    /// let input = Vec::new();
    ///
    /// input.push(hash(tx_object,32));
    ///
    /// let merkle_tree=MerkleTree::from(input);
    /// ```
    pub fn from(hashes: Vec<HashValue>) -> MerkleTree {
        if hashes.len() == 0 {
            return MerkleTree::empty_tree()
        }

        let tree_size = MerkleTree::length_for(hashes.len());
        let mut tree: Vec<HashValue> = Vec::with_capacity(tree_size);
        let mut prev_level_size = hashes.len();
        let levels = ((hashes.len() as f64).log2().ceil()) as usize;

        for hash in hashes {
            tree.push(hash);
        }

        let mut tree_index = prev_level_size;

        for _ in 0..levels {
            let odd = prev_level_size % 2 == 1;

            let mut level_size = 0;

            for pair in (0..prev_level_size - 1).step_by(2) {
                let hash = MerkleTree::couple_hash(&tree[tree_index + pair - prev_level_size], &tree[tree_index + pair + 1 - prev_level_size]);
                tree.push(hash);
                level_size += 1;
            }

            if odd {
                let hash = MerkleTree::couple_hash(&tree[tree_index + 2 * level_size - prev_level_size], &tree[tree_index + 2 * level_size - prev_level_size]);
                tree.push(hash);
                level_size += 1;
            }

            prev_level_size = level_size;
            tree_index += level_size;
        }

        MerkleTree {
            tree
        }
    }

    /// Return the hash value stored in the root element of this tree
    pub fn root(&self) -> &[u8] {
        self.tree[self.tree.len()-1].as_bytes()
    }

    /// Return the size of merkle tree
    pub fn size(&self) -> usize {
        self.tree.len()
    }
}
/// Construct a merkle tree of given the hash value vector and return the root value
pub fn calculate_merkle_root(v: Vec<HashValue>) -> HashValue {
    let mut mt= MerkleTree::from(v);
    match mt.tree.pop() {
        Some(root) => root,
        None => Blake2b::new(HASH_LENGTH).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::Encode;
    use common::signed_tx::SignedTx;
    use blake2_rfc::blake2b::blake2b;
    use common::tx::Tx;
    use common::address::{Address, ValidAddress};
    use secp256k1::{RecoverableSignature, RecoveryId, Secp256k1};

    #[derive(Debug)]
    pub struct TestResult {
        pub amount: u64,
        pub fee: u64,
        pub addr_from: String,
        pub addr_to: String,
        pub nonce: u32,
        pub result: Vec<u8>
    }

    pub fn create_tx(amount: u64, fee: u64, from_addr_string: &String, to_addr_str: &String, signature_bytes: Vec<u8>, nonce: u32, recovery_num: i32) -> Tx {
        let from_addr = Address::from_string(&from_addr_string).unwrap();
        let to_addr = Address::from_string(&to_addr_str).unwrap();
        let recovery = RecoveryId::from_i32(recovery_num).unwrap();
        let secp = Secp256k1::without_caps();
        let sign =
            RecoverableSignature::from_compact(&secp, &signature_bytes, recovery);
        let signature = match sign {
            Ok(sig)=>sig,
            Err(err)=>panic!("{:?}",err)
        };
        let signed_tx=SignedTx::new(from_addr, to_addr, amount, fee, nonce, signature, recovery);
        let tx_to_return=Tx::new(signed_tx.from, signed_tx.to, signed_tx.amount, signed_tx.fee, signed_tx.nonce);
        tx_to_return
    }

    #[test]
    fn it_calculates_length_for_a_size_two_input() {
        let size = 2;
        assert_eq!(MerkleTree::length_for(size), 3);
    }

    #[test]
    fn it_calculates_length_for_a_size_three_input() {
        let size = 3;
        assert_eq!(MerkleTree::length_for(size), 6);
    }

    #[test]
    fn it_makes_a_merkle_tree_from_no_tx_hashes() {
        let tx_hashes = vec![];
        let merkle_tree = MerkleTree::from(tx_hashes);
        let empty_tree =  MerkleTree::empty_tree();
        let expected_root = empty_tree.root();
        assert_eq!(merkle_tree.root(), expected_root);
    }

    #[test]
    fn it_makes_a_merkle_tree_from_a_single_tx_hash() {
        let bytes = vec![0xFF; 32];
        let txhash = blake2b(32, &[], &bytes);//hash(&bytes, 32);

        let merkle_tree = MerkleTree::from(vec![txhash]);
        let expected_root = txhash.as_bytes();
        assert_eq!(merkle_tree.root(), expected_root);
    }

    #[test]
    fn it_makes_a_merkle_tree_from_two_tx_hashes() {
        let tx_bytes_1 = vec![0xFF; 32];
        let tx_bytes_2 = vec![0xAA; 32];

        let tx_hash_1 = blake2b(32, &[], &tx_bytes_1);//hash(&tx_bytes_1, 32);
        let tx_hash_2 = blake2b(32, &[], &tx_bytes_2);//= hash(&tx_bytes_2, 32);

        let tx_hashes = vec![tx_hash_1.clone(), tx_hash_2.clone()];
        let expected_root_tree = MerkleTree::couple_hash(&tx_hash_1, &tx_hash_2);
        let expected_root = expected_root_tree.as_bytes();

        let merkle_tree = MerkleTree::from(tx_hashes);

        assert_eq!(merkle_tree.root(), expected_root);
    }

    #[test]
    fn it_makes_a_merkle_tree_from_three_tx_hashes() {
        let tx_bytes_1 = vec![0xFF; 32];
        let tx_bytes_2 = vec![0xAA; 32];
        let tx_bytes_3 = vec![0xBB; 32];

        let tx_hash_1 = blake2b(32, &[], &tx_bytes_1);//hash(&tx_bytes_1, 32);
        let tx_hash_2 = blake2b(32, &[], &tx_bytes_2);//hash(&tx_bytes_2, 32);
        let tx_hash_3 = blake2b(32, &[], &tx_bytes_3);//hash(&tx_bytes_3, 32);

        let tx_hashes = vec![tx_hash_1.clone(), tx_hash_2.clone(), tx_hash_3.clone()];

        let expected_hash_1 = MerkleTree::couple_hash(&tx_hash_1, &tx_hash_2);
        let expected_hash_2 = MerkleTree::couple_hash(&tx_hash_3, &tx_hash_3);

        let expected_root_tree = MerkleTree::couple_hash(&expected_hash_1, &expected_hash_2);
        let expected_root = expected_root_tree.as_bytes();

        let merkle_tree = MerkleTree::from(tx_hashes);

        assert_eq!(merkle_tree.root(), expected_root);
    }

    #[test]
    /// Test the constructing procedure and the root value referencing the rapidphoenix's results
    fn merkletree_construction_and_root_value() {
        let test_data=vec![ //These data are acquired from rapidphoenix (written in typescript) test_data[i].result == merkle(test_data[..i+1])
            TestResult{amount:18446744073709551615, fee:1844674407370955161, addr_from:"H2Z1W1w7y9vySYP8TYJhBjcbPgdEtGNqo".to_string(), addr_to:"H3v1XBKocnuPtf68jXCyhk3BjJWiCEpin".to_string(), nonce:447021795,	result:vec![148,125,226,153,45,127,15,1,105,67,93,39,104,46,119,117,252,155,63,86,88,126,59,14,26,169,112,171,13,177,27,135]},
            TestResult{amount:1844674407370955161, fee:184467440737095516, addr_from:"H1FSL3irdyHKaFkke9pUUc5p9gL44LAz".to_string(), addr_to:"H4Kwv2gEnP2KrXGgYZ2D1i3u17R5U6sJS".to_string(), nonce:4194833957,	result:vec![247,150,231,209,72,73,254,5,0,23,135,32,83,165,14,181,196,146,129,220,244,242,138,189,122,152,32,77,80,192,181,86]},
            TestResult{amount:1844674407370955161, fee:184467440737095516, addr_from:"H2nbfgyC9Gm4Pg9a3UYWnpbnxXnwe72R9".to_string(), addr_to:"H2j9LbEsqvmXYuHDEuGghRXZ6Rz8xHNhs".to_string(), nonce:3243135675,	result:vec![23,32,12,177,27,101,213,213,141,111,219,71,34,145,96,66,225,163,151,84,75,10,147,23,233,241,154,97,148,107,255,68]},
            TestResult{amount:184467440737095516, fee:18446744073709551, addr_from:"H3ELoH8HKN38Wh8qJXWFcSQad5XRmGAYL".to_string(), addr_to:"H3uTpDC2eQy2nuoYVpEhpsVA8xtQr2Bp8".to_string(), nonce:817126706,	result:vec![98,26,77,214,216,141,157,11,113,82,4,174,86,198,90,124,191,8,10,190,186,65,54,170,78,105,153,25,73,116,215,204]},
            TestResult{amount:184467440737095516, fee:18446744073709551, addr_from:"HoAVwmoNpTcNs44WAC2fmysH4up5BMXz".to_string(), addr_to:"HdhND5TA8pYrRF3Ev2CBCkgQoyLL6tUs".to_string(), nonce:3559107386,	result:vec![62,196,239,64,186,21,8,67,173,183,99,122,204,55,242,9,166,239,241,47,70,215,125,244,89,195,233,238,234,156,108,37]},
            TestResult{amount:18446744073709551, fee:1844674407370955, addr_from:"H39e7xU1mQ1GP9cBCGGaAjt64cP4m3K9x".to_string(), addr_to:"HqBjdZoxkGYxzremrLijtqDCuDgx3prz".to_string(), nonce:2650042352,	result:vec![14,84,39,124,134,34,103,180,121,118,131,247,134,237,209,141,78,117,82,252,120,171,150,182,101,32,132,185,102,98,51,248]},
            TestResult{amount:18446744073709551, fee:1844674407370955, addr_from:"H3iLQbkuLygS8eBU8Ub5msANFGrj9AXfo".to_string(), addr_to:"H3kwghi42eJ2Zc38bvdraBo2hFkZJAie5".to_string(), nonce:817464996,	result:vec![81,101,118,59,158,182,114,241,237,188,129,55,97,197,220,99,197,175,71,136,38,47,200,96,210,4,240,151,90,189,157,10]},
            TestResult{amount:1844674407370955, fee:184467440737095, addr_from:"H2Cp6aJQvjVddAA3WxFR8RijUyUji9nWQ".to_string(), addr_to:"H4RJAiB3WQ84XoseNF5eXm43Z8Y9KHVkM".to_string(), nonce:2983338036,	result:vec![191,195,216,74,183,162,175,115,33,190,4,53,117,166,36,60,99,152,158,74,33,245,207,157,39,231,22,131,29,110,139,220]},
            TestResult{amount:1844674407370955, fee:184467440737095, addr_from:"H2yz9TDfYMCTAdN2sEYgaVvBjcM9L6oVu".to_string(), addr_to:"H2aLAkdRFKHCCrv9nuCTaqELpDPFL8DCx".to_string(), nonce:3453094064,	result:vec![13,199,31,119,140,65,242,90,175,73,52,16,54,231,37,52,136,51,65,206,59,58,163,103,46,162,160,159,155,5,50,47]},
            TestResult{amount:184467440737095, fee:18446744073709, addr_from:"Ho4H7nBRbNqcU2neVkEgpdk1a6ChTzRk".to_string(), addr_to:"H3iCF2qSa8KtwYx5oZBL8hJhBxsz72weL".to_string(), nonce:3627677068,	result:vec![143,63,172,208,245,254,190,62,8,36,210,104,192,80,85,26,207,137,29,186,213,186,74,211,59,196,231,97,84,57,105,168]},
            TestResult{amount:184467440737095, fee:18446744073709, addr_from:"H3nVLDa7oF2NWqvphGL7iBnE8Dvak7VwT".to_string(), addr_to:"HkzjwsAZRX8PwoicX8V5qMocVQ7YC9r3".to_string(), nonce:211425792,	result:vec![220,41,227,217,192,85,210,24,3,111,8,107,83,253,7,2,213,230,207,113,54,83,213,13,247,112,39,20,237,255,227,29]},
            TestResult{amount:18446744073709, fee:1844674407370, addr_from:"H3E1Zfcf4AgF4KQispbsQJ1GJRPPBEUfJ".to_string(), addr_to:"H6gkVrg2haAruMaVfouq8zYLQvaT8tsA".to_string(), nonce:4217375358,	result:vec![180,188,149,10,45,230,156,237,134,101,194,131,208,3,152,153,38,253,226,73,80,135,127,50,108,127,10,59,210,57,232,49]},
            TestResult{amount:18446744073709, fee:1844674407370, addr_from:"H27wReyY14Vuo6Puic5kqNW94qxBDHDL".to_string(), addr_to:"H4HezNxQRfxcpPwDnKUeZ9T5ERgL62sLp".to_string(), nonce:3796604911,	result:vec![73,178,87,223,38,197,169,246,13,187,160,113,171,237,80,224,82,56,95,146,187,145,137,8,70,110,3,255,20,21,103,218]},
            TestResult{amount:1844674407370, fee:184467440737, addr_from:"H3Dq3CcQKX6vSnMhT8N1cJy7kYicEGTWo".to_string(), addr_to:"H24mMii6Ni3LyefgZYfdXFvzCcRSwDCck".to_string(), nonce:1207311295,	result:vec![97,214,1,47,16,134,7,235,182,130,213,84,173,62,31,232,210,36,215,226,248,254,210,238,39,186,189,3,191,178,156,157]},
            TestResult{amount:1844674407370, fee:184467440737, addr_from:"H39s3AgrWYn3MhRH9DhXtsTjjbtNmAdZH".to_string(), addr_to:"H2gPXu862fsiapoMYek982m7gHAfwtn9C".to_string(), nonce:895359516,	result:vec![130,158,87,237,149,241,228,178,23,166,178,195,200,105,97,18,158,114,248,69,214,214,215,172,138,96,110,138,20,64,97,188]},
        ]; 
        let mut signedtxs: Vec<HashValue>=Vec::new();

        assert_eq!(calculate_merkle_root(signedtxs.clone()).as_bytes().to_vec(), vec![14, 87, 81, 192, 38, 229, 67, 178, 232, 171, 46, 176, 96, 153, 218, 161, 209, 229, 223, 71, 119, 143, 119, 135, 250, 171, 69, 205, 241, 47, 227, 168]); // The check about zero-lenth vector case.

        for i in 0..test_data.len() { //Accumulating the test datas, this function can test the cases of vectors whose length are 1,2,3,4,5,6,7,8,9,10,11,12,13,14, and 15 which is test_data.len()
            let signed_tx = create_tx(
                test_data[i].amount,      test_data[i].fee,      &test_data[i].addr_from,   &test_data[i].addr_to , vec![26,136,5,119,252,37,249,228,222,118,1,220,11,97,82,8,74,177,75,208,3,131,29,140,121,30,178,136,35,252,159,162,200,221,75,156,114,228,155,24,165,44,158,23,180,44,147,39,159,172,103,134,97,228,187,142,7,246,129,132,123,58,161,151], test_data[i].nonce,      0
            );
            signedtxs.push(blake2b(32, &[], &signed_tx.encode().unwrap().as_slice()));//hash(, 32));
            assert_eq!(MerkleTree::from(signedtxs.clone()).size(), MerkleTree::length_for(i+1));
            assert_eq!(calculate_merkle_root(signedtxs.clone()).as_bytes().to_vec(), test_data[i].result); // check the case of a vector whose length is (i+1)
        } 
    }
}
