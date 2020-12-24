use crate::BLOCK_224_256_LEN as BLOCK_LEN;
use crate::PAD_AND_LENGTH_224_256_LEN as PAD_AND_LENGTH_LEN;
use crate::STATE_224_256_LEN as STATE_LEN;
use crate::WORD_224_256_LEN as WORD_LEN;
use crate::{inner_full_pad, inner_pad, process_block_224_256, zero_block};
use crate::{Error, Hash, Sha2};

/// Digest length in bytes (256-bits)
pub const DIGEST_LEN: usize = 32;

// Initial state words
const INITIAL_STATE: [u32; STATE_LEN] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Implementation of the SHA-256 transform
pub struct Sha256 {
    state: [u32; STATE_LEN],
    block: [u8; BLOCK_LEN],
    index: usize,
    bit_index: usize,
    total_len: u64,
    hash: Hash,
}

impl Sha2 for Sha256 {
    type Block = [u8; BLOCK_LEN];
    type Digest = [u8; DIGEST_LEN];
    type State = [u32; STATE_LEN];

    /// Create a newly initialized SHA-256 transform
    fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0_u8; BLOCK_LEN],
            index: 0,
            bit_index: 0,
            total_len: 0,
            hash: Hash::Sha256,
        }
    }

    fn encode_state(&self) -> Self::Digest {
        let mut res = [0_u8; DIGEST_LEN];

        for (i, word) in self.state.iter().enumerate() {
            res[i * WORD_LEN..(i + 1) * WORD_LEN].copy_from_slice(word.to_be_bytes().as_ref());
        }

        res
    }

    fn process_block(&mut self) {
        process_block_224_256(&mut self.state, &mut self.block, &mut self.index);
    }

    fn pad(&mut self) -> Result<(), Error> {
        inner_pad(
            &mut self.block,
            self.index,
            self.bit_index,
            self.total_len as u128,
            &self.hash,
        )
    }

    fn full_pad(&mut self) {
        inner_full_pad(&mut self.block, self.total_len as u128, &self.hash);
    }

    fn index(&self) -> usize {
        self.index
    }

    fn increment_index(&mut self) {
        self.index += 1;
    }

    fn bit_index(&self) -> usize {
        self.bit_index
    }

    fn set_bit_index(&mut self, index: usize) {
        self.bit_index = index;
    }

    fn total_len(&self) -> u128 {
        self.total_len as u128
    }

    fn increment_total_len(&mut self, len: usize) -> Result<(), Error> {
        let len = len as u64;

        if len + self.total_len > u64::MAX {
            return Err(Error::InvalidLength);
        }

        // increase the total length of the message
        self.total_len += len;

        Ok(())
    }

    fn hash(&self) -> &Hash {
        &self.hash
    }

    fn initial_state(&mut self) {
        self.state.copy_from_slice(INITIAL_STATE.as_ref());
    }

    fn block_mut(&mut self) -> &mut [u8] {
        &mut self.block
    }

    fn zero_block(&mut self) {
        zero_block(&mut self.block);
    }

    fn reset_counters(&mut self) {
        self.index = 0;
        self.bit_index = 0;
        self.total_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_vector1() {
        let input = b"abc";
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector2() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector3() {
        let input = b"a";
        let expected = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];

        let mut sha = Sha256::new();

        for _i in 0..1_000_000 {
            sha.input(input.as_ref()).unwrap();
        }

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector4() {
        let input = b"0123456701234567012345670123456701234567012345670123456701234567";
        let expected = [
            0x59, 0x48, 0x47, 0x32, 0x84, 0x51, 0xbd, 0xfa, 0x85, 0x05, 0x62, 0x25, 0x46, 0x2c,
            0xc1, 0xd8, 0x67, 0xd8, 0x77, 0xfb, 0x38, 0x8d, 0xf0, 0xce, 0x35, 0xf2, 0x5a, 0xb5,
            0x56, 0x2b, 0xfb, 0xb5,
        ];

        let mut sha = Sha256::new();

        for _i in 0..10 {
            sha.input(input.as_ref()).unwrap();
        }

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    // FIXME: skip vector 5, 7, and 9 since the `final_bits` API is unimplemented
    #[test]
    fn rfc_vector5() {
        let input = [];
        let expected = [
            0xd6, 0xd3, 0xe0, 0x2a, 0x31, 0xa8, 0x4a, 0x8c, 0xaa, 0x97, 0x18, 0xed, 0x6c, 0x20,
            0x57, 0xbe, 0x09, 0xdb, 0x45, 0xe7, 0x82, 0x3e, 0xb5, 0x07, 0x9c, 0xe7, 0xa5, 0x73,
            0xa3, 0x76, 0x0f, 0x95,
        ];

        let mut sha = Sha256::new();
        sha.input(input.as_ref()).unwrap();
        let digest = sha.final_bits(0x68, 5).unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector6() {
        let input = b"\x19";
        let expected = [
            0x68, 0xaa, 0x2e, 0x2e, 0xe5, 0xdf, 0xf9, 0x6e, 0x33, 0x55, 0xe6, 0xc7, 0xee, 0x37,
            0x3e, 0x3d, 0x6a, 0x4e, 0x17, 0xf7, 0x5f, 0x95, 0x18, 0xd8, 0x43, 0x70, 0x9c, 0x0c,
            0x9b, 0xc3, 0xe3, 0xd4,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector7() {
        let input = [
            0xbe, 0x27, 0x46, 0xc6, 0xdb, 0x52, 0x76, 0x5f, 0xdb, 0x2f, 0x88, 0x70, 0x0f, 0x9a,
            0x73,
        ];
        let expected = [
            0x77, 0xec, 0x1d, 0xc8, 0x9c, 0x82, 0x1f, 0xf2, 0xa1, 0x27, 0x90, 0x89, 0xfa, 0x09,
            0x1b, 0x35, 0xb8, 0xcd, 0x96, 0x0b, 0xca, 0xf7, 0xde, 0x01, 0xc6, 0xa7, 0x68, 0x07,
            0x56, 0xbe, 0xb9, 0x72,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.final_bits(0x60, 3).unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector8() {
        let input = b"\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52";
        let expected = [
            0x17, 0x5e, 0xe6, 0x9b, 0x02, 0xba, 0x9b, 0x58, 0xe2, 0xb0, 0xa5, 0xfd, 0x13, 0x81,
            0x9c, 0xea, 0x57, 0x3f, 0x39, 0x40, 0xa9, 0x4f, 0x82, 0x51, 0x28, 0xcf, 0x42, 0x09,
            0xbe, 0xab, 0xb4, 0xe8,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector9() {
        let input = [
            0x3e, 0x74, 0x03, 0x71, 0xc8, 0x10, 0xc2, 0xb9, 0x9f, 0xc0, 0x4e, 0x80, 0x49, 0x07,
            0xef, 0x7c, 0xf2, 0x6b, 0xe2, 0x8b, 0x57, 0xcb, 0x58, 0xa3, 0xe2, 0xf3, 0xc0, 0x07,
            0x16, 0x6e, 0x49, 0xc1, 0x2e, 0x9b, 0xa3, 0x4c, 0x01, 0x04, 0x06, 0x91, 0x29, 0xea,
            0x76, 0x15, 0x64, 0x25, 0x45, 0x70, 0x3a, 0x2b, 0xd9, 0x01, 0xe1, 0x6e, 0xb0, 0xe0,
            0x5d, 0xeb, 0xa0, 0x14, 0xeb, 0xff, 0x64, 0x06, 0xa0, 0x7d, 0x54, 0x36, 0x4e, 0xff,
            0x74, 0x2d, 0xa7, 0x79, 0xb0, 0xb3,
        ];
        let expected = [
            0x3e, 0x9a, 0xd6, 0x46, 0x8b, 0xbb, 0xad, 0x2a, 0xc3, 0xc2, 0xcd, 0xc2, 0x92, 0xe0,
            0x18, 0xba, 0x5f, 0xd7, 0x0b, 0x96, 0x0c, 0xf1, 0x67, 0x97, 0x77, 0xfc, 0xe7, 0x08,
            0xfd, 0xb0, 0x66, 0xe9,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.final_bits(0xa0, 3).unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector10() {
        let input = [
            0x83, 0x26, 0x75, 0x4e, 0x22, 0x77, 0x37, 0x2f, 0x4f, 0xc1, 0x2b, 0x20, 0x52, 0x7a,
            0xfe, 0xf0, 0x4d, 0x8a, 0x05, 0x69, 0x71, 0xb1, 0x1a, 0xd5, 0x71, 0x23, 0xa7, 0xc1,
            0x37, 0x76, 0x00, 0x00, 0xd7, 0xbe, 0xf6, 0xf3, 0xc1, 0xf7, 0xa9, 0x08, 0x3a, 0xa3,
            0x9d, 0x81, 0x0d, 0xb3, 0x10, 0x77, 0x7d, 0xab, 0x8b, 0x1e, 0x7f, 0x02, 0xb8, 0x4a,
            0x26, 0xc7, 0x73, 0x32, 0x5f, 0x8b, 0x23, 0x74, 0xde, 0x7a, 0x4b, 0x5a, 0x58, 0xcb,
            0x5c, 0x5c, 0xf3, 0x5b, 0xce, 0xe6, 0xfb, 0x94, 0x6e, 0x5b, 0xd6, 0x94, 0xfa, 0x59,
            0x3a, 0x8b, 0xeb, 0x3f, 0x9d, 0x65, 0x92, 0xec, 0xed, 0xaa, 0x66, 0xca, 0x82, 0xa2,
            0x9d, 0x0c, 0x51, 0xbc, 0xf9, 0x33, 0x62, 0x30, 0xe5, 0xd7, 0x84, 0xe4, 0xc0, 0xa4,
            0x3f, 0x8d, 0x79, 0xa3, 0x0a, 0x16, 0x5c, 0xba, 0xbe, 0x45, 0x2b, 0x77, 0x4b, 0x9c,
            0x71, 0x09, 0xa9, 0x7d, 0x13, 0x8f, 0x12, 0x92, 0x28, 0x96, 0x6f, 0x6c, 0x0a, 0xdc,
            0x10, 0x6a, 0xad, 0x5a, 0x9f, 0xdd, 0x30, 0x82, 0x57, 0x69, 0xb2, 0xc6, 0x71, 0xaf,
            0x67, 0x59, 0xdf, 0x28, 0xeb, 0x39, 0x3d, 0x54, 0xd6,
        ];
        let expected = [
            0x97, 0xdb, 0xca, 0x7d, 0xf4, 0x6d, 0x62, 0xc8, 0xa4, 0x22, 0xc9, 0x41, 0xdd, 0x7e,
            0x83, 0x5b, 0x8a, 0xd3, 0x36, 0x17, 0x63, 0xf7, 0xe9, 0xb2, 0xd9, 0x5f, 0x4f, 0x0d,
            0xa6, 0xe1, 0xcc, 0xbc,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }
}