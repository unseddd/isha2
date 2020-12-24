use crate::BLOCK_384_512_LEN as BLOCK_LEN;
use crate::PAD_AND_LENGTH_384_512_LEN as PAD_AND_LENGTH_LEN;
use crate::STATE_384_512_LEN as STATE_LEN;
use crate::WORD_384_512_LEN as WORD_LEN;
use crate::{inner_full_pad, inner_pad, process_block_384_512, zero_block};
use crate::{Error, Hash, Sha2};

/// Digest length in bytes (384-bits)
pub const DIGEST_LEN: usize = 48;

// Initial state words: FIPS-180-2 sections 5.3.3
const INITIAL_STATE: [u64; STATE_LEN] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// Implementation of the SHA-256 transform
pub struct Sha384 {
    state: [u64; STATE_LEN],
    block: [u8; BLOCK_LEN],
    index: usize,
    bit_index: usize,
    total_len: u128,
    hash: Hash,
}

impl Sha2 for Sha384 {
    type Block = [u8; BLOCK_LEN];
    type Digest = [u8; DIGEST_LEN];
    type State = [u64; STATE_LEN];

    /// Create a newly initialized SHA-256 transform
    fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0_u8; BLOCK_LEN],
            index: 0,
            bit_index: 0,
            total_len: 0,
            hash: Hash::Sha384,
        }
    }

    fn encode_state(&self) -> Self::Digest {
        let mut res = [0_u8; DIGEST_LEN];

        for (i, word) in self.state.iter().enumerate() {
            if i * WORD_LEN == DIGEST_LEN {
                break;
            };
            res[i * WORD_LEN..(i + 1) * WORD_LEN].copy_from_slice(word.to_be_bytes().as_ref());
        }

        res
    }

    fn process_block(&mut self) {
        process_block_384_512(&mut self.state, &mut self.block, &mut self.index);
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
        inner_full_pad(&mut self.block, self.total_len, &self.hash);
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
        let len = len as u128;

        if len + self.total_len > u128::MAX {
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
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
            0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
            0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
            0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];

        let mut sha = Sha384::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector2() {
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = [
            0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd,
            0x1b, 0x47, 0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2, 0x2f, 0xa0, 0x80, 0x86,
            0xe3, 0xb0, 0xf7, 0x12, 0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3,
            0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39,
        ];

        let mut sha = Sha384::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector3() {
        let input = b"a";
        let expected = [
            0x9d, 0x0e, 0x18, 0x09, 0x71, 0x64, 0x74, 0xcb, 0x08, 0x6e, 0x83, 0x4e, 0x31, 0x0a,
            0x4a, 0x1c, 0xed, 0x14, 0x9e, 0x9c, 0x00, 0xf2, 0x48, 0x52, 0x79, 0x72, 0xce, 0xc5,
            0x70, 0x4c, 0x2a, 0x5b, 0x07, 0xb8, 0xb3, 0xdc, 0x38, 0xec, 0xc4, 0xeb, 0xae, 0x97,
            0xdd, 0xd8, 0x7f, 0x3d, 0x89, 0x85,
        ];

        let mut sha = Sha384::new();

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
            0x2f, 0xc6, 0x4a, 0x4f, 0x50, 0x0d, 0xdb, 0x68, 0x28, 0xf6, 0xa3, 0x43, 0x0b, 0x8d,
            0xd7, 0x2a, 0x36, 0x8e, 0xb7, 0xf3, 0xa8, 0x32, 0x2a, 0x70, 0xbc, 0x84, 0x27, 0x5b,
            0x9c, 0x0b, 0x3a, 0xb0, 0x0d, 0x27, 0xa5, 0xcc, 0x3c, 0x2d, 0x22, 0x4a, 0xa6, 0xb6,
            0x1a, 0x0d, 0x79, 0xfb, 0x45, 0x96,
        ];

        let mut sha = Sha384::new();

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
            0x8d, 0x17, 0xbe, 0x79, 0xe3, 0x2b, 0x67, 0x18, 0xe0, 0x7d, 0x8a, 0x60, 0x3e, 0xb8,
            0x4b, 0xa0, 0x47, 0x8f, 0x7f, 0xcf, 0xd1, 0xbb, 0x93, 0x99, 0x5f, 0x7d, 0x11, 0x49,
            0xe0, 0x91, 0x43, 0xac, 0x1f, 0xfc, 0xfc, 0x56, 0x82, 0x0e, 0x46, 0x9f, 0x38, 0x78,
            0xd9, 0x57, 0xa1, 0x5a, 0x3f, 0xe4,
        ];

        let mut sha = Sha384::new();
        sha.input(input.as_ref()).unwrap();
        let digest = sha.final_bits(0x10, 5).unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector6() {
        let input = b"\xb9";
        let expected = [
            0xbc, 0x80, 0x89, 0xa1, 0x90, 0x07, 0xc0, 0xb1, 0x41, 0x95, 0xf4, 0xec, 0xc7, 0x40,
            0x94, 0xfe, 0xc6, 0x4f, 0x01, 0xf9, 0x09, 0x29, 0x28, 0x2c, 0x2f, 0xb3, 0x92, 0x88,
            0x15, 0x78, 0x20, 0x8a, 0xd4, 0x66, 0x82, 0x8b, 0x1c, 0x6c, 0x28, 0x3d, 0x27, 0x22,
            0xcf, 0x0a, 0xd1, 0xab, 0x69, 0x38,
        ];

        let mut sha = Sha384::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector7() {
        let input = b"\x8b\xc5\x00\xc7\x7c\xee\xd9\x87\x9d\xa9\x89\x10\x7c\xe0\xaa";
        let expected = [
            0xd8, 0xc4, 0x3b, 0x38, 0xe1, 0x2e, 0x7c, 0x42, 0xa7, 0xc9, 0xb8, 0x10, 0x29, 0x9f,
            0xd6, 0xa7, 0x70, 0xbe, 0xf3, 0x09, 0x20, 0xf1, 0x75, 0x32, 0xa8, 0x98, 0xde, 0x62,
            0xc7, 0xa0, 0x7e, 0x42, 0x93, 0x44, 0x9c, 0x0b, 0x5f, 0xa7, 0x01, 0x09, 0xf0, 0x78,
            0x32, 0x11, 0xcf, 0xc4, 0xbc, 0xe3,
        ];

        let mut sha = Sha384::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.final_bits(0xa0, 3).unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector8() {
        let input = b"\xa4\x1c\x49\x77\x79\xc0\x37\x5f\xf1\x0a\x7f\x4e\x08\x59\x17\x39";
        let expected = [
            0xc9, 0xa6, 0x84, 0x43, 0xa0, 0x05, 0x81, 0x22, 0x56, 0xb8, 0xec, 0x76, 0xb0, 0x05,
            0x16, 0xf0, 0xdb, 0xb7, 0x4f, 0xab, 0x26, 0xd6, 0x65, 0x91, 0x3f, 0x19, 0x4b, 0x6f,
            0xfb, 0x0e, 0x91, 0xea, 0x99, 0x67, 0x56, 0x6b, 0x58, 0x10, 0x9c, 0xbc, 0x67, 0x5c,
            0xc2, 0x08, 0xe4, 0xc8, 0x23, 0xf7,
        ];

        let mut sha = Sha384::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector9() {
        let input = [
            0x68, 0xf5, 0x01, 0x79, 0x2d, 0xea, 0x97, 0x96, 0x76, 0x70, 0x22, 0xd9, 0x3d, 0xa7,
            0x16, 0x79, 0x30, 0x99, 0x20, 0xfa, 0x10, 0x12, 0xae, 0xa3, 0x57, 0xb2, 0xb1, 0x33,
            0x1d, 0x40, 0xa1, 0xd0, 0x3c, 0x41, 0xc2, 0x40, 0xb3, 0xc9, 0xa7, 0x5b, 0x48, 0x92,
            0xf4, 0xc0, 0x72, 0x4b, 0x68, 0xc8, 0x75, 0x32, 0x1a, 0xb8, 0xcf, 0xe5, 0x02, 0x3b,
            0xd3, 0x75, 0xbc, 0x0f, 0x94, 0xbd, 0x89, 0xfe, 0x04, 0xf2, 0x97, 0x10, 0x5d, 0x7b,
            0x82, 0xff, 0xc0, 0x02, 0x1a, 0xeb, 0x1c, 0xcb, 0x67, 0x4f, 0x52, 0x44, 0xea, 0x34,
            0x97, 0xde, 0x26, 0xa4, 0x19, 0x1c, 0x5f, 0x62, 0xe5, 0xe9, 0xa2, 0xd8, 0x08, 0x2f,
            0x05, 0x51, 0xf4, 0xa5, 0x30, 0x68, 0x26, 0xe9, 0x1c, 0xc0, 0x06, 0xce, 0x1b, 0xf6,
            0x0f, 0xf7, 0x19, 0xd4, 0x2f, 0xa5, 0x21, 0xc8, 0x71, 0xcd, 0x23, 0x94, 0xd9, 0x6e,
            0xf4, 0x46, 0x8f, 0x21, 0x96, 0x6b, 0x41, 0xf2, 0xba, 0x80, 0xc2, 0x6e, 0x83, 0xa9,
        ];
        let expected = [
            0x58, 0x60, 0xe8, 0xde, 0x91, 0xc2, 0x15, 0x78, 0xbb, 0x41, 0x74, 0xd2, 0x27, 0x89,
            0x8a, 0x98, 0xe0, 0xb4, 0x5c, 0x4c, 0x76, 0x0f, 0x00, 0x95, 0x49, 0x49, 0x56, 0x14,
            0xda, 0xed, 0xc0, 0x77, 0x5d, 0x92, 0xd1, 0x1d, 0x9f, 0x8c, 0xe9, 0xb0, 0x64, 0xee,
            0xac, 0x8d, 0xaf, 0xc3, 0xa2, 0x97,
        ];

        let mut sha = Sha384::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.final_bits(0xe0, 3).unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector10() {
        let input = [
            0x39, 0x96, 0x69, 0xe2, 0x8f, 0x6b, 0x9c, 0x6d, 0xbc, 0xbb, 0x69, 0x12, 0xec, 0x10,
            0xff, 0xcf, 0x74, 0x79, 0x03, 0x49, 0xb7, 0xdc, 0x8f, 0xbe, 0x4a, 0x8e, 0x7b, 0x3b,
            0x56, 0x21, 0xdb, 0x0f, 0x3e, 0x7d, 0xc8, 0x7f, 0x82, 0x32, 0x64, 0xbb, 0xe4, 0x0d,
            0x18, 0x11, 0xc9, 0xea, 0x20, 0x61, 0xe1, 0xc8, 0x4a, 0xd1, 0x0a, 0x23, 0xfa, 0xc1,
            0x72, 0x7e, 0x72, 0x02, 0xfc, 0x3f, 0x50, 0x42, 0xe6, 0xbf, 0x58, 0xcb, 0xa8, 0xa2,
            0x74, 0x6e, 0x1f, 0x64, 0xf9, 0xb9, 0xea, 0x35, 0x2c, 0x71, 0x15, 0x07, 0x05, 0x3c,
            0xf4, 0xe5, 0x33, 0x9d, 0x52, 0x86, 0x5f, 0x25, 0xcc, 0x22, 0xb5, 0xe8, 0x77, 0x84,
            0xa1, 0x2f, 0xc9, 0x61, 0xd6, 0x6c, 0xb6, 0xe8, 0x95, 0x73, 0x19, 0x9a, 0x2c, 0xe6,
            0x56, 0x5c, 0xbd, 0xf1, 0x3d, 0xca, 0x40, 0x38, 0x32, 0xcf, 0xcb, 0x0e, 0x8b, 0x72,
            0x11, 0xe8, 0x3a, 0xf3, 0x2a, 0x11, 0xac, 0x17, 0x92, 0x9f, 0xf1, 0xc0, 0x73, 0xa5,
            0x1c, 0xc0, 0x27, 0xaa, 0xed, 0xef, 0xf8, 0x5a, 0xad, 0x7c, 0x2b, 0x7c, 0x5a, 0x80,
            0x3e, 0x24, 0x04, 0xd9, 0x6d, 0x2a, 0x77, 0x35, 0x7b, 0xda, 0x1a, 0x6d, 0xae, 0xed,
            0x17, 0x15, 0x1c, 0xb9, 0xbc, 0x51, 0x25, 0xa4, 0x22, 0xe9, 0x41, 0xde, 0x0c, 0xa0,
            0xfc, 0x50, 0x11, 0xc2, 0x3e, 0xcf, 0xfe, 0xfd, 0xd0, 0x96, 0x76, 0x71, 0x1c, 0xf3,
            0xdb, 0x0a, 0x34, 0x40, 0x72, 0x0e, 0x16, 0x15, 0xc1, 0xf2, 0x2f, 0xbc, 0x3c, 0x72,
            0x1d, 0xe5, 0x21, 0xe1, 0xb9, 0x9b, 0xa1, 0xbd, 0x55, 0x77, 0x40, 0x86, 0x42, 0x14,
            0x7e, 0xd0, 0x96,
        ];
        let expected = [
            0x4f, 0x44, 0x0d, 0xb1, 0xe6, 0xed, 0xd2, 0x89, 0x9f, 0xa3, 0x35, 0xf0, 0x95, 0x15,
            0xaa, 0x02, 0x5e, 0xe1, 0x77, 0xa7, 0x9f, 0x4b, 0x4a, 0xaf, 0x38, 0xe4, 0x2b, 0x5c,
            0x4d, 0xe6, 0x60, 0xf5, 0xde, 0x8f, 0xb2, 0xa5, 0xb2, 0xfb, 0xd2, 0xa3, 0xcb, 0xff,
            0xd2, 0x0c, 0xff, 0x12, 0x88, 0xc0,
        ];

        let mut sha = Sha384::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }
}