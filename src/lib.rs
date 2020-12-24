#![no_std]

use core::convert::TryInto;

/// SHA-224 implementation
pub mod sha224;

/// SHA-256 implementation
pub mod sha256;

/// SHA-384 implementation
pub mod sha384;

/// SHA-512 implementation
pub mod sha512;

/// SHA2 Error types
#[derive(Debug)]
pub enum Error {
    InvalidLength,
    InvalidBitLength,
}

/// SHA2 implementation type
#[derive(PartialEq)]
pub enum Hash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

// Number of bytes in SHA-224/256 internal message block
const BLOCK_224_256_LEN: usize = 64;

// Number of bytes in SHA-384/512 internal message block
const BLOCK_384_512_LEN: usize = 128;

// Word byte length for SHA-224/256
const WORD_224_256_LEN: usize = 4;

// Word byte length for SHA-384/512
const WORD_384_512_LEN: usize = 8;

// Number of words used in SHA-224/256 block processing
const WORK_224_256_LEN: usize = 64;

// Number of words used in SHA-384/512 block processing
const WORK_384_512_LEN: usize = 80;

// Length of the minimum amount of padding bytes (0x80 || MSG_BITS_LEN(8))
const PAD_AND_LENGTH_224_256_LEN: usize = 9;

// Length of the minimum amount of padding bytes (0x80 || MSG_BITS_LEN(16))
const PAD_AND_LENGTH_384_512_LEN: usize = 17;

// Number of 32-bit words in the SHA-224/256 internal state
const STATE_224_256_LEN: usize = 8;

// Number of 64-bit words in the SHA-384/512 internal state
const STATE_384_512_LEN: usize = 8;

// SHA224/256 byte-length to represent the bit-length of the message
const MSG_BITS_LENGTH_224_256_LEN: usize = 8;

// SHA384/512 byte-length to represent the bit-length of the message
const MSG_BITS_LENGTH_384_512_LEN: usize = 16;

const ZERO_BLOCK: [u8; BLOCK_384_512_LEN] = [0_u8; BLOCK_384_512_LEN];
const ZERO_WORK_224_256: [u32; WORK_224_256_LEN] = [0_u32; WORK_224_256_LEN];
const ZERO_WORK_384_512: [u64; WORK_384_512_LEN] = [0_u64; WORK_384_512_LEN];

// Word constants used during SHA-224/256 block processing
//
// Defined in FIPS-180-2, section 4.2.2
const K_224_256: [u32; WORK_224_256_LEN] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Word constants used during SHA-384/512 block processing
//
// Defined in FIPS-180-2, section 4.2.2
const K_384_512: [u64; WORK_384_512_LEN] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub trait Sha2 {
    type Block;
    type Digest;
    type State;

    fn new() -> Self;

    /// Incrementally update the internal SHA-256 state with message bytes
    ///
    /// Total message length must be below TotalLength::MAX:
    ///
    /// u64::MAX for Sha224/256
    /// u128::MAX for Sha384/512
    fn input(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.increment_total_len(msg.len() * 8)?;

        for &byte in msg.iter() {
            let index = self.index();
            self.block_mut()[index] = byte;
            self.increment_index();

            if self.index() == self.block_len() {
                self.process_block();
            }
        }

        Ok(())
    }

    /// Add final bits to internal state, and finalize the digest
    ///
    /// Bit length must be in range: 0 < len < 8
    ///
    /// Resets the internal state to the initial state
    fn final_bits(&mut self, bits: u8, len: usize) -> Result<Self::Digest, Error> {
        if len == 0 || len >= 8 {
            return Err(Error::InvalidBitLength);
        }

        // process a block if full, or move the index to the next byte
        if self.index() == self.block_len() {
            self.process_block();
        }

        let mask = match len {
            1 => 0b1000_0000,
            2 => 0b1100_0000,
            3 => 0b1110_0000,
            4 => 0b1111_0000,
            5 => 0b1111_1000,
            6 => 0b1111_1100,
            7 => 0b1111_1110,
            _ => return Err(Error::InvalidBitLength),
        };

        // add final bits as the last byte
        let index = self.index();
        self.block_mut()[index] = bits & mask;

        // set bit index for padding
        self.set_bit_index(len);
        self.increment_total_len(len);

        // perform final processing
        self.finalize()
    }

    /// Compute the final digest
    ///
    /// Resets the internal state to the initial state
    fn finalize(&mut self) -> Result<Self::Digest, Error> {
        let index = self.index();
        let (block_len, pad_and_length_len) = match self.hash() {
            Hash::Sha224 | Hash::Sha256 => (BLOCK_224_256_LEN, PAD_AND_LENGTH_224_256_LEN),
            Hash::Sha384 | Hash::Sha512 => (BLOCK_384_512_LEN, PAD_AND_LENGTH_384_512_LEN),
        };
        if index < block_len {
            let old_len = index;

            // pad and process the padded block
            self.pad()?;
            self.process_block();

            if old_len > block_len - pad_and_length_len {
                // there wasn't enough room to include the message bit-length
                // process a full block of padding
                self.full_pad();
                self.process_block();
            }
        }

        let res = self.encode_state();

        self.reset();

        Ok(res)
    }

    /// Reset the internal state to the initial state
    fn reset(&mut self) {
        self.initial_state();
        self.zero_block();
        self.reset_counters();
    }

    /// Convenience function to calculate the hash digest
    fn digest(input: &[u8]) -> Result<Self::Digest, Error>
    where
        Self: Sized,
    {
        let mut sha = Self::new();
        sha.input(input)?;
        sha.finalize()
    }

    fn process_block(&mut self);
    fn pad(&mut self) -> Result<(), Error>;
    fn full_pad(&mut self);

    fn index(&self) -> usize;
    fn increment_index(&mut self);
    fn bit_index(&self) -> usize;
    fn set_bit_index(&mut self, index: usize);
    fn total_len(&self) -> u128;
    fn increment_total_len(&mut self, len: usize) -> Result<(), Error>;
    fn hash(&self) -> &Hash;
    fn encode_state(&self) -> Self::Digest;
    fn initial_state(&mut self);
    fn block_mut(&mut self) -> &mut [u8];
    fn block_len(&self) -> usize {
        match self.hash() {
            Hash::Sha224 | Hash::Sha256 => BLOCK_224_256_LEN,
            Hash::Sha384 | Hash::Sha512 => BLOCK_384_512_LEN,
        }
    }
    fn zero_block(&mut self);
    fn reset_counters(&mut self);
}

fn process_block_224_256(
    state: &mut [u32; STATE_224_256_LEN],
    block: &mut [u8; BLOCK_224_256_LEN],
    index: &mut usize,
) {
    let mut w = [0_u32; WORK_224_256_LEN];

    // initialize first 16 working words from the message block
    for (t, word) in block.chunks_exact(WORD_224_256_LEN).enumerate() {
        // unwrap safe here, because word guaranteed 4 bytes long
        w[t] = u32::from_be_bytes(word.try_into().unwrap());
    }

    // initialize remaining working words
    for t in 16..WORK_224_256_LEN {
        w[t] = (lil_sigma1_224_256(w[t - 2]) as u64
            + w[t - 7] as u64
            + lil_sigma0_224_256(w[t - 15]) as u64
            + w[t - 16] as u64
            & 0xffff_ffff) as u32;
    }

    // initialize working variables from current state
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // perform main transformations
    for t in 0..WORK_224_256_LEN {
        let temp1 = ((h as u64
            + big_sigma1_224_256(e) as u64
            + ch_224_256(e, f, g) as u64
            + K_224_256[t] as u64
            + w[t] as u64)
            & 0xffff_ffff) as u32;

        let temp2 =
            ((big_sigma0_224_256(a) as u64 + maj_224_256(a, b, c) as u64) & 0xffff_ffff) as u32;

        h = g;
        g = f;
        f = e;
        e = ((d as u64 + temp1 as u64) & 0xffff_ffff) as u32;
        d = c;
        c = b;
        b = a;
        a = ((temp1 as u64 + temp2 as u64) & 0xffff_ffff) as u32;
    }

    // add the temporary values back to the state words
    for (i, word) in state.iter_mut().enumerate() {
        let temp = match i {
            0 => a as u64,
            1 => b as u64,
            2 => c as u64,
            3 => d as u64,
            4 => e as u64,
            5 => f as u64,
            6 => g as u64,
            7 => h as u64,
            _ => unreachable!("invalid state index"),
        };

        *word = ((*word as u64 + temp) & 0xffff_ffff) as u32;
    }

    // zero the working words
    zero_work_224_256(&mut w);
    // zero the message block
    zero_block(block);
    // reset the index
    *index = 0;
}

fn process_block_384_512(
    state: &mut [u64; STATE_384_512_LEN],
    block: &mut [u8; BLOCK_384_512_LEN],
    index: &mut usize,
) {
    let mut w = [0_u64; WORK_384_512_LEN];

    // initialize first 16 working words from the message block
    for (t, word) in block.chunks_exact(WORD_384_512_LEN).enumerate() {
        // unwrap safe here, because word guaranteed 4 bytes long
        w[t] = u64::from_be_bytes(word.try_into().unwrap());
    }

    // initialize remaining working words
    for t in 16..WORK_384_512_LEN {
        w[t] = (lil_sigma1_384_512(w[t - 2]) as u128
            + w[t - 7] as u128
            + lil_sigma0_384_512(w[t - 15]) as u128
            + w[t - 16] as u128
            & 0xffff_ffff_ffff_ffff) as u64;
    }

    // initialize working variables from current state
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // perform main transformations
    for t in 0..WORK_384_512_LEN {
        let temp1 = ((h as u128
            + big_sigma1_384_512(e) as u128
            + ch_384_512(e, f, g) as u128
            + K_384_512[t] as u128
            + w[t] as u128)
            & 0xffff_ffff_ffff_ffff) as u64;

        let temp2 = ((big_sigma0_384_512(a) as u128 + maj_384_512(a, b, c) as u128)
            & 0xffff_ffff_ffff_ffff) as u64;

        h = g;
        g = f;
        f = e;
        e = ((d as u128 + temp1 as u128) & 0xffff_ffff_ffff_ffff) as u64;
        d = c;
        c = b;
        b = a;
        a = ((temp1 as u128 + temp2 as u128) & 0xffff_ffff_ffff_ffff) as u64;
    }

    // add the temporary values back to the state words
    for (i, word) in state.iter_mut().enumerate() {
        let temp = match i {
            0 => a as u128,
            1 => b as u128,
            2 => c as u128,
            3 => d as u128,
            4 => e as u128,
            5 => f as u128,
            6 => g as u128,
            7 => h as u128,
            _ => unreachable!("invalid state index"),
        };

        *word = ((*word as u128 + temp) & 0xffff_ffff_ffff_ffff) as u64;
    }

    // zero the working words
    zero_work_384_512(&mut w);
    // zero the message block
    zero_block(block);
    // reset the index
    *index = 0;
}

// Perform inner padding
fn inner_pad(
    block: &mut [u8],
    index: usize,
    bit_index: usize,
    total_len: u128,
    hash: &Hash,
) -> Result<(), Error> {
    let block_len = match hash {
        Hash::Sha224 | Hash::Sha256 => BLOCK_224_256_LEN,
        Hash::Sha384 | Hash::Sha512 => BLOCK_384_512_LEN,
    };

    let pad_len = block_len - index;

    // check that we are not padding a full block
    // total_len is a u64, so can't be more than u64::MAX
    if pad_len == 0 {
        return Err(Error::InvalidLength);
    }

    block[index] |= match bit_index {
        0 => 0b1000_0000,
        1 => 0b0100_0000,
        2 => 0b0010_0000,
        3 => 0b0001_0000,
        4 => 0b0000_1000,
        5 => 0b0000_0100,
        6 => 0b0000_0010,
        7 => 0b0000_0001,
        _ => return Err(Error::InvalidBitLength),
    };

    let (pad_and_length_len, msg_bits_length_len) = match hash {
        Hash::Sha224 | Hash::Sha256 => (PAD_AND_LENGTH_224_256_LEN, MSG_BITS_LENGTH_224_256_LEN),
        Hash::Sha384 | Hash::Sha512 => (PAD_AND_LENGTH_384_512_LEN, MSG_BITS_LENGTH_384_512_LEN),
    };

    // the end position of zero-byte padding
    let zero_pad_end = if pad_len > pad_and_length_len {
        // enough room for message bit length to follow
        block_len - msg_bits_length_len
    } else {
        // only enough room for zeros
        block_len
    };

    if pad_len > 1 {
        // will pad with zeroes, or a no-op if index + 1 == zero_pad_end
        zero_block(&mut block[index + 1..zero_pad_end]);
    }

    if pad_len >= pad_and_length_len {
        // add the message bits length
        let len_start = core::mem::size_of_val(&total_len);
        let length_bytes = &total_len.to_be_bytes()[len_start - msg_bits_length_len..];
        block[block_len - msg_bits_length_len..].copy_from_slice(length_bytes);
    }

    Ok(())
}

// Add a full block of padding
fn inner_full_pad(block: &mut [u8], total_len: u128, hash: &Hash) {
    let (block_len, msg_bits_length_len) = match hash {
        Hash::Sha224 | Hash::Sha256 => (BLOCK_224_256_LEN, MSG_BITS_LENGTH_224_256_LEN),
        Hash::Sha384 | Hash::Sha512 => (BLOCK_384_512_LEN, MSG_BITS_LENGTH_384_512_LEN),
    };
    zero_block(&mut block[..block_len - msg_bits_length_len]);
    // copy the total message bit length bytes to the end of the message block
    let len_start = core::mem::size_of_val(&total_len);
    let length_bytes = &total_len.to_be_bytes()[len_start - msg_bits_length_len..];
    block[block_len - msg_bits_length_len..].copy_from_slice(length_bytes);
}

// Corresponds to SHA224/256_Ch from RFC 4634
fn ch_224_256(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

// Corresponds to SHA224/256_Maj from RFC 4634
fn maj_224_256(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

// Corresponds to SHA224/256_SIGMA0 from RFC 4634
fn big_sigma0_224_256(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

// Corresponds to SHA224/256_SIGMA1 from RFC 4634
fn big_sigma1_224_256(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

// Corresponds to SHA224/256_sigma0 from RFC 4634
fn lil_sigma0_224_256(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

// Corresponds to SHA224/256_sigma1 from RFC 4634
fn lil_sigma1_224_256(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// Corresponds to SHA384/512_Ch from RFC 4634
//
// From the RFC:
// * These definitions are potentially faster equivalents for the ones
// * used in FIPS-180-2, section 4.1.3.
// *   ((x & y) ^ (~x & z)) becomes
// *   ((x & (y ^ z)) ^ z)
fn ch_384_512(x: u64, y: u64, z: u64) -> u64 {
    (x & (y ^ z)) ^ z
}

// Corresponds to SHA384/512_Maj from RFC 4634
//
// From the RFC:
//
// * These definitions are potentially faster equivalents for the ones
// * used in FIPS-180-2, section 4.1.3.
// *   ((x & y) ^ (x & z) ^ (y & z)) becomes
// *   ((x & (y | z)) | (y & z))
fn maj_384_512(x: u64, y: u64, z: u64) -> u64 {
    (x & (y | z)) | (y & z)
}

// Corresponds to SHA384/512_SIGMA0 from RFC 4634
fn big_sigma0_384_512(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

// Corresponds to SHA384/512_SIGMA1 from RFC 4634
fn big_sigma1_384_512(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

// Corresponds to SHA384/512_sigma0 from RFC 4634
fn lil_sigma0_384_512(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

// Corresponds to SHA384/512_sigma1 from RFC 4634
fn lil_sigma1_384_512(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

// Zero a work word buffer potentially containing sensitive data
// FIXME: compiler may actually optimize this away (uses memcpy internally)
//    For secure zeroing, implement Zeroize trait or similar
fn zero_work_224_256(work: &mut [u32; WORK_224_256_LEN]) {
    work.copy_from_slice(ZERO_WORK_224_256.as_ref());
}

// Zero a work word buffer potentially containing sensitive data
// FIXME: compiler may actually optimize this away (uses memcpy internally)
//    For secure zeroing, implement Zeroize trait or similar
fn zero_work_384_512(work: &mut [u64; WORK_384_512_LEN]) {
    work.copy_from_slice(ZERO_WORK_384_512.as_ref());
}

// Zero a block potentially containing sensitive data
// FIXME: compiler may actually optimize this away (uses memcpy internally)
//    For secure zeroing, implement Zeroize trait or similar
fn zero_block(block: &mut [u8]) {
    block.copy_from_slice(&ZERO_BLOCK[..block.len()]);
}
