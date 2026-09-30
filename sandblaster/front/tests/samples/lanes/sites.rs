//! The lane sites.

use sandblaster::prelude::*;

use crate::sha256::{Digest, compress, hash_64};

/// Sixteen independent compressions (AVX-512 ×16).
pub fn compress_x16(states: &[[u32; 8]; 16], blocks: &[[u8; 64]; 16]) -> [[u32; 8]; 16] {
    [compress(states[0], &blocks[0]), compress(states[1], &blocks[1]), compress(states[2], &blocks[2]), compress(states[3], &blocks[3]), compress(states[4], &blocks[4]), compress(states[5], &blocks[5]), compress(states[6], &blocks[6]), compress(states[7], &blocks[7]), compress(states[8], &blocks[8]), compress(states[9], &blocks[9]), compress(states[10], &blocks[10]), compress(states[11], &blocks[11]), compress(states[12], &blocks[12]), compress(states[13], &blocks[13]), compress(states[14], &blocks[14]), compress(states[15], &blocks[15])]
}

/// Eight independent compressions (AVX2 ×8).
pub fn compress_x8(states: &[[u32; 8]; 8], blocks: &[[u8; 64]; 8]) -> [[u32; 8]; 8] {
    [compress(states[0], &blocks[0]), compress(states[1], &blocks[1]), compress(states[2], &blocks[2]), compress(states[3], &blocks[3]), compress(states[4], &blocks[4]), compress(states[5], &blocks[5]), compress(states[6], &blocks[6]), compress(states[7], &blocks[7])]
}

/// Four independent compressions (NEON ×4; rejected on the M5 by the cost model).
pub fn compress_x4(states: &[[u32; 8]; 4], blocks: &[[u8; 64]; 4]) -> [[u32; 8]; 4] {
    [compress(states[0], &blocks[0]), compress(states[1], &blocks[1]), compress(states[2], &blocks[2]), compress(states[3], &blocks[3])]
}

/// Sixteen independent 64-byte hashes: the second block is constant
/// padding (the shape-specialized ×16).
pub fn hash64_x16(msgs: &[[u8; 64]; 16]) -> [Digest; 16] {
    [hash_64(&msgs[0]), hash_64(&msgs[1]), hash_64(&msgs[2]), hash_64(&msgs[3]), hash_64(&msgs[4]), hash_64(&msgs[5]), hash_64(&msgs[6]), hash_64(&msgs[7]), hash_64(&msgs[8]), hash_64(&msgs[9]), hash_64(&msgs[10]), hash_64(&msgs[11]), hash_64(&msgs[12]), hash_64(&msgs[13]), hash_64(&msgs[14]), hash_64(&msgs[15])]
}
