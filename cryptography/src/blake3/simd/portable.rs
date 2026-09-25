//! Scalar words, one array element per lane.

use super::Words;
use blake3::{BLOCK_LEN, OUT_LEN};

impl<const L: usize> Words<L> for [u32; L] {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        [word; L]
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        core::array::from_fn(|lane| self[lane].wrapping_add(other[lane]))
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        core::array::from_fn(|lane| self[lane] ^ other[lane])
    }

    #[inline(always)]
    unsafe fn rotate16(self) -> Self {
        self.map(|word| word.rotate_right(16))
    }

    #[inline(always)]
    unsafe fn rotate12(self) -> Self {
        self.map(|word| word.rotate_right(12))
    }

    #[inline(always)]
    unsafe fn rotate8(self) -> Self {
        self.map(|word| word.rotate_right(8))
    }

    #[inline(always)]
    unsafe fn rotate7(self) -> Self {
        self.map(|word| word.rotate_right(7))
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; L]) -> [Self; 16] {
        let mut words = [[0u32; L]; 16];
        for (lane, block) in blocks.iter().enumerate() {
            for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
                word[lane] = u32::from_le_bytes(*bytes);
            }
        }
        words
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; L] {
        core::array::from_fn(|lane| {
            let mut output = [0u8; OUT_LEN];
            for (chunk, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(words) {
                *chunk = word[lane].to_le_bytes();
            }
            output
        })
    }
}
