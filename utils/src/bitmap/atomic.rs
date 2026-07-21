//! A fixed-length bitmap whose bits can be set concurrently through shared references.

use super::BitMap;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicU64, Ordering},
};

/// A fixed-length bitmap whose bits can be set concurrently through shared references.
///
/// [Atomic::set] uses relaxed ordering, which is published by ownership transfer rather than
/// by the operations themselves: the bits can only be read back by consuming the map
/// ([Atomic::into_bitmap]), so whatever reclaims exclusive ownership from the setters
/// (joining their tasks, `Arc::into_inner`) is what makes their writes visible.
pub struct Atomic {
    /// The bits, packed into words (bit `i` is bit `i % 64` of word `i / 64`).
    ///
    /// Invariant: `words.len() == len.div_ceil(64)`
    /// Invariant: All bits at index `i` where `i >= len` are 0.
    words: Vec<AtomicU64>,

    /// The number of bits in the bitmap.
    len: u64,
}

impl Atomic {
    /// The size of a word in bits.
    const WORD_BITS: u64 = u64::BITS as u64;

    /// Create a bitmap of `len` zero bits.
    pub fn zeroes(len: u64) -> Self {
        let words = (0..len.div_ceil(Self::WORD_BITS))
            .map(|_| AtomicU64::new(0))
            .collect();
        Self { words, len }
    }

    /// Set `bit` to 1.
    ///
    /// # Panics
    ///
    /// Panics if the bit doesn't exist.
    pub fn set(&self, bit: u64) {
        assert!(
            bit < self.len,
            "bit {} out of bounds (len: {})",
            bit,
            self.len
        );
        self.words[(bit / Self::WORD_BITS) as usize]
            .fetch_or(1 << (bit % Self::WORD_BITS), Ordering::Relaxed);
    }

    /// Convert into a [BitMap] holding the same bits.
    ///
    /// Taking `self` by value means the caller already reclaimed exclusive ownership from
    /// every setter, which is the synchronization that makes their relaxed writes visible.
    pub fn into_bitmap(self) -> BitMap {
        let chunks: VecDeque<_> = self
            .words
            .into_iter()
            .map(|word| word.into_inner().to_le_bytes())
            .collect();
        BitMap::from_chunks(chunks, self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The converted bitmap must match a [BitMap] built with plain sets, across lengths
    /// covering the empty, sub-word, word-aligned, and multi-word-with-tail shapes.
    #[test]
    fn test_set_and_into_bitmap_matches_plain_sets() {
        for len in [0u64, 1, 63, 64, 65, 128, 200] {
            let atomic = Atomic::zeroes(len);
            let mut expected = BitMap::zeroes(len);
            for bit in (0..len).step_by(3).chain(len.checked_sub(1)) {
                atomic.set(bit);
                expected.set(bit, true);
            }
            assert_eq!(atomic.into_bitmap(), expected, "len {len}");
        }
    }

    #[test]
    fn test_shared_setters() {
        let atomic = Atomic::zeroes(1000);
        std::thread::scope(|s| {
            for stripe in 0..4u64 {
                let atomic = &atomic;
                s.spawn(move || {
                    for bit in (stripe..1000).step_by(4) {
                        atomic.set(bit);
                    }
                });
            }
        });
        assert_eq!(atomic.into_bitmap(), BitMap::ones(1000));
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_set_past_len_panics() {
        Atomic::zeroes(64).set(64);
    }

    /// A bit past `len` must be rejected even when it lands inside the trailing word's
    /// allocation, where the word indexing alone would accept it.
    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_set_past_len_in_tail_word_panics() {
        Atomic::zeroes(65).set(70);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_set_on_empty_panics() {
        Atomic::zeroes(0).set(0);
    }
}
