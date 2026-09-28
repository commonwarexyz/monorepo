//! One message in general-purpose registers.
//!
//! A single message is one chain of dependent compressions with too little
//! independent work to fill vectors, and on Zen 5 each vector instruction
//! takes two cycles against one for a general-purpose one. Each rotate is
//! written as one `ROR` in assembly, which keeps every state word in a
//! general-purpose register whatever the target CPU: LLVM would otherwise
//! pack the four columns into a vector when vector rotates are available, and
//! lower rotates to `SHLD` on targets tuned for it.

use crate::blake3::simd::Words;
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::asm;

/// A state or message word in a general-purpose register.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::blake3::simd) struct Scalar(u32);

impl Scalar {
    /// Exclusive-or with `other`, then rotate right by `R` bits.
    #[inline(always)]
    fn xor_rotate<const R: u32>(self, other: Self) -> Self {
        let mut word = self.0 ^ other.0;
        // SAFETY: The assembly only rotates the one register it is given.
        unsafe {
            asm!(
                "ror {word:e}, {r}",
                word = inout(reg) word,
                r = const R,
                options(pure, nomem, nostack),
            );
        }
        Self(word)
    }
}

impl Words<1> for Scalar {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        Self(word)
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        Self(self.0.wrapping_add(other.0))
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }

    #[inline(always)]
    unsafe fn xor_rotate16(self, other: Self) -> Self {
        self.xor_rotate::<16>(other)
    }

    #[inline(always)]
    unsafe fn xor_rotate12(self, other: Self) -> Self {
        self.xor_rotate::<12>(other)
    }

    #[inline(always)]
    unsafe fn xor_rotate8(self, other: Self) -> Self {
        self.xor_rotate::<8>(other)
    }

    #[inline(always)]
    unsafe fn xor_rotate7(self, other: Self) -> Self {
        self.xor_rotate::<7>(other)
    }

    #[inline(always)]
    unsafe fn load([block]: [&[u8; BLOCK_LEN]; 1]) -> [Self; 16] {
        let mut words = [Self(0); 16];
        for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = Self(u32::from_le_bytes(*bytes));
        }
        words
    }

    #[inline(always)]
    unsafe fn load_partial(inputs: [&[u8]; 1], start: usize, len: usize) -> [Self; 16] {
        // SAFETY: Scalar words require no target features.
        unsafe { crate::blake3::simd::pad(inputs, start, len) }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; 1] {
        let mut output = [0u8; OUT_LEN];
        for (bytes, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *bytes = word.0.to_le_bytes();
        }
        [output]
    }
}
