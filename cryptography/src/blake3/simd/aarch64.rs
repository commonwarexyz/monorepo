//! NEON words: four messages per 128-bit vector.

use super::{Digest, Words, batch};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::aarch64::*;

/// Messages per NEON vector.
const LANES: usize = 4;

/// Minimum active lanes for the batch kernel.
const MINIMUM: usize = 2;

/// Byte shuffle rotating each 32-bit word right by 8 bits.
static ROTATE8: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

/// Interleave the 64-bit halves of `low` and `high`.
#[inline(always)]
unsafe fn interleave(low: uint32x4_t, high: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
    // SAFETY: The caller establishes NEON.
    unsafe {
        let (low, high) = (vreinterpretq_u64_u32(low), vreinterpretq_u64_u32(high));
        (
            vreinterpretq_u32_u64(vtrn1q_u64(low, high)),
            vreinterpretq_u32_u64(vtrn2q_u64(low, high)),
        )
    }
}

/// Transpose a 4x4 matrix of words held as four row vectors.
#[inline(always)]
unsafe fn transpose(rows: [uint32x4_t; 4]) -> [uint32x4_t; 4] {
    // SAFETY: The caller establishes NEON.
    unsafe {
        let ab_02 = vtrn1q_u32(rows[0], rows[1]);
        let ab_13 = vtrn2q_u32(rows[0], rows[1]);
        let cd_02 = vtrn1q_u32(rows[2], rows[3]);
        let cd_13 = vtrn2q_u32(rows[2], rows[3]);
        let (abcd_0, abcd_2) = interleave(ab_02, cd_02);
        let (abcd_1, abcd_3) = interleave(ab_13, cd_13);
        [abcd_0, abcd_1, abcd_2, abcd_3]
    }
}

/// Load and transpose 16 bytes at `offset` of each block.
#[inline(always)]
unsafe fn quarter(blocks: [&[u8; BLOCK_LEN]; LANES], offset: usize) -> [uint32x4_t; 4] {
    // SAFETY: The caller establishes NEON and passes an offset of at most 48,
    // so each 16-byte load stays within its 64-byte block.
    unsafe {
        transpose([
            vreinterpretq_u32_u8(vld1q_u8(blocks[0][offset..].as_ptr())),
            vreinterpretq_u32_u8(vld1q_u8(blocks[1][offset..].as_ptr())),
            vreinterpretq_u32_u8(vld1q_u8(blocks[2][offset..].as_ptr())),
            vreinterpretq_u32_u8(vld1q_u8(blocks[3][offset..].as_ptr())),
        ])
    }
}

impl Words<LANES> for uint32x4_t {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { vdupq_n_u32(word) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { vaddq_u32(self, other) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { veorq_u32(self, other) }
    }

    #[inline(always)]
    unsafe fn rotate16(self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(self))) }
    }

    #[inline(always)]
    unsafe fn rotate12(self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { vsriq_n_u32::<12>(vshlq_n_u32::<20>(self), self) }
    }

    #[inline(always)]
    unsafe fn rotate8(self) -> Self {
        // SAFETY: The caller establishes NEON, and the table is 16 bytes.
        unsafe {
            let table = vld1q_u8(ROTATE8.as_ptr());
            vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(self), table))
        }
    }

    #[inline(always)]
    unsafe fn rotate7(self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { vsriq_n_u32::<7>(vshlq_n_u32::<25>(self), self) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16] {
        // SAFETY: The caller establishes NEON, and each quarter offset is at
        // most 48.
        unsafe {
            let [q0, q1, q2, q3] = [
                quarter(blocks, 0),
                quarter(blocks, 16),
                quarter(blocks, 32),
                quarter(blocks, 48),
            ];
            [
                q0[0], q0[1], q0[2], q0[3], q1[0], q1[1], q1[2], q1[3], q2[0], q2[1], q2[2], q2[3],
                q3[0], q3[1], q3[2], q3[3],
            ]
        }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES] {
        // SAFETY: The caller establishes NEON, and each 16-byte store starts
        // at offset 0 or 16 of a 32-byte output.
        unsafe {
            let low = transpose([words[0], words[1], words[2], words[3]]);
            let high = transpose([words[4], words[5], words[6], words[7]]);
            let mut outputs = [[0u8; OUT_LEN]; LANES];
            for ((output, low), high) in outputs.iter_mut().zip(low).zip(high) {
                vst1q_u8(output.as_mut_ptr(), vreinterpretq_u8_u32(low));
                vst1q_u8(output[16..].as_mut_ptr(), vreinterpretq_u8_u32(high));
            }
            outputs
        }
    }
}

/// Hash four equal-length messages, one per NEON lane.
///
/// # Safety
///
/// The caller must establish NEON availability.
#[target_feature(enable = "neon")]
unsafe fn hash_x4(inputs: [&[u8]; LANES]) -> [[u8; OUT_LEN]; LANES] {
    // SAFETY: NEON is enabled for this function.
    unsafe { super::hash::<uint32x4_t, LANES>(inputs) }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        /// Return whether NEON is available.
        #[inline]
        fn supported() -> bool {
            std::arch::is_aarch64_feature_detected!("neon")
        }
    } else {
        /// Return whether NEON is statically enabled.
        const fn supported() -> bool {
            cfg!(target_feature = "neon")
        }
    }
}

/// Hash independent messages in batches of four.
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    if !supported() {
        return None;
    }
    Some(batch(messages, MINIMUM, |inputs| {
        // SAFETY: NEON availability was established above.
        unsafe { hash_x4(inputs) }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lanes_match_reference() {
        assert!(supported());

        // SAFETY: NEON availability was asserted above.
        super::super::tests::check_lanes::<LANES>(|inputs| unsafe { hash_x4(inputs) });
    }
}
