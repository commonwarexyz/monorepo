//! AVX2 pair kernel: two messages per 256-bit vector, one per 128-bit half.
//!
//! Each vector holds one row of the 4x4 state matrix for both messages. Every
//! instruction in the compression acts on 128-bit halves independently, so the
//! row-wise compression of a single message runs on two messages at the cost
//! of one.
//!
//! The kernel comes in two builds that differ only in how they rotate: AVX2
//! shifts, or single AVX-512VL rotate instructions (`VL`).

use super::row;
use crate::blake3::{
    PAIR_LEN,
    simd::{CHUNK_END, CHUNK_START, IV, ROOT},
};
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::x86_64::*;

/// Hash two `len`-byte messages, each zero-padded to [`PAIR_LEN`] bytes.
///
/// # Safety
///
/// The caller must establish AVX2, and AVX-512F and AVX-512VL when `VL`.
#[inline(always)]
unsafe fn hash<const VL: bool>(
    left: &[u8; PAIR_LEN],
    right: &[u8; PAIR_LEN],
    len: usize,
) -> [[u8; OUT_LEN]; 2] {
    assert!(len <= PAIR_LEN, "pair messages exceed PAIR_LEN");
    let blocks = len.div_ceil(BLOCK_LEN).max(1);

    // SAFETY: The caller establishes the features this build requires, and
    // each unaligned 16-byte load starts at most 112 bytes into a 128-byte
    // buffer.
    unsafe {
        let low = _mm256_setr_epi32(
            IV[0] as i32,
            IV[1] as i32,
            IV[2] as i32,
            IV[3] as i32,
            IV[0] as i32,
            IV[1] as i32,
            IV[2] as i32,
            IV[3] as i32,
        );
        let high = _mm256_setr_epi32(
            IV[4] as i32,
            IV[5] as i32,
            IV[6] as i32,
            IV[7] as i32,
            IV[4] as i32,
            IV[5] as i32,
            IV[6] as i32,
            IV[7] as i32,
        );
        let mut cv = [low, high];
        for block in 0..blocks {
            let offset = block * BLOCK_LEN;
            let block_len = (len - offset).min(BLOCK_LEN);
            let mut flags = if block == 0 { CHUNK_START } else { 0 };
            if block + 1 == blocks {
                flags |= CHUNK_END | ROOT;
            }
            let mut message = [_mm256_setzero_si256(); 4];
            for (quarter, words) in message.iter_mut().enumerate() {
                let start = offset + 16 * quarter;
                *words = _mm256_loadu2_m128i(
                    right[start..].as_ptr().cast(),
                    left[start..].as_ptr().cast(),
                );
            }
            row::compress::<_, VL>(&mut cv, message, block_len, flags);
        }

        // Words 0-7 of the left message sit in the low halves, the right in
        // the high halves.
        let left_words = _mm256_permute2x128_si256::<0x20>(cv[0], cv[1]);
        let right_words = _mm256_permute2x128_si256::<0x31>(cv[0], cv[1]);
        let mut outputs = [[0u8; OUT_LEN]; 2];
        _mm256_storeu_si256(outputs[0].as_mut_ptr().cast(), left_words);
        _mm256_storeu_si256(outputs[1].as_mut_ptr().cast(), right_words);
        outputs
    }
}

/// Copy the concatenation of `parts` into `buffer`, zero-padded, returning its
/// length, or `None` if it exceeds [`PAIR_LEN`] bytes or a part is not a whole
/// number of 32-bit words.
///
/// Masked loads assemble each 32-byte half of a block in a register from the
/// parts that overlap it, and one 32-byte store writes it, so each 16-byte
/// load of the kernel reads bytes written by a single store.
///
/// # Safety
///
/// The caller must establish AVX2 availability.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn gather(parts: &[&[u8]], buffer: &mut [u8; PAIR_LEN]) -> Option<usize> {
    const HALF: usize = BLOCK_LEN / 2;
    let mut halves = [_mm256_setzero_si256(); PAIR_LEN / HALF];
    let lanes = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
    let mut len = 0;
    for part in parts {
        let end = len + part.len();
        if end > PAIR_LEN || part.len() % 4 != 0 {
            return None;
        }
        for (index, half) in halves.iter_mut().enumerate() {
            // Message bytes `low..high` lie in both the part and the half.
            let start = index * HALF;
            let (low, high) = (len.max(start), end.min(start + HALF));
            if low >= high {
                continue;
            }

            // Every part so far is whole words, so `low` and `high` fall on
            // word boundaries. Select words `first..last` of the half.
            let first = _mm256_set1_epi32(((low - start) / 4) as i32);
            let last = _mm256_set1_epi32(((high - start) / 4) as i32);
            let mask = _mm256_andnot_si256(
                _mm256_cmpgt_epi32(first, lanes),
                _mm256_cmpgt_epi32(last, lanes),
            );

            // Word `i` of the load is bytes `start + 4 * i..` of the message.
            let base = part.as_ptr().wrapping_add(start).wrapping_sub(len);

            // SAFETY: AVX2 is enabled, and the mask selects the words of bytes
            // `low - len..high - len` of `part`, the only bytes read.
            let words = unsafe { _mm256_maskload_epi32(base.cast(), mask) };
            *half = _mm256_or_si256(*half, words);
        }
        len = end;
    }
    for (chunk, half) in buffer.as_chunks_mut::<HALF>().0.iter_mut().zip(halves) {
        // SAFETY: AVX2 is enabled, and the store fills one 32-byte chunk.
        unsafe { _mm256_storeu_si256(chunk.as_mut_ptr().cast(), half) };
    }
    Some(len)
}

/// Hash two `len`-byte messages, each zero-padded to [`PAIR_LEN`] bytes,
/// rotating with AVX2 shifts.
///
/// # Safety
///
/// The caller must establish AVX2 availability.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn hash_pair(
    left: &[u8; PAIR_LEN],
    right: &[u8; PAIR_LEN],
    len: usize,
) -> [[u8; OUT_LEN]; 2] {
    // SAFETY: AVX2 is enabled for this function.
    unsafe { hash::<false>(left, right, len) }
}

/// Hash two `len`-byte messages, each zero-padded to [`PAIR_LEN`] bytes,
/// rotating with AVX-512VL instructions.
///
/// # Safety
///
/// The caller must establish AVX2, AVX-512F, and AVX-512VL availability.
#[target_feature(enable = "avx2,avx512f,avx512vl")]
pub(super) unsafe fn hash_pair_vl(
    left: &[u8; PAIR_LEN],
    right: &[u8; PAIR_LEN],
    len: usize,
) -> [[u8; OUT_LEN]; 2] {
    // SAFETY: AVX2, AVX-512F, and AVX-512VL are enabled for this function.
    unsafe { hash::<true>(left, right, len) }
}
