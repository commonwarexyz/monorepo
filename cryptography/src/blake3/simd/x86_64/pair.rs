//! AVX2 pair kernel: two messages per 256-bit vector, one per 128-bit half.
//!
//! Each vector holds one row of the 4x4 state matrix for both messages. Every
//! instruction in the compression acts on 128-bit halves independently, so the
//! row-wise compression of a single message runs on two messages at the cost
//! of one.
//!
//! The kernel comes in two builds that differ only in how they rotate: AVX2
//! shifts, or single AVX-512VL rotate instructions (`VL`).

use crate::blake3::{
    PAIR_LEN,
    simd::{CHUNK_END, CHUNK_START, IV, ROOT},
};
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::x86_64::*;

/// Encode a 4-element shuffle selecting elements `z`, `y`, `x`, `w` (high to low).
const fn order(z: i32, y: i32, x: i32, w: i32) -> i32 {
    (z << 6) | (y << 4) | (x << 2) | w
}

/// Rotate each 32-bit lane right by `R` bits (`L` must be `32 - R`).
///
/// # Safety
///
/// The caller must establish AVX2, and AVX-512F and AVX-512VL when `VL`.
#[inline(always)]
unsafe fn rotate<const VL: bool, const R: i32, const L: i32>(x: __m256i) -> __m256i {
    // SAFETY: The caller establishes the features this build requires.
    unsafe {
        if VL {
            _mm256_ror_epi32::<R>(x)
        } else {
            _mm256_or_si256(_mm256_srli_epi32::<R>(x), _mm256_slli_epi32::<L>(x))
        }
    }
}

/// Select two elements from each of `a` and `b` (per 128-bit half).
#[inline(always)]
unsafe fn shuffle2<const MASK: i32>(a: __m256i, b: __m256i) -> __m256i {
    // SAFETY: The caller establishes AVX2.
    unsafe {
        _mm256_castps_si256(_mm256_shuffle_ps::<MASK>(
            _mm256_castsi256_ps(a),
            _mm256_castsi256_ps(b),
        ))
    }
}

/// First half of the column (or diagonal) mix, rotating by 16 and 12.
#[inline(always)]
unsafe fn g1<const VL: bool>(rows: &mut [__m256i; 4], message: __m256i) {
    // SAFETY: The caller establishes the features this build requires.
    unsafe {
        rows[0] = _mm256_add_epi32(_mm256_add_epi32(rows[0], message), rows[1]);
        rows[3] = rotate::<VL, 16, 16>(_mm256_xor_si256(rows[3], rows[0]));
        rows[2] = _mm256_add_epi32(rows[2], rows[3]);
        rows[1] = rotate::<VL, 12, 20>(_mm256_xor_si256(rows[1], rows[2]));
    }
}

/// Second half of the column (or diagonal) mix, rotating by 8 and 7.
#[inline(always)]
unsafe fn g2<const VL: bool>(rows: &mut [__m256i; 4], message: __m256i) {
    // SAFETY: The caller establishes the features this build requires.
    unsafe {
        rows[0] = _mm256_add_epi32(_mm256_add_epi32(rows[0], message), rows[1]);
        rows[3] = rotate::<VL, 8, 24>(_mm256_xor_si256(rows[3], rows[0]));
        rows[2] = _mm256_add_epi32(rows[2], rows[3]);
        rows[1] = rotate::<VL, 7, 25>(_mm256_xor_si256(rows[1], rows[2]));
    }
}

/// Rotate rows so the diagonals line up as columns.
///
/// Row 1 stays fixed and the message words are arranged to compensate.
#[inline(always)]
unsafe fn diagonalize(rows: &mut [__m256i; 4]) {
    // SAFETY: The caller establishes AVX2.
    unsafe {
        rows[0] = _mm256_shuffle_epi32::<{ order(2, 1, 0, 3) }>(rows[0]);
        rows[3] = _mm256_shuffle_epi32::<{ order(1, 0, 3, 2) }>(rows[3]);
        rows[2] = _mm256_shuffle_epi32::<{ order(0, 3, 2, 1) }>(rows[2]);
    }
}

/// Undo [`diagonalize`].
#[inline(always)]
unsafe fn undiagonalize(rows: &mut [__m256i; 4]) {
    // SAFETY: The caller establishes AVX2.
    unsafe {
        rows[0] = _mm256_shuffle_epi32::<{ order(0, 3, 2, 1) }>(rows[0]);
        rows[3] = _mm256_shuffle_epi32::<{ order(1, 0, 3, 2) }>(rows[3]);
        rows[2] = _mm256_shuffle_epi32::<{ order(2, 1, 0, 3) }>(rows[2]);
    }
}

/// Compress one block of each message into its chaining value.
///
/// `cv` holds chaining value words 0-3 and 4-7, and `message` holds block
/// words 0-3, 4-7, 8-11, and 12-15, each with one message per 128-bit half.
#[inline(always)]
unsafe fn compress<const VL: bool>(
    cv: &mut [__m256i; 2],
    message: [__m256i; 4],
    len: usize,
    flags: u32,
) {
    // SAFETY: The caller establishes the features this build requires.
    unsafe {
        let iv = _mm256_setr_epi32(
            IV[0] as i32,
            IV[1] as i32,
            IV[2] as i32,
            IV[3] as i32,
            IV[0] as i32,
            IV[1] as i32,
            IV[2] as i32,
            IV[3] as i32,
        );
        let (len, flags) = (len as i32, flags as i32);
        let mut rows = [
            cv[0],
            cv[1],
            iv,
            _mm256_setr_epi32(0, 0, len, flags, 0, 0, len, flags),
        ];
        let [mut m0, mut m1, mut m2, mut m3] = message;

        // The first round gathers the message words from their original order
        // into the groups mixed together.
        let t0 = shuffle2::<{ order(2, 0, 2, 0) }>(m0, m1);
        g1::<VL>(&mut rows, t0);
        let t1 = shuffle2::<{ order(3, 1, 3, 1) }>(m0, m1);
        g2::<VL>(&mut rows, t1);
        diagonalize(&mut rows);
        let t2 = shuffle2::<{ order(2, 0, 2, 0) }>(m2, m3);
        let t2 = _mm256_shuffle_epi32::<{ order(2, 1, 0, 3) }>(t2);
        g1::<VL>(&mut rows, t2);
        let t3 = shuffle2::<{ order(3, 1, 3, 1) }>(m2, m3);
        let t3 = _mm256_shuffle_epi32::<{ order(2, 1, 0, 3) }>(t3);
        g2::<VL>(&mut rows, t3);
        undiagonalize(&mut rows);
        (m0, m1, m2, m3) = (t0, t1, t2, t3);

        // Each later round applies the same permutation to the previous
        // round's message groups.
        for _ in 1..7 {
            let t0 = shuffle2::<{ order(3, 1, 1, 2) }>(m0, m1);
            let t0 = _mm256_shuffle_epi32::<{ order(0, 3, 2, 1) }>(t0);
            g1::<VL>(&mut rows, t0);
            let t1 = shuffle2::<{ order(3, 3, 2, 2) }>(m2, m3);
            let tt = _mm256_shuffle_epi32::<{ order(0, 0, 3, 3) }>(m0);
            let t1 = _mm256_blend_epi16::<0xCC>(tt, t1);
            g2::<VL>(&mut rows, t1);
            diagonalize(&mut rows);
            let t2 = _mm256_unpacklo_epi64(m3, m1);
            let tt = _mm256_blend_epi16::<0xC0>(t2, m2);
            let t2 = _mm256_shuffle_epi32::<{ order(1, 3, 2, 0) }>(tt);
            g1::<VL>(&mut rows, t2);
            let t3 = _mm256_unpackhi_epi32(m1, m3);
            let tt = _mm256_unpacklo_epi32(m2, t3);
            let t3 = _mm256_shuffle_epi32::<{ order(0, 1, 3, 2) }>(tt);
            g2::<VL>(&mut rows, t3);
            undiagonalize(&mut rows);
            (m0, m1, m2, m3) = (t0, t1, t2, t3);
        }

        cv[0] = _mm256_xor_si256(rows[0], rows[2]);
        cv[1] = _mm256_xor_si256(rows[1], rows[3]);
    }
}

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
            compress::<VL>(&mut cv, message, block_len, flags);
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
