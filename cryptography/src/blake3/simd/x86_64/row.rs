//! BLAKE3 compression with one message per 128-bit group of each state row.

use crate::blake3::simd::IV;
use core::arch::x86_64::*;

/// Row operations preserve each message's 128-bit group.
///
/// Callers establish AVX2 for 256-bit rows, AVX-512F and AVX-512VL as well
/// when selecting native 256-bit rotates, and AVX-512F for 512-bit rows.
pub(super) trait Row: Copy {
    unsafe fn from_words(words: [u32; 4]) -> Self;
    unsafe fn add(a: Self, b: Self) -> Self;
    unsafe fn xor(a: Self, b: Self) -> Self;
    unsafe fn rotate<const VL: bool, const R: i32, const L: i32>(x: Self) -> Self;
    unsafe fn shuffle<const MASK: i32>(x: Self) -> Self;
    unsafe fn shuffle2<const MASK: i32>(a: Self, b: Self) -> Self;

    /// Take the 32-bit lanes of `b` whose bits are set in `MASK`, and the
    /// other lanes of `a`. `MASK` spans two 128-bit groups and repeats across
    /// wider rows.
    unsafe fn blend<const MASK: i32>(a: Self, b: Self) -> Self;

    unsafe fn unpacklo64(a: Self, b: Self) -> Self;
    unsafe fn unpackhi32(a: Self, b: Self) -> Self;
    unsafe fn unpacklo32(a: Self, b: Self) -> Self;
}

impl Row for __m256i {
    #[inline(always)]
    unsafe fn from_words(words: [u32; 4]) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe {
            _mm256_broadcastsi128_si256(_mm_setr_epi32(
                words[0] as i32,
                words[1] as i32,
                words[2] as i32,
                words[3] as i32,
            ))
        }
    }

    #[inline(always)]
    unsafe fn add(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm256_add_epi32(a, b) }
    }

    #[inline(always)]
    unsafe fn xor(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm256_xor_si256(a, b) }
    }

    #[inline(always)]
    unsafe fn rotate<const VL: bool, const R: i32, const L: i32>(x: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe {
            if VL {
                _mm256_ror_epi32::<R>(x)
            } else {
                _mm256_or_si256(_mm256_srli_epi32::<R>(x), _mm256_slli_epi32::<L>(x))
            }
        }
    }

    #[inline(always)]
    unsafe fn shuffle<const MASK: i32>(x: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm256_shuffle_epi32::<MASK>(x) }
    }

    #[inline(always)]
    unsafe fn shuffle2<const MASK: i32>(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe {
            _mm256_castps_si256(_mm256_shuffle_ps::<MASK>(
                _mm256_castsi256_ps(a),
                _mm256_castsi256_ps(b),
            ))
        }
    }

    #[inline(always)]
    unsafe fn blend<const MASK: i32>(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm256_blend_epi32::<MASK>(a, b) }
    }

    #[inline(always)]
    unsafe fn unpacklo64(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm256_unpacklo_epi64(a, b) }
    }

    #[inline(always)]
    unsafe fn unpackhi32(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm256_unpackhi_epi32(a, b) }
    }

    #[inline(always)]
    unsafe fn unpacklo32(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm256_unpacklo_epi32(a, b) }
    }
}

impl Row for __m512i {
    #[inline(always)]
    unsafe fn from_words(words: [u32; 4]) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe {
            _mm512_broadcast_i32x4(_mm_setr_epi32(
                words[0] as i32,
                words[1] as i32,
                words[2] as i32,
                words[3] as i32,
            ))
        }
    }

    #[inline(always)]
    unsafe fn add(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_add_epi32(a, b) }
    }

    #[inline(always)]
    unsafe fn xor(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_xor_si512(a, b) }
    }

    #[inline(always)]
    unsafe fn rotate<const VL: bool, const R: i32, const L: i32>(x: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_ror_epi32::<R>(x) }
    }

    #[inline(always)]
    unsafe fn shuffle<const MASK: i32>(x: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_shuffle_epi32::<MASK>(x) }
    }

    #[inline(always)]
    unsafe fn shuffle2<const MASK: i32>(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe {
            _mm512_castps_si512(_mm512_shuffle_ps::<MASK>(
                _mm512_castsi512_ps(a),
                _mm512_castsi512_ps(b),
            ))
        }
    }

    #[inline(always)]
    unsafe fn blend<const MASK: i32>(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_mask_blend_epi32((MASK as u16) | ((MASK as u16) << 8), a, b) }
    }

    #[inline(always)]
    unsafe fn unpacklo64(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_unpacklo_epi64(a, b) }
    }

    #[inline(always)]
    unsafe fn unpackhi32(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_unpackhi_epi32(a, b) }
    }

    #[inline(always)]
    unsafe fn unpacklo32(a: Self, b: Self) -> Self {
        // SAFETY: The caller establishes the row implementation's features.
        unsafe { _mm512_unpacklo_epi32(a, b) }
    }
}

/// Encode a 4-element shuffle selecting elements `z`, `y`, `x`, `w` (high to low).
const fn order(z: i32, y: i32, x: i32, w: i32) -> i32 {
    (z << 6) | (y << 4) | (x << 2) | w
}

/// First half of the column (or diagonal) mix, rotating by 16 and 12.
#[inline(always)]
unsafe fn g1<V: Row, const VL: bool>(rows: &mut [V; 4], message: V) {
    // SAFETY: The caller establishes the row implementation's features.
    unsafe {
        rows[0] = V::add(V::add(rows[0], message), rows[1]);
        rows[3] = V::rotate::<VL, 16, 16>(V::xor(rows[3], rows[0]));
        rows[2] = V::add(rows[2], rows[3]);
        rows[1] = V::rotate::<VL, 12, 20>(V::xor(rows[1], rows[2]));
    }
}

/// Second half of the column (or diagonal) mix, rotating by 8 and 7.
#[inline(always)]
unsafe fn g2<V: Row, const VL: bool>(rows: &mut [V; 4], message: V) {
    // SAFETY: The caller establishes the row implementation's features.
    unsafe {
        rows[0] = V::add(V::add(rows[0], message), rows[1]);
        rows[3] = V::rotate::<VL, 8, 24>(V::xor(rows[3], rows[0]));
        rows[2] = V::add(rows[2], rows[3]);
        rows[1] = V::rotate::<VL, 7, 25>(V::xor(rows[1], rows[2]));
    }
}

/// Rotate rows so the diagonals line up as columns.
///
/// Row 1 stays fixed and the message words are arranged to compensate.
#[inline(always)]
unsafe fn diagonalize<V: Row>(rows: &mut [V; 4]) {
    // SAFETY: The caller establishes the row implementation's features.
    unsafe {
        rows[0] = V::shuffle::<{ order(2, 1, 0, 3) }>(rows[0]);
        rows[3] = V::shuffle::<{ order(1, 0, 3, 2) }>(rows[3]);
        rows[2] = V::shuffle::<{ order(0, 3, 2, 1) }>(rows[2]);
    }
}

/// Undo [`diagonalize`].
#[inline(always)]
unsafe fn undiagonalize<V: Row>(rows: &mut [V; 4]) {
    // SAFETY: The caller establishes the row implementation's features.
    unsafe {
        rows[0] = V::shuffle::<{ order(0, 3, 2, 1) }>(rows[0]);
        rows[3] = V::shuffle::<{ order(1, 0, 3, 2) }>(rows[3]);
        rows[2] = V::shuffle::<{ order(2, 1, 0, 3) }>(rows[2]);
    }
}

/// Compress one block of each message into its chaining value.
///
/// `cv` holds chaining value words 0-3 and 4-7, and `message` holds block
/// words 0-3, 4-7, 8-11, and 12-15, each with one message per 128-bit group.
///
/// The round schedule is ported from `compress_pre` in the blake3 crate's
/// `rust_sse41.rs`, with one message per 128-bit group. Its 16-bit blend masks
/// `0xCC` and `0xC0` are the 32-bit blend masks `0xA` and `0x8` of each group.
#[inline(always)]
pub(super) unsafe fn compress<V: Row, const VL: bool>(
    cv: &mut [V; 2],
    message: [V; 4],
    len: usize,
    flags: u32,
) {
    // SAFETY: The caller establishes the row implementation's features.
    unsafe {
        let mut rows = [
            cv[0],
            cv[1],
            V::from_words([IV[0], IV[1], IV[2], IV[3]]),
            V::from_words([0, 0, len as u32, flags]),
        ];
        let [mut m0, mut m1, mut m2, mut m3] = message;

        // The first round gathers the message words from their original order
        // into the groups mixed together.
        let t0 = V::shuffle2::<{ order(2, 0, 2, 0) }>(m0, m1);
        g1::<V, VL>(&mut rows, t0);
        let t1 = V::shuffle2::<{ order(3, 1, 3, 1) }>(m0, m1);
        g2::<V, VL>(&mut rows, t1);
        diagonalize(&mut rows);
        let t2 = V::shuffle2::<{ order(2, 0, 2, 0) }>(m2, m3);
        let t2 = V::shuffle::<{ order(2, 1, 0, 3) }>(t2);
        g1::<V, VL>(&mut rows, t2);
        let t3 = V::shuffle2::<{ order(3, 1, 3, 1) }>(m2, m3);
        let t3 = V::shuffle::<{ order(2, 1, 0, 3) }>(t3);
        g2::<V, VL>(&mut rows, t3);
        undiagonalize(&mut rows);
        (m0, m1, m2, m3) = (t0, t1, t2, t3);

        // Each later round applies the same permutation to the previous
        // round's message groups.
        for _ in 1..7 {
            let t0 = V::shuffle2::<{ order(3, 1, 1, 2) }>(m0, m1);
            let t0 = V::shuffle::<{ order(0, 3, 2, 1) }>(t0);
            g1::<V, VL>(&mut rows, t0);
            let t1 = V::shuffle2::<{ order(3, 3, 2, 2) }>(m2, m3);
            let tt = V::shuffle::<{ order(0, 0, 3, 3) }>(m0);
            let t1 = V::blend::<0xAA>(tt, t1);
            g2::<V, VL>(&mut rows, t1);
            diagonalize(&mut rows);
            let t2 = V::unpacklo64(m3, m1);
            let tt = V::blend::<0x88>(t2, m2);
            let t2 = V::shuffle::<{ order(1, 3, 2, 0) }>(tt);
            g1::<V, VL>(&mut rows, t2);
            let t3 = V::unpackhi32(m1, m3);
            let tt = V::unpacklo32(m2, t3);
            let t3 = V::shuffle::<{ order(0, 1, 3, 2) }>(tt);
            g2::<V, VL>(&mut rows, t3);
            undiagonalize(&mut rows);
            (m0, m1, m2, m3) = (t0, t1, t2, t3);
        }

        cv[0] = V::xor(rows[0], rows[2]);
        cv[1] = V::xor(rows[1], rows[3]);
    }
}
