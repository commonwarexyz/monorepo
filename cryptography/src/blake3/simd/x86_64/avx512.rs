//! AVX-512 words: sixteen messages per 512-bit vector.

use crate::blake3::simd::Words;
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::x86_64::*;

/// Messages per AVX-512 vector.
const LANES: usize = 16;

/// Minimum active lanes for the batch kernel.
pub(super) const MINIMUM: usize = 2;

/// Interleave 32-bit and then 64-bit elements of four row vectors.
///
/// Output `s` holds, in 128-bit block `k`, column `4k + s` of the four rows.
#[inline(always)]
unsafe fn interleave(rows: [__m512i; 4]) -> [__m512i; 4] {
    // SAFETY: The caller establishes AVX-512F.
    unsafe {
        let ab_low = _mm512_unpacklo_epi32(rows[0], rows[1]);
        let ab_high = _mm512_unpackhi_epi32(rows[0], rows[1]);
        let cd_low = _mm512_unpacklo_epi32(rows[2], rows[3]);
        let cd_high = _mm512_unpackhi_epi32(rows[2], rows[3]);
        [
            _mm512_unpacklo_epi64(ab_low, cd_low),
            _mm512_unpackhi_epi64(ab_low, cd_low),
            _mm512_unpacklo_epi64(ab_high, cd_high),
            _mm512_unpackhi_epi64(ab_high, cd_high),
        ]
    }
}

impl Words<LANES> for __m512i {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes AVX-512F.
        unsafe { _mm512_set1_epi32(word as i32) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        // SAFETY: The caller establishes AVX-512F.
        unsafe { _mm512_add_epi32(self, other) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        // SAFETY: The caller establishes AVX-512F.
        unsafe { _mm512_xor_si512(self, other) }
    }

    #[inline(always)]
    unsafe fn rotate16(self) -> Self {
        // SAFETY: The caller establishes AVX-512F.
        unsafe { _mm512_ror_epi32::<16>(self) }
    }

    #[inline(always)]
    unsafe fn rotate12(self) -> Self {
        // SAFETY: The caller establishes AVX-512F.
        unsafe { _mm512_ror_epi32::<12>(self) }
    }

    #[inline(always)]
    unsafe fn rotate8(self) -> Self {
        // SAFETY: The caller establishes AVX-512F.
        unsafe { _mm512_ror_epi32::<8>(self) }
    }

    #[inline(always)]
    unsafe fn rotate7(self) -> Self {
        // SAFETY: The caller establishes AVX-512F.
        unsafe { _mm512_ror_epi32::<7>(self) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16] {
        // SAFETY: The caller establishes AVX-512F, and each unaligned 64-byte
        // load reads one whole block.
        unsafe {
            let mut rows = [_mm512_setzero_si512(); LANES];
            for (row, block) in rows.iter_mut().zip(blocks) {
                *row = _mm512_loadu_si512(block.as_ptr().cast());
            }

            // Group `g` interleaves lanes `4g..4g + 4`: output `s` holds, in
            // 128-bit block `k`, word `4k + s` of those lanes.
            let g0 = interleave([rows[0], rows[1], rows[2], rows[3]]);
            let g1 = interleave([rows[4], rows[5], rows[6], rows[7]]);
            let g2 = interleave([rows[8], rows[9], rows[10], rows[11]]);
            let g3 = interleave([rows[12], rows[13], rows[14], rows[15]]);

            // Gather block `k` of every group into word `4k + s`.
            let mut words = [_mm512_setzero_si512(); 16];
            for s in 0..4 {
                let low01 = _mm512_shuffle_i32x4::<0x44>(g0[s], g1[s]);
                let high01 = _mm512_shuffle_i32x4::<0xEE>(g0[s], g1[s]);
                let low23 = _mm512_shuffle_i32x4::<0x44>(g2[s], g3[s]);
                let high23 = _mm512_shuffle_i32x4::<0xEE>(g2[s], g3[s]);
                words[s] = _mm512_shuffle_i32x4::<0x88>(low01, low23);
                words[s + 4] = _mm512_shuffle_i32x4::<0xDD>(low01, low23);
                words[s + 8] = _mm512_shuffle_i32x4::<0x88>(high01, high23);
                words[s + 12] = _mm512_shuffle_i32x4::<0xDD>(high01, high23);
            }
            words
        }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES] {
        // SAFETY: The caller establishes AVX-512F, and each unaligned 32-byte
        // store fills one 32-byte output.
        unsafe {
            // Output `t` holds, in 128-bit block `k`, words 0-3 (`low`) or
            // words 4-7 (`high`) of lane `4k + t`.
            let low = interleave([words[0], words[1], words[2], words[3]]);
            let high = interleave([words[4], words[5], words[6], words[7]]);

            let mut outputs = [[0u8; OUT_LEN]; LANES];
            for t in 0..4 {
                // Pair each lane's two halves: blocks 0/1 of `front` are lane
                // `t`, blocks 2/3 are lane `4 + t` (and lanes `8 + t`, `12 + t`
                // for `back`).
                let front = _mm512_shuffle_i32x4::<0x44>(low[t], high[t]);
                let front = _mm512_shuffle_i32x4::<0xD8>(front, front);
                let back = _mm512_shuffle_i32x4::<0xEE>(low[t], high[t]);
                let back = _mm512_shuffle_i32x4::<0xD8>(back, back);
                for (k, half) in [
                    _mm512_castsi512_si256(front),
                    _mm512_extracti64x4_epi64::<1>(front),
                    _mm512_castsi512_si256(back),
                    _mm512_extracti64x4_epi64::<1>(back),
                ]
                .into_iter()
                .enumerate()
                {
                    _mm256_storeu_si256(outputs[4 * k + t].as_mut_ptr().cast(), half);
                }
            }
            outputs
        }
    }
}

/// Hash sixteen equal-length messages, one per AVX-512 lane.
///
/// # Safety
///
/// The caller must establish AVX-512F availability.
#[target_feature(enable = "avx512f")]
pub(super) unsafe fn hash_x16(inputs: [&[u8]; LANES]) -> [[u8; OUT_LEN]; LANES] {
    // SAFETY: AVX-512F is enabled for this function.
    unsafe { crate::blake3::simd::hash::<__m512i, LANES>(inputs) }
}
