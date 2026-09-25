//! AVX2 words: eight messages per 256-bit vector.

use crate::blake3::simd::Words;
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::x86_64::*;

/// Messages per AVX2 vector.
const LANES: usize = 8;

/// Minimum active lanes for the batch kernel.
pub(super) const MINIMUM: usize = 2;

/// Rotate each 32-bit lane right by `R` bits (`L` must be `32 - R`).
#[inline(always)]
unsafe fn rotate<const R: i32, const L: i32>(x: __m256i) -> __m256i {
    // SAFETY: The caller establishes AVX2.
    unsafe { _mm256_or_si256(_mm256_srli_epi32::<R>(x), _mm256_slli_epi32::<L>(x)) }
}

/// Transpose an 8x8 matrix of words held as eight row vectors.
#[inline(always)]
unsafe fn transpose(rows: [__m256i; LANES]) -> [__m256i; LANES] {
    // SAFETY: The caller establishes AVX2.
    unsafe {
        // Interleave 32-bit lanes: the low unpack holds columns 0/1/4/5 and
        // the high unpack columns 2/3/6/7.
        let ab_0145 = _mm256_unpacklo_epi32(rows[0], rows[1]);
        let ab_2367 = _mm256_unpackhi_epi32(rows[0], rows[1]);
        let cd_0145 = _mm256_unpacklo_epi32(rows[2], rows[3]);
        let cd_2367 = _mm256_unpackhi_epi32(rows[2], rows[3]);
        let ef_0145 = _mm256_unpacklo_epi32(rows[4], rows[5]);
        let ef_2367 = _mm256_unpackhi_epi32(rows[4], rows[5]);
        let gh_0145 = _mm256_unpacklo_epi32(rows[6], rows[7]);
        let gh_2367 = _mm256_unpackhi_epi32(rows[6], rows[7]);

        // Interleave 64-bit lanes: each 128-bit half now holds one column of
        // four rows.
        let abcd_04 = _mm256_unpacklo_epi64(ab_0145, cd_0145);
        let abcd_15 = _mm256_unpackhi_epi64(ab_0145, cd_0145);
        let abcd_26 = _mm256_unpacklo_epi64(ab_2367, cd_2367);
        let abcd_37 = _mm256_unpackhi_epi64(ab_2367, cd_2367);
        let efgh_04 = _mm256_unpacklo_epi64(ef_0145, gh_0145);
        let efgh_15 = _mm256_unpackhi_epi64(ef_0145, gh_0145);
        let efgh_26 = _mm256_unpacklo_epi64(ef_2367, gh_2367);
        let efgh_37 = _mm256_unpackhi_epi64(ef_2367, gh_2367);

        // Interleave 128-bit halves.
        [
            _mm256_permute2x128_si256::<0x20>(abcd_04, efgh_04),
            _mm256_permute2x128_si256::<0x20>(abcd_15, efgh_15),
            _mm256_permute2x128_si256::<0x20>(abcd_26, efgh_26),
            _mm256_permute2x128_si256::<0x20>(abcd_37, efgh_37),
            _mm256_permute2x128_si256::<0x31>(abcd_04, efgh_04),
            _mm256_permute2x128_si256::<0x31>(abcd_15, efgh_15),
            _mm256_permute2x128_si256::<0x31>(abcd_26, efgh_26),
            _mm256_permute2x128_si256::<0x31>(abcd_37, efgh_37),
        ]
    }
}

impl Words<LANES> for __m256i {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes AVX2.
        unsafe { _mm256_set1_epi32(word as i32) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        // SAFETY: The caller establishes AVX2.
        unsafe { _mm256_add_epi32(self, other) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        // SAFETY: The caller establishes AVX2.
        unsafe { _mm256_xor_si256(self, other) }
    }

    #[inline(always)]
    unsafe fn rotate16(self) -> Self {
        // SAFETY: The caller establishes AVX2.
        unsafe { rotate::<16, 16>(self) }
    }

    #[inline(always)]
    unsafe fn rotate12(self) -> Self {
        // SAFETY: The caller establishes AVX2.
        unsafe { rotate::<12, 20>(self) }
    }

    #[inline(always)]
    unsafe fn rotate8(self) -> Self {
        // SAFETY: The caller establishes AVX2.
        unsafe { rotate::<8, 24>(self) }
    }

    #[inline(always)]
    unsafe fn rotate7(self) -> Self {
        // SAFETY: The caller establishes AVX2.
        unsafe { rotate::<7, 25>(self) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16] {
        // SAFETY: The caller establishes AVX2, and each unaligned 32-byte load
        // starts at offset 0 or 32 of a 64-byte block.
        unsafe {
            let mut low = [_mm256_setzero_si256(); LANES];
            let mut high = [_mm256_setzero_si256(); LANES];
            for ((low, high), block) in low.iter_mut().zip(high.iter_mut()).zip(blocks) {
                *low = _mm256_loadu_si256(block.as_ptr().cast());
                *high = _mm256_loadu_si256(block[32..].as_ptr().cast());
            }
            let low = transpose(low);
            let high = transpose(high);
            [
                low[0], low[1], low[2], low[3], low[4], low[5], low[6], low[7], high[0], high[1],
                high[2], high[3], high[4], high[5], high[6], high[7],
            ]
        }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES] {
        // SAFETY: The caller establishes AVX2, and each unaligned 32-byte
        // store fills one 32-byte output.
        unsafe {
            let mut outputs = [[0u8; OUT_LEN]; LANES];
            for (output, lane) in outputs.iter_mut().zip(transpose(words)) {
                _mm256_storeu_si256(output.as_mut_ptr().cast(), lane);
            }
            outputs
        }
    }
}

/// Hash eight equal-length messages, one per AVX2 lane.
///
/// # Safety
///
/// The caller must establish AVX2 availability.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn hash_x8(inputs: [&[u8]; LANES]) -> [[u8; OUT_LEN]; LANES] {
    // SAFETY: AVX2 is enabled for this function.
    unsafe { crate::blake3::simd::hash::<__m256i, LANES>(inputs) }
}
