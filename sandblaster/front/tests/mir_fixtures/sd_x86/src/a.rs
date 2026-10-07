//! SSSE3 table lookups (PSHUFB): the x86 counterpart of `sd_neon`, read onto
//! the x86 models (extracted for `x86_64-apple-darwin`).
use core::arch::x86_64::*;

/// Each byte `k` of `idx` looked up in `table`: `table[k & 15]`, or 0 when
/// bit 7 of `k` is set.
#[target_feature(enable = "ssse3")]
pub fn lookup(table: __m128i, idx: __m128i) -> __m128i {
    _mm_shuffle_epi8(table, idx)
}

/// The bytes of `x` with their low and high nibbles split beforehand
/// (`lo_n`, `hi_n`) through the nibble tables: `lo[lo_n] ^ hi[hi_n]`.
#[target_feature(enable = "ssse3")]
pub fn mul_split(lo_n: __m128i, hi_n: __m128i, lo: __m128i, hi: __m128i) -> __m128i {
    _mm_xor_si128(_mm_shuffle_epi8(lo, lo_n), _mm_shuffle_epi8(hi, hi_n))
}

/// The lookup of the low nibbles of `idx` (masked with `mask`).
#[target_feature(enable = "ssse3")]
pub fn lookup_masked(table: __m128i, idx: __m128i, mask: __m128i) -> __m128i {
    _mm_shuffle_epi8(table, _mm_and_si128(idx, mask))
}
