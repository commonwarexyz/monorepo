//! SSE implementations of the fixed four-word instructions shared by x86-64 tokens.
//!
//! Every x86-64 token's construction check implies SSE4.1 and the earlier SSE levels,
//! so a token may call these entries after its construction succeeded.

use core::arch::x86_64::*;

#[inline]
#[target_feature(enable = "sse2")]
pub(super) unsafe fn load(input: &[u32]) -> __m128i {
    assert!(input.len() >= 4);
    // SAFETY: This entry enables the required feature. Slice bounds above establish
    // the readable or writable extent for unaligned memory operations.
    unsafe { _mm_loadu_si128(input.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "sse2")]
pub(super) unsafe fn store(value: __m128i, output: &mut [u32]) {
    assert!(output.len() >= 4);
    // SAFETY: This entry enables the required feature. Slice bounds above establish
    // the readable or writable extent for unaligned memory operations.
    unsafe { _mm_storeu_si128(output.as_mut_ptr().cast(), value) }
}

#[inline]
#[target_feature(enable = "sse2")]
pub(super) unsafe fn add(a: __m128i, b: __m128i) -> __m128i {
    _mm_add_epi32(a, b)
}

#[inline]
#[target_feature(enable = "sse2")]
pub(super) unsafe fn shuffle<const MASK: i32>(value: __m128i) -> __m128i {
    assert!((0..256).contains(&MASK));
    _mm_shuffle_epi32::<MASK>(value)
}

#[inline]
#[target_feature(enable = "ssse3")]
unsafe fn byte_swap_words(value: __m128i) -> __m128i {
    _mm_shuffle_epi8(
        value,
        _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203),
    )
}

#[inline]
#[target_feature(enable = "ssse3")]
pub(super) unsafe fn load_be(input: &[u8]) -> __m128i {
    assert!(input.len() >= 16);
    // SAFETY: This entry enables the required feature. Slice bounds above establish
    // the readable or writable extent for unaligned memory operations.
    unsafe { byte_swap_words(_mm_loadu_si128(input.as_ptr().cast())) }
}

#[inline]
#[target_feature(enable = "ssse3")]
pub(super) unsafe fn load_be2(input: &[u8]) -> __m128i {
    assert!(input.len() >= 8);
    // SAFETY: This entry enables the required feature. Slice bounds above establish
    // the readable or writable extent for unaligned memory operations.
    unsafe { byte_swap_words(_mm_loadl_epi64(input.as_ptr().cast())) }
}

#[inline]
#[target_feature(enable = "ssse3")]
pub(super) unsafe fn store_be(value: __m128i, output: &mut [u8]) {
    assert!(output.len() >= 16);
    // SAFETY: This entry enables the required feature. Slice bounds above establish
    // the readable or writable extent for unaligned memory operations.
    unsafe { _mm_storeu_si128(output.as_mut_ptr().cast(), byte_swap_words(value)) }
}

#[inline]
#[target_feature(enable = "ssse3")]
pub(super) unsafe fn align<const N: i32>(a: __m128i, b: __m128i) -> __m128i {
    assert!((0..=4).contains(&N));
    match N {
        0 => a,
        1 => _mm_alignr_epi8::<4>(b, a),
        2 => _mm_alignr_epi8::<8>(b, a),
        3 => _mm_alignr_epi8::<12>(b, a),
        4 => b,
        _ => unreachable!(),
    }
}

#[inline]
#[target_feature(enable = "sse4.1")]
pub(super) unsafe fn blend<const MASK: i32>(a: __m128i, b: __m128i) -> __m128i {
    assert!((0..16).contains(&MASK));
    _mm_blendv_epi8(
        a,
        b,
        _mm_set_epi32(
            if MASK & 8 != 0 { -1 } else { 0 },
            if MASK & 4 != 0 { -1 } else { 0 },
            if MASK & 2 != 0 { -1 } else { 0 },
            if MASK & 1 != 0 { -1 } else { 0 },
        ),
    )
}
