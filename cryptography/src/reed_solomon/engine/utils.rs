//! A collection of utility functions and helpers to facilitate the implementation of the [`Engine`] trait.
//!
//! [`Engine`]: crate::reed_solomon::engine::Engine

use crate::reed_solomon::engine::{
    Engine, GF_BITS, GF_ORDER, GfElement, SHARD_CHUNK_BYTES, ShardsRefMut, fwht, tables,
};
#[cfg(target_arch = "x86")]
use core::arch::x86::{_mm512_loadu_si512, _mm512_storeu_si512, _mm512_xor_si512};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{_mm512_loadu_si512, _mm512_storeu_si512, _mm512_xor_si512};
use core::iter::zip;

// ======================================================================
// FUNCTIONS - PUBLIC

/// Evaluate Polynomial using Fast Walsh-Hadamard Transform (FWHT).
///
/// This function is designed to be inlined and be compiled with SIMD
/// features enabled within an Engine's implementation of `eval_poly`.
///
/// See `Avx2` for an example on how to do this.
///
/// Entries at and after `truncated_size` must be zero.
///
/// # Panics
///
/// If `truncated_size > GF_ORDER`.
#[inline(always)]
pub fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
    assert!(truncated_size <= GF_ORDER);
    let log_walsh = tables::get_log_walsh();

    fwht::fwht(erasures, truncated_size);

    for (e, factor) in zip(erasures.iter_mut(), log_walsh.iter()) {
        let product = u32::from(*e) * u32::from(*factor);
        *e = add_mod(product as GfElement, (product >> GF_BITS) as GfElement);
    }

    fwht::fwht(erasures, GF_ORDER);
}

/// Evaluate an XOR locator on a shorter power-of-two coordinate domain.
/// Entries in `data[nonzero..n]` must be zero; entries at and after `n` are untouched.
pub(crate) fn eval_poly_short(data: &mut [GfElement; GF_ORDER], nonzero: usize, n: usize) {
    assert!(n.is_power_of_two() && n < GF_ORDER && nonzero <= n);
    let kernel = tables::get_short_log_walsh(n);
    let values = &mut data[..n];
    fwht::fwht(values, nonzero);
    for (value, factor) in zip(values.iter_mut(), kernel) {
        let product = u32::from(*value) * u32::from(*factor);
        *value = add_mod(product as GfElement, (product >> GF_BITS) as GfElement);
    }
    fwht::fwht(values, n);
}

/// `x[] ^= y[]`
#[inline(always)]
pub fn xor(xs: &mut [[u8; SHARD_CHUNK_BYTES]], ys: &[[u8; SHARD_CHUNK_BYTES]]) {
    assert_eq!(xs.len(), ys.len());

    for (x_chunk, y_chunk) in zip(xs.iter_mut(), ys.iter()) {
        for (x, y) in zip(x_chunk.iter_mut(), y_chunk.iter()) {
            *x ^= y;
        }
    }
}

/// `data[x .. x + count] ^= data[y .. y + count]`
///
/// Ranges must not overlap.
#[inline(always)]
pub fn xor_within(data: &mut ShardsRefMut<'_>, x: usize, y: usize, count: usize) {
    let (xs, ys) = data.flat2_mut(x, y, count);
    xor(xs, ys);
}

// ======================================================================
// FUNCTIONS - CRATE - Galois field operations

/// Addition modulo 65535, allowing both 0 and 65535 to represent zero.
#[inline(always)]
pub(crate) fn add_mod(x: GfElement, y: GfElement) -> GfElement {
    let sum = u32::from(x) + u32::from(y);
    (sum + (sum >> GF_BITS)) as GfElement
}

/// Subtraction modulo 65535, allowing both 0 and 65535 to represent zero.
#[inline(always)]
pub(crate) fn sub_mod(x: GfElement, y: GfElement) -> GfElement {
    let dif = u32::from(x).wrapping_sub(u32::from(y));
    dif.wrapping_add(dif >> GF_BITS) as GfElement
}

// ======================================================================
// FUNCTIONS - CRATE

/// FFT with `skew_delta = pos + size`.
#[inline(always)]
pub(crate) fn fft_skew_end(
    engine: &impl Engine,
    data: &mut ShardsRefMut<'_>,
    pos: usize,
    size: usize,
    truncated_size: usize,
) {
    engine.fft(data, pos, size, truncated_size, pos + size);
}

/// IFFT with `skew_delta = pos + size`.
#[inline(always)]
pub(crate) fn ifft_skew_end(
    engine: &impl Engine,
    data: &mut ShardsRefMut<'_>,
    pos: usize,
    size: usize,
    truncated_size: usize,
) {
    engine.ifft(data, pos, size, truncated_size, pos + size);
}

// Formal derivative.
pub(crate) fn formal_derivative(data: &mut ShardsRefMut<'_>) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let fused16_end = if data.len() >= 16
        && data[0].len() >= 512 / SHARD_CHUNK_BYTES
        // Shard strides aligned to a 4 KiB page favor the four-way leaf.
        && !data[0].len().is_multiple_of(4096 / SHARD_CHUNK_BYTES)
        && super::cpu_features::avx512()
    {
        data.len() / 16 * 16
    } else {
        0
    };
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let fused16_end = 0;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    for base in (0..fused16_end).step_by(16) {
        // Read this block for the preceding larger pass before applying its
        // local leaf passes.
        if base != 0 {
            let width = 1 << base.trailing_zeros();
            let count = width.min(data.len() - base);
            xor_within(data, base - width, base, count);
        }
        // SAFETY: The runtime guard verifies AVX-512F and each iteration
        // contains 16 complete, disjoint shards of 64-byte chunks.
        unsafe { formal_derivative_16_avx512(data, base) };
    }

    let fused_end = data.len() / 4 * 4;
    for base in (fused16_end..fused_end).step_by(4) {
        // This pass reads the next four shards before their leaf passes.
        if base != 0 {
            let width = 1 << base.trailing_zeros();
            let count = width.min(data.len() - base);
            xor_within(data, base - width, base, count);
        }

        let (a, b, c, d) = data.dist4_mut(base, 1);
        for (((a, b), c), d) in a.iter_mut().zip(b).zip(c).zip(d) {
            for j in 0..SHARD_CHUNK_BYTES {
                let bj = b[j];
                let cj = c[j];
                let dj = d[j];
                a[j] ^= bj ^ cj;
                b[j] = bj ^ dj;
                c[j] = cj ^ dj;
            }
        }
    }

    for i in fused_end.max(1)..data.len() {
        let width: usize = 1 << i.trailing_zeros();
        let count = width.min(data.len() - i);
        xor_within(data, i - width, i, count);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx512f")]
unsafe fn formal_derivative_16_avx512(data: &mut ShardsRefMut<'_>, base: usize) {
    let (_, mut suffix) = data.split_at_mut(base);
    let (mut block, _) = suffix.split_at_mut(16);
    // The ascending original passes give each output its own fixed source
    // map; all 16 inputs must be loaded before the first store.
    for chunk in 0..block[0].len() {
        // SAFETY: The runtime guard checks AVX-512F. The two checked splits
        // bound 16 distinct shard slices and each indexed chunk is 64 bytes.
        // Unaligned loads/stores accept their alignment.
        unsafe {
            macro_rules! vxor {
                ($first:ident, $second:ident $(, $next:ident)*) => {{
                    let value = _mm512_xor_si512($first, $second);
                    $(let value = _mm512_xor_si512(value, $next);)*
                    value
                }};
            }
            let s0 = _mm512_loadu_si512(block[0][chunk].as_ptr().cast());
            let s1 = _mm512_loadu_si512(block[1][chunk].as_ptr().cast());
            let s2 = _mm512_loadu_si512(block[2][chunk].as_ptr().cast());
            let s3 = _mm512_loadu_si512(block[3][chunk].as_ptr().cast());
            let s4 = _mm512_loadu_si512(block[4][chunk].as_ptr().cast());
            let s5 = _mm512_loadu_si512(block[5][chunk].as_ptr().cast());
            let s6 = _mm512_loadu_si512(block[6][chunk].as_ptr().cast());
            let s7 = _mm512_loadu_si512(block[7][chunk].as_ptr().cast());
            let s8 = _mm512_loadu_si512(block[8][chunk].as_ptr().cast());
            let s9 = _mm512_loadu_si512(block[9][chunk].as_ptr().cast());
            let s10 = _mm512_loadu_si512(block[10][chunk].as_ptr().cast());
            let s11 = _mm512_loadu_si512(block[11][chunk].as_ptr().cast());
            let s12 = _mm512_loadu_si512(block[12][chunk].as_ptr().cast());
            let s13 = _mm512_loadu_si512(block[13][chunk].as_ptr().cast());
            let s14 = _mm512_loadu_si512(block[14][chunk].as_ptr().cast());
            let s15 = _mm512_loadu_si512(block[15][chunk].as_ptr().cast());

            _mm512_storeu_si512(
                block[0][chunk].as_mut_ptr().cast(),
                vxor!(s0, s1, s2, s4, s8),
            );
            _mm512_storeu_si512(block[1][chunk].as_mut_ptr().cast(), vxor!(s1, s3, s5, s9));
            _mm512_storeu_si512(block[2][chunk].as_mut_ptr().cast(), vxor!(s2, s3, s6, s10));
            _mm512_storeu_si512(block[3][chunk].as_mut_ptr().cast(), vxor!(s3, s7, s11));
            _mm512_storeu_si512(block[4][chunk].as_mut_ptr().cast(), vxor!(s4, s5, s6, s12));
            _mm512_storeu_si512(block[5][chunk].as_mut_ptr().cast(), vxor!(s5, s7, s13));
            _mm512_storeu_si512(block[6][chunk].as_mut_ptr().cast(), vxor!(s6, s7, s14));
            _mm512_storeu_si512(block[7][chunk].as_mut_ptr().cast(), vxor!(s7, s15));
            _mm512_storeu_si512(block[8][chunk].as_mut_ptr().cast(), vxor!(s8, s9, s10, s12));
            _mm512_storeu_si512(block[9][chunk].as_mut_ptr().cast(), vxor!(s9, s11, s13));
            _mm512_storeu_si512(block[10][chunk].as_mut_ptr().cast(), vxor!(s10, s11, s14));
            _mm512_storeu_si512(block[11][chunk].as_mut_ptr().cast(), vxor!(s11, s15));
            _mm512_storeu_si512(block[12][chunk].as_mut_ptr().cast(), vxor!(s12, s13, s14));
            _mm512_storeu_si512(block[13][chunk].as_mut_ptr().cast(), vxor!(s13, s15));
            _mm512_storeu_si512(block[14][chunk].as_mut_ptr().cast(), vxor!(s14, s15));
        }
    }
}
