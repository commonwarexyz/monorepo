//! A collection of utility functions and helpers to facilitate the implementation of the [`Engine`] trait.
//!
//! [`Engine`]: crate::reed_solomon::engine::Engine

use crate::reed_solomon::engine::{
    fwht, tables, Engine, GfElement, ShardsRefMut, GF_BITS, GF_ORDER, SHARD_CHUNK_BYTES,
};
use core::iter::zip;

// ======================================================================
// FUNCTIONS - PUBLIC

/// Evaluate Polynomial using Fast Walsh-Hadamard Transform (FWHT).
///
/// This function is designed to be inlined and be compiled with SIMD
/// features enabled within an Engine's implementation of `eval_poly`.
///
/// See `Avx2` for an example on how to do this.
#[inline(always)]
pub fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
    let log_walsh = tables::get_log_walsh();

    fwht::fwht(erasures, truncated_size);

    for (e, factor) in zip(erasures.iter_mut(), log_walsh.iter()) {
        let product = u32::from(*e) * u32::from(*factor);
        *e = add_mod(product as GfElement, (product >> GF_BITS) as GfElement);
    }

    fwht::fwht(erasures, GF_ORDER);
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

/// Some kind of addition.
#[inline(always)]
pub(crate) fn add_mod(x: GfElement, y: GfElement) -> GfElement {
    let sum = u32::from(x) + u32::from(y);
    (sum + (sum >> GF_BITS)) as GfElement
}

/// Some kind of subtraction.
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
    for i in 1..data.len() {
        let width: usize = 1 << i.trailing_zeros();
        xor_within(data, i - width, i, width);
    }
}
