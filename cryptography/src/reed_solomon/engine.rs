//! Low-level building blocks for Reed-Solomon encoding/decoding.
//!
//! See [basic usage] for encoding and decoding with automatic engine selection.
//!
//! This module is relevant if you want to
//! - use [`rate`] module and need an [`Engine`] to use with it.
//! - create your own [`Engine`].
//! - understand/benchmark/test at low level.
//!
//! # Engines
//!
//! An [`Engine`] is an implementation of basic low-level algorithms
//! needed for Reed-Solomon encoding/decoding.
//!
//! - [`Naive`]
//!     - Simple reference implementation.
//! - [`NoSimd`]
//!     - Basic optimized engine without SIMD so that it works on all CPUs.
//! - `Avx2`
//!     - Optimized engine that takes advantage of the x86(-64) AVX2 SIMD instructions.
//! - `Ssse3`
//!     - Optimized engine that takes advantage of the x86(-64) SSSE3 SIMD instructions.
//! - `Neon`
//!     - Optimized engine that takes advantage of the `AArch64` Neon SIMD instructions.
//! - [`DefaultEngine`]
//!     - Default engine which is used when no specific engine is given.
//!     - Automatically selects best engine at runtime.
//!
//! [basic usage]: crate::reed_solomon#basic-usage
//! [`Encoder`]: crate::reed_solomon::Encoder
//! [`Decoder`]: crate::reed_solomon::Decoder
//! [`rate`]: crate::reed_solomon::rate

// TODO(https://github.com/commonwarexyz/monorepo/issues/4414): Bump cpufeatures and remove this workaround.
#[allow(
    unfulfilled_lint_expectations,
    reason = "stable Rust does not emit this nightly-only deprecation"
)]
#[expect(
    deprecated,
    reason = "tracked by https://github.com/commonwarexyz/monorepo/issues/4414"
)]
mod cpu_features {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    cpufeatures::new!(has_avx2, "avx2");
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    cpufeatures::new!(has_ssse3, "ssse3");
    #[cfg(target_arch = "aarch64")]
    cpufeatures::new!(has_neon, "neon");

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub(super) use self::{has_avx2::get as avx2, has_ssse3::get as ssse3};
    #[cfg(target_arch = "aarch64")]
    pub(super) use has_neon::get as neon;
}

#[cfg(target_arch = "aarch64")]
pub use self::engine_neon::Neon;
pub(crate) use self::shards::Shards;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::{engine_avx2::Avx2, engine_ssse3::Ssse3};
pub use self::{
    engine_default::DefaultEngine, engine_naive::Naive, engine_nosimd::NoSimd, shards::ShardsRefMut,
};
pub(crate) use utils::{fft_skew_end, formal_derivative, ifft_skew_end, xor_within};

mod engine_default;
mod engine_naive;
mod engine_nosimd;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod engine_avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod engine_ssse3;

#[cfg(target_arch = "aarch64")]
mod engine_neon;

mod fwht;
mod shards;

pub mod tables;
pub mod utils;

// ======================================================================
// CONST - PUBLIC

/// Size of Galois field element [`GfElement`] in bits.
pub const GF_BITS: usize = 16;

/// Galois field order, i.e. number of elements.
pub const GF_ORDER: usize = 65536;

/// `GF_ORDER - 1`
pub const GF_MODULUS: GfElement = 65535;

/// Galois field polynomial.
pub const GF_POLYNOMIAL: usize = 0x1002D;

/// Byte width of a shard chunk.
///
/// [`Engine`] methods process shard buffers as arrays of this size.
/// Input shards may span multiple chunks; any partial final chunk is padded
/// during processing and returned at the original shard length.
pub const SHARD_CHUNK_BYTES: usize = 64;

/// Cantor basis used by the additive FFT over GF(2^16).
pub const CANTOR_BASIS: [GfElement; GF_BITS] = [
    0x0001, 0xACCA, 0x3C0E, 0x163E, 0xC582, 0xED2E, 0x914C, 0x4012, 0x6C98, 0x10D8, 0x6A72, 0xB900,
    0xFDB8, 0xFB34, 0xFF38, 0x991E,
];

// ======================================================================
// TYPE ALIASES - PUBLIC

/// Galois field element expressed in the [`CANTOR_BASIS`].
pub type GfElement = u16;

// ======================================================================
// Engine - PUBLIC

/// Trait for compute-intensive low-level algorithms needed
/// for Reed-Solomon encoding/decoding.
///
/// This is the trait you would implement to provide SIMD support
/// for a CPU architecture not already provided.
///
/// [`Naive`] engine is provided for those who want to
/// study the source code to understand [`Engine`].
pub trait Engine {
    // ============================================================
    // REQUIRED

    /// In-place decimation-in-time FFT (fast Fourier transform).
    ///
    /// Transforms `data[pos..pos + size]`, producing the requested output prefix in
    /// `data[pos..pos + truncated_size]`. The remaining shards in the transform block have
    /// unspecified values. Shards outside the block are unchanged.
    ///
    /// A transform of size one is the identity and ignores `skew_delta`.
    ///
    /// # Panics
    ///
    /// If `size` is not a power of two in `1..=GF_ORDER`, `truncated_size > size`, or the
    /// transform block is outside `data`. For `size > 1`, also panics if
    /// `skew_delta > GF_ORDER - size`.
    fn fft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    );

    /// In-place decimation-in-time IFFT (inverse fast Fourier transform).
    ///
    /// Transforms `data[pos..pos + size]`. Input shards in
    /// `data[pos + truncated_size..pos + size]` must be zero. The full transform block then
    /// contains the inverse result. Shards outside the block are unchanged.
    ///
    /// A transform of size one is the identity and ignores `skew_delta`.
    ///
    /// # Panics
    ///
    /// If the size, range, or skew requirements of [`Engine::fft`] are not met.
    fn ifft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    );

    /// Multiply every field element in `x` by the field element with logarithm `log_m`.
    ///
    /// Each chunk stores 32 low bytes followed by their 32 high bytes.
    /// Exponents `0` and [`GF_MODULUS`] both represent the multiplicative identity.
    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement);

    // ============================================================
    // PROVIDED

    /// Evaluate a polynomial whose entries at and after `truncated_size` are zero.
    ///
    /// # Panics
    ///
    /// If `truncated_size > GF_ORDER`.
    fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize)
    where
        Self: Sized,
    {
        utils::eval_poly(erasures, truncated_size);
    }
}

#[inline]
fn validate_transform(
    data: &ShardsRefMut<'_>,
    pos: usize,
    size: usize,
    truncated_size: usize,
    skew_delta: usize,
) {
    assert!(size.is_power_of_two() && size <= GF_ORDER);
    assert!(truncated_size <= size);
    assert!(pos <= data.len() && size <= data.len() - pos);
    assert!(size == 1 || skew_delta <= GF_ORDER - size);
}

// ======================================================================
// TESTS

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn invalid_transform(
        shard_count: usize,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        let engines: [&dyn Engine; 2] = [&NoSimd::new(), &Naive::new()];
        for engine in engines {
            for inverse in [false, true] {
                let mut shards = ShardsRefMut::new(shard_count, 0, &mut []);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    if inverse {
                        engine.ifft(&mut shards, pos, size, truncated_size, skew_delta);
                    } else {
                        engine.fft(&mut shards, pos, size, truncated_size, skew_delta);
                    }
                }));
                assert!(
                    result.is_err(),
                    "invalid transform accepted (inverse={inverse})"
                );
            }
        }
    }

    #[test]
    fn transform_zero_size() {
        invalid_transform(4, 0, 0, 0, 0);
    }

    #[test]
    fn transform_non_power_of_two_size() {
        invalid_transform(4, 0, 3, 0, 0);
    }

    #[test]
    fn transform_size_exceeds_field() {
        invalid_transform(GF_ORDER * 2, 0, GF_ORDER * 2, 0, 0);
    }

    #[test]
    fn transform_range_out_of_bounds() {
        for pos in [3, 4, usize::MAX] {
            invalid_transform(4, pos, 2, 0, 0);
        }
    }

    #[test]
    fn transform_truncation_out_of_bounds() {
        invalid_transform(4, 0, 2, 3, 0);
    }

    #[test]
    fn transform_skew_out_of_bounds() {
        for skew_delta in [GF_ORDER - 1, usize::MAX] {
            invalid_transform(4, 0, 2, 0, skew_delta);
        }
    }

    #[test]
    fn transform_empty_shards_and_identity() {
        let engines: [&dyn Engine; 2] = [&NoSimd::new(), &Naive::new()];
        for engine in engines {
            let mut empty = ShardsRefMut::new(GF_ORDER + 3, 0, &mut []);
            engine.fft(&mut empty, 3, GF_ORDER, 0, 0);
            engine.ifft(&mut empty, 3, GF_ORDER, 0, 0);

            for truncated_size in [0, 1] {
                let mut data = [[17; SHARD_CHUNK_BYTES]; 3];
                let mut shards = ShardsRefMut::new(3, 1, &mut data);
                engine.fft(&mut shards, 1, 1, truncated_size, usize::MAX);
                engine.ifft(&mut shards, 1, 1, 1, usize::MAX);
                assert_eq!(data, [[17; SHARD_CHUNK_BYTES]; 3]);
            }
        }
    }

    #[test]
    fn eval_poly_feature_guard() {
        let mut input = Box::new([0; GF_ORDER]);
        input[..4].copy_from_slice(&[1, 0, 1, 1]);
        let mut expected = input.clone();
        NoSimd::eval_poly(&mut expected, 4);

        type Evaluate = fn(&mut [GfElement; GF_ORDER], usize);
        let evaluators: &[(Evaluate, bool)] = &[
            (DefaultEngine::eval_poly, true),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            (Avx2::eval_poly, cpu_features::avx2()),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            (Ssse3::eval_poly, cpu_features::ssse3()),
            #[cfg(target_arch = "aarch64")]
            (Neon::eval_poly, cpu_features::neon()),
        ];

        for (evaluate, supported) in evaluators {
            let mut actual = input.clone();
            if *supported {
                evaluate(&mut actual, 4);
                assert_eq!(actual, expected);
            } else {
                assert!(catch_unwind(AssertUnwindSafe(|| evaluate(&mut actual, 4))).is_err());
                assert_eq!(actual, input);
            }
        }
    }

    #[test]
    #[should_panic]
    fn eval_poly_truncation_out_of_bounds() {
        utils::eval_poly(&mut [0; GF_ORDER], GF_ORDER + 1);
    }
}
