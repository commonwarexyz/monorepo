//! An AVX-512F and GFNI kernel operating on 64 bytes at a time.

use super::{Kernel, WithKernel};
use core::arch::x86_64::{
    __m512i, __mmask16, _mm512_gf2p8mul_epi8, _mm512_loadu_si512, _mm512_mask_storeu_epi32,
    _mm512_maskz_loadu_epi32, _mm512_set1_epi64, _mm512_storeu_si512, _mm512_xor_si512,
};

/// An AVX-512F and GFNI [`Kernel`].
///
/// The private field ensures this can only be constructed after checking the
/// required CPU features with [`Self::new`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Avx512(());

impl Avx512 {
    /// Constructs the kernel if the required CPU features are available.
    pub(super) fn new() -> Option<Self> {
        available().then_some(Self(()))
    }

    /// Runs an entire computation with AVX-512F and GFNI enabled.
    ///
    /// Enabling the target features around the whole computation lets kernel
    /// operations inline without crossing a target-feature boundary for every
    /// operation.
    #[target_feature(enable = "avx512f,gfni")]
    pub(super) fn call<F: WithKernel>(self, f: F) -> F::Output {
        f.call(self)
    }
}

impl Default for Avx512 {
    fn default() -> Self {
        Self::new().expect("AVX-512 Ocelot kernel requires AVX-512F and GFNI CPU support")
    }
}

impl Kernel for Avx512 {
    type Vector = __m512i;
    const LANES: usize = 64;
    const PARTIAL_GRANULARITY: usize = 4;
    const FUSED_BUTTERFLY: bool = true;
    type Constant = __m512i;

    #[inline]
    fn run<F: WithKernel>(self, f: F) -> F::Output {
        // SAFETY: constructing `self` checked every feature enabled by `call`.
        unsafe { self.call(f) }
    }

    #[inline]
    fn splat(self, x: u8) -> Self::Constant {
        // SAFETY: `Avx512` can only be constructed when AVX-512F and GFNI are available.
        unsafe { splat(x) }
    }

    #[inline]
    fn load(self, bytes: &[u8]) -> Self::Vector {
        assert_eq!(bytes.len(), Self::LANES, "bytes.len() != LANES");
        // SAFETY: `Avx512` proves AVX-512F is available, and the length check above proves
        // `bytes` contains exactly one full vector. The unaligned load imposes no alignment
        // requirement.
        unsafe { load(bytes.as_ptr()) }
    }

    #[inline]
    fn load_partial(self, bytes: &[u8]) -> Self::Vector {
        assert!(!bytes.is_empty(), "partial load is empty");
        assert!(bytes.len() <= Self::LANES, "partial load exceeds LANES");
        assert!(
            bytes.len().is_multiple_of(Self::PARTIAL_GRANULARITY),
            "partial load is not aligned"
        );
        let mask = prefix_mask(bytes.len());
        // SAFETY: `Avx512` proves AVX-512F is available. Each enabled mask bit loads one
        // four-byte lane, and the checks above prove `bytes` contains every enabled lane.
        // Masked-off lanes are not accessed and are set to zero. The unaligned load imposes
        // no alignment requirement.
        unsafe { load_partial(bytes.as_ptr(), mask) }
    }

    #[inline]
    fn store(self, a: Self::Vector, out: &mut [u8]) {
        assert_eq!(out.len(), Self::LANES, "out.len() != LANES");
        // SAFETY: `Avx512` proves AVX-512F is available, and the length check above proves `out`
        // contains space for exactly one full vector. The unaligned store imposes no alignment
        // requirement.
        unsafe { store(a, out.as_mut_ptr()) }
    }

    #[inline]
    fn store_partial(self, a: Self::Vector, out: &mut [u8]) {
        assert!(!out.is_empty(), "partial store is empty");
        assert!(out.len() <= Self::LANES, "partial store exceeds LANES");
        assert!(
            out.len().is_multiple_of(Self::PARTIAL_GRANULARITY),
            "partial store is not aligned"
        );
        let mask = prefix_mask(out.len());
        // SAFETY: `Avx512` proves AVX-512F is available. Each enabled mask bit stores one
        // four-byte lane, and the checks above prove `out` contains every enabled lane.
        // Masked-off lanes are not accessed. The unaligned store imposes no alignment
        // requirement.
        unsafe { store_partial(a, out.as_mut_ptr(), mask) }
    }

    #[inline]
    fn xor(self, a: Self::Vector, b: Self::Vector) -> Self::Vector {
        // SAFETY: `Avx512` can only be constructed when AVX-512F and GFNI are available.
        unsafe { xor(a, b) }
    }

    #[inline]
    fn xor_fold(self, a: Self::Vector) -> u8 {
        // SAFETY: `Avx512` can only be constructed when AVX-512F and GFNI are available.
        unsafe { xor_fold(a) }
    }

    #[inline]
    fn gf8_mul_vec(self, a: Self::Vector, b: Self::Vector) -> Self::Vector {
        // SAFETY: `Avx512` can only be constructed when AVX-512F and GFNI are available.
        unsafe { gf8_mul(a, b) }
    }

    #[inline]
    fn gf8_mul_constant(self, a: Self::Vector, b: Self::Constant) -> Self::Vector {
        // SAFETY: `Avx512` can only be constructed when AVX-512F and GFNI are available.
        unsafe { gf8_mul(a, b) }
    }
}

/// Feature set required by this kernel.
fn available() -> bool {
    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("gfni")
}

#[inline]
const fn prefix_mask(bytes: usize) -> __mmask16 {
    let lanes = bytes / 4;
    u16::MAX >> (16 - lanes)
}

#[inline]
#[target_feature(enable = "avx512f")]
fn splat(x: u8) -> __m512i {
    let repeated = u64::from_ne_bytes([x; 8]);
    _mm512_set1_epi64(repeated as i64)
}

#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn load(bytes: *const u8) -> __m512i {
    // SAFETY: the caller guarantees `bytes` points to 64 readable bytes. `loadu` imposes no
    // alignment requirement.
    unsafe { _mm512_loadu_si512(bytes.cast()) }
}

#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn load_partial(bytes: *const u8, mask: __mmask16) -> __m512i {
    // SAFETY: the caller guarantees that `bytes` points to four readable bytes for each enabled
    // low mask bit. The intrinsic does not access masked-off lanes and permits unaligned input.
    unsafe { _mm512_maskz_loadu_epi32(mask, bytes.cast()) }
}

#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn store(a: __m512i, out: *mut u8) {
    // SAFETY: the caller guarantees `out` points to 64 writable bytes. `storeu` imposes no
    // alignment requirement.
    unsafe { _mm512_storeu_si512(out.cast(), a) };
}

#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn store_partial(a: __m512i, out: *mut u8, mask: __mmask16) {
    // SAFETY: the caller guarantees that `out` points to four writable bytes for each enabled low
    // mask bit. The intrinsic does not access masked-off lanes and permits unaligned output.
    unsafe { _mm512_mask_storeu_epi32(out.cast(), mask, a) };
}

#[inline]
#[target_feature(enable = "avx512f")]
fn xor(a: __m512i, b: __m512i) -> __m512i {
    _mm512_xor_si512(a, b)
}

#[inline]
#[target_feature(enable = "avx512f")]
fn xor_fold(a: __m512i) -> u8 {
    let mut bytes = [0u8; 64];
    // SAFETY: `bytes` is exactly one vector wide and writable. `storeu` imposes no alignment
    // requirement.
    unsafe { _mm512_storeu_si512(bytes.as_mut_ptr().cast(), a) };
    bytes.into_iter().fold(0, |acc, byte| acc ^ byte)
}

#[inline]
#[target_feature(enable = "avx512f,gfni")]
fn gf8_mul(a: __m512i, b: __m512i) -> __m512i {
    _mm512_gf2p8mul_epi8(a, b)
}
