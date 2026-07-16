#[cfg(target_arch = "aarch64")]
use crate::reed_solomon::engine::Neon;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::reed_solomon::engine::{Avx2, Ssse3};
use crate::reed_solomon::engine::{
    Engine, GfElement, NoSimd, ShardsRefMut, GF_ORDER, SHARD_CHUNK_BYTES,
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

// ======================================================================
// DefaultEngine - PUBLIC

/// [`Engine`] that at runtime selects the best Engine.
pub struct DefaultEngine(Box<dyn Engine + Send + Sync>);

impl DefaultEngine {
    /// Creates new [`DefaultEngine`] by chosing and initializing the underlying engine.
    ///
    /// On x86(-64) the engine is chosen in the following order of preference:
    /// 1. `Avx2`
    /// 2. `Ssse3`
    /// 3. [`NoSimd`]
    ///
    /// On `AArch64` the engine is chosen in the following order of preference:
    /// 1. `Neon`
    /// 2. [`NoSimd`]
    pub fn new() -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            cpufeatures::new!(has_avx2, "avx2");
            if has_avx2::get() {
                return Self(Box::new(Avx2::new()));
            }

            cpufeatures::new!(has_ssse3, "ssse3");
            if has_ssse3::get() {
                return Self(Box::new(Ssse3::new()));
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            cpufeatures::new!(has_neon, "neon");
            if has_neon::get() {
                return Self(Box::new(Neon::new()));
            }
        }

        Self(Box::new(NoSimd::new()))
    }
}

// ======================================================================
// DefaultEngine - IMPL Default

impl Default for DefaultEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ======================================================================
// DefaultEngine - IMPL Engine

impl Engine for DefaultEngine {
    fn fft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        self.0.fft(data, pos, size, truncated_size, skew_delta);
    }

    fn ifft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        self.0.ifft(data, pos, size, truncated_size, skew_delta);
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        self.0.mul(x, log_m);
    }

    fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            cpufeatures::new!(has_avx2, "avx2");
            if has_avx2::get() {
                return Avx2::eval_poly(erasures, truncated_size);
            }

            cpufeatures::new!(has_ssse3, "ssse3");
            if has_ssse3::get() {
                return Ssse3::eval_poly(erasures, truncated_size);
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            cpufeatures::new!(has_neon, "neon");
            if has_neon::get() {
                return Neon::eval_poly(erasures, truncated_size);
            }
        }

        NoSimd::eval_poly(erasures, truncated_size);
    }
}
