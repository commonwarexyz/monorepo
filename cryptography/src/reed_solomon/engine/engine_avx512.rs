use crate::reed_solomon::engine::{
    Engine, GF_MODULUS, GF_ORDER, GfElement, SHARD_CHUNK_BYTES, ShardsRefMut,
    tables::{self, MulGfni, MultiplyGfni, Skew},
    utils,
};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::iter::zip;

// ======================================================================
// Avx512 - PUBLIC

/// Optimized [`Engine`] using AVX-512 instructions.
///
/// [`Avx512`] is an optimized engine that follows the same algorithm as
/// [`NoSimd`] but uses the x86 AVX-512F, AVX-512VL, AVX-512BW, and GFNI extensions.
///
/// [`NoSimd`]: crate::reed_solomon::engine::NoSimd
///
/// Construction and [`Engine::eval_poly`] panic if the required extensions are unavailable.
#[derive(Clone, Copy)]
pub struct Avx512 {
    multiply: &'static MulGfni,
    skew: &'static Skew,
}

impl Avx512 {
    /// Creates new [`Avx512`], initializing all [tables]
    /// needed for encoding or decoding.
    ///
    /// Currently only difference between encoding/decoding is
    /// [`LogWalsh`] (128 kiB) which is only needed for decoding.
    ///
    /// [`LogWalsh`]: crate::reed_solomon::engine::tables::LogWalsh
    pub fn new() -> Self {
        assert!(super::cpu_features::avx512());

        let multiply = tables::get_mul_gfni();
        let skew = tables::get_skew();

        Self { multiply, skew }
    }
}

impl Engine for Avx512 {
    fn fft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        super::validate_transform(data, pos, size, truncated_size, skew_delta);

        // SAFETY: Construction verifies the required features, and transform validation bounds all offsets.
        unsafe { self.fft_private(data, pos, size, truncated_size, skew_delta) }
    }

    fn ifft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        super::validate_transform(data, pos, size, truncated_size, skew_delta);

        // SAFETY: Construction verifies the required features, and transform validation bounds all offsets.
        unsafe { self.ifft_private(data, pos, size, truncated_size, skew_delta) }
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        // SAFETY: Construction verifies the required features; chunks have the fixed engine width.
        unsafe { self.mul_private(x, log_m) }
    }

    fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        assert!(super::cpu_features::avx512());

        // SAFETY: The runtime check establishes all target features enabled by eval_poly_avx512.
        unsafe { Self::eval_poly_avx512(erasures, truncated_size) }
    }
}

// ======================================================================
// Avx512 - IMPL Default

impl Default for Avx512 {
    fn default() -> Self {
        Self::new()
    }
}

// ======================================================================
// Avx512 - PRIVATE

#[derive(Copy, Clone)]
struct LutGfni {
    direct: __m512i,
    cross: __m512i,
}

impl From<&MultiplyGfni> for LutGfni {
    #[inline(always)]
    fn from(lut: &MultiplyGfni) -> Self {
        // SAFETY: Callers execute within a GFNI target-feature boundary, and each operand is exactly 64 bytes.
        unsafe {
            Self {
                direct: _mm512_loadu_si512(lut.direct.as_ptr().cast::<__m512i>()),
                cross: _mm512_loadu_si512(lut.cross.as_ptr().cast::<__m512i>()),
            }
        }
    }
}

impl Avx512 {
    #[target_feature(enable = "avx512f,avx512vl,avx512bw,gfni")]
    unsafe fn mul_private(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        let lut = LutGfni::from(&self.multiply[log_m as usize]);

        for chunk in x.iter_mut() {
            // SAFETY: This function enables the required features; each chunk is exactly 64 bytes.
            unsafe {
                let x_ptr = chunk.as_mut_ptr().cast::<__m512i>();
                let x = _mm512_loadu_si512(x_ptr);
                let prod = Self::multiply_512(x, lut);
                _mm512_storeu_si512(x_ptr, prod);
            }
        }
    }

    #[inline(always)]
    unsafe fn multiply_512(value: __m512i, lut: LutGfni) -> __m512i {
        // SAFETY: The caller executes within the AVX-512 and GFNI target-feature boundary.
        unsafe {
            let swapped = _mm512_shuffle_i64x2(value, value, 0x4e);
            let direct = _mm512_gf2p8affine_epi64_epi8(value, lut.direct, 0);
            let cross = _mm512_gf2p8affine_epi64_epi8(swapped, lut.cross, 0);
            _mm512_xor_si512(direct, cross)
        }
    }

    // Implementation of LEO_MULADD_512.
    #[inline(always)]
    unsafe fn muladd_512(x: __m512i, y: __m512i, lut: LutGfni) -> __m512i {
        // SAFETY: The caller executes within the AVX-512 and GFNI target-feature boundary.
        unsafe {
            let prod = Self::multiply_512(y, lut);
            _mm512_xor_si512(x, prod)
        }
    }
}

// ======================================================================
// Avx512 - PRIVATE - FFT (fast Fourier transform)

impl Avx512 {
    // Implementation of LEO_FFTB_512.
    // Partial butterfly, caller must do `GF_MODULUS` check with `xor`.
    #[inline(always)]
    unsafe fn fft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        let lut = LutGfni::from(&self.multiply[log_m as usize]);

        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            // SAFETY: The caller enables the required features; both disjoint chunks are exactly 64 bytes.
            unsafe {
                let x_ptr = x_chunk.as_mut_ptr().cast::<__m512i>();
                let y_ptr = y_chunk.as_mut_ptr().cast::<__m512i>();
                let mut x = _mm512_loadu_si512(x_ptr);
                let mut y = _mm512_loadu_si512(y_ptr);

                x = Self::muladd_512(x, y, lut);
                y = _mm512_xor_si512(y, x);

                _mm512_storeu_si512(x_ptr, x);
                _mm512_storeu_si512(y_ptr, y);
            }
        }
    }

    #[inline(always)]
    unsafe fn fft_butterfly_two_layers(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        dist: usize,
        log_m01: GfElement,
        log_m23: GfElement,
        log_m02: GfElement,
    ) {
        let (s0, s1, s2, s3) = data.dist4_mut(pos, dist);

        // FIRST LAYER

        if log_m02 == GF_MODULUS {
            utils::xor(s2, s0);
            utils::xor(s3, s1);
        } else {
            // SAFETY: The caller enables the required features.
            unsafe {
                self.fft_butterfly_partial(s0, s2, log_m02);
                self.fft_butterfly_partial(s1, s3, log_m02);
            }
        }

        // SECOND LAYER

        if log_m01 == GF_MODULUS {
            utils::xor(s1, s0);
        } else {
            // SAFETY: The caller enables the required features.
            unsafe { self.fft_butterfly_partial(s0, s1, log_m01) };
        }

        if log_m23 == GF_MODULUS {
            utils::xor(s3, s2);
        } else {
            // SAFETY: The caller enables the required features.
            unsafe { self.fft_butterfly_partial(s2, s3, log_m23) };
        }
    }

    #[target_feature(enable = "avx512f,avx512vl,avx512bw,gfni")]
    unsafe fn fft_private(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // TWO LAYERS AT TIME

        let mut dist4 = size;
        let mut dist = size >> 2;
        while dist != 0 {
            let mut r = 0;
            while r < truncated_size {
                let base = r + dist + skew_delta - 1;

                let log_m01 = self.skew[base];
                let log_m02 = self.skew[base + dist];
                let log_m23 = self.skew[base + dist * 2];

                for i in r..r + dist {
                    // SAFETY: This function enables the required features.
                    unsafe {
                        self.fft_butterfly_two_layers(
                            data,
                            pos + i,
                            dist,
                            log_m01,
                            log_m23,
                            log_m02,
                        )
                    };
                }

                r += dist4;
            }
            dist4 = dist;
            dist >>= 2;
        }

        // FINAL ODD LAYER

        if dist4 == 2 {
            let mut r = 0;
            while r < truncated_size {
                let log_m = self.skew[r + skew_delta];

                let (x, y) = data.dist2_mut(pos + r, 1);

                if log_m == GF_MODULUS {
                    utils::xor(y, x);
                } else {
                    // SAFETY: This function enables the required features.
                    unsafe { self.fft_butterfly_partial(x, y, log_m) };
                }

                r += 2;
            }
        }
    }
}

// ======================================================================
// Avx512 - PRIVATE - IFFT (inverse fast Fourier transform)

impl Avx512 {
    // Implementation of LEO_IFFTB_512.
    #[inline(always)]
    unsafe fn ifft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        let lut = LutGfni::from(&self.multiply[log_m as usize]);

        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            // SAFETY: The caller enables the required features; both disjoint chunks are exactly 64 bytes.
            unsafe {
                let x_ptr = x_chunk.as_mut_ptr().cast::<__m512i>();
                let y_ptr = y_chunk.as_mut_ptr().cast::<__m512i>();
                let mut x = _mm512_loadu_si512(x_ptr);
                let mut y = _mm512_loadu_si512(y_ptr);

                y = _mm512_xor_si512(y, x);
                x = Self::muladd_512(x, y, lut);

                _mm512_storeu_si512(x_ptr, x);
                _mm512_storeu_si512(y_ptr, y);
            }
        }
    }

    #[inline(always)]
    unsafe fn ifft_butterfly_two_layers(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        dist: usize,
        log_m01: GfElement,
        log_m23: GfElement,
        log_m02: GfElement,
    ) {
        let (s0, s1, s2, s3) = data.dist4_mut(pos, dist);

        // FIRST LAYER

        if log_m01 == GF_MODULUS {
            utils::xor(s1, s0);
        } else {
            // SAFETY: The caller enables the required features.
            unsafe { self.ifft_butterfly_partial(s0, s1, log_m01) };
        }

        if log_m23 == GF_MODULUS {
            utils::xor(s3, s2);
        } else {
            // SAFETY: The caller enables the required features.
            unsafe { self.ifft_butterfly_partial(s2, s3, log_m23) };
        }

        // SECOND LAYER

        if log_m02 == GF_MODULUS {
            utils::xor(s2, s0);
            utils::xor(s3, s1);
        } else {
            // SAFETY: The caller enables the required features.
            unsafe {
                self.ifft_butterfly_partial(s0, s2, log_m02);
                self.ifft_butterfly_partial(s1, s3, log_m02);
            }
        }
    }

    #[target_feature(enable = "avx512f,avx512vl,avx512bw,gfni")]
    unsafe fn ifft_private(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // TWO LAYERS AT TIME

        let mut dist = 1;
        let mut dist4 = 4;
        while dist4 <= size {
            let mut r = 0;
            while r < truncated_size {
                let base = r + dist + skew_delta - 1;

                let log_m01 = self.skew[base];
                let log_m02 = self.skew[base + dist];
                let log_m23 = self.skew[base + dist * 2];

                for i in r..r + dist {
                    // SAFETY: This function enables the required features.
                    unsafe {
                        self.ifft_butterfly_two_layers(
                            data,
                            pos + i,
                            dist,
                            log_m01,
                            log_m23,
                            log_m02,
                        )
                    };
                }

                r += dist4;
            }
            dist = dist4;
            dist4 <<= 2;
        }

        // FINAL ODD LAYER

        if dist < size {
            let log_m = self.skew[dist + skew_delta - 1];
            if log_m == GF_MODULUS {
                utils::xor_within(data, pos + dist, pos, dist);
            } else {
                let (mut a, mut b) = data.split_at_mut(pos + dist);
                for i in 0..dist {
                    // SAFETY: This function enables the required features.
                    unsafe { self.ifft_butterfly_partial(&mut a[pos + i], &mut b[i], log_m) };
                }
            }
        }
    }
}

// ======================================================================
// Avx512 - PRIVATE - Evaluate polynomial

impl Avx512 {
    #[target_feature(enable = "avx512f,avx512vl,avx512bw,gfni")]
    unsafe fn eval_poly_avx512(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        utils::eval_poly(erasures, truncated_size);
    }
}

// ======================================================================
// TESTS

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gfni_all_multipliers_basis() {
        if !super::super::cpu_features::avx512() {
            return;
        }
        let gfni = Avx512::new();
        let exp_log = tables::get_exp_log();
        let mut basis = [[0u8; SHARD_CHUNK_BYTES]; 1];
        for bit in 0..16 {
            let value = 1u16 << bit;
            basis[0][bit] = value as u8;
            basis[0][32 + bit] = (value >> 8) as u8;
        }

        for log_m in 0..=GF_MODULUS {
            let mut actual = basis;
            gfni.mul(&mut actual, log_m);
            for bit in 0..16 {
                let actual = actual[0][bit] as u16 | (actual[0][32 + bit] as u16) << 8;
                let expected = tables::mul(1u16 << bit, log_m, &exp_log.exp, &exp_log.log);
                assert_eq!(actual, expected, "log_m={log_m} input_bit={bit}");
            }
        }
    }
}
