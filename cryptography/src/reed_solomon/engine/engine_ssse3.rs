use crate::reed_solomon::engine::{
    tables::{self, Mul128, Multiply128lutT, Skew},
    utils, Engine, GfElement, ShardsRefMut, GF_MODULUS, GF_ORDER, SHARD_CHUNK_BYTES,
};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::iter::zip;

// ======================================================================
// Ssse3 - PUBLIC

/// Optimized [`Engine`] using SSSE3 instructions.
///
/// [`Ssse3`] is an optimized engine that follows the same algorithm as
/// [`NoSimd`] but takes advantage of the x86 SSSE3 SIMD instructions.
///
/// [`NoSimd`]: crate::reed_solomon::engine::NoSimd
#[derive(Clone, Copy)]
pub struct Ssse3 {
    mul128: &'static Mul128,
    skew: &'static Skew,
}

impl Ssse3 {
    /// Creates new [`Ssse3`], initializing all [tables]
    /// needed for encoding or decoding.
    ///
    /// Currently only difference between encoding/decoding is
    /// [`LogWalsh`] (128 kiB) which is only needed for decoding.
    ///
    /// [`LogWalsh`]: crate::reed_solomon::engine::tables::LogWalsh
    pub fn new() -> Self {
        cpufeatures::new!(has_ssse3_for_engine, "ssse3");
        assert!(has_ssse3_for_engine::get());

        let mul128 = tables::get_mul128();
        let skew = tables::get_skew();

        Self { mul128, skew }
    }
}

impl Engine for Ssse3 {
    fn fft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe {
            self.fft_private_ssse3(data, pos, size, truncated_size, skew_delta);
        }
    }

    fn ifft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe {
            self.ifft_private_ssse3(data, pos, size, truncated_size, skew_delta);
        }
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe {
            self.mul_ssse3(x, log_m);
        }
    }

    fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe { Self::eval_poly_ssse3(erasures, truncated_size) }
    }
}

// ======================================================================
// Ssse3 - IMPL Default

impl Default for Ssse3 {
    fn default() -> Self {
        Self::new()
    }
}

// ======================================================================
// Ssse3 - PRIVATE
//
//

impl Ssse3 {
    #[target_feature(enable = "ssse3")]
    unsafe fn mul_ssse3(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        let lut = &self.mul128[log_m as usize];

        for chunk in x.iter_mut() {
            let x_ptr = chunk.as_mut_ptr().cast::<__m128i>();
            // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
            unsafe {
                let x0_lo = _mm_loadu_si128(x_ptr);
                let x1_lo = _mm_loadu_si128(x_ptr.add(1));
                let x0_hi = _mm_loadu_si128(x_ptr.add(2));
                let x1_hi = _mm_loadu_si128(x_ptr.add(3));
                let (prod0_lo, prod0_hi) = Self::mul_128(x0_lo, x0_hi, lut);
                let (prod1_lo, prod1_hi) = Self::mul_128(x1_lo, x1_hi, lut);
                _mm_storeu_si128(x_ptr, prod0_lo);
                _mm_storeu_si128(x_ptr.add(1), prod1_lo);
                _mm_storeu_si128(x_ptr.add(2), prod0_hi);
                _mm_storeu_si128(x_ptr.add(3), prod1_hi);
            }
        }
    }

    // Impelemntation of LEO_MUL_128
    #[inline(always)]
    fn mul_128(value_lo: __m128i, value_hi: __m128i, lut: &Multiply128lutT) -> (__m128i, __m128i) {
        let mut prod_lo: __m128i;
        let mut prod_hi: __m128i;

        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe {
            let t0_lo = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.lo[0]).cast::<__m128i>());
            let t1_lo = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.lo[1]).cast::<__m128i>());
            let t2_lo = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.lo[2]).cast::<__m128i>());
            let t3_lo = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.lo[3]).cast::<__m128i>());

            let t0_hi = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.hi[0]).cast::<__m128i>());
            let t1_hi = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.hi[1]).cast::<__m128i>());
            let t2_hi = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.hi[2]).cast::<__m128i>());
            let t3_hi = _mm_loadu_si128(core::ptr::from_ref::<u128>(&lut.hi[3]).cast::<__m128i>());

            let clr_mask = _mm_set1_epi8(0x0f);

            let data_0 = _mm_and_si128(value_lo, clr_mask);
            prod_lo = _mm_shuffle_epi8(t0_lo, data_0);
            prod_hi = _mm_shuffle_epi8(t0_hi, data_0);

            let data_1 = _mm_and_si128(_mm_srli_epi64(value_lo, 4), clr_mask);
            prod_lo = _mm_xor_si128(prod_lo, _mm_shuffle_epi8(t1_lo, data_1));
            prod_hi = _mm_xor_si128(prod_hi, _mm_shuffle_epi8(t1_hi, data_1));

            let data_0 = _mm_and_si128(value_hi, clr_mask);
            prod_lo = _mm_xor_si128(prod_lo, _mm_shuffle_epi8(t2_lo, data_0));
            prod_hi = _mm_xor_si128(prod_hi, _mm_shuffle_epi8(t2_hi, data_0));

            let data_1 = _mm_and_si128(_mm_srli_epi64(value_hi, 4), clr_mask);
            prod_lo = _mm_xor_si128(prod_lo, _mm_shuffle_epi8(t3_lo, data_1));
            prod_hi = _mm_xor_si128(prod_hi, _mm_shuffle_epi8(t3_hi, data_1));
        }

        (prod_lo, prod_hi)
    }

    //// {x_lo, x_hi} ^= {y_lo, y_hi} * log_m
    // Implementation of LEO_MULADD_128
    #[inline(always)]
    fn muladd_128(
        mut x_lo: __m128i,
        mut x_hi: __m128i,
        y_lo: __m128i,
        y_hi: __m128i,
        lut: &Multiply128lutT,
    ) -> (__m128i, __m128i) {
        let (prod_lo, prod_hi) = Self::mul_128(y_lo, y_hi, lut);
        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe {
            x_lo = _mm_xor_si128(x_lo, prod_lo);
            x_hi = _mm_xor_si128(x_hi, prod_hi);
        }
        (x_lo, x_hi)
    }
}

// ======================================================================
// Ssse3 - PRIVATE - FFT (fast Fourier transform)

impl Ssse3 {
    // Implementation of LEO_FFTB_128
    #[inline(always)]
    fn fftb_128(
        &self,
        x: &mut [u8; SHARD_CHUNK_BYTES],
        y: &mut [u8; SHARD_CHUNK_BYTES],
        log_m: GfElement,
    ) {
        let lut = &self.mul128[log_m as usize];
        let x_ptr = x.as_mut_ptr().cast::<__m128i>();
        let y_ptr = y.as_mut_ptr().cast::<__m128i>();
        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe {
            let mut x0_lo = _mm_loadu_si128(x_ptr);
            let mut x1_lo = _mm_loadu_si128(x_ptr.add(1));
            let mut x0_hi = _mm_loadu_si128(x_ptr.add(2));
            let mut x1_hi = _mm_loadu_si128(x_ptr.add(3));

            let mut y0_lo = _mm_loadu_si128(y_ptr);
            let mut y1_lo = _mm_loadu_si128(y_ptr.add(1));
            let mut y0_hi = _mm_loadu_si128(y_ptr.add(2));
            let mut y1_hi = _mm_loadu_si128(y_ptr.add(3));

            (x0_lo, x0_hi) = Self::muladd_128(x0_lo, x0_hi, y0_lo, y0_hi, lut);
            (x1_lo, x1_hi) = Self::muladd_128(x1_lo, x1_hi, y1_lo, y1_hi, lut);

            _mm_storeu_si128(x_ptr, x0_lo);
            _mm_storeu_si128(x_ptr.add(1), x1_lo);
            _mm_storeu_si128(x_ptr.add(2), x0_hi);
            _mm_storeu_si128(x_ptr.add(3), x1_hi);

            y0_lo = _mm_xor_si128(y0_lo, x0_lo);
            y1_lo = _mm_xor_si128(y1_lo, x1_lo);
            y0_hi = _mm_xor_si128(y0_hi, x0_hi);
            y1_hi = _mm_xor_si128(y1_hi, x1_hi);

            _mm_storeu_si128(y_ptr, y0_lo);
            _mm_storeu_si128(y_ptr.add(1), y1_lo);
            _mm_storeu_si128(y_ptr.add(2), y0_hi);
            _mm_storeu_si128(y_ptr.add(3), y1_hi);
        }
    }

    // Partial butterfly, caller must do `GF_MODULUS` check with `xor`.
    #[inline(always)]
    fn fft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            self.fftb_128(x_chunk, y_chunk, log_m);
        }
    }

    #[inline(always)]
    fn fft_butterfly_two_layers(
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
            self.fft_butterfly_partial(s0, s2, log_m02);
            self.fft_butterfly_partial(s1, s3, log_m02);
        }

        // SECOND LAYER

        if log_m01 == GF_MODULUS {
            utils::xor(s1, s0);
        } else {
            self.fft_butterfly_partial(s0, s1, log_m01);
        }

        if log_m23 == GF_MODULUS {
            utils::xor(s3, s2);
        } else {
            self.fft_butterfly_partial(s2, s3, log_m23);
        }
    }

    #[target_feature(enable = "ssse3")]
    unsafe fn fft_private_ssse3(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // Drop unsafe privileges
        self.fft_private(data, pos, size, truncated_size, skew_delta);
    }

    #[inline(always)]
    fn fft_private(
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
                    self.fft_butterfly_two_layers(data, pos + i, dist, log_m01, log_m23, log_m02);
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
                    self.fft_butterfly_partial(x, y, log_m);
                }

                r += 2;
            }
        }
    }
}

// ======================================================================
// Ssse3 - PRIVATE - IFFT (inverse fast Fourier transform)

impl Ssse3 {
    // Implementation of LEO_IFFTB_128
    #[inline(always)]
    fn ifftb_128(
        &self,
        x: &mut [u8; SHARD_CHUNK_BYTES],
        y: &mut [u8; SHARD_CHUNK_BYTES],
        log_m: GfElement,
    ) {
        let lut = &self.mul128[log_m as usize];
        let x_ptr = x.as_mut_ptr().cast::<__m128i>();
        let y_ptr = y.as_mut_ptr().cast::<__m128i>();

        // SAFETY: Constructors and runtime dispatch ensure the SIMD feature is available; offsets stay within fixed-size shard buffers.
        unsafe {
            let mut x0_lo = _mm_loadu_si128(x_ptr);
            let mut x1_lo = _mm_loadu_si128(x_ptr.add(1));
            let mut x0_hi = _mm_loadu_si128(x_ptr.add(2));
            let mut x1_hi = _mm_loadu_si128(x_ptr.add(3));

            let mut y0_lo = _mm_loadu_si128(y_ptr);
            let mut y1_lo = _mm_loadu_si128(y_ptr.add(1));
            let mut y0_hi = _mm_loadu_si128(y_ptr.add(2));
            let mut y1_hi = _mm_loadu_si128(y_ptr.add(3));

            y0_lo = _mm_xor_si128(y0_lo, x0_lo);
            y1_lo = _mm_xor_si128(y1_lo, x1_lo);
            y0_hi = _mm_xor_si128(y0_hi, x0_hi);
            y1_hi = _mm_xor_si128(y1_hi, x1_hi);

            _mm_storeu_si128(y_ptr, y0_lo);
            _mm_storeu_si128(y_ptr.add(1), y1_lo);
            _mm_storeu_si128(y_ptr.add(2), y0_hi);
            _mm_storeu_si128(y_ptr.add(3), y1_hi);

            (x0_lo, x0_hi) = Self::muladd_128(x0_lo, x0_hi, y0_lo, y0_hi, lut);
            (x1_lo, x1_hi) = Self::muladd_128(x1_lo, x1_hi, y1_lo, y1_hi, lut);

            _mm_storeu_si128(x_ptr, x0_lo);
            _mm_storeu_si128(x_ptr.add(1), x1_lo);
            _mm_storeu_si128(x_ptr.add(2), x0_hi);
            _mm_storeu_si128(x_ptr.add(3), x1_hi);
        }
    }

    #[inline(always)]
    fn ifft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            self.ifftb_128(x_chunk, y_chunk, log_m);
        }
    }

    #[inline(always)]
    fn ifft_butterfly_two_layers(
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
            self.ifft_butterfly_partial(s0, s1, log_m01);
        }

        if log_m23 == GF_MODULUS {
            utils::xor(s3, s2);
        } else {
            self.ifft_butterfly_partial(s2, s3, log_m23);
        }

        // SECOND LAYER

        if log_m02 == GF_MODULUS {
            utils::xor(s2, s0);
            utils::xor(s3, s1);
        } else {
            self.ifft_butterfly_partial(s0, s2, log_m02);
            self.ifft_butterfly_partial(s1, s3, log_m02);
        }
    }

    #[target_feature(enable = "ssse3")]
    unsafe fn ifft_private_ssse3(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // Drop unsafe privileges
        self.ifft_private(data, pos, size, truncated_size, skew_delta);
    }

    #[inline(always)]
    fn ifft_private(
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
                    self.ifft_butterfly_two_layers(data, pos + i, dist, log_m01, log_m23, log_m02);
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
                    self.ifft_butterfly_partial(
                        &mut a[pos + i], // data[pos + i]
                        &mut b[i],       // data[pos + i + dist]
                        log_m,
                    );
                }
            }
        }
    }
}

// ======================================================================
// Ssse3 - PRIVATE - Evaluate polynomial

impl Ssse3 {
    #[target_feature(enable = "ssse3")]
    unsafe fn eval_poly_ssse3(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        utils::eval_poly(erasures, truncated_size);
    }
}

// ======================================================================
// TESTS

// Engines are tested indirectly via roundtrip tests of HighRate and LowRate.
