use crate::reed_solomon::engine::{
    Engine, GF_MODULUS, GF_ORDER, GfElement, SHARD_CHUNK_BYTES, ShardsRefMut,
    tables::{self, Mul128, MulGfni, Multiply128lutT, MultiplyGfni, Skew},
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
/// [`NoSimd`] but uses the x86 AVX-512F, AVX-512VL, and AVX-512BW extensions.
/// When GFNI is available, it uses affine byte operations for field multiplication.
/// Construction initializes only the selected multiplication table.
///
/// [`NoSimd`]: crate::reed_solomon::engine::NoSimd
///
/// Construction and [`Engine::eval_poly`] panic if the required AVX-512 extensions are unavailable.
#[derive(Clone, Copy)]
pub struct Avx512 {
    multiply: MultiplyBackend,
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

        let multiply = if super::cpu_features::gfni() {
            MultiplyBackend::Gfni(tables::get_mul_gfni())
        } else {
            MultiplyBackend::Shuffle(tables::get_mul128())
        };
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

        // SAFETY: Construction verifies the features represented by the selected backend, and transform validation bounds all offsets.
        unsafe {
            match self.multiply {
                MultiplyBackend::Shuffle(table) => self.fft_private_avx512(
                    ShuffleBackend(table),
                    data,
                    pos,
                    size,
                    truncated_size,
                    skew_delta,
                ),
                MultiplyBackend::Gfni(table) => self.fft_private_gfni(
                    GfniBackend(table),
                    data,
                    pos,
                    size,
                    truncated_size,
                    skew_delta,
                ),
            }
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
        super::validate_transform(data, pos, size, truncated_size, skew_delta);

        // SAFETY: Construction verifies the features represented by the selected backend, and transform validation bounds all offsets.
        unsafe {
            match self.multiply {
                MultiplyBackend::Shuffle(table) => self.ifft_private_avx512(
                    ShuffleBackend(table),
                    data,
                    pos,
                    size,
                    truncated_size,
                    skew_delta,
                ),
                MultiplyBackend::Gfni(table) => self.ifft_private_gfni(
                    GfniBackend(table),
                    data,
                    pos,
                    size,
                    truncated_size,
                    skew_delta,
                ),
            }
        }
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        // SAFETY: Construction verifies the features represented by the selected backend; chunks have the fixed engine width.
        unsafe {
            match self.multiply {
                MultiplyBackend::Shuffle(table) => {
                    Self::mul_avx512(ShuffleBackend(table), x, log_m)
                }
                MultiplyBackend::Gfni(table) => Self::mul_gfni(GfniBackend(table), x, log_m),
            }
        }
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

/// The variant records the CPU features verified at construction.
#[derive(Clone, Copy)]
enum MultiplyBackend {
    Shuffle(&'static Mul128),
    Gfni(&'static MulGfni),
}

#[derive(Clone, Copy)]
struct ShuffleBackend(&'static Mul128);

#[derive(Clone, Copy)]
struct GfniBackend(&'static MulGfni);

/// Callers must enable the target features required by the concrete backend.
trait Multiplication: Copy {
    type Lut: Copy;

    unsafe fn load(self, log_m: GfElement) -> Self::Lut;

    unsafe fn multiply(value: __m512i, lut: Self::Lut) -> __m512i;
}

#[derive(Copy, Clone)]
struct LutAvx512 {
    t0_t2_lo: __m512i,
    t0_t2_hi: __m512i,
    t1_t3_lo: __m512i,
    t1_t3_hi: __m512i,
}

impl From<&Multiply128lutT> for LutAvx512 {
    #[inline(always)]
    fn from(lut: &Multiply128lutT) -> Self {
        let t0_t2_lo: __m512i;
        let t0_t2_hi: __m512i;
        let t1_t3_lo: __m512i;
        let t1_t3_hi: __m512i;

        // SAFETY: Callers execute within an AVX-512 target-feature boundary, and table entries are fixed-size values.
        unsafe {
            let t0_lo = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.lo[0]).cast::<__m128i>(),
            ));
            let t1_lo = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.lo[1]).cast::<__m128i>(),
            ));
            let t2_lo = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.lo[2]).cast::<__m128i>(),
            ));
            let t3_lo = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.lo[3]).cast::<__m128i>(),
            ));

            let t0_hi = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.hi[0]).cast::<__m128i>(),
            ));
            let t1_hi = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.hi[1]).cast::<__m128i>(),
            ));
            let t2_hi = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.hi[2]).cast::<__m128i>(),
            ));
            let t3_hi = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                (&raw const lut.hi[3]).cast::<__m128i>(),
            ));

            t0_t2_lo = _mm512_inserti64x4(_mm512_castsi256_si512(t0_lo), t2_lo, 1);
            t0_t2_hi = _mm512_inserti64x4(_mm512_castsi256_si512(t0_hi), t2_hi, 1);
            t1_t3_lo = _mm512_inserti64x4(_mm512_castsi256_si512(t1_lo), t3_lo, 1);
            t1_t3_hi = _mm512_inserti64x4(_mm512_castsi256_si512(t1_hi), t3_hi, 1);
        }

        Self {
            t0_t2_lo,
            t0_t2_hi,
            t1_t3_lo,
            t1_t3_hi,
        }
    }
}

#[derive(Copy, Clone)]
struct LutGfni {
    direct: __m512i,
    cross: __m512i,
}

impl From<&MultiplyGfni> for LutGfni {
    #[inline(always)]
    fn from(lut: &MultiplyGfni) -> Self {
        // SAFETY: Callers execute within a GFNI target-feature boundary.
        unsafe {
            let direct_low = _mm256_set1_epi64x(lut.low_from_low.cast_signed());
            let direct_high = _mm256_set1_epi64x(lut.high_from_high.cast_signed());
            let cross_low = _mm256_set1_epi64x(lut.low_from_high.cast_signed());
            let cross_high = _mm256_set1_epi64x(lut.high_from_low.cast_signed());

            Self {
                direct: _mm512_inserti64x4(_mm512_castsi256_si512(direct_low), direct_high, 1),
                cross: _mm512_inserti64x4(_mm512_castsi256_si512(cross_low), cross_high, 1),
            }
        }
    }
}

impl Multiplication for ShuffleBackend {
    type Lut = LutAvx512;

    #[inline(always)]
    unsafe fn load(self, log_m: GfElement) -> Self::Lut {
        LutAvx512::from(&self.0[log_m as usize])
    }

    #[inline(always)]
    unsafe fn multiply(value: __m512i, lut: Self::Lut) -> __m512i {
        // SAFETY: The caller executes within the classic AVX-512 target-feature boundary.
        unsafe { Avx512::mul_shuffle_512(value, lut) }
    }
}

impl Multiplication for GfniBackend {
    type Lut = LutGfni;

    #[inline(always)]
    unsafe fn load(self, log_m: GfElement) -> Self::Lut {
        LutGfni::from(&self.0[log_m as usize])
    }

    #[inline(always)]
    unsafe fn multiply(value: __m512i, lut: Self::Lut) -> __m512i {
        // SAFETY: The caller executes within the GFNI target-feature boundary.
        unsafe {
            let swapped = _mm512_shuffle_i64x2(value, value, 0x4e);
            let direct = _mm512_gf2p8affine_epi64_epi8(value, lut.direct, 0);
            let cross = _mm512_gf2p8affine_epi64_epi8(swapped, lut.cross, 0);
            _mm512_xor_si512(direct, cross)
        }
    }
}

impl Avx512 {
    #[target_feature(enable = "avx512f,avx512vl,avx512bw")]
    unsafe fn mul_avx512(
        backend: ShuffleBackend,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        // SAFETY: This function establishes the target features required by ShuffleBackend.
        unsafe { Self::mul_private(backend, x, log_m) }
    }

    #[target_feature(enable = "avx512f,avx512vl,avx512bw,gfni")]
    unsafe fn mul_gfni(backend: GfniBackend, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        // SAFETY: This function establishes the target features required by GfniBackend.
        unsafe { Self::mul_private(backend, x, log_m) }
    }

    #[inline(always)]
    unsafe fn mul_private<M: Multiplication>(
        backend: M,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
        let lut = unsafe { backend.load(log_m) };

        for chunk in x.iter_mut() {
            // SAFETY: The wrapper establishes the backend's features; each chunk is exactly 64 bytes.
            unsafe {
                let x_ptr = chunk.as_mut_ptr().cast::<__m512i>();
                let x = _mm512_loadu_si512(x_ptr);
                let prod = M::multiply(x, lut);
                _mm512_storeu_si512(x_ptr, prod);
            }
        }
    }

    // Implementation of LEO_MUL_512.
    #[inline(always)]
    unsafe fn mul_shuffle_512(value: __m512i, lut_avx512: LutAvx512) -> __m512i {
        // SAFETY: The caller executes within the AVX-512 target-feature boundary.
        unsafe {
            let clr_mask = _mm512_set1_epi8(0x0f);

            let data = _mm512_and_si512(value, clr_mask);
            let mut prod_lo_512 = _mm512_shuffle_epi8(lut_avx512.t0_t2_lo, data);
            let mut prod_hi_512 = _mm512_shuffle_epi8(lut_avx512.t0_t2_hi, data);

            let data = _mm512_and_si512(_mm512_srli_epi64(value, 4), clr_mask);
            prod_lo_512 =
                _mm512_xor_si512(prod_lo_512, _mm512_shuffle_epi8(lut_avx512.t1_t3_lo, data));
            prod_hi_512 =
                _mm512_xor_si512(prod_hi_512, _mm512_shuffle_epi8(lut_avx512.t1_t3_hi, data));

            let prod_lo = _mm256_xor_si256(
                _mm512_castsi512_si256(prod_lo_512),
                _mm512_extracti64x4_epi64(prod_lo_512, 1),
            );
            let prod_hi = _mm256_xor_si256(
                _mm512_castsi512_si256(prod_hi_512),
                _mm512_extracti64x4_epi64(prod_hi_512, 1),
            );

            _mm512_inserti64x4(_mm512_castsi256_si512(prod_lo), prod_hi, 1)
        }
    }

    // Implementation of LEO_MULADD_512.
    #[inline(always)]
    unsafe fn muladd_512<M: Multiplication>(x: __m512i, y: __m512i, lut: M::Lut) -> __m512i {
        // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
        unsafe {
            let prod = M::multiply(y, lut);
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
    unsafe fn fft_butterfly_partial<M: Multiplication>(
        backend: M,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
        let lut = unsafe { backend.load(log_m) };

        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            // SAFETY: The wrapper establishes the backend's features; both disjoint chunks are exactly 64 bytes.
            unsafe {
                let x_ptr = x_chunk.as_mut_ptr().cast::<__m512i>();
                let y_ptr = y_chunk.as_mut_ptr().cast::<__m512i>();
                let mut x = _mm512_loadu_si512(x_ptr);
                let mut y = _mm512_loadu_si512(y_ptr);

                x = Self::muladd_512::<M>(x, y, lut);
                y = _mm512_xor_si512(y, x);

                _mm512_storeu_si512(x_ptr, x);
                _mm512_storeu_si512(y_ptr, y);
            }
        }
    }

    #[inline(always)]
    unsafe fn fft_butterfly_two_layers<M: Multiplication>(
        backend: M,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        dist: usize,
        log_m01: GfElement,
        log_m23: GfElement,
        log_m02: GfElement,
    ) {
        let (s0, s1, s2, s3) = data.dist4_mut(pos, dist);

        // Skew uses `GF_MODULUS` for a zero coefficient, while multiplication tables use it
        // for the duplicated identity exponent.
        if log_m01 != GF_MODULUS && log_m23 != GF_MODULUS && log_m02 != GF_MODULUS {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            let (lut01, lut23, lut02) = unsafe {
                (
                    backend.load(log_m01),
                    backend.load(log_m23),
                    backend.load(log_m02),
                )
            };

            for (((s0_chunk, s1_chunk), s2_chunk), s3_chunk) in zip(
                zip(zip(s0.iter_mut(), s1.iter_mut()), s2.iter_mut()),
                s3.iter_mut(),
            ) {
                // SAFETY: The wrapper establishes the backend's features; all four disjoint chunks are exactly 64 bytes.
                unsafe {
                    let s0_ptr = s0_chunk.as_mut_ptr().cast::<__m512i>();
                    let s1_ptr = s1_chunk.as_mut_ptr().cast::<__m512i>();
                    let s2_ptr = s2_chunk.as_mut_ptr().cast::<__m512i>();
                    let s3_ptr = s3_chunk.as_mut_ptr().cast::<__m512i>();
                    let mut s0 = _mm512_loadu_si512(s0_ptr);
                    let mut s1 = _mm512_loadu_si512(s1_ptr);
                    let mut s2 = _mm512_loadu_si512(s2_ptr);
                    let mut s3 = _mm512_loadu_si512(s3_ptr);

                    s0 = Self::muladd_512::<M>(s0, s2, lut02);
                    s2 = _mm512_xor_si512(s2, s0);
                    s1 = Self::muladd_512::<M>(s1, s3, lut02);
                    s3 = _mm512_xor_si512(s3, s1);

                    s0 = Self::muladd_512::<M>(s0, s1, lut01);
                    s1 = _mm512_xor_si512(s1, s0);
                    s2 = Self::muladd_512::<M>(s2, s3, lut23);
                    s3 = _mm512_xor_si512(s3, s2);

                    _mm512_storeu_si512(s0_ptr, s0);
                    _mm512_storeu_si512(s1_ptr, s1);
                    _mm512_storeu_si512(s2_ptr, s2);
                    _mm512_storeu_si512(s3_ptr, s3);
                }
            }
            return;
        }

        // FIRST LAYER

        if log_m02 == GF_MODULUS {
            utils::xor(s2, s0);
            utils::xor(s3, s1);
        } else {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            unsafe {
                Self::fft_butterfly_partial(backend, s0, s2, log_m02);
                Self::fft_butterfly_partial(backend, s1, s3, log_m02);
            }
        }

        // SECOND LAYER

        if log_m01 == GF_MODULUS {
            utils::xor(s1, s0);
        } else {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            unsafe { Self::fft_butterfly_partial(backend, s0, s1, log_m01) };
        }

        if log_m23 == GF_MODULUS {
            utils::xor(s3, s2);
        } else {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            unsafe { Self::fft_butterfly_partial(backend, s2, s3, log_m23) };
        }
    }

    #[target_feature(enable = "avx512f,avx512vl,avx512bw")]
    unsafe fn fft_private_avx512(
        &self,
        backend: ShuffleBackend,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // SAFETY: This function establishes the target features required by ShuffleBackend.
        unsafe { self.fft_private(backend, data, pos, size, truncated_size, skew_delta) };
    }

    #[target_feature(enable = "avx512f,avx512vl,avx512bw,gfni")]
    unsafe fn fft_private_gfni(
        &self,
        backend: GfniBackend,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // SAFETY: This function establishes the target features required by GfniBackend.
        unsafe { self.fft_private(backend, data, pos, size, truncated_size, skew_delta) };
    }

    #[inline(always)]
    unsafe fn fft_private<M: Multiplication>(
        &self,
        backend: M,
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
                    // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
                    unsafe {
                        Self::fft_butterfly_two_layers(
                            backend,
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
                    // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
                    unsafe { Self::fft_butterfly_partial(backend, x, y, log_m) };
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
    unsafe fn ifft_butterfly_partial<M: Multiplication>(
        backend: M,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
        let lut = unsafe { backend.load(log_m) };

        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            // SAFETY: The wrapper establishes the backend's features; both disjoint chunks are exactly 64 bytes.
            unsafe {
                let x_ptr = x_chunk.as_mut_ptr().cast::<__m512i>();
                let y_ptr = y_chunk.as_mut_ptr().cast::<__m512i>();
                let mut x = _mm512_loadu_si512(x_ptr);
                let mut y = _mm512_loadu_si512(y_ptr);

                y = _mm512_xor_si512(y, x);
                x = Self::muladd_512::<M>(x, y, lut);

                _mm512_storeu_si512(x_ptr, x);
                _mm512_storeu_si512(y_ptr, y);
            }
        }
    }

    #[inline(always)]
    unsafe fn ifft_butterfly_two_layers<M: Multiplication>(
        backend: M,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        dist: usize,
        log_m01: GfElement,
        log_m23: GfElement,
        log_m02: GfElement,
    ) {
        let (s0, s1, s2, s3) = data.dist4_mut(pos, dist);

        // Skew uses `GF_MODULUS` for a zero coefficient, while multiplication tables use it
        // for the duplicated identity exponent.
        if log_m01 != GF_MODULUS && log_m23 != GF_MODULUS && log_m02 != GF_MODULUS {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            let (lut01, lut23, lut02) = unsafe {
                (
                    backend.load(log_m01),
                    backend.load(log_m23),
                    backend.load(log_m02),
                )
            };

            for (((s0_chunk, s1_chunk), s2_chunk), s3_chunk) in zip(
                zip(zip(s0.iter_mut(), s1.iter_mut()), s2.iter_mut()),
                s3.iter_mut(),
            ) {
                // SAFETY: The wrapper establishes the backend's features; all four disjoint chunks are exactly 64 bytes.
                unsafe {
                    let s0_ptr = s0_chunk.as_mut_ptr().cast::<__m512i>();
                    let s1_ptr = s1_chunk.as_mut_ptr().cast::<__m512i>();
                    let s2_ptr = s2_chunk.as_mut_ptr().cast::<__m512i>();
                    let s3_ptr = s3_chunk.as_mut_ptr().cast::<__m512i>();
                    let mut s0 = _mm512_loadu_si512(s0_ptr);
                    let mut s1 = _mm512_loadu_si512(s1_ptr);
                    let mut s2 = _mm512_loadu_si512(s2_ptr);
                    let mut s3 = _mm512_loadu_si512(s3_ptr);

                    s1 = _mm512_xor_si512(s1, s0);
                    s0 = Self::muladd_512::<M>(s0, s1, lut01);
                    s3 = _mm512_xor_si512(s3, s2);
                    s2 = Self::muladd_512::<M>(s2, s3, lut23);

                    s2 = _mm512_xor_si512(s2, s0);
                    s0 = Self::muladd_512::<M>(s0, s2, lut02);
                    s3 = _mm512_xor_si512(s3, s1);
                    s1 = Self::muladd_512::<M>(s1, s3, lut02);

                    _mm512_storeu_si512(s0_ptr, s0);
                    _mm512_storeu_si512(s1_ptr, s1);
                    _mm512_storeu_si512(s2_ptr, s2);
                    _mm512_storeu_si512(s3_ptr, s3);
                }
            }
            return;
        }

        // FIRST LAYER

        if log_m01 == GF_MODULUS {
            utils::xor(s1, s0);
        } else {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            unsafe { Self::ifft_butterfly_partial(backend, s0, s1, log_m01) };
        }

        if log_m23 == GF_MODULUS {
            utils::xor(s3, s2);
        } else {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            unsafe { Self::ifft_butterfly_partial(backend, s2, s3, log_m23) };
        }

        // SECOND LAYER

        if log_m02 == GF_MODULUS {
            utils::xor(s2, s0);
            utils::xor(s3, s1);
        } else {
            // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
            unsafe {
                Self::ifft_butterfly_partial(backend, s0, s2, log_m02);
                Self::ifft_butterfly_partial(backend, s1, s3, log_m02);
            }
        }
    }

    #[target_feature(enable = "avx512f,avx512vl,avx512bw")]
    unsafe fn ifft_private_avx512(
        &self,
        backend: ShuffleBackend,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // SAFETY: This function establishes the target features required by ShuffleBackend.
        unsafe { self.ifft_private(backend, data, pos, size, truncated_size, skew_delta) };
    }

    #[target_feature(enable = "avx512f,avx512vl,avx512bw,gfni")]
    unsafe fn ifft_private_gfni(
        &self,
        backend: GfniBackend,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // SAFETY: This function establishes the target features required by GfniBackend.
        unsafe { self.ifft_private(backend, data, pos, size, truncated_size, skew_delta) };
    }

    #[inline(always)]
    unsafe fn ifft_private<M: Multiplication>(
        &self,
        backend: M,
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
                    // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
                    unsafe {
                        Self::ifft_butterfly_two_layers(
                            backend,
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
                    // SAFETY: The target-feature wrapper matches the concrete multiplication backend.
                    unsafe {
                        Self::ifft_butterfly_partial(backend, &mut a[pos + i], &mut b[i], log_m)
                    };
                }
            }
        }
    }
}

// ======================================================================
// Avx512 - PRIVATE - Evaluate polynomial

impl Avx512 {
    #[target_feature(enable = "avx512f,avx512vl,avx512bw")]
    unsafe fn eval_poly_avx512(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        utils::eval_poly(erasures, truncated_size);
    }
}

// ======================================================================
// TESTS

#[cfg(test)]
mod tests {
    use super::{super::NoSimd, *};
    use commonware_utils::TestRng;
    use rand::Rng as _;

    fn engines() -> Option<(Avx512, Avx512)> {
        if !super::super::cpu_features::avx512() || !super::super::cpu_features::gfni() {
            return None;
        }

        let skew = tables::get_skew();
        Some((
            Avx512 {
                multiply: MultiplyBackend::Shuffle(tables::get_mul128()),
                skew,
            },
            Avx512 {
                multiply: MultiplyBackend::Gfni(tables::get_mul_gfni()),
                skew,
            },
        ))
    }

    #[test]
    fn gfni_all_multipliers_basis() {
        let Some((_, gfni)) = engines() else {
            return;
        };
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

    #[test]
    fn multiplication_backends_match() {
        let Some((shuffle, gfni)) = engines() else {
            return;
        };
        let mut rng = TestRng::new(8);

        for chunk_count in [0, 1, 16, 256] {
            let mut expected = vec![[0u8; SHARD_CHUNK_BYTES]; chunk_count];
            rng.fill_bytes(expected.as_flattened_mut());
            for log_m in [0, 1, 12_345, GF_MODULUS] {
                let mut actual = expected.clone();
                shuffle.mul(&mut expected, log_m);
                gfni.mul(&mut actual, log_m);
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn transform_backends_match() {
        let Some((shuffle, gfni)) = engines() else {
            return;
        };
        let mut rng = TestRng::new(9);

        for chunk_count in [1, 16, 256] {
            let mut input = vec![[0u8; SHARD_CHUNK_BYTES]; 128 * chunk_count];
            rng.fill_bytes(input.as_flattened_mut());

            for (inverse, truncated_size) in [(false, 128), (false, 77), (true, 128), (true, 77)] {
                let mut expected = input.clone();
                let mut actual = input.clone();
                if inverse {
                    expected[truncated_size * chunk_count..].fill([0; SHARD_CHUNK_BYTES]);
                    actual[truncated_size * chunk_count..].fill([0; SHARD_CHUNK_BYTES]);
                }
                let mut expected_shards =
                    ShardsRefMut::new(128, chunk_count, expected.as_mut_slice());
                let mut actual_shards = ShardsRefMut::new(128, chunk_count, actual.as_mut_slice());

                if inverse {
                    shuffle.ifft(&mut expected_shards, 0, 128, truncated_size, 0);
                    gfni.ifft(&mut actual_shards, 0, 128, truncated_size, 0);
                } else {
                    shuffle.fft(&mut expected_shards, 0, 128, truncated_size, 0);
                    gfni.fft(&mut actual_shards, 0, 128, truncated_size, 0);
                }
                assert_eq!(actual, expected, "inverse={inverse} chunks={chunk_count}");
            }
        }
    }

    #[test]
    fn fused_butterflies_match_nosimd() {
        let Some((shuffle, gfni)) = engines() else {
            return;
        };
        let skew = tables::get_skew();
        assert_eq!(skew[0], GF_MODULUS);
        assert_eq!(skew[1], GF_MODULUS);
        assert_eq!(skew[3], GF_MODULUS);
        assert!(skew[2] != GF_MODULUS);
        assert!(skew[4..=6].iter().all(|&log_m| log_m != GF_MODULUS));

        let nosimd = NoSimd::new();
        let mut rng = TestRng::new(10);
        for (pos, size, truncated_size, skew_delta, chunk_count) in [
            (1, 4, 4, 4, 0),
            (1, 4, 0, 4, 1),
            (1, 4, 4, 0, 1),
            (2, 4, 3, 1, 65),
            (3, 4, 2, 2, 1),
            (2, 4, 4, 4, 65),
            (1, 16, 13, 0, 1),
            (2, 64, 37, 17, 17),
        ] {
            let shard_count = pos + size + 2;
            let mut input = vec![[0u8; SHARD_CHUNK_BYTES]; shard_count * chunk_count];
            rng.fill_bytes(input.as_flattened_mut());

            for inverse in [false, true] {
                let mut expected = input.clone();
                if inverse {
                    expected[(pos + truncated_size) * chunk_count..(pos + size) * chunk_count]
                        .fill([0; SHARD_CHUNK_BYTES]);
                }
                let mut expected_shards =
                    ShardsRefMut::new(shard_count, chunk_count, expected.as_mut_slice());
                if inverse {
                    nosimd.ifft(&mut expected_shards, pos, size, truncated_size, skew_delta);
                } else {
                    nosimd.fft(&mut expected_shards, pos, size, truncated_size, skew_delta);
                }

                for (backend, engine) in [("shuffle", shuffle), ("gfni", gfni)] {
                    let mut actual = input.clone();
                    if inverse {
                        actual[(pos + truncated_size) * chunk_count..(pos + size) * chunk_count]
                            .fill([0; SHARD_CHUNK_BYTES]);
                    }
                    let mut actual_shards =
                        ShardsRefMut::new(shard_count, chunk_count, actual.as_mut_slice());
                    if inverse {
                        engine.ifft(&mut actual_shards, pos, size, truncated_size, skew_delta);
                    } else {
                        engine.fft(&mut actual_shards, pos, size, truncated_size, skew_delta);
                    }

                    assert_eq!(
                        actual, expected,
                        "backend={backend} inverse={inverse} pos={pos} size={size} truncated_size={truncated_size} skew_delta={skew_delta} chunks={chunk_count}"
                    );
                    assert_eq!(
                        &actual[..pos * chunk_count],
                        &input[..pos * chunk_count],
                        "prefix changed"
                    );
                    assert_eq!(
                        &actual[(pos + size) * chunk_count..],
                        &input[(pos + size) * chunk_count..],
                        "suffix changed"
                    );
                }
            }
        }
    }
}
