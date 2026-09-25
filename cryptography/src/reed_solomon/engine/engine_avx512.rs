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

/// Optimized [`Engine`] using AVX-512 instructions.
///
/// [`Avx512`] is an optimized engine that follows the same algorithm as
/// [`NoSimd`] but uses the x86 AVX-512F and GFNI instructions.
///
/// Construction and [`Engine::eval_poly`] panic if AVX-512F or GFNI is unavailable.
///
/// [`NoSimd`]: crate::reed_solomon::engine::NoSimd
#[derive(Clone, Copy)]
pub struct Avx512 {
    multiply: &'static MulGfni,
    skew: &'static Skew,
}

impl Avx512 {
    /// Creates a new [`Avx512`] and initializes its multiplication and skew [tables].
    ///
    /// Decoding builds its Walsh transform tables on first use.
    ///
    /// # Panics
    ///
    /// If AVX-512F or GFNI is unavailable.
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

        // SAFETY: Construction verifies the required features, and transform validation bounds all
        // offsets.
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

        // SAFETY: Construction verifies the required features, and transform validation bounds all
        // offsets.
        unsafe { self.ifft_private(data, pos, size, truncated_size, skew_delta) }
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        // SAFETY: Construction verifies the required features.
        unsafe { self.mul_private(x, log_m) }
    }

    fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        assert!(super::cpu_features::avx512());

        // SAFETY: The runtime check establishes all target features enabled by eval_poly_avx512.
        unsafe { Self::eval_poly_avx512(erasures, truncated_size) }
    }
}

impl Default for Avx512 {
    fn default() -> Self {
        Self::new()
    }
}

/// Affine matrices for one multiplier, laid out for a chunk of 32 low bytes followed by
/// 32 high bytes.
#[derive(Copy, Clone)]
struct LutGfni {
    /// `low_from_low` in each 64-bit lane of the low half, `high_from_high` in the high half.
    direct: __m512i,
    /// `low_from_high` in each 64-bit lane of the low half, `high_from_low` in the high half.
    cross: __m512i,
}

impl From<&MultiplyGfni> for LutGfni {
    #[inline(always)]
    fn from(lut: &MultiplyGfni) -> Self {
        // SAFETY: Only `Avx512` methods call this, and `Avx512::new` verifies AVX-512F.
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

impl Avx512 {
    #[target_feature(enable = "avx512f,gfni")]
    unsafe fn mul_private(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        let lut = LutGfni::from(&self.multiply[log_m as usize]);

        for chunk in x.iter_mut() {
            // SAFETY: This function enables the required features. Each chunk is exactly 64 bytes.
            unsafe {
                let x_ptr = chunk.as_mut_ptr().cast::<__m512i>();
                let x = _mm512_loadu_si512(x_ptr);
                let prod = Self::multiply_512(x, lut);
                _mm512_storeu_si512(x_ptr, prod);
            }
        }
    }

    /// Multiplies the 32 field elements of one chunk by the multiplier in `lut`.
    ///
    /// The low 256 bits hold the low bytes and the high 256 bits hold the high bytes.
    /// `direct` maps each half into the same output half. Shuffle immediate `0x4e` selects
    /// 128-bit lanes 2, 3, 0, 1, which swaps the halves, so `cross` maps each half into the
    /// other output half. Their XOR is the product.
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

    /// AVX-512 counterpart of LEO_MULADD_256. Returns `x ^ y * m`, where `lut` encodes `m`.
    #[inline(always)]
    unsafe fn muladd_512(x: __m512i, y: __m512i, lut: LutGfni) -> __m512i {
        // SAFETY: The caller executes within the AVX-512 and GFNI target-feature boundary.
        unsafe {
            let prod = Self::multiply_512(y, lut);
            _mm512_xor_si512(x, prod)
        }
    }
}

impl Avx512 {
    /// AVX-512 counterpart of LEO_FFTB_256. Computes `x ^= y * m`, then `y ^= x`.
    ///
    /// Partial butterfly. The caller handles a `GF_MODULUS` coefficient with `xor`.
    #[inline(always)]
    unsafe fn fft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        let lut = LutGfni::from(&self.multiply[log_m as usize]);

        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            // SAFETY: The caller enables the required features. Both disjoint chunks are exactly
            // 64 bytes.
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

        // With three nonzero coefficients, fuse both layers into one pass that loads and
        // stores each 64-byte chunk of the four shards once. Skew uses `GF_MODULUS` for a zero
        // coefficient, while multiplication tables use it for the duplicated identity exponent,
        // so a zero coefficient takes the per-layer path below.
        if log_m01 != GF_MODULUS && log_m23 != GF_MODULUS && log_m02 != GF_MODULUS {
            let lut01 = LutGfni::from(&self.multiply[log_m01 as usize]);
            let lut23 = LutGfni::from(&self.multiply[log_m23 as usize]);
            let lut02 = LutGfni::from(&self.multiply[log_m02 as usize]);

            for (((s0_chunk, s1_chunk), s2_chunk), s3_chunk) in zip(
                zip(zip(s0.iter_mut(), s1.iter_mut()), s2.iter_mut()),
                s3.iter_mut(),
            ) {
                // SAFETY: The caller enables AVX-512 and GFNI. All four disjoint chunks are exactly
                // 64 bytes.
                unsafe {
                    let s0_ptr = s0_chunk.as_mut_ptr().cast::<__m512i>();
                    let s1_ptr = s1_chunk.as_mut_ptr().cast::<__m512i>();
                    let s2_ptr = s2_chunk.as_mut_ptr().cast::<__m512i>();
                    let s3_ptr = s3_chunk.as_mut_ptr().cast::<__m512i>();
                    let mut s0 = _mm512_loadu_si512(s0_ptr);
                    let mut s1 = _mm512_loadu_si512(s1_ptr);
                    let mut s2 = _mm512_loadu_si512(s2_ptr);
                    let mut s3 = _mm512_loadu_si512(s3_ptr);

                    // First layer: (s0, s2) and (s1, s3) with `lut02`.
                    s0 = Self::muladd_512(s0, s2, lut02);
                    s2 = _mm512_xor_si512(s2, s0);
                    s1 = Self::muladd_512(s1, s3, lut02);
                    s3 = _mm512_xor_si512(s3, s1);

                    // Second layer: (s0, s1) with `lut01` and (s2, s3) with `lut23`.
                    s0 = Self::muladd_512(s0, s1, lut01);
                    s1 = _mm512_xor_si512(s1, s0);
                    s2 = Self::muladd_512(s2, s3, lut23);
                    s3 = _mm512_xor_si512(s3, s2);

                    _mm512_storeu_si512(s0_ptr, s0);
                    _mm512_storeu_si512(s1_ptr, s1);
                    _mm512_storeu_si512(s2_ptr, s2);
                    _mm512_storeu_si512(s3_ptr, s3);
                }
            }
            return;
        }

        // First layer: (s0, s2) and (s1, s3).
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

        // Second layer: (s0, s1) and (s2, s3).
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

    #[target_feature(enable = "avx512f,gfni")]
    unsafe fn fft_private(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // Apply two butterfly layers per pass.
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

        // An odd log2(size) leaves one final layer.
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

impl Avx512 {
    /// AVX-512 counterpart of LEO_IFFTB_256. Computes `y ^= x`, then `x ^= y * m`.
    #[inline(always)]
    unsafe fn ifft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        let lut = LutGfni::from(&self.multiply[log_m as usize]);

        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter_mut()) {
            // SAFETY: The caller enables the required features. Both disjoint chunks are exactly
            // 64 bytes.
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

        // With three nonzero coefficients, fuse both layers into one pass that loads and
        // stores each 64-byte chunk of the four shards once. Skew uses `GF_MODULUS` for a zero
        // coefficient, while multiplication tables use it for the duplicated identity exponent,
        // so a zero coefficient takes the per-layer path below.
        if log_m01 != GF_MODULUS && log_m23 != GF_MODULUS && log_m02 != GF_MODULUS {
            let lut01 = LutGfni::from(&self.multiply[log_m01 as usize]);
            let lut23 = LutGfni::from(&self.multiply[log_m23 as usize]);
            let lut02 = LutGfni::from(&self.multiply[log_m02 as usize]);

            for (((s0_chunk, s1_chunk), s2_chunk), s3_chunk) in zip(
                zip(zip(s0.iter_mut(), s1.iter_mut()), s2.iter_mut()),
                s3.iter_mut(),
            ) {
                // SAFETY: The caller enables AVX-512 and GFNI. All four disjoint chunks are exactly
                // 64 bytes.
                unsafe {
                    let s0_ptr = s0_chunk.as_mut_ptr().cast::<__m512i>();
                    let s1_ptr = s1_chunk.as_mut_ptr().cast::<__m512i>();
                    let s2_ptr = s2_chunk.as_mut_ptr().cast::<__m512i>();
                    let s3_ptr = s3_chunk.as_mut_ptr().cast::<__m512i>();
                    let mut s0 = _mm512_loadu_si512(s0_ptr);
                    let mut s1 = _mm512_loadu_si512(s1_ptr);
                    let mut s2 = _mm512_loadu_si512(s2_ptr);
                    let mut s3 = _mm512_loadu_si512(s3_ptr);

                    // First layer: (s0, s1) with `lut01` and (s2, s3) with `lut23`.
                    s1 = _mm512_xor_si512(s1, s0);
                    s0 = Self::muladd_512(s0, s1, lut01);
                    s3 = _mm512_xor_si512(s3, s2);
                    s2 = Self::muladd_512(s2, s3, lut23);

                    // Second layer: (s0, s2) and (s1, s3) with `lut02`.
                    s2 = _mm512_xor_si512(s2, s0);
                    s0 = Self::muladd_512(s0, s2, lut02);
                    s3 = _mm512_xor_si512(s3, s1);
                    s1 = Self::muladd_512(s1, s3, lut02);

                    _mm512_storeu_si512(s0_ptr, s0);
                    _mm512_storeu_si512(s1_ptr, s1);
                    _mm512_storeu_si512(s2_ptr, s2);
                    _mm512_storeu_si512(s3_ptr, s3);
                }
            }
            return;
        }

        // First layer: (s0, s1) and (s2, s3).
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

        // Second layer: (s0, s2) and (s1, s3).
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

    #[target_feature(enable = "avx512f,gfni")]
    unsafe fn ifft_private(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        // Apply two butterfly layers per pass.
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

        // An odd log2(size) leaves one final layer.
        if dist < size {
            let log_m = self.skew[dist + skew_delta - 1];
            if log_m == GF_MODULUS {
                utils::xor_within(data, pos + dist, pos, dist);
            } else {
                let (mut a, mut b) = data.split_at_mut(pos + dist);
                for i in 0..dist {
                    // SAFETY: This function enables the required features.
                    unsafe {
                        self.ifft_butterfly_partial(
                            &mut a[pos + i], // data[pos + i]
                            &mut b[i],       // data[pos + i + dist]
                            log_m,
                        )
                    };
                }
            }
        }
    }
}

impl Avx512 {
    #[target_feature(enable = "avx512f,gfni")]
    unsafe fn eval_poly_avx512(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        utils::eval_poly(erasures, truncated_size);
    }
}

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
