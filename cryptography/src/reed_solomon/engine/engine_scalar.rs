use crate::reed_solomon::engine::{
    Engine, GF_MODULUS, GfElement, SHARD_CHUNK_BYTES, ShardsRefMut,
    tables::{self, Mul16, Skew},
    utils,
};
use core::iter::zip;

/// Portable [`Engine`] without SIMD.
///
/// [`Scalar`] works on all CPUs. It multiplies one field element at a time with four lookups in
/// the nibble tables of [`Mul16`].
#[derive(Clone, Copy)]
pub struct Scalar {
    mul16: &'static Mul16,
    skew: &'static Skew,
}

impl Scalar {
    /// Creates a new [`Scalar`] and initializes its multiplication and skew [tables].
    ///
    /// Decoding builds its Walsh transform tables on first use.
    pub fn new() -> Self {
        let mul16 = tables::get_mul16();
        let skew = tables::get_skew();

        Self { mul16, skew }
    }
}

impl Engine for Scalar {
    fn fft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        super::validate_transform(data, pos, size, truncated_size, skew_delta);
        self.fft_private(data, pos, size, truncated_size, skew_delta);
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
        self.ifft_private(data, pos, size, truncated_size, skew_delta);
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        let lut = &self.mul16[log_m as usize];

        for x_chunk in x.iter_mut() {
            let (x_lo, x_hi) = x_chunk.split_at_mut(SHARD_CHUNK_BYTES / 2);

            for i in 0..SHARD_CHUNK_BYTES / 2 {
                let lo = x_lo[i];
                let hi = x_hi[i];
                let prod = lut[0][usize::from(lo & 15)]
                    ^ lut[1][usize::from(lo >> 4)]
                    ^ lut[2][usize::from(hi & 15)]
                    ^ lut[3][usize::from(hi >> 4)];
                x_lo[i] = prod as u8;
                x_hi[i] = (prod >> 8) as u8;
            }
        }
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::new()
    }
}

impl Scalar {
    /// Computes `x ^= y * m` for each chunk, where `m` is the field element with logarithm
    /// `log_m`.
    ///
    /// Processes `min(x.len(), y.len())` chunks.
    fn mul_add(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &[[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        let lut = &self.mul16[log_m as usize];

        for (x_chunk, y_chunk) in zip(x.iter_mut(), y.iter()) {
            let (x_lo, x_hi) = x_chunk.split_at_mut(SHARD_CHUNK_BYTES / 2);
            let (y_lo, y_hi) = y_chunk.split_at(SHARD_CHUNK_BYTES / 2);

            for i in 0..SHARD_CHUNK_BYTES / 2 {
                let lo = y_lo[i];
                let hi = y_hi[i];
                let prod = lut[0][usize::from(lo & 15)]
                    ^ lut[1][usize::from(lo >> 4)]
                    ^ lut[2][usize::from(hi & 15)]
                    ^ lut[3][usize::from(hi >> 4)];
                x_lo[i] ^= prod as u8;
                x_hi[i] ^= (prod >> 8) as u8;
            }
        }
    }
}

impl Scalar {
    /// Partial butterfly. The caller handles a `GF_MODULUS` coefficient with `xor`.
    #[inline(always)]
    fn fft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        self.mul_add(x, y, log_m);
        utils::xor(y, x);
    }

    /// Applies two FFT layers to shards `pos`, `pos + dist`, `pos + 2 * dist`, and
    /// `pos + 3 * dist`.
    ///
    /// A `GF_MODULUS` coefficient encodes zero, so its butterfly reduces to an XOR.
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

        // First layer: (s0, s2) and (s1, s3).
        if log_m02 == GF_MODULUS {
            utils::xor(s2, s0);
            utils::xor(s3, s1);
        } else {
            self.fft_butterfly_partial(s0, s2, log_m02);
            self.fft_butterfly_partial(s1, s3, log_m02);
        }

        // Second layer: (s0, s1) and (s2, s3).
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

    /// In-place FFT of `data[pos..pos + size]`, as specified by [`Engine::fft`].
    #[inline(always)]
    fn fft_private(
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
                    self.fft_butterfly_two_layers(data, pos + i, dist, log_m01, log_m23, log_m02);
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
                    self.fft_butterfly_partial(x, y, log_m);
                }

                r += 2;
            }
        }
    }
}

impl Scalar {
    /// Partial IFFT butterfly. The caller handles a `GF_MODULUS` coefficient with `xor`.
    #[inline(always)]
    fn ifft_butterfly_partial(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &mut [[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        utils::xor(y, x);
        self.mul_add(x, y, log_m);
    }

    /// Applies two IFFT layers to shards `pos`, `pos + dist`, `pos + 2 * dist`, and
    /// `pos + 3 * dist`.
    ///
    /// A `GF_MODULUS` coefficient encodes zero, so its butterfly reduces to an XOR.
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

        // First layer: (s0, s1) and (s2, s3).
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

        // Second layer: (s0, s2) and (s1, s3).
        if log_m02 == GF_MODULUS {
            utils::xor(s2, s0);
            utils::xor(s3, s1);
        } else {
            self.ifft_butterfly_partial(s0, s2, log_m02);
            self.ifft_butterfly_partial(s1, s3, log_m02);
        }
    }

    /// In-place IFFT of `data[pos..pos + size]`, as specified by [`Engine::ifft`].
    #[inline(always)]
    fn ifft_private(
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
                    self.ifft_butterfly_two_layers(data, pos + i, dist, log_m01, log_m23, log_m02);
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

#[cfg(test)]
mod tests {
    use crate::reed_solomon::engine::{Engine, Naive, SHARD_CHUNK_BYTES, Scalar};
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use rand::{Rng, RngExt as _, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn mul() {
        let naive = Naive::default();
        let scalar = Scalar::default();

        let mut rng = ChaCha8Rng::from_seed([0; 32]);

        for shard_chunks in 0..6 {
            let mut data_scalar = vec![[0; SHARD_CHUNK_BYTES]; shard_chunks];
            rng.fill_bytes(data_scalar.as_flattened_mut());
            let mut data_naive = data_scalar.clone();

            let log_m = rng.random();

            scalar.mul(&mut data_scalar, log_m);
            naive.mul(&mut data_naive, log_m);

            assert_eq!(data_scalar, data_naive);
        }
    }
}
