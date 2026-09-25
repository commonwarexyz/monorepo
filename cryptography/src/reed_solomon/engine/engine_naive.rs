use crate::reed_solomon::engine::{
    Engine, GF_MODULUS, GfElement, SHARD_CHUNK_BYTES, ShardsRefMut,
    tables::{self, Exp, Log, Skew},
    utils,
};

/// Simple reference implementation of [`Engine`].
///
/// - [`Naive`] is meant for those who want to study
///   the source code to understand [`Engine`].
/// - [`Naive`] also includes some assertions
///   which are not present in other implementations.
#[derive(Clone, Copy)]
pub struct Naive {
    exp: &'static Exp,
    log: &'static Log,
    skew: &'static Skew,
}

impl Naive {
    /// Creates a new [`Naive`] and initializes its multiplication and skew [tables].
    ///
    /// Decoding builds its Walsh transform tables on first use.
    pub fn new() -> Self {
        let exp_log = tables::get_exp_log();
        let skew = tables::get_skew();

        Self {
            exp: &exp_log.exp,
            log: &exp_log.log,
            skew,
        }
    }
}

impl Engine for Naive {
    fn fft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        super::validate_transform(data, pos, size, truncated_size, skew_delta);

        let mut dist = size / 2;
        while dist > 0 {
            let mut r = 0;
            while r < truncated_size {
                let log_m = self.skew[r + dist + skew_delta - 1];
                for i in r..r + dist {
                    let (a, b) = data.dist2_mut(pos + i, dist);

                    // FFT butterfly.
                    if log_m != GF_MODULUS {
                        self.mul_add(a, b, log_m);
                    }
                    utils::xor(b, a);
                }
                r += dist * 2;
            }
            dist /= 2;
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

        let mut dist = 1;
        while dist < size {
            let mut r = 0;
            while r < truncated_size {
                let log_m = self.skew[r + dist + skew_delta - 1];
                for i in r..r + dist {
                    let (a, b) = data.dist2_mut(pos + i, dist);

                    // IFFT butterfly.
                    utils::xor(b, a);
                    if log_m != GF_MODULUS {
                        self.mul_add(a, b, log_m);
                    }
                }
                r += dist * 2;
            }
            dist *= 2;
        }
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        for chunk in x.iter_mut() {
            for i in 0..SHARD_CHUNK_BYTES / 2 {
                let lo = GfElement::from(chunk[i]);
                let hi = GfElement::from(chunk[i + SHARD_CHUNK_BYTES / 2]);
                let prod = tables::mul(lo | (hi << 8), log_m, self.exp, self.log);
                chunk[i] = prod as u8;
                chunk[i + SHARD_CHUNK_BYTES / 2] = (prod >> 8) as u8;
            }
        }
    }
}

impl Default for Naive {
    fn default() -> Self {
        Self::new()
    }
}

impl Naive {
    /// Computes `x[] ^= y[] * log_m`.
    fn mul_add(
        &self,
        x: &mut [[u8; SHARD_CHUNK_BYTES]],
        y: &[[u8; SHARD_CHUNK_BYTES]],
        log_m: GfElement,
    ) {
        assert_eq!(x.len(), y.len());

        for (x_chunk, y_chunk) in core::iter::zip(x.iter_mut(), y.iter()) {
            for i in 0..SHARD_CHUNK_BYTES / 2 {
                let lo = GfElement::from(y_chunk[i]);
                let hi = GfElement::from(y_chunk[i + SHARD_CHUNK_BYTES / 2]);
                let prod = tables::mul(lo | (hi << 8), log_m, self.exp, self.log);
                x_chunk[i] ^= prod as u8;
                x_chunk[i + SHARD_CHUNK_BYTES / 2] ^= (prod >> 8) as u8;
            }
        }
    }
}
