//! GF(2^16) Reed-Solomon engine wrapping the `reed-solomon-simd` crate.
//!
//! This engine delegates to `reed-solomon-simd`'s Leopard-RS FFT-based algorithm,
//! which supports up to 65535 total shards. It is the default engine used by
//! [`super::ReedSolomon`].

use super::Engine;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

/// GF(2^16) Reed-Solomon engine using `reed-solomon-simd`.
///
/// Supports up to 65535 total shards. Uses a Leopard-RS FFT-based algorithm that
/// is optimized for large shard counts but has higher overhead at small counts
/// compared to direct matrix approaches.
#[derive(Clone, Debug)]
pub struct Gf16;

impl Engine for Gf16 {
    type Error = reed_solomon_simd::Error;

    /// `reed-solomon-simd` requires even shard lengths for internal optimizations.
    const SHARD_ALIGNMENT: usize = 2;

    fn max_shards() -> usize {
        65535
    }

    fn encode(k: usize, m: usize, original: &[&[u8]]) -> Result<Vec<Vec<u8>>, Self::Error> {
        let shard_len = original[0].len();
        let mut encoder = ReedSolomonEncoder::new(k, m, shard_len)?;
        for shard in original {
            encoder.add_original_shard(shard)?;
        }
        let encoding = encoder.encode()?;
        Ok(encoding.recovery_iter().map(|s| s.to_vec()).collect())
    }

    fn decode(
        k: usize,
        m: usize,
        shard_len: usize,
        original: &[(usize, &[u8])],
        recovery: &[(usize, &[u8])],
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        let mut decoder = ReedSolomonDecoder::new(k, m, shard_len)?;
        for &(idx, shard) in original {
            decoder.add_original_shard(idx, shard)?;
        }
        for &(idx, shard) in recovery {
            decoder.add_recovery_shard(idx, shard)?;
        }
        let decoding = decoder.decode()?;

        let mut result = vec![vec![0u8; shard_len]; k];
        for &(idx, shard) in original {
            result[idx] = shard.to_vec();
        }
        for (idx, shard) in decoding.restored_original_iter() {
            result[idx] = shard.to_vec();
        }
        Ok(result)
    }
}
