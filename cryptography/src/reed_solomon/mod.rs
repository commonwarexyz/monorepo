//! Vendored version of [`reed_solomon_simd`].
//!
//! # Changes vs. Upstream
//!
//! - Moved the crate into `commonware_cryptography::reed_solomon` and rewrote internal
//!   `crate::` paths accordingly.
//! - Retained the upstream `LICENSE` file, including the BSD-3-Clause notice for Leopard-RS.
//! - Removed the build script and README rustdoc generation.
//! - Removed upstream examples. Kept upstream-style benchmarks under Commonware's benchmark layout
//!   and naming rules.
//! - Uses workspace dependencies and [`commonware_formatting`] in the test harness.
//! - Uses [`thiserror`] for error display formatting.
//! - Renamed upstream `ReedSolomonEncoder` and `ReedSolomonDecoder` to [`Encoder`] and [`Decoder`].
//! - Uses plain code references for cfg-gated SIMD engine docs so rustdoc works on all targets.
//!
//! [`reed_solomon_simd`]: https://crates.io/crates/reed-solomon-simd
//! [`thiserror`]: https://docs.rs/thiserror

extern crate alloc;

pub use self::{
    decoder_result::{DecoderResult, RestoredOriginal},
    encoder_result::{EncoderResult, Recovery},
    engine::SHARD_CHUNK_BYTES,
    wrappers::{Decoder, Encoder},
};
use alloc::{collections::BTreeMap, vec::Vec};
use thiserror::Error;

#[cfg(test)]
#[macro_use]
mod test_util;

mod decoder_result;
mod encoder_result;
mod wrappers;

pub mod algorithm {
    #![doc = include_str!("algorithm.md")]
}
pub mod engine;
pub mod rate;

/// Represents all possible errors that can occur in this library.
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum Error {
    /// Given shard has different size than given or inferred shard size.
    ///
    /// - Shard size is given explicitly to encoders/decoders
    ///   and inferred for [`encode`] and [`decode`].
    #[error("different shard size: expected {shard_bytes} bytes, got {got} bytes")]
    DifferentShardSize {
        /// Given or inferred shard size.
        shard_bytes: usize,
        /// Size of the given shard.
        got: usize,
    },

    /// Decoder was given two original shards with same index.
    #[error("duplicate original shard index: {index}")]
    DuplicateOriginalShardIndex {
        /// Given duplicate index.
        index: usize,
    },

    /// Decoder was given two recovery shards with same index.
    #[error("duplicate recovery shard index: {index}")]
    DuplicateRecoveryShardIndex {
        /// Given duplicate index.
        index: usize,
    },

    /// Decoder was given original shard with invalid index,
    /// i.e. `index >= original_count`.
    #[error("invalid original shard index: {index} >= original_count {original_count}")]
    InvalidOriginalShardIndex {
        /// Configured number of original shards.
        original_count: usize,
        /// Given invalid index.
        index: usize,
    },

    /// Decoder was given recovery shard with invalid index,
    /// i.e. `index >= recovery_count`.
    #[error("invalid recovery shard index: {index} >= recovery_count {recovery_count}")]
    InvalidRecoveryShardIndex {
        /// Configured number of recovery shards.
        recovery_count: usize,
        /// Given invalid index.
        index: usize,
    },

    /// Given or inferred shard size is invalid:
    /// Size must be non-zero and even.
    ///
    /// - Shard size is given explicitly to encoders/decoders
    ///   and inferred for [`encode`] and [`decode`].
    #[error("invalid shard size: {shard_bytes} bytes (must non-zero and multiple of 2)")]
    InvalidShardSize {
        /// Given or inferred shard size.
        shard_bytes: usize,
    },

    /// Decoder was given too few shards.
    ///
    /// Decoding requires as many shards as there were original shards
    /// in total, in any combination of original shards and recovery shards.
    #[error(
        "not enough shards: {original_received_count} original + {recovery_received_count} recovery < {original_count} original_count"
    )]
    NotEnoughShards {
        /// Configured number of original shards.
        original_count: usize,
        /// Number of original shards given to decoder.
        original_received_count: usize,
        /// Number of recovery shards given to decoder.
        recovery_received_count: usize,
    },

    /// Encoder was given less than `original_count` original shards.
    #[error(
        "too few original shards: got {original_received_count} shards while original_count is {original_count}"
    )]
    TooFewOriginalShards {
        /// Configured number of original shards.
        original_count: usize,
        /// Number of original shards given to encoder.
        original_received_count: usize,
    },

    /// Encoder was given more than `original_count` original shards.
    #[error("too many original shards: got more than original_count ({original_count}) shards")]
    TooManyOriginalShards {
        /// Configured number of original shards.
        original_count: usize,
    },

    /// Given `original_count` / `recovery_count` combination is not supported.
    #[error(
        "unsupported shard count: {original_count} original shards with {recovery_count} recovery shards"
    )]
    UnsupportedShardCount {
        /// Given number of original shards.
        original_count: usize,
        /// Given number of recovery shards.
        recovery_count: usize,
    },
}

/// Encodes in one go using [`Encoder`], returning generated recovery shards.
pub fn encode<T>(
    original_count: usize,
    recovery_count: usize,
    original: T,
) -> Result<Vec<Vec<u8>>, Error>
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    if !Encoder::supports(original_count, recovery_count) {
        return Err(Error::UnsupportedShardCount {
            original_count,
            recovery_count,
        });
    }

    let mut original = original.into_iter();
    let (shard_bytes, first) = original.next().map_or_else(
        || {
            Err(Error::TooFewOriginalShards {
                original_count,
                original_received_count: 0,
            })
        },
        |first| Ok((first.as_ref().len(), first)),
    )?;

    let mut encoder = Encoder::new(original_count, recovery_count, shard_bytes)?;

    encoder.add_original_shard(first)?;
    for original in original {
        encoder.add_original_shard(original)?;
    }

    let result = encoder.encode()?;

    Ok(result.recovery_iter().map(<[u8]>::to_vec).collect())
}

/// Decodes in one go using [`Decoder`], returning restored original shards
/// with their indexes.
pub fn decode<O, R, OT, RT>(
    original_count: usize,
    recovery_count: usize,
    original: O,
    recovery: R,
) -> Result<BTreeMap<usize, Vec<u8>>, Error>
where
    O: IntoIterator<Item = (usize, OT)>,
    R: IntoIterator<Item = (usize, RT)>,
    OT: AsRef<[u8]>,
    RT: AsRef<[u8]>,
{
    if !Decoder::supports(original_count, recovery_count) {
        return Err(Error::UnsupportedShardCount {
            original_count,
            recovery_count,
        });
    }

    let original = original.into_iter();
    let mut recovery = recovery.into_iter();

    let (shard_bytes, first_recovery) = if let Some(first_recovery) = recovery.next() {
        (first_recovery.1.as_ref().len(), first_recovery)
    } else {
        let original_received_count = original.count();
        if original_received_count == original_count {
            return Ok(BTreeMap::new());
        }

        return Err(Error::NotEnoughShards {
            original_count,
            original_received_count,
            recovery_received_count: 0,
        });
    };

    let mut decoder = Decoder::new(original_count, recovery_count, shard_bytes)?;

    for (index, original) in original {
        decoder.add_original_shard(index, original)?;
    }

    decoder.add_recovery_shard(first_recovery.0, first_recovery.1)?;
    for (index, recovery) in recovery {
        decoder.add_recovery_shard(index, recovery)?;
    }

    let mut result = BTreeMap::new();
    for (index, original) in decoder.decode()?.restored_original_iter() {
        result.insert(index, original.to_vec());
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{engine::DefaultEngine, rate::DefaultRate};

    #[test]
    fn roundtrip() {
        let original = test_util::generate_original(2, 1024, 123);
        let recovery = encode(2, 3, &original).unwrap();

        test_util::assert_hash(&recovery, test_util::LOW_2_3);

        let restored = decode(2, 3, [(0, ""); 0], [(0, &recovery[0]), (1, &recovery[1])]).unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[&0], original[0]);
        assert_eq!(restored[&1], original[1]);
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Encoder>();
        assert_send::<Decoder>();
        assert_send::<DefaultEngine>();
        assert_send::<DefaultRate<DefaultEngine>>();
        assert_send::<DecoderResult<'_>>();
        assert_send::<EncoderResult<'_>>();
        assert_send::<Error>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Encoder>();
        assert_sync::<Decoder>();
        assert_sync::<DefaultEngine>();
        assert_sync::<DefaultRate<DefaultEngine>>();
        assert_sync::<DecoderResult<'_>>();
        assert_sync::<EncoderResult<'_>>();
        assert_sync::<Error>();
    }
}
