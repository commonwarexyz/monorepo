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

pub use self::{
    decoder_result::{DecoderResult, Originals, Recoveries, RecoveryDecoderResult},
    encoder_result::{EncoderResult, Recovery},
    engine::SHARD_CHUNK_BYTES,
    wrappers::{Decoder, Encoder},
};
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
    /// Given shard has different size than the configured shard size.
    #[error("different shard size: expected {shard_bytes} bytes, got {got} bytes")]
    DifferentShardSize {
        /// Configured shard size.
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

    /// Configured shard size is invalid: size must be non-zero and even.
    #[error("invalid shard size: {shard_bytes} bytes (must non-zero and multiple of 2)")]
    InvalidShardSize {
        /// Configured shard size.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{engine::DefaultEngine, rate::DefaultRate};

    #[test]
    fn roundtrip() {
        let original = test_util::generate_original(2, 1024, 123);

        let mut encoder = Encoder::new(2, 3, 1024).unwrap();
        for shard in &original {
            encoder.add_original_shard(shard).unwrap();
        }
        let encoding = encoder.encode().unwrap();
        let recovery: Vec<_> = encoding.recovery_iter().map(<[u8]>::to_vec).collect();

        test_util::assert_hash(&recovery, test_util::LOW_2_3);

        let mut decoder = Decoder::new(2, 3, 1024).unwrap();
        decoder.add_recovery_shard(0, &recovery[0]).unwrap();
        decoder.add_recovery_shard(1, &recovery[1]).unwrap();
        let decoding = decoder.decode().unwrap().unwrap();
        let mut restored = decoding.original_iter();

        assert_eq!(restored.next(), Some((0, original[0].as_slice())));
        assert_eq!(restored.next(), Some((1, original[1].as_slice())));
        assert_eq!(restored.next(), None);
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Encoder>();
        assert_send::<Decoder>();
        assert_send::<DefaultEngine>();
        assert_send::<DefaultRate<DefaultEngine>>();
        assert_send::<DecoderResult<'_>>();
        assert_send::<RecoveryDecoderResult<'_>>();
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
        assert_sync::<RecoveryDecoderResult<'_>>();
        assert_sync::<EncoderResult<'_>>();
        assert_sync::<Error>();
    }
}
