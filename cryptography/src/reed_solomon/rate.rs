//! Advanced encoding/decoding using chosen [`Engine`] and [`Rate`].
//!
//! **This is an advanced module which is not needed for [basic usage].**
//!
//! This module is relevant if you want to
//! - encode/decode using other [`Engine`] than [`DefaultEngine`].
//! - re-use working space of one encoder/decoder in another.
//! - understand/benchmark/test high or low rate directly.
//!
//! # Rates
//!
//! See [algorithm > Rate] for details about high/low rate.
//!
//! - [`DefaultRate`], [`DefaultRateEncoder`], [`DefaultRateDecoder`]
//!     - Encoding/decoding using high or low rate as appropriate.
//!     - These are basically same as [`Encoder`]
//!       and [`Decoder`] except with slightly different API
//!       which allows specifying [`Engine`] and working space.
//! - [`HighRate`], [`HighRateEncoder`], [`HighRateDecoder`]
//!     - Encoding/decoding using only high rate.
//! - [`LowRate`], [`LowRateEncoder`], [`LowRateDecoder`]
//!     - Encoding/decoding using only low rate.
//!
//! [basic usage]: crate::reed_solomon#basic-usage
//! [algorithm > Rate]: crate::reed_solomon::algorithm#rate
//! [`Encoder`]: crate::reed_solomon::Encoder
//! [`Decoder`]: crate::reed_solomon::Decoder
//! [`DefaultEngine`]: crate::reed_solomon::engine::DefaultEngine

pub use self::{
    decoder_work::DecoderWork,
    encoder_work::EncoderWork,
    rate_default::{DefaultRate, DefaultRateDecoder, DefaultRateEncoder},
    rate_high::{HighRate, HighRateDecoder, HighRateEncoder},
    rate_low::{LowRate, LowRateDecoder, LowRateEncoder},
};
use crate::reed_solomon::{
    DecoderResult, EncoderResult, Error,
    engine::{self, Engine, GF_ORDER, GfElement, SHARD_CHUNK_BYTES},
};

mod decoder_work;
mod encoder_work;
pub(crate) mod rate_default;
pub(crate) mod rate_high;
pub(crate) mod rate_low;

/// Returns [`Error::InvalidShardSize`] if `work_count` shards of `shard_bytes` bytes, each
/// rounded up to whole `SHARD_CHUNK_BYTES` chunks, exceed `isize::MAX` bytes in total.
///
/// # Panics
///
/// Panics if `work_count` is zero.
const fn validate_work_size(shard_bytes: usize, work_count: usize) -> Result<(), Error> {
    // The chunk array must fit within Vec's maximum allocation size.
    let max_chunks = isize::MAX as usize / SHARD_CHUNK_BYTES;
    if shard_bytes.div_ceil(SHARD_CHUNK_BYTES) > max_chunks / work_count {
        return Err(Error::InvalidShardSize { shard_bytes });
    }
    Ok(())
}

/// XOR-convolve `erasures` with the field logarithm table.
///
/// `erasures` holds `n = end.next_power_of_two()` entries, and entries at and after `end` must
/// be zero. Because `i ^ j < n` for all `i, j < n`, the `n`-point transform matches the first
/// `n` outputs of the full-field one.
///
/// # Panics
///
/// If `erasures.len() != end.next_power_of_two()` or `end > GF_ORDER`.
fn eval_locator<E: Engine>(erasures: &mut [GfElement], end: usize) {
    let n = erasures.len();
    assert_eq!(n, end.next_power_of_two());
    if n == GF_ORDER {
        E::eval_poly(erasures.try_into().expect("length is GF_ORDER"), end);
    } else {
        engine::utils::eval_poly_short(erasures, end);
    }
}

/// Reed-Solomon encoder/decoder generator using specific rate.
pub trait Rate<E: Engine> {
    /// Encoder of this rate.
    type RateEncoder: RateEncoder<E>;
    /// Decoder of this rate.
    type RateDecoder: RateDecoder<E>;

    /// Returns `true` if given `original_count` / `recovery_count`
    /// combination is supported.
    fn supports(original_count: usize, recovery_count: usize) -> bool;

    /// Creates new encoder. This is same as [`RateEncoder::new`].
    fn encoder(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<EncoderWork>,
    ) -> Result<Self::RateEncoder, Error> {
        Self::RateEncoder::new(original_count, recovery_count, shard_bytes, engine, work)
    }

    /// Creates new decoder. This is same as [`RateDecoder::new`].
    fn decoder(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<DecoderWork>,
    ) -> Result<Self::RateDecoder, Error> {
        Self::RateDecoder::new(original_count, recovery_count, shard_bytes, engine, work)
    }

    /// Checks that the shard counts are supported and the shard size is nonzero and even.
    ///
    /// Use [`RateEncoder::validate`] or [`RateDecoder::validate`] to also check the
    /// working-space requirements of the chosen operation.
    fn validate(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        if !Self::supports(original_count, recovery_count) {
            Err(Error::UnsupportedShardCount {
                original_count,
                recovery_count,
            })
        } else if shard_bytes == 0 || shard_bytes & 1 != 0 {
            Err(Error::InvalidShardSize { shard_bytes })
        } else {
            Ok(())
        }
    }
}

/// Reed-Solomon encoder using specific rate.
pub trait RateEncoder<E: Engine>
where
    Self: Sized,
{
    /// Rate of this encoder.
    type Rate: Rate<E>;

    /// Like [`Encoder::add_original_shard`](crate::reed_solomon::Encoder::add_original_shard).
    fn add_original_shard<T: AsRef<[u8]>>(&mut self, original_shard: T) -> Result<(), Error>;

    /// Like [`Encoder::encode`](crate::reed_solomon::Encoder::encode).
    fn encode(&mut self) -> Result<EncoderResult<'_>, Error>;

    /// Consumes this encoder returning its [`Engine`] and [`EncoderWork`]
    /// so that they can be re-used by another encoder.
    fn into_parts(self) -> (E, EncoderWork);

    /// Like [`Encoder::new`](crate::reed_solomon::Encoder::new)
    /// with [`Engine`] to use and optional working space to be re-used.
    fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<EncoderWork>,
    ) -> Result<Self, Error>;

    /// Like [`Encoder::reset`](crate::reed_solomon::Encoder::reset).
    fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error>;

    /// Checks that the shard counts are supported, the shard size is nonzero and even, and
    /// this encoder's working space fits in a single allocation.
    fn validate(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error>;

    /// Returns `true` if given `original_count` / `recovery_count`
    /// combination is supported.
    ///
    /// This is same as [`Rate::supports`].
    fn supports(original_count: usize, recovery_count: usize) -> bool {
        Self::Rate::supports(original_count, recovery_count)
    }
}

/// Reed-Solomon decoder using specific rate.
pub trait RateDecoder<E: Engine>
where
    Self: Sized,
{
    /// Rate of this decoder.
    type Rate: Rate<E>;

    /// Like [`Decoder::add_original_shard`](crate::reed_solomon::Decoder::add_original_shard).
    fn add_original_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        original_shard: T,
    ) -> Result<(), Error>;

    /// Like [`Decoder::add_recovery_shard`](crate::reed_solomon::Decoder::add_recovery_shard).
    fn add_recovery_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        recovery_shard: T,
    ) -> Result<(), Error>;

    /// Like [`Decoder::decode`](crate::reed_solomon::Decoder::decode): reconstructs the missing
    /// shards, or returns `Ok(None)` if every original was already provided (nothing to
    /// reconstruct). When `compute_recovery` is set, the missing recovery shards are also
    /// reconstructed.
    fn decode(&mut self, compute_recovery: bool) -> Result<Option<DecoderResult<'_>>, Error>;

    /// Consumes this decoder returning its [`Engine`] and [`DecoderWork`]
    /// so that they can be re-used by another decoder.
    fn into_parts(self) -> (E, DecoderWork);

    /// Like [`Decoder::new`](crate::reed_solomon::Decoder::new)
    /// with [`Engine`] to use and optional working space to be re-used.
    fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<DecoderWork>,
    ) -> Result<Self, Error>;

    /// Like [`Decoder::reset`](crate::reed_solomon::Decoder::reset).
    fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error>;

    /// Checks that the shard counts are supported, the shard size is nonzero and even, and
    /// this decoder's working space fits in a single allocation.
    fn validate(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error>;

    /// Returns `true` if given `original_count` / `recovery_count`
    /// combination is supported.
    ///
    /// This is same as [`Rate::supports`].
    fn supports(original_count: usize, recovery_count: usize) -> bool {
        Self::Rate::supports(original_count, recovery_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{engine::Scalar, test_util};

    /// Checks that `validate` accepts the largest whole-chunk shard size for `work_count` work
    /// shards and rejects that size plus 2 bytes, which needs one more chunk per shard.
    fn check_capacity(validate: impl Fn(usize) -> Result<(), Error>, work_count: usize) {
        let shard_bytes =
            (isize::MAX as usize / SHARD_CHUNK_BYTES / work_count) * SHARD_CHUNK_BYTES;
        assert_eq!(validate(shard_bytes), Ok(()));
        assert_eq!(
            validate(shard_bytes + 2),
            Err(Error::InvalidShardSize {
                shard_bytes: shard_bytes + 2
            })
        );
    }

    /// Checks the shard size limit for counts such as (9, 3) and (3, 9), which encode with 12
    /// work shards (9 rounded up to a multiple of the chunk of 4) and decode with 16 (4 + 9
    /// rounded up to a power of two).
    fn check_rate_capacity<R: Rate<Scalar>>(original_count: usize, recovery_count: usize) {
        check_capacity(
            |shard_bytes| R::RateEncoder::validate(original_count, recovery_count, shard_bytes),
            12,
        );
        check_capacity(
            |shard_bytes| R::RateDecoder::validate(original_count, recovery_count, shard_bytes),
            16,
        );
    }

    #[test]
    fn working_space_capacity() {
        check_rate_capacity::<HighRate<Scalar>>(9, 3);
        check_rate_capacity::<LowRate<Scalar>>(3, 9);
        check_rate_capacity::<DefaultRate<Scalar>>(9, 3);
        check_rate_capacity::<DefaultRate<Scalar>>(3, 9);
    }

    #[test]
    fn work_and_result_reuse() {
        let mut encoder_work = None;
        let mut decoder_work = None;
        for (phase, (original_count, recovery_count, shard_bytes)) in
            [(3, 2, 66), (2, 3, 34), (5, 3, 130), (4, 6, 2)]
                .into_iter()
                .enumerate()
        {
            let mut encoder = DefaultRate::<Scalar>::encoder(
                original_count,
                recovery_count,
                shard_bytes,
                Scalar::new(),
                encoder_work,
            )
            .unwrap();
            let mut decoder = DefaultRate::<Scalar>::decoder(
                original_count,
                recovery_count,
                shard_bytes,
                Scalar::new(),
                decoder_work,
            )
            .unwrap();
            for round in 0..2 {
                let original = test_util::generate_original(
                    original_count,
                    shard_bytes,
                    (phase * 2 + round) as u8,
                );
                let mut fresh = DefaultRate::<Scalar>::encoder(
                    original_count,
                    recovery_count,
                    shard_bytes,
                    Scalar::new(),
                    None,
                )
                .unwrap();
                for shard in &original {
                    encoder.add_original_shard(shard).unwrap();
                    fresh.add_original_shard(shard).unwrap();
                }
                let expected = fresh.encode().unwrap();
                {
                    let encoded = encoder.encode().unwrap();
                    for index in 0..recovery_count {
                        assert_eq!(encoded.recovery(index), expected.recovery(index));
                    }
                    let mut iter = encoded.recovery_iter();
                    assert_eq!(iter.next(), expected.recovery(0));
                    assert_eq!(iter.len(), recovery_count - 1);
                }
                assert!(matches!(
                    encoder.encode(),
                    Err(Error::TooFewOriginalShards {
                        original_received_count: 0,
                        ..
                    })
                ));

                for (index, shard) in original.iter().enumerate() {
                    decoder.add_original_shard(index, shard).unwrap();
                }
                assert!(decoder.decode(round == 0).unwrap().is_none());
                assert!(matches!(
                    decoder.decode(false),
                    Err(Error::NotEnoughShards {
                        original_received_count: 0,
                        recovery_received_count: 0,
                        ..
                    })
                ));
                for (index, shard) in original.iter().enumerate().skip(2) {
                    decoder.add_original_shard(index, shard).unwrap();
                }
                for index in 0..2 {
                    decoder
                        .add_recovery_shard(index, expected.recovery(index).unwrap())
                        .unwrap();
                }
                {
                    let decoded = decoder.decode(true).unwrap().unwrap();
                    let mut iter = decoded.original_iter();
                    assert_eq!(iter.next(), Some((0, original[0].as_slice())));
                    assert_eq!(iter.len(), 1);
                    assert_eq!(decoded.original(1), Some(original[1].as_slice()));
                }
                assert!(matches!(
                    decoder.decode(false),
                    Err(Error::NotEnoughShards {
                        original_received_count: 0,
                        recovery_received_count: 0,
                        ..
                    })
                ));
            }

            // Hand the next phase work with a shard still pending. Reuse must drop the stale
            // received state and keep the stale bytes out of its results.
            let pending = vec![255; shard_bytes];
            encoder.add_original_shard(&pending).unwrap();
            decoder.add_original_shard(0, &pending).unwrap();
            encoder_work = Some(encoder.into_parts().1);
            decoder_work = Some(decoder.into_parts().1);
        }
    }
}
