use crate::reed_solomon::{
    DecoderResult, EncoderResult, Error, Plan,
    engine::{self, Engine, GF_MODULUS, GF_ORDER, GfElement, SHARD_CHUNK_BYTES},
    rate::{DecoderWork, EncoderWork, Rate, RateDecoder, RateEncoder},
};
#[cfg(not(feature = "std"))]
use alloc::vec;
use core::marker::PhantomData;
use fixedbitset::FixedBitSet;

/// Write the log erasure locator for each position in `erasures[..end]`, where
/// `end = recovery_count.next_power_of_two() + original_count`.
///
/// Missing recovery shards, the padding in `recovery_count..recovery_count.next_power_of_two()`,
/// and missing originals are erased. `erasures` must hold `end.next_power_of_two()` zeroed
/// entries. Entries at and after `end` are unspecified.
///
/// # Panics
///
/// If `erasures.len() != end.next_power_of_two()`.
pub(crate) fn eval_erasures<E: Engine>(
    erasures: &mut [GfElement],
    original_count: usize,
    recovery_count: usize,
    received: &FixedBitSet,
) {
    let chunk_size = recovery_count.next_power_of_two();
    let end = chunk_size + original_count;
    for i in 0..recovery_count {
        if !received[i] {
            erasures[i] = 1;
        }
    }
    erasures[recovery_count..chunk_size].fill(1);
    for i in chunk_size..end {
        if !received[i] {
            erasures[i] = 1;
        }
    }
    super::eval_locator::<E>(erasures, end);
}

/// Reed-Solomon encoder/decoder generator using only high rate.
pub struct HighRate<E: Engine>(PhantomData<E>);

impl<E: Engine> Rate<E> for HighRate<E> {
    type RateEncoder = HighRateEncoder<E>;
    type RateDecoder = HighRateDecoder<E>;

    fn supports(original_count: usize, recovery_count: usize) -> bool {
        original_count > 0
            && recovery_count > 0
            && original_count < GF_ORDER
            && recovery_count < GF_ORDER
            && recovery_count.next_power_of_two() + original_count <= GF_ORDER
    }
}

/// Reed-Solomon encoder using only high rate.
pub struct HighRateEncoder<E: Engine> {
    engine: E,
    /// Originals at `0..original_count`. Encoding leaves the recovery shards at
    /// `0..recovery_count`.
    work: EncoderWork,
}

impl<E: Engine> RateEncoder<E> for HighRateEncoder<E> {
    type Rate = HighRate<E>;

    fn validate(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        Self::Rate::validate(original_count, recovery_count, shard_bytes)?;
        super::validate_work_size(
            shard_bytes,
            Self::work_count(original_count, recovery_count),
        )
    }

    fn add_original_shard<T: AsRef<[u8]>>(&mut self, original_shard: T) -> Result<(), Error> {
        self.work.add_original_shard(original_shard)
    }

    fn encode(&mut self) -> Result<EncoderResult<'_>, Error> {
        let (mut work, original_count, recovery_count) = self.work.encode_begin()?;
        let chunk_size = recovery_count.next_power_of_two();
        let engine = &self.engine;

        // Zero-pad the first chunk past `first_count` and IFFT it.
        let first_count = core::cmp::min(original_count, chunk_size);
        work.zero(first_count..chunk_size);
        engine::ifft_skew_end(engine, &mut work, 0, chunk_size, first_count);

        if original_count > chunk_size {
            // IFFT each full chunk and XOR it into the first chunk.
            let mut chunk_start = chunk_size;
            while chunk_start + chunk_size <= original_count {
                engine::ifft_skew_end(engine, &mut work, chunk_start, chunk_size, chunk_size);
                engine::xor_within(&mut work, 0, chunk_start, chunk_size);
                chunk_start += chunk_size;
            }

            // Zero-pad the final partial chunk, IFFT it, and XOR it into the first chunk.
            let last_count = original_count % chunk_size;
            if last_count > 0 {
                work.zero(chunk_start + last_count..);
                engine::ifft_skew_end(engine, &mut work, chunk_start, chunk_size, last_count);
                engine::xor_within(&mut work, 0, chunk_start, chunk_size);
            }
        }

        engine.fft(&mut work, 0, chunk_size, recovery_count, 0);

        self.work.undo_last_chunk_encoding();

        Ok(EncoderResult::new(&mut self.work))
    }

    fn into_parts(self) -> (E, EncoderWork) {
        (self.engine, self.work)
    }

    fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<EncoderWork>,
    ) -> Result<Self, Error> {
        let mut work = work.unwrap_or_default();
        Self::reset_work(original_count, recovery_count, shard_bytes, &mut work)?;
        Ok(Self { engine, work })
    }

    fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        Self::reset_work(original_count, recovery_count, shard_bytes, &mut self.work)
    }
}

impl<E: Engine> HighRateEncoder<E> {
    /// Validates the parameters, then resets `work` for them with [`Self::work_count`] shards.
    ///
    /// Returns the error from [`RateEncoder::validate`] and leaves `work` unchanged on failure.
    fn reset_work(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        work: &mut EncoderWork,
    ) -> Result<(), Error> {
        Self::validate(original_count, recovery_count, shard_bytes)?;
        work.reset(
            original_count,
            recovery_count,
            shard_bytes,
            Self::work_count(original_count, recovery_count),
        );
        Ok(())
    }

    /// Returns the number of shards in the working space.
    ///
    /// This is `original_count` rounded up to a multiple of the chunk size
    /// `recovery_count.next_power_of_two()`, so every chunk of originals, including a
    /// zero-padded final chunk, has room for its IFFT.
    ///
    /// # Panics
    ///
    /// Panics if the counts are not supported by [`HighRate`].
    fn work_count(original_count: usize, recovery_count: usize) -> usize {
        assert!(Self::supports(original_count, recovery_count));

        let chunk_size = recovery_count.next_power_of_two();

        original_count.next_multiple_of(chunk_size)
    }
}

/// Reed-Solomon decoder using only high rate.
pub struct HighRateDecoder<E: Engine> {
    engine: E,
    /// Recovery shards at `0..recovery_count`. Originals start at
    /// `recovery_count.next_power_of_two()`.
    work: DecoderWork,
}

impl<E: Engine> RateDecoder<E> for HighRateDecoder<E> {
    type Rate = HighRate<E>;

    fn validate(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        Self::Rate::validate(original_count, recovery_count, shard_bytes)?;
        super::validate_work_size(
            shard_bytes,
            Self::work_count(original_count, recovery_count),
        )
    }

    fn add_original_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        original_shard: T,
    ) -> Result<(), Error> {
        self.work.add_original_shard(index, original_shard)
    }

    fn add_recovery_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        recovery_shard: T,
    ) -> Result<(), Error> {
        self.work.add_recovery_shard(index, recovery_shard)
    }

    fn decode(&mut self, compute_recovery: bool) -> Result<Option<DecoderResult<'_>>, Error> {
        self.decode_impl(compute_recovery, None)
    }

    fn into_parts(self) -> (E, DecoderWork) {
        (self.engine, self.work)
    }

    fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<DecoderWork>,
    ) -> Result<Self, Error> {
        let mut work = work.unwrap_or_default();
        Self::reset_work(original_count, recovery_count, shard_bytes, &mut work)?;
        Ok(Self { engine, work })
    }

    fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        Self::reset_work(original_count, recovery_count, shard_bytes, &mut self.work)
    }
}

impl<E: Engine> HighRateDecoder<E> {
    /// Decodes like [`RateDecoder::decode`], taking the erasure locators from `plan` instead of
    /// evaluating them.
    ///
    /// Returns [`Error::PlanMismatch`] unless `plan` was built for these counts, high rate, and
    /// the received shard indices.
    pub(crate) fn decode_with_plan(
        &mut self,
        compute_recovery: bool,
        plan: &Plan,
    ) -> Result<Option<DecoderResult<'_>>, Error> {
        self.decode_impl(compute_recovery, Some(plan))
    }
}

impl<E: Engine> HighRateDecoder<E> {
    /// Reconstructs the missing originals, and the missing recovery shards when
    /// `compute_recovery` is set, taking the erasure locators from `plan` when given.
    ///
    /// Returns `Ok(None)` and clears the received state when every original was provided.
    fn decode_impl(
        &mut self,
        compute_recovery: bool,
        plan: Option<&Plan>,
    ) -> Result<Option<DecoderResult<'_>>, Error> {
        if let Some(plan) = plan {
            self.work.validate_plan(plan, true)?;
        }
        let Some((mut work, original_count, recovery_count, received)) =
            self.work.decode_begin()?
        else {
            // Every original was provided: nothing to reconstruct. Clear the received state and
            // report nothing.
            self.work.reset_received();
            return Ok(None);
        };

        let chunk_size = recovery_count.next_power_of_two();
        let original_end = chunk_size + original_count;
        let work_count = work.len();

        // Take the erasure locators from the plan, or evaluate them from the received shards.
        let mut owned_erasures;
        #[expect(
            clippy::option_if_let_else,
            reason = "The fallback initializes a scratch buffer and returns a borrow of it."
        )]
        let erasures: &[GfElement] = match plan {
            Some(plan) => plan.coefficients(),
            None => {
                owned_erasures = vec![0; original_end.next_power_of_two()];
                eval_erasures::<E>(
                    &mut owned_erasures,
                    original_count,
                    recovery_count,
                    received,
                );
                &owned_erasures
            }
        };

        // Multiply received shards by their erasure locators and zero everything else:
        //
        // work[               .. recovery_count] = recovery * erasures
        // work[recovery_count .. chunk_size    ] = 0
        // work[chunk_size     .. original_end  ] = original * erasures
        // work[original_end   ..               ] = 0
        for i in 0..recovery_count {
            if received[i] {
                self.engine.mul(&mut work[i], erasures[i]);
            } else {
                work[i].fill([0; SHARD_CHUNK_BYTES]);
            }
        }
        work.zero(recovery_count..chunk_size);
        for i in chunk_size..original_end {
            if received[i] {
                self.engine.mul(&mut work[i], erasures[i]);
            } else {
                work[i].fill([0; SHARD_CHUNK_BYTES]);
            }
        }
        work.zero(original_end..);

        // Take the formal derivative between an IFFT and an FFT.
        self.engine.ifft(&mut work, 0, work_count, original_end, 0);
        engine::formal_derivative(&mut work);
        self.engine.fft(&mut work, 0, work_count, original_end, 0);

        // Reveal the missing originals by scaling them by the inverse locator.
        for i in chunk_size..original_end {
            if !received[i] {
                self.engine.mul(&mut work[i], GF_MODULUS - erasures[i]);
            }
        }

        // When the caller passed `compute_recovery = true` to `decode`, reveal the missing
        // recovery shards at `work[0..recovery_count]`. Scale them by the inverse locator so they
        // hold the canonical recovery values, mirroring the reveal of the originals above. This
        // lets `DecoderResult::recovery` return them without a separate re-encode.
        if compute_recovery {
            for i in 0..recovery_count {
                if !received[i] {
                    self.engine.mul(&mut work[i], GF_MODULUS - erasures[i]);
                }
            }
        }

        // Undo the last chunk encoding of the originals, and of the recovery shards if computed.
        self.work.undo_last_chunk_encoding();
        if compute_recovery {
            self.work.undo_last_chunk_encoding_recovery();
        }

        Ok(Some(DecoderResult::new(&mut self.work)))
    }

    /// Validates the parameters, then resets `work` for them with [`Self::work_count`] shards.
    ///
    /// Returns the error from [`RateDecoder::validate`] and leaves `work` unchanged on failure.
    fn reset_work(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        work: &mut DecoderWork,
    ) -> Result<(), Error> {
        Self::validate(original_count, recovery_count, shard_bytes)?;

        // work[..recovery_count     ]  =  recovery
        // work[recovery_count_pow2..]  =  original
        work.reset(
            original_count,
            recovery_count,
            shard_bytes,
            recovery_count.next_power_of_two(),
            0,
            Self::work_count(original_count, recovery_count),
        );

        Ok(())
    }

    /// Returns the number of shards in the working space.
    ///
    /// This is `recovery_count.next_power_of_two() + original_count` rounded up to a power of two,
    /// the size of the decoding transforms.
    ///
    /// # Panics
    ///
    /// Panics if the counts are not supported by [`HighRate`].
    fn work_count(original_count: usize, recovery_count: usize) -> usize {
        assert!(Self::supports(original_count, recovery_count));

        (recovery_count.next_power_of_two() + original_count).next_power_of_two()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::test_util;
    use commonware_macros::test_group;

    #[test]
    fn roundtrip_all_originals_missing() {
        roundtrip_single!(
            HighRate,
            3,
            3,
            1024,
            test_util::EITHER_3_3,
            &[],
            &[test_util::range(0, 3)],
            133,
        );
    }

    #[test]
    fn roundtrip_no_originals_missing() {
        roundtrip_single!(
            HighRate,
            3,
            2,
            1024,
            test_util::HIGH_3_2,
            &[test_util::range(0, 3)],
            &[],
            132
        );
    }

    #[test]
    fn roundtrips_tiny() {
        for (original_count, recovery_count, seed, recovery_hash) in test_util::HIGH_TINY {
            roundtrip_single!(
                HighRate,
                *original_count,
                *recovery_count,
                1024,
                recovery_hash,
                &[test_util::range(*recovery_count, *original_count)],
                &[test_util::range(
                    0,
                    core::cmp::min(*original_count, *recovery_count)
                )],
                *seed,
            );
        }
    }

    #[test_group("slow")]
    #[test]
    fn roundtrip_3000_30000() {
        roundtrip_single!(
            HighRate,
            3000,
            30000,
            crate::reed_solomon::SHARD_CHUNK_BYTES,
            test_util::HIGH_3000_30000_14,
            &[],
            &[test_util::range(0, 3000)],
            14,
        );
    }

    #[test_group("slow")]
    #[test]
    fn roundtrip_32768_32768() {
        roundtrip_single!(
            HighRate,
            32768,
            32768,
            crate::reed_solomon::SHARD_CHUNK_BYTES,
            test_util::EITHER_32768_32768_11,
            &[],
            &[test_util::range(0, 32768)],
            11,
        );
    }

    #[test_group("slow")]
    #[test]
    fn roundtrip_60000_3000() {
        roundtrip_single!(
            HighRate,
            60000,
            3000,
            crate::reed_solomon::SHARD_CHUNK_BYTES,
            test_util::HIGH_60000_3000_12,
            &[test_util::range(3000, 60000)],
            &[test_util::range(0, 3000)],
            12,
        );
    }

    #[test]
    fn roundtrip_34000_2000_shard_size_8() {
        roundtrip_single!(
            HighRate,
            34000,
            2000,
            8,
            test_util::HIGH_34000_2000_123_8,
            &[test_util::range(0, 32000)],
            &[test_util::range(0, 2000)],
            123
        );
    }

    #[test]
    fn two_rounds_implicit_reset() {
        roundtrip_two_rounds!(
            HighRate,
            false,
            (
                3,
                2,
                1024,
                test_util::HIGH_3_2,
                &[test_util::index(1)],
                &[test_util::index(0), test_util::index(1)],
                132
            ),
            (
                3,
                2,
                1024,
                test_util::HIGH_3_2_232,
                &[test_util::index(0)],
                &[test_util::index(0), test_util::index(1)],
                232
            ),
        );
    }

    #[test]
    fn two_rounds_explicit_reset() {
        roundtrip_two_rounds!(
            HighRate,
            true,
            (
                3,
                2,
                1024,
                test_util::HIGH_3_2,
                &[test_util::index(1)],
                &[test_util::index(0), test_util::index(1)],
                132
            ),
            (
                5,
                2,
                1024,
                test_util::HIGH_5_2,
                &[
                    test_util::index(0),
                    test_util::index(2),
                    test_util::index(4)
                ],
                &[test_util::index(0), test_util::index(1)],
                152
            ),
        );
    }

    mod high_rate {
        use crate::reed_solomon::{
            Error, SHARD_CHUNK_BYTES,
            engine::Scalar,
            rate::{HighRate, Rate},
        };

        #[test]
        fn decoder() {
            assert_eq!(
                HighRate::<Scalar>::decoder(4096, 61440, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(
                HighRate::<Scalar>::decoder(61440, 4096, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .is_ok()
            );
        }

        #[test]
        fn encoder() {
            assert_eq!(
                HighRate::<Scalar>::encoder(4096, 61440, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(
                HighRate::<Scalar>::encoder(61440, 4096, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .is_ok()
            );
        }

        #[test]
        fn supports() {
            assert!(!HighRate::<Scalar>::supports(0, 1));
            assert!(!HighRate::<Scalar>::supports(1, 0));

            assert!(!HighRate::<Scalar>::supports(4096, 61440));

            assert!(HighRate::<Scalar>::supports(61440, 4096));
            assert!(!HighRate::<Scalar>::supports(61440, 4097));
            assert!(!HighRate::<Scalar>::supports(61441, 4096));

            assert!(!HighRate::<Scalar>::supports(usize::MAX, usize::MAX));
        }

        #[test]
        fn validate() {
            assert_eq!(
                HighRate::<Scalar>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert_eq!(
                HighRate::<Scalar>::validate(4096, 61440, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRate::<Scalar>::validate(61440, 4096, SHARD_CHUNK_BYTES).is_ok());
        }
    }

    mod high_rate_encoder {
        use crate::reed_solomon::{
            Error, SHARD_CHUNK_BYTES,
            engine::Scalar,
            rate::{HighRateEncoder, RateEncoder},
        };

        test_rate_encoder_errors! {HighRateEncoder}

        #[test]
        fn supports() {
            assert!(!HighRateEncoder::<Scalar>::supports(4096, 61440));
            assert!(HighRateEncoder::<Scalar>::supports(61440, 4096));
        }

        #[test]
        fn validate() {
            assert_eq!(
                HighRateEncoder::<Scalar>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert_eq!(
                HighRateEncoder::<Scalar>::validate(4096, 61440, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRateEncoder::<Scalar>::validate(61440, 4096, SHARD_CHUNK_BYTES).is_ok());
        }

        #[test]
        fn work_count() {
            assert_eq!(HighRateEncoder::<Scalar>::work_count(1, 1), 1);
            assert_eq!(HighRateEncoder::<Scalar>::work_count(4096, 1024), 4096);
            assert_eq!(HighRateEncoder::<Scalar>::work_count(4097, 1024), 5120);
            assert_eq!(HighRateEncoder::<Scalar>::work_count(4097, 1025), 6144);
            assert_eq!(HighRateEncoder::<Scalar>::work_count(32768, 32768), 32768);
        }
    }

    mod high_rate_decoder {
        use crate::reed_solomon::{
            Error, SHARD_CHUNK_BYTES,
            engine::Scalar,
            rate::{HighRateDecoder, RateDecoder},
        };

        test_rate_decoder_errors! {HighRateDecoder}

        #[test]
        fn supports() {
            assert!(!HighRateDecoder::<Scalar>::supports(4096, 61440));
            assert!(HighRateDecoder::<Scalar>::supports(61440, 4096));
        }

        #[test]
        fn validate() {
            assert_eq!(
                HighRateDecoder::<Scalar>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert_eq!(
                HighRateDecoder::<Scalar>::validate(4096, 61440, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRateDecoder::<Scalar>::validate(61440, 4096, SHARD_CHUNK_BYTES).is_ok());
        }

        #[test]
        fn work_count() {
            assert_eq!(HighRateDecoder::<Scalar>::work_count(1, 1), 2);
            assert_eq!(HighRateDecoder::<Scalar>::work_count(2048, 1025), 4096);
            assert_eq!(HighRateDecoder::<Scalar>::work_count(2049, 1025), 8192);
            assert_eq!(HighRateDecoder::<Scalar>::work_count(3072, 1024), 4096);
            assert_eq!(HighRateDecoder::<Scalar>::work_count(3073, 1024), 8192);
            assert_eq!(HighRateDecoder::<Scalar>::work_count(32768, 32768), 65536);
        }
    }
}
