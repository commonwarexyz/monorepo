use crate::reed_solomon::{
    DecoderResult, EncoderResult, Error, Plan,
    engine::{self, Engine, GF_MODULUS, GF_ORDER, GfElement, SHARD_CHUNK_BYTES, tables},
    rate::{DecoderWork, EncoderWork, Rate, RateDecoder, RateEncoder},
};
#[cfg(not(feature = "std"))]
use alloc::vec;
use core::marker::PhantomData;
use fixedbitset::FixedBitSet;

/// Largest decoding domain that `with_erasures` evaluates directly, bounding the quadratic
/// calculation and its stack storage.
pub(crate) const DIRECT_EVALUATION_LIMIT: usize = 32;

/// Evaluate the log erasure locator for each position below `end` and pass those entries to
/// `f`, where `end = original_count.next_power_of_two() + recovery_count`.
pub(crate) fn with_erasures<E: Engine, T>(
    original_count: usize,
    recovery_count: usize,
    received: &FixedBitSet,
    f: impl FnOnce(&[GfElement]) -> T,
) -> T {
    let end = original_count.next_power_of_two() + recovery_count;
    if end <= DIRECT_EVALUATION_LIMIT {
        let mut erasures = [0; DIRECT_EVALUATION_LIMIT];
        eval_direct(&mut erasures[..end], original_count, received);
        f(&erasures[..end])
    } else {
        let mut erasures = vec![0; end.next_power_of_two()];
        eval_walsh::<E>(&mut erasures, original_count, recovery_count, received);
        f(&erasures[..end])
    }
}

/// Compute log erasure factors directly from the known positions in a small decoding domain.
/// This avoids the zeroed buffer and the Walsh transforms of `eval_walsh`.
///
/// `erasures.len()` is the domain end `original_count.next_power_of_two() + recovery_count` and
/// must not exceed [`DIRECT_EVALUATION_LIMIT`].
fn eval_direct(erasures: &mut [GfElement], original_count: usize, received: &FixedBitSet) {
    let chunk_size = original_count.next_power_of_two();
    let mut known = [0; DIRECT_EVALUATION_LIMIT];
    let mut count = 0;
    for i in 0..erasures.len() {
        // Padded original positions are known zeros, even though no shard was received.
        if received[i] || (original_count..chunk_size).contains(&i) {
            known[count] = i;
            count += 1;
        }
    }

    // The product over the nonzero field elements is one. The erased-position
    // product is therefore the reciprocal of the known-position product.
    let log = &tables::get_exp_log().log;
    for (i, erasure) in erasures.iter_mut().enumerate() {
        // At most DIRECT_EVALUATION_LIMIT terms fit comfortably in u32.
        let mut sum = 0u32;
        for &j in &known[..count] {
            // log[0] is GF_MODULUS, so the self term vanishes modulo GF_MODULUS.
            sum += u32::from(log[i ^ j]);
        }
        *erasure = GF_MODULUS - (sum % u32::from(GF_MODULUS)) as GfElement;
    }
}

/// Write the log erasure locator for each position in `erasures[..end]` with Walsh
/// transforms, where `end = original_count.next_power_of_two() + recovery_count`.
///
/// Missing shards and every position at and after `end` are erased. `erasures` must hold
/// `end.next_power_of_two()` zeroed entries. Entries at and after `end` are unspecified.
///
/// # Panics
///
/// If `erasures.len() != end.next_power_of_two()`.
pub(crate) fn eval_walsh<E: Engine>(
    erasures: &mut [GfElement],
    original_count: usize,
    recovery_count: usize,
    received: &FixedBitSet,
) {
    let chunk_size = original_count.next_power_of_two();
    let end = chunk_size + recovery_count;

    // Every position at and after `end` is erased. For each `i`, the values `i ^ j` with
    // `j != i` cover every nonzero field element, whose product is one. So evaluate the
    // known positions, which lie below `end`, and negate the logarithm.
    for i in 0..end {
        if received[i] || (original_count..chunk_size).contains(&i) {
            erasures[i] = 1;
        }
    }
    super::eval_locator::<E>(erasures, end);
    for value in &mut erasures[..end] {
        *value = GF_MODULUS - *value;
    }
}

/// Reed-Solomon encoder/decoder generator using only low rate.
pub struct LowRate<E: Engine>(PhantomData<E>);

impl<E: Engine> Rate<E> for LowRate<E> {
    type RateEncoder = LowRateEncoder<E>;
    type RateDecoder = LowRateDecoder<E>;

    fn supports(original_count: usize, recovery_count: usize) -> bool {
        original_count > 0
            && recovery_count > 0
            && original_count < GF_ORDER
            && recovery_count < GF_ORDER
            && original_count.next_power_of_two() + recovery_count <= GF_ORDER
    }
}

/// Reed-Solomon encoder using only low rate.
pub struct LowRateEncoder<E: Engine> {
    engine: E,
    /// Originals at `0..original_count`. Encoding leaves the recovery shards at
    /// `0..recovery_count`.
    work: EncoderWork,
}

impl<E: Engine> RateEncoder<E> for LowRateEncoder<E> {
    type Rate = LowRate<E>;

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
        let chunk_size = original_count.next_power_of_two();
        let engine = &self.engine;

        // Zero-pad the originals to `chunk_size` and IFFT them.
        work.zero(original_count..chunk_size);
        engine.ifft(&mut work, 0, chunk_size, original_count, 0);

        // Copy the IFFT result into each remaining chunk.
        let mut chunk_start = chunk_size;
        while chunk_start < recovery_count {
            work.copy_within(0, chunk_start, chunk_size);
            chunk_start += chunk_size;
        }

        // FFT each full chunk.
        let mut chunk_start = 0;
        while chunk_start + chunk_size <= recovery_count {
            engine::fft_skew_end(engine, &mut work, chunk_start, chunk_size, chunk_size);
            chunk_start += chunk_size;
        }

        // FFT the final partial chunk.
        let last_count = recovery_count % chunk_size;
        if last_count > 0 {
            engine::fft_skew_end(engine, &mut work, chunk_start, chunk_size, last_count);
        }

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

impl<E: Engine> LowRateEncoder<E> {
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
    /// This is `recovery_count` rounded up to a multiple of the chunk size
    /// `original_count.next_power_of_two()`. This leaves room for the zero-padded originals in
    /// the first chunk and for the FFT of every chunk of recovery shards, including a partial
    /// final chunk.
    ///
    /// # Panics
    ///
    /// Panics if the counts are not supported by [`LowRate`].
    fn work_count(original_count: usize, recovery_count: usize) -> usize {
        assert!(Self::supports(original_count, recovery_count));

        let chunk_size = original_count.next_power_of_two();

        recovery_count.next_multiple_of(chunk_size)
    }
}

/// Reed-Solomon decoder using only low rate.
pub struct LowRateDecoder<E: Engine> {
    engine: E,
    /// Originals at `0..original_count`. Recovery shards start at
    /// `original_count.next_power_of_two()`.
    work: DecoderWork,
}

impl<E: Engine> RateDecoder<E> for LowRateDecoder<E> {
    type Rate = LowRate<E>;

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

impl<E: Engine> LowRateDecoder<E> {
    /// Decodes like [`RateDecoder::decode`], taking the erasure locators from `plan` instead of
    /// evaluating them.
    ///
    /// Returns [`Error::PlanMismatch`] unless `plan` was built for these counts, low rate, and
    /// the received shard indices.
    pub(crate) fn decode_with_plan(
        &mut self,
        compute_recovery: bool,
        plan: &Plan,
    ) -> Result<Option<DecoderResult<'_>>, Error> {
        self.decode_impl(compute_recovery, Some(plan))
    }
}

impl<E: Engine> LowRateDecoder<E> {
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
            self.work.validate_plan(plan, false)?;
        }
        let Some((mut work, original_count, recovery_count, received)) =
            self.work.decode_begin()?
        else {
            // Every original was provided: nothing to reconstruct. Clear the received state and
            // report nothing.
            self.work.reset_received();
            return Ok(None);
        };

        let chunk_size = original_count.next_power_of_two();
        let recovery_end = chunk_size + recovery_count;
        let work_count = work.len();

        // Take the erasure locators from the plan, or evaluate them with `with_erasures`.
        // `with_erasures` lends coefficients from its own scratch buffer, so the rest of decoding
        // is a closure over either those or the plan's coefficients.
        let mut decode = |erasures: &[GfElement]| {
            // Multiply received shards by their erasure locators and zero everything else:
            //
            // work[               .. original_count] = original * erasures
            // work[original_count .. chunk_size    ] = 0
            // work[chunk_size     .. recovery_end  ] = recovery * erasures
            // work[recovery_end   ..               ] = 0
            for i in 0..original_count {
                if received[i] {
                    self.engine.mul(&mut work[i], erasures[i]);
                } else {
                    work[i].fill([0; SHARD_CHUNK_BYTES]);
                }
            }
            work.zero(original_count..chunk_size);
            for i in chunk_size..recovery_end {
                if received[i] {
                    self.engine.mul(&mut work[i], erasures[i]);
                } else {
                    work[i].fill([0; SHARD_CHUNK_BYTES]);
                }
            }
            work.zero(recovery_end..);

            // Take the formal derivative between an IFFT and an FFT.
            self.engine.ifft(&mut work, 0, work_count, recovery_end, 0);
            engine::formal_derivative(&mut work);
            self.engine.fft(&mut work, 0, work_count, recovery_end, 0);

            // Reveal the missing originals by scaling them by the inverse locator.
            for i in 0..original_count {
                if !received[i] {
                    self.engine.mul(&mut work[i], GF_MODULUS - erasures[i]);
                }
            }

            // When the caller passed `compute_recovery = true` to `decode`, reveal the missing
            // recovery shards at `work[chunk_size..recovery_end]`. Scale them by the inverse
            // locator so they hold the canonical recovery values, mirroring the reveal of the
            // originals above. This lets `RecoveryDecoderResult::recovery` return them without a
            // separate re-encode.
            if compute_recovery {
                for i in chunk_size..recovery_end {
                    if !received[i] {
                        self.engine.mul(&mut work[i], GF_MODULUS - erasures[i]);
                    }
                }
            }
        };
        match plan {
            Some(plan) => decode(plan.coefficients()),
            None => with_erasures::<E, _>(original_count, recovery_count, received, decode),
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

        // work[..original_count     ]  =  original
        // work[original_count_pow2..]  =  recovery
        work.reset(
            original_count,
            recovery_count,
            shard_bytes,
            0,
            original_count.next_power_of_two(),
            Self::work_count(original_count, recovery_count),
        );

        Ok(())
    }

    /// Returns the number of shards in the working space.
    ///
    /// This is `original_count.next_power_of_two() + recovery_count` rounded up to a power of two,
    /// the size of the decoding transforms.
    ///
    /// # Panics
    ///
    /// Panics if the counts are not supported by [`LowRate`].
    fn work_count(original_count: usize, recovery_count: usize) -> usize {
        assert!(Self::supports(original_count, recovery_count));

        (original_count.next_power_of_two() + recovery_count).next_power_of_two()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{engine::Scalar, test_util};
    use commonware_macros::test_group;
    use commonware_utils::test_rng;
    use rand::RngExt as _;

    #[test]
    fn direct_matches_transform() {
        let mut rng = test_rng();

        // `chunk - 1` and `chunk` originals both pad to `chunk`, so the last two domains end one
        // short of and exactly at DIRECT_EVALUATION_LIMIT.
        let quarter = DIRECT_EVALUATION_LIMIT / 4;
        let chunk = quarter.next_power_of_two();
        let recovery = DIRECT_EVALUATION_LIMIT - chunk;
        for (original_count, recovery_count) in [
            (1usize, 1),
            (3, 5),
            (7, 13),
            (quarter / 2, quarter),
            (chunk - 1, recovery - 1),
            (chunk, recovery),
        ] {
            let chunk_size = original_count.next_power_of_two();
            let end = chunk_size + recovery_count;
            for pattern in 0..18 {
                let mut received = FixedBitSet::with_capacity(end.next_power_of_two());
                let mut expected = [1; GF_ORDER];
                expected[original_count..chunk_size].fill(0);
                for i in (0..original_count).chain(chunk_size..end) {
                    // Include both extremes as well as mixed and surplus shard sets.
                    if pattern == 0 || (pattern > 1 && rng.random()) {
                        received.insert(i);
                        expected[i] = 0;
                    }
                }
                Scalar::eval_poly(&mut expected, GF_ORDER);
                let mut actual = [0; DIRECT_EVALUATION_LIMIT];
                eval_direct(&mut actual[..end], original_count, &received);
                for i in 0..end {
                    // Zero and GF_MODULUS represent the same logarithmic exponent.
                    assert_eq!(
                        actual[i] % GF_MODULUS,
                        expected[i] % GF_MODULUS,
                        "originals={original_count} recoveries={recovery_count} pattern={pattern} i={i}"
                    );
                }
            }
        }
    }

    #[test]
    fn roundtrip_all_originals_missing() {
        roundtrip_single!(
            LowRate,
            3,
            3,
            1024,
            test_util::EITHER_3_3,
            &[],
            &[test_util::range(0, 3)],
            133
        );
    }

    #[test]
    fn roundtrip_no_originals_missing() {
        roundtrip_single!(
            LowRate,
            2,
            3,
            1024,
            test_util::LOW_2_3,
            &[test_util::index(0), test_util::index(1)],
            &[],
            123
        );
    }

    #[test]
    fn roundtrips_tiny() {
        for (original_count, recovery_count, seed, recovery_hash) in test_util::LOW_TINY {
            roundtrip_single!(
                LowRate,
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
    fn roundtrip_3000_60000() {
        roundtrip_single!(
            LowRate,
            3000,
            60000,
            crate::reed_solomon::SHARD_CHUNK_BYTES,
            test_util::LOW_3000_60000_13,
            &[],
            &[test_util::range(0, 3000)],
            13,
        );
    }

    #[test_group("slow")]
    #[test]
    fn roundtrip_30000_3000() {
        roundtrip_single!(
            LowRate,
            30000,
            3000,
            crate::reed_solomon::SHARD_CHUNK_BYTES,
            test_util::LOW_30000_3000_15,
            &[test_util::range(3000, 30000)],
            &[test_util::range(0, 3000)],
            15,
        );
    }

    #[test_group("slow")]
    #[test]
    fn roundtrip_32768_32768() {
        roundtrip_single!(
            LowRate,
            32768,
            32768,
            crate::reed_solomon::SHARD_CHUNK_BYTES,
            test_util::EITHER_32768_32768_11,
            &[],
            &[test_util::range(0, 32768)],
            11,
        );
    }

    #[test]
    fn roundtrip_2000_34000_shard_size_8() {
        roundtrip_single!(
            LowRate,
            2000,
            34000,
            8,
            test_util::LOW_2000_34000_123_8,
            &[test_util::range(0, 2000)],
            &[test_util::range(0, 32000)],
            123
        );
    }

    #[test]
    fn two_rounds_implicit_reset() {
        roundtrip_two_rounds!(
            LowRate,
            false,
            (
                2,
                3,
                1024,
                test_util::LOW_2_3,
                &[],
                &[test_util::index(0), test_util::index(2)],
                123
            ),
            (
                2,
                3,
                1024,
                test_util::LOW_2_3_223,
                &[],
                &[test_util::index(1), test_util::index(2)],
                223
            ),
        );
    }

    #[test]
    fn two_rounds_explicit_reset() {
        roundtrip_two_rounds!(
            LowRate,
            true,
            (
                2,
                3,
                1024,
                test_util::LOW_2_3,
                &[],
                &[test_util::index(0), test_util::index(2)],
                123
            ),
            (
                2,
                5,
                1024,
                test_util::LOW_2_5,
                &[],
                &[test_util::index(0), test_util::index(4)],
                125
            ),
        );
    }

    mod low_rate {
        use crate::reed_solomon::{
            Error, SHARD_CHUNK_BYTES,
            engine::Scalar,
            rate::{LowRate, Rate},
        };

        #[test]
        fn decoder() {
            assert!(
                LowRate::<Scalar>::decoder(4096, 61440, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .is_ok()
            );

            assert_eq!(
                LowRate::<Scalar>::decoder(61440, 4096, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        #[test]
        fn encoder() {
            assert!(
                LowRate::<Scalar>::encoder(4096, 61440, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .is_ok()
            );

            assert_eq!(
                LowRate::<Scalar>::encoder(61440, 4096, SHARD_CHUNK_BYTES, Scalar::new(), None)
                    .err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        #[test]
        fn supports() {
            assert!(!LowRate::<Scalar>::supports(0, 1));
            assert!(!LowRate::<Scalar>::supports(1, 0));

            assert!(LowRate::<Scalar>::supports(4096, 61440));
            assert!(!LowRate::<Scalar>::supports(4096, 61441));
            assert!(!LowRate::<Scalar>::supports(4097, 61440));

            assert!(!LowRate::<Scalar>::supports(61440, 4096));

            assert!(!LowRate::<Scalar>::supports(usize::MAX, usize::MAX));
        }

        #[test]
        fn validate() {
            assert_eq!(
                LowRate::<Scalar>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert!(LowRate::<Scalar>::validate(4096, 61440, SHARD_CHUNK_BYTES).is_ok());

            assert_eq!(
                LowRate::<Scalar>::validate(61440, 4096, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }
    }

    mod low_rate_encoder {
        use crate::reed_solomon::{
            Error, SHARD_CHUNK_BYTES,
            engine::Scalar,
            rate::{LowRateEncoder, RateEncoder},
        };

        test_rate_encoder_errors! {LowRateEncoder}

        #[test]
        fn supports() {
            assert!(LowRateEncoder::<Scalar>::supports(4096, 61440));
            assert!(!LowRateEncoder::<Scalar>::supports(61440, 4096));
        }

        #[test]
        fn validate() {
            assert_eq!(
                LowRateEncoder::<Scalar>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert!(LowRateEncoder::<Scalar>::validate(4096, 61440, SHARD_CHUNK_BYTES).is_ok());

            assert_eq!(
                LowRateEncoder::<Scalar>::validate(61440, 4096, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        #[test]
        fn work_count() {
            assert_eq!(LowRateEncoder::<Scalar>::work_count(1, 1), 1);
            assert_eq!(LowRateEncoder::<Scalar>::work_count(1024, 4096), 4096);
            assert_eq!(LowRateEncoder::<Scalar>::work_count(1024, 4097), 5120);
            assert_eq!(LowRateEncoder::<Scalar>::work_count(1025, 4097), 6144);
            assert_eq!(LowRateEncoder::<Scalar>::work_count(32768, 32768), 32768);
        }
    }

    mod low_rate_decoder {
        use crate::reed_solomon::{
            Error, SHARD_CHUNK_BYTES,
            engine::Scalar,
            rate::{LowRateDecoder, RateDecoder},
        };

        test_rate_decoder_errors! {LowRateDecoder}

        #[test]
        fn supports() {
            assert!(LowRateDecoder::<Scalar>::supports(4096, 61440));
            assert!(!LowRateDecoder::<Scalar>::supports(61440, 4096));
        }

        #[test]
        fn validate() {
            assert_eq!(
                LowRateDecoder::<Scalar>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert!(LowRateDecoder::<Scalar>::validate(4096, 61440, SHARD_CHUNK_BYTES).is_ok());

            assert_eq!(
                LowRateDecoder::<Scalar>::validate(61440, 4096, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        #[test]
        fn work_count() {
            assert_eq!(LowRateDecoder::<Scalar>::work_count(1, 1), 2);
            assert_eq!(LowRateDecoder::<Scalar>::work_count(1024, 3072), 4096);
            assert_eq!(LowRateDecoder::<Scalar>::work_count(1024, 3073), 8192);
            assert_eq!(LowRateDecoder::<Scalar>::work_count(1025, 2048), 4096);
            assert_eq!(LowRateDecoder::<Scalar>::work_count(1025, 2049), 8192);
            assert_eq!(LowRateDecoder::<Scalar>::work_count(32768, 32768), 65536);
        }
    }
}
