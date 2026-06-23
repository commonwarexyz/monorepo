use crate::reed_solomon::{
    engine::{self, Engine, GF_MODULUS, GF_ORDER, SHARD_CHUNK_BYTES},
    rate::{DecoderWork, EncoderWork, Rate, RateDecoder, RateEncoder},
    Decoded, DecoderResult, EncoderResult, Error,
};
use core::marker::PhantomData;

// ======================================================================
// LowRate - PUBLIC

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

// ======================================================================
// LowRateEncoder - PUBLIC

/// Reed-Solomon encoder using only low rate.
pub struct LowRateEncoder<E: Engine> {
    engine: E,
    work: EncoderWork,
}

impl<E: Engine> RateEncoder<E> for LowRateEncoder<E> {
    type Rate = LowRate<E>;

    fn add_original_shard<T: AsRef<[u8]>>(&mut self, original_shard: T) -> Result<(), Error> {
        self.work.add_original_shard(original_shard)
    }

    fn encode(&mut self) -> Result<EncoderResult<'_>, Error> {
        let (mut work, original_count, recovery_count) = self.work.encode_begin()?;
        let chunk_size = original_count.next_power_of_two();
        let engine = &self.engine;

        // ZEROPAD ORIGINAL

        work.zero(original_count..chunk_size);

        // IFFT - ORIGINAL

        engine.ifft(&mut work, 0, chunk_size, original_count, 0);

        // COPY IFFT RESULT TO OTHER CHUNKS

        let mut chunk_start = chunk_size;
        while chunk_start < recovery_count {
            work.copy_within(0, chunk_start, chunk_size);
            chunk_start += chunk_size;
        }

        // FFT - FULL CHUNKS

        let mut chunk_start = 0;
        while chunk_start + chunk_size <= recovery_count {
            engine::fft_skew_end(engine, &mut work, chunk_start, chunk_size, chunk_size);
            chunk_start += chunk_size;
        }

        // FFT - FINAL PARTIAL CHUNK

        let last_count = recovery_count % chunk_size;
        if last_count > 0 {
            engine::fft_skew_end(engine, &mut work, chunk_start, chunk_size, last_count);
        }

        // UNDO LAST CHUNK ENCODING

        self.work.undo_last_chunk_encoding();

        // DONE

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

// ======================================================================
// LowRateEncoder - PRIVATE

impl<E: Engine> LowRateEncoder<E> {
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

    fn work_count(original_count: usize, recovery_count: usize) -> usize {
        assert!(Self::supports(original_count, recovery_count));

        let chunk_size = original_count.next_power_of_two();

        recovery_count.next_multiple_of(chunk_size)
    }
}

// ======================================================================
// LowRateDecoder - PUBLIC

/// Reed-Solomon decoder using only low rate.
pub struct LowRateDecoder<E: Engine> {
    engine: E,
    work: DecoderWork,
}

impl<E: Engine> RateDecoder<E> for LowRateDecoder<E> {
    type Rate = LowRate<E>;

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

    fn decode(&mut self, compute_recovery: bool) -> Result<Decoded<'_>, Error> {
        let Some((mut work, original_count, recovery_count, received)) =
            self.work.decode_begin()?
        else {
            // Every original was provided: nothing to reconstruct. Clear the received state and
            // report completion.
            self.work.reset_received();
            return Ok(Decoded::Complete);
        };

        let chunk_size = original_count.next_power_of_two();
        let recovery_end = chunk_size + recovery_count;
        let work_count = work.len();

        // ERASURE LOCATIONS

        let mut erasures = [0; GF_ORDER];

        for i in 0..original_count {
            if !received[i] {
                erasures[i] = 1;
            }
        }

        for i in chunk_size..recovery_end {
            if !received[i] {
                erasures[i] = 1;
            }
        }

        erasures[recovery_end..].fill(1);

        // EVALUATE POLYNOMIAL

        E::eval_poly(&mut erasures, GF_ORDER);

        // MULTIPLY SHARDS

        // work[               .. original_count] = original * erasures
        // work[original_count .. chunk_size    ] = 0
        // work[chunk_size     .. original_end  ] = recovery * erasures
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

        // IFFT / FORMAL DERIVATIVE / FFT

        self.engine.ifft(&mut work, 0, work_count, recovery_end, 0);
        engine::formal_derivative(&mut work);
        self.engine.fft(&mut work, 0, work_count, recovery_end, 0);

        // REVEAL ERASURES

        for i in 0..original_count {
            if !received[i] {
                self.engine.mul(&mut work[i], GF_MODULUS - erasures[i]);
            }
        }

        // REVEAL ERASURES (RECOVERY)
        //
        // Only when the caller passed `compute_recovery = true` to `decode`. Recovery shards
        // live at `work[chunk_size..recovery_end]`. Un-scale the missing ones by the inverse
        // locator so they hold the canonical recovery values, mirroring the original reveal above.
        // This lets `DecoderResult::recovery` return them without a separate re-encode.

        if compute_recovery {
            for i in chunk_size..recovery_end {
                if !received[i] {
                    self.engine.mul(&mut work[i], GF_MODULUS - erasures[i]);
                }
            }
        }

        // UNDO LAST CHUNK ENCODING

        self.work.undo_last_chunk_encoding();
        if compute_recovery {
            self.work.undo_last_chunk_encoding_recovery();
            self.work.set_recovery_computed();
        }

        // DONE

        Ok(Decoded::Reconstructed(DecoderResult::new(&mut self.work)))
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

// ======================================================================
// LowRateDecoder - PRIVATE

impl<E: Engine> LowRateDecoder<E> {
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

    fn work_count(original_count: usize, recovery_count: usize) -> usize {
        assert!(Self::supports(original_count, recovery_count));

        (original_count.next_power_of_two() + recovery_count).next_power_of_two()
    }
}

// ======================================================================
// TESTS

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::test_util;

    // ============================================================
    // ROUNDTRIPS - SINGLE ROUND

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

    #[test]
    #[ignore]
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

    #[test]
    #[ignore]
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

    #[test]
    #[ignore]
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

    // ============================================================
    // ROUNDTRIPS - TWO ROUNDS

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

    // ============================================================
    // LowRate

    mod low_rate {
        use crate::reed_solomon::{
            engine::NoSimd,
            rate::{LowRate, Rate},
            Error, SHARD_CHUNK_BYTES,
        };

        #[test]
        fn decoder() {
            assert!(LowRate::<NoSimd>::decoder(
                4096,
                61440,
                SHARD_CHUNK_BYTES,
                NoSimd::new(),
                None
            )
            .is_ok());

            assert_eq!(
                LowRate::<NoSimd>::decoder(61440, 4096, SHARD_CHUNK_BYTES, NoSimd::new(), None)
                    .err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        #[test]
        fn encoder() {
            assert!(LowRate::<NoSimd>::encoder(
                4096,
                61440,
                SHARD_CHUNK_BYTES,
                NoSimd::new(),
                None
            )
            .is_ok());

            assert_eq!(
                LowRate::<NoSimd>::encoder(61440, 4096, SHARD_CHUNK_BYTES, NoSimd::new(), None)
                    .err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        #[test]
        fn supports() {
            assert!(!LowRate::<NoSimd>::supports(0, 1));
            assert!(!LowRate::<NoSimd>::supports(1, 0));

            assert!(LowRate::<NoSimd>::supports(4096, 61440));
            assert!(!LowRate::<NoSimd>::supports(4096, 61441));
            assert!(!LowRate::<NoSimd>::supports(4097, 61440));

            assert!(!LowRate::<NoSimd>::supports(61440, 4096));

            assert!(!LowRate::<NoSimd>::supports(usize::MAX, usize::MAX));
        }

        #[test]
        fn validate() {
            assert_eq!(
                LowRate::<NoSimd>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert!(LowRate::<NoSimd>::validate(4096, 61440, SHARD_CHUNK_BYTES).is_ok());

            assert_eq!(
                LowRate::<NoSimd>::validate(61440, 4096, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }
    }

    // ============================================================
    // LowRateEncoder

    mod low_rate_encoder {
        use crate::reed_solomon::{
            engine::NoSimd,
            rate::{LowRateEncoder, RateEncoder},
            Error, SHARD_CHUNK_BYTES,
        };

        // ==================================================
        // ERRORS

        test_rate_encoder_errors! {LowRateEncoder}

        // ==================================================
        // supports

        #[test]
        fn supports() {
            assert!(LowRateEncoder::<NoSimd>::supports(4096, 61440));
            assert!(!LowRateEncoder::<NoSimd>::supports(61440, 4096));
        }

        // ==================================================
        // validate

        #[test]
        fn validate() {
            assert_eq!(
                LowRateEncoder::<NoSimd>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert!(LowRateEncoder::<NoSimd>::validate(4096, 61440, SHARD_CHUNK_BYTES).is_ok());

            assert_eq!(
                LowRateEncoder::<NoSimd>::validate(61440, 4096, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        // ==================================================
        // work_count

        #[test]
        fn work_count() {
            assert_eq!(LowRateEncoder::<NoSimd>::work_count(1, 1), 1);
            assert_eq!(LowRateEncoder::<NoSimd>::work_count(1024, 4096), 4096);
            assert_eq!(LowRateEncoder::<NoSimd>::work_count(1024, 4097), 5120);
            assert_eq!(LowRateEncoder::<NoSimd>::work_count(1025, 4097), 6144);
            assert_eq!(LowRateEncoder::<NoSimd>::work_count(32768, 32768), 32768);
        }
    }

    // ============================================================
    // LowRateDecoder

    mod low_rate_decoder {
        use crate::reed_solomon::{
            engine::NoSimd,
            rate::{LowRateDecoder, RateDecoder},
            Error, SHARD_CHUNK_BYTES,
        };

        // ==================================================
        // ERRORS

        test_rate_decoder_errors! {LowRateDecoder}

        // ==================================================
        // supports

        #[test]
        fn supports() {
            assert!(LowRateDecoder::<NoSimd>::supports(4096, 61440));
            assert!(!LowRateDecoder::<NoSimd>::supports(61440, 4096));
        }

        // ==================================================
        // validate

        #[test]
        fn validate() {
            assert_eq!(
                LowRateDecoder::<NoSimd>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert!(LowRateDecoder::<NoSimd>::validate(4096, 61440, SHARD_CHUNK_BYTES).is_ok());

            assert_eq!(
                LowRateDecoder::<NoSimd>::validate(61440, 4096, SHARD_CHUNK_BYTES).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 61440,
                    recovery_count: 4096,
                })
            );
        }

        // ==================================================
        // work_count

        #[test]
        fn work_count() {
            assert_eq!(LowRateDecoder::<NoSimd>::work_count(1, 1), 2);
            assert_eq!(LowRateDecoder::<NoSimd>::work_count(1024, 3072), 4096);
            assert_eq!(LowRateDecoder::<NoSimd>::work_count(1024, 3073), 8192);
            assert_eq!(LowRateDecoder::<NoSimd>::work_count(1025, 2048), 4096);
            assert_eq!(LowRateDecoder::<NoSimd>::work_count(1025, 2049), 8192);
            assert_eq!(LowRateDecoder::<NoSimd>::work_count(32768, 32768), 65536);
        }
    }
}
