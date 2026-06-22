use crate::reed_solomon::{
    engine::{self, Engine, GF_MODULUS, GF_ORDER},
    rate::{DecoderWork, EncoderWork, Rate, RateDecoder, RateEncoder},
    DecoderResult, EncoderResult, Error,
};
use core::marker::PhantomData;

// ======================================================================
// HighRate - PUBLIC

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

// ======================================================================
// HighRateEncoder - PUBLIC

/// Reed-Solomon encoder using only high rate.
pub struct HighRateEncoder<E: Engine> {
    engine: E,
    work: EncoderWork,
}

impl<E: Engine> RateEncoder<E> for HighRateEncoder<E> {
    type Rate = HighRate<E>;

    fn add_original_shard<T: AsRef<[u8]>>(&mut self, original_shard: T) -> Result<(), Error> {
        self.work.add_original_shard(original_shard)
    }

    fn encode(&mut self) -> Result<EncoderResult<'_>, Error> {
        let (mut work, original_count, recovery_count) = self.work.encode_begin()?;
        let chunk_size = recovery_count.next_power_of_two();
        let engine = &self.engine;

        // FIRST CHUNK

        let first_count = core::cmp::min(original_count, chunk_size);

        work.zero(first_count..chunk_size);
        engine::ifft_skew_end(engine, &mut work, 0, chunk_size, first_count);

        if original_count > chunk_size {
            // FULL CHUNKS

            let mut chunk_start = chunk_size;
            while chunk_start + chunk_size <= original_count {
                engine::ifft_skew_end(engine, &mut work, chunk_start, chunk_size, chunk_size);
                engine::xor_within(&mut work, 0, chunk_start, chunk_size);
                chunk_start += chunk_size;
            }

            // FINAL PARTIAL CHUNK

            let last_count = original_count % chunk_size;
            if last_count > 0 {
                work.zero(chunk_start + last_count..);
                engine::ifft_skew_end(engine, &mut work, chunk_start, chunk_size, last_count);
                engine::xor_within(&mut work, 0, chunk_start, chunk_size);
            }
        }

        // FFT

        engine.fft(&mut work, 0, chunk_size, recovery_count, 0);

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
// HighRateEncoder - PRIVATE

impl<E: Engine> HighRateEncoder<E> {
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
        debug_assert!(Self::supports(original_count, recovery_count));

        let chunk_size = recovery_count.next_power_of_two();

        original_count.next_multiple_of(chunk_size)
    }
}

// ======================================================================
// HighRateDecoder - PUBLIC

/// Reed-Solomon decoder using only high rate.
pub struct HighRateDecoder<E: Engine> {
    engine: E,
    work: DecoderWork,
}

impl<E: Engine> RateDecoder<E> for HighRateDecoder<E> {
    type Rate = HighRate<E>;

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

    fn decode(&mut self) -> Result<DecoderResult<'_>, Error> {
        let Some((mut work, original_count, recovery_count, received)) =
            self.work.decode_begin()?
        else {
            // Nothing to do, original data is complete.
            return Ok(DecoderResult::new(&mut self.work));
        };

        let chunk_size = recovery_count.next_power_of_two();
        let original_end = chunk_size + original_count;
        let work_count = work.len();

        // ERASURE LOCATIONS

        let mut erasures = [0; GF_ORDER];

        for i in 0..recovery_count {
            if !received[i] {
                erasures[i] = 1;
            }
        }

        erasures[recovery_count..chunk_size].fill(1);

        for i in chunk_size..original_end {
            if !received[i] {
                erasures[i] = 1;
            }
        }

        // EVALUATE POLYNOMIAL

        E::eval_poly(&mut erasures, original_end);

        // MULTIPLY SHARDS

        // work[               .. recovery_count] = recovery * erasures
        // work[recovery_count .. chunk_size    ] = 0
        // work[chunk_size     .. original_end  ] = original * erasures
        // work[original_end   ..               ] = 0

        for i in 0..recovery_count {
            if received[i] {
                self.engine.mul(&mut work[i], erasures[i]);
            } else {
                work[i].fill([0; 64]);
            }
        }

        work.zero(recovery_count..chunk_size);

        for i in chunk_size..original_end {
            if received[i] {
                self.engine.mul(&mut work[i], erasures[i]);
            } else {
                work[i].fill([0; 64]);
            }
        }

        work.zero(original_end..);

        // IFFT / FORMAL DERIVATIVE / FFT

        self.engine.ifft(&mut work, 0, work_count, original_end, 0);
        engine::formal_derivative(&mut work);
        self.engine.fft(&mut work, 0, work_count, original_end, 0);

        // REVEAL ERASURES

        for i in chunk_size..original_end {
            if !received[i] {
                self.engine.mul(&mut work[i], GF_MODULUS - erasures[i]);
            }
        }

        // UNDO LAST CHUNK ENCODING

        self.work.undo_last_chunk_encoding();

        // DONE

        Ok(DecoderResult::new(&mut self.work))
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
// HighRateDecoder - PRIVATE

impl<E: Engine> HighRateDecoder<E> {
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

    fn work_count(original_count: usize, recovery_count: usize) -> usize {
        debug_assert!(Self::supports(original_count, recovery_count));

        (recovery_count.next_power_of_two() + original_count).next_power_of_two()
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
            HighRate,
            3,
            3,
            1024,
            test_util::EITHER_3_3,
            &[],
            &[0..3],
            133,
        );
    }

    #[test]
    fn roundtrip_no_originals_missing() {
        roundtrip_single!(HighRate, 3, 2, 1024, test_util::HIGH_3_2, &[0..3], &[], 132);
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
                &[*recovery_count..*original_count],
                &[0..core::cmp::min(*original_count, *recovery_count)],
                *seed,
            );
        }
    }

    #[test]
    #[ignore]
    fn roundtrip_3000_30000() {
        roundtrip_single!(
            HighRate,
            3000,
            30000,
            64,
            test_util::HIGH_3000_30000_14,
            &[],
            &[0..3000],
            14,
        );
    }

    #[test]
    #[ignore]
    fn roundtrip_32768_32768() {
        roundtrip_single!(
            HighRate,
            32768,
            32768,
            64,
            test_util::EITHER_32768_32768_11,
            &[],
            &[0..32768],
            11,
        );
    }

    #[test]
    #[ignore]
    fn roundtrip_60000_3000() {
        roundtrip_single!(
            HighRate,
            60000,
            3000,
            64,
            test_util::HIGH_60000_3000_12,
            &[3000..60000],
            &[0..3000],
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
            &[0..32000],
            &[0..2000],
            123
        );
    }

    // ============================================================
    // ROUNDTRIPS - TWO ROUNDS

    #[test]
    fn two_rounds_implicit_reset() {
        roundtrip_two_rounds!(
            HighRate,
            false,
            (3, 2, 1024, test_util::HIGH_3_2, &[1], &[0, 1], 132),
            (3, 2, 1024, test_util::HIGH_3_2_232, &[0], &[0, 1], 232),
        );
    }

    #[test]
    fn two_rounds_explicit_reset() {
        roundtrip_two_rounds!(
            HighRate,
            true,
            (3, 2, 1024, test_util::HIGH_3_2, &[1], &[0, 1], 132),
            (5, 2, 1024, test_util::HIGH_5_2, &[0, 2, 4], &[0, 1], 152),
        );
    }

    // ============================================================
    // HighRate

    mod high_rate {
        use crate::reed_solomon::{
            engine::NoSimd,
            rate::{HighRate, Rate},
            Error,
        };

        #[test]
        fn decoder() {
            assert_eq!(
                HighRate::<NoSimd>::decoder(4096, 61440, 64, NoSimd::new(), None).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRate::<NoSimd>::decoder(61440, 4096, 64, NoSimd::new(), None).is_ok());
        }

        #[test]
        fn encoder() {
            assert_eq!(
                HighRate::<NoSimd>::encoder(4096, 61440, 64, NoSimd::new(), None).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRate::<NoSimd>::encoder(61440, 4096, 64, NoSimd::new(), None).is_ok());
        }

        #[test]
        fn supports() {
            assert!(!HighRate::<NoSimd>::supports(0, 1));
            assert!(!HighRate::<NoSimd>::supports(1, 0));

            assert!(!HighRate::<NoSimd>::supports(4096, 61440));

            assert!(HighRate::<NoSimd>::supports(61440, 4096));
            assert!(!HighRate::<NoSimd>::supports(61440, 4097));
            assert!(!HighRate::<NoSimd>::supports(61441, 4096));

            assert!(!HighRate::<NoSimd>::supports(usize::MAX, usize::MAX));
        }

        #[test]
        fn validate() {
            assert_eq!(
                HighRate::<NoSimd>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert_eq!(
                HighRate::<NoSimd>::validate(4096, 61440, 64).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRate::<NoSimd>::validate(61440, 4096, 64).is_ok());
        }
    }

    // ============================================================
    // HighRateEncoder

    mod high_rate_encoder {
        use crate::reed_solomon::{
            engine::NoSimd,
            rate::{HighRateEncoder, RateEncoder},
            Error,
        };

        // ==================================================
        // ERRORS

        test_rate_encoder_errors! {HighRateEncoder}

        // ==================================================
        // supports

        #[test]
        fn supports() {
            assert!(!HighRateEncoder::<NoSimd>::supports(4096, 61440));
            assert!(HighRateEncoder::<NoSimd>::supports(61440, 4096));
        }

        // ==================================================
        // validate

        #[test]
        fn validate() {
            assert_eq!(
                HighRateEncoder::<NoSimd>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert_eq!(
                HighRateEncoder::<NoSimd>::validate(4096, 61440, 64).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRateEncoder::<NoSimd>::validate(61440, 4096, 64).is_ok());
        }

        // ==================================================
        // work_count

        #[test]
        fn work_count() {
            assert_eq!(HighRateEncoder::<NoSimd>::work_count(1, 1), 1);
            assert_eq!(HighRateEncoder::<NoSimd>::work_count(4096, 1024), 4096);
            assert_eq!(HighRateEncoder::<NoSimd>::work_count(4097, 1024), 5120);
            assert_eq!(HighRateEncoder::<NoSimd>::work_count(4097, 1025), 6144);
            assert_eq!(HighRateEncoder::<NoSimd>::work_count(32768, 32768), 32768);
        }
    }

    // ============================================================
    // HighRateDecoder

    mod high_rate_decoder {
        use crate::reed_solomon::{
            engine::NoSimd,
            rate::{HighRateDecoder, RateDecoder},
            Error,
        };

        // ==================================================
        // ERRORS

        test_rate_decoder_errors! {HighRateDecoder}

        // ==================================================
        // supports

        #[test]
        fn supports() {
            assert!(!HighRateDecoder::<NoSimd>::supports(4096, 61440));
            assert!(HighRateDecoder::<NoSimd>::supports(61440, 4096));
        }

        // ==================================================
        // validate

        #[test]
        fn validate() {
            assert_eq!(
                HighRateDecoder::<NoSimd>::validate(1, 1, 123).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 })
            );

            assert_eq!(
                HighRateDecoder::<NoSimd>::validate(4096, 61440, 64).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 4096,
                    recovery_count: 61440,
                })
            );

            assert!(HighRateDecoder::<NoSimd>::validate(61440, 4096, 64).is_ok());
        }

        // ==================================================
        // work_count

        #[test]
        fn work_count() {
            assert_eq!(HighRateDecoder::<NoSimd>::work_count(1, 1), 2);
            assert_eq!(HighRateDecoder::<NoSimd>::work_count(2048, 1025), 4096);
            assert_eq!(HighRateDecoder::<NoSimd>::work_count(2049, 1025), 8192);
            assert_eq!(HighRateDecoder::<NoSimd>::work_count(3072, 1024), 4096);
            assert_eq!(HighRateDecoder::<NoSimd>::work_count(3073, 1024), 8192);
            assert_eq!(HighRateDecoder::<NoSimd>::work_count(32768, 32768), 65536);
        }
    }
}
