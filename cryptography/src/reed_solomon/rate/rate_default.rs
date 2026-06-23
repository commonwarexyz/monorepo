use crate::reed_solomon::{
    engine::{Engine, GF_ORDER},
    rate::{
        DecoderWork, EncoderWork, HighRate, HighRateDecoder, HighRateEncoder, LowRate,
        LowRateDecoder, LowRateEncoder, Rate, RateDecoder, RateEncoder,
    },
    Decoded, EncoderResult, Error,
};
use core::{cmp::Ordering, marker::PhantomData};

// ======================================================================
// FUNCTIONS - PRIVATE

fn use_high_rate(original_count: usize, recovery_count: usize) -> Result<bool, Error> {
    if original_count > GF_ORDER || recovery_count > GF_ORDER {
        return Err(Error::UnsupportedShardCount {
            original_count,
            recovery_count,
        });
    }

    let original_count_pow2 = original_count.next_power_of_two();
    let recovery_count_pow2 = recovery_count.next_power_of_two();

    let smaller_pow2 = core::cmp::min(original_count_pow2, recovery_count_pow2);
    let larger = core::cmp::max(original_count, recovery_count);

    if original_count == 0 || recovery_count == 0 || smaller_pow2 + larger > GF_ORDER {
        return Err(Error::UnsupportedShardCount {
            original_count,
            recovery_count,
        });
    }

    match original_count_pow2.cmp(&recovery_count_pow2) {
        Ordering::Less => {
            // The "correct" rate is generally faster here,
            // and also must be used if `recovery_count > 32768`.

            Ok(false)
        }

        Ordering::Greater => {
            // The "correct" rate is generally faster here,
            // and also must be used if `original_count > 32768`.

            Ok(true)
        }

        Ordering::Equal => {
            // Here counter-intuitively the "wrong" rate is generally faster
            // in decoding if `original_count` and `recovery_count` differ a lot.

            if original_count <= recovery_count {
                // Using the "wrong" rate on purpose.
                Ok(true)
            } else {
                // Using the "wrong" rate on purpose.
                Ok(false)
            }
        }
    }
}

fn validate_rate<E: Engine>(
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
) -> Result<bool, Error> {
    let use_high = use_high_rate(original_count, recovery_count)?;
    if use_high {
        HighRate::<E>::validate(original_count, recovery_count, shard_bytes)?;
    } else {
        LowRate::<E>::validate(original_count, recovery_count, shard_bytes)?;
    }
    Ok(use_high)
}

// ======================================================================
// DefaultRate - PUBLIC

/// Reed-Solomon encoder/decoder generator using high or low rate as appropriate.
pub struct DefaultRate<E: Engine>(PhantomData<E>);

impl<E: Engine> Rate<E> for DefaultRate<E> {
    type RateEncoder = DefaultRateEncoder<E>;
    type RateDecoder = DefaultRateDecoder<E>;

    fn supports(original_count: usize, recovery_count: usize) -> bool {
        use_high_rate(original_count, recovery_count).is_ok()
    }
}

// ======================================================================
// InnerEncoder - PRIVATE

#[derive(Default)]
enum InnerEncoder<E: Engine> {
    High(HighRateEncoder<E>),
    Low(LowRateEncoder<E>),

    // Used only after reset validation, while switching rates.
    #[default]
    None,
}

// ======================================================================
// DefaultRateEncoder - PUBLIC

/// Reed-Solomon encoder using high or low rate as appropriate.
///
/// This is basically same as [`Encoder`]
/// except with slightly different API which allows
/// specifying [`Engine`] and [`EncoderWork`].
///
/// [`Encoder`]: crate::reed_solomon::Encoder
pub struct DefaultRateEncoder<E: Engine>(InnerEncoder<E>);

impl<E: Engine> RateEncoder<E> for DefaultRateEncoder<E> {
    type Rate = DefaultRate<E>;

    fn add_original_shard<T: AsRef<[u8]>>(&mut self, original_shard: T) -> Result<(), Error> {
        match &mut self.0 {
            InnerEncoder::High(high) => high.add_original_shard(original_shard),
            InnerEncoder::Low(low) => low.add_original_shard(original_shard),
            InnerEncoder::None => unreachable!(),
        }
    }

    fn encode(&mut self) -> Result<EncoderResult<'_>, Error> {
        match &mut self.0 {
            InnerEncoder::High(high) => high.encode(),
            InnerEncoder::Low(low) => low.encode(),
            InnerEncoder::None => unreachable!(),
        }
    }

    fn into_parts(self) -> (E, EncoderWork) {
        match self.0 {
            InnerEncoder::High(high) => high.into_parts(),
            InnerEncoder::Low(low) => low.into_parts(),
            InnerEncoder::None => unreachable!(),
        }
    }

    fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<EncoderWork>,
    ) -> Result<Self, Error> {
        let inner = if use_high_rate(original_count, recovery_count)? {
            InnerEncoder::High(HighRateEncoder::new(
                original_count,
                recovery_count,
                shard_bytes,
                engine,
                work,
            )?)
        } else {
            InnerEncoder::Low(LowRateEncoder::new(
                original_count,
                recovery_count,
                shard_bytes,
                engine,
                work,
            )?)
        };

        Ok(Self(inner))
    }

    fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        let new_rate_is_high = validate_rate::<E>(original_count, recovery_count, shard_bytes)?;

        match &mut self.0 {
            InnerEncoder::High(high) if new_rate_is_high => {
                return high.reset(original_count, recovery_count, shard_bytes);
            }
            InnerEncoder::Low(low) if !new_rate_is_high => {
                return low.reset(original_count, recovery_count, shard_bytes);
            }
            _ => {}
        }

        self.0 = match core::mem::take(&mut self.0) {
            InnerEncoder::High(high) => {
                let (engine, work) = high.into_parts();
                InnerEncoder::Low(
                    LowRateEncoder::new(
                        original_count,
                        recovery_count,
                        shard_bytes,
                        engine,
                        Some(work),
                    )
                    .expect("low-rate encoder configuration was validated"),
                )
            }

            InnerEncoder::Low(low) => {
                let (engine, work) = low.into_parts();
                InnerEncoder::High(
                    HighRateEncoder::new(
                        original_count,
                        recovery_count,
                        shard_bytes,
                        engine,
                        Some(work),
                    )
                    .expect("high-rate encoder configuration was validated"),
                )
            }

            InnerEncoder::None => unreachable!(),
        };

        Ok(())
    }
}

// ======================================================================
// InnerDecoder - PRIVATE

#[derive(Default)]
enum InnerDecoder<E: Engine> {
    High(HighRateDecoder<E>),
    Low(LowRateDecoder<E>),

    // Used only after reset validation, while switching rates.
    #[default]
    None,
}

// ======================================================================
// DefaultRateDecoder - PUBLIC

/// Reed-Solomon decoder using high or low rate as appropriate.
///
/// This is basically same as [`Decoder`]
/// except with slightly different API which allows
/// specifying [`Engine`] and [`DecoderWork`].
///
/// [`Decoder`]: crate::reed_solomon::Decoder
pub struct DefaultRateDecoder<E: Engine>(InnerDecoder<E>);

impl<E: Engine> RateDecoder<E> for DefaultRateDecoder<E> {
    type Rate = DefaultRate<E>;

    fn add_original_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        original_shard: T,
    ) -> Result<(), Error> {
        match &mut self.0 {
            InnerDecoder::High(high) => high.add_original_shard(index, original_shard),
            InnerDecoder::Low(low) => low.add_original_shard(index, original_shard),
            InnerDecoder::None => unreachable!(),
        }
    }

    fn add_recovery_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        recovery_shard: T,
    ) -> Result<(), Error> {
        match &mut self.0 {
            InnerDecoder::High(high) => high.add_recovery_shard(index, recovery_shard),
            InnerDecoder::Low(low) => low.add_recovery_shard(index, recovery_shard),
            InnerDecoder::None => unreachable!(),
        }
    }

    fn decode(&mut self, compute_recovery: bool) -> Result<Decoded<'_>, Error> {
        match &mut self.0 {
            InnerDecoder::High(high) => high.decode(compute_recovery),
            InnerDecoder::Low(low) => low.decode(compute_recovery),
            InnerDecoder::None => unreachable!(),
        }
    }

    fn into_parts(self) -> (E, DecoderWork) {
        match self.0 {
            InnerDecoder::High(high) => high.into_parts(),
            InnerDecoder::Low(low) => low.into_parts(),
            InnerDecoder::None => unreachable!(),
        }
    }

    fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        engine: E,
        work: Option<DecoderWork>,
    ) -> Result<Self, Error> {
        let inner = if use_high_rate(original_count, recovery_count)? {
            InnerDecoder::High(HighRateDecoder::new(
                original_count,
                recovery_count,
                shard_bytes,
                engine,
                work,
            )?)
        } else {
            InnerDecoder::Low(LowRateDecoder::new(
                original_count,
                recovery_count,
                shard_bytes,
                engine,
                work,
            )?)
        };

        Ok(Self(inner))
    }

    fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        let new_rate_is_high = validate_rate::<E>(original_count, recovery_count, shard_bytes)?;

        match &mut self.0 {
            InnerDecoder::High(high) if new_rate_is_high => {
                return high.reset(original_count, recovery_count, shard_bytes);
            }
            InnerDecoder::Low(low) if !new_rate_is_high => {
                return low.reset(original_count, recovery_count, shard_bytes);
            }
            _ => {}
        }

        self.0 = match core::mem::take(&mut self.0) {
            InnerDecoder::High(high) => {
                let (engine, work) = high.into_parts();
                InnerDecoder::Low(
                    LowRateDecoder::new(
                        original_count,
                        recovery_count,
                        shard_bytes,
                        engine,
                        Some(work),
                    )
                    .expect("low-rate decoder configuration was validated"),
                )
            }

            InnerDecoder::Low(low) => {
                let (engine, work) = low.into_parts();
                InnerDecoder::High(
                    HighRateDecoder::new(
                        original_count,
                        recovery_count,
                        shard_bytes,
                        engine,
                        Some(work),
                    )
                    .expect("high-rate decoder configuration was validated"),
                )
            }

            InnerDecoder::None => unreachable!(),
        };

        Ok(())
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
    fn roundtrips_tiny() {
        for (original_count, recovery_count, seed, recovery_hash) in test_util::DEFAULT_TINY {
            roundtrip_single!(
                DefaultRate,
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

    // ============================================================
    // ROUNDTRIPS - TWO ROUNDS

    #[test]
    fn two_rounds_implicit_reset() {
        roundtrip_two_rounds!(
            DefaultRate,
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
                &[test_util::index(0)],
                &[test_util::index(1)],
                223
            ),
        );
    }

    #[test]
    fn two_rounds_reset_high_to_high() {
        roundtrip_two_rounds!(
            DefaultRate,
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
                3,
                1024,
                test_util::HIGH_5_3,
                &[test_util::index(1), test_util::index(3)],
                &[
                    test_util::index(0),
                    test_util::index(1),
                    test_util::index(2)
                ],
                153
            ),
        );
    }

    #[test]
    fn two_rounds_reset_high_to_low() {
        roundtrip_two_rounds!(
            DefaultRate,
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
                2,
                3,
                1024,
                test_util::LOW_2_3,
                &[],
                &[test_util::index(0), test_util::index(2)],
                123
            ),
        );
    }

    #[test]
    fn two_rounds_reset_low_to_high() {
        roundtrip_two_rounds!(
            DefaultRate,
            true,
            (
                2,
                3,
                1024,
                test_util::LOW_2_3,
                &[],
                &[test_util::index(0), test_util::index(1)],
                123
            ),
            (
                3,
                2,
                1024,
                test_util::HIGH_3_2,
                &[test_util::index(1)],
                &[test_util::index(0), test_util::index(1)],
                132
            ),
        );
    }

    #[test]
    fn two_rounds_reset_low_to_low() {
        roundtrip_two_rounds!(
            DefaultRate,
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
                3,
                5,
                1024,
                test_util::LOW_3_5,
                &[],
                &[
                    test_util::index(0),
                    test_util::index(2),
                    test_util::index(4)
                ],
                135
            ),
        );
    }

    // ============================================================
    // use_high_rate

    #[test]
    fn use_high_rate() {
        fn err(original_count: usize, recovery_count: usize) -> Result<bool, Error> {
            Err(Error::UnsupportedShardCount {
                original_count,
                recovery_count,
            })
        }

        for (original_count, recovery_count, expected) in [
            (0, 1, err(0, 1)),
            (1, 0, err(1, 0)),
            // CORRECT/WRONG RATE
            (3, 3, Ok(true)),
            (3, 4, Ok(true)),
            (3, 5, Ok(false)),
            (4, 3, Ok(false)),
            (5, 3, Ok(true)),
            // LOW RATE LIMIT
            (4096, 61440, Ok(false)),
            (4096, 61441, err(4096, 61441)),
            (4097, 61440, err(4097, 61440)),
            // HIGH RATE LIMIT
            (61440, 4096, Ok(true)),
            (61440, 4097, err(61440, 4097)),
            (61441, 4096, err(61441, 4096)),
            // OVERFLOW CHECK
            (usize::MAX, usize::MAX, err(usize::MAX, usize::MAX)),
        ] {
            assert_eq!(
                super::use_high_rate(original_count, recovery_count),
                expected
            );
        }
    }
}
