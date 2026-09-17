use crate::reed_solomon::{
    Error,
    engine::{DefaultEngine, Engine, GF_ORDER, GfElement},
    rate::{DecoderWork, use_high_rate},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use fixedbitset::FixedBitSet;

/// Immutable reconstruction coefficients for a fixed set of received shard indices.
///
/// A plan can be shared across decoders with different shard sizes and contents, provided their
/// original/recovery counts and received indices match. Each decoder retains its own working space.
/// Use with [`Decoder::decode_with_recovery_plan`](crate::reed_solomon::Decoder::decode_with_recovery_plan).
#[derive(Debug)]
pub struct DecodePlan {
    original_count: usize,
    recovery_count: usize,
    high_rate: bool,
    received: FixedBitSet,
    erasures: Vec<GfElement>,
}

impl DecodePlan {
    /// Prepare reconstruction for the supplied original and recovery indices.
    ///
    /// Indices are relative to their respective shard sets and may be supplied in any order.
    /// Rejects unsupported shard counts, out-of-range or duplicate indices, and insufficient shards.
    /// No polynomial is evaluated when every original is present.
    pub fn new(
        original_count: usize,
        recovery_count: usize,
        originals: impl IntoIterator<Item = usize>,
        recoveries: impl IntoIterator<Item = usize>,
    ) -> Result<Self, Error> {
        let high_rate = use_high_rate(original_count, recovery_count)?;
        let (original_base, recovery_base) = if high_rate {
            (recovery_count.next_power_of_two(), 0)
        } else {
            (0, original_count.next_power_of_two())
        };
        let end = (original_base + original_count).max(recovery_base + recovery_count);
        let mut received = FixedBitSet::with_capacity(end);
        let mut original_received_count = 0;
        for index in originals {
            if index >= original_count {
                return Err(Error::InvalidOriginalShardIndex {
                    original_count,
                    index,
                });
            }
            if received.put(original_base + index) {
                return Err(Error::DuplicateOriginalShardIndex { index });
            }
            original_received_count += 1;
        }
        let mut recovery_received_count = 0;
        for index in recoveries {
            if index >= recovery_count {
                return Err(Error::InvalidRecoveryShardIndex {
                    recovery_count,
                    index,
                });
            }
            if received.put(recovery_base + index) {
                return Err(Error::DuplicateRecoveryShardIndex { index });
            }
            recovery_received_count += 1;
        }
        if original_received_count + recovery_received_count < original_count {
            return Err(Error::NotEnoughShards {
                original_count,
                original_received_count,
                recovery_received_count,
            });
        }

        let erasures = if original_received_count == original_count {
            Vec::new()
        } else {
            let mut erasures = [0; GF_ORDER];
            eval_erasures::<DefaultEngine>(
                &mut erasures,
                original_count,
                recovery_count,
                high_rate,
                &received,
            );
            // Only shard positions are needed after evaluating the full field.
            erasures[..end].to_vec()
        };
        Ok(Self {
            original_count,
            recovery_count,
            high_rate,
            received,
            erasures,
        })
    }

    /// Number of original shards in the code.
    pub const fn original_count(&self) -> usize {
        self.original_count
    }

    /// Number of recovery shards in the code.
    pub const fn recovery_count(&self) -> usize {
        self.recovery_count
    }

    pub(crate) fn validate(&self, work: &DecoderWork, high_rate: bool) -> Result<(), Error> {
        // Cached workspaces may retain extra zero bits after being reset to smaller shard counts.
        if self.original_count != work.original_count()
            || self.recovery_count != work.recovery_count()
            || self.high_rate != high_rate
            || !self.received.is_subset(work.received())
            || !work.received().is_subset(&self.received)
        {
            return Err(Error::DecodePlanMismatch);
        }
        Ok(())
    }

    pub(crate) fn erasures(&self) -> &[GfElement] {
        &self.erasures
    }
}

/// Evaluate the erasure polynomial for the rate's work-buffer layout.
pub(crate) fn eval_erasures<E: Engine>(
    erasures: &mut [GfElement; GF_ORDER],
    original_count: usize,
    recovery_count: usize,
    high_rate: bool,
    received: &FixedBitSet,
) {
    let (original_base, recovery_base, end) = if high_rate {
        let chunk_size = recovery_count.next_power_of_two();
        erasures[recovery_count..chunk_size].fill(1);
        (chunk_size, 0, chunk_size + original_count)
    } else {
        let chunk_size = original_count.next_power_of_two();
        erasures[chunk_size + recovery_count..].fill(1);
        (0, chunk_size, GF_ORDER)
    };
    for i in original_base..original_base + original_count {
        erasures[i] = GfElement::from(!received[i]);
    }
    for i in recovery_base..recovery_base + recovery_count {
        erasures[i] = GfElement::from(!received[i]);
    }
    E::eval_poly(erasures, end);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{Decoder, Encoder, test_util};
    use commonware_utils::test_rng;
    use rand::seq::SliceRandom;

    #[test]
    fn rejects_invalid_indices_and_counts() {
        for (k, m) in [
            (0, 1),
            (1, 0),
            (usize::MAX, 1),
            (1, usize::MAX),
            (32769, 32769),
        ] {
            assert!(matches!(
                DecodePlan::new(k, m, [], []),
                Err(Error::UnsupportedShardCount { .. })
            ));
        }
        assert!(matches!(
            DecodePlan::new(2, 3, [2], []),
            Err(Error::InvalidOriginalShardIndex { index: 2, .. })
        ));
        assert!(matches!(
            DecodePlan::new(2, 3, [], [3]),
            Err(Error::InvalidRecoveryShardIndex { index: 3, .. })
        ));
        assert!(matches!(
            DecodePlan::new(2, 3, [0, 0], []),
            Err(Error::DuplicateOriginalShardIndex { index: 0 })
        ));
        assert!(matches!(
            DecodePlan::new(2, 3, [], [1, 1]),
            Err(Error::DuplicateRecoveryShardIndex { index: 1 })
        ));
        assert!(matches!(
            DecodePlan::new(3, 2, [0], [1]),
            Err(Error::NotEnoughShards {
                original_count: 3,
                original_received_count: 1,
                recovery_received_count: 1,
            })
        ));
    }

    #[test]
    fn reuse_across_sizes_patterns_and_rates() {
        let mut rng = test_rng();
        // Retain a larger received bitmap while resetting between low and high rates.
        let mut decoder = Decoder::new(65, 33, 128).unwrap();
        for (k, m) in [(1, 1), (2, 3), (3, 2), (17, 33), (33, 17)] {
            for received_count in k..=k + m {
                let mut indices: Vec<_> = (0..k + m).collect();
                indices.shuffle(&mut rng);
                indices.truncate(received_count);
                let originals: Vec<_> = indices.iter().copied().filter(|&i| i < k).collect();
                let recoveries: Vec<_> = indices
                    .iter()
                    .copied()
                    .filter(|&i| i >= k)
                    .map(|i| i - k)
                    .collect();
                let plan =
                    DecodePlan::new(k, m, originals.iter().copied(), recoveries.iter().copied())
                        .unwrap();
                for size in [2, 64, 66, 130] {
                    let shards = test_util::generate_original(k, size, size as u8);
                    let mut encoder = Encoder::new(k, m, size).unwrap();
                    for shard in &shards {
                        encoder.add_original_shard(shard).unwrap();
                    }
                    let encoded = encoder.encode().unwrap();
                    let recovery: Vec<_> = encoded.recovery_iter().collect();
                    // Dropping the result must reset the decoder for another round with this plan.
                    decoder.reset(k, m, size).unwrap();
                    for _ in 0..2 {
                        for &i in originals.iter().rev() {
                            decoder.add_original_shard(i, &shards[i]).unwrap();
                        }
                        for &i in recoveries.iter().rev() {
                            decoder.add_recovery_shard(i, recovery[i]).unwrap();
                        }
                        let result = decoder.decode_with_recovery_plan(&plan).unwrap();
                        if originals.len() == k {
                            assert!(result.is_none());
                            continue;
                        }
                        let result = result.unwrap();
                        for (i, shard) in shards.iter().enumerate() {
                            assert_eq!(
                                result.original(i),
                                (!originals.contains(&i)).then_some(shard.as_slice())
                            );
                        }
                        for (i, shard) in recovery.iter().enumerate() {
                            assert_eq!(
                                result.recovery(i),
                                (!recoveries.contains(&i)).then_some(*shard)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn mismatch_preserves_decoder() {
        let shards = test_util::generate_original(2, 66, 123);
        let mut encoder = Encoder::new(2, 3, 66).unwrap();
        for shard in &shards {
            encoder.add_original_shard(shard).unwrap();
        }
        let encoded = encoder.encode().unwrap();
        let recovery: Vec<_> = encoded.recovery_iter().collect();
        let mut decoder = Decoder::new(2, 3, 66).unwrap();
        decoder.add_original_shard(0, &shards[0]).unwrap();
        decoder.add_recovery_shard(0, recovery[0]).unwrap();
        for plan in [
            DecodePlan::new(2, 3, [1], [0]).unwrap(),
            DecodePlan::new(2, 3, [0], [1]).unwrap(),
            DecodePlan::new(2, 3, [0], [0, 1]).unwrap(),
            DecodePlan::new(2, 2, [0], [0]).unwrap(),
            DecodePlan::new(3, 2, [0, 1], [0]).unwrap(),
        ] {
            assert!(matches!(
                decoder.decode_with_recovery_plan(&plan),
                Err(Error::DecodePlanMismatch)
            ));
        }
        // A supplied shard absent from the plan is also a mismatch.
        let plan = DecodePlan::new(2, 3, [0], [0]).unwrap();
        decoder.add_recovery_shard(1, recovery[1]).unwrap();
        assert!(matches!(
            decoder.decode_with_recovery_plan(&plan),
            Err(Error::DecodePlanMismatch)
        ));
        let plan = DecodePlan::new(2, 3, [0], [0, 1]).unwrap();
        let result = decoder.decode_with_recovery_plan(&plan).unwrap().unwrap();
        assert_eq!(result.original(1), Some(shards[1].as_slice()));
        assert_eq!(result.recovery(2), Some(recovery[2]));
    }
}
