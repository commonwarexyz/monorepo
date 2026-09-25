use crate::reed_solomon::{
    Error,
    engine::{DefaultEngine, GfElement},
    rate::{rate_default::use_high_rate, rate_high, rate_low},
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use fixedbitset::FixedBitSet;

/// Erasure coefficients prepared once for a fixed set of received shard indices.
///
/// A plan depends only on the shard counts and the received original and recovery indices.
/// It does not depend on shard contents or shard byte length, so decoders that receive the
/// same indices can share one plan, even with different shard byte lengths. Each decoder's
/// shards must still belong to one codeword.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::reed_solomon::{Decoder, Encoder, Plan};
///
/// // Original 0 and recovery 0 arrive for both codewords. Original 1 is missing.
/// let plan = Plan::new(2, 1, [0], [0])?;
/// let codewords: [[&[u8]; 2]; 2] = [[&[1, 2], &[3, 4]], [&[5, 6, 7, 8], &[9, 10, 11, 12]]];
/// for [first, second] in codewords {
///     let mut encoder = Encoder::new(2, 1, first.len())?;
///     encoder.add_original_shard(first)?;
///     encoder.add_original_shard(second)?;
///     let encoded = encoder.encode()?;
///
///     let mut decoder = Decoder::new(2, 1, first.len())?;
///     decoder.add_original_shard(0, first)?;
///     decoder.add_recovery_shard(0, encoded.recovery(0).unwrap())?;
///     let decoded = decoder.decode_with_plan(&plan)?.unwrap();
///     assert_eq!(decoded.original(1), Some(second));
/// }
/// # Ok::<(), commonware_cryptography::reed_solomon::Error>(())
/// ```
pub struct Plan {
    original_count: usize,
    recovery_count: usize,
    /// Whether the high-rate layout applies, which places originals after the recovery block.
    high_rate: bool,
    /// Received flags indexed by work position, in the layout `DecoderWork` uses for this rate.
    received: FixedBitSet,
    /// Log erasure locators indexed by work position, one per bit of `received`.
    ///
    /// Empty when every original was received.
    coefficients: Vec<GfElement>,
}

impl Plan {
    /// Prepares coefficients for the received original and recovery shard indices.
    ///
    /// A [`Decoder`](super::Decoder) accepts the plan only when it has the same counts and has
    /// received exactly these indices. At least `original_count` indices must be given in total.
    /// Extra recovery indices are allowed.
    ///
    /// Returns [`Error::UnsupportedShardCount`] for unsupported counts, an index error for an
    /// out-of-range or repeated index, and [`Error::NotEnoughShards`] when too few indices are
    /// given.
    pub fn new(
        original_count: usize,
        recovery_count: usize,
        original_indices: impl IntoIterator<Item = usize>,
        recovery_indices: impl IntoIterator<Item = usize>,
    ) -> Result<Self, Error> {
        let high_rate = use_high_rate(original_count, recovery_count)?;

        // Mirror the received-bit layout that each rate's `reset_work` gives `DecoderWork`,
        // which `matches` compares bit for bit.
        let (original_base, recovery_base) = if high_rate {
            (recovery_count.next_power_of_two(), 0)
        } else {
            (0, original_count.next_power_of_two())
        };
        let end = (original_base + original_count).max(recovery_base + recovery_count);
        let mut received = FixedBitSet::with_capacity(end);
        let mut original_received = 0;
        let mut recovery_received = 0;
        for index in original_indices {
            if index >= original_count {
                return Err(Error::InvalidOriginalShardIndex {
                    original_count,
                    index,
                });
            }
            let pos = original_base + index;
            if received[pos] {
                return Err(Error::DuplicateOriginalShardIndex { index });
            }
            received.set(pos, true);
            original_received += 1;
        }
        for index in recovery_indices {
            if index >= recovery_count {
                return Err(Error::InvalidRecoveryShardIndex {
                    recovery_count,
                    index,
                });
            }
            let pos = recovery_base + index;
            if received[pos] {
                return Err(Error::DuplicateRecoveryShardIndex { index });
            }
            received.set(pos, true);
            recovery_received += 1;
        }
        if original_received + recovery_received < original_count {
            return Err(Error::NotEnoughShards {
                original_count,
                original_received_count: original_received,
                recovery_received_count: recovery_received,
            });
        }

        // With every original received, `decode_begin` returns before reading coefficients.
        let coefficients = if original_received == original_count {
            Vec::new()
        } else if high_rate {
            let mut erasures = vec![0; end.next_power_of_two()];
            rate_high::eval_erasures::<DefaultEngine>(
                &mut erasures,
                original_count,
                recovery_count,
                &received,
            );
            erasures.truncate(end);
            erasures
        } else {
            rate_low::with_erasures::<DefaultEngine, _>(
                original_count,
                recovery_count,
                &received,
                |erasures| erasures.to_vec(),
            )
        };
        Ok(Self {
            original_count,
            recovery_count,
            high_rate,
            received,
            coefficients,
        })
    }

    /// Returns the log erasure locators indexed by work position.
    ///
    /// The slice is empty when every original was received, since decoding then returns before
    /// reading it.
    pub(crate) fn coefficients(&self) -> &[GfElement] {
        &self.coefficients
    }

    /// Returns whether this plan was built for these counts, rate, and received positions.
    ///
    /// `DecoderWork::reset` never shrinks `received`, so it may have more words than the plan's
    /// bitset. With matching counts and rate, `DecoderWork` sets no bit at or past the plan's
    /// length because it rejects out-of-range indices. A prefix comparison is therefore exact.
    pub(crate) fn matches(
        &self,
        original_count: usize,
        recovery_count: usize,
        high_rate: bool,
        received: &FixedBitSet,
    ) -> bool {
        self.original_count == original_count
            && self.recovery_count == recovery_count
            && self.high_rate == high_rate
            && received.as_slice().starts_with(self.received.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{Decoder, Encoder, test_util};

    #[test]
    fn rejects_invalid_received_indices() {
        for (k, m) in [(3, 5), (5, 3)] {
            assert!(matches!(
                Plan::new(k, m, [k], []),
                Err(Error::InvalidOriginalShardIndex { .. })
            ));
            assert!(matches!(
                Plan::new(k, m, [], [m]),
                Err(Error::InvalidRecoveryShardIndex { .. })
            ));
            assert!(matches!(
                Plan::new(k, m, [0, 0], []),
                Err(Error::DuplicateOriginalShardIndex { index: 0 })
            ));
            assert!(matches!(
                Plan::new(k, m, [], [0, 0]),
                Err(Error::DuplicateRecoveryShardIndex { index: 0 })
            ));
            assert!(matches!(
                Plan::new(k, m, [0], [0]),
                Err(Error::NotEnoughShards {
                    original_received_count: 1,
                    recovery_received_count: 1,
                    ..
                })
            ));
        }
    }

    #[test]
    fn decoders_reject_mismatched_plans() {
        // Each case pairs a decoder's counts and received indices with a plan's.
        type Shape = (usize, usize, &'static [usize], &'static [usize]);
        let cases: [(Shape, Shape); 6] = [
            // Only the recovery count differs, and both set the same work positions.
            ((5, 1, &[0, 1, 3, 4], &[0]), (5, 3, &[0, 1], &[0, 1, 2])),
            ((2, 4, &[0], &[0]), (2, 3, &[0], &[0])),
            // Only the original count differs, and both set the same work positions.
            ((4, 5, &[0, 1], &[0, 1]), (3, 5, &[0, 1], &[0, 1])),
            ((4, 2, &[0, 1], &[0, 1]), (3, 2, &[0, 1], &[0, 1])),
            // The decoder received one more recovery shard than the plan names.
            ((2, 4, &[0], &[0, 1]), (2, 4, &[0], &[0])),
            ((5, 3, &[0, 1, 2, 3], &[0, 1]), (5, 3, &[0, 1, 2, 3], &[0])),
        ];
        for ((k, m, originals, recoveries), (plan_k, plan_m, plan_originals, plan_recoveries)) in
            cases
        {
            let data = test_util::generate_original(k, 64, 0);
            let mut encoder = Encoder::new(k, m, 64).unwrap();
            for shard in &data {
                encoder.add_original_shard(shard).unwrap();
            }
            let encoded = encoder.encode().unwrap();
            let mut decoder = Decoder::new(k, m, 64).unwrap();
            for &i in originals {
                decoder.add_original_shard(i, &data[i]).unwrap();
            }
            for &i in recoveries {
                decoder
                    .add_recovery_shard(i, encoded.recovery(i).unwrap())
                    .unwrap();
            }

            let plan = Plan::new(
                plan_k,
                plan_m,
                plan_originals.iter().copied(),
                plan_recoveries.iter().copied(),
            )
            .unwrap();
            assert!(matches!(
                decoder.decode_with_plan(&plan),
                Err(Error::PlanMismatch)
            ));
            assert!(matches!(
                decoder.decode_with_recovery_plan(&plan),
                Err(Error::PlanMismatch)
            ));

            // The decoder's own plan still recovers the missing originals.
            let own =
                Plan::new(k, m, originals.iter().copied(), recoveries.iter().copied()).unwrap();
            let decoded = decoder.decode_with_plan(&own).unwrap().unwrap();
            for (i, shard) in data.iter().enumerate() {
                if !originals.contains(&i) {
                    assert_eq!(decoded.original(i), Some(shard.as_slice()));
                }
            }
        }
    }
}
