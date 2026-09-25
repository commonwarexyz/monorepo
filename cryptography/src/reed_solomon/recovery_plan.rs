use crate::reed_solomon::{
    Error,
    engine::{DefaultEngine, GF_ORDER, GfElement},
    rate::{rate_default::use_high_rate, rate_high, rate_low},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use fixedbitset::FixedBitSet;

/// Immutable erasure coefficients reusable across decoders with the same received shard indices.
///
/// A plan depends on shard counts and indices, but not shard contents or byte length. Build it
/// once and share it across independent stripes, including stripes with different even lengths.
/// All supplied shards must still belong to the same codeword for their respective stripe.
pub struct RecoveryPlan {
    original_count: usize,
    recovery_count: usize,
    high_rate: bool,
    received: FixedBitSet,
    coefficients: Vec<GfElement>,
}

impl RecoveryPlan {
    /// Prepare the coefficients for the distinct original and recovery indices to be decoded.
    ///
    /// At least `original_count` total shards must be supplied. Extra recovery shards are allowed.
    /// The plan is valid for any nonzero even shard byte length accepted by [`Decoder`](super::Decoder).
    pub fn new(
        original_count: usize,
        recovery_count: usize,
        original_indices: impl IntoIterator<Item = usize>,
        recovery_indices: impl IntoIterator<Item = usize>,
    ) -> Result<Self, Error> {
        let high_rate = use_high_rate(original_count, recovery_count)?;
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

        let coefficients = if original_received == original_count {
            Vec::new()
        } else if high_rate {
            let mut erasures = [0; GF_ORDER];
            rate_high::eval_erasures::<DefaultEngine>(
                &mut erasures,
                original_count,
                recovery_count,
                &received,
            );
            erasures[..end].to_vec()
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

    pub(crate) fn coefficients(&self) -> &[GfElement] {
        &self.coefficients
    }

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
            // Decoder work may retain extra zero words after shrinking.
            && received.as_slice().starts_with(self.received.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_received_indices() {
        for (k, m) in [(3, 5), (5, 3)] {
            assert!(matches!(
                RecoveryPlan::new(k, m, [k], []),
                Err(Error::InvalidOriginalShardIndex { .. })
            ));
            assert!(matches!(
                RecoveryPlan::new(k, m, [], [m]),
                Err(Error::InvalidRecoveryShardIndex { .. })
            ));
            assert!(matches!(
                RecoveryPlan::new(k, m, [0, 0], []),
                Err(Error::DuplicateOriginalShardIndex { index: 0 })
            ));
            assert!(matches!(
                RecoveryPlan::new(k, m, [], [0, 0]),
                Err(Error::DuplicateRecoveryShardIndex { index: 0 })
            ));
            assert!(matches!(
                RecoveryPlan::new(k, m, [0], [0]),
                Err(Error::NotEnoughShards {
                    original_received_count: 1,
                    recovery_received_count: 1,
                    ..
                })
            ));
        }
    }
}
