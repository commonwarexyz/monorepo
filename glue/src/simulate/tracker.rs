//! Finalization progress tracking and agreement checking.

use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::PublicKey;
use std::collections::{BTreeMap, HashSet};

/// A finalization event from a validator.
pub struct FinalizationUpdate<P: PublicKey> {
    /// Which validator reported this finalization.
    pub pk: P,
    /// The finalized round.
    pub round: Round,
    /// The digest of the finalized block (encoded as bytes).
    pub block_digest: Vec<u8>,
}

/// Tracks finalization progress across all validators.
///
/// Validates safety invariants (agreement / no forks) and tracks
/// liveness (progress toward a finalization target).
pub struct ProgressTracker<P: PublicKey> {
    /// Latest finalized round per validator.
    status: BTreeMap<P, Round>,

    /// Block digests seen at each round (for fork detection).
    digests_by_round: BTreeMap<Round, HashSet<Vec<u8>>>,
}

impl<P: PublicKey> Default for ProgressTracker<P> {
    fn default() -> Self {
        Self {
            status: BTreeMap::new(),
            digests_by_round: BTreeMap::new(),
        }
    }
}

impl<P: PublicKey> ProgressTracker<P> {
    /// Record a finalization update from a validator.
    ///
    /// Returns an error if a different block digest was already seen at
    /// the same round (fork detected).
    ///
    /// Strictly lower rounds are silently ignored: after a crash/restart,
    /// the consensus engine may replay finalizations a validator has
    /// already advanced past. Same-round replays are still checked for
    /// agreement so conflicting digests remain detectable.
    pub fn observe(&mut self, update: FinalizationUpdate<P>) -> Result<(), String> {
        let FinalizationUpdate {
            pk,
            round,
            block_digest,
        } = update;

        // Skip strictly stale replays after crash/restart. Same-round repeats
        // still go through agreement tracking so conflicting digests remain
        // detectable.
        if let Some(prev) = self.status.get(&pk) {
            if *prev > round {
                return Ok(());
            }
        }

        // Check agreement (fork detection)
        let digests = self.digests_by_round.entry(round).or_default();
        digests.insert(block_digest);
        if digests.len() > 1 {
            return Err(format!("fork detected at round {:?}", round));
        }

        self.status.insert(pk, round);
        Ok(())
    }

    /// Check if at least `total` validators have finalized past the required view.
    pub fn all_reached(&self, total: usize, required: u64) -> bool {
        let required_round = Round::new(Epoch::zero(), View::new(required));
        self.status
            .values()
            .filter(|round| **round >= required_round)
            .count()
            >= total
    }

    /// Minimum finalized view across all tracked validators.
    pub fn min_view(&self) -> u64 {
        self.status
            .values()
            .map(|round| round.view().get())
            .min()
            .unwrap_or(0)
    }

    /// Highest finalized round observed from any validator.
    pub fn max_round(&self) -> Option<Round> {
        self.status.values().copied().max()
    }

    /// Number of validators currently being tracked.
    pub fn tracked_count(&self) -> usize {
        self.status.len()
    }

    /// Number of unique finalized block digests observed at `view`.
    pub fn unique_digests_at(&self, view: u64) -> usize {
        self.digests_by_round
            .get(&Round::new(Epoch::zero(), View::new(view)))
            .map_or(0, HashSet::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519, Signer as _};

    #[test]
    fn conflicting_same_round_from_same_validator_is_rejected() {
        let pk = ed25519::PrivateKey::from_seed(7).public_key();
        let mut tracker = ProgressTracker::default();

        tracker
            .observe(FinalizationUpdate {
                pk: pk.clone(),
                round: Round::new(Epoch::zero(), View::new(3)),
                block_digest: vec![1, 2, 3],
            })
            .expect("first update should be accepted");

        let err = tracker
            .observe(FinalizationUpdate {
                pk,
                round: Round::new(Epoch::zero(), View::new(3)),
                block_digest: vec![9, 9, 9],
            })
            .expect_err("conflicting digest at same round should be rejected");
        assert!(err.contains("fork detected"), "unexpected error: {err}");
    }

    #[test]
    fn stale_replay_does_not_poison_agreement_tracking() {
        let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
        let pk2 = ed25519::PrivateKey::from_seed(2).public_key();
        let mut tracker = ProgressTracker::default();

        tracker
            .observe(FinalizationUpdate {
                pk: pk1.clone(),
                round: Round::new(Epoch::zero(), View::new(5)),
                block_digest: vec![5, 5, 5],
            })
            .expect("high-watermark update should be accepted");

        // A stale replay from pk1 should be ignored and must not influence
        // fork detection for that old round.
        tracker
            .observe(FinalizationUpdate {
                pk: pk1,
                round: Round::new(Epoch::zero(), View::new(3)),
                block_digest: vec![1, 1, 1],
            })
            .expect("stale replay should be ignored");

        tracker
            .observe(FinalizationUpdate {
                pk: pk2,
                round: Round::new(Epoch::zero(), View::new(3)),
                block_digest: vec![2, 2, 2],
            })
            .expect("stale replay from another validator should not trigger a fork");
    }

    #[test]
    fn same_view_in_different_epochs_is_not_a_fork() {
        let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
        let pk2 = ed25519::PrivateKey::from_seed(2).public_key();
        let mut tracker = ProgressTracker::default();

        tracker
            .observe(FinalizationUpdate {
                pk: pk1,
                round: Round::new(Epoch::zero(), View::new(3)),
                block_digest: vec![1, 1, 1],
            })
            .expect("epoch zero finalization should be accepted");

        tracker
            .observe(FinalizationUpdate {
                pk: pk2,
                round: Round::new(Epoch::new(1), View::new(3)),
                block_digest: vec![2, 2, 2],
            })
            .expect("same view in another epoch should not trigger a fork");
    }
}
