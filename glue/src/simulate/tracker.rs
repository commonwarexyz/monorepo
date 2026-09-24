//! Finalization progress tracking and agreement checking.

use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::PublicKey;
use std::collections::{BTreeMap, HashSet};

/// A finalization event from a validator.
pub struct FinalizationUpdate<P: PublicKey> {
    /// Which validator reported this finalization.
    pub pk: P,
    /// The finalized round.
    pub round: Round,
    /// The finalized application height.
    pub height: Height,
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

    /// Block digest seen at each application height.
    digests_by_height: BTreeMap<Height, Vec<u8>>,
}

impl<P: PublicKey> Default for ProgressTracker<P> {
    fn default() -> Self {
        Self {
            status: BTreeMap::new(),
            digests_by_round: BTreeMap::new(),
            digests_by_height: BTreeMap::new(),
        }
    }
}

impl<P: PublicKey> ProgressTracker<P> {
    /// Record a finalization update from a validator.
    ///
    /// Returns an error if a different block digest was already seen at
    /// the same round or application height. Replayed tips are checked for
    /// agreement without regressing the validator's latest finalized round.
    pub fn observe(&mut self, update: FinalizationUpdate<P>) -> Result<(), String> {
        let FinalizationUpdate {
            pk,
            round,
            height,
            block_digest,
        } = update;

        let digest = self
            .digests_by_height
            .entry(height)
            .or_insert_with(|| block_digest.clone());
        if *digest != block_digest {
            return Err(format!("fork detected at height {height}"));
        }

        let digests = self.digests_by_round.entry(round).or_default();
        digests.insert(block_digest);
        if digests.len() > 1 {
            return Err(format!("fork detected at round {:?}", round));
        }

        self.status
            .entry(pk)
            .and_modify(|previous| *previous = (*previous).max(round))
            .or_insert(round);
        Ok(())
    }

    /// Check if at least `total` validators have finalized past the required view.
    pub fn all_reached(&self, total: usize, required: u64) -> bool {
        let required_view = View::new(required);
        self.status
            .values()
            .filter(|round| round.view() >= required_view)
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
    use commonware_cryptography::{Signer as _, ed25519};

    fn observe_view(
        tracker: &mut ProgressTracker<ed25519::PublicKey>,
        seed: u64,
        epoch: u64,
        view: u64,
    ) {
        tracker
            .observe(FinalizationUpdate {
                pk: ed25519::PrivateKey::from_seed(seed).public_key(),
                round: Round::new(Epoch::new(epoch), View::new(view)),
                height: Height::new(view),
                block_digest: view.to_le_bytes().to_vec(),
            })
            .expect("finalization should be accepted");
    }

    #[test]
    fn conflicting_same_round_from_same_validator_is_rejected() {
        let pk = ed25519::PrivateKey::from_seed(7).public_key();
        let mut tracker = ProgressTracker::default();

        tracker
            .observe(FinalizationUpdate {
                pk: pk.clone(),
                round: Round::new(Epoch::zero(), View::new(3)),
                height: Height::new(3),
                block_digest: vec![1, 2, 3],
            })
            .expect("first update should be accepted");

        let err = tracker
            .observe(FinalizationUpdate {
                pk,
                round: Round::new(Epoch::zero(), View::new(3)),
                height: Height::new(4),
                block_digest: vec![9, 9, 9],
            })
            .expect_err("conflicting digest at same round should be rejected");
        assert!(
            err.contains("fork detected at round"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn stale_replay_is_checked_without_regressing_progress() {
        let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
        let pk2 = ed25519::PrivateKey::from_seed(2).public_key();
        let mut tracker = ProgressTracker::default();

        tracker
            .observe(FinalizationUpdate {
                pk: pk1.clone(),
                round: Round::new(Epoch::zero(), View::new(5)),
                height: Height::new(5),
                block_digest: vec![5, 5, 5],
            })
            .expect("high-watermark update should be accepted");

        tracker
            .observe(FinalizationUpdate {
                pk: pk1,
                round: Round::new(Epoch::zero(), View::new(3)),
                height: Height::new(3),
                block_digest: vec![1, 1, 1],
            })
            .expect("stale replay should be accepted");
        assert_eq!(tracker.min_view(), 5);

        let err = tracker
            .observe(FinalizationUpdate {
                pk: pk2,
                round: Round::new(Epoch::zero(), View::new(3)),
                height: Height::new(3),
                block_digest: vec![2, 2, 2],
            })
            .expect_err("conflict with a stale replay must be rejected");
        assert!(err.contains("fork detected"));
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
                height: Height::new(3),
                block_digest: vec![1, 1, 1],
            })
            .expect("epoch zero finalization should be accepted");

        tracker
            .observe(FinalizationUpdate {
                pk: pk2,
                round: Round::new(Epoch::new(1), View::new(3)),
                height: Height::new(8),
                block_digest: vec![2, 2, 2],
            })
            .expect("same view in another epoch should not trigger a fork");
    }

    #[test]
    fn later_epoch_low_view_does_not_satisfy_required_view() {
        let mut tracker = ProgressTracker::default();

        observe_view(&mut tracker, 1, 1, 1);
        observe_view(&mut tracker, 2, 1, 2);

        assert!(!tracker.all_reached(1, 10));
        assert!(!tracker.all_reached(2, 10));
    }

    #[test]
    fn exact_required_view_satisfies_progress_threshold() {
        let mut tracker = ProgressTracker::default();

        observe_view(&mut tracker, 1, 0, 10);
        observe_view(&mut tracker, 2, 1, 10);

        assert!(tracker.all_reached(1, 10));
        assert!(tracker.all_reached(2, 10));
        assert!(!tracker.all_reached(1, 11));
    }
}
