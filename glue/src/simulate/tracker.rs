//! Finalization progress tracking and agreement checking.

use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;
use std::collections::{BTreeMap, HashSet};

/// A finalization event from a validator.
pub struct FinalizationUpdate<P: PublicKey> {
    /// Which validator reported this finalization.
    pub pk: P,
    /// The finalized view.
    pub view: View,
    /// The digest of the finalized block (encoded as bytes).
    pub block_digest: Vec<u8>,
}

/// Tracks finalization progress across all validators.
///
/// Validates safety invariants (agreement / no forks) and tracks
/// liveness (progress toward a finalization target).
pub struct ProgressTracker<P: PublicKey> {
    /// Latest finalized view per validator.
    status: BTreeMap<P, View>,

    /// Block digests seen at each view (for fork detection).
    digests_by_view: BTreeMap<View, HashSet<Vec<u8>>>,
}

impl<P: PublicKey> Default for ProgressTracker<P> {
    fn default() -> Self {
        Self {
            status: BTreeMap::new(),
            digests_by_view: BTreeMap::new(),
        }
    }
}

impl<P: PublicKey> ProgressTracker<P> {
    /// Record a finalization update from a validator.
    ///
    /// Returns an error if a different block digest was already seen at
    /// the same view (fork detected).
    ///
    /// Strictly lower views are silently ignored: after a crash/restart,
    /// the consensus engine may replay finalizations a validator has
    /// already advanced past. Same-view replays are still checked for
    /// agreement so conflicting digests remain detectable.
    pub fn observe(&mut self, update: FinalizationUpdate<P>) -> Result<(), String> {
        let FinalizationUpdate {
            pk,
            view,
            block_digest,
        } = update;

        // Skip strictly stale replays after crash/restart. Same-view repeats
        // still go through agreement tracking so conflicting digests remain
        // detectable.
        if let Some(prev) = self.status.get(&pk) {
            if *prev > view {
                return Ok(());
            }
        }

        // Check agreement (fork detection)
        let digests = self.digests_by_view.entry(view).or_default();
        digests.insert(block_digest);
        if digests.len() > 1 {
            return Err(format!("fork detected at view {:?}", view));
        }

        self.status.insert(pk, view);
        Ok(())
    }

    /// Check if at least `total` validators have finalized past the required view.
    pub fn all_reached(&self, total: usize, required: u64) -> bool {
        let required_view = View::new(required);
        self.status
            .values()
            .filter(|v| **v >= required_view)
            .count()
            >= total
    }

    /// Minimum finalized view across all tracked validators.
    pub fn min_view(&self) -> u64 {
        self.status.values().map(|v| v.get()).min().unwrap_or(0)
    }

    /// Number of validators currently being tracked.
    pub fn tracked_count(&self) -> usize {
        self.status.len()
    }

    /// Number of unique finalized block digests observed at `view`.
    pub fn unique_digests_at(&self, view: u64) -> usize {
        self.digests_by_view
            .get(&View::new(view))
            .map_or(0, HashSet::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519, Signer as _};

    #[test]
    fn conflicting_same_view_from_same_validator_is_rejected() {
        let pk = ed25519::PrivateKey::from_seed(7).public_key();
        let mut tracker = ProgressTracker::default();

        tracker
            .observe(FinalizationUpdate {
                pk: pk.clone(),
                view: View::new(3),
                block_digest: vec![1, 2, 3],
            })
            .expect("first update should be accepted");

        let err = tracker
            .observe(FinalizationUpdate {
                pk,
                view: View::new(3),
                block_digest: vec![9, 9, 9],
            })
            .expect_err("conflicting digest at same view should be rejected");
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
                view: View::new(5),
                block_digest: vec![5, 5, 5],
            })
            .expect("high-watermark update should be accepted");

        // A stale replay from pk1 should be ignored and must not influence
        // fork detection for that old view.
        tracker
            .observe(FinalizationUpdate {
                pk: pk1,
                view: View::new(3),
                block_digest: vec![1, 1, 1],
            })
            .expect("stale replay should be ignored");

        tracker
            .observe(FinalizationUpdate {
                pk: pk2,
                view: View::new(3),
                block_digest: vec![2, 2, 2],
            })
            .expect("stale replay from another validator should not trigger a fork");
    }
}
