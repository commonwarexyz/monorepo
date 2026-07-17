//! Step-level safety oracle: at most one payload may be finalized per view.
//!
//! This reads the reporters' `finalizes` participation map, which is keyed by
//! payload and therefore APPEND-ONLY (unlike the `finalizations` certificate
//! map, which overwrites per view and loses a conflict landing between two
//! polls). In N4F0C4 two conflicting finalization certificates require two
//! overlapping quorums of three, i.e. at least two nodes finalize-voting for
//! both payloads, so a conflict always surfaces here as a second distinct
//! payload under the same view, no matter the poll timing.
//!
//! Chaos checks SAFETY only. It does not check liveness: a sound liveness
//! oracle would need a journal-replay / catch-up completion signal the harness
//! does not expose, and the finalization monitors are lossy.

use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::collections::HashMap;

/// Tracks the first finalized payload seen per view (across all reporters).
pub(crate) struct Checker {
    finalized: HashMap<u64, Sha256Digest>,
}

impl Checker {
    pub(crate) fn new() -> Self {
        Self {
            finalized: HashMap::new(),
        }
    }

    /// Panic on a second distinct finalized payload for any view.
    pub(crate) fn observe(&mut self, finalize_votes: &[(u64, Sha256Digest)]) {
        for (view, payload) in finalize_votes {
            match self.finalized.get(view) {
                Some(previous) => assert!(
                    previous == payload,
                    "chaos: two payloads finalized in view {view}: {previous:?} and {payload:?}",
                ),
                None => {
                    self.finalized.insert(*view, *payload);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(tag: u8) -> Sha256Digest {
        Sha256Digest::from([tag; 32])
    }

    #[test]
    #[should_panic(expected = "chaos: two payloads finalized in view 5")]
    fn two_payloads_in_one_view_is_a_finding() {
        let mut checker = Checker::new();
        // Both conflicting payloads in one observation: the append-only map
        // cannot lose one between polls.
        checker.observe(&[(5, digest(1)), (5, digest(2))]);
    }

    #[test]
    #[should_panic(expected = "chaos: two payloads finalized in view 5")]
    fn a_conflict_split_across_polls_is_a_finding() {
        let mut checker = Checker::new();
        checker.observe(&[(5, digest(1))]);
        checker.observe(&[(5, digest(2))]);
    }

    #[test]
    fn re_reported_votes_with_a_stable_payload_are_not_findings() {
        let mut checker = Checker::new();
        checker.observe(&[(5, digest(1)), (6, digest(2))]);
        checker.observe(&[(5, digest(1)), (6, digest(2))]);
    }
}
