//! End-of-run invariants for the multi-node marshal liveness model.
//!
//! Asserted over the honest nodes' downstream [`Application`] sinks after the
//! liveness window. Panics on violation with the offending state, matching the
//! rest of the consensus fuzz crate. Generic over the marshal variant `H`.
//!
//! Checks operate on the sink's append-only delivery log
//! ([`Application::delivered`]) -- the actual `(height, digest)` arrival
//! sequence -- rather than a by-height snapshot, so out-of-order delivery,
//! gaps, duplicates, and same-height forks are all observable (a by-height map
//! would silently overwrite them).

use commonware_consensus::{
    marshal::mocks::{application::Application, harness::TestHarness},
    types::Height,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::collections::BTreeMap;

/// Run every liveness-model invariant.
pub fn check_all<H: TestHarness>(
    required: u64,
    honest_apps: &[(usize, Application<H::ApplicationBlock>)],
) {
    for (idx, app) in honest_apps {
        check_in_order(*idx, required, &app.delivered());
    }
    check_cross_node_agreement::<H>(honest_apps);
}

/// Invariant: per-node in-order, gap-free delivery.
///
/// Walks the arrival-ordered delivery log. Delivery starts either at the
/// genesis floor block (height 0, surfaced on a fresh start) or at the first
/// finalized container (height 1), then every subsequent delivery must advance
/// by exactly one. Because this is the true arrival sequence, an out-of-order
/// delivery, a gap, or a duplicate/refinalized height all fail the `+ 1` check.
/// After liveness the highest delivered height must be at least `required`.
fn check_in_order<D>(idx: usize, required: u64, delivered: &[(Height, D)]) {
    let heights: Vec<u64> = delivered.iter().map(|(h, _)| h.get()).collect();
    let first = heights.first().copied().unwrap_or(0);
    assert!(
        first <= 1,
        "node{idx} first delivery at height {first} is above the genesis floor + 1 \
         (sequence={heights:?})",
    );
    for window in heights.windows(2) {
        assert_eq!(
            window[1],
            window[0] + 1,
            "node{idx} violated in-order delivery (out-of-order, gap, or duplicate); \
             sequence={heights:?}",
        );
    }
    let max = heights.last().copied().unwrap_or(0);
    assert!(
        max >= required,
        "node{idx} delivered up to height {max}, fewer than required {required} \
         (sequence={heights:?})",
    );
}

/// Invariant: cross-node agreement (safety).
///
/// No honest fork: any height delivered by more than one honest node must carry
/// the same block digest everywhere it appears.
fn check_cross_node_agreement<H: TestHarness>(
    honest_apps: &[(usize, Application<H::ApplicationBlock>)],
) {
    let mut seen: BTreeMap<Height, (usize, Sha256Digest)> = BTreeMap::new();
    for (idx, app) in honest_apps {
        for (height, digest) in app.delivered() {
            if let Some((first_idx, first_digest)) = seen.get(&height) {
                assert_eq!(
                    *first_digest,
                    digest,
                    "honest fork at height {}: node{first_idx} delivered {first_digest:?} \
                     but node{idx} delivered {digest:?}",
                    height.get(),
                );
            } else {
                seen.insert(height, (*idx, digest));
            }
        }
    }
}
