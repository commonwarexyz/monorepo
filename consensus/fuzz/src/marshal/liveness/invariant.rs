//! End-of-run invariants for the multi-node marshal liveness model.
//!
//! Asserted over the honest nodes' downstream [`Application`] sinks after the
//! liveness window. Panics on violation with the offending state, matching the
//! rest of the consensus fuzz crate. Generic over the marshal variant `H`.

use commonware_consensus::{
    marshal::mocks::{application::Application, harness::TestHarness},
    types::Height,
};
use commonware_cryptography::{sha256::Digest as Sha256Digest, Digestible};
use std::collections::BTreeMap;

/// Run every liveness-model invariant.
pub fn check_all<H: TestHarness>(
    required: u64,
    honest_apps: &[(usize, Application<H::ApplicationBlock>)],
) {
    for (idx, app) in honest_apps {
        let blocks = app.blocks();
        check_in_order::<H>(*idx, required, &blocks);
    }
    check_cross_node_agreement::<H>(honest_apps);
}

/// Invariant: per-node in-order, gap-free delivery.
///
/// Marshal delivers finalized blocks in monotonically increasing height with no
/// gaps, starting at height 1. After liveness, at least `required` blocks must
/// be present, so the keys must be exactly `1..=len`.
fn check_in_order<H: TestHarness>(
    idx: usize,
    required: u64,
    blocks: &BTreeMap<Height, H::ApplicationBlock>,
) {
    let len = blocks.len() as u64;
    assert!(
        len >= required,
        "node{idx} delivered {len} blocks, fewer than required {required}",
    );
    for (offset, height) in blocks.keys().enumerate() {
        let expected = offset as u64 + 1;
        assert_eq!(
            height.get(),
            expected,
            "node{idx} violated in-order/no-gap delivery: expected height {expected}, \
             observed {} (delivered heights={:?})",
            height.get(),
            blocks.keys().map(|h| h.get()).collect::<Vec<_>>(),
        );
    }
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
        for (height, block) in app.blocks() {
            let digest = block.digest();
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
