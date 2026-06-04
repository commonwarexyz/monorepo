//! Marshal fuzz invariants.
//!
//! Each function asserts one property of the marshal-under-test against
//! the driver's shadow state. The orchestrator [`check_all`] runs them
//! in order; runner.rs only calls `check_all`.
//!
//! Conventions match the rest of the consensus fuzz crate: panics on
//! violation, with a message that includes the relevant shadow state so
//! libFuzzer's crash log is self-explanatory.

use commonware_consensus::{
    marshal::mocks::harness::{TestHarness, D},
    types::Height,
};
use std::collections::{BTreeSet, HashSet};

/// Run every marshal invariant. Called from the driver at end of run.
pub fn check_all<H: TestHarness>(
    ready_prefix: u64,
    delivery_log: &[Height],
    segment_bounds: &[usize],
    segment_starts: &[u64],
    expected_redeliveries: &[Vec<Height>],
    application_delivered: &[(Height, D)],
    canonical: &[H::TestBlock],
) {
    check_ready_prefix_delivered(ready_prefix, delivery_log);
    check_segment_ordering(segment_bounds, segment_starts, delivery_log);
    check_redelivery_after_restart(expected_redeliveries, segment_bounds, delivery_log);
    check_digest_fidelity::<H>(application_delivered, canonical);
}

/// Invariant: ready-prefix delivery.
///
/// Every height in `1..=ready_prefix` must appear at least once in
/// `delivery_log`. The driver advances `ready_prefix` only when an
/// above-floor `ReportFinalization` (or restart-triggered repair)
/// observes a complete chain back to height 1, which is precisely when
/// marshal is obliged to deliver the prefix.
pub fn check_ready_prefix_delivered(ready_prefix: u64, delivery_log: &[Height]) {
    let delivered_set: BTreeSet<u64> = delivery_log.iter().map(|h| h.get()).collect();
    for h in 1..=ready_prefix {
        assert!(
            delivered_set.contains(&h),
            "marshal violated at-least-once delivery: ready height {h} never reached \
             the application (ready_prefix={ready_prefix}, delivered={delivered_set:?})",
        );
    }
}

/// Invariant: per-segment in-order delivery.
///
/// Within each actor instance (segment between restarts) marshal must
/// deliver heights starting at `restored processed_height + 1` and
/// advance strictly by one. The driver pre-populates `segment_starts`
/// from each `setup.height` and `segment_bounds` from the delivery_log
/// positions at restart boundaries.
pub fn check_segment_ordering(
    segment_bounds: &[usize],
    segment_starts: &[u64],
    delivery_log: &[Height],
) {
    assert_eq!(
        segment_bounds.len(),
        segment_starts.len() + 1,
        "segment bookkeeping inconsistency",
    );
    for (segment_idx, window) in segment_bounds.windows(2).enumerate() {
        let (start_idx, end_idx) = (window[0], window[1]);
        if start_idx == end_idx {
            continue;
        }
        let segment = &delivery_log[start_idx..end_idx];
        let expected_start = segment_starts[segment_idx];
        assert_eq!(
            segment[0].get(),
            expected_start,
            "segment #{segment_idx} must start at restored processed height + 1 \
             ({expected_start}), got {} (segment={:?})",
            segment[0].get(),
            segment,
        );
        for (offset, h) in segment.iter().enumerate() {
            let expected = expected_start + offset as u64;
            assert_eq!(
                h.get(),
                expected,
                "marshal violated in-order delivery within segment #{segment_idx}: \
                 expected height {expected}, observed {} (segment={:?})",
                h.get(),
                segment,
            );
        }
    }
}

/// Invariant: at-least-once across restart.
///
/// Each height that was pending ack at the moment of restart `i` must reappear
/// after that restart. Their ack handles were never signaled, so marshal's
/// persistent state retains them as un-processed and a later instance is
/// obliged to redeliver.
pub fn check_redelivery_after_restart(
    expected_redeliveries: &[Vec<Height>],
    segment_bounds: &[usize],
    delivery_log: &[Height],
) {
    assert_eq!(
        segment_bounds.len(),
        expected_redeliveries.len() + 2,
        "redelivery bookkeeping inconsistency",
    );
    for (restart_idx, expected) in expected_redeliveries.iter().enumerate() {
        if expected.is_empty() {
            continue;
        }
        let post_restart_start = segment_bounds[restart_idx + 1];
        let post_restart: HashSet<u64> = delivery_log[post_restart_start..]
            .iter()
            .map(|h| h.get())
            .collect();
        for h in expected {
            assert!(
                post_restart.contains(&h.get()),
                "marshal violated at-least-once across restart: height {} was \
                 pending at restart #{} but was never delivered again \
                 (deliveries after restart={post_restart:?})",
                h.get(),
                restart_idx + 1,
            );
        }
    }
}

/// Invariant: digest fidelity.
///
/// Every finalized block surfaced by the application must match the canonical
/// chain digest at its height. The height-0 genesis floor block (which marshal
/// surfaces on a fresh start) is intentionally skipped: it is not part of the
/// canonical chain, which is indexed from height 1. This checks the append-only
/// delivery log so same-height re-emits cannot hide a bad earlier delivery.
pub fn check_digest_fidelity<H: TestHarness>(
    application_delivered: &[(Height, D)],
    canonical: &[H::TestBlock],
) {
    for (height, digest) in application_delivered.iter() {
        // Height 0 is the genesis floor block, not part of the canonical chain
        // (which is indexed from height 1); marshal surfaces it on a fresh start.
        if height.get() == 0 {
            continue;
        }
        let Some(canonical_block) = canonical.get((height.get() - 1) as usize) else {
            panic!(
                "marshal delivered unexpected height {} beyond canonical chain length {}",
                height.get(),
                canonical.len()
            );
        };
        assert_eq!(
            *digest,
            H::digest(canonical_block),
            "marshal delivered a block whose digest does not match the canonical \
             chain at height {}",
            height.get(),
        );
    }
}
