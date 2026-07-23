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
    marshal::mocks::harness::{D, TestHarness},
    types::Height,
};
use std::{
    collections::{BTreeSet, HashSet},
    ops::Range,
};

/// Run every marshal invariant. Called from the driver at end of run.
pub fn check_all<H: TestHarness>(
    ready_prefix: u64,
    application_segment_bounds: &[usize],
    application_candidate_stale_ranges: &[Range<usize>],
    segment_starts: &[u64],
    expected_redeliveries: &[Vec<Height>],
    application_delivered: &[(Height, D)],
    canonical: &[H::TestBlock],
) {
    check_ready_prefix_delivered(ready_prefix, application_delivered);
    check_segment_ordering(
        application_segment_bounds,
        application_candidate_stale_ranges,
        segment_starts,
        application_delivered,
    );
    check_redelivery_after_restart(
        expected_redeliveries,
        application_segment_bounds,
        application_delivered,
    );
    check_digest_fidelity::<H>(application_delivered, canonical);
}

/// Invariant: ready-prefix delivery.
///
/// Every height in `1..=ready_prefix` must appear at least once in the
/// application's delivery record. The driver advances `ready_prefix` only when
/// mirrored repair makes marshal's finalized archive contiguous from height 1,
/// which is precisely when marshal is obliged to deliver the prefix. This
/// checks `application_delivered` (the ground truth of what reached the
/// application) rather than the ack-derived `delivery_log`, which omits stale
/// redeliveries skipped at restart boundaries.
pub fn check_ready_prefix_delivered(ready_prefix: u64, application_delivered: &[(Height, D)]) {
    let delivered_set: BTreeSet<u64> = application_delivered.iter().map(|(h, _)| h.get()).collect();
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
/// from each `setup.height` and `segment_bounds` from the application's
/// append-only delivery log at restart boundaries. Ack-derived observations
/// can skip stale handles orphaned by restart or floor changes, so they are
/// not precise enough for this delivery-order invariant.
///
/// Entries in `candidate_stale_ranges` are ambiguous: the driver observed each
/// range where one floor transition may have orphaned its ack waiters, but
/// asynchronous mailbox handling can also make the floor stale before it clears
/// those waiters. Treat each whole range as either stale or live, and require at
/// least one classification in which every live delivery forms the exact
/// contiguous sequence. A floor clears all of its pending waiters together, so
/// individual entries within one range cannot be classified independently.
/// Unmarked entries are always live and cannot be skipped.
pub fn check_segment_ordering(
    segment_bounds: &[usize],
    candidate_stale_ranges: &[Range<usize>],
    segment_starts: &[u64],
    application_delivered: &[(Height, D)],
) {
    assert_eq!(
        segment_bounds.len(),
        segment_starts.len() + 1,
        "segment bookkeeping inconsistency",
    );
    let mut previous_candidate_end = 0;
    for candidate in candidate_stale_ranges {
        assert!(
            candidate.start < candidate.end
                && candidate.end <= application_delivered.len()
                && candidate.start >= previous_candidate_end
                && application_delivered[candidate.clone()]
                    .iter()
                    .all(|(height, _)| height.get() != 0),
            "candidate stale ranges must be non-empty, ordered, non-overlapping, and in bounds: \
             {candidate_stale_ranges:?}",
        );
        assert!(
            segment_bounds
                .windows(2)
                .any(|window| window[0] <= candidate.start && candidate.end <= window[1]),
            "candidate stale range {candidate:?} crosses an actor segment boundary",
        );
        previous_candidate_end = candidate.end;
    }
    for (segment_idx, window) in segment_bounds.windows(2).enumerate() {
        let (start_idx, end_idx) = (window[0], window[1]);
        if start_idx == end_idx {
            continue;
        }
        let segment = application_delivered[start_idx..end_idx]
            .iter()
            .enumerate()
            .map(|(offset, (height, _))| (start_idx + offset, *height))
            .filter(|(_, height)| height.get() != 0)
            .collect::<Vec<_>>();
        if segment.is_empty() {
            continue;
        }
        let expected_start = segment_starts[segment_idx];
        assert!(
            segment_ordering_is_possible(expected_start, &segment, candidate_stale_ranges),
            "marshal violated in-order delivery within segment #{segment_idx}: no assignment \
             of ambiguous floor-orphaned deliveries produces a sequence starting at \
             {expected_start} (segment={segment:?}, candidates={candidate_stale_ranges:?})",
        );
    }
}

fn segment_ordering_is_possible(
    expected_start: u64,
    segment: &[(usize, Height)],
    candidate_stale_ranges: &[Range<usize>],
) -> bool {
    let mut possible_next = BTreeSet::from([expected_start]);
    let mut position = 0;
    while position < segment.len() {
        let delivery_idx = segment[position].0;
        let Some(candidate) = candidate_stale_ranges
            .iter()
            .find(|candidate| candidate.start == delivery_idx)
        else {
            possible_next = consume_deliveries(possible_next, &segment[position..position + 1]);
            if possible_next.is_empty() {
                return false;
            }
            position += 1;
            continue;
        };

        let group_len = candidate.end - candidate.start;
        let group_end = position + group_len;
        if group_len == 0
            || group_end > segment.len()
            || segment[group_end - 1].0.saturating_add(1) != candidate.end
        {
            return false;
        }

        // One floor transition clears all pending waiters together. Branch once
        // for the whole observed range: skip all as stale, or consume all as live.
        let live_next = consume_deliveries(possible_next.clone(), &segment[position..group_end]);
        possible_next.extend(live_next);
        position = group_end;
    }
    true
}

fn consume_deliveries(
    mut possible_next: BTreeSet<u64>,
    deliveries: &[(usize, Height)],
) -> BTreeSet<u64> {
    for (_, height) in deliveries {
        let mut next = BTreeSet::new();
        for expected in possible_next {
            if height.get() == expected {
                next.insert(expected.saturating_add(1));
            }
        }
        possible_next = next;
    }
    possible_next
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
    application_delivered: &[(Height, D)],
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
        let post_restart: HashSet<u64> = application_delivered[post_restart_start..]
            .iter()
            .map(|(height, _)| height.get())
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
