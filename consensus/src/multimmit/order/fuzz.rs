//! Differential ordering: slot streams and symbolic expansion, resumed from random cuts, against
//! an explicitly sorted order.

use super::{Cut, Expansion, FinalSweep, Lanes, Slot, SlotStream, SweepFact};
use crate::{
    multimmit::{
        fuzz::ByteSchedule,
        types::{BlockRef, ChainId, TipRecord},
    },
    types::Height,
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use std::sync::Arc;

/// A slot coordinate: chain index and height.
pub(super) type Coordinate = (usize, u64);

/// Returns the deterministic test block at `height` on `chain`.
pub(super) fn reference(chain: usize, height: u64) -> BlockRef<Digest> {
    BlockRef::new(
        ChainId::new(chain as u32),
        Height::new(height),
        Sha256::hash(&[
            b"marshal history",
            &(chain as u32).to_be_bytes(),
            &height.to_be_bytes(),
        ]),
    )
}

/// Returns the frontier of test blocks at `heights`, one per chain.
pub(super) fn frontier(heights: &[u64]) -> Vec<BlockRef<Digest>> {
    heights
        .iter()
        .enumerate()
        .map(|(chain, height)| reference(chain, *height))
        .collect()
}

/// Returns the coordinate of `slot`.
pub(super) const fn coordinate(slot: Slot<Digest>) -> Coordinate {
    (slot.tip().chain().get() as usize, slot.height().get())
}

/// Returns each chain's maximum height among the `remaining` slot coordinates.
pub(super) fn remaining_maxima(remaining: &[Coordinate], chains: usize) -> Vec<Option<Height>> {
    let mut maxima = vec![None; chains];
    for &(chain, height) in remaining {
        let maximum = &mut maxima[chain];
        *maximum = Some(maximum.unwrap_or(Height::zero()).max(Height::new(height)));
    }
    maxima
}

// Actual slots and virtual stopping holes share the pass/offset/chain ordering key: the payment
// pass, then pass A and pass B of the ordinary chains. Payment chains have no holes.
fn explicit_order(
    base: &[u64],
    target: &[u64],
    proposed: &[u64],
    settled: Option<&[bool]>,
    payment: &[bool],
) -> Vec<Coordinate> {
    let mut events = Vec::new();
    for chain in 0..base.len() {
        if payment[chain] {
            for height in base[chain] + 1..=target[chain] {
                events.push(((0, height - base[chain], chain), Some((chain, height))));
            }
            continue;
        }
        let boundary = target[chain].min(proposed[chain]);
        for height in base[chain] + 1..=target[chain] {
            let (pass, offset) = if height <= boundary {
                (1, height - base[chain])
            } else {
                (2, height - boundary)
            };
            events.push(((pass, offset, chain), Some((chain, height))));
        }
        if let Some(settled) = settled {
            if target[chain] < proposed[chain] {
                events.push(((1, boundary - base[chain] + 1, chain), None));
            }
            if !settled[chain] {
                events.push(((2, target[chain] - boundary + 1, chain), None));
            }
        }
    }
    events.sort_unstable_by_key(|(key, _)| *key);
    events
        .into_iter()
        .map(|(_, value)| value)
        .take_while(Option::is_some)
        .flatten()
        .collect()
}

/// Checks that `stream` yields exactly `expected`, with exact remaining maxima at every step.
fn check_stream(mut stream: SlotStream<Digest>, expected: &[Coordinate], chains: usize) {
    for position in 0..=expected.len() {
        assert_eq!(
            stream.maxima(),
            remaining_maxima(&expected[position..], chains)
        );
        if position == expected.len() {
            break;
        }
        assert_eq!(coordinate(stream.next().unwrap()), expected[position]);
    }
    assert!(stream.next().is_none());
    assert!(stream.next().is_none());
    assert_eq!(stream.maxima(), vec![None; chains]);
}

/// Checks slot streams and the symbolic expansion, resumed from a random cut in every round,
/// against the explicit order.
pub(crate) fn exercise(input: &[u8]) {
    let mut schedule = ByteSchedule::cycling(input);
    let mut next = || schedule.index();
    let chains = 2 + next() % 7;
    let mut base = (0..chains).map(|_| next() as u64).collect::<Vec<_>>();
    // Half the epochs run without payment chains.
    let payment = if next() % 2 == 0 {
        vec![false; chains]
    } else {
        (0..chains).map(|_| next() % 3 == 0).collect::<Vec<_>>()
    };
    let lanes = Lanes::new(payment.iter().copied());
    let mut emitted = base.clone();
    let mut history = Sha256::hash(&[b"initial history"]);
    let mut expected_delivery = Vec::new();
    let mut order_cut = Cut::new(
        history,
        frontier(&base).into(),
        base.iter().map(|height| Height::new(*height)).collect(),
    )
    .unwrap();
    let mut expanded = Vec::new();
    for _ in 0..2 + next() % 10 {
        let round_start = expected_delivery.len();
        let target = base
            .iter()
            .map(|height| height + (next() % 10) as u64)
            .collect::<Vec<_>>();
        let proposed = base
            .iter()
            .map(|height| height + (next() % 12) as u64)
            .collect::<Vec<_>>();
        let settled = (0..chains).map(|_| next() % 2 == 0).collect::<Vec<_>>();
        let proposed_heights = proposed
            .iter()
            .map(|height| Height::new(*height))
            .collect::<Vec<_>>();
        let sweep_order = explicit_order(&base, &target, &proposed, Some(&settled), &payment);
        let horizontal_order = explicit_order(&base, &target, &proposed, None, &payment);
        let sweep = FinalSweep::new(
            &frontier(&base),
            frontier(&target),
            &proposed_heights,
            settled.clone(),
            &lanes,
        )
        .unwrap();
        assert_eq!(sweep.planned(), sweep_order.len() as u64);
        // The halt flag reports deferred target blocks; a hole after every real slot defers none.
        assert_eq!(sweep.halted(), sweep_order.len() < horizontal_order.len());
        check_stream(sweep.into_stream(), &sweep_order, chains);
        check_stream(
            SlotStream::new(
                &frontier(&base),
                &frontier(&target),
                &proposed_heights,
                &lanes,
            )
            .unwrap(),
            &horizontal_order,
            chains,
        );
        // The order of the round: the sweep, then the opening of the next record, each slot
        // emitted once at the next height of its chain.
        for &(chain, height) in sweep_order.iter().chain(&horizontal_order) {
            if height > emitted[chain] {
                assert_eq!(height, emitted[chain] + 1);
                emitted[chain] = height;
                expected_delivery.push((chain, height));
            }
        }
        assert_eq!(emitted, target);

        let record = TipRecord::new(history, frontier(&target), proposed_heights.clone()).unwrap();
        let commitment = record.commitment::<Sha256>();
        // The symbolic expansion yields the same dense sequence, also when resumed from the cut
        // it reached part way through.
        let fact = Arc::new(
            SweepFact::new(frontier(&target), proposed_heights.clone(), settled.clone()).unwrap(),
        );
        let record = Arc::new(record);
        let end = order_cut
            .sweep(&fact, &lanes)
            .unwrap()
            .open(commitment, &record)
            .unwrap();
        let round = expected_delivery.len() - round_start;
        let stop = next() % (round + 1);
        let mut expansion = Expansion::new(order_cut.clone(), lanes.clone());
        expansion.sweep(Arc::clone(&fact));
        expansion.open(commitment, Arc::clone(&record));
        for _ in 0..stop {
            let position = expansion.next_position().unwrap().unwrap();
            assert_eq!(position.index, expansion.cut().index());
            expanded.push((position.chain().get() as usize, position.height.get()));
        }
        let mut resumed = Expansion::new(expansion.cut().clone(), lanes.clone());
        // A cut part way through a round still names the previous record; re-queueing the
        // sweep is harmless because the cut already covers whatever of it was emitted.
        if expansion.cut().history() != commitment {
            resumed.sweep(fact);
            resumed.open(commitment, record);
        }
        while let Some(position) = resumed.next_position().unwrap() {
            assert_eq!(position.index, resumed.cut().index());
            expanded.push((position.chain().get() as usize, position.height.get()));
        }
        assert!(resumed.is_idle());
        order_cut = resumed.cut().clone();
        assert_eq!(order_cut, end);
        assert_eq!(order_cut.history(), commitment);
        assert_eq!(order_cut.index(), target.iter().sum::<u64>());
        assert_eq!(expanded, expected_delivery);
        history = commitment;
        base = target;
    }
}

#[cfg(test)]
mod tests {
    use super::exercise;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn expansion_matches_explicit_order_across_resumed_cuts(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            exercise(&input);
        }
    }
}
