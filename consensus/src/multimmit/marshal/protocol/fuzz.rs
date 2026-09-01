//! Differential ordering histories with partial iteration and acknowledged-frontier replay.

use super::order::{FinalSweep, HistoryState, Horizontal, OrderedSlots, Reconciliation, Slot};
use crate::{
    multimmit::types::{BlockRef, ChainId, TipRecord},
    types::Height,
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};

type Coordinate = (usize, u64);

fn reference(chain: usize, height: u64) -> BlockRef<Digest> {
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

fn frontier(heights: &[u64]) -> Vec<BlockRef<Digest>> {
    heights
        .iter()
        .enumerate()
        .map(|(chain, height)| reference(chain, *height))
        .collect()
}

const fn coordinate(slot: Slot<Digest>) -> Coordinate {
    (slot.tip().chain().get() as usize, slot.height().get())
}

// Actual slots and virtual stopping holes share the pass/offset/chain ordering key.
fn explicit_order(
    base: &[u64],
    target: &[u64],
    proposed: &[u64],
    settled: Option<&[bool]>,
) -> Vec<Coordinate> {
    let mut events = Vec::new();
    for chain in 0..base.len() {
        let boundary = target[chain].min(proposed[chain]);
        for height in base[chain] + 1..=target[chain] {
            let (pass, offset) = if height <= boundary {
                (0, height - base[chain])
            } else {
                (1, height - boundary)
            };
            events.push(((pass, offset, chain), Some((chain, height))));
        }
        if let Some(settled) = settled {
            if target[chain] < proposed[chain] {
                events.push(((0, boundary - base[chain] + 1, chain), None));
            }
            if !settled[chain] {
                events.push(((1, target[chain] - boundary + 1, chain), None));
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

fn consume(
    mut stream: impl OrderedSlots<Digest>,
    expected: &[Coordinate],
    count: usize,
    state: &mut HistoryState<Digest>,
    acknowledged: &mut [u64],
    delivered: &mut Vec<Coordinate>,
) {
    for position in 0..=count {
        let mut maxima = vec![None; acknowledged.len()];
        for &(chain, height) in &expected[position..] {
            let maximum = &mut maxima[chain];
            *maximum = Some(maximum.unwrap_or(Height::zero()).max(Height::new(height)));
        }
        assert_eq!(stream.maxima(), maxima);
        if position == count {
            break;
        }
        let slot = stream.next().unwrap();
        let (chain, height) = coordinate(slot);
        assert_eq!((chain, height), expected[position]);
        let action = state.reconcile(slot, reference(chain, height)).unwrap();
        if height <= acknowledged[chain] {
            assert_eq!(action, Reconciliation::Duplicate);
        } else {
            assert_eq!(height, acknowledged[chain] + 1);
            assert_eq!(action, Reconciliation::Emit);
            acknowledged[chain] = height;
            delivered.push((chain, height));
        }
        assert_eq!(state.emitted(), frontier(acknowledged));
    }
    if count == expected.len() {
        assert!(stream.next().is_none());
        assert!(stream.next().is_none());
        assert_eq!(stream.maxima(), vec![None; acknowledged.len()]);
    }
}

/// Checks sweep ordering, history reconciliation, and dense output sequence across replay cuts.
pub(crate) fn exercise(input: &[u8]) {
    let mut bytes = input.iter().copied().cycle();
    let mut next = || bytes.next().unwrap_or(0) as usize;
    let chains = 2 + next() % 7;
    let mut base = (0..chains).map(|_| next() as u64).collect::<Vec<_>>();
    let mut acknowledged = base.clone();
    let mut history = Sha256::hash(&[b"initial history"]);
    let mut state = HistoryState::new(history, frontier(&base), frontier(&base)).unwrap();
    let mut delivered = Vec::new();
    let mut expected_delivery = Vec::new();
    for _ in 0..2 + next() % 10 {
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
        let sweep_order = explicit_order(&base, &target, &proposed, Some(&settled));
        let horizontal_order = explicit_order(&base, &target, &proposed, None);
        let make_sweep = || {
            FinalSweep::new(
                &frontier(&base),
                frontier(&target),
                &proposed_heights,
                settled.clone(),
            )
            .unwrap()
        };
        let sweep = make_sweep();
        assert_eq!(sweep.planned(), sweep_order.len() as u64);
        // The halt flag reports deferred target blocks; a hole after every real slot defers none.
        assert_eq!(sweep.halted(), sweep_order.len() < horizontal_order.len());
        let mut oracle_frontier = acknowledged.clone();
        for &(chain, height) in sweep_order.iter().chain(&horizontal_order) {
            if height > oracle_frontier[chain] {
                assert_eq!(height, oracle_frontier[chain] + 1);
                oracle_frontier[chain] = height;
                expected_delivery.push((chain, height));
            }
        }
        let cut = next() % (sweep_order.len() + 1);
        consume(
            sweep,
            &sweep_order,
            cut,
            &mut state,
            &mut acknowledged,
            &mut delivered,
        );
        state = HistoryState::new(
            state.history(),
            state.ordered().to_vec(),
            state.emitted().to_vec(),
        )
        .unwrap();
        consume(
            make_sweep(),
            &sweep_order,
            sweep_order.len(),
            &mut state,
            &mut acknowledged,
            &mut delivered,
        );

        let record = TipRecord::new(history, frontier(&target), proposed_heights.clone()).unwrap();
        let commitment = record.commitment::<Sha256>();
        let common = target
            .iter()
            .zip(&acknowledged)
            .map(|(target, ack)| (*target).min(*ack))
            .collect::<Vec<_>>();
        state
            .validate_opening::<Sha256>(commitment, &record, &frontier(&common))
            .unwrap();
        // A contradictory resolved common ancestor must never authorize duplicate suppression.
        let mut wrong_common = frontier(&common);
        wrong_common[0] = BlockRef::new(
            wrong_common[0].chain(),
            wrong_common[0].height(),
            Sha256::hash(&[b"fork"]),
        );
        assert!(
            state
                .validate_opening::<Sha256>(commitment, &record, &wrong_common)
                .is_err()
        );
        let make_horizontal =
            || Horizontal::new(&frontier(&base), &frontier(&target), &proposed_heights).unwrap();
        let cut = next() % (horizontal_order.len() + 1);
        consume(
            make_horizontal(),
            &horizontal_order,
            cut,
            &mut state,
            &mut acknowledged,
            &mut delivered,
        );
        state = HistoryState::new(
            state.history(),
            state.ordered().to_vec(),
            state.emitted().to_vec(),
        )
        .unwrap();
        consume(
            make_horizontal(),
            &horizontal_order,
            horizontal_order.len(),
            &mut state,
            &mut acknowledged,
            &mut delivered,
        );
        state.finish_opening::<Sha256>(commitment, &record).unwrap();
        assert_eq!(state.ordered(), frontier(&target));
        assert_eq!(acknowledged, target);
        assert_eq!(delivered, expected_delivery);
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
        fn ragged_history_replay_matches_explicit_order(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            exercise(&input);
        }
    }
}
