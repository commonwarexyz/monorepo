//! Ordered history openings with partial delivery and replay, checked against an explicit
//! enumeration of the horizontal order; the body of the `fuzz_marshal` target.
//!
//! Each view reports zero or more monotone open-view sweeps (`ViewSweep` facts) and then its
//! resolution (`ViewResolved`). Every stream is delivered up to a random cut, the cut is
//! restarted from its durable parts (view, history, ordered and emitted frontiers), and the whole
//! stream is replayed. The output must be the concatenation of every view's enumerated order,
//! each block exactly once.

use super::order::{
    self, Error, HistoryState, Reconciliation, horizontal, settled_flags, sweep, sweep_maxima,
};
use crate::{
    multimmit::{
        algebra::Append,
        types::{BlockRef, ChainId, ChainSet, HistoryRecord},
    },
    types::{Height, View},
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_utils::FuzzRng;
use rand::{Rng, RngExt as _};

/// A block coordinate: chain index and height.
type Point = (usize, u64);

const MAX_CHAINS: usize = 5;
const MAX_VIEWS: usize = 6;
const MAX_SWEEPS: usize = 3;
const MAX_LEAD: u64 = 4;

/// Runs one ordering campaign with choices drawn from `input`.
pub(crate) fn exercise(input: &[u8]) {
    campaign(&mut FuzzRng::new(input.to_vec()));
}

/// Returns the block at `height` on `chain`; each coordinate has one block.
fn block(chain: usize, height: u64) -> BlockRef<Digest> {
    BlockRef::new(
        ChainId::new(chain as u32),
        Height::new(height),
        Sha256::hash(&[
            b"marshal fuzz",
            &(chain as u32).to_be_bytes(),
            &height.to_be_bytes(),
        ]),
    )
}

fn frontier(heights: &[u64]) -> Vec<BlockRef<Digest>> {
    heights
        .iter()
        .enumerate()
        .map(|(chain, height)| block(chain, *height))
        .collect()
}

fn heights(blocks: &[BlockRef<Digest>]) -> Vec<u64> {
    blocks.iter().map(|block| block.height().get()).collect()
}

/// The horizontal order above `base` up to `tips`, enumerated from its definition: offset first,
/// then chain.
fn enumerate_horizontal(base: &[u64], tips: &[u64]) -> Vec<Point> {
    let last = base.iter().zip(tips).map(|(b, t)| t - b).max().unwrap_or(0);
    let mut order = Vec::new();
    for offset in 1..=last {
        for (chain, (base, tip)) in base.iter().zip(tips).enumerate() {
            if base + offset <= *tip {
                order.push((chain, base + offset));
            }
        }
    }
    order
}

/// The sweep above `base` enumerated from its definition: the horizontal order up to the
/// furthest final tip, stopping at the first coordinate of an unsettled chain above its final tip.
fn enumerate_sweep(base: &[u64], finals: &[u64], settled: &[bool]) -> Vec<Point> {
    let last = base
        .iter()
        .zip(finals)
        .map(|(b, f)| f - b)
        .max()
        .unwrap_or(0);
    let mut order = Vec::new();
    for offset in 1..=last {
        for chain in 0..base.len() {
            let height = base[chain] + offset;
            if height <= finals[chain] {
                order.push((chain, height));
            } else if !settled[chain] {
                return order;
            }
        }
    }
    order
}

fn points(slots: &[Append<Digest>]) -> Vec<Point> {
    slots
        .iter()
        .map(|slot| {
            assert_eq!(slot.tip.chain(), slot.chain);
            (slot.chain.index(), slot.height.get())
        })
        .collect()
}

/// Rebuilds `state` from the parts a checkpoint persists.
fn restart(state: &HistoryState<Digest>) -> HistoryState<Digest> {
    HistoryState::new(
        state.view(),
        state.history(),
        state.ordered().to_vec(),
        state.emitted().to_vec(),
    )
    .expect("a live cut is a valid checkpoint")
}

/// Delivers `slots` up to a random cut, restarts, and replays all of them, appending every newly
/// emitted block to `delivered`.
fn deliver(
    rng: &mut impl Rng,
    state: &mut HistoryState<Digest>,
    slots: &[Append<Digest>],
    delivered: &mut Vec<Point>,
) {
    let cut = rng.random_range(0..=slots.len());
    for slot in &slots[..cut] {
        reconcile(state, *slot, delivered);
    }
    *state = restart(state);
    for slot in slots {
        reconcile(state, *slot, delivered);
    }
}

/// Reconciles one slot: blocks at or below the emitted frontier are duplicates, the next block of
/// its chain is emitted.
fn reconcile(state: &mut HistoryState<Digest>, slot: Append<Digest>, delivered: &mut Vec<Point>) {
    let (chain, height) = (slot.chain.index(), slot.height.get());
    let emitted = state.emitted()[chain].height().get();
    let action = state.reconcile(slot, block(chain, height)).unwrap();
    if height <= emitted {
        assert_eq!(action, Reconciliation::Duplicate);
    } else {
        assert_eq!(height, emitted + 1);
        assert_eq!(action, Reconciliation::Emit);
        delivered.push((chain, height));
    }
}

/// Checks that a block conflicting with the emitted frontier is rejected without changing the
/// cut.
fn reject_fork(rng: &mut impl Rng, state: &mut HistoryState<Digest>) {
    let chain = rng.random_range(0..state.emitted().len());
    let emitted = state.emitted()[chain];
    let fork = BlockRef::new(emitted.chain(), emitted.height(), Sha256::hash(&[b"fork"]));
    let slot = Append {
        chain: emitted.chain(),
        height: emitted.height(),
        tip: fork,
    };
    let before = state.clone();
    assert_eq!(state.reconcile(slot, fork), Err(Error::Conflict));
    assert_eq!(*state, before);
}

fn campaign(rng: &mut impl Rng) {
    let chains = rng.random_range(1..=MAX_CHAINS);
    let origin: Vec<u64> = (0..chains).map(|_| rng.random_range(0..=3)).collect();
    let mut ordered = origin.clone();
    let mut state = HistoryState::new(
        View::zero(),
        Sha256::hash(&[b"genesis history"]),
        frontier(&origin),
        frontier(&origin),
    )
    .unwrap();
    let mut delivered = Vec::new();
    let mut expected = Vec::new();

    for view in 1..=rng.random_range(1..=MAX_VIEWS) as u64 {
        let tips: Vec<u64> = ordered
            .iter()
            .map(|height| height + rng.random_range(0..=MAX_LEAD))
            .collect();

        // Monotone sweeps of the open view: final tips rise toward the view's tips, and a chain
        // settles only at the view's tip (a settled chain's final tip is the tip it resolves to).
        let mut finals = ordered.clone();
        let mut settled = vec![false; chains];
        for _ in 0..rng.random_range(0..=MAX_SWEEPS) {
            for chain in 0..chains {
                if settled[chain] {
                    continue;
                }
                finals[chain] = rng.random_range(finals[chain]..=tips[chain]);
                settled[chain] = finals[chain] == tips[chain] && rng.random_bool(0.5);
            }
            let set = ChainSet::from_chains(
                chains,
                (0..chains)
                    .filter(|chain| settled[*chain])
                    .map(|chain| ChainId::new(chain as u32)),
            )
            .unwrap();
            let flags = settled_flags(chains, &set).unwrap();
            let base = frontier(&ordered);
            let final_tips = frontier(&finals);
            let slots: Vec<_> = sweep(&base, &final_tips, &flags).unwrap().collect();
            assert_eq!(points(&slots), enumerate_sweep(&ordered, &finals, &flags));
            let mut maxima = vec![None; chains];
            for slot in &slots {
                maxima[slot.chain.index()] = Some(slot.height);
            }
            assert_eq!(sweep_maxima(&base, &final_tips, &flags), maxima);

            // A later sweep of the view covers what earlier sweeps emitted.
            state.check_prefix(slots.iter().copied()).unwrap();
            deliver(rng, &mut state, &slots, &mut delivered);
        }
        reject_fork(rng, &mut state);

        // A resolution that drops a swept block contradicts the sweep.
        if let Some(chain) =
            (0..chains).find(|chain| state.emitted()[*chain] != state.ordered()[*chain])
        {
            let mut lower = tips.clone();
            lower[chain] = state.emitted()[chain].height().get() - 1;
            let lower = frontier(&lower);
            let base = frontier(&ordered);
            let order = horizontal(&base, [lower.as_slice()]).unwrap();
            assert_eq!(state.check_prefix(order), Err(Error::Prefix));
        }

        // The resolution of the view.
        let base = frontier(&ordered);
        let resolved = frontier(&tips);
        let slots: Vec<_> = horizontal(&base, [resolved.as_slice()]).unwrap().collect();
        let enumerated = enumerate_horizontal(&ordered, &tips);
        assert_eq!(points(&slots), enumerated);
        assert_eq!(
            order::outputs(&base, &resolved).unwrap(),
            enumerated.len() as u64
        );
        state.check_prefix(slots.iter().copied()).unwrap();
        deliver(rng, &mut state, &slots, &mut delivered);
        expected.extend(enumerated);

        let record = HistoryRecord::new(state.history(), resolved.clone()).unwrap();
        let commitment = record.commitment::<Sha256>();
        let stray = HistoryRecord::new(Sha256::hash(&[b"stray"]), resolved.clone()).unwrap();
        assert_eq!(
            state.finish_opening::<Sha256>(stray.commitment::<Sha256>(), &stray),
            Err(Error::History)
        );
        state.finish_opening::<Sha256>(commitment, &record).unwrap();
        assert_eq!(state.view(), View::new(view));
        assert_eq!(state.history(), commitment);
        assert_eq!(state.ordered(), resolved.as_slice());
        assert_eq!(state.emitted(), resolved.as_slice());
        ordered = tips;
    }

    assert_eq!(delivered, expected);
    let total: u64 = ordered
        .iter()
        .zip(&origin)
        .map(|(tip, base)| tip - base)
        .sum();
    assert_eq!(delivered.len() as u64, total);
    assert_eq!(heights(state.emitted()), ordered);
}

#[cfg(test)]
mod tests {
    use super::exercise;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn ordered_delivery_matches_enumeration(input in proptest::collection::vec(any::<u8>(), 0..256)) {
            exercise(&input);
        }
    }
}
