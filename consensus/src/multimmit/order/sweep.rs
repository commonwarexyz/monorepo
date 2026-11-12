//! Offset-major slot streams and the final sweep one finalized leader fixes.

use super::{Error, Lanes};
use crate::{
    multimmit::types::{BlockRef, Frontier},
    types::Height,
};
use commonware_cryptography::Digest;

/// One ancestor required by an ordering stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Slot<D: Digest> {
    tip: BlockRef<D>,
    height: Height,
}

impl<D: Digest> Slot<D> {
    /// Returns the target tip whose ancestor fills this slot.
    pub(crate) const fn tip(self) -> BlockRef<D> {
        self.tip
    }

    /// Returns the height of the required ancestor on the tip's chain.
    pub(crate) const fn height(self) -> Height {
        self.height
    }
}

/// The three ordering passes from one tip vector to a higher one.
///
/// The payment pass holds every height of the payment chains ([`Lanes`]) from the base up to the
/// target. A payment chain proposes no extension and is settled in every view, so nothing defers
/// its slots, and visiting them first keeps an unsettled ordinary chain from stopping them.
///
/// On the ordinary chains, pass A holds the heights from the base up to the proposed tip, clamped
/// to the target; pass B the heights above the proposed tip. The proposal pins pass A's blocks, so
/// an L-QC finalizes them with fewer votes than the extensions of pass B need
/// ([`FinalTips::from_lqc`](crate::multimmit::algebra::FinalTips::from_lqc) applies the
/// thresholds). Sweeping pass A first keeps an extension that only some voters saw from deferring
/// other chains' pinned blocks.
struct Passes {
    /// Height of each chain's base tip.
    base: Vec<u64>,
    /// Height of each chain's proposed tip, clamped into `[base, target]`.
    boundary: Vec<u64>,
    /// The payment pass, offsets above `base` on payment chains only.
    payment: Coordinates,
    /// Pass A, offsets above `base` on ordinary chains only.
    positional: Coordinates,
    /// Pass B, offsets above `boundary` on ordinary chains only.
    extension: Coordinates,
}

impl Passes {
    fn new<D: Digest>(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
        proposed: &[Height],
        lanes: &Lanes,
    ) -> Result<Self, Error> {
        validate_monotone(base, target)?;
        if proposed.len() != base.len() {
            return Err(Error::Frontier);
        }
        let chains = base.len();
        lanes.check(chains)?;
        let mut heights = Vec::with_capacity(chains);
        let mut boundaries = Vec::with_capacity(chains);
        let mut payment = Vec::with_capacity(chains);
        let mut positional = Vec::with_capacity(chains);
        let mut extension = Vec::with_capacity(chains);
        for (chain, ((base, target), proposed)) in base.iter().zip(target).zip(proposed).enumerate()
        {
            let (base, target) = (base.height().get(), target.height().get());
            if proposed.get() < base {
                return Err(Error::Regression);
            }
            let boundary = proposed.get().min(target);
            heights.push(base);
            boundaries.push(boundary);
            if lanes.payment(chain) {
                payment.push(target - base);
                positional.push(0);
                extension.push(0);
            } else {
                payment.push(0);
                positional.push(boundary - base);
                extension.push(target - boundary);
            }
        }
        Ok(Self {
            base: heights,
            boundary: boundaries,
            payment: Coordinates::new(payment),
            positional: Coordinates::new(positional),
            extension: Coordinates::new(extension),
        })
    }

    /// Returns the slot count of every pass together.
    #[cfg(any(test, feature = "mocks"))]
    fn total(&self) -> Result<u64, Error> {
        self.payment
            .maxima
            .iter()
            .chain(&self.positional.maxima)
            .chain(&self.extension.maxima)
            .try_fold(0u64, |total, delta| total.checked_add(*delta))
            .ok_or(Error::Frontier)
    }

    /// Truncates the ordinary passes for a final sweep, as [`FinalSweep`] describes. Payment
    /// chains never halt a pass.
    fn halt(&mut self, proposed: &[Height], settled: &[bool], lanes: &Lanes) {
        let short =
            self.boundary
                .iter()
                .zip(proposed)
                .enumerate()
                .map(|(chain, (boundary, proposed))| {
                    *boundary < proposed.get() && !lanes.payment(chain)
                });
        let positional = truncate_at(&self.positional.maxima, short);
        let extension = if positional.halted {
            vec![0; self.extension.maxima.len()]
        } else {
            truncate_at(
                &self.extension.maxima,
                settled
                    .iter()
                    .enumerate()
                    .map(|(chain, settled)| !*settled && !lanes.payment(chain)),
            )
            .kept
        };
        self.positional = Coordinates::new(positional.kept);
        self.extension = Coordinates::new(extension);
    }

    fn next<D: Digest>(&mut self, target: &[BlockRef<D>]) -> Option<Slot<D>> {
        if let Some(coordinate) = self.payment.next() {
            return Some(slot_above(&self.base, target, coordinate));
        }
        if let Some(coordinate) = self.positional.next() {
            return Some(slot_above(&self.base, target, coordinate));
        }
        self.extension
            .next()
            .map(|coordinate| slot_above(&self.boundary, target, coordinate))
    }

    fn maxima(&self) -> Vec<Option<Height>> {
        let mut maxima = vec![None; self.base.len()];
        // A chain's slots lie in the payment pass alone or in the ordinary passes, and every
        // extension slot is above the positional slots on its chain.
        for (floor, coordinates) in [
            (&self.base, &self.payment),
            (&self.base, &self.positional),
            (&self.boundary, &self.extension),
        ] {
            for (chain, maximum) in coordinates.remaining_maxima() {
                maxima[chain] = Some(Height::new(
                    floor[chain]
                        .checked_add(maximum)
                        .expect("offset is bounded by the target height"),
                ));
            }
        }
        maxima
    }
}

/// Offset-major traversal from one canonical tip vector toward a higher one: the payment pass
/// first, then pass A and pass B on the ordinary chains.
pub(crate) struct SlotStream<D: Digest> {
    target: Vec<BlockRef<D>>,
    passes: Passes,
}

impl<D: Digest> SlotStream<D> {
    /// Creates the full traversal from `base` to `target`, with the payment pass over the
    /// payment chains of `lanes` and pass A ending at `proposed`.
    pub(crate) fn new(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
        proposed: &[Height],
        lanes: &Lanes,
    ) -> Result<Self, Error> {
        Ok(Self {
            target: target.to_vec(),
            passes: Passes::new(base, target, proposed, lanes)?,
        })
    }

    /// Returns each chain's maximum remaining slot height in O(chains) time. Chains with no
    /// remaining slots have no maximum.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn maxima(&self) -> Vec<Option<Height>> {
        self.passes.maxima()
    }
}

impl<D: Digest> Iterator for SlotStream<D> {
    type Item = Slot<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.passes.next(&self.target)
    }
}

/// Final sweep: the canonical order of the slots one L-QC finalizes, toward its final tips.
///
/// The payment pass emits every payment chain up to its final tip and never halts: a payment
/// chain is settled in every view. Pass A then halts at the first ordinary chain whose finalized
/// position fell short of its proposed tip, since a same-view V-QC may still carry that chain up
/// to the proposed tip. Pass B runs only when every ordinary chain reached its proposed tip and
/// halts at the first unsettled ordinary chain, since `f + 1` votes may still endorse a block
/// beyond its finalized tip. Either halt defers only the slots after it.
pub(crate) struct FinalSweep<D: Digest> {
    stream: SlotStream<D>,
    /// Whether a halt deferred slots below the final tips to a later view.
    #[cfg(any(test, feature = "mocks"))]
    halted: bool,
    /// Slots the sweep will emit.
    #[cfg(any(test, feature = "mocks"))]
    planned: u64,
}

impl<D: Digest> FinalSweep<D> {
    pub(crate) fn new(
        base: &[BlockRef<D>],
        target: Vec<BlockRef<D>>,
        proposed: &[Height],
        settled: Vec<bool>,
        lanes: &Lanes,
    ) -> Result<Self, Error> {
        let mut passes = Passes::new(base, &target, proposed, lanes)?;
        if settled.len() != target.len() {
            return Err(Error::Frontier);
        }
        #[cfg(any(test, feature = "mocks"))]
        let total = passes.total()?;
        passes.halt(proposed, &settled, lanes);
        #[cfg(any(test, feature = "mocks"))]
        let planned = passes.total()?;
        Ok(Self {
            stream: SlotStream { target, passes },
            #[cfg(any(test, feature = "mocks"))]
            halted: planned < total,
            #[cfg(any(test, feature = "mocks"))]
            planned,
        })
    }

    /// Returns, per chain, the highest height the sweep [`Self::new`] builds for the same inputs
    /// places: its highest planned slot, or the base height when it plans none on that chain.
    ///
    /// Computes only the cutoffs, without copying the target or building the slot stream.
    pub(crate) fn placed(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
        proposed: &[Height],
        settled: &[bool],
        lanes: &Lanes,
    ) -> Result<Vec<Height>, Error> {
        let mut passes = Passes::new(base, target, proposed, lanes)?;
        if settled.len() != target.len() {
            return Err(Error::Frontier);
        }
        passes.halt(proposed, settled, lanes);
        Ok(passes
            .maxima()
            .into_iter()
            .zip(&passes.base)
            .map(|(maximum, base)| maximum.unwrap_or(Height::new(*base)))
            .collect())
    }

    /// Returns whether a halt deferred slots below the final tips to a later view.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn halted(&self) -> bool {
        self.halted
    }

    /// Returns how many slots this sweep emits in total.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn planned(&self) -> u64 {
        self.planned
    }

    /// Returns the slots of the sweep, toward the final tips.
    pub(crate) fn into_stream(self) -> SlotStream<D> {
        self.stream
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Coordinate {
    offset: u64,
    chain: usize,
}

/// Offset-major traversal whose active set contains only chains with a slot at the current offset.
struct Coordinates {
    maxima: Vec<u64>,
    active: Vec<usize>,
    offset: u64,
    position: usize,
}

impl Coordinates {
    fn new(maxima: Vec<u64>) -> Self {
        let active = maxima
            .iter()
            .enumerate()
            .filter_map(|(chain, maximum)| (*maximum > 0).then_some(chain))
            .collect::<Vec<_>>();
        Self {
            maxima,
            active,
            offset: 1,
            position: 0,
        }
    }

    fn remaining_maxima(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.active
            .iter()
            .enumerate()
            .filter_map(|(position, &chain)| {
                let maximum = self.maxima[chain];
                (maximum > self.offset || position >= self.position).then_some((chain, maximum))
            })
    }
}

impl Iterator for Coordinates {
    type Item = Coordinate;

    fn next(&mut self) -> Option<Self::Item> {
        if self.active.is_empty() {
            return None;
        }
        if self.position == self.active.len() {
            let Some(offset) = self.offset.checked_add(1) else {
                self.active.clear();
                return None;
            };
            self.offset = offset;
            self.position = 0;
            self.active
                .retain(|chain| self.maxima[*chain] >= self.offset);
            if self.active.is_empty() {
                return None;
            }
        }
        let chain = self.active[self.position];
        self.position += 1;
        Some(Coordinate {
            offset: self.offset,
            chain,
        })
    }
}

const fn slot_above<D: Digest>(
    floor: &[u64],
    target: &[BlockRef<D>],
    coordinate: Coordinate,
) -> Slot<D> {
    Slot {
        tip: target[coordinate.chain],
        height: Height::new(
            floor[coordinate.chain]
                .checked_add(coordinate.offset)
                .expect("offset is bounded by the target height"),
        ),
    }
}

/// The per-chain slot counts one pass keeps after [`truncate_at`].
#[derive(Debug, PartialEq, Eq)]
struct Truncation {
    /// Slots each chain keeps.
    kept: Vec<u64>,
    /// Whether any chain halted the pass.
    halted: bool,
}

/// Truncates offset-major deltas at the first empty slot of a halting chain.
fn truncate_at(deltas: &[u64], halting: impl Iterator<Item = bool>) -> Truncation {
    let cutoff = deltas
        .iter()
        .zip(halting)
        .enumerate()
        .filter(|(_, (_, halting))| *halting)
        .filter_map(|(chain, (delta, _))| delta.checked_add(1).map(|offset| (offset, chain)))
        .min();
    let truncated = deltas
        .iter()
        .enumerate()
        .map(|(chain, delta)| match cutoff {
            None => *delta,
            Some((offset, halt_chain)) => (*delta).min(offset - u64::from(chain >= halt_chain)),
        })
        .collect();
    Truncation {
        kept: truncated,
        halted: cutoff.is_some(),
    }
}

/// Checks that `base` and `target` are frontiers of the same chains and that `target` dominates
/// `base`.
fn validate_monotone<D: Digest>(base: &[BlockRef<D>], target: &[BlockRef<D>]) -> Result<(), Error> {
    Frontier::new(target.to_vec())?.dominates(&Frontier::new(base.to_vec())?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            SweepFact,
            fuzz::{Coordinate, coordinate, frontier, remaining_maxima},
        },
        *,
    };
    use crate::{
        multimmit::{
            algebra::{FinalTips, PoolExtractor},
            mocks::{Bls, Committee},
            types::{ChainId, DigestedLeader, Extension, Position, VoteBody},
        },
        types::View,
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{Participant, test_rng};
    use proptest::{collection::vec, prelude::*};

    fn heights(heights: &[u64]) -> Vec<Height> {
        heights.iter().map(|height| Height::new(*height)).collect()
    }

    fn coordinates<I: Iterator<Item = Slot<Sha256Digest>>>(stream: I) -> Vec<Coordinate> {
        stream.map(coordinate).collect()
    }

    fn assert_remaining_maxima(
        mut stream: SlotStream<Sha256Digest>,
        chains: usize,
        expected: &[Coordinate],
    ) {
        for consumed in 0..=expected.len() {
            assert_eq!(
                stream.maxima(),
                remaining_maxima(&expected[consumed..], chains),
                "after {consumed} slots"
            );
            assert_eq!(
                stream.next().map(coordinate),
                expected.get(consumed).copied()
            );
        }
        assert_eq!(stream.maxima(), vec![None; chains]);
        assert!(stream.next().is_none());
    }

    #[test]
    fn horizontal_is_offset_major() {
        let stream = SlotStream::new(
            &frontier(&[2, 5]),
            &frontier(&[4, 6]),
            &heights(&[2, 5]),
            &Lanes::none(),
        )
        .unwrap();
        assert_eq!(coordinates(stream), vec![(0, 3), (1, 6), (0, 4)]);
    }

    #[test]
    fn horizontal_places_positional_slots_before_extensions() {
        let base = frontier(&[0, 0]);
        let target = frontier(&[3, 2]);
        let stream = SlotStream::new(&base, &target, &heights(&[2, 1]), &Lanes::none()).unwrap();
        let forward = coordinates(stream);
        assert_eq!(forward, vec![(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)]);

        // A proposal beyond the target only pins what the target reaches.
        let stream = SlotStream::new(&base, &target, &heights(&[5, 1]), &Lanes::none()).unwrap();
        assert_eq!(
            coordinates(stream),
            vec![(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)]
        );
        assert!(matches!(
            SlotStream::new(
                &frontier(&[2, 2]),
                &target,
                &heights(&[1, 2]),
                &Lanes::none()
            ),
            Err(Error::Regression)
        ));
    }

    #[test]
    fn horizontal_maxima_follow_remaining_slots() {
        let base = frontier(&[2, 5, 1, 8]);
        let target = frontier(&[6, 6, 4, 8]);
        let proposed = heights(&[4, 6, 2, 8]);
        let expected =
            coordinates(SlotStream::new(&base, &target, &proposed, &Lanes::none()).unwrap());
        assert_remaining_maxima(
            SlotStream::new(&base, &target, &proposed, &Lanes::none()).unwrap(),
            4,
            &expected,
        );
    }

    #[test]
    fn maxima_handle_wide_sparse_chains() {
        let base = frontier(&vec![7; 4096]);
        let mut target = vec![7; base.len()];
        target[1] = 10;
        target[2048] = 9;
        target[4095] = 11;
        let target = frontier(&target);
        let proposed = heights(&vec![8; base.len()]);
        let expected =
            coordinates(SlotStream::new(&base, &target, &proposed, &Lanes::none()).unwrap());
        assert_remaining_maxima(
            SlotStream::new(&base, &target, &proposed, &Lanes::none()).unwrap(),
            base.len(),
            &expected,
        );
        let proposed = heights(&vec![7; base.len()]);
        let mut settled = vec![true; base.len()];
        settled[2048] = false;
        let expected = coordinates(
            FinalSweep::new(
                &base,
                target.clone(),
                &proposed,
                settled.clone(),
                &Lanes::none(),
            )
            .unwrap()
            .into_stream(),
        );
        assert_remaining_maxima(
            FinalSweep::new(&base, target, &proposed, settled, &Lanes::none())
                .unwrap()
                .into_stream(),
            base.len(),
            &expected,
        );
    }

    #[test]
    fn maxima_handle_maximum_height_and_offset() {
        let base = frontier(&[u64::MAX - 2, u64::MAX]);
        let target = frontier(&[u64::MAX, u64::MAX]);
        let proposed = heights(&[u64::MAX - 1, u64::MAX]);
        let expected = [(0, u64::MAX - 1), (0, u64::MAX)];
        assert_remaining_maxima(
            SlotStream::new(&base, &target, &proposed, &Lanes::none()).unwrap(),
            2,
            &expected,
        );
        assert_remaining_maxima(
            FinalSweep::new(&base, target, &proposed, vec![true; 2], &Lanes::none())
                .unwrap()
                .into_stream(),
            2,
            &expected,
        );

        let mut stream = SlotStream::new(
            &frontier(&[0, 0]),
            &frontier(&[u64::MAX, u64::MAX]),
            &heights(&[0, 0]),
            &Lanes::none(),
        )
        .unwrap();
        assert_eq!(stream.maxima(), vec![Some(Height::new(u64::MAX)); 2]);
        stream.next().unwrap();
        assert_eq!(stream.maxima(), vec![Some(Height::new(u64::MAX)); 2]);

        // At the final offset, consuming a chain exhausts it without incrementing the offset.
        stream.passes.extension.offset = u64::MAX;
        stream.passes.extension.position = 0;
        assert_remaining_maxima(stream, 2, &[(0, u64::MAX), (1, u64::MAX)]);
    }

    #[test]
    fn final_sweep_places_up_to_its_highest_planned_slot_per_chain() {
        // Base, target, and proposed heights, and settledness, per chain.
        type Case = (
            &'static [u64],
            &'static [u64],
            &'static [u64],
            &'static [bool],
        );
        let cases: [Case; 7] = [
            (&[0, 0], &[1, 2], &[0, 0], &[true, true]),
            (&[0, 0], &[1, 2], &[0, 0], &[false, true]),
            (&[1, 0], &[1, 2], &[1, 0], &[false, true]),
            (&[0, 0], &[0, 4], &[0, 3], &[false, true]),
            (&[0, 0], &[2, 3], &[1, 3], &[true, true]),
            (&[0, 0], &[1, 3], &[2, 2], &[false, true]),
            (&[2, 5, 1], &[6, 9, 1], &[4, 7, 3], &[true, false, true]),
        ];
        for (base, target, proposed, settled) in cases {
            let placed = FinalSweep::placed(
                &frontier(base),
                &frontier(target),
                &heights(proposed),
                settled,
                &Lanes::none(),
            )
            .unwrap();
            let sweep = FinalSweep::new(
                &frontier(base),
                frontier(target),
                &heights(proposed),
                settled.to_vec(),
                &Lanes::none(),
            )
            .unwrap();
            let mut expected = heights(base);
            for (chain, height) in coordinates(sweep.into_stream()) {
                expected[chain] = expected[chain].max(Height::new(height));
            }
            assert_eq!(
                placed, expected,
                "placed heights for {base:?} -> {target:?}"
            );
        }
    }

    #[test]
    fn final_sweep_skips_settled_and_halts_at_unsettled_holes() {
        let base = frontier(&[0, 0]);
        let target = frontier(&[1, 2]);
        let settled = FinalSweep::new(
            &base,
            target.clone(),
            &heights(&[0, 0]),
            vec![true, true],
            &Lanes::none(),
        )
        .unwrap();
        assert!(!settled.halted());
        assert_eq!(settled.planned(), 3);
        assert_eq!(
            coordinates(settled.into_stream()),
            vec![(0, 1), (1, 1), (1, 2)]
        );

        let unsettled = FinalSweep::new(
            &base,
            target.clone(),
            &heights(&[0, 0]),
            vec![false, true],
            &Lanes::none(),
        )
        .unwrap();
        assert!(unsettled.halted());
        assert_eq!(unsettled.planned(), 2);
        assert_eq!(coordinates(unsettled.into_stream()), vec![(0, 1), (1, 1)]);

        // An unsettled chain with no new block may still gain one at the first offset, so the
        // sweep halts before emitting anything.
        let idle = FinalSweep::new(
            &frontier(&[1, 0]),
            target,
            &heights(&[1, 0]),
            vec![false, true],
            &Lanes::none(),
        )
        .unwrap();
        assert!(idle.halted());
        assert_eq!(idle.planned(), 0);
        assert!(coordinates(idle.into_stream()).is_empty());
    }

    #[test]
    fn final_sweep_places_pinned_slots_past_an_unsettled_extension() {
        // Chain 0 proposed nothing and some voters endorsed a block above its tip; chain 1's
        // proposal reached height 3 and every position finalized. The pinned blocks emit.
        let base = frontier(&[0, 0]);
        let sweep = FinalSweep::new(
            &base,
            frontier(&[0, 3]),
            &heights(&[0, 3]),
            vec![false, true],
            &Lanes::none(),
        )
        .unwrap();
        assert!(!sweep.halted());
        assert_eq!(sweep.planned(), 3);
        assert_eq!(
            coordinates(sweep.into_stream()),
            vec![(1, 1), (1, 2), (1, 3)]
        );

        // Chain 1's own extension above its proposed tip waits behind chain 0's empty slot.
        let sweep = FinalSweep::new(
            &base,
            frontier(&[0, 4]),
            &heights(&[0, 3]),
            vec![false, true],
            &Lanes::none(),
        )
        .unwrap();
        assert!(sweep.halted());
        assert_eq!(sweep.planned(), 3);
        assert_eq!(
            coordinates(sweep.into_stream()),
            vec![(1, 1), (1, 2), (1, 3)]
        );

        // A settled extension follows every pinned block.
        let sweep = FinalSweep::new(
            &base,
            frontier(&[2, 3]),
            &heights(&[1, 3]),
            vec![true, true],
            &Lanes::none(),
        )
        .unwrap();
        assert!(!sweep.halted());
        assert_eq!(sweep.planned(), 5);
        assert_eq!(
            coordinates(sweep.into_stream()),
            vec![(0, 1), (1, 1), (1, 2), (1, 3), (0, 2)]
        );
    }

    #[test]
    fn final_sweep_halts_the_positional_pass_on_a_shortfall() {
        // Chain 0 finalized position 1 of a two-entry proposal: a V-QC may still carry it to
        // height 2, so the pass halts there and no extension slot is reached.
        let base = frontier(&[0, 0]);
        let sweep = FinalSweep::new(
            &base,
            frontier(&[1, 3]),
            &heights(&[2, 2]),
            vec![false, true],
            &Lanes::none(),
        )
        .unwrap();
        assert!(sweep.halted());
        assert_eq!(sweep.planned(), 2);
        assert_eq!(coordinates(sweep.into_stream()), vec![(0, 1), (1, 1)]);
    }

    #[test]
    fn final_sweep_maxima_follow_remaining_slots() {
        for (base, target, proposed, settled) in [
            (
                vec![2, 5, 1, 8],
                vec![6, 6, 4, 8],
                vec![2, 5, 1, 8],
                vec![true; 4],
            ),
            (
                vec![2, 5, 1, 8],
                vec![6, 6, 4, 8],
                vec![2, 5, 1, 8],
                vec![true, false, true, false],
            ),
            (
                vec![2, 5, 1, 8],
                vec![2, 8, 4, 9],
                vec![2, 5, 1, 8],
                vec![false, true, false, true],
            ),
            (
                vec![2, 5, 1, 8],
                vec![6, 6, 4, 9],
                vec![4, 6, 2, 8],
                vec![true, false, true, false],
            ),
            (
                vec![2, 5, 1, 8],
                vec![6, 6, 4, 9],
                vec![4, 7, 2, 8],
                vec![true, false, true, false],
            ),
        ] {
            let base = frontier(&base);
            let target = frontier(&target);
            let stream = FinalSweep::new(
                &base,
                target.clone(),
                &heights(&proposed),
                settled.clone(),
                &Lanes::none(),
            )
            .unwrap()
            .into_stream();
            let expected = coordinates(
                FinalSweep::new(&base, target, &heights(&proposed), settled, &Lanes::none())
                    .unwrap()
                    .into_stream(),
            );
            assert_remaining_maxima(stream, base.len(), &expected);
        }
    }

    #[test]
    fn final_sweep_continues_after_branch_settlement() {
        let committee = Committee::<Bls<MinPk>>::builder(17, 6).build();
        let codec = committee.codec();
        let signed = committee.leader_block(View::new(1));
        let leader = signed.block();
        let votes = (0..6)
            .map(|signer| {
                let mut extensions = vec![Extension::empty(); codec.chains()];
                if signer < 2 {
                    extensions[0] =
                        Extension::new(vec![Sha256::hash(&[&[signer as u8]])], 1).unwrap();
                }
                extensions[1] = Extension::new(vec![Sha256::hash(&[b"ready"])], 1).unwrap();
                let body = VoteBody::for_leader(
                    DigestedLeader::new::<Sha256>(leader),
                    vec![Position::new(0); codec.chains()],
                    extensions,
                    codec,
                )
                .unwrap();
                committee.signers[signer].sign_vote(body).unwrap()
            })
            .collect::<Vec<_>>();
        let genesis = committee.config.genesis().tips().to_vec();
        let lqc = committee
            .verifier
            .assemble_lqc::<_, Sha256, _>(&mut test_rng(), leader.clone(), &votes[..5], &Sequential)
            .unwrap();
        let certified = FinalTips::from_lqc::<Sha256, Bls<MinPk>>(&lqc, codec).unwrap();
        assert_eq!(certified.settled(ChainId::new(0)), Some(false));
        let fact = SweepFact::from_lqc::<Sha256, Bls<MinPk>>(&lqc, codec).unwrap();
        assert!(
            coordinates(
                FinalSweep::new(
                    &genesis,
                    fact.tips().to_vec(),
                    fact.proposed(),
                    fact.settled().to_vec(),
                    &Lanes::none(),
                )
                .unwrap()
                .into_stream()
            )
            .is_empty()
        );
        for (size, expected) in [(5, vec![]), (6, vec![(1, 1)])] {
            let mut pool = PoolExtractor::new::<Sha256, Bls<MinPk>>(leader, codec).unwrap();
            for (signer, vote) in votes[..size].iter().enumerate() {
                pool.insert::<Sha256, Bls<MinPk>>(
                    leader,
                    Participant::new(signer as u32),
                    vote.body(),
                )
                .unwrap();
            }
            let tips = pool.final_tips().unwrap();
            assert_eq!(tips.settled(ChainId::new(0)), Some(size == 6));
            if size == 5 {
                assert_eq!(tips, certified);
            }
            let settled = (0..codec.chains())
                .map(|chain| tips.settled(ChainId::new(chain as u32)).unwrap())
                .collect();
            let sweep = FinalSweep::new(
                &genesis,
                tips.blocks().to_vec(),
                &vec![Height::zero(); codec.chains()],
                settled,
                &Lanes::none(),
            )
            .unwrap();
            assert_eq!(coordinates(sweep.into_stream()), expected);
        }
    }

    #[test]
    fn final_sweep_reuses_authenticated_lqc_algebra() {
        let committee = Committee::<Bls<MinPk>>::builder(17, 6).build();
        let lqc = committee.lqc(View::new(1));
        let genesis = committee.config.genesis().tips().to_vec();
        let fact = SweepFact::from_lqc::<Sha256, Bls<MinPk>>(&lqc, committee.codec()).unwrap();
        assert_eq!(fact.tips().len(), committee.codec().chains());
        let sweep = FinalSweep::new(
            &genesis,
            fact.tips().to_vec(),
            fact.proposed(),
            fact.settled().to_vec(),
            &Lanes::none(),
        )
        .unwrap();
        let placed = FinalSweep::placed(
            &genesis,
            fact.tips(),
            fact.proposed(),
            fact.settled(),
            &Lanes::none(),
        )
        .unwrap();
        assert_eq!(
            sweep.planned(),
            placed.iter().map(|height| height.get()).sum::<u64>()
        );
    }

    #[test]
    fn cutoff_handles_empty_and_extreme_frontiers() {
        for (deltas, halting, expected, halted) in [
            (vec![], vec![], vec![], false),
            (vec![0, 0], vec![false, false], vec![0, 0], false),
            (vec![0, u64::MAX], vec![true, false], vec![0, 0], true),
            (
                vec![u64::MAX, 0, u64::MAX],
                vec![false, true, false],
                vec![1, 0, 0],
                true,
            ),
            (
                vec![u64::MAX - 1, u64::MAX, u64::MAX],
                vec![true, false, false],
                vec![u64::MAX - 1; 3],
                true,
            ),
            (
                vec![u64::MAX, u64::MAX - 1, u64::MAX],
                vec![false, true, false],
                vec![u64::MAX, u64::MAX - 1, u64::MAX - 1],
                true,
            ),
            (vec![u64::MAX; 2], vec![true; 2], vec![u64::MAX; 2], false),
        ] {
            assert_eq!(
                truncate_at(&deltas, halting.into_iter()),
                Truncation {
                    kept: expected,
                    halted,
                }
            );
        }
    }

    #[test]
    fn payment_pass_precedes_ordinary_passes() {
        // Chain 1 is a payment chain: its slots come first, then pass A and pass B of chains 0
        // and 2.
        let base = frontier(&[0, 0, 0]);
        let target = frontier(&[2, 3, 2]);
        let proposed = heights(&[1, 3, 2]);
        let lanes = Lanes::new([false, true, false]);
        let expected = vec![(1, 1), (1, 2), (1, 3), (0, 1), (2, 1), (2, 2), (0, 2)];
        let stream = SlotStream::new(&base, &target, &proposed, &lanes).unwrap();
        assert_eq!(coordinates(stream), expected);
        assert_remaining_maxima(
            SlotStream::new(&base, &target, &proposed, &lanes).unwrap(),
            3,
            &expected,
        );
        let sweep =
            FinalSweep::new(&base, target.clone(), &proposed, vec![true; 3], &lanes).unwrap();
        assert!(!sweep.halted());
        assert_eq!(sweep.planned(), 7);
        assert_eq!(coordinates(sweep.into_stream()), expected);
        // Without payment chains, chain 1 is ordinary again.
        assert_eq!(
            coordinates(SlotStream::new(&base, &target, &proposed, &Lanes::none()).unwrap()),
            vec![(0, 1), (1, 1), (2, 1), (1, 2), (2, 2), (1, 3), (0, 2)]
        );

        // Several payment chains are visited in horizontal order: offset first, then chain.
        let lanes = Lanes::new([true, true, false]);
        let stream =
            SlotStream::new(&base, &frontier(&[2, 3, 1]), &heights(&[2, 3, 1]), &lanes).unwrap();
        assert_eq!(
            coordinates(stream),
            vec![(0, 1), (1, 1), (0, 2), (1, 2), (1, 3), (2, 1)]
        );

        // A mask for another number of chains is malformed.
        assert!(matches!(
            SlotStream::new(&base, &target, &proposed, &Lanes::new([true, false])),
            Err(Error::Frontier)
        ));
        assert!(matches!(
            FinalSweep::placed(
                &base,
                &target,
                &proposed,
                &[true; 3],
                &Lanes::new([true; 4])
            ),
            Err(Error::Frontier)
        ));
    }

    #[test]
    fn an_unsettled_or_short_ordinary_chain_does_not_stop_the_payment_pass() {
        // Chain 0 fell short of its proposed tip and halts pass A at its second offset. Payment
        // chain 2 is placed whole, whatever its own proposed height and settledness.
        let base = frontier(&[0, 0, 0]);
        let target = frontier(&[1, 3, 2]);
        let proposed = heights(&[2, 3, 3]);
        let settled = vec![false, true, false];
        let sweep = FinalSweep::new(
            &base,
            target.clone(),
            &proposed,
            settled.clone(),
            &Lanes::new([false, false, true]),
        )
        .unwrap();
        assert!(sweep.halted());
        assert_eq!(sweep.planned(), 4);
        assert_eq!(
            coordinates(sweep.into_stream()),
            vec![(2, 1), (2, 2), (0, 1), (1, 1)]
        );
        // As an ordinary chain, chain 2 waits behind chain 0's hole too.
        let ordinary = FinalSweep::new(&base, target, &proposed, settled, &Lanes::none()).unwrap();
        assert_eq!(
            coordinates(ordinary.into_stream()),
            vec![(0, 1), (1, 1), (2, 1)]
        );

        // An unsettled chain that proposed nothing defers only the ordinary extensions.
        let base = frontier(&[0, 0]);
        let target = frontier(&[1, 2]);
        let lanes = Lanes::new([false, true]);
        let sweep = FinalSweep::new(
            &base,
            target.clone(),
            &heights(&[0, 0]),
            vec![false, true],
            &lanes,
        )
        .unwrap();
        assert!(!sweep.halted());
        assert_eq!(
            coordinates(sweep.into_stream()),
            vec![(1, 1), (1, 2), (0, 1)]
        );
        let idle = FinalSweep::new(
            &frontier(&[1, 0]),
            target,
            &heights(&[1, 0]),
            vec![false, false],
            &lanes,
        )
        .unwrap();
        assert!(!idle.halted());
        assert_eq!(idle.planned(), 2);
        assert_eq!(coordinates(idle.into_stream()), vec![(1, 1), (1, 2)]);
    }

    #[test]
    fn a_payment_anchor_jump_is_emitted_whole_first() {
        // The payment chain's anchor jumps five heights in one view; the ordinary chain is short
        // and unsettled. Every block of the jump precedes the ordinary chain's first slot.
        let base = frontier(&[0, 0]);
        let target = frontier(&[1, 5]);
        let proposed = heights(&[2, 5]);
        let lanes = Lanes::new([false, true]);
        let sweep =
            FinalSweep::new(&base, target.clone(), &proposed, vec![false, true], &lanes).unwrap();
        assert_eq!(
            coordinates(sweep.into_stream()),
            vec![(1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (0, 1)]
        );
        assert_eq!(
            FinalSweep::placed(&base, &target, &proposed, &[false, true], &lanes).unwrap(),
            heights(&[1, 5])
        );
        // Without payment chains the jump waits behind chain 0's hole after its first block.
        assert_eq!(
            FinalSweep::placed(&base, &target, &proposed, &[false, true], &Lanes::none()).unwrap(),
            heights(&[1, 1])
        );
    }

    #[test]
    fn final_sweep_places_its_highest_planned_slot_with_every_payment_mask() {
        type Case = (
            &'static [u64],
            &'static [u64],
            &'static [u64],
            &'static [bool],
        );
        let cases: [Case; 5] = [
            (&[0, 0], &[1, 2], &[0, 0], &[false, true]),
            (&[0, 0], &[0, 4], &[0, 3], &[false, true]),
            (&[0, 0], &[1, 3], &[2, 2], &[false, true]),
            (&[2, 5, 1], &[6, 9, 1], &[4, 7, 3], &[true, false, true]),
            (&[0, 0, 0], &[1, 3, 2], &[2, 3, 3], &[false, true, false]),
        ];
        for (base, target, proposed, settled) in cases {
            for mask in 0..1u32 << base.len() {
                let payment = |chain: usize| mask >> chain & 1 == 1;
                let lanes = Lanes::new((0..base.len()).map(payment));
                let placed = FinalSweep::placed(
                    &frontier(base),
                    &frontier(target),
                    &heights(proposed),
                    settled,
                    &lanes,
                )
                .unwrap();
                let sweep = FinalSweep::new(
                    &frontier(base),
                    frontier(target),
                    &heights(proposed),
                    settled.to_vec(),
                    &lanes,
                )
                .unwrap();
                let planned = sweep.planned();
                let mut expected = heights(base);
                let slots = coordinates(sweep.into_stream());
                assert_eq!(slots.len() as u64, planned);
                for (chain, height) in slots {
                    expected[chain] = expected[chain].max(Height::new(height));
                }
                assert_eq!(
                    placed, expected,
                    "{base:?} -> {target:?} with mask {mask:b}"
                );
                // Every payment chain reaches its target.
                for chain in (0..base.len()).filter(|chain| payment(*chain)) {
                    assert_eq!(placed[chain].get(), target[chain]);
                }
            }
        }
    }

    /// One offset-major pass over `deltas` above `floors`, halting at the first empty slot of a
    /// halting chain. Returns the visited coordinates and whether the pass halted.
    fn reference_pass(floors: &[u64], deltas: &[u64], halting: &[bool]) -> (Vec<Coordinate>, bool) {
        let max = deltas.iter().copied().max().unwrap_or(0);
        let mut visited = Vec::new();
        for offset in 1..=max.saturating_add(1) {
            for chain in 0..deltas.len() {
                if offset <= deltas[chain] {
                    visited.push((chain, floors[chain] + offset));
                } else if halting[chain] {
                    return (visited, true);
                }
            }
        }
        (visited, false)
    }

    /// Checks that the payment slots of the sweep (or, without `sweep`, the opening) from `base`
    /// to `target` with payment chains `mask` form a prefix that takes every payment chain to its
    /// target, and that removing them leaves the order without payment chains in which every
    /// payment chain stays at its base, proposes nothing and is settled.
    fn assert_non_interference(
        base: &[u64],
        target: &[u64],
        proposed: &[u64],
        settled: &[bool],
        mask: &[bool],
        sweep: bool,
    ) {
        let chains = base.len();
        let lanes = Lanes::new(mask.iter().copied());
        let frozen = |heights: &[u64]| {
            (0..chains)
                .map(|chain| {
                    if mask[chain] {
                        base[chain]
                    } else {
                        heights[chain]
                    }
                })
                .collect::<Vec<_>>()
        };
        let paid = (0..chains)
            .filter(|chain| mask[*chain])
            .map(|chain| target[chain] - base[chain])
            .sum::<u64>();
        let (frozen_target, frozen_proposed) =
            (frontier(&frozen(target)), heights(&frozen(proposed)));
        let (base, target, proposed) = (frontier(base), frontier(target), heights(proposed));
        let (slots, reference) = if sweep {
            let frozen_settled = (0..chains)
                .map(|chain| mask[chain] || settled[chain])
                .collect::<Vec<_>>();
            let with = FinalSweep::new(&base, target, &proposed, settled.to_vec(), &lanes).unwrap();
            let without = FinalSweep::new(
                &base,
                frozen_target,
                &frozen_proposed,
                frozen_settled,
                &Lanes::none(),
            )
            .unwrap();
            assert_eq!(with.halted(), without.halted());
            let planned = (with.planned(), without.planned());
            let slots = coordinates(with.into_stream());
            let reference = coordinates(without.into_stream());
            assert_eq!(planned, (slots.len() as u64, reference.len() as u64));
            (slots, reference)
        } else {
            let with = SlotStream::new(&base, &target, &proposed, &lanes).unwrap();
            let without =
                SlotStream::new(&base, &frozen_target, &frozen_proposed, &Lanes::none()).unwrap();
            (coordinates(with), coordinates(without))
        };
        let (payment, ordinary): (Vec<_>, Vec<_>) =
            slots.iter().partition(|(chain, _)| mask[*chain]);
        assert_eq!(payment.len() as u64, paid);
        assert_eq!(&slots[..payment.len()], payment.as_slice());
        assert_eq!(ordinary, reference);
    }

    proptest! {
        #[test]
        fn streams_match_materialized_reference(
            base in vec(0u64..20, 1..5),
            deltas in vec(0u64..6, 1..5),
            proposed in vec(0u64..8, 1..5),
            settled in vec(any::<bool>(), 1..5),
            payments in any::<bool>(),
            mask in vec(any::<bool>(), 4),
        ) {
            let chains = base.len().min(deltas.len()).min(proposed.len()).min(settled.len());
            let base = &base[..chains];
            let deltas = &deltas[..chains];
            let settled = &settled[..chains];
            // Half the cases run without payment chains.
            let payment = (0..chains).map(|chain| payments && mask[chain]).collect::<Vec<_>>();
            let lanes = Lanes::new(payment.iter().copied());
            let target_heights = base.iter().zip(deltas).map(|(base, delta)| base + delta).collect::<Vec<_>>();
            let proposed_heights = base.iter().zip(&proposed[..chains]).map(|(base, delta)| base + delta).collect::<Vec<_>>();
            let boundary = target_heights.iter().zip(&proposed_heights).map(|(target, proposed)| *target.min(proposed)).collect::<Vec<_>>();
            // A payment chain's slots are all in the payment pass, none in the ordinary ones.
            let ordinary = |chain: usize, delta: u64| if payment[chain] { 0 } else { delta };
            let paid = (0..chains).map(|chain| if payment[chain] { deltas[chain] } else { 0 }).collect::<Vec<_>>();
            let positional = (0..chains).map(|chain| ordinary(chain, boundary[chain] - base[chain])).collect::<Vec<_>>();
            let extension = (0..chains).map(|chain| ordinary(chain, target_heights[chain] - boundary[chain])).collect::<Vec<_>>();
            let base_tips = frontier(base);
            let target_tips = frontier(&target_heights);
            let proposed = heights(&proposed_heights);

            let never = vec![false; chains];
            let mut expected_horizontal = reference_pass(base, &paid, &never).0;
            expected_horizontal.extend(reference_pass(base, &positional, &never).0);
            expected_horizontal.extend(reference_pass(&boundary, &extension, &never).0);
            let horizontal_stream = SlotStream::new(&base_tips, &target_tips, &proposed, &lanes).unwrap();
            assert_remaining_maxima(horizontal_stream, chains, &expected_horizontal);

            let short = (0..chains).map(|chain| !payment[chain] && boundary[chain] < proposed_heights[chain]).collect::<Vec<_>>();
            let mut expected_sweep = reference_pass(base, &paid, &never).0;
            let (positional_sweep, halted) = reference_pass(base, &positional, &short);
            expected_sweep.extend(positional_sweep);
            if !halted {
                let unsettled = (0..chains).map(|chain| !payment[chain] && !settled[chain]).collect::<Vec<_>>();
                expected_sweep.extend(reference_pass(&boundary, &extension, &unsettled).0);
            }
            let total = paid.iter().chain(&positional).chain(&extension).sum::<u64>();
            let sweep_stream =
                FinalSweep::new(&base_tips, target_tips, &proposed, settled.to_vec(), &lanes).unwrap();
            prop_assert_eq!(sweep_stream.planned(), expected_sweep.len() as u64);
            prop_assert_eq!(sweep_stream.halted(), (expected_sweep.len() as u64) < total);
            assert_remaining_maxima(sweep_stream.into_stream(), chains, &expected_sweep);
        }

        #[test]
        fn payment_chains_never_interfere_with_ordinary_chains(
            base in vec(0u64..20, 1..6),
            deltas in vec(0u64..6, 1..6),
            proposed in vec(0u64..8, 1..6),
            settled in vec(any::<bool>(), 1..6),
            mask in vec(any::<bool>(), 6),
        ) {
            let chains = base.len().min(deltas.len()).min(proposed.len()).min(settled.len());
            let base = &base[..chains];
            let target = (0..chains).map(|chain| base[chain] + deltas[chain]).collect::<Vec<_>>();
            let proposed = (0..chains).map(|chain| base[chain] + proposed[chain]).collect::<Vec<_>>();
            for sweep in [false, true] {
                assert_non_interference(base, &target, &proposed, &settled[..chains], &mask[..chains], sweep);
            }
        }
    }
}
