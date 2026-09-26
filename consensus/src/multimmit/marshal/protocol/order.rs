//! Streaming reconstruction of Multimmit's canonical block order.

use crate::{
    multimmit::{
        algebra::{self, FinalTips},
        types::{BlockRef, ChainId, CodecConfig, Frontier, FrontierError, Lqc, TipRecord},
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

/// A malformed or non-monotone ordering input.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    #[error("ordering frontiers are not canonical")]
    Frontier,
    #[error("ordering frontier regresses")]
    Regression,
    #[error("ordering frontiers conflict at one height")]
    Conflict,
    #[error("ordering stream has a chain-local gap")]
    Gap,
    #[error("tip-history opening does not extend the active history")]
    History,
    #[error("resolved block does not match its requested coordinate")]
    Coordinate,
    #[error(transparent)]
    Algebra(#[from] algebra::Error),
}

impl From<FrontierError> for Error {
    fn from(error: FrontierError) -> Self {
        match error {
            FrontierError::Regression(_) => Self::Regression,
            FrontierError::Conflict(_) => Self::Conflict,
            FrontierError::Empty | FrontierError::Chain { .. } | FrontierError::Length => {
                Self::Frontier
            }
        }
    }
}

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

/// The action for one resolved block reference.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reconciliation {
    /// The block belongs to the acknowledged prefix.
    Duplicate,
    /// The block is the next chain-local output.
    Emit,
}

/// A restartable cut through recursive ordering and final-sweep emission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoryState<D: Digest> {
    history: D,
    ordered: Frontier<D>,
    emitted: Frontier<D>,
}

impl<D: Digest> HistoryState<D> {
    /// Creates a state whose emitted frontier contains its recursive ordering frontier.
    pub(crate) fn new(
        history: D,
        ordered: Vec<BlockRef<D>>,
        emitted: Vec<BlockRef<D>>,
    ) -> Result<Self, Error> {
        let ordered = Frontier::new(ordered)?;
        let emitted = Frontier::new(emitted)?;
        emitted.dominates(&ordered)?;
        Ok(Self {
            history,
            ordered,
            emitted,
        })
    }

    /// Returns the commitment of the newest incorporated tip-history opening.
    pub(crate) const fn history(&self) -> D {
        self.history
    }

    /// Returns the per-chain tips of the newest incorporated history opening.
    pub(crate) fn ordered(&self) -> &[BlockRef<D>] {
        self.ordered.references()
    }

    /// Returns the per-chain tips of the emitted output prefix.
    pub(crate) fn emitted(&self) -> &[BlockRef<D>] {
        self.emitted.references()
    }

    /// Returns the frontier of [`Self::ordered`].
    pub(crate) const fn ordered_frontier(&self) -> &Frontier<D> {
        &self.ordered
    }

    /// Returns the frontier of [`Self::emitted`].
    pub(crate) const fn emitted_frontier(&self) -> &Frontier<D> {
        &self.emitted
    }

    /// Validates the next oldest-first history opening against resolved ancestry.
    ///
    /// `common` contains, on every chain, the resolved lower of the opening tip and the emitted tip.
    /// It proves exact ancestry compatibility before height-based duplicate suppression is used.
    pub(crate) fn validate_opening<H: Hasher<Digest = D>>(
        &self,
        commitment: D,
        record: &TipRecord<D>,
        common: &[BlockRef<D>],
    ) -> Result<(), Error> {
        self.check_opening::<H>(commitment, record)?;
        self.validate_reconciliation(record.tips(), common)
    }

    /// Incorporates a completely streamed history opening.
    pub(crate) fn finish_opening<H: Hasher<Digest = D>>(
        &mut self,
        commitment: D,
        record: &TipRecord<D>,
    ) -> Result<(), Error> {
        self.check_opening::<H>(commitment, record)?;
        same_chains(&self.emitted, record.tips())?;
        for (tip, emitted) in record.tips().iter().zip(self.emitted.references()) {
            if emitted.height() < tip.height() {
                return Err(Error::Gap);
            }
            if emitted.height() == tip.height() && emitted != tip {
                return Err(Error::Conflict);
            }
        }
        self.history = commitment;
        self.ordered = Frontier::new(record.tips().to_vec())?;
        Ok(())
    }

    /// Checks that `record`, with commitment `commitment`, is the next opening of the active
    /// history.
    fn check_opening<H: Hasher<Digest = D>>(
        &self,
        commitment: D,
        record: &TipRecord<D>,
    ) -> Result<(), Error> {
        if record.parent() != self.history || record.commitment::<H>() != commitment {
            return Err(Error::History);
        }
        Ok(())
    }

    /// Extracts one verified L-QC's final sweep without reproducing protocol thresholds.
    pub(crate) fn final_sweep<H, V>(
        &self,
        certificate: &Lqc<V, D>,
        config: CodecConfig,
        common: &[BlockRef<D>],
    ) -> Result<FinalSweep<D>, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let sweep = FinalSweep::from_lqc::<H, V>(self.ordered.references(), certificate, config)?;
        self.validate_reconciliation(sweep.stream.target(), common)?;
        Ok(sweep)
    }

    /// Reconciles one resolved stream slot against the acknowledged frontier.
    pub(crate) fn reconcile(
        &mut self,
        slot: Slot<D>,
        reference: BlockRef<D>,
    ) -> Result<Reconciliation, Error> {
        if reference.chain() != slot.tip.chain() || reference.height() != slot.height {
            return Err(Error::Coordinate);
        }
        let frontier = *self.emitted.get(reference.chain()).ok_or(Error::Frontier)?;
        if reference.height() < frontier.height() {
            return Ok(Reconciliation::Duplicate);
        }
        if reference.height() == frontier.height() {
            return (reference == frontier)
                .then_some(Reconciliation::Duplicate)
                .ok_or(Error::Conflict);
        }
        let next = frontier.height().get().checked_add(1).ok_or(Error::Gap)?;
        if reference.height().get() != next {
            return Err(Error::Gap);
        }
        self.emitted.replace(reference);
        Ok(Reconciliation::Emit)
    }

    /// Validates that `common` holds, on every chain, the lower of `target` and the emitted tip.
    pub(crate) fn validate_reconciliation(
        &self,
        target: &[BlockRef<D>],
        common: &[BlockRef<D>],
    ) -> Result<(), Error> {
        same_chains(&self.emitted, target)?;
        same_chains(&self.emitted, common)?;
        for ((emitted, target), common) in self.emitted.references().iter().zip(target).zip(common)
        {
            if emitted.height() == target.height() && emitted != target {
                return Err(Error::Conflict);
            }
            let expected = if target.height() <= emitted.height() {
                target
            } else {
                emitted
            };
            if common != expected {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
}

/// The two ordering passes from one tip vector to a higher one.
///
/// Pass A holds the heights from the base up to the proposed tip, clamped to the target; pass B
/// the heights above the proposed tip. The proposal pins pass A's blocks, so an L-QC finalizes
/// them with fewer votes than the extensions of pass B need ([`FinalTips::from_lqc`] applies the
/// thresholds). Sweeping pass A first keeps an extension that only some voters saw from deferring
/// other chains' pinned blocks.
struct Passes {
    /// Height of each chain's base tip.
    base: Vec<u64>,
    /// Height of each chain's proposed tip, clamped into `[base, target]`.
    boundary: Vec<u64>,
    /// Pass A, offsets above `base`.
    positional: Coordinates,
    /// Pass B, offsets above `boundary`.
    extension: Coordinates,
}

impl Passes {
    fn new<D: Digest>(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
        proposed: &[Height],
    ) -> Result<Self, Error> {
        validate_monotone(base, target)?;
        if proposed.len() != base.len() {
            return Err(Error::Frontier);
        }
        let chains = base.len();
        let mut heights = Vec::with_capacity(chains);
        let mut boundaries = Vec::with_capacity(chains);
        let mut positional = Vec::with_capacity(chains);
        let mut extension = Vec::with_capacity(chains);
        for ((base, target), proposed) in base.iter().zip(target).zip(proposed) {
            let (base, target) = (base.height().get(), target.height().get());
            if proposed.get() < base {
                return Err(Error::Regression);
            }
            let boundary = proposed.get().min(target);
            heights.push(base);
            boundaries.push(boundary);
            positional.push(boundary - base);
            extension.push(target - boundary);
        }
        Ok(Self {
            base: heights,
            boundary: boundaries,
            positional: Coordinates::new(positional),
            extension: Coordinates::new(extension),
        })
    }

    /// Returns the slot count of both passes together.
    fn total(&self) -> Result<u64, Error> {
        self.positional
            .maxima
            .iter()
            .chain(&self.extension.maxima)
            .try_fold(0u64, |total, delta| total.checked_add(*delta))
            .ok_or(Error::Frontier)
    }

    /// Truncates both passes for a final sweep, as [`FinalSweep`] describes.
    fn halt(&mut self, proposed: &[Height], settled: &[bool]) {
        let short = self
            .boundary
            .iter()
            .zip(proposed)
            .map(|(boundary, proposed)| *boundary < proposed.get());
        let positional = truncate_at(&self.positional.maxima, short);
        let extension = if positional.halted {
            vec![0; self.extension.maxima.len()]
        } else {
            truncate_at(
                &self.extension.maxima,
                settled.iter().map(|settled| !*settled),
            )
            .kept
        };
        self.positional = Coordinates::new(positional.kept);
        self.extension = Coordinates::new(extension);
    }

    fn next<D: Digest>(&mut self, target: &[BlockRef<D>]) -> Option<Slot<D>> {
        if let Some(coordinate) = self.positional.next() {
            return Some(slot_above(&self.base, target, coordinate));
        }
        self.extension
            .next()
            .map(|coordinate| slot_above(&self.boundary, target, coordinate))
    }

    fn maxima(&self) -> Vec<Option<Height>> {
        let mut maxima = vec![None; self.base.len()];
        // Every extension slot is above the positional slots on its chain.
        for (floor, coordinates) in [
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

/// Offset-major traversal from one canonical tip vector toward a higher one, pass A first and
/// pass B second.
pub(crate) struct SlotStream<D: Digest> {
    target: Vec<BlockRef<D>>,
    passes: Passes,
}

impl<D: Digest> SlotStream<D> {
    /// Creates the full traversal from `base` to `target`, with pass A ending at `proposed`.
    pub(crate) fn new(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
        proposed: &[Height],
    ) -> Result<Self, Error> {
        Ok(Self {
            target: target.to_vec(),
            passes: Passes::new(base, target, proposed)?,
        })
    }

    /// Returns how many slots [`Self::new`] yields for the same inputs, without copying the target.
    pub(crate) fn count(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
        proposed: &[Height],
    ) -> Result<u64, Error> {
        Passes::new(base, target, proposed)?.total()
    }

    /// Returns the tips the traversal moves toward.
    pub(crate) fn target(&self) -> &[BlockRef<D>] {
        &self.target
    }

    /// Returns each chain's maximum remaining slot height in O(chains) time. Chains with no
    /// remaining slots have no maximum.
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
/// Pass A halts at the first chain whose finalized position fell short of its proposed tip, since
/// a same-view V-QC may still carry that chain up to the proposed tip. Pass B runs only when every
/// chain reached its proposed tip and halts at the first unsettled chain, since `f + 1` votes may
/// still endorse a block beyond its finalized tip. Either halt defers only the slots after it.
pub(crate) struct FinalSweep<D: Digest> {
    stream: SlotStream<D>,
    /// Whether a halt deferred slots below the final tips to a later view.
    halted: bool,
    /// Slots the sweep will emit.
    planned: u64,
}

impl<D: Digest> FinalSweep<D> {
    pub(crate) fn new(
        base: &[BlockRef<D>],
        target: Vec<BlockRef<D>>,
        proposed: &[Height],
        settled: Vec<bool>,
    ) -> Result<Self, Error> {
        let mut passes = Passes::new(base, &target, proposed)?;
        if settled.len() != target.len() {
            return Err(Error::Frontier);
        }
        let total = passes.total()?;
        passes.halt(proposed, &settled);
        let planned = passes.total()?;
        Ok(Self {
            stream: SlotStream { target, passes },
            halted: planned < total,
            planned,
        })
    }

    fn from_lqc<H, V>(
        base: &[BlockRef<D>],
        certificate: &Lqc<V, D>,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let tips = FinalTips::from_lqc::<H, V>(certificate, config)?;
        let settled = (0..config.chains())
            .map(|chain| {
                let chain = u32::try_from(chain).map_err(|_| Error::Frontier)?;
                tips.settled(ChainId::new(chain)).ok_or(Error::Frontier)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proposed = certificate.leader().proposed_heights();
        Self::new(base, tips.blocks().to_vec(), &proposed, settled)
    }

    /// Returns whether a halt deferred slots below the final tips to a later view.
    pub(crate) const fn halted(&self) -> bool {
        self.halted
    }

    /// Returns how many slots this sweep emits in total.
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

/// Checks that `references` names the chains of `frontier`, one per chain in the same order.
fn same_chains<D: Digest>(frontier: &Frontier<D>, references: &[BlockRef<D>]) -> Result<(), Error> {
    let same = references.len() == frontier.chains()
        && references
            .iter()
            .zip(frontier.references())
            .all(|(reference, expected)| reference.chain() == expected.chain());
    same.then_some(()).ok_or(Error::Frontier)
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
        super::fuzz::{Coordinate, coordinate, frontier, reference, remaining_maxima},
        *,
    };
    use crate::{
        multimmit::{
            algebra::{FinalTips, PoolExtractor},
            mocks::Committee,
            types::{DigestedLeader, Extension, Position, VoteBody},
        },
        types::View,
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::Participant;
    use proptest::{collection::vec, prelude::*};

    fn heights(heights: &[u64]) -> Vec<Height> {
        heights.iter().map(|height| Height::new(*height)).collect()
    }

    fn resolve(slot: Slot<Sha256Digest>) -> BlockRef<Sha256Digest> {
        let (chain, height) = coordinate(slot);
        reference(chain, height)
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
        let stream =
            SlotStream::new(&frontier(&[2, 5]), &frontier(&[4, 6]), &heights(&[2, 5])).unwrap();
        assert_eq!(coordinates(stream), vec![(0, 3), (1, 6), (0, 4)]);
    }

    #[test]
    fn horizontal_places_positional_slots_before_extensions() {
        let base = frontier(&[0, 0]);
        let target = frontier(&[3, 2]);
        let stream = SlotStream::new(&base, &target, &heights(&[2, 1])).unwrap();
        let forward = coordinates(stream);
        assert_eq!(forward, vec![(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)]);

        // A proposal beyond the target only pins what the target reaches.
        let stream = SlotStream::new(&base, &target, &heights(&[5, 1])).unwrap();
        assert_eq!(
            coordinates(stream),
            vec![(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)]
        );
        assert!(matches!(
            SlotStream::new(&frontier(&[2, 2]), &target, &heights(&[1, 2])),
            Err(Error::Regression)
        ));
    }

    #[test]
    fn horizontal_maxima_follow_remaining_slots() {
        let base = frontier(&[2, 5, 1, 8]);
        let target = frontier(&[6, 6, 4, 8]);
        let proposed = heights(&[4, 6, 2, 8]);
        let expected = coordinates(SlotStream::new(&base, &target, &proposed).unwrap());
        assert_remaining_maxima(
            SlotStream::new(&base, &target, &proposed).unwrap(),
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
        let expected = coordinates(SlotStream::new(&base, &target, &proposed).unwrap());
        assert_remaining_maxima(
            SlotStream::new(&base, &target, &proposed).unwrap(),
            base.len(),
            &expected,
        );
        let proposed = heights(&vec![7; base.len()]);
        let mut settled = vec![true; base.len()];
        settled[2048] = false;
        let expected = coordinates(
            FinalSweep::new(&base, target.clone(), &proposed, settled.clone())
                .unwrap()
                .into_stream(),
        );
        assert_remaining_maxima(
            FinalSweep::new(&base, target, &proposed, settled)
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
            SlotStream::new(&base, &target, &proposed).unwrap(),
            2,
            &expected,
        );
        assert_remaining_maxima(
            FinalSweep::new(&base, target, &proposed, vec![true; 2])
                .unwrap()
                .into_stream(),
            2,
            &expected,
        );

        let mut stream = SlotStream::new(
            &frontier(&[0, 0]),
            &frontier(&[u64::MAX, u64::MAX]),
            &heights(&[0, 0]),
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
    fn final_sweep_skips_settled_and_halts_at_unsettled_holes() {
        let base = frontier(&[0, 0]);
        let target = frontier(&[1, 2]);
        let settled =
            FinalSweep::new(&base, target.clone(), &heights(&[0, 0]), vec![true, true]).unwrap();
        assert!(!settled.halted());
        assert_eq!(settled.planned(), 3);
        assert_eq!(
            coordinates(settled.into_stream()),
            vec![(0, 1), (1, 1), (1, 2)]
        );

        let unsettled =
            FinalSweep::new(&base, target.clone(), &heights(&[0, 0]), vec![false, true]).unwrap();
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
            let stream = FinalSweep::new(&base, target, &heights(&proposed), settled.clone())
                .unwrap()
                .into_stream();
            let expected = coordinates(
                FinalSweep::new(
                    &base,
                    stream.target().to_vec(),
                    &heights(&proposed),
                    settled,
                )
                .unwrap()
                .into_stream(),
            );
            assert_remaining_maxima(stream, base.len(), &expected);
        }
    }

    #[test]
    fn final_sweep_continues_after_branch_settlement() {
        let committee = Committee::<MinPk>::builder(17, 6).build();
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
        let state = HistoryState::new(
            Sha256::hash(&[b"history"]),
            genesis.clone(),
            genesis.clone(),
        )
        .unwrap();
        let lqc = committee
            .verifier
            .assemble_lqc::<Sha256, _>(leader.clone(), &votes[..5], &Sequential)
            .unwrap();
        let certified = FinalTips::from_lqc::<Sha256, MinPk>(&lqc, codec).unwrap();
        assert_eq!(certified.settled(ChainId::new(0)), Some(false));
        assert!(
            coordinates(
                state
                    .final_sweep::<Sha256, MinPk>(&lqc, codec, &genesis)
                    .unwrap()
                    .into_stream()
            )
            .is_empty()
        );
        for (size, expected) in [(5, vec![]), (6, vec![(1, 1)])] {
            let mut pool = PoolExtractor::new::<Sha256, MinPk>(leader, codec).unwrap();
            for (signer, vote) in votes[..size].iter().enumerate() {
                pool.insert::<Sha256, MinPk>(leader, Participant::new(signer as u32), vote.body())
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
            )
            .unwrap();
            assert_eq!(coordinates(sweep.into_stream()), expected);
        }
    }

    #[test]
    fn final_sweep_reuses_authenticated_lqc_algebra() {
        let committee = Committee::<MinPk>::builder(17, 6).build();
        let lqc = committee.lqc(View::new(1));
        let genesis = committee.config.genesis().tips().to_vec();
        let state = HistoryState::new(
            Sha256::hash(&[b"history"]),
            genesis.clone(),
            genesis.clone(),
        )
        .unwrap();
        let sweep = state
            .final_sweep::<Sha256, MinPk>(&lqc, committee.codec(), &genesis)
            .unwrap();

        assert_eq!(
            sweep.into_stream().target().len(),
            committee.codec().chains()
        );
    }

    #[test]
    fn history_openings_are_oldest_first_and_frontier_is_exact() {
        let history = Sha256::hash(&[b"history"]);
        let first = TipRecord::at_tips(history, frontier(&[1, 1])).unwrap();
        let first_id = first.commitment::<Sha256>();
        let second = TipRecord::at_tips(first_id, frontier(&[2, 2])).unwrap();
        let second_id = second.commitment::<Sha256>();
        let mut state = HistoryState::new(history, frontier(&[0, 0]), frontier(&[1, 0])).unwrap();

        assert!(matches!(
            state.validate_opening::<Sha256>(second_id, &second, &frontier(&[1, 0])),
            Err(Error::History)
        ));
        state
            .validate_opening::<Sha256>(first_id, &first, &frontier(&[1, 0]))
            .unwrap();
        let stream = SlotStream::new(state.ordered(), first.tips(), first.proposed()).unwrap();
        for slot in stream {
            let resolved = resolve(slot);
            let action = state.reconcile(slot, resolved).unwrap();
            let expected = if resolved == reference(0, 1) {
                Reconciliation::Duplicate
            } else {
                Reconciliation::Emit
            };
            assert_eq!(action, expected);
        }
        state.finish_opening::<Sha256>(first_id, &first).unwrap();
        assert_eq!(state.history(), first_id);
        assert_eq!(state.ordered(), first.tips());
        assert_eq!(state.emitted(), first.tips());

        let conflict = reference(0, 1);
        let conflict = BlockRef::new(
            conflict.chain(),
            conflict.height(),
            Sha256::hash(&[b"fork"]),
        );
        let slot = Slot {
            tip: conflict,
            height: conflict.height(),
        };
        assert_eq!(state.reconcile(slot, conflict), Err(Error::Conflict));
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

    proptest! {
        #[test]
        fn streams_match_materialized_reference(
            base in vec(0u64..20, 1..5),
            deltas in vec(0u64..6, 1..5),
            proposed in vec(0u64..8, 1..5),
            settled in vec(any::<bool>(), 1..5),
        ) {
            let chains = base.len().min(deltas.len()).min(proposed.len()).min(settled.len());
            let base = &base[..chains];
            let deltas = &deltas[..chains];
            let settled = &settled[..chains];
            let target_heights = base.iter().zip(deltas).map(|(base, delta)| base + delta).collect::<Vec<_>>();
            let proposed_heights = base.iter().zip(&proposed[..chains]).map(|(base, delta)| base + delta).collect::<Vec<_>>();
            let boundary = target_heights.iter().zip(&proposed_heights).map(|(target, proposed)| *target.min(proposed)).collect::<Vec<_>>();
            let positional = boundary.iter().zip(base).map(|(boundary, base)| boundary - base).collect::<Vec<_>>();
            let extension = target_heights.iter().zip(&boundary).map(|(target, boundary)| target - boundary).collect::<Vec<_>>();
            let base_tips = frontier(base);
            let target_tips = frontier(&target_heights);
            let proposed = heights(&proposed_heights);

            let never = vec![false; chains];
            let mut expected_horizontal = reference_pass(base, &positional, &never).0;
            expected_horizontal.extend(reference_pass(&boundary, &extension, &never).0);
            let horizontal_stream = SlotStream::new(&base_tips, &target_tips, &proposed).unwrap();
            assert_remaining_maxima(horizontal_stream, chains, &expected_horizontal);

            let short = boundary.iter().zip(&proposed_heights).map(|(boundary, proposed)| boundary < proposed).collect::<Vec<_>>();
            let (mut expected_sweep, halted) = reference_pass(base, &positional, &short);
            if !halted {
                let unsettled = settled.iter().map(|settled| !settled).collect::<Vec<_>>();
                expected_sweep.extend(reference_pass(&boundary, &extension, &unsettled).0);
            }
            let total = positional.iter().chain(&extension).sum::<u64>();
            let sweep_stream =
                FinalSweep::new(&base_tips, target_tips, &proposed, settled.to_vec()).unwrap();
            prop_assert_eq!(sweep_stream.planned(), expected_sweep.len() as u64);
            prop_assert_eq!(sweep_stream.halted(), (expected_sweep.len() as u64) < total);
            assert_remaining_maxima(sweep_stream.into_stream(), chains, &expected_sweep);
        }
    }
}
