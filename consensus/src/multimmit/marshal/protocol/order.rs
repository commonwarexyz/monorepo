//! Streaming reconstruction of Multimmit's canonical block order.

use crate::{
    multimmit::{
        config::CodecConfig,
        machine::algebra::{self, FinalTips},
        types::{BlockRef, ChainId, Lqc, TipRecord},
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

/// A malformed or non-monotone ordering input.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
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

/// One ancestor required by an ordering stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct Slot<D: Digest> {
    tip: BlockRef<D>,
    height: Height,
}

impl<D: Digest> Slot<D> {
    pub(in crate::multimmit::marshal) const fn tip(self) -> BlockRef<D> {
        self.tip
    }

    pub(in crate::multimmit::marshal) const fn height(self) -> Height {
        self.height
    }
}

/// The action for one exact resolved block reference.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) enum Reconciliation {
    /// The exact block belongs to the acknowledged prefix.
    Duplicate,
    /// The block is the exact next chain-local output.
    Emit,
}

/// A restartable cut through recursive ordering and final-sweep emission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct HistoryState<D: Digest> {
    history: D,
    ordered: Vec<BlockRef<D>>,
    emitted: Vec<BlockRef<D>>,
}

impl<D: Digest> HistoryState<D> {
    /// Creates a state whose emitted frontier contains its recursive ordering frontier.
    pub(in crate::multimmit::marshal) fn new(
        history: D,
        ordered: Vec<BlockRef<D>>,
        emitted: Vec<BlockRef<D>>,
    ) -> Result<Self, Error> {
        validate_vectors(&ordered, &emitted)?;
        for (ordered, emitted) in ordered.iter().zip(&emitted) {
            if emitted.height() < ordered.height() {
                return Err(Error::Regression);
            }
            if emitted.height() == ordered.height() && emitted != ordered {
                return Err(Error::Conflict);
            }
        }
        Ok(Self {
            history,
            ordered,
            emitted,
        })
    }

    pub(in crate::multimmit::marshal) const fn history(&self) -> D {
        self.history
    }

    pub(in crate::multimmit::marshal) fn ordered(&self) -> &[BlockRef<D>] {
        &self.ordered
    }

    pub(in crate::multimmit::marshal) fn emitted(&self) -> &[BlockRef<D>] {
        &self.emitted
    }

    /// Validates the next oldest-first history opening against resolved ancestry.
    ///
    /// `common` contains, on every chain, the resolved lower of the opening tip and the emitted tip.
    /// It proves exact ancestry compatibility before height-based duplicate suppression is used.
    pub(in crate::multimmit::marshal) fn validate_opening<H: Hasher<Digest = D>>(
        &self,
        commitment: D,
        record: &TipRecord<D>,
        common: &[BlockRef<D>],
    ) -> Result<(), Error> {
        if record.parent() != self.history || record.commitment::<H>() != commitment {
            return Err(Error::History);
        }
        self.validate_reconciliation(record.tips(), common)
    }

    /// Incorporates a completely streamed history opening.
    pub(in crate::multimmit::marshal) fn finish_opening<H: Hasher<Digest = D>>(
        &mut self,
        commitment: D,
        record: &TipRecord<D>,
    ) -> Result<(), Error> {
        if record.parent() != self.history || record.commitment::<H>() != commitment {
            return Err(Error::History);
        }
        for (tip, emitted) in record.tips().iter().zip(&self.emitted) {
            if emitted.height() < tip.height() {
                return Err(Error::Gap);
            }
            if emitted.height() == tip.height() && emitted != tip {
                return Err(Error::Conflict);
            }
        }
        self.history = commitment;
        self.ordered = record.tips().to_vec();
        Ok(())
    }

    /// Extracts one verified L-QC's final sweep without reproducing protocol thresholds.
    pub(in crate::multimmit::marshal) fn final_sweep<H, V>(
        &self,
        certificate: &Lqc<V, D>,
        config: CodecConfig,
        common: &[BlockRef<D>],
    ) -> Result<FinalSweep<D>, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let sweep = FinalSweep::from_lqc::<H, V>(&self.ordered, certificate, config)?;
        self.validate_reconciliation(sweep.target(), common)?;
        Ok(sweep)
    }

    /// Reconciles one resolved stream slot against the acknowledged frontier.
    pub(in crate::multimmit::marshal) fn reconcile(
        &mut self,
        slot: Slot<D>,
        reference: BlockRef<D>,
    ) -> Result<Reconciliation, Error> {
        if reference.chain() != slot.tip.chain() || reference.height() != slot.height {
            return Err(Error::Coordinate);
        }
        let frontier = self
            .emitted
            .get_mut(reference.chain().get() as usize)
            .ok_or(Error::Frontier)?;
        if reference.height() < frontier.height() {
            return Ok(Reconciliation::Duplicate);
        }
        if reference.height() == frontier.height() {
            return (reference == *frontier)
                .then_some(Reconciliation::Duplicate)
                .ok_or(Error::Conflict);
        }
        let next = frontier.height().get().checked_add(1).ok_or(Error::Gap)?;
        if reference.height().get() != next {
            return Err(Error::Gap);
        }
        *frontier = reference;
        Ok(Reconciliation::Emit)
    }

    pub(in crate::multimmit::marshal) fn validate_reconciliation(
        &self,
        target: &[BlockRef<D>],
        common: &[BlockRef<D>],
    ) -> Result<(), Error> {
        validate_vectors(&self.emitted, target)?;
        validate_vectors(target, common)?;
        for ((emitted, target), common) in self.emitted.iter().zip(target).zip(common) {
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

/// A canonical ordering stream that can be inspected newest-first without advancing it.
pub(in crate::multimmit::marshal) trait OrderedSlots<D: Digest>:
    Iterator<Item = Slot<D>>
{
    /// Traverses the remaining slots in the exact reverse of canonical order.
    fn newest_first(&self) -> impl Iterator<Item = Slot<D>> + '_;
}

/// Per-chain slot counts of the two ordering passes from one tip vector to a higher one.
///
/// Pass A holds the heights from the base up to the proposed tip, clamped to the target; pass B
/// the heights above the proposed tip. The proposal pins pass A's blocks, so an L-QC finalizes them
/// at `3f + 1` votes, while pass B's blocks need every quorum vote. Sweeping pass A first keeps an
/// extension that only some voters saw from deferring other chains' pinned blocks.
struct Regions {
    /// Height of each chain's base tip.
    base: Vec<u64>,
    /// Height of each chain's proposed tip, clamped into `[base, target]`.
    boundary: Vec<u64>,
    /// Pass A slots per chain.
    positional: Vec<u64>,
    /// Pass B slots per chain.
    extension: Vec<u64>,
}

impl Regions {
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
        let mut regions = Self {
            base: Vec::with_capacity(chains),
            boundary: Vec::with_capacity(chains),
            positional: Vec::with_capacity(chains),
            extension: Vec::with_capacity(chains),
        };
        for ((base, target), proposed) in base.iter().zip(target).zip(proposed) {
            let (base, target) = (base.height().get(), target.height().get());
            if proposed.get() < base {
                return Err(Error::Regression);
            }
            let boundary = proposed.get().min(target);
            regions.base.push(base);
            regions.boundary.push(boundary);
            regions.positional.push(boundary - base);
            regions.extension.push(target - boundary);
        }
        Ok(regions)
    }

    /// Returns the slot count of both passes together.
    fn total(&self) -> Result<u64, Error> {
        self.positional
            .iter()
            .chain(&self.extension)
            .try_fold(0u64, |total, delta| total.checked_add(*delta))
            .ok_or(Error::Frontier)
    }
}

/// Traversal state of both passes.
struct Passes {
    base: Vec<u64>,
    boundary: Vec<u64>,
    positional: Coordinates,
    extension: Coordinates,
}

impl Passes {
    fn new(base: Vec<u64>, boundary: Vec<u64>, positional: Vec<u64>, extension: Vec<u64>) -> Self {
        Self {
            base,
            boundary,
            positional: Coordinates::new(positional),
            extension: Coordinates::new(extension),
        }
    }

    fn next<D: Digest>(&mut self, target: &[BlockRef<D>]) -> Option<Slot<D>> {
        if let Some(coordinate) = self.positional.next() {
            return Some(slot_above(&self.base, target, coordinate));
        }
        self.extension
            .next()
            .map(|coordinate| slot_above(&self.boundary, target, coordinate))
    }

    fn newest_first<'a, D: Digest>(
        &'a self,
        target: &'a [BlockRef<D>],
    ) -> impl Iterator<Item = Slot<D>> + 'a {
        self.extension
            .newest_first()
            .map(move |coordinate| slot_above(&self.boundary, target, coordinate))
            .chain(
                self.positional
                    .newest_first()
                    .map(move |coordinate| slot_above(&self.base, target, coordinate)),
            )
    }
}

/// Offset-major traversal from one canonical tip vector to a higher vector, positional region
/// first and extension region second.
pub(in crate::multimmit::marshal) struct Horizontal<D: Digest> {
    target: Vec<BlockRef<D>>,
    passes: Passes,
}

impl<D: Digest> Horizontal<D> {
    pub(in crate::multimmit::marshal) fn new(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
        proposed: &[Height],
    ) -> Result<Self, Error> {
        let regions = Regions::new(base, target, proposed)?;
        Ok(Self {
            target: target.to_vec(),
            passes: Passes::new(
                regions.base,
                regions.boundary,
                regions.positional,
                regions.extension,
            ),
        })
    }
}

impl<D: Digest> Iterator for Horizontal<D> {
    type Item = Slot<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.passes.next(&self.target)
    }
}

impl<D: Digest> OrderedSlots<D> for Horizontal<D> {
    fn newest_first(&self) -> impl Iterator<Item = Slot<D>> + '_ {
        self.passes.newest_first(&self.target)
    }
}

/// Streaming rho sweep toward final tips.
///
/// Pass A halts at the first chain whose finalized position fell short of its proposed tip, since
/// a same-view V-QC may still carry that chain up to the proposed tip. Pass B runs only when every
/// chain reached its proposed tip and halts at the first unsettled chain, since `f + 1` votes may
/// still endorse a block beyond its finalized tip. Either halt defers only the slots after it.
pub(in crate::multimmit::marshal) struct FinalSweep<D: Digest> {
    target: Vec<BlockRef<D>>,
    passes: Passes,
    /// Whether a halt deferred slots below the final tips to a later view.
    halted: bool,
    /// Slots the sweep will emit.
    planned: u64,
}

impl<D: Digest> FinalSweep<D> {
    pub(in crate::multimmit::marshal) fn new(
        base: &[BlockRef<D>],
        target: Vec<BlockRef<D>>,
        proposed: &[Height],
        settled: Vec<bool>,
    ) -> Result<Self, Error> {
        let regions = Regions::new(base, &target, proposed)?;
        if settled.len() != target.len() {
            return Err(Error::Frontier);
        }
        let total = regions.total()?;
        let short = regions
            .boundary
            .iter()
            .zip(proposed)
            .map(|(boundary, proposed)| *boundary < proposed.get());
        let (positional, halted_positional) = truncate_at(&regions.positional, short);
        let extension = if halted_positional {
            vec![0; regions.extension.len()]
        } else {
            truncate_at(&regions.extension, settled.iter().map(|settled| !*settled)).0
        };
        let planned = positional.iter().chain(&extension).sum::<u64>();
        Ok(Self {
            target,
            halted: planned < total,
            planned,
            passes: Passes::new(regions.base, regions.boundary, positional, extension),
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

    pub(in crate::multimmit::marshal) fn target(&self) -> &[BlockRef<D>] {
        &self.target
    }

    /// Returns whether a halt deferred slots below the final tips to a later view.
    pub(in crate::multimmit::marshal) const fn halted(&self) -> bool {
        self.halted
    }

    /// Returns how many slots this sweep emits in total.
    pub(in crate::multimmit::marshal) const fn planned(&self) -> u64 {
        self.planned
    }
}

impl<D: Digest> Iterator for FinalSweep<D> {
    type Item = Slot<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.passes.next(&self.target)
    }
}

impl<D: Digest> OrderedSlots<D> for FinalSweep<D> {
    fn newest_first(&self) -> impl Iterator<Item = Slot<D>> + '_ {
        self.passes.newest_first(&self.target)
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

    fn newest_first(&self) -> ReverseCoordinates {
        let mut ranges = vec![None; self.maxima.len()];
        for (position, chain) in self.active.iter().copied().enumerate() {
            let lower = self.offset.checked_add(u64::from(position < self.position));
            if let Some(lower) = lower.filter(|lower| *lower <= self.maxima[chain]) {
                ranges[chain] = Some((lower, self.maxima[chain]));
            }
        }
        ReverseCoordinates::new(ranges)
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

/// Reverse traversal activates chains at their maximum and retires them below their lower bound.
struct ReverseCoordinates {
    lower: Vec<Option<u64>>,
    scheduled: Vec<(u64, usize)>,
    scheduled_position: usize,
    active: Vec<usize>,
    scratch: Vec<usize>,
    offset: Option<u64>,
    position: usize,
}

impl ReverseCoordinates {
    fn new(ranges: Vec<Option<(u64, u64)>>) -> Self {
        let mut scheduled = ranges
            .iter()
            .enumerate()
            .filter_map(|(chain, range)| range.map(|(_, maximum)| (maximum, chain)))
            .collect::<Vec<_>>();
        scheduled.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1))
        });
        let lower = ranges
            .into_iter()
            .map(|range| range.map(|(lower, _)| lower))
            .collect();
        let mut coordinates = Self {
            lower,
            scheduled,
            scheduled_position: 0,
            active: Vec::new(),
            scratch: Vec::new(),
            offset: None,
            position: 0,
        };
        coordinates.advance();
        coordinates
    }

    fn advance(&mut self) {
        let mut offset = match self.offset {
            Some(offset) => offset.saturating_sub(1),
            None => self
                .scheduled
                .get(self.scheduled_position)
                .map_or(0, |(maximum, _)| *maximum),
        };
        loop {
            self.active
                .retain(|chain| self.lower[*chain].is_some_and(|lower| lower <= offset));
            let next_scheduled = self
                .scheduled
                .get(self.scheduled_position)
                .map(|(maximum, _)| *maximum);
            if self.active.is_empty()
                && let Some(maximum) = next_scheduled
                && maximum < offset
            {
                offset = maximum;
            }

            let start = self.scheduled_position;
            while self
                .scheduled
                .get(self.scheduled_position)
                .is_some_and(|(maximum, _)| *maximum == offset)
            {
                self.scheduled_position += 1;
            }
            self.merge_scheduled(start..self.scheduled_position);
            if !self.active.is_empty() {
                self.offset = Some(offset);
                self.position = self.active.len();
                return;
            }
            let Some((maximum, _)) = self.scheduled.get(self.scheduled_position) else {
                self.offset = None;
                self.position = 0;
                return;
            };
            offset = *maximum;
        }
    }

    fn merge_scheduled(&mut self, additions: std::ops::Range<usize>) {
        self.scratch.clear();
        let mut active = self.active.iter().copied().peekable();
        let mut additions = self.scheduled[additions]
            .iter()
            .map(|(_, chain)| *chain)
            .peekable();
        while active.peek().is_some() || additions.peek().is_some() {
            let chain = match (active.peek(), additions.peek()) {
                (Some(left), Some(right)) if left <= right => active.next(),
                (Some(_), Some(_)) => additions.next(),
                (Some(_), None) => active.next(),
                (None, Some(_)) => additions.next(),
                (None, None) => unreachable!(),
            }
            .expect("one sorted source remains");
            self.scratch.push(chain);
        }
        std::mem::swap(&mut self.active, &mut self.scratch);
    }
}

impl Iterator for ReverseCoordinates {
    type Item = Coordinate;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == 0 {
            self.offset?;
            self.advance();
        }
        let offset = self.offset?;
        self.position -= 1;
        Some(Coordinate {
            offset,
            chain: self.active[self.position],
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

/// Truncates offset-major deltas at the first empty slot of a halting chain.
///
/// Returns the slots each chain keeps and whether any chain halted the pass.
fn truncate_at(deltas: &[u64], halting: impl Iterator<Item = bool>) -> (Vec<u64>, bool) {
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
    (truncated, cutoff.is_some())
}

fn validate_vectors<D: Digest>(left: &[BlockRef<D>], right: &[BlockRef<D>]) -> Result<(), Error> {
    if left.is_empty() || left.len() != right.len() || u32::try_from(left.len()).is_err() {
        return Err(Error::Frontier);
    }
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        let chain = ChainId::new(u32::try_from(index).map_err(|_| Error::Frontier)?);
        if left.chain() != chain || right.chain() != chain {
            return Err(Error::Frontier);
        }
    }
    Ok(())
}

fn validate_monotone<D: Digest>(base: &[BlockRef<D>], target: &[BlockRef<D>]) -> Result<(), Error> {
    validate_vectors(base, target)?;
    for (base, target) in base.iter().zip(target) {
        if target.height() < base.height() {
            return Err(Error::Regression);
        }
        if target.height() == base.height() && target != base {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        config::Limits,
        machine::algebra::{FinalTips, PoolExtractor},
        mocks::Committee,
        types::{Extension, Position, VoteBody},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::Participant;
    use proptest::{collection::vec, prelude::*};

    fn reference(chain: u32, height: u64) -> BlockRef<Sha256Digest> {
        let chain_bytes = chain.to_be_bytes();
        let height_bytes = height.to_be_bytes();
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[b"order test", &chain_bytes, &height_bytes]),
        )
    }

    fn heights(heights: &[u64]) -> Vec<Height> {
        heights.iter().map(|height| Height::new(*height)).collect()
    }

    fn tips(heights: &[u64]) -> Vec<BlockRef<Sha256Digest>> {
        heights
            .iter()
            .enumerate()
            .map(|(chain, height)| reference(chain as u32, *height))
            .collect()
    }

    fn resolve(slot: Slot<Sha256Digest>) -> BlockRef<Sha256Digest> {
        reference(slot.tip().chain().get(), slot.height().get())
    }

    fn coordinates<I: Iterator<Item = Slot<Sha256Digest>>>(stream: I) -> Vec<(u32, u64)> {
        stream
            .map(|slot| (slot.tip().chain().get(), slot.height().get()))
            .collect()
    }

    #[test]
    fn horizontal_is_offset_major() {
        let stream = Horizontal::new(&tips(&[2, 5]), &tips(&[4, 6]), &heights(&[2, 5])).unwrap();
        assert_eq!(coordinates(stream), vec![(0, 3), (1, 6), (0, 4)]);
    }

    #[test]
    fn horizontal_places_positional_slots_before_extensions() {
        let base = tips(&[0, 0]);
        let target = tips(&[3, 2]);
        let stream = Horizontal::new(&base, &target, &heights(&[2, 1])).unwrap();
        let mut reverse = coordinates(stream.newest_first());
        reverse.reverse();
        let forward = coordinates(stream);
        assert_eq!(forward, vec![(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)]);
        assert_eq!(forward, reverse);

        // A proposal beyond the target only pins what the target reaches.
        let stream = Horizontal::new(&base, &target, &heights(&[5, 1])).unwrap();
        assert_eq!(
            coordinates(stream),
            vec![(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)]
        );
        assert!(matches!(
            Horizontal::new(&tips(&[2, 2]), &target, &heights(&[1, 2])),
            Err(Error::Regression)
        ));
    }

    #[test]
    fn horizontal_newest_first_is_exact_reverse() {
        let base = tips(&[2, 5, 1, 8]);
        let target = tips(&[6, 6, 4, 8]);
        let stream = Horizontal::new(&base, &target, &heights(&[2, 5, 1, 8])).unwrap();
        let mut reverse = coordinates(stream.newest_first());
        reverse.reverse();
        assert_eq!(coordinates(stream), reverse);
    }

    #[test]
    fn final_sweep_skips_settled_and_halts_at_unsettled_holes() {
        let base = tips(&[0, 0]);
        let target = tips(&[1, 2]);
        let mut settled =
            FinalSweep::new(&base, target.clone(), &heights(&[0, 0]), vec![true, true]).unwrap();
        assert!(!settled.halted());
        assert_eq!(settled.planned(), 3);
        assert_eq!(coordinates(settled.by_ref()), vec![(0, 1), (1, 1), (1, 2)]);

        let mut unsettled =
            FinalSweep::new(&base, target.clone(), &heights(&[0, 0]), vec![false, true]).unwrap();
        assert!(unsettled.halted());
        assert_eq!(unsettled.planned(), 2);
        assert_eq!(coordinates(unsettled.by_ref()), vec![(0, 1), (1, 1)]);

        // An unsettled chain with no new block may still gain one at the first offset, so the
        // sweep halts before emitting anything.
        let mut idle =
            FinalSweep::new(&tips(&[1, 0]), target, &heights(&[1, 0]), vec![false, true]).unwrap();
        assert!(idle.halted());
        assert_eq!(idle.planned(), 0);
        assert!(coordinates(idle.by_ref()).is_empty());
    }

    #[test]
    fn final_sweep_places_pinned_slots_past_an_unsettled_extension() {
        // Chain 0 proposed nothing and some voters endorsed a block above its tip; chain 1's
        // proposal reached height 3 and every position finalized. The pinned blocks emit.
        let base = tips(&[0, 0]);
        let mut sweep =
            FinalSweep::new(&base, tips(&[0, 3]), &heights(&[0, 3]), vec![false, true]).unwrap();
        assert!(!sweep.halted());
        assert_eq!(sweep.planned(), 3);
        assert_eq!(coordinates(sweep.by_ref()), vec![(1, 1), (1, 2), (1, 3)]);

        // Chain 1's own extension above its proposed tip waits behind chain 0's empty slot.
        let mut sweep =
            FinalSweep::new(&base, tips(&[0, 4]), &heights(&[0, 3]), vec![false, true]).unwrap();
        assert!(sweep.halted());
        assert_eq!(sweep.planned(), 3);
        assert_eq!(coordinates(sweep.by_ref()), vec![(1, 1), (1, 2), (1, 3)]);

        // A settled extension follows every pinned block.
        let mut sweep =
            FinalSweep::new(&base, tips(&[2, 3]), &heights(&[1, 3]), vec![true, true]).unwrap();
        assert!(!sweep.halted());
        assert_eq!(sweep.planned(), 5);
        assert_eq!(
            coordinates(sweep.by_ref()),
            vec![(0, 1), (1, 1), (1, 2), (1, 3), (0, 2)]
        );
    }

    #[test]
    fn final_sweep_halts_the_positional_pass_on_a_shortfall() {
        // Chain 0 finalized position 1 of a two-entry proposal: a V-QC may still carry it to
        // height 2, so the pass halts there and no extension slot is reached.
        let base = tips(&[0, 0]);
        let mut sweep =
            FinalSweep::new(&base, tips(&[1, 3]), &heights(&[2, 2]), vec![false, true]).unwrap();
        assert!(sweep.halted());
        assert_eq!(sweep.planned(), 2);
        assert_eq!(coordinates(sweep.by_ref()), vec![(0, 1), (1, 1)]);
    }

    #[test]
    fn final_sweep_newest_first_is_exact_reverse() {
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
            let base = tips(&base);
            let target = tips(&target);
            let stream = FinalSweep::new(&base, target, &heights(&proposed), settled).unwrap();
            let mut reverse = coordinates(stream.newest_first());
            reverse.reverse();
            assert_eq!(coordinates(stream), reverse);
        }
    }

    #[test]
    fn final_sweep_continues_after_branch_settlement() {
        let committee = Committee::<MinPk>::new(17, 6, Limits::new(2, 1).unwrap());
        let codec = committee.codec();
        let signed = committee.leader_block(1);
        let leader = signed.block();
        let votes = (0..6)
            .map(|signer| {
                let mut extensions = vec![Extension::empty(); codec.chains()];
                if signer < 2 {
                    extensions[0] =
                        Extension::new(vec![Sha256::hash(&[&[signer as u8]])], 1).unwrap();
                }
                extensions[1] = Extension::new(vec![Sha256::hash(&[b"ready"])], 1).unwrap();
                let body = VoteBody::for_leader::<Sha256, MinPk>(
                    leader,
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
            assert_eq!(coordinates(sweep), expected);
        }
    }

    #[test]
    fn final_sweep_reuses_authenticated_lqc_algebra() {
        let committee = Committee::<MinPk>::new(17, 6, Limits::new(2, 1).unwrap());
        let lqc = committee.lqc(1);
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

        assert_eq!(sweep.target().len(), committee.codec().chains());
    }

    #[test]
    fn history_openings_are_oldest_first_and_frontier_is_exact() {
        let history = Sha256::hash(&[b"history"]);
        let first = TipRecord::at_tips(history, tips(&[1, 1])).unwrap();
        let first_id = first.commitment::<Sha256>();
        let second = TipRecord::at_tips(first_id, tips(&[2, 2])).unwrap();
        let second_id = second.commitment::<Sha256>();
        let mut state = HistoryState::new(history, tips(&[0, 0]), tips(&[1, 0])).unwrap();

        assert!(matches!(
            state.validate_opening::<Sha256>(second_id, &second, &tips(&[1, 0])),
            Err(Error::History)
        ));
        state
            .validate_opening::<Sha256>(first_id, &first, &tips(&[1, 0]))
            .unwrap();
        let stream = Horizontal::new(state.ordered(), first.tips(), first.proposed()).unwrap();
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
                (expected, halted)
            );
        }
    }

    /// One offset-major pass over `deltas` above `floors`, halting at the first empty slot of a
    /// halting chain. Returns the visited coordinates and whether the pass halted.
    fn reference_pass(floors: &[u64], deltas: &[u64], halting: &[bool]) -> (Vec<(u32, u64)>, bool) {
        let max = deltas.iter().copied().max().unwrap_or(0);
        let mut visited = Vec::new();
        for offset in 1..=max.saturating_add(1) {
            for chain in 0..deltas.len() {
                if offset <= deltas[chain] {
                    visited.push((chain as u32, floors[chain] + offset));
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
            let base_tips = tips(base);
            let target_tips = tips(&target_heights);
            let proposed = heights(&proposed_heights);

            let never = vec![false; chains];
            let mut expected_horizontal = reference_pass(base, &positional, &never).0;
            expected_horizontal.extend(reference_pass(&boundary, &extension, &never).0);
            let horizontal_stream = Horizontal::new(&base_tips, &target_tips, &proposed).unwrap();
            let mut reverse_horizontal = coordinates(horizontal_stream.newest_first());
            reverse_horizontal.reverse();
            let horizontal = coordinates(horizontal_stream);
            prop_assert_eq!(&horizontal, &expected_horizontal);
            prop_assert_eq!(horizontal, reverse_horizontal);

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
            let mut reverse_sweep = coordinates(sweep_stream.newest_first());
            reverse_sweep.reverse();
            let sweep = coordinates(sweep_stream);
            prop_assert_eq!(&sweep, &expected_sweep);
            prop_assert_eq!(sweep, reverse_sweep);
        }
    }
}
