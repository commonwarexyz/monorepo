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

/// Offset-major traversal from one canonical tip vector to a higher vector.
pub(in crate::multimmit::marshal) struct Horizontal<D: Digest> {
    base: Vec<BlockRef<D>>,
    target: Vec<BlockRef<D>>,
    coordinates: Coordinates,
}

impl<D: Digest> Horizontal<D> {
    pub(in crate::multimmit::marshal) fn new(
        base: &[BlockRef<D>],
        target: &[BlockRef<D>],
    ) -> Result<Self, Error> {
        validate_monotone(base, target)?;
        let deltas = base
            .iter()
            .zip(target)
            .map(|(base, target)| target.height().get() - base.height().get())
            .collect::<Vec<_>>();
        Ok(Self {
            base: base.to_vec(),
            target: target.to_vec(),
            coordinates: Coordinates::new(deltas),
        })
    }
}

impl<D: Digest> Iterator for Horizontal<D> {
    type Item = Slot<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.coordinates
            .next()
            .map(|coordinate| slot_at(&self.base, &self.target, coordinate))
    }
}

impl<D: Digest> OrderedSlots<D> for Horizontal<D> {
    fn newest_first(&self) -> impl Iterator<Item = Slot<D>> + '_ {
        newest_first(&self.base, &self.target, &self.coordinates)
    }
}

/// Streaming rho sweep toward final tips.
pub(in crate::multimmit::marshal) struct FinalSweep<D: Digest> {
    base: Vec<BlockRef<D>>,
    target: Vec<BlockRef<D>>,
    coordinates: Coordinates,
}

impl<D: Digest> FinalSweep<D> {
    pub(in crate::multimmit::marshal) fn new(
        base: &[BlockRef<D>],
        target: Vec<BlockRef<D>>,
        settled: Vec<bool>,
    ) -> Result<Self, Error> {
        validate_monotone(base, &target)?;
        if settled.len() != target.len() {
            return Err(Error::Frontier);
        }
        let deltas = base
            .iter()
            .zip(&target)
            .map(|(base, target)| target.height().get() - base.height().get())
            .collect::<Vec<_>>();
        let max_offset = deltas.iter().copied().max().ok_or(Error::Frontier)?;
        let cutoff = base
            .iter()
            .zip(&target)
            .zip(&settled)
            .enumerate()
            .filter(|(_, (_, settled))| !**settled)
            .filter_map(|(chain, ((base, target), _))| {
                (target.height().get() - base.height().get())
                    .checked_add(1)
                    .map(|offset| (offset, chain))
            })
            .min();
        let back = match cutoff {
            Some((1, 0)) => None,
            Some((offset, chain)) if chain > 0 => Some(Coordinate {
                offset,
                chain: chain - 1,
            }),
            Some((offset, _)) => Some(Coordinate {
                offset: offset - 1,
                chain: base.len() - 1,
            }),
            None if max_offset == 0 => None,
            None => Some(Coordinate {
                offset: max_offset,
                chain: base.len() - 1,
            }),
        };
        Ok(Self {
            base: base.to_vec(),
            target,
            coordinates: Coordinates::new(truncate_deltas(&deltas, back)),
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
        Self::new(base, tips.blocks().to_vec(), settled)
    }

    pub(in crate::multimmit::marshal) fn target(&self) -> &[BlockRef<D>] {
        &self.target
    }
}

impl<D: Digest> Iterator for FinalSweep<D> {
    type Item = Slot<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.coordinates
            .next()
            .map(|coordinate| slot_at(&self.base, &self.target, coordinate))
    }
}

impl<D: Digest> OrderedSlots<D> for FinalSweep<D> {
    fn newest_first(&self) -> impl Iterator<Item = Slot<D>> + '_ {
        newest_first(&self.base, &self.target, &self.coordinates)
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

fn slot_at<D: Digest>(
    base: &[BlockRef<D>],
    target: &[BlockRef<D>],
    coordinate: Coordinate,
) -> Slot<D> {
    let base = base[coordinate.chain];
    let target = target[coordinate.chain];
    Slot {
        tip: target,
        height: Height::new(
            base.height()
                .get()
                .checked_add(coordinate.offset)
                .expect("offset is bounded by the target height"),
        ),
    }
}

fn newest_first<'a, D: Digest>(
    base: &'a [BlockRef<D>],
    target: &'a [BlockRef<D>],
    coordinates: &Coordinates,
) -> impl Iterator<Item = Slot<D>> + 'a {
    coordinates
        .newest_first()
        .map(move |coordinate| slot_at(base, target, coordinate))
}

fn truncate_deltas(deltas: &[u64], back: Option<Coordinate>) -> Vec<u64> {
    deltas
        .iter()
        .enumerate()
        .map(|(chain, delta)| {
            let Some(back) = back else {
                return 0;
            };
            let last_offset = if chain <= back.chain {
                back.offset
            } else {
                back.offset.saturating_sub(1)
            };
            (*delta).min(last_offset)
        })
        .collect()
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
    use crate::multimmit::{config::Limits, mocks::Committee};
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
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
        let stream = Horizontal::new(&tips(&[2, 5]), &tips(&[4, 6])).unwrap();
        assert_eq!(coordinates(stream), vec![(0, 3), (1, 6), (0, 4)]);
    }

    #[test]
    fn horizontal_newest_first_is_exact_reverse() {
        let base = tips(&[2, 5, 1, 8]);
        let target = tips(&[6, 6, 4, 8]);
        let stream = Horizontal::new(&base, &target).unwrap();
        let mut reverse = coordinates(stream.newest_first());
        reverse.reverse();
        assert_eq!(coordinates(stream), reverse);
    }

    #[test]
    fn final_sweep_skips_settled_and_halts_at_unsettled_holes() {
        let base = tips(&[0, 0]);
        let target = tips(&[1, 2]);
        let mut settled = FinalSweep::new(&base, target.clone(), vec![true, true]).unwrap();
        assert_eq!(coordinates(settled.by_ref()), vec![(0, 1), (1, 1), (1, 2)]);

        let mut unsettled = FinalSweep::new(&base, target, vec![false, true]).unwrap();
        assert_eq!(coordinates(unsettled.by_ref()), vec![(0, 1), (1, 1)]);
    }

    #[test]
    fn final_sweep_newest_first_is_exact_reverse() {
        for (base, target, settled) in [
            (vec![2, 5, 1, 8], vec![6, 6, 4, 8], vec![true; 4]),
            (
                vec![2, 5, 1, 8],
                vec![6, 6, 4, 8],
                vec![true, false, true, false],
            ),
            (
                vec![2, 5, 1, 8],
                vec![2, 8, 4, 9],
                vec![false, true, false, true],
            ),
        ] {
            let base = tips(&base);
            let target = tips(&target);
            let stream = FinalSweep::new(&base, target, settled).unwrap();
            let mut reverse = coordinates(stream.newest_first());
            reverse.reverse();
            assert_eq!(coordinates(stream), reverse);
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
        let first = TipRecord::new(history, tips(&[1, 1])).unwrap();
        let first_id = first.commitment::<Sha256>();
        let second = TipRecord::new(first_id, tips(&[2, 2])).unwrap();
        let second_id = second.commitment::<Sha256>();
        let mut state = HistoryState::new(history, tips(&[0, 0]), tips(&[1, 0])).unwrap();

        assert!(matches!(
            state.validate_opening::<Sha256>(second_id, &second, &tips(&[1, 0])),
            Err(Error::History)
        ));
        state
            .validate_opening::<Sha256>(first_id, &first, &tips(&[1, 0]))
            .unwrap();
        let stream = Horizontal::new(state.ordered(), first.tips()).unwrap();
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

    proptest! {
        #[test]
        fn streams_match_materialized_reference(
            base in vec(0u64..20, 1..5),
            deltas in vec(0u64..6, 1..5),
            settled in vec(any::<bool>(), 1..5),
        ) {
            let chains = base.len().min(deltas.len()).min(settled.len());
            let base = &base[..chains];
            let deltas = &deltas[..chains];
            let settled = &settled[..chains];
            let target_heights = base.iter().zip(deltas).map(|(base, delta)| base + delta).collect::<Vec<_>>();
            let base_tips = tips(base);
            let target_tips = tips(&target_heights);

            let max = deltas.iter().copied().max().unwrap();
            let expected_horizontal = (1..=max)
                .flat_map(|offset| (0..chains).filter_map(move |chain| {
                    (offset <= deltas[chain]).then_some((chain as u32, base[chain] + offset))
                }))
                .collect::<Vec<_>>();
            let horizontal_stream = Horizontal::new(&base_tips, &target_tips).unwrap();
            let mut reverse_horizontal = coordinates(horizontal_stream.newest_first());
            reverse_horizontal.reverse();
            let horizontal = coordinates(horizontal_stream);
            prop_assert_eq!(&horizontal, &expected_horizontal);
            prop_assert_eq!(horizontal, reverse_horizontal);

            let mut expected_sweep = Vec::new();
            'outer: for offset in 1..=max.saturating_add(1) {
                for chain in 0..chains {
                    if offset <= deltas[chain] {
                        expected_sweep.push((chain as u32, base[chain] + offset));
                    } else if !settled[chain] {
                        break 'outer;
                    }
                }
                if offset == max && settled.iter().all(|settled| *settled) {
                    break;
                }
            }
            let sweep_stream =
                FinalSweep::new(&base_tips, target_tips, settled.to_vec()).unwrap();
            let mut reverse_sweep = coordinates(sweep_stream.newest_first());
            reverse_sweep.reverse();
            let sweep = coordinates(sweep_stream);
            prop_assert_eq!(&sweep, &expected_sweep);
            prop_assert_eq!(sweep, reverse_sweep);
        }
    }
}
