//! The canonical block order and the restartable cut through it.
//!
//! Each resolved view contributes `Horiz(base, tips)`: the blocks between the previous view's tips
//! and its own, in horizontal order (see [`algebra::Horiz`]). The open view's sweep (see
//! [`algebra::Sweep`]) may emit a prefix of the next resolved view's contribution early. The cut is
//! a [`HistoryState`]: the newest resolved view, its tips-history commitment and tips (the ordered
//! frontier), and the highest emitted block on every chain (the emitted frontier), which runs ahead
//! of the ordered frontier only by such a sweep prefix.

use crate::{
    multimmit::{
        algebra::{self, Append, Horiz, Step, Sweep},
        types::{BlockRef, ChainId, ChainSet, Frontier, FrontierError, HistoryRecord},
    },
    types::{Height, View},
};
use commonware_cryptography::{Digest, Hasher};

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
    #[error("tips-history opening does not extend the active history")]
    History,
    #[error("tips-history view overflows")]
    ViewOverflow,
    #[error("emitted blocks are not a prefix of the order")]
    Prefix,
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

/// The action for one resolved block reference.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reconciliation {
    /// The block belongs to the emitted prefix.
    Duplicate,
    /// The block is the next chain-local output.
    Emit,
}

/// A restartable cut through the resolved views and the open view's sweep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoryState<D: Digest> {
    view: View,
    history: D,
    ordered: Frontier<D>,
    emitted: Frontier<D>,
}

impl<D: Digest> HistoryState<D> {
    /// Creates the cut at resolved `view`, whose tips-history commitment is `history` and whose
    /// tips are `ordered`, with `emitted` at or above `ordered` on every chain.
    pub(crate) fn new(
        view: View,
        history: D,
        ordered: Vec<BlockRef<D>>,
        emitted: Vec<BlockRef<D>>,
    ) -> Result<Self, Error> {
        let ordered = Frontier::new(ordered)?;
        let emitted = Frontier::new(emitted)?;
        emitted.dominates(&ordered)?;
        Ok(Self {
            view,
            history,
            ordered,
            emitted,
        })
    }

    /// Returns the newest resolved view.
    pub(crate) const fn view(&self) -> View {
        self.view
    }

    /// Returns the tips-history commitment of [`Self::view`].
    pub(crate) const fn history(&self) -> D {
        self.history
    }

    /// Returns the tips of [`Self::view`], one per chain.
    pub(crate) fn ordered(&self) -> &[BlockRef<D>] {
        self.ordered.references()
    }

    /// Returns the highest emitted block on every chain.
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

    /// Advances the cut to the next view, whose history opening has been completely emitted.
    pub(crate) fn finish_opening<H: Hasher<Digest = D>>(
        &mut self,
        commitment: D,
        record: &HistoryRecord<D>,
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
        self.view = self
            .view
            .get()
            .checked_add(1)
            .map(View::new)
            .ok_or(Error::ViewOverflow)?;
        self.history = commitment;
        self.ordered = Frontier::new(record.tips().to_vec())?;
        Ok(())
    }

    /// Checks that `record`, with commitment `commitment`, opens the view after [`Self::view`].
    fn check_opening<H: Hasher<Digest = D>>(
        &self,
        commitment: D,
        record: &HistoryRecord<D>,
    ) -> Result<(), Error> {
        if record.parent() != self.history || record.commitment::<H>() != commitment {
            return Err(Error::History);
        }
        Ok(())
    }

    /// Reconciles one resolved slot against the emitted frontier.
    pub(crate) fn reconcile(
        &mut self,
        slot: Append<D>,
        reference: BlockRef<D>,
    ) -> Result<Reconciliation, Error> {
        if reference.chain() != slot.chain || reference.height() != slot.height {
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

    /// Validates `common`, which holds on every chain the ancestor of the higher of `target` and
    /// the emitted tip at the lower one's height.
    ///
    /// Every resolved view's tips and every sweep's final tips extend the emitted frontier or lie
    /// below it on the same path, so the ancestor must be the lower reference.
    pub(crate) fn validate_reconciliation(
        &self,
        target: &[BlockRef<D>],
        common: &[BlockRef<D>],
    ) -> Result<(), Error> {
        same_chains(&self.emitted, target)?;
        same_chains(&self.emitted, common)?;
        for ((emitted, target), common) in self.emitted.references().iter().zip(target).zip(common)
        {
            let lower = if target.height() <= emitted.height() {
                target
            } else {
                emitted
            };
            if common != lower {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }

    /// Checks that the blocks emitted above the ordered frontier are exactly a prefix of `slots`,
    /// the order the next view places above the ordered frontier.
    ///
    /// The open view's sweep emits a prefix of its view's horizontal order (CS Lemma prefix). A
    /// resolution or later sweep whose order does not start with every emitted block contradicts
    /// it.
    pub(crate) fn check_prefix(
        &self,
        slots: impl IntoIterator<Item = Append<D>>,
    ) -> Result<(), Error> {
        let mut swept = Vec::with_capacity(self.ordered.chains());
        let mut remaining = 0u64;
        for (ordered, emitted) in self.ordered().iter().zip(self.emitted()) {
            swept.push(emitted.height());
            remaining += emitted.height().get() - ordered.height().get();
        }
        for slot in slots {
            if remaining == 0 {
                return Ok(());
            }
            let emitted = swept.get(slot.chain.index()).ok_or(Error::Frontier)?;
            if slot.height > *emitted {
                return Err(Error::Prefix);
            }
            remaining -= 1;
        }
        (remaining == 0).then_some(()).ok_or(Error::Prefix)
    }
}

/// Returns the order the views ending at each of `tips` place above `base`: `Horiz(base, tips[0])`,
/// then `Horiz(tips[0], tips[1])`, and so on.
///
/// The order is generated lazily; it holds one cursor per view.
pub(crate) fn horizontal<'a, D: Digest>(
    base: &'a [BlockRef<D>],
    tips: impl IntoIterator<Item = &'a [BlockRef<D>]>,
) -> Result<impl Iterator<Item = Append<D>> + 'a, Error> {
    let mut from = base;
    let views = tips
        .into_iter()
        .map(|to| {
            let view = Horiz::new(from, to);
            from = to;
            view
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(views.into_iter().flatten())
}

/// Returns, in chain order, whether each of the `chains` chains is in `settled`.
pub(crate) fn settled_flags(chains: usize, settled: &ChainSet) -> Result<Vec<bool>, Error> {
    if settled.chains() != chains {
        return Err(Error::Frontier);
    }
    Ok((0..chains)
        .map(|chain| settled.contains(ChainId::new(chain as u32)))
        .collect())
}

/// Returns the blocks the open view's sweep over `base` places before it halts or finishes,
/// generated lazily.
pub(crate) fn sweep<'a, D: Digest>(
    base: &'a [BlockRef<D>],
    finals: &'a [BlockRef<D>],
    settled: &'a [bool],
) -> Result<impl Iterator<Item = Append<D>> + 'a, Error> {
    Ok(
        Sweep::new(base, finals, settled)?.map_while(|step| match step {
            Step::Append(append) => Some(append),
            Step::Halt => None,
        }),
    )
}

/// Returns each chain's highest height that [`sweep`] places, in O(chains); chains it places
/// nothing on have none.
///
/// The sweep halts at the first coordinate `(o, i)`, offset first, at which an unsettled chain
/// `i` lies above its final tip, that is `o = ht(finals_i) - ht(base_i) + 1`, provided some chain
/// still has a block at that offset. Every chain places its blocks up to its final tip at the
/// offsets before the halt, and at the halt's offset the chains before it place one more.
pub(crate) fn sweep_maxima<D: Digest>(
    base: &[BlockRef<D>],
    finals: &[BlockRef<D>],
    settled: &[bool],
) -> Vec<Option<Height>> {
    let leads = base
        .iter()
        .zip(finals)
        .map(|(base, finals)| finals.height().get().saturating_sub(base.height().get()))
        .collect::<Vec<_>>();
    let last = leads.iter().copied().max().unwrap_or(0);
    let halt = leads
        .iter()
        .zip(settled)
        .enumerate()
        .filter(|(_, (_, settled))| !**settled)
        .filter_map(|(chain, (lead, _))| {
            lead.checked_add(1)
                .filter(|offset| *offset <= last)
                .map(|offset| (offset, chain))
        })
        .min();
    base.iter()
        .zip(&leads)
        .enumerate()
        .map(|(chain, (base, lead))| {
            let limit = match halt {
                Some((offset, halted)) if chain < halted => offset,
                Some((offset, _)) => offset - 1,
                None => *lead,
            };
            let placed = (*lead).min(limit);
            (placed > 0).then(|| Height::new(base.height().get() + placed))
        })
        .collect()
}

/// Returns the number of blocks between `base` (exclusive) and `target` (inclusive).
pub(crate) fn outputs<D: Digest>(
    base: &[BlockRef<D>],
    target: &[BlockRef<D>],
) -> Result<u64, Error> {
    Frontier::new(target.to_vec())?.dominates(&Frontier::new(base.to_vec())?)?;
    base.iter()
        .zip(target)
        .try_fold(0u64, |total, (base, target)| {
            total.checked_add(target.height().get() - base.height().get())
        })
        .ok_or(Error::Frontier)
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
    use proptest::{collection::vec, prelude::*};

    /// A slot coordinate: chain index and height.
    type Point = (usize, u64);

    fn reference(chain: usize, height: u64) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain as u32),
            Height::new(height),
            Sha256::hash(&[
                b"marshal order",
                &(chain as u32).to_be_bytes(),
                &height.to_be_bytes(),
            ]),
        )
    }

    fn frontier(heights: &[u64]) -> Vec<BlockRef<Sha256Digest>> {
        heights
            .iter()
            .enumerate()
            .map(|(chain, height)| reference(chain, *height))
            .collect()
    }

    fn points(slots: &[Append<Sha256Digest>]) -> Vec<Point> {
        slots
            .iter()
            .map(|slot| {
                assert_eq!(slot.tip.chain(), slot.chain);
                (slot.chain.index(), slot.height.get())
            })
            .collect()
    }

    /// Returns the order of the views ending at each of `tips` above `base`.
    fn horiz(base: &[u64], tips: &[&[u64]]) -> Result<Vec<Append<Sha256Digest>>, Error> {
        let base = frontier(base);
        let tips = tips.iter().map(|tips| frontier(tips)).collect::<Vec<_>>();
        Ok(horizontal(&base, tips.iter().map(Vec::as_slice))?.collect())
    }

    /// Returns the sweep's blocks, checking [`sweep_maxima`] against them.
    fn swept_slots(base: &[u64], finals: &[u64], members: &[usize]) -> Vec<Append<Sha256Digest>> {
        let settled = (0..base.len())
            .map(|chain| members.contains(&chain))
            .collect::<Vec<_>>();
        let (base, finals) = (frontier(base), frontier(finals));
        let slots = sweep(&base, &finals, &settled).unwrap().collect::<Vec<_>>();
        let mut maxima = vec![None; base.len()];
        for slot in &slots {
            maxima[slot.chain.index()] = Some(slot.height);
        }
        assert_eq!(sweep_maxima(&base, &finals, &settled), maxima);
        slots
    }

    /// The horizontal order enumerated from its definition: offset first, then chain.
    fn enumerate(base: &[u64], tips: &[u64]) -> Vec<Point> {
        let lead = base
            .iter()
            .zip(tips)
            .map(|(base, tip)| tip - base)
            .max()
            .unwrap_or(0);
        let mut order = Vec::new();
        for offset in 1..=lead {
            for (chain, (base, tip)) in base.iter().zip(tips).enumerate() {
                if base + offset <= *tip {
                    order.push((chain, base + offset));
                }
            }
        }
        order
    }

    /// Returns the cut at view 1 whose emitted frontier holds every block of `slots`.
    fn swept(ordered: &[u64], slots: &[Append<Sha256Digest>]) -> HistoryState<Sha256Digest> {
        let mut emitted = ordered.to_vec();
        for slot in slots {
            emitted[slot.chain.index()] = slot.height.get();
        }
        HistoryState::new(
            View::new(1),
            Sha256::hash(&[b"history"]),
            frontier(ordered),
            frontier(&emitted),
        )
        .unwrap()
    }

    #[test]
    fn horizontal_is_offset_major_across_views() {
        let slots = horiz(&[2, 5], &[&[4, 6]]).unwrap();
        assert_eq!(points(&slots), vec![(0, 3), (1, 6), (0, 4)]);
        assert_eq!(outputs(&frontier(&[2, 5]), &frontier(&[4, 6])), Ok(3));
        let slots = horiz(&[2, 5], &[&[3, 5], &[4, 7]]).unwrap();
        assert_eq!(points(&slots), vec![(0, 3), (0, 4), (1, 6), (1, 7)]);
        assert!(horiz(&[2, 2], &[&[1, 2]]).is_err());
        assert!(horiz(&[2, 2], &[&[3, 2], &[2, 2]]).is_err());
        assert_eq!(
            outputs(&frontier(&[2, 2]), &frontier(&[1, 2])),
            Err(Error::Regression)
        );
    }

    #[test]
    fn sweep_halts_at_the_first_unsettled_chain_above_its_final_tip() {
        let slots = swept_slots(&[0, 0, 0], &[2, 1, 0], &[]);
        assert_eq!(points(&slots), vec![(0, 1), (1, 1)]);
        // A halt at a later chain lets the earlier chains place one more block at its offset.
        let slots = swept_slots(&[0, 0, 0], &[3, 3, 1], &[]);
        assert_eq!(points(&slots), vec![(0, 1), (1, 1), (2, 1), (0, 2), (1, 2)]);
    }

    #[test]
    fn sweep_skips_settled_chains() {
        let slots = swept_slots(&[0, 0, 0], &[2, 1, 0], &[2]);
        assert_eq!(points(&slots), vec![(0, 1), (1, 1), (0, 2)]);
        let slots = swept_slots(&[0, 0, 0], &[2, 1, 0], &[1, 2]);
        assert_eq!(points(&slots), vec![(0, 1), (1, 1), (0, 2)]);
        let slots = swept_slots(&[0, 0, 0], &[2, 1, 0], &[0, 1, 2]);
        assert_eq!(points(&slots), vec![(0, 1), (1, 1), (0, 2)]);
        assert_eq!(settled_flags(3, &ChainSet::empty(2)), Err(Error::Frontier));
    }

    #[test]
    fn resolution_after_a_sweep_must_start_with_the_swept_blocks() {
        let ordered = [0, 0, 0];
        let swept_slots = swept_slots(&ordered, &[2, 1, 0], &[2]);
        let state = swept(&ordered, &swept_slots);

        // Chain 2 was settled at its base, so the view's tips keep it there.
        let resolution = horiz(&ordered, &[&[2, 2, 0]]).unwrap();
        assert_eq!(points(&resolution[..3]), points(&swept_slots));
        state.check_prefix(resolution).unwrap();

        // A resolution that places chain 2 before the swept (0, 2) contradicts the sweep.
        let reordered = horiz(&ordered, &[&[2, 2, 1]]).unwrap();
        assert_eq!(state.check_prefix(reordered), Err(Error::Prefix));

        // A resolution below the swept blocks drops them.
        let lower = horiz(&ordered, &[&[1, 1, 0]]).unwrap();
        assert_eq!(state.check_prefix(lower), Err(Error::Prefix));
    }

    #[test]
    fn a_retreating_sweep_does_not_cover_the_emitted_prefix() {
        let ordered = [0, 0];
        let state = swept(&ordered, &swept_slots(&ordered, &[2, 2], &[]));
        let lower = swept_slots(&ordered, &[1, 2], &[]);
        assert_eq!(state.check_prefix(lower), Err(Error::Prefix));
        state
            .check_prefix(swept_slots(&ordered, &[3, 2], &[]))
            .unwrap();
    }

    #[test]
    fn openings_advance_the_view_and_extend_the_history() {
        let genesis = Sha256::hash(&[b"genesis"]);
        let first = HistoryRecord::new(genesis, frontier(&[1, 1])).unwrap();
        let first_id = first.commitment::<Sha256>();
        let second = HistoryRecord::new(first_id, frontier(&[2, 2])).unwrap();
        let second_id = second.commitment::<Sha256>();
        let mut state =
            HistoryState::new(View::zero(), genesis, frontier(&[0, 0]), frontier(&[1, 0])).unwrap();

        assert_eq!(
            state.finish_opening::<Sha256>(second_id, &second),
            Err(Error::History)
        );
        assert_eq!(
            state.finish_opening::<Sha256>(first_id, &first),
            Err(Error::Gap)
        );
        for slot in horiz(&[0, 0], &[&[1, 1]]).unwrap() {
            let resolved = reference(slot.chain.index(), slot.height.get());
            let expected = if resolved == reference(0, 1) {
                Reconciliation::Duplicate
            } else {
                Reconciliation::Emit
            };
            assert_eq!(state.reconcile(slot, resolved), Ok(expected));
        }
        state.finish_opening::<Sha256>(first_id, &first).unwrap();
        assert_eq!(state.view(), View::new(1));
        assert_eq!(state.history(), first_id);
        assert_eq!(state.ordered(), first.tips());
        assert_eq!(state.emitted(), first.tips());
    }

    #[test]
    fn reconciliation_rejects_conflicts_gaps_and_misplaced_blocks() {
        let mut state = swept(&[1, 1], &[]);
        let fork = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"fork"]));
        let slot = |chain: usize, height: u64| Append {
            chain: ChainId::new(chain as u32),
            height: Height::new(height),
            tip: reference(chain, height),
        };
        assert_eq!(state.reconcile(slot(0, 1), fork), Err(Error::Conflict));
        assert_eq!(
            state.reconcile(slot(0, 3), reference(0, 3)),
            Err(Error::Gap)
        );
        assert_eq!(
            state.reconcile(slot(0, 2), reference(1, 2)),
            Err(Error::Coordinate)
        );
        assert_eq!(
            state.reconcile(slot(0, 1), reference(0, 1)),
            Ok(Reconciliation::Duplicate)
        );
        assert_eq!(
            state.reconcile(slot(0, 2), reference(0, 2)),
            Ok(Reconciliation::Emit)
        );
    }

    #[test]
    fn reconciliation_requires_the_lower_frontier_on_the_higher_path() {
        let state = swept(&[2, 1], &[]);
        let target = frontier(&[3, 1]);
        state
            .validate_reconciliation(&target, &frontier(&[2, 1]))
            .unwrap();
        let fork = BlockRef::new(ChainId::new(0), Height::new(2), Sha256::hash(&[b"fork"]));
        assert_eq!(
            state.validate_reconciliation(&target, &[fork, reference(1, 1)]),
            Err(Error::Conflict)
        );
        // A target below the emitted tip must be its ancestor.
        assert_eq!(
            state.validate_reconciliation(&frontier(&[1, 1]), &frontier(&[2, 1])),
            Err(Error::Conflict)
        );
    }

    proptest! {
        /// PO-12: the horizontal order matches its explicit enumeration, every sweep whose final
        /// tips lie below the view's tips (settled chains exactly at them) is a prefix of it, and
        /// the cut after any such sweep accepts the resolution.
        #[test]
        fn sweeps_are_prefixes_of_the_resolved_order(
            view in vec((0u64..6, 0u64..6, 0u64..6, any::<bool>()), 1..6),
        ) {
            let base = view.iter().map(|(base, ..)| *base).collect::<Vec<_>>();
            let tips = view.iter().map(|(base, lead, ..)| base + lead).collect::<Vec<_>>();
            let finals = view
                .iter()
                .map(|(base, lead, swept, _)| base + swept.min(lead))
                .collect::<Vec<_>>();
            let members = view
                .iter()
                .enumerate()
                .filter(|(_, (_, lead, swept, settle))| *settle && swept >= lead)
                .map(|(chain, _)| chain)
                .collect::<Vec<_>>();

            let resolution = horiz(&base, &[&tips]).unwrap();
            prop_assert_eq!(points(&resolution), enumerate(&base, &tips));
            prop_assert_eq!(
                outputs(&frontier(&base), &frontier(&tips)).unwrap(),
                resolution.len() as u64
            );

            let swept_slots = swept_slots(&base, &finals, &members);
            prop_assert_eq!(points(&resolution[..swept_slots.len()]), points(&swept_slots));
            swept(&base, &swept_slots).check_prefix(resolution).unwrap();
        }

        /// The O(chains) sweep maxima match the blocks any sweep places.
        #[test]
        fn sweep_maxima_match_the_placed_blocks(
            chains in vec((0u64..6, 0u64..6, any::<bool>()), 1..8),
        ) {
            let base = chains.iter().map(|(base, ..)| *base).collect::<Vec<_>>();
            let finals = chains.iter().map(|(base, lead, _)| base + lead).collect::<Vec<_>>();
            let members = chains
                .iter()
                .enumerate()
                .filter(|(_, (.., settled))| *settled)
                .map(|(chain, _)| chain)
                .collect::<Vec<_>>();
            swept_slots(&base, &finals, &members);
        }
    }
}
