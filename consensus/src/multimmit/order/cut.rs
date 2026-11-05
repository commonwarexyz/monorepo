//! Symbolic positions in the canonical order and the slots between them.
//!
//! The order is a deterministic function of authenticated inputs: the chain of tip-history
//! records each finalized leader commits to, and the final sweep its L-QC fixes (see the
//! [module](super) docs). A [`Cut`] is a position in that order expressed without block digests:
//! the newest incorporated record, its tips, and the height emitted on every chain. Moving a cut
//! across a record or a sweep costs O(chains) and hashes nothing; enumerating the slots in
//! between ([`Expansion`]) costs O(slots).
//!
//! Every slot names its chain, height and the authenticated tip whose ancestor fills it. The
//! digest of that ancestor is not part of the order: callers resolve it by walking parent links
//! down from the tip, so a block is identified by its authenticated descendant rather than by
//! whichever block happens to be stored at its height.

use super::{Error, FinalSweep, SlotStream};
use crate::{
    multimmit::{
        algebra::FinalTips,
        scheme::Scheme,
        types::{BlockRef, ChainId, CodecConfig, FinalityFact, Lqc, TipRecord},
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher};
use std::{collections::VecDeque, sync::Arc};

/// The parts of one leader's finality that fix its final sweep: the final tip, proposed tip
/// height and settledness of every chain, in chain order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SweepFact<D: Digest> {
    tips: Vec<BlockRef<D>>,
    proposed: Vec<Height>,
    settled: Vec<bool>,
}

impl<D: Digest> SweepFact<D> {
    /// Creates a sweep fact, checking that every vector names the same chains in order.
    pub(crate) fn new(
        tips: Vec<BlockRef<D>>,
        proposed: Vec<Height>,
        settled: Vec<bool>,
    ) -> Result<Self, Error> {
        if tips.is_empty() || proposed.len() != tips.len() || settled.len() != tips.len() {
            return Err(Error::Frontier);
        }
        if !canonical(&tips) {
            return Err(Error::Frontier);
        }
        Ok(Self {
            tips,
            proposed,
            settled,
        })
    }

    /// Returns the sweep fact `certificate` proves for its leader.
    pub(crate) fn from_lqc<H, S>(
        certificate: &Lqc<S, D>,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        S: Scheme,
    {
        let tips = FinalTips::from_lqc::<H, S>(certificate, config)?;
        let settled = (0..config.chains())
            .map(|chain| {
                let chain = u32::try_from(chain).map_err(|_| Error::Frontier)?;
                tips.settled(ChainId::new(chain)).ok_or(Error::Frontier)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            tips.blocks().to_vec(),
            certificate.leader().proposed_heights(),
            settled,
        )
    }

    /// Returns the final tip of every chain.
    pub(crate) fn tips(&self) -> &[BlockRef<D>] {
        &self.tips
    }

    /// Returns the proposed tip height of every chain.
    pub(crate) fn proposed(&self) -> &[Height] {
        &self.proposed
    }

    /// Returns the settledness of every chain.
    pub(crate) fn settled(&self) -> &[bool] {
        &self.settled
    }
}

impl<D: Digest> TryFrom<&FinalityFact<D>> for SweepFact<D> {
    type Error = Error;

    fn try_from(fact: &FinalityFact<D>) -> Result<Self, Error> {
        Self::new(
            fact.blocks().to_vec(),
            fact.proposed().to_vec(),
            fact.settled().to_vec(),
        )
    }
}

/// Returns whether the tips name chains zero, one, two and so on, in order.
fn canonical<D: Digest>(tips: &[BlockRef<D>]) -> bool {
    tips.iter()
        .enumerate()
        .all(|(chain, tip)| tip.chain().get() as usize == chain)
}

/// A position in the canonical order, after the record whose commitment is [`Self::history`].
///
/// Records that emit no block still advance the history, so two cuts can share an index and
/// differ in history. Callers order cuts by index and then by the position of their history in
/// the record chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cut<D: Digest> {
    index: u64,
    history: D,
    ordered: Arc<[BlockRef<D>]>,
    emitted: Vec<Height>,
}

impl<D: Digest> Cut<D> {
    /// Creates the cut at the record with commitment `history` and tips `ordered`, having
    /// emitted `emitted` on every chain. The index is the sum of the emitted heights, because
    /// every chain starts at height zero and every output advances one chain by one.
    pub(crate) fn new(
        history: D,
        ordered: Arc<[BlockRef<D>]>,
        emitted: Vec<Height>,
    ) -> Result<Self, Error> {
        if ordered.is_empty() || ordered.len() != emitted.len() || !canonical(&ordered) {
            return Err(Error::Frontier);
        }
        let index = emitted
            .iter()
            .try_fold(0u64, |sum, height| sum.checked_add(height.get()))
            .ok_or(Error::Frontier)?;
        Ok(Self {
            index,
            history,
            ordered,
            emitted,
        })
    }

    /// Returns the index of the last output before this cut, zero before any output.
    pub(crate) const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the commitment of the newest incorporated record.
    pub(crate) const fn history(&self) -> D {
        self.history
    }

    /// Returns the tips of the newest incorporated record.
    pub(crate) fn ordered(&self) -> &[BlockRef<D>] {
        &self.ordered
    }

    /// Returns the tips of the newest incorporated record, shared.
    pub(crate) fn shared_ordered(&self) -> Arc<[BlockRef<D>]> {
        Arc::clone(&self.ordered)
    }

    /// Returns the emitted height of every chain.
    pub(crate) fn emitted(&self) -> &[Height] {
        &self.emitted
    }

    /// Returns the number of chains.
    pub(crate) fn chains(&self) -> usize {
        self.ordered.len()
    }

    /// Returns the cut after opening `record`, whose commitment is `commitment`.
    ///
    /// The caller authenticates that `record` is the next record of the finalized chain; this
    /// only checks that it extends [`Self::history`] and names the same chains.
    pub(crate) fn open(&self, commitment: D, record: &TipRecord<D>) -> Result<Self, Error> {
        if record.parent() != self.history {
            return Err(Error::History);
        }
        if record.tips().len() != self.chains() {
            return Err(Error::Frontier);
        }
        let (emitted, grown) = raise(&self.emitted, record.tips().iter().map(|tip| tip.height()))?;
        Ok(Self {
            index: self.index.checked_add(grown).ok_or(Error::Frontier)?,
            history: commitment,
            ordered: record.tips().into(),
            emitted,
        })
    }

    /// Returns the cut after the final sweep `fact` fixes above this cut's record.
    ///
    /// The caller authenticates that `fact` belongs to a leader whose history is
    /// [`Self::history`].
    pub(crate) fn sweep(&self, fact: &SweepFact<D>) -> Result<Self, Error> {
        if fact.tips.len() != self.chains() {
            return Err(Error::Frontier);
        }
        let placed = FinalSweep::placed(&self.ordered, &fact.tips, &fact.proposed, &fact.settled)?;
        let (emitted, grown) = raise(&self.emitted, placed.into_iter())?;
        Ok(Self {
            index: self.index.checked_add(grown).ok_or(Error::Frontier)?,
            history: self.history,
            ordered: Arc::clone(&self.ordered),
            emitted,
        })
    }
}

/// Returns the per-chain maximum of `emitted` and `heights`, and how much their sum grew.
fn raise(
    emitted: &[Height],
    heights: impl Iterator<Item = Height>,
) -> Result<(Vec<Height>, u64), Error> {
    let mut grown = 0u64;
    let raised = emitted
        .iter()
        .zip(heights)
        .map(|(emitted, height)| {
            if height <= *emitted {
                return Ok(*emitted);
            }
            grown = grown
                .checked_add(height.get() - emitted.get())
                .ok_or(Error::Frontier)?;
            Ok(height)
        })
        .collect::<Result<Vec<Height>, Error>>()?;
    Ok((raised, grown))
}

/// One position of the canonical order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Position<D: Digest> {
    /// Output index of the slot; the first output has index one.
    pub(crate) index: u64,
    /// Height of the slot on the tip's chain.
    pub(crate) height: Height,
    /// Authenticated tip whose ancestor at [`Self::height`] fills the slot.
    pub(crate) tip: BlockRef<D>,
}

impl<D: Digest> Position<D> {
    /// Returns the chain of the slot.
    pub(crate) const fn chain(&self) -> ChainId {
        self.tip.chain()
    }
}

/// One step of an expansion.
enum Step<D: Digest> {
    Open(D, Arc<TipRecord<D>>),
    Sweep(Arc<SweepFact<D>>),
}

/// The slots of the step in progress.
struct Active<D: Digest> {
    slots: SlotStream<D>,
    /// The cut once the step completes.
    end: Cut<D>,
    /// Whether the step is a sweep.
    sweep: bool,
}

/// The positions between a cut and a later one, oldest first, produced lazily.
///
/// An expansion opens each queued record and then applies a queued sweep. Slots at or below a
/// chain's emitted height are skipped, so an expansion resumes correctly from a cut taken in the
/// middle of an opening or a sweep: within one step a chain's slots strictly increase in height,
/// so its emitted prefix is exactly the slots skipped. Memory is O(chains) plus the queued steps.
pub(crate) struct Expansion<D: Digest> {
    cut: Cut<D>,
    steps: VecDeque<Step<D>>,
    active: Option<Active<D>>,
}

impl<D: Digest> Expansion<D> {
    /// Starts an expansion at `cut`.
    pub(crate) const fn new(cut: Cut<D>) -> Self {
        Self {
            cut,
            steps: VecDeque::new(),
            active: None,
        }
    }

    /// Returns the cut after every position yielded so far, including steps that the last
    /// yielded position completed.
    pub(crate) const fn cut(&self) -> &Cut<D> {
        &self.cut
    }

    /// Returns the number of queued steps not started yet.
    pub(crate) fn pending_steps(&self) -> usize {
        self.steps.len()
    }

    /// Queues the opening of `record`, whose commitment is `commitment`.
    pub(crate) fn open(&mut self, commitment: D, record: Arc<TipRecord<D>>) {
        self.steps.push_back(Step::Open(commitment, record));
    }

    /// Queues the final sweep `fact` fixes above the last queued record.
    pub(crate) fn sweep(&mut self, fact: Arc<SweepFact<D>>) {
        self.steps.push_back(Step::Sweep(fact));
    }

    /// Returns whether no step is queued or in progress.
    pub(crate) fn is_idle(&self) -> bool {
        self.active.is_none() && self.steps.is_empty()
    }

    /// Discards the queued or active sweep, keeping the positions already yielded.
    ///
    /// A stronger proof for the same record, or a proof for a later record, supersedes the
    /// sweep in progress; the replacement step resumes after the yielded positions.
    pub(crate) fn abandon_sweep(&mut self) {
        if self.active.as_ref().is_some_and(|active| active.sweep) {
            self.active = None;
        }
        self.steps.retain(|step| matches!(step, Step::Open(..)));
    }

    /// Activates the next step, completing steps that emit nothing at once.
    fn activate(&mut self) -> Result<bool, Error> {
        while self.active.is_none() {
            let Some(step) = self.steps.pop_front() else {
                return Ok(false);
            };
            let (end, stream, sweep) = match step {
                Step::Open(commitment, record) => (
                    self.cut.open(commitment, &record)?,
                    SlotStream::new(&self.cut.ordered, record.tips(), record.proposed())?,
                    false,
                ),
                Step::Sweep(fact) => (
                    self.cut.sweep(&fact)?,
                    FinalSweep::new(
                        &self.cut.ordered,
                        fact.tips.clone(),
                        &fact.proposed,
                        fact.settled.clone(),
                    )?
                    .into_stream(),
                    true,
                ),
            };
            if end.index == self.cut.index {
                // Nothing to emit: the step only advances the history.
                self.cut = end;
                continue;
            }
            self.active = Some(Active {
                slots: stream,
                end,
                sweep,
            });
        }
        Ok(true)
    }

    /// Returns the next position, or `None` once every queued step is complete.
    pub(crate) fn next_position(&mut self) -> Result<Option<Position<D>>, Error> {
        loop {
            if !self.activate()? {
                return Ok(None);
            }
            let active = self.active.as_mut().expect("activated above");
            let emitted = &self.cut.emitted;
            let slot = active
                .slots
                .by_ref()
                .find(|slot| slot.height() > emitted[slot.tip().chain().get() as usize]);
            let Some(slot) = slot else {
                self.cut = self.active.take().expect("active").end;
                continue;
            };
            let index = self.cut.index + 1;
            if index == active.end.index {
                self.cut = self.active.take().expect("active").end;
            } else {
                self.cut.index = index;
                self.cut.emitted[slot.tip().chain().get() as usize] = slot.height();
            }
            return Ok(Some(Position {
                index,
                height: slot.height(),
                tip: slot.tip(),
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::fuzz::frontier, *};
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};

    fn genesis() -> Sha256Digest {
        Sha256::hash(&[b"genesis history"])
    }

    fn heights(heights: &[u64]) -> Vec<Height> {
        heights.iter().map(|height| Height::new(*height)).collect()
    }

    fn start(base: &[u64]) -> Cut<Sha256Digest> {
        Cut::new(genesis(), frontier(base).into(), heights(base)).unwrap()
    }

    fn record(parent: Sha256Digest, tips: &[u64]) -> (Sha256Digest, Arc<TipRecord<Sha256Digest>>) {
        let record = TipRecord::at_tips(parent, frontier(tips)).unwrap();
        (record.commitment::<Sha256>(), Arc::new(record))
    }

    fn fact(tips: &[u64], proposed: &[u64], settled: &[bool]) -> Arc<SweepFact<Sha256Digest>> {
        Arc::new(SweepFact::new(frontier(tips), heights(proposed), settled.to_vec()).unwrap())
    }

    /// Drains `expansion`, checking every index is dense, and returns the coordinates yielded.
    fn drain(expansion: &mut Expansion<Sha256Digest>) -> Vec<(u32, u64)> {
        let mut yielded = Vec::new();
        while let Some(position) = expansion.next_position().unwrap() {
            assert_eq!(position.index, expansion.cut().index());
            assert!(
                position.height <= position.tip.height(),
                "slot above its tip"
            );
            yielded.push((position.chain().get(), position.height.get()));
        }
        assert!(expansion.is_idle());
        yielded
    }

    #[test]
    fn cut_index_is_the_sum_of_emitted_heights() {
        let cut = start(&[3, 0, 5]);
        assert_eq!(cut.index(), 8);
        assert_eq!(cut.chains(), 3);
        assert_eq!(cut.emitted(), heights(&[3, 0, 5]));
        assert_eq!(cut.ordered(), frontier(&[3, 0, 5]));

        // Lengths must agree, chains must be canonical and the index must not overflow.
        assert_eq!(
            Cut::new(genesis(), frontier(&[1, 1]).into(), heights(&[1])),
            Err(Error::Frontier)
        );
        assert_eq!(
            Cut::<Sha256Digest>::new(genesis(), Vec::new().into(), Vec::new()),
            Err(Error::Frontier)
        );
        let mut swapped = frontier(&[1, 1]);
        swapped.swap(0, 1);
        assert_eq!(
            Cut::new(genesis(), swapped.into(), heights(&[1, 1])),
            Err(Error::Frontier)
        );
        assert_eq!(
            Cut::new(genesis(), frontier(&[0, 0]).into(), heights(&[u64::MAX, 1])),
            Err(Error::Frontier)
        );
    }

    #[test]
    fn steps_check_history_and_chain_count() {
        let cut = start(&[0, 0]);
        let (_, stranger) = record(Sha256::hash(&[b"stranger"]), &[1, 1]);
        assert_eq!(
            cut.open(Sha256::hash(&[b"any"]), &stranger),
            Err(Error::History)
        );
        let (commitment, wide) = record(genesis(), &[1, 1, 1]);
        assert_eq!(cut.open(commitment, &wide), Err(Error::Frontier));
        assert_eq!(
            cut.sweep(&fact(&[1, 1, 1], &[1, 1, 1], &[true, true, true])),
            Err(Error::Frontier)
        );
        assert!(SweepFact::new(frontier(&[1]), heights(&[1, 1]), vec![true]).is_err());
    }

    #[test]
    fn a_record_that_emits_nothing_only_advances_the_history() {
        let cut = start(&[2, 2]);
        let (commitment, unchanged) = record(genesis(), &[2, 2]);
        let mut expansion = Expansion::new(cut.clone());
        expansion.open(commitment, Arc::clone(&unchanged));
        assert_eq!(drain(&mut expansion), Vec::new());
        assert_eq!(expansion.cut().history(), commitment);
        assert_eq!(expansion.cut().index(), cut.index());
        assert_eq!(expansion.cut(), &cut.open(commitment, &unchanged).unwrap());
    }

    #[test]
    fn an_opening_places_positional_slots_before_extensions() {
        let cut = start(&[0, 0]);
        let record = TipRecord::new(genesis(), frontier(&[2, 1]), heights(&[1, 1])).unwrap();
        let commitment = record.commitment::<Sha256>();
        let mut expansion = Expansion::new(cut.clone());
        expansion.open(commitment, Arc::new(record.clone()));
        assert_eq!(drain(&mut expansion), vec![(0, 1), (1, 1), (0, 2)]);
        assert_eq!(expansion.cut(), &cut.open(commitment, &record).unwrap());
        assert_eq!(expansion.cut().index(), 3);
    }

    #[test]
    fn a_superseded_sweep_resumes_through_the_next_opening() {
        let (first, opening) = record(genesis(), &[0, 0]);
        let mut expansion = Expansion::new(start(&[0, 0]));
        expansion.open(first, opening);
        expansion.sweep(fact(&[2, 2], &[2, 2], &[true, true]));
        let mut yielded = Vec::new();
        for _ in 0..2 {
            let position = expansion.next_position().unwrap().unwrap();
            yielded.push((position.chain().get(), position.height.get()));
        }
        assert_eq!(yielded, vec![(0, 1), (1, 1)]);
        assert_eq!(expansion.cut().history(), first);

        // A later leader's proof supersedes the sweep; its opening covers the slots the sweep
        // already yielded, which are not yielded again.
        expansion.abandon_sweep();
        assert!(expansion.is_idle());
        let (second, next) = record(first, &[3, 2]);
        expansion.open(second, Arc::clone(&next));
        expansion.sweep(fact(&[3, 2], &[3, 2], &[true, true]));
        yielded.extend(drain(&mut expansion));
        assert_eq!(yielded, vec![(0, 1), (1, 1), (0, 2), (1, 2), (0, 3)]);
        assert_eq!(expansion.cut().history(), second);
        assert_eq!(expansion.cut().index(), 5);
        assert_eq!(expansion.cut().ordered(), next.tips());
    }

    #[test]
    fn abandoning_keeps_queued_openings() {
        let (first, opening) = record(genesis(), &[1, 0]);
        let mut expansion = Expansion::new(start(&[0, 0]));
        expansion.sweep(fact(&[0, 1], &[0, 1], &[true, true]));
        expansion.open(first, opening);
        expansion.abandon_sweep();
        assert_eq!(drain(&mut expansion), vec![(0, 1)]);
        assert_eq!(expansion.cut().history(), first);
    }

    #[test]
    fn a_halted_sweep_emits_only_its_planned_slots() {
        // Chain 0 fell short of its proposed tip, so the sweep halts at its first missing slot.
        let cut = start(&[0, 0]);
        let halted = fact(&[1, 3], &[2, 2], &[false, true]);
        let mut expansion = Expansion::new(cut.clone());
        expansion.sweep(Arc::clone(&halted));
        assert_eq!(drain(&mut expansion), vec![(0, 1), (1, 1)]);
        assert_eq!(expansion.cut(), &cut.sweep(&halted).unwrap());
        assert_eq!(expansion.cut().history(), genesis());
    }
}
