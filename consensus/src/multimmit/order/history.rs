//! The recursive order of tip-history openings and its reconciliation with emitted output.

use super::{Error, FinalSweep, Slot};
use crate::multimmit::{
    scheme::Scheme,
    types::{BlockRef, CodecConfig, Frontier, Lqc, TipRecord},
};
use commonware_cryptography::{Digest, Hasher};

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
    /// `common` contains, on every chain, the ancestor of the higher of the opening tip and the
    /// emitted tip at the lower one's height, as [`Self::validate_reconciliation`] describes.
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
    pub(crate) fn final_sweep<H, S>(
        &self,
        certificate: &Lqc<S, D>,
        config: CodecConfig,
        common: &[BlockRef<D>],
    ) -> Result<FinalSweep<D>, Error>
    where
        H: Hasher<Digest = D>,
        S: Scheme,
    {
        let sweep = FinalSweep::from_lqc::<H, S>(self.ordered.references(), certificate, config)?;
        self.validate_reconciliation(sweep.target(), common)?;
        Ok(sweep)
    }

    /// Reconciles one resolved stream slot against the acknowledged frontier.
    pub(crate) fn reconcile(
        &mut self,
        slot: Slot<D>,
        reference: BlockRef<D>,
    ) -> Result<Reconciliation, Error> {
        if reference.chain() != slot.tip().chain() || reference.height() != slot.height() {
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
    /// Slots at or below the emitted height are suppressed as duplicates, so the ancestor must be
    /// the lower reference. The exception is a target above an ordered tip that nothing was
    /// emitted past: an anchor may jump to a certified block on another branch (only an
    /// equivocating producer makes one), and the order then reads every new block off the
    /// target's own path.
    pub(crate) fn validate_reconciliation(
        &self,
        target: &[BlockRef<D>],
        common: &[BlockRef<D>],
    ) -> Result<(), Error> {
        same_chains(&self.emitted, target)?;
        same_chains(&self.emitted, common)?;
        for (((emitted, ordered), target), common) in self
            .emitted
            .references()
            .iter()
            .zip(self.ordered.references())
            .zip(target)
            .zip(common)
        {
            if emitted.height() == target.height() && emitted != target {
                return Err(Error::Conflict);
            }
            let valid = if target.height() <= emitted.height() {
                common == target
            } else {
                common == emitted || (emitted == ordered && common.height() == emitted.height())
            };
            if !valid {
                return Err(Error::Conflict);
            }
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            order::{
                SlotStream,
                fuzz::{coordinate, frontier, reference},
            },
            types::ChainId,
        },
        types::Height,
    };
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};

    fn resolve(slot: Slot<Sha256Digest>) -> BlockRef<Sha256Digest> {
        let (chain, height) = coordinate(slot);
        reference(chain, height)
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
        let slot = Slot::new(conflict, conflict.height());
        assert_eq!(state.reconcile(slot, conflict), Err(Error::Conflict));
    }

    #[test]
    fn reconciliation_accepts_an_anchor_jump_only_from_an_unextended_ordered_tip() {
        let history = Sha256::hash(&[b"jump history"]);
        let rival = |height: u64| {
            BlockRef::new(
                ChainId::new(0),
                Height::new(height),
                Sha256::hash(&[b"rival", &height.to_be_bytes()]),
            )
        };
        // Chain 0's target sits on a rival branch whose block at height 2 is not the emitted tip.
        let target = vec![rival(3), reference(1, 1)];
        let common = vec![rival(2), reference(1, 1)];

        // Nothing was emitted past the ordered tip, so the rival path supplies every new block.
        let ordered = frontier(&[2, 1]);
        HistoryState::new(history, ordered.clone(), ordered)
            .unwrap()
            .validate_reconciliation(&target, &common)
            .unwrap();

        // A final sweep emitted height 2 past the ordered tip, and a target must keep it.
        let swept = HistoryState::new(history, frontier(&[1, 1]), frontier(&[2, 1])).unwrap();
        assert_eq!(
            swept.validate_reconciliation(&target, &common),
            Err(Error::Conflict)
        );

        // A resolved ancestor must sit at the emitted height.
        let state = HistoryState::new(history, frontier(&[2, 1]), frontier(&[2, 1])).unwrap();
        assert_eq!(
            state.validate_reconciliation(&target, &[rival(1), reference(1, 1)]),
            Err(Error::Conflict)
        );
        // A target below the emitted tip must be the emitted tip's ancestor.
        let ahead = HistoryState::new(history, frontier(&[1, 1]), frontier(&[3, 1])).unwrap();
        assert_eq!(
            ahead.validate_reconciliation(
                &[rival(2), reference(1, 1)],
                &[reference(0, 2), reference(1, 1)]
            ),
            Err(Error::Conflict)
        );
    }
}
