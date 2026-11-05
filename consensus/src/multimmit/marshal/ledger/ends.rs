//! Ends: where the order each L-QC proves ends, and closing them as floors.
//!
//! An L-QC's order ends at the cut its leader's record opens plus its final sweep. When delivery
//! reaches that end exactly, a cut entry records it as a floor. This machine owns that
//! bookkeeping and does no I/O: the ledger hands it a read-only [`View`] and applies what it
//! returns (facts to read or derive, cut entries to write).
//!
//! Its states, per L-QC at a connected ordinal:
//!
//! - **pending**: its ordinal is opened but its end is unknown, because its fact is still being
//!   read or derived. The order opens no record past the lowest pending ordinal
//!   ([`Ends::projected_through`]): an L-QC ends at or after the cut its history opens, so
//!   delivery never passes an end before it is known.
//! - **waiting**: its end is known and lies ahead of delivery; [`Ends::reached`] closes it when
//!   delivery stands exactly there.
//! - **known**: its end is projected (waiting, closed, or passed); it is never projected again.

use super::{End, order::Order};
use crate::multimmit::{
    marshal::store::proofs::{CutEntry, Index},
    order::{FinalSweep, SweepFact},
    types::{BlockRef, CertificateId},
};
use commonware_cryptography::Digest;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

/// What [`Ends`] reads.
pub(super) struct View<'a, D: Digest> {
    pub(super) index: &'a Index<D>,
    pub(super) order: &'a Order<D>,
    pub(super) facts: &'a HashMap<CertificateId<D>, Arc<SweepFact<D>>>,
    /// The exact last delivered block of every chain.
    pub(super) delivered: &'a [BlockRef<D>],
}

impl<D: Digest> View<'_, D> {
    /// Returns the output index delivery stands at.
    fn delivered_index(&self) -> u64 {
        self.delivered
            .iter()
            .map(|block| block.height().get())
            .sum()
    }

    /// Returns whether delivery stands exactly at the emitted heights `emitted`.
    fn stands_at(&self, emitted: &[crate::types::Height]) -> bool {
        emitted
            .iter()
            .zip(self.delivered)
            .all(|(height, block)| *height == block.height())
    }
}

/// A cut entry to write: the end of an L-QC whose leader history is `history`.
pub(super) struct Closed<D: Digest> {
    pub(super) history: D,
    pub(super) entry: CutEntry<D>,
}

/// The outcome of projecting one end.
enum Projected<D: Digest> {
    /// Nothing is left to project: the end is known (with a cut entry to write when delivery
    /// stands at it), or it can never be.
    Settled(Option<Closed<D>>),
    /// The L-QC's fact is not in memory yet.
    NeedsFact,
}

/// The ends of the L-QCs at opened ordinals.
pub(super) struct Ends<D: Digest> {
    /// The next ordinal whose L-QCs are queued once the order opens it.
    next: u64,
    /// L-QCs whose end is unknown, by their history's ordinal.
    pending: BTreeMap<u64, Vec<CertificateId<D>>>,
    /// Projected ends ahead of delivery, by output index.
    waiting: BTreeMap<u64, Vec<End<D>>>,
    /// L-QCs whose end is projected.
    known: HashSet<CertificateId<D>>,
}

impl<D: Digest> Ends<D> {
    /// Starts with the order opened through `ordinal`.
    pub(super) fn new(ordinal: u64) -> Self {
        Self {
            next: ordinal,
            pending: BTreeMap::new(),
            waiting: BTreeMap::new(),
            known: HashSet::new(),
        }
    }

    /// Restarts at `ordinal` after the order restarted there (a floor install).
    pub(super) fn reset(&mut self, ordinal: u64) {
        self.next = ordinal;
        self.pending.clear();
    }

    /// Returns whether the end of every L-QC at or below `ordinal` is known.
    pub(super) fn projected_through(&self, ordinal: u64) -> bool {
        ordinal < self.next && self.pending.range(..=ordinal).next().is_none()
    }

    /// Queues the newly indexed L-QCs whose ordinal the order already opened; the others are
    /// queued when the order opens theirs.
    pub(super) fn indexed(&mut self, lqcs: &[CertificateId<D>], index: &Index<D>) {
        for id in lqcs {
            let Some(ordinal) = index
                .lqc(id)
                .and_then(|entry| index.ordinal(&entry.history))
            else {
                continue;
            };
            if ordinal < self.next && !self.known.contains(id) {
                self.pending.entry(ordinal).or_default().push(*id);
            }
        }
    }

    /// Queues the L-QCs of every ordinal the order opened since the last call, then projects
    /// every pending end it can.
    ///
    /// Returns the pending L-QCs whose fact is missing (the ledger reads or derives it; an
    /// attempt already in flight is not repeated) and the ends delivery already stands at.
    pub(super) fn settle(&mut self, view: &View<'_, D>) -> (Vec<CertificateId<D>>, Vec<Closed<D>>) {
        let queued = view.order.queued();
        while self.next <= queued {
            let ordinal = self.next;
            self.next += 1;
            let ids = view
                .index
                .connected_at(ordinal)
                .iter()
                .filter(|id| !self.known.contains(id))
                .copied()
                .collect::<Vec<_>>();
            if !ids.is_empty() {
                self.pending.entry(ordinal).or_default().extend(ids);
            }
        }
        let mut missing = Vec::new();
        let mut closed = Vec::new();
        let mut pending = std::mem::take(&mut self.pending);
        pending.retain(|_, ids| {
            ids.retain(|id| match self.project(*id, view) {
                Projected::Settled(close) => {
                    closed.extend(close);
                    false
                }
                Projected::NeedsFact => {
                    missing.push(*id);
                    true
                }
            });
            !ids.is_empty()
        });
        self.pending = pending;
        (missing, closed)
    }

    /// Projects where L-QC `id` ends: the cut after its leader's record plus its sweep.
    fn project(&mut self, id: CertificateId<D>, view: &View<'_, D>) -> Projected<D> {
        if self.known.contains(&id) {
            return Projected::Settled(None);
        }
        // An L-QC dropped, not opened here, or whose sweep does not fit the cut never ends here.
        let Some(entry) = view.index.lqc(&id) else {
            return Projected::Settled(None);
        };
        let Some(ordinal) = view.index.ordinal(&entry.history) else {
            return Projected::Settled(None);
        };
        let Some(cut) = view.order.opened(ordinal) else {
            return Projected::Settled(None);
        };
        let Some(fact) = view.facts.get(&id) else {
            return Projected::NeedsFact;
        };
        let Ok(through) = cut.sweep(fact) else {
            return Projected::Settled(None);
        };
        // The order's starting cut is where delivery resumed, not the cut its record opens: a
        // sweep that does not pass it may end before it, and ends exactly there only if every
        // chain stands at the sweep's own height or at the record's tip.
        let exact = ordinal != view.order.start()
            || through.index() > cut.index()
            || FinalSweep::placed(cut.ordered(), fact.tips(), fact.proposed(), fact.settled())
                .is_ok_and(|placed| {
                    placed.iter().zip(cut.ordered()).zip(cut.emitted()).all(
                        |((placed, tip), emitted)| placed == emitted || tip.height() == *emitted,
                    )
                });
        self.known.insert(id);
        if through.index() > view.delivered_index() {
            self.waiting.entry(through.index()).or_default().push((
                id,
                entry.history,
                through.emitted().to_vec(),
            ));
            return Projected::Settled(None);
        }
        // The order already stands at this end (a restart resumed at it): close it now.
        let close = (through.index() == view.delivered_index()
            && view.stands_at(through.emitted())
            && exact
            && view.index.cut_of(&id).is_none())
        .then(|| Closed {
            history: entry.history,
            entry: CutEntry {
                lqc: id,
                boundary: view.delivered.to_vec(),
            },
        });
        Projected::Settled(close)
    }

    /// Returns the cut entries of the ends delivery just reached at output `index`, and forgets
    /// the ends it passed.
    pub(super) fn reached(&mut self, index: u64, view: &View<'_, D>) -> Vec<Closed<D>> {
        let ends = self.waiting.remove(&index).unwrap_or_default();
        // Ends already passed can no longer be closed.
        self.waiting = self.waiting.split_off(&index);
        ends.into_iter()
            .filter(|(lqc, _, emitted)| view.stands_at(emitted) && view.index.cut_of(lqc).is_none())
            .map(|(lqc, history, _)| Closed {
                history,
                entry: CutEntry {
                    lqc,
                    boundary: view.delivered.to_vec(),
                },
            })
            .collect()
    }

    /// Forgets the L-QCs `keep` rejects and the ends at or below output `delivered`.
    pub(super) fn trim(&mut self, keep: impl Fn(&CertificateId<D>) -> bool, delivered: u64) {
        self.known.retain(|id| keep(id));
        self.waiting = self.waiting.split_off(&delivered.saturating_add(1));
    }
}
