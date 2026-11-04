//! Leader history records, each reported once.
//!
//! A leader block commits to the safe-tip opening of its parent V-QC. The opening is
//! reconstructible only while that parent is retained as a proposal parent, so every source that
//! learns of a leader (its own admission, its finality, or a certificate for it) offers the leader
//! here, and the record is reported the first time the leader and its parent are both known.
//!
//! # Exactly once
//!
//! Above the report floor (the finality retention floor), reported leaders are remembered by view
//! and digest. Below it, a leader can only be reported again through its retained parent, so the
//! marker moves onto that parent and is dropped with it; these markers are bounded by the parents
//! retirement keeps. A leader is reported twice only if its parent is retired, retained again
//! from a fresh copy of its V-QC, and the leader, already below the report floor, is offered
//! again. A restarted engine starts with no markers and may report a leader once more.
//!
//! # Late parents
//!
//! A leader offered before its parent is retained waits, keyed by the parent, and is reported
//! when the parent is retained. A leader whose parent is not retained before the leader falls to
//! the report floor is never reported.

use crate::{
    Viewable as _,
    multimmit::{
        machine::util::drain_prefix,
        scheme::Scheme,
        types::{CertificateId, LeaderBlock, TipRecord},
    },
    types::View,
};
use commonware_cryptography::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A leader block whose safe-tip history opening may be reported.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaderHistory<D: Digest> {
    /// The view of the leader block.
    pub(crate) view: View,
    /// The digest of the unsigned leader block.
    pub(crate) leader: D,
    /// The V-QC the leader block builds on.
    pub(crate) parent: CertificateId<D>,
    /// The history commitment the leader block carries.
    pub(crate) history: D,
}

impl<D: Digest> LeaderHistory<D> {
    /// Describes `block`, whose digest is `leader`.
    pub(crate) fn new<S: Scheme>(block: &LeaderBlock<S, D>, leader: D) -> Self {
        Self {
            view: block.view(),
            leader,
            parent: block.parent(),
            history: block.history(),
        }
    }

    const fn key(&self) -> (View, D) {
        (self.view, self.leader)
    }
}

/// A reconstructed history record not yet handed to the reporter.
pub(crate) type HistoryRecord<D> = (LeaderHistory<D>, Arc<TipRecord<D>>);

/// Which leaders were reported, which wait on their parent, and the records not yet drained.
pub(super) struct HistoryReports<D: Digest> {
    /// Leaders at or below this view are no longer remembered by view.
    floor: View,
    /// Reported leaders above the floor, with the parent each was reconstructed from.
    reported: BTreeMap<(View, D), CertificateId<D>>,
    /// Reported leaders at or below the floor, by the retained parent they name.
    ///
    /// Entries are dropped with their parent, which no other leader can be reconstructed from.
    retired: BTreeMap<CertificateId<D>, Vec<(View, D)>>,
    /// Leaders above the floor whose parent is not retained, by that parent.
    awaiting: BTreeMap<CertificateId<D>, Vec<LeaderHistory<D>>>,
    /// The view and parent of every awaiting leader, so the floor visits only what it retires.
    awaiting_views: BTreeSet<(View, CertificateId<D>)>,
    /// Records reconstructed since the last drain.
    pending: Vec<HistoryRecord<D>>,
}

impl<D: Digest> Default for HistoryReports<D> {
    fn default() -> Self {
        Self {
            floor: View::zero(),
            reported: BTreeMap::new(),
            retired: BTreeMap::new(),
            awaiting: BTreeMap::new(),
            awaiting_views: BTreeSet::new(),
            pending: Vec::new(),
        }
    }
}

impl<D: Digest> HistoryReports<D> {
    /// Returns whether `source` was already reported.
    pub(super) fn reported(&self, source: &LeaderHistory<D>) -> bool {
        if source.view > self.floor {
            self.reported.contains_key(&source.key())
        } else {
            self.retired
                .get(&source.parent)
                .is_some_and(|reported| reported.contains(&source.key()))
        }
    }

    /// Queues the record of `source`, which was not reported, and marks it reported.
    pub(super) fn record(&mut self, source: LeaderHistory<D>, record: Arc<TipRecord<D>>) {
        if source.view > self.floor {
            self.reported.insert(source.key(), source.parent);
        } else {
            self.retired
                .entry(source.parent)
                .or_default()
                .push(source.key());
        }
        self.pending.push((source, record));
    }

    /// Parks `source` until its parent is retained, unless it is already at the floor.
    pub(super) fn await_parent(&mut self, source: LeaderHistory<D>) {
        if source.view <= self.floor {
            return;
        }
        let awaiting = self.awaiting.entry(source.parent).or_default();
        if awaiting.contains(&source) {
            return;
        }
        awaiting.push(source);
        self.awaiting_views.insert((source.view, source.parent));
    }

    /// Takes the leaders that waited on `parent`.
    pub(super) fn take_awaiting(&mut self, parent: &CertificateId<D>) -> Vec<LeaderHistory<D>> {
        let awaiting = self.awaiting.remove(parent).unwrap_or_default();
        for source in &awaiting {
            self.awaiting_views.remove(&(source.view, source.parent));
        }
        awaiting
    }

    /// Forgets the markers of leaders that name a retired parent.
    pub(super) fn retire_parents(&mut self, retired: &[CertificateId<D>]) {
        for parent in retired {
            self.retired.remove(parent);
        }
    }

    /// Raises the floor to `floor`, moving the markers it passes onto the parents for which
    /// `retained` holds and dropping the leaders still waiting on their parent.
    pub(super) fn retire_through(
        &mut self,
        floor: View,
        retained: impl Fn(&CertificateId<D>) -> bool,
    ) {
        if floor <= self.floor {
            return;
        }
        self.floor = floor;
        for (key, parent) in drain_prefix(&mut self.reported, |(view, _)| *view <= floor) {
            if retained(&parent) {
                self.retired.entry(parent).or_default().push(key);
            }
        }
        while let Some((view, parent)) = self.awaiting_views.first().copied() {
            if view > floor {
                break;
            }
            self.awaiting_views.pop_first();
            if let Some(awaiting) = self.awaiting.get_mut(&parent) {
                awaiting.retain(|source| source.view > floor);
                if awaiting.is_empty() {
                    self.awaiting.remove(&parent);
                }
            }
        }
    }

    /// Takes the records reconstructed since the last drain.
    pub(super) fn take_pending(&mut self) -> Vec<HistoryRecord<D>> {
        core::mem::take(&mut self.pending)
    }

    /// Drops the records not yet drained, so a later offer of the same leaders reports them.
    pub(super) fn discard_pending(&mut self) {
        for (source, _) in core::mem::take(&mut self.pending) {
            if self.reported.remove(&source.key()).is_some() {
                continue;
            }
            if let Some(reported) = self.retired.get_mut(&source.parent) {
                reported.retain(|key| *key != source.key());
                if reported.is_empty() {
                    self.retired.remove(&source.parent);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{BlockRef, ChainId},
        types::Height,
    };
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    fn digest(marker: u8) -> Sha256Digest {
        Sha256::hash(&[&[marker]])
    }

    fn source(view: u64, leader: u8, parent: u8) -> LeaderHistory<Sha256Digest> {
        LeaderHistory {
            view: View::new(view),
            leader: digest(leader),
            parent: CertificateId::new(digest(parent)),
            history: digest(0),
        }
    }

    fn record() -> Arc<TipRecord<Sha256Digest>> {
        Arc::new(
            TipRecord::new(
                digest(0),
                vec![BlockRef::new(ChainId::new(0), Height::zero(), digest(0))],
                vec![Height::zero()],
            )
            .unwrap(),
        )
    }

    #[test]
    fn markers_follow_their_retained_parent_below_the_floor() {
        let mut reports = HistoryReports::default();
        let kept = source(2, 1, 1);
        let dropped = source(2, 2, 2);
        for source in [kept, dropped] {
            assert!(!reports.reported(&source));
            reports.record(source, record());
        }
        assert_eq!(reports.take_pending().len(), 2);

        // Only the first parent survives the floor, so only its child stays remembered.
        let retained = kept.parent;
        reports.retire_through(View::new(2), |parent| *parent == retained);
        assert!(reports.reported.is_empty());
        assert!(reports.reported(&kept));
        assert!(!reports.reported(&dropped));

        reports.retire_parents(&[retained]);
        assert!(!reports.reported(&kept));
        assert!(reports.retired.is_empty());
    }

    #[test]
    fn awaiting_leaders_are_bounded_by_the_floor() {
        let mut reports = HistoryReports::default();
        let early = source(2, 1, 1);
        let late = source(3, 2, 1);
        reports.await_parent(early);
        reports.await_parent(early);
        reports.await_parent(late);
        reports.retire_through(View::new(2), |_| false);
        // A leader at or below the floor is no longer awaited, nor parked anew.
        reports.await_parent(early);
        assert_eq!(reports.take_awaiting(&early.parent), [late]);
        assert!(reports.awaiting.is_empty());
        assert!(reports.awaiting_views.is_empty());
    }

    #[test]
    fn discarded_records_leave_their_leaders_unreported() {
        let mut reports = HistoryReports::default();
        let above = source(3, 1, 1);
        let below = source(1, 2, 1);
        reports.retire_through(View::new(2), |_| true);
        for source in [above, below] {
            reports.record(source, record());
            assert!(reports.reported(&source));
        }
        reports.discard_pending();
        assert!(!reports.reported(&above));
        assert!(!reports.reported(&below));
        assert!(reports.reported.is_empty());
        assert!(reports.retired.is_empty());
        assert!(reports.take_pending().is_empty());
    }
}
