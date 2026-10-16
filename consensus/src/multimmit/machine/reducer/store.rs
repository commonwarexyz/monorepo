//! The retained artifact store and the indexes admission and retirement keep over it.

use crate::{
    multimmit::{
        machine::{
            input::Now,
            resolution::RetrievalKey,
            util::{drain_prefix, remove_indexed},
            verification::{Observation, VerificationTicket},
        },
        types::{Artifact, ArtifactId, VoteContent},
    },
    types::{Attributable as _, Participant, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    sync::Arc,
};

/// Admission progress of one retained peer artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactState<D: Digest> {
    /// Held unauthenticated until an artifact this key names is read: a vote update whose signed
    /// content extends an earlier update of its sender that this node has not read.
    Parked(RetrievalKey<D>),
    /// Awaiting the verdict for this ticket.
    Pending(VerificationTicket<D>),
    /// Authenticated, and waiting for the artifact this key names.
    Waiting(RetrievalKey<D>),
    /// Authenticated with every dependency held, and handed to its protocol component.
    Ready,
}

/// One retained peer artifact.
#[derive(Clone, Debug)]
pub(crate) struct ArtifactEntry<V: Variant, D: Digest> {
    /// The artifact.
    pub(crate) artifact: Arc<Artifact<V, D>>,
    /// The keys this artifact provides to waiters once ready.
    pub(crate) provisions: Arc<[RetrievalKey<D>]>,
    /// The earliest observation of this artifact, which orders it against its peers.
    pub(crate) observation: Observation,
    /// When the earliest observation's network message arrived at this node, or the clock
    /// reading of its admission when that is earlier or unknown.
    pub(crate) received: Now,
    /// The signed content a vote update was rebuilt to, which its verification covered.
    pub(crate) content: Option<Arc<VoteContent<D>>>,
    /// The artifact's admission progress.
    pub(crate) state: ArtifactState<D>,
}

/// Retained peer artifacts with the indexes admission and retirement keep over them.
///
/// Every entry counts against the artifact cache together with durable occupancy. View-scoped
/// entries are indexed by view so retirement visits only the views it retires, and entries above
/// the current view are indexed separately against the future-artifact bound. Vote updates not
/// yet handed to the pool are counted per sender against the pending-update bound.
pub(crate) struct ArtifactStore<V: Variant, D: Digest> {
    artifacts: BTreeMap<ArtifactId<D>, ArtifactEntry<V, D>>,
    by_view: BTreeMap<View, BTreeSet<ArtifactId<D>>>,
    future: BTreeSet<(View, ArtifactId<D>)>,
    /// Parked and waiting entries by the key they wait for.
    waiters: BTreeMap<RetrievalKey<D>, BTreeSet<ArtifactId<D>>>,
    /// Authenticated entries waiting on a dependency.
    waiting: usize,
    /// Vote updates parked until an earlier update of their sender is read.
    parked: usize,
    /// Per sender, the vote updates not yet handed to the pool.
    pending_updates: BTreeMap<Participant, usize>,
    /// The input cohort the next observation belongs to.
    pub(in crate::multimmit::machine) next_cohort: u64,
}

impl<V: Variant, D: Digest> ArtifactStore<V, D> {
    pub(super) const fn new() -> Self {
        Self {
            artifacts: BTreeMap::new(),
            by_view: BTreeMap::new(),
            future: BTreeSet::new(),
            waiters: BTreeMap::new(),
            waiting: 0,
            parked: 0,
            pending_updates: BTreeMap::new(),
            next_cohort: 0,
        }
    }

    /// Returns the number of retained entries.
    pub(crate) fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Returns the number of entries above the current view.
    pub(crate) fn future_len(&self) -> usize {
        self.future.len()
    }

    /// Returns the number of authenticated entries waiting on a dependency.
    pub(crate) const fn waiting_len(&self) -> usize {
        self.waiting
    }

    /// Returns the number of vote updates parked until an earlier update of their sender is read.
    pub(crate) const fn parked_len(&self) -> usize {
        self.parked
    }

    /// Returns the number of `sender`'s vote updates retained and not yet handed to the pool.
    pub(crate) fn pending_updates(&self, sender: Participant) -> usize {
        self.pending_updates.get(&sender).copied().unwrap_or(0)
    }

    /// Returns the entry retained under `id`.
    pub(crate) fn get(&self, id: &ArtifactId<D>) -> Option<&ArtifactEntry<V, D>> {
        self.artifacts.get(id)
    }

    /// Returns every retained entry in identifier order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ArtifactId<D>, &ArtifactEntry<V, D>)> {
        self.artifacts.iter()
    }

    /// Retains `entry` under `id`, indexed as future while its view is above `current`.
    pub(super) fn insert(&mut self, id: ArtifactId<D>, entry: ArtifactEntry<V, D>, current: View) {
        if let Some(view) = entry.artifact.view() {
            self.by_view.entry(view).or_default().insert(id);
            if view > current {
                self.future.insert((view, id));
            }
        }
        if entry.state != ArtifactState::Ready {
            self.count_update(&entry.artifact, true);
        }
        self.index_state(id, &entry.state);
        self.artifacts.insert(id, entry);
    }

    /// Removes the entry retained under `id` and every index that names it.
    pub(in crate::multimmit::machine) fn remove(
        &mut self,
        id: &ArtifactId<D>,
    ) -> Option<ArtifactEntry<V, D>> {
        let entry = self.artifacts.remove(id)?;
        self.unindex(id, &entry);
        if let Some(view) = entry.artifact.view() {
            remove_indexed(&mut self.by_view, &view, id);
        }
        Some(entry)
    }

    /// Drops the future and waiter indexes of the removed `entry`.
    fn unindex(&mut self, id: &ArtifactId<D>, entry: &ArtifactEntry<V, D>) {
        if let Some(view) = entry.artifact.view() {
            self.future.remove(&(view, *id));
        }
        if entry.state != ArtifactState::Ready {
            self.count_update(&entry.artifact, false);
        }
        self.unindex_state(id, &entry.state);
    }

    /// Moves the entry `id` to `state`, keeping the waiter index in step.
    pub(super) fn set_state(&mut self, id: &ArtifactId<D>, state: ArtifactState<D>) {
        let Some(entry) = self.artifacts.get_mut(id) else {
            return;
        };
        let previous = core::mem::replace(&mut entry.state, state.clone());
        let artifact = Arc::clone(&entry.artifact);
        if previous != ArtifactState::Ready && state == ArtifactState::Ready {
            self.count_update(&artifact, false);
        }
        self.unindex_state(id, &previous);
        self.index_state(*id, &state);
    }

    /// Moves the parked entry `id` to verification under `ticket`, covering a vote update's
    /// rebuilt `content`.
    pub(super) fn unpark(
        &mut self,
        id: &ArtifactId<D>,
        content: Option<Arc<VoteContent<D>>>,
        ticket: VerificationTicket<D>,
    ) {
        if let Some(entry) = self.artifacts.get_mut(id) {
            entry.content = content;
        }
        self.set_state(id, ArtifactState::Pending(ticket));
    }

    fn index_state(&mut self, id: ArtifactId<D>, state: &ArtifactState<D>) {
        let key = match state {
            ArtifactState::Waiting(key) => {
                self.waiting += 1;
                key
            }
            ArtifactState::Parked(key) => {
                self.parked += 1;
                key
            }
            ArtifactState::Pending(_) | ArtifactState::Ready => return,
        };
        self.waiters.entry(*key).or_default().insert(id);
    }

    fn unindex_state(&mut self, id: &ArtifactId<D>, state: &ArtifactState<D>) {
        let key = match state {
            ArtifactState::Waiting(key) => {
                self.waiting -= 1;
                key
            }
            ArtifactState::Parked(key) => {
                self.parked -= 1;
                key
            }
            ArtifactState::Pending(_) | ArtifactState::Ready => return,
        };
        remove_indexed(&mut self.waiters, key, id);
    }

    /// Counts a vote update entering (`added`) or leaving the sender's pending updates.
    fn count_update(&mut self, artifact: &Artifact<V, D>, added: bool) {
        let Artifact::Update(update) = artifact else {
            return;
        };
        let sender = update.signer();
        if added {
            *self.pending_updates.entry(sender).or_default() += 1;
        } else if let Some(count) = self.pending_updates.get_mut(&sender) {
            *count -= 1;
            if *count == 0 {
                self.pending_updates.remove(&sender);
            }
        }
    }

    /// Returns whether an entry waits on `key`.
    pub(crate) fn has_waiters(&self, key: &RetrievalKey<D>) -> bool {
        self.waiters.contains_key(key)
    }

    /// Returns every key an entry waits on, in key order.
    pub(super) fn waited_keys(&self) -> impl Iterator<Item = &RetrievalKey<D>> {
        self.waiters.keys()
    }

    /// Returns the entries waiting on `key`, in identifier order.
    pub(super) fn waiters(&self, key: &RetrievalKey<D>) -> Vec<ArtifactId<D>> {
        self.waiters
            .get(key)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the entries waiting on a key within `keys`, in key and identifier order.
    pub(super) fn waiters_within(
        &self,
        keys: RangeInclusive<RetrievalKey<D>>,
    ) -> Vec<ArtifactId<D>> {
        self.waiters
            .range(keys)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect()
    }

    /// Clears the future mark of every entry at or below `view`.
    pub(in crate::multimmit::machine) fn release_future_through(&mut self, view: View) {
        while self
            .future
            .first()
            .is_some_and(|(future, _)| *future <= view)
        {
            self.future.pop_first();
        }
    }

    /// Removes every view-scoped entry at or below `view`.
    pub(in crate::multimmit::machine) fn retire_through(&mut self, view: View) {
        let retired = drain_prefix(&mut self.by_view, |scoped| *scoped <= view)
            .flat_map(|(_, ids)| ids)
            .collect::<Vec<_>>();
        for id in &retired {
            if let Some(entry) = self.artifacts.remove(id) {
                self.unindex(id, &entry);
            }
        }
    }
}
