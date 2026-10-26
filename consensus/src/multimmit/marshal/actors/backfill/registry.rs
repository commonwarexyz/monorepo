//! Registered backfill waiters, grouped by key, and the policy that admits new ones.

use super::waiter::{BackfillSubscriber, BlockMode, Resolved, Target, Waiter};
use crate::multimmit::{
    marshal::{actors::metrics::FetchReason, wire::BackfillKey},
    types::{BlockRef, Body},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, num::NonZeroU16};

/// A waiter taken out of the registry.
pub(super) struct Removed<H: Hasher, V: Variant, B: Body<H>> {
    pub key: BackfillKey<H::Digest>,
    pub waiter: Waiter<H, V, B>,
    /// Whether the key has no waiters left.
    pub emptied: bool,
}

/// The outcome of [`Registry::make_room`].
pub(super) struct Eviction<H: Hasher, V: Variant, B: Body<H>> {
    /// Waiters removed to make room.
    pub evicted: Vec<Removed<H, V, B>>,
    /// Whether one more waiter now fits.
    pub room: bool,
}

/// Returns whether a request for `reason` may evict another waiter when the registry is full.
///
/// Synchronization concurrency is bounded by the registry, so finality, finalized-body,
/// state-sync and DA-certified requests evict the oldest waiter instead of being rejected.
const fn preempts(reason: FetchReason) -> bool {
    matches!(
        reason,
        FetchReason::Finality
            | FetchReason::FinalizedBody
            | FetchReason::StateSync
            | FetchReason::Certified
    )
}

/// The waiters of each key, oldest first.
type Waiters<H, V, B> = BTreeMap<BackfillKey<<H as Hasher>::Digest>, Vec<Waiter<H, V, B>>>;

/// Every live waiter, grouped by the key it waits on, bounded by `max`.
pub(super) struct Registry<H: Hasher, V: Variant, B: Body<H>> {
    waiters: Waiters<H, V, B>,
    len: usize,
    next: BackfillSubscriber,
    max: usize,
}

impl<H: Hasher, V: Variant, B: Body<H>> Registry<H, V, B> {
    pub(super) fn new(max: usize) -> Self {
        Self {
            waiters: BTreeMap::new(),
            len: 0,
            next: BackfillSubscriber::default(),
            max,
        }
    }

    /// Returns the number of waiters.
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Returns the maximum number of waiters.
    pub(super) const fn capacity(&self) -> usize {
        self.max
    }

    /// Returns whether the registry holds `max` waiters.
    pub(super) const fn is_full(&self) -> bool {
        self.len >= self.max
    }

    /// Returns whether any waiter waits on `key`.
    pub(super) fn contains(&self, key: &BackfillKey<H::Digest>) -> bool {
        self.waiters.contains_key(key)
    }

    /// Returns the waiters of `key`, oldest first.
    pub(super) fn waiters(
        &self,
        key: &BackfillKey<H::Digest>,
    ) -> impl Iterator<Item = &Waiter<H, V, B>> {
        self.waiters.get(key).into_iter().flatten()
    }

    /// Returns the waiters of `key` for update, oldest first.
    pub(super) fn waiters_mut(
        &mut self,
        key: &BackfillKey<H::Digest>,
    ) -> impl Iterator<Item = &mut Waiter<H, V, B>> {
        self.waiters.get_mut(key).into_iter().flatten()
    }

    /// Returns the waited-on range keys whose newest block is `head`.
    pub(super) fn ranges_from(
        &self,
        head: BlockRef<H::Digest>,
    ) -> impl Iterator<Item = BackfillKey<H::Digest>> + '_ {
        let low = BackfillKey::producer_blocks(head, NonZeroU16::MIN);
        let high = BackfillKey::producer_blocks(head, NonZeroU16::MAX);
        self.waiters.range(low..=high).map(|(key, _)| *key)
    }

    /// Allocates the identity of the next waiter.
    pub(super) const fn allocate(&mut self) -> BackfillSubscriber {
        let id = self.next;
        self.next = id.next();
        id
    }

    /// Adds `waiter` under `key`.
    pub(super) fn insert(&mut self, key: BackfillKey<H::Digest>, waiter: Waiter<H, V, B>) {
        self.waiters.entry(key).or_default().push(waiter);
        self.len += 1;
    }

    /// Removes the waiter `id` of `key`.
    pub(super) fn remove(
        &mut self,
        key: &BackfillKey<H::Digest>,
        id: BackfillSubscriber,
    ) -> Option<Removed<H, V, B>> {
        self.take(key, |waiter| waiter.id == id).pop()
    }

    /// Returns whether a DA-certificate marker holds block `reference`.
    pub(super) fn has_marker(
        &self,
        key: &BackfillKey<H::Digest>,
        reference: &BlockRef<H::Digest>,
    ) -> bool {
        self.waiters(key)
            .any(|waiter| is_marker_for(waiter, reference))
    }

    /// Replaces the DA-certificate marker for block `reference` with `waiter`.
    pub(super) fn replace_marker(
        &mut self,
        key: &BackfillKey<H::Digest>,
        reference: &BlockRef<H::Digest>,
        waiter: Waiter<H, V, B>,
    ) {
        let marker = self
            .waiters_mut(key)
            .find(|waiter| is_marker_for(waiter, reference))
            .expect("a replaced marker is registered");
        *marker = waiter;
    }

    /// Removes the waiters of `key` that accept `resolved`.
    pub(super) fn take_accepting(&mut self, resolved: &Resolved<H, V, B>) -> Vec<Removed<H, V, B>> {
        self.take(&resolved.key(), |waiter| waiter.target.accepts(resolved))
    }

    /// Removes every waiter matching `predicate`.
    pub(super) fn remove_where(
        &mut self,
        predicate: impl Fn(&Waiter<H, V, B>) -> bool,
    ) -> Vec<Removed<H, V, B>> {
        let keys = self
            .waiters
            .iter()
            .filter(|(_, waiters)| waiters.iter().any(&predicate))
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        keys.iter()
            .flat_map(|key| self.take(key, |waiter| predicate(waiter)))
            .collect()
    }

    /// Makes room for one more waiter for `target`, registered for `reason`.
    ///
    /// When the registry is full, in order: drop the waiters whose callers are done; unless the
    /// new waiter is itself a DA-certificate marker, evict the oldest marker; if `reason`
    /// preempts, evict the oldest waiter so finality and state-sync fetches are never rejected.
    pub(super) fn make_room(
        &mut self,
        target: &Target<H::Digest>,
        reason: FetchReason,
    ) -> Eviction<H, V, B> {
        let mut evicted = Vec::new();
        if self.is_full() {
            evicted = self.remove_where(Waiter::is_closed);
        }
        if self.is_full() && !target.is_marker() {
            evicted.extend(self.remove_oldest(Waiter::is_marker));
        }
        if self.is_full() && preempts(reason) {
            evicted.extend(self.remove_oldest(|_| true));
        }
        Eviction {
            evicted,
            room: !self.is_full(),
        }
    }

    /// Removes the oldest waiter matching `predicate`.
    fn remove_oldest(
        &mut self,
        predicate: impl Fn(&Waiter<H, V, B>) -> bool,
    ) -> Option<Removed<H, V, B>> {
        let (key, id) = self
            .waiters
            .iter()
            .flat_map(|(key, waiters)| waiters.iter().map(move |waiter| (key, waiter)))
            .filter(|(_, waiter)| predicate(waiter))
            .min_by_key(|(_, waiter)| waiter.id)
            .map(|(key, waiter)| (*key, waiter.id))?;
        self.remove(&key, id)
    }

    /// Removes the waiters of `key` matching `predicate`.
    fn take(
        &mut self,
        key: &BackfillKey<H::Digest>,
        predicate: impl FnMut(&mut Waiter<H, V, B>) -> bool,
    ) -> Vec<Removed<H, V, B>> {
        let Some(waiters) = self.waiters.get_mut(key) else {
            return Vec::new();
        };
        let taken = waiters.extract_if(.., predicate).collect::<Vec<_>>();
        let emptied = waiters.is_empty();
        if emptied {
            self.waiters.remove(key);
        }
        self.len -= taken.len();
        let last = taken.len().saturating_sub(1);
        taken
            .into_iter()
            .enumerate()
            .map(|(index, waiter)| Removed {
                key: *key,
                waiter,
                emptied: emptied && index == last,
            })
            .collect()
    }
}

/// Returns whether `waiter` is the DA-certificate marker for block `reference`.
fn is_marker_for<H: Hasher, V: Variant, B: Body<H>>(
    waiter: &Waiter<H, V, B>,
    reference: &BlockRef<H::Digest>,
) -> bool {
    matches!(
        &waiter.target,
        Target::Block { reference: expected, mode: BlockMode::Certified } if expected == reference
    )
}
