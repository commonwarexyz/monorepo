//! Fixed-capacity key-value caching with pluggable admission and eviction.
//!
//! [Cache] owns the resident hash index, keys, values, stable slots, and free
//! slots. A [Policy] owns only the metadata and transitions needed to record
//! hits, admit entries, and select victims. This keeps storage, full-key
//! validation, and value reuse consistent across policies without forcing one
//! metadata layout on every policy.
//!
//! A policy can use [Policy::SlotState] to co-locate hot metadata with each
//! cache slot. Any other metadata needed for admission or eviction remains
//! internal to the policy.
//!
//! # Stable Slots and Hints
//!
//! A resident keeps the same numeric slot until it is removed or evicted.
//! [Cache::get_at] uses that slot as a lookup hint and validates both liveness
//! and the full key before returning a value. A stale hint therefore becomes a
//! miss when its slot is freed or reused for another key. Callers can fall back
//! to [Cache::get] without maintaining the hint on every eviction.
//!
//! Stable slots also give policies durable integer identities for queue links
//! and dense indexes. They do not pin an entry forever. Once an entry leaves,
//! the cache can reuse its slot and value for another key.
//!
//! # Value Reuse
//!
//! Slots grow lazily to capacity and are then reused in place. [Cache::remove]
//! and [Cache::retain] detach residents while keeping their values available for
//! later insertion. [Cache::get_or_insert_mut] returns the selected slot and its
//! existing value so pooled buffers can be overwritten without reallocating.
//! [Cache::prefill] can allocate every value during construction, which removes
//! value allocation from steady-state insertion. Value-returning methods such
//! as [Cache::put] replace and drop displaced values as usual.
//!
//! The [clock] module provides [Clock], the default replacement policy.
//!
//! # Concurrency
//!
//! [Cache] performs no internal locking. Shared lookups record use through
//! [Policy::hit], whose contract permits concurrent calls through shared
//! references. Mutating operations, including insertion after a miss, require
//! `&mut self`. A cache can therefore be wrapped in a reader-writer lock and
//! queried concurrently on the hit path:
//!
//! ```
//! use commonware_utils::cache::Cache;
//! use core::num::NonZeroUsize;
//! use std::sync::RwLock;
//!
//! let cache = RwLock::new(Cache::<u64, u64>::new(NonZeroUsize::new(4).unwrap()));
//!
//! // Hit path: shared read lock, runs concurrently with other readers.
//! if cache.read().unwrap().get(&7).is_none() {
//!     // Miss path: exclusive write lock, computes and inserts the value once.
//!     cache.write().unwrap().get_or_insert_with(7, || 7 * 7);
//! }
//! assert_eq!(cache.read().unwrap().get(&7).copied(), Some(49));
//! ```
//!
//! # Example
//!
//! ```
//! use commonware_utils::cache::Cache;
//! use core::num::NonZeroUsize;
//!
//! let mut cache = Cache::<u64, u64>::new(NonZeroUsize::new(2).unwrap());
//!
//! // Compute an expensive value only on a miss.
//! let value = *cache.get_or_insert_with(1, || 1 * 1000);
//! assert_eq!(value, 1000);
//!
//! // A second lookup is served from the cache.
//! assert_eq!(cache.get(&1).copied(), Some(1000));
//! ```

pub mod clock;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
pub use clock::Clock;
use core::{hash::Hash, num::NonZeroUsize, ops::Index};
use hashbrown::HashMap;

type Hasher = ahash::RandomState;

/// Stable identifier for cache storage and policy metadata.
pub type Slot = usize;

/// Result of claiming storage for an incoming resident.
pub enum Claimed<K> {
    /// Vacant capacity was claimed at this slot.
    Vacant(Slot),
    /// The requested victim was claimed, yielding its owned key.
    Evicted(K),
}

/// Admission and eviction policy for a fixed-capacity [Cache].
///
/// A policy never owns resident keys or values. It identifies residents by
/// stable slot ID and owns only the metadata needed for admission and eviction.
///
/// Insertion runs as one exclusive transition. The policy selects either
/// vacant capacity or a victim, then invokes the cache-provided claim exactly
/// once. The claim returns the cache-selected vacant slot or transfers the
/// victim's owned key. The policy finishes its metadata transition and returns
/// the incoming resident's initial slot state.
pub trait Policy<K> {
    /// Policy state stored inline with each cache slot.
    ///
    /// A policy that needs no per-slot state may use `()`.
    type SlotState;

    /// Creates empty policy state for `capacity` residents.
    fn new(capacity: NonZeroUsize) -> Self;

    /// Records a hit for a validated resident slot.
    ///
    /// This method may be called concurrently through shared cache references.
    /// Mutable hit metadata must therefore use atomics or internal
    /// synchronization.
    fn hit(&self, slot: Slot, state: &Self::SlotState);

    /// Records a hit while the cache is exclusively borrowed.
    ///
    /// Unlike [Self::hit], this method may update policy metadata directly
    /// without synchronization.
    fn hit_mut(&mut self, slot: Slot, state: &mut Self::SlotState);

    /// Inserts `key` after a confirmed cache miss.
    ///
    /// `states` provides policy state indexed by [Slot]. `has_vacancy` reports
    /// whether unused capacity is available, though the policy may still choose
    /// a victim. The policy commits its choice by calling `claim` exactly once.
    /// Passing `None` claims unused capacity and returns its assigned slot.
    /// Passing `Some(slot)` replaces that slot and returns its previous key.
    /// The returned [Self::SlotState] becomes the incoming entry's initial
    /// policy state.
    fn insert<I, C>(&mut self, states: &I, key: &K, has_vacancy: bool, claim: C) -> Self::SlotState
    where
        I: Index<Slot, Output = Self::SlotState>,
        C: FnOnce(Option<Slot>) -> Claimed<K>;

    /// Forgets `key` and its policy state.
    ///
    /// `slot` identifies the key's previous slot when it was cached.
    fn remove(&mut self, slot: Option<Slot>, key: &K);

    /// Retains policy state only for keys accepted by `keep`.
    fn retain<F: FnMut(&K) -> bool>(&mut self, keep: F);

    /// Clears all policy-owned state.
    fn clear(&mut self);
}

/// A single cache slot.
///
/// A slot is live when its key is present in the index, and free otherwise.
/// Free slots keep their (now stale) `key` and `value` until the slot is reused,
/// with `live` cleared so [Cache::get_at] cannot resolve them.
struct Entry<K, V, M> {
    key: K,
    value: V,
    state: M,
    live: bool,
}

struct States<'a, K, V, S>(&'a [Entry<K, V, S>]);

impl<K, V, S> Index<Slot> for States<'_, K, V, S> {
    type Output = S;

    #[inline]
    fn index(&self, slot: Slot) -> &Self::Output {
        &self.0[slot].state
    }
}

/// A fixed-capacity key-value cache with pluggable admission and eviction.
///
/// The cache owns resident keys and values, stable slots, full-key hint
/// validation, and allocation reuse. `P` owns only policy metadata and
/// replacement decisions.
pub struct Cache<K, V, P = Clock>
where
    P: Policy<K>,
{
    /// Maps each live key to the index of its slot in `slots`.
    ///
    /// `index.len() + free.len() == slots.len()` always holds.
    index: HashMap<K, Slot, Hasher>,
    /// Backing storage for slots, grown lazily up to `capacity` and then reused.
    slots: Vec<Entry<K, V, P::SlotState>>,
    /// Slots detached from the index and available for reuse. Populated by
    /// [Self::remove] and [Self::retain]; eviction reuses its victim slot
    /// directly, so it never adds here.
    free: Vec<Slot>,
    /// Maximum number of resident entries.
    capacity: usize,
    /// Admission and eviction metadata.
    policy: P,
}

impl<K: Hash + Eq + Clone, V, P: Policy<K>> Cache<K, V, P> {
    /// Creates an empty cache with room for `capacity` residents.
    pub fn new(capacity: NonZeroUsize) -> Self {
        let policy = P::new(capacity);
        let capacity = capacity.get();
        Self {
            index: HashMap::with_capacity_and_hasher(capacity, Hasher::default()),
            slots: Vec::with_capacity(capacity),
            free: Vec::new(),
            capacity,
            policy,
        }
    }

    /// Returns the maximum number of entries the cache can hold.
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of entries currently in the cache.
    #[inline]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Returns `true` if the cache holds no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Returns `true` if `key` is in the cache without recording use.
    #[inline]
    pub fn contains(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    /// Returns a reference to the value for `key` without recording use.
    ///
    /// Unlike [Self::get], this does not notify the policy of a hit.
    #[inline]
    pub fn peek(&self, key: &K) -> Option<&V> {
        let &slot = self.index.get(key)?;
        Some(&self.slots[slot].value)
    }

    /// Returns a reference to the value for `key`, recording use.
    ///
    /// This takes `&self` so it can be called concurrently behind a shared lock.
    /// The policy is responsible for synchronizing any metadata changed by
    /// [Policy::hit].
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        let &index = self.index.get(key)?;
        let slot = &self.slots[index];
        self.policy.hit(index, &slot.state);
        Some(&slot.value)
    }

    /// Returns a reference to the value in `slot` if that slot currently holds
    /// `key` as a live entry, recording use.
    ///
    /// This is the read half of an external slot index: callers that recorded a
    /// key's slot (via [Self::get_or_insert_mut]) can resolve it with a
    /// key compare instead of a hash lookup. Any stale index entry reads as a
    /// miss rather than a wrong value: a slot reused for another key fails the
    /// key compare, a slot freed by [Self::remove] or [Self::retain] is not
    /// live, and an out-of-range slot does not exist. External indexes
    /// therefore need no maintenance beyond tolerating misses.
    #[inline]
    pub fn get_at(&self, slot: Slot, key: &K) -> Option<&V> {
        let resident = self.slots.get(slot)?;
        if !resident.live || resident.key != *key {
            return None;
        }

        self.policy.hit(slot, &resident.state);
        Some(&resident.value)
    }

    /// Returns a mutable reference to the value for `key`, recording use.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let &index = self.index.get(key)?;
        let slot = &mut self.slots[index];
        self.policy.hit_mut(index, &mut slot.state);
        Some(&mut slot.value)
    }

    /// Inserts `value` for `key`.
    ///
    /// If `key` was already present, replaces and returns the previous value,
    /// recording use. If the cache cannot use vacant capacity, the policy
    /// selects a resident to evict.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        if let Some(&index) = self.index.get(&key) {
            let slot = &mut self.slots[index];
            self.policy.hit_mut(index, &mut slot.state);
            return Some(core::mem::replace(&mut slot.value, value));
        }
        self.insert_value(key, value);
        None
    }

    /// Returns the value for `key`, computing and inserting it with `f` on a
    /// miss.
    ///
    /// On a hit, `f` is not called. On a miss, `f` is called, its result is
    /// inserted (evicting an entry if the cache is full), and a reference to the
    /// stored value is returned.
    pub fn get_or_insert_with<F: FnOnce() -> V>(&mut self, key: K, f: F) -> &V {
        let slot = match self.index.get(&key) {
            Some(&slot) => {
                self.policy.hit_mut(slot, &mut self.slots[slot].state);
                slot
            }
            None => self.insert_value(key, f()),
        };
        &self.slots[slot].value
    }

    /// Returns the value for `key`, computing and inserting it with a fallible
    /// `f` on a miss.
    ///
    /// On a hit, `f` is not called. On a miss, `f` is called; if it returns an
    /// error the error is propagated and nothing is inserted, so failures are
    /// not cached.
    pub fn try_get_or_insert_with<F: FnOnce() -> Result<V, E>, E>(
        &mut self,
        key: K,
        f: F,
    ) -> Result<&V, E> {
        let slot = match self.index.get(&key) {
            Some(&slot) => {
                self.policy.hit_mut(slot, &mut self.slots[slot].state);
                slot
            }
            None => self.insert_value(key, f()?),
        };
        Ok(&self.slots[slot].value)
    }

    /// Returns the slot index and a mutable reference to the slot for `key`,
    /// reusing an existing allocation where possible.
    ///
    /// On a hit, records use and returns the current value. On a miss into a
    /// reused slot (a freed slot or an eviction victim), the returned reference
    /// is the reused slot's stale value, which the caller is expected to
    /// overwrite. Only when the cache grows is `make` called to produce a fresh
    /// value. This lets callers holding pooled buffers overwrite in place
    /// rather than allocating on every insert.
    ///
    /// The slot index identifies the entry until it is evicted or removed, so
    /// callers can record it in an external index and resolve later reads with
    /// [Self::get_at] instead of a hash lookup.
    pub fn get_or_insert_mut<F: FnOnce() -> V>(&mut self, key: K, make: F) -> (Slot, &mut V) {
        if let Some(&slot) = self.index.get(&key) {
            self.policy.hit_mut(slot, &mut self.slots[slot].state);
            return (slot, &mut self.slots[slot].value);
        }
        let mut value = None;
        let mut make = Some(make);
        let (slot, state) = self.claim_slot(&key, |growing| {
            if growing {
                value = Some(make.take().expect("value factory must be available")());
            }
        });
        self.install(slot, key, state, value);
        (slot, &mut self.slots[slot].value)
    }

    /// Removes `key`, returning whether it was present.
    ///
    /// The slot and its allocation are retained for reuse, so the value is not
    /// returned.
    pub fn remove(&mut self, key: &K) -> bool {
        match self.index.remove(key) {
            Some(slot) => {
                self.policy.remove(Some(slot), key);
                self.slots[slot].live = false;
                self.free.push(slot);
                true
            }
            None => {
                self.policy.remove(None, key);
                false
            }
        }
    }

    /// Retains only the entries for which `keep` returns `true`.
    ///
    /// Dropped entries' slots and allocations are retained for reuse.
    pub fn retain<F: FnMut(&K, &V) -> bool>(&mut self, mut keep: F) {
        let Self {
            index,
            slots,
            free,
            policy,
            ..
        } = self;
        index.retain(|key, &mut slot| {
            let keep = keep(key, &slots[slot].value);
            if !keep {
                policy.remove(Some(slot), key);
                slots[slot].live = false;
                free.push(slot);
            }
            keep
        });
    }

    /// Retains resident entries and policy history accepted by `keep`.
    ///
    /// This key-only form is useful when nonresident admission history must be
    /// invalidated by the same predicate as resident entries.
    pub fn retain_keys<F: FnMut(&K) -> bool>(&mut self, mut keep: F) {
        let Self {
            index,
            slots,
            free,
            policy,
            ..
        } = self;
        index.retain(|key, &mut slot| {
            let keep = keep(key);
            if !keep {
                policy.remove(Some(slot), key);
                slots[slot].live = false;
                free.push(slot);
            }
            keep
        });
        policy.retain(keep);
    }

    /// Removes all entries, dropping their values and retaining the allocated
    /// capacity of the index and slot vector.
    pub fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.free.clear();
        self.policy.clear();
    }

    /// Inserts `value` for a `key` known to be absent, returning its slot.
    fn insert_value(&mut self, key: K, value: V) -> Slot {
        let (slot, state) = self.claim_slot(&key, |_| {});
        self.install(slot, key, state, Some(value));
        slot
    }

    fn install(&mut self, slot: Slot, key: K, state: P::SlotState, value: Option<V>) {
        let index_key = key.clone();
        if slot == self.slots.len() {
            debug_assert!(slot < self.capacity, "cache cannot grow beyond capacity");
            self.slots.push(Entry {
                key,
                value: value.expect("a new slot requires a value"),
                state,
                live: true,
            });
        } else {
            let resident = self
                .slots
                .get_mut(slot)
                .expect("policy selected a slot outside the cache");
            resident.key = key;
            if let Some(value) = value {
                resident.value = value;
            }
            resident.state = state;
            resident.live = true;
        }
        let replaced = self.index.insert(index_key, slot);
        debug_assert!(replaced.is_none(), "an incoming key must not be resident");
    }

    /// Claims storage for an incoming key and returns its slot and initial
    /// policy state. `on_claim` runs before the policy observes the result.
    fn claim_slot<F: FnOnce(bool)>(&mut self, key: &K, on_claim: F) -> (Slot, P::SlotState) {
        let Self {
            index,
            slots,
            free,
            capacity,
            policy,
        } = self;
        let has_vacancy = !free.is_empty() || slots.len() < *capacity;
        let mut claimed_slot = None;
        let state = policy.insert(&States(slots), key, has_vacancy, |victim| {
            let (slot, claimed) = victim.map_or_else(
                || {
                    assert!(has_vacancy, "policy requested unavailable cache capacity");
                    let slot = free.pop().unwrap_or(slots.len());
                    (slot, Claimed::Vacant(slot))
                },
                |slot| {
                    let resident = slots
                        .get(slot)
                        .expect("policy selected a slot outside the cache");
                    assert!(resident.live, "policy selected a nonresident slot");
                    let (evicted, indexed_slot) = index
                        .remove_entry(&resident.key)
                        .expect("a live victim must be indexed");
                    debug_assert_eq!(indexed_slot, slot, "resident index must match its slot");
                    (slot, Claimed::Evicted(evicted))
                },
            );
            on_claim(slot == slots.len());
            claimed_slot = Some(slot);
            claimed
        });
        let slot = claimed_slot.expect("policy must claim storage exactly once");
        (slot, state)
    }
}

impl<K: Hash + Eq + Clone + Default, V, P: Policy<K>> Cache<K, V, P>
where
    P::SlotState: Default,
{
    /// Pre-allocates all slots up to capacity, each holding a value from `make`,
    /// and leaves them free for reuse.
    ///
    /// After this call, the first `capacity` inserts reuse a pre-allocated slot
    /// instead of growing, so `make` (and any allocation it performs) runs only
    /// here. Use this to front-load allocation at construction so steady-state
    /// inserts never allocate. Free slots are seeded with the default key as a
    /// throwaway placeholder that is overwritten when the slot is first filled.
    pub fn prefill<F: FnMut() -> V>(&mut self, mut make: F) {
        let start = self.free.len();
        while self.slots.len() < self.capacity {
            let slot = self.slots.len();
            self.slots.push(Entry {
                key: K::default(),
                value: make(),
                state: P::SlotState::default(),
                live: false,
            });
            self.free.push(slot);
        }
        // The free list pops from the back, so reverse the new entries to hand
        // them out in ascending slot order (matching how growth assigns slots).
        self.free[start..].reverse();
    }
}

impl<K, V> core::fmt::Debug for Cache<K, V, Clock> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cache")
            .field("len", &self.index.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NZUsize;
    use core::{cell::Cell, hash::Hash};
    use proptest::{prelude::*, test_runner::TestCaseResult};
    use std::{
        collections::{HashMap, HashSet},
        rc::Rc,
    };

    struct TestPolicy {
        residents: Vec<Slot>,
    }

    impl<K> Policy<K> for TestPolicy {
        type SlotState = ();

        fn new(capacity: NonZeroUsize) -> Self {
            Self {
                residents: Vec::with_capacity(capacity.get()),
            }
        }

        fn hit(&self, _slot: Slot, _state: &()) {}

        fn hit_mut(&mut self, _slot: Slot, _state: &mut ()) {}

        fn insert<I, C>(&mut self, _states: &I, _key: &K, has_vacancy: bool, claim: C)
        where
            I: Index<Slot, Output = ()>,
            C: FnOnce(Option<Slot>) -> Claimed<K>,
        {
            let slot = if has_vacancy {
                let Claimed::Vacant(slot) = claim(None) else {
                    panic!("vacancy claim returned an eviction");
                };
                slot
            } else {
                let victim = self.residents.remove(0);
                let Claimed::Evicted(_) = claim(Some(victim)) else {
                    panic!("victim claim returned vacant capacity");
                };
                victim
            };
            self.residents.push(slot);
        }

        fn remove(&mut self, slot: Option<Slot>, _key: &K) {
            if let Some(slot) = slot {
                let position = self
                    .residents
                    .iter()
                    .position(|resident| *resident == slot)
                    .unwrap();
                self.residents.remove(position);
            }
        }

        fn retain<F: FnMut(&K) -> bool>(&mut self, _keep: F) {}

        fn clear(&mut self) {
            self.residents.clear();
        }
    }

    type TestCache<K, V> = Cache<K, V, TestPolicy>;

    impl<K: Hash + Eq + Clone, V, P: Policy<K>> Cache<K, V, P> {
        pub(super) fn check_cache_invariants(&self) {
            assert!(self.slots.len() <= self.capacity());
            assert_eq!(self.index.len() + self.free.len(), self.slots.len());

            let free: HashSet<Slot> = self.free.iter().copied().collect();
            assert_eq!(free.len(), self.free.len(), "duplicate free slot");
            let mut seen = HashSet::new();
            for (key, &slot) in &self.index {
                assert!(slot < self.slots.len());
                assert!(!free.contains(&slot), "slot {slot} both live and free");
                assert!(seen.insert(slot), "slot {slot} mapped twice");
                assert!(self.slots[slot].key == *key);
                assert!(self.slots[slot].live, "indexed slot {slot} not live");
            }
            for &slot in &self.free {
                assert!(!self.slots[slot].live, "free slot {slot} still live");
            }
        }
    }

    #[test]
    fn basic_put_get_peek() {
        let mut cache = TestCache::new(NZUsize!(2));
        assert!(cache.is_empty());
        assert_eq!(cache.capacity(), 2);

        assert_eq!(cache.put(1u64, 10u64), None);
        assert_eq!(cache.put(2, 20), None);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&1).copied(), Some(10));
        assert_eq!(cache.peek(&2).copied(), Some(20));
        assert!(cache.contains(&1));
        assert!(!cache.contains(&3));
        assert_eq!(cache.get(&3), None);
        cache.check_cache_invariants();
    }

    #[test]
    fn capacity_is_const() {
        const fn capacity(cache: &TestCache<u64, u64>) -> usize {
            cache.capacity()
        }

        let cache = TestCache::new(NZUsize!(2));
        assert_eq!(capacity(&cache), 2);
    }

    #[test]
    fn put_replaces_existing() {
        let mut cache = TestCache::new(NZUsize!(2));
        assert_eq!(cache.put(1u64, 10u64), None);
        assert_eq!(cache.put(1, 11), Some(10));
        assert_eq!(cache.get(&1).copied(), Some(11));
        assert_eq!(cache.len(), 1);
        cache.check_cache_invariants();
    }

    #[test]
    fn capacity_one_reuses_its_only_slot() {
        let mut cache = TestCache::new(NZUsize!(1));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        assert!(!cache.contains(&1));
        assert_eq!(cache.get(&2).copied(), Some(20));
        assert_eq!(cache.len(), 1);
        cache.check_cache_invariants();
    }

    #[test]
    fn get_or_insert_with_calls_factory_only_on_miss() {
        let mut cache = TestCache::new(NZUsize!(2));
        let calls = Cell::new(0);
        let compute = |key: u64| {
            calls.set(calls.get() + 1);
            key * 100
        };

        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        cache.check_cache_invariants();
    }

    #[test]
    fn try_get_or_insert_with_does_not_cache_errors() {
        let mut cache = TestCache::new(NZUsize!(2));

        let error: Result<&u64, &str> = cache.try_get_or_insert_with(1u64, || Err("bad"));
        assert_eq!(error, Err("bad"));
        assert!(!cache.contains(&1));

        let value: Result<&u64, &str> = cache.try_get_or_insert_with(1, || Ok(10));
        assert_eq!(value, Ok(&10));
        assert!(cache.contains(&1));
        cache.check_cache_invariants();
    }

    #[test]
    fn remove_keeps_slot_for_reuse() {
        let makes = Cell::new(0);
        let mut cache = TestCache::new(NZUsize!(2));
        cache.get_or_insert_mut(1, || {
            makes.set(makes.get() + 1);
            10
        });
        cache.get_or_insert_mut(2, || {
            makes.set(makes.get() + 1);
            20
        });
        assert_eq!(makes.get(), 2);
        assert_eq!(cache.slots.len(), 2);

        assert!(cache.remove(&1));
        assert!(!cache.contains(&1));
        assert_eq!(cache.len(), 1);
        *cache
            .get_or_insert_mut(3, || {
                makes.set(makes.get() + 1);
                30
            })
            .1 = 30;

        assert_eq!(makes.get(), 2);
        assert_eq!(cache.slots.len(), 2);
        assert_eq!(cache.get(&3).copied(), Some(30));
        assert!(!cache.remove(&999));
        cache.check_cache_invariants();
    }

    #[test]
    fn retain_frees_slots_for_reuse() {
        let mut cache = TestCache::new(NZUsize!(4));
        for key in 0..4u64 {
            cache.put(key, key * 10);
        }
        cache.retain(|key, _| key % 2 == 0);
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&0));
        assert!(cache.contains(&2));
        assert!(!cache.contains(&1));
        assert!(!cache.contains(&3));

        cache.put(10, 100);
        cache.put(12, 120);
        assert_eq!(cache.slots.len(), 4);
        assert_eq!(cache.len(), 4);
        cache.check_cache_invariants();
    }

    #[test]
    fn get_or_insert_mut_reuses_allocations() {
        let makes = Cell::new(0);
        let mut cache = TestCache::new(NZUsize!(3));
        for key in 0..100u64 {
            let (_, value) = cache.get_or_insert_mut(key, || {
                makes.set(makes.get() + 1);
                0
            });
            *value = key;
        }
        assert_eq!(makes.get(), 3);
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_cache_invariants();
    }

    #[test]
    fn prefill_allocates_once_and_reuses() {
        let makes = Cell::new(0);
        let mut cache = TestCache::new(NZUsize!(3));
        cache.prefill(|| {
            makes.set(makes.get() + 1);
            0
        });
        assert_eq!(makes.get(), 3);
        assert_eq!(cache.slots.len(), 3);
        assert!(cache.is_empty());
        cache.check_cache_invariants();

        for key in 0..100u64 {
            *cache
                .get_or_insert_mut(key, || {
                    makes.set(makes.get() + 1);
                    0
                })
                .1 = key;
        }
        assert_eq!(makes.get(), 3);
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_cache_invariants();
    }

    #[test]
    fn clear_drops_entries_and_allows_reuse() {
        let mut cache = TestCache::new(NZUsize!(4));
        for key in 0..4u64 {
            cache.put(key, key);
        }
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.put(9, 9);
        assert_eq!(cache.get(&9).copied(), Some(9));
        cache.check_cache_invariants();
    }

    #[derive(Clone)]
    struct Tracked(Rc<Cell<usize>>);

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn values_are_dropped_on_replacement_and_clear() {
        let drops = Rc::new(Cell::new(0));
        let mut cache = TestCache::new(NZUsize!(2));
        for key in 0..2u64 {
            cache.put(key, Tracked(drops.clone()));
        }
        assert_eq!(drops.get(), 0);
        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);

        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 2);

        cache.clear();
        assert_eq!(drops.get(), 4);
    }

    #[test]
    fn remove_retains_value_until_reuse() {
        let drops = Rc::new(Cell::new(0));
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1, Tracked(drops.clone()));
        assert!(cache.remove(&1));
        assert_eq!(drops.get(), 0);

        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn get_at_validates_key() {
        let mut cache = TestCache::new(NZUsize!(2));
        let (first, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (second, value) = cache.get_or_insert_mut(2u64, || 0u64);
        *value = 20;

        assert_eq!(cache.get_at(first, &1).copied(), Some(10));
        assert_eq!(cache.get_at(second, &2).copied(), Some(20));
        assert_eq!(cache.get_at(first, &2), None);
        assert_eq!(cache.get_at(cache.capacity(), &1), None);
        cache.check_cache_invariants();
    }

    #[test]
    fn get_at_rejects_stale_evicted_slot() {
        let mut cache = TestCache::new(NZUsize!(1));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (reused, value) = cache.get_or_insert_mut(3u64, || 0u64);
        *value = 30;

        assert_eq!(slot, reused);
        assert_eq!(cache.get_at(slot, &1), None);
        assert_eq!(cache.get_at(slot, &3).copied(), Some(30));
        cache.check_cache_invariants();
    }

    #[test]
    fn get_at_rejects_freed_slot() {
        let mut cache = TestCache::new(NZUsize!(2));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        assert!(cache.remove(&1));
        assert_eq!(cache.get_at(slot, &1), None);

        let (reused, value) = cache.get_or_insert_mut(2u64, || 0u64);
        *value = 20;
        assert_eq!(reused, slot);
        assert_eq!(cache.get_at(slot, &1), None);
        assert_eq!(cache.get_at(slot, &2).copied(), Some(20));
        cache.check_cache_invariants();
    }

    #[test]
    fn get_or_insert_mut_slot_is_stable_on_hit() {
        let mut cache = TestCache::new(NZUsize!(2));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (hit_slot, value) = cache.get_or_insert_mut(1u64, || unreachable!());
        assert_eq!(slot, hit_slot);
        assert_eq!(*value, 10);
        cache.check_cache_invariants();
    }

    #[test]
    fn get_mut_updates_resident_value() {
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        assert_eq!(cache.get_mut(&2), None);
        *cache.get_mut(&1).unwrap() = 11;
        assert_eq!(cache.get(&1).copied(), Some(11));
        cache.check_cache_invariants();
    }

    struct EarlyEvictionPolicy {
        residents: Vec<Slot>,
        history: Vec<u64>,
    }

    impl Policy<u64> for EarlyEvictionPolicy {
        type SlotState = ();

        fn new(_capacity: NonZeroUsize) -> Self {
            Self {
                residents: Vec::new(),
                history: Vec::new(),
            }
        }

        fn hit(&self, _slot: Slot, _state: &()) {}

        fn hit_mut(&mut self, _slot: Slot, _state: &mut ()) {}

        fn insert<I, C>(&mut self, _states: &I, _key: &u64, has_vacancy: bool, claim: C)
        where
            I: Index<Slot, Output = ()>,
            C: FnOnce(Option<Slot>) -> Claimed<u64>,
        {
            let slot = if let Some(&victim) = self.residents.first() {
                let Claimed::Evicted(key) = claim(Some(victim)) else {
                    panic!("early eviction policy must evict a resident");
                };
                self.residents.remove(0);
                self.history.push(key);
                victim
            } else {
                assert!(has_vacancy);
                let Claimed::Vacant(slot) = claim(None) else {
                    panic!("early eviction policy must claim vacant capacity");
                };
                slot
            };
            self.residents.push(slot);
        }

        fn remove(&mut self, slot: Option<Slot>, key: &u64) {
            if let Some(slot) = slot {
                let position = self
                    .residents
                    .iter()
                    .position(|resident| *resident == slot)
                    .unwrap();
                self.residents.remove(position);
            }
            self.history.retain(|historical| historical != key);
        }

        fn retain<F: FnMut(&u64) -> bool>(&mut self, keep: F) {
            self.history.retain(keep);
        }

        fn clear(&mut self) {
            self.residents.clear();
            self.history.clear();
        }
    }

    #[test]
    fn policy_can_evict_before_capacity() {
        let mut cache = Cache::<u64, u64, EarlyEvictionPolicy>::new(NZUsize!(3));
        cache.prefill(|| 0);

        let (first_slot, first_value) = cache.get_or_insert_mut(1, || unreachable!());
        *first_value = 10;
        let (second_slot, second_value) = cache.get_or_insert_mut(2, || unreachable!());
        *second_value = 20;

        assert_eq!(first_slot, second_slot);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2).copied(), Some(20));
        assert_eq!(cache.policy.history, vec![1]);

        assert!(!cache.remove(&1));
        assert!(cache.policy.history.is_empty());
        cache.put(3, 30);
        cache.put(4, 40);
        assert_eq!(cache.policy.history, vec![2, 3]);
        cache.retain_keys(|key| *key >= 3);
        assert_eq!(cache.policy.history, vec![3]);

        cache.clear();
        assert!(cache.policy.residents.is_empty());
        assert!(cache.policy.history.is_empty());
    }

    #[derive(Clone, Debug)]
    enum Op {
        Get(u8),
        Peek(u8),
        Put(u8, u16),
        GetOrInsert(u8, u16),
        GetOrInsertMut(u8, u16),
        GetMut(u8, u16),
        Remove(u8),
        Retain(u8),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..16).prop_map(Op::Get),
            (0u8..16).prop_map(Op::Peek),
            (0u8..16, any::<u16>()).prop_map(|(key, value)| Op::Put(key, value)),
            (0u8..16, any::<u16>()).prop_map(|(key, value)| Op::GetOrInsert(key, value)),
            (0u8..16, any::<u16>()).prop_map(|(key, value)| Op::GetOrInsertMut(key, value)),
            (0u8..16, any::<u16>()).prop_map(|(key, value)| Op::GetMut(key, value)),
            (0u8..16).prop_map(Op::Remove),
            (0u8..16).prop_map(Op::Retain),
        ]
    }

    fn exercise_policy<P, F>(
        capacity: usize,
        prefill: bool,
        ops: Vec<Op>,
        check_policy_invariants: F,
    ) -> TestCaseResult
    where
        P: Policy<u8>,
        P::SlotState: Default,
        F: Fn(&Cache<u8, u16, P>),
    {
        let mut cache = Cache::<u8, u16, P>::new(NonZeroUsize::new(capacity).unwrap());
        if prefill {
            cache.prefill(|| 0u16);
        }
        let mut model = HashMap::new();

        for op in ops {
            match op {
                Op::Get(key) => {
                    let value = cache.get(&key).copied();
                    prop_assert_eq!(value, cache.peek(&key).copied());
                }
                Op::Peek(key) => {
                    let _ = cache.peek(&key);
                }
                Op::Put(key, value) => {
                    cache.put(key, value);
                    model.insert(key, value);
                    prop_assert_eq!(cache.peek(&key).copied(), Some(value));
                }
                Op::GetOrInsert(key, value) => {
                    let stored = *cache.get_or_insert_with(key, || value);
                    model.insert(key, stored);
                    prop_assert_eq!(cache.peek(&key).copied(), Some(stored));
                }
                Op::GetOrInsertMut(key, value) => {
                    *cache.get_or_insert_mut(key, || value).1 = value;
                    model.insert(key, value);
                    prop_assert_eq!(cache.peek(&key).copied(), Some(value));
                }
                Op::GetMut(key, value) => {
                    if let Some(stored) = cache.get_mut(&key) {
                        *stored = value;
                        model.insert(key, value);
                    }
                }
                Op::Remove(key) => {
                    let present = cache.contains(&key);
                    prop_assert_eq!(cache.remove(&key), present);
                    model.remove(&key);
                    prop_assert!(!cache.contains(&key));
                }
                Op::Retain(key) => {
                    cache.retain(|resident, _| *resident < key);
                    model.retain(|resident, _| *resident < key);
                    prop_assert!(cache.len() <= usize::from(key).min(capacity));
                }
            }

            prop_assert!(cache.len() <= capacity);
            prop_assert!(cache.slots.len() <= capacity);
            for key in 0..16u8 {
                let present = cache.contains(&key);
                prop_assert_eq!(present, cache.peek(&key).is_some());
                if present {
                    prop_assert_eq!(cache.peek(&key).copied(), model.get(&key).copied());
                }
            }
            cache.check_cache_invariants();
            check_policy_invariants(&cache);
        }

        Ok(())
    }

    proptest! {
        #[test]
        fn clock_invariants_hold(
            capacity in 1usize..8,
            prefill in any::<bool>(),
            ops in proptest::collection::vec(op_strategy(), 0..256),
        ) {
            exercise_policy::<Clock, _>(capacity, prefill, ops, |cache| {
                cache.check_policy_invariants();
            })?;
        }
    }
}
