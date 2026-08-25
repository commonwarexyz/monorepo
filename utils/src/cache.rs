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
//! The resident index stores only slot IDs and reads keys from the slots. It
//! reserves space for twice the resident limit at construction, keeping its
//! backing allocation fixed throughout insertion and eviction. Tombstone
//! cleanup can still rehash the index in place. [Clock2QPlus] makes the same
//! reservation for its independently bounded Ghost index. This reservation
//! covers index storage; keys, values, and other metadata can allocate separately.
//!
//! # Policies
//!
//! The default [Clock] policy provides low-overhead replacement without retaining
//! evicted keys. It suits workloads with cheap misses or little benefit from
//! reuse history. [Clock2QPlus] uses bounded history and separate admission and
//! eviction regions to resist scans and favor recurring entries. Its extra work
//! and metadata can pay off when avoiding a miss is expensive. Compare policies
//! using the workload's total cost, including misses and retained memory.
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
pub mod clock2qplus;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
pub use clock::Clock;
pub use clock2qplus::Clock2QPlus;
use core::{hash::Hash, num::NonZeroUsize, ops::Index};
use hashbrown::HashTable;

type Hasher = ahash::RandomState;

/// Stable identifier for cache storage and policy metadata.
pub type Slot = usize;

/// Cache-owned hashing context for one policy key operation.
///
/// The context binds the operation's key and any hash already computed by the
/// cache to the same randomized state used by the resident index. Policies can
/// also use [Self::hash_one] when their own indexes need to rehash canonical
/// keys. A context cannot be constructed outside this module, so public cache
/// operations never accept caller-supplied precomputed hashes.
///
/// The key's [Hash] and [Eq] identity must remain stable throughout the cache
/// operation, including callbacks, so its precomputed hash remains valid.
pub struct HashContext<'a, K> {
    key: &'a K,
    hash: Option<u64>,
    hasher: &'a Hasher,
}

impl<'a, K: Hash> HashContext<'a, K> {
    #[inline]
    const fn prehashed(key: &'a K, hash: u64, hasher: &'a Hasher) -> Self {
        Self {
            key,
            hash: Some(hash),
            hasher,
        }
    }

    #[inline]
    const fn lazy(key: &'a K, hasher: &'a Hasher) -> Self {
        Self {
            key,
            hash: None,
            hasher,
        }
    }

    /// Returns the key for this policy operation.
    #[inline]
    pub const fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the key's hash in the cache's randomized hash context.
    #[inline]
    pub fn hash(&self) -> u64 {
        self.hash.unwrap_or_else(|| self.hasher.hash_one(self.key))
    }

    /// Hashes `key` with the cache's randomized state.
    ///
    /// Policy-owned hash tables use this method for rehash callbacks so every
    /// hash participating in the operation has the same origin.
    #[inline]
    pub fn hash_one(&self, key: &K) -> u64 {
        self.hasher.hash_one(key)
    }
}

/// Result of claiming storage for an incoming resident.
pub enum Claimed<'a, K> {
    /// Vacant capacity was claimed at this slot.
    Vacant(Slot),
    /// The requested victim was claimed, yielding its canonical key and hash.
    ///
    /// The hash comes from the same cache context passed to [Policy::insert]
    /// and is valid only during that insertion transition.
    Evicted {
        /// Victim's canonical key, borrowed until the policy transition ends.
        key: &'a K,
        /// Hash used to remove the victim from the resident index.
        hash: u64,
    },
}

/// Admission and eviction policy for a fixed-capacity [Cache].
///
/// A policy never owns resident keys or values. It identifies residents by
/// stable slot ID and owns only the metadata needed for admission and eviction.
///
/// Insertion runs as one exclusive transition. The policy selects either
/// vacant capacity or a victim, then invokes the cache-provided claim exactly
/// once. The claim returns the cache-selected vacant slot or borrows the
/// victim's key. A policy that retains history clones that key into its own
/// storage. The policy finishes its metadata transition and returns the
/// incoming resident's initial slot state.
///
/// Policy operations and their callbacks must preserve the [Hash] and [Eq]
/// identity of the operation's key and all resident or history keys. Cloning a
/// key must preserve that identity.
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
    /// `key` carries the confirmed-miss key, its resident lookup hash, and the
    /// cache's rehash context. `states` provides policy state indexed by [Slot].
    /// `has_vacancy` reports whether unused capacity is available, though the
    /// policy may still choose a victim. The policy commits its choice by
    /// calling `claim` exactly once. Passing `None` requires `has_vacancy` and
    /// claims unused capacity, returning its assigned slot. Passing `Some(slot)`
    /// replaces that live slot and returns a reference to its previous key and
    /// its resident hash. The key remains available until this method returns.
    ///
    /// The returned [Slot] must be the storage resolved by `claim`. The returned
    /// [Self::SlotState] becomes the incoming entry's initial policy state.
    fn insert<'a, I, C>(
        &mut self,
        states: &I,
        key: HashContext<'_, K>,
        has_vacancy: bool,
        claim: C,
    ) -> (Slot, Self::SlotState)
    where
        K: 'a,
        I: Index<Slot, Output = Self::SlotState>,
        C: FnOnce(Option<Slot>) -> Claimed<'a, K>;

    /// Forgets `key` and its policy state.
    ///
    /// `slot` identifies the key's previous slot when it was cached. A missing
    /// slot means the resident lookup missed, so [HashContext::hash] reuses that
    /// lookup hash for any policy-owned nonresident index. Resident removals
    /// made by [Cache::retain] derive the hash lazily if the policy needs it.
    fn remove(&mut self, slot: Option<Slot>, key: HashContext<'_, K>);

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
///
/// Keys must keep the same [Hash] and [Eq] identity throughout each cache
/// operation, including value factories and other callbacks, and while resident
/// or retained in policy history. Cloning a key must preserve its identity.
/// Violating these requirements is a logic error and may cause incorrect
/// lookups or admission decisions.
pub struct Cache<K, V, P = Clock>
where
    P: Policy<K>,
{
    /// Indexes live slots by their canonical keys in `slots`.
    ///
    /// Twice the resident bound keeps live entries within half the usable
    /// capacity, where hashbrown reclaims tombstones in place without growing.
    ///
    /// `index.len() + free.len() == slots.len()` always holds.
    index: HashTable<Slot>,
    hasher: Hasher,
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

impl<K: Hash + Eq, V, P: Policy<K>> Cache<K, V, P> {
    /// Creates an empty cache with room for `capacity` residents.
    pub fn new(capacity: NonZeroUsize) -> Self {
        let policy = P::new(capacity);
        let capacity = capacity.get();
        Self {
            index: HashTable::with_capacity(capacity.checked_mul(2).expect("capacity overflow")),
            hasher: Hasher::default(),
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
        self.find_slot(key).is_some()
    }

    /// Returns a reference to the value for `key` without recording use.
    ///
    /// Unlike [Self::get], this does not notify the policy of a hit.
    #[inline]
    pub fn peek(&self, key: &K) -> Option<&V> {
        let slot = self.find_slot(key)?;
        Some(&self.slots[slot].value)
    }

    /// Returns a reference to the value for `key`, recording use.
    ///
    /// This takes `&self` so it can be called concurrently behind a shared lock.
    /// The policy is responsible for synchronizing any metadata changed by
    /// [Policy::hit].
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        let index = self.find_slot(key)?;
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
        let index = self.find_slot(key)?;
        let slot = &mut self.slots[index];
        self.policy.hit_mut(index, &mut slot.state);
        Some(&mut slot.value)
    }

    /// Inserts `value` for `key`.
    ///
    /// If `key` was already present, replaces and returns the previous value,
    /// recording use. Otherwise the policy claims vacant capacity or selects a
    /// resident to evict.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.hasher.hash_one(&key);
        if let Some(index) = self.find_slot_hashed(&key, hash) {
            let slot = &mut self.slots[index];
            self.policy.hit_mut(index, &mut slot.state);
            return Some(core::mem::replace(&mut slot.value, value));
        }
        self.insert_value(key, value, hash);
        None
    }

    /// Returns the value for `key`, computing and inserting it with `f` on a
    /// miss.
    ///
    /// On a hit, `f` is not called. On a miss, `f` is called, its result is
    /// inserted (evicting a resident if the policy selects one), and a reference
    /// to the stored value is returned.
    pub fn get_or_insert_with<F: FnOnce() -> V>(&mut self, key: K, f: F) -> &V {
        let hash = self.hasher.hash_one(&key);
        let slot = match self.find_slot_hashed(&key, hash) {
            Some(slot) => {
                self.policy.hit_mut(slot, &mut self.slots[slot].state);
                slot
            }
            None => self.insert_value(key, f(), hash),
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
        let hash = self.hasher.hash_one(&key);
        let slot = match self.find_slot_hashed(&key, hash) {
            Some(slot) => {
                self.policy.hit_mut(slot, &mut self.slots[slot].state);
                slot
            }
            None => self.insert_value(key, f()?, hash),
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
    ///
    /// # Panics
    ///
    /// If `make` panics while producing a value for a new slot, policy metadata
    /// may already have been updated. If the panic is caught, this cache must
    /// not be used again.
    pub fn get_or_insert_mut<F: FnOnce() -> V>(&mut self, key: K, make: F) -> (Slot, &mut V) {
        let hash = self.hasher.hash_one(&key);
        let slot = match self.find_slot_hashed(&key, hash) {
            Some(slot) => {
                self.policy.hit_mut(slot, &mut self.slots[slot].state);
                slot
            }
            None => {
                let (slot, state) = self.claim_slot(&key, hash);
                match slot {
                    Some(slot) => {
                        self.slots[slot].key = key;
                        self.slots[slot].state = state;
                        self.slots[slot].live = true;
                        self.index_slot(slot, hash);
                        slot
                    }
                    None => self.grow(key, make(), state, hash),
                }
            }
        };
        (slot, &mut self.slots[slot].value)
    }

    /// Removes `key`, returning whether it was present.
    ///
    /// The slot and its allocation are retained for reuse, so the value is not
    /// returned.
    pub fn remove(&mut self, key: &K) -> bool {
        let hash = self.hasher.hash_one(key);
        match self
            .index
            .find_entry(hash, |&slot| self.slots[slot].key == *key)
        {
            Ok(entry) => {
                let slot = entry.remove().0;
                self.policy
                    .remove(Some(slot), HashContext::prehashed(key, hash, &self.hasher));
                self.slots[slot].live = false;
                self.free.push(slot);
                true
            }
            Err(_) => {
                self.policy
                    .remove(None, HashContext::prehashed(key, hash, &self.hasher));
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
            hasher,
            ..
        } = self;
        index.retain(|&mut slot| {
            let resident = &mut slots[slot];
            let keep = keep(&resident.key, &resident.value);
            if !keep {
                policy.remove(Some(slot), HashContext::lazy(&resident.key, hasher));
                slots[slot].live = false;
                free.push(slot);
            }
            keep
        });
    }

    /// Removes all entries, dropping their values and retaining the allocated
    /// capacity of the index and slot vector.
    pub fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.free.clear();
        self.policy.clear();
    }

    #[inline]
    fn find_slot(&self, key: &K) -> Option<Slot> {
        self.find_slot_hashed(key, self.hasher.hash_one(key))
    }

    #[inline]
    fn find_slot_hashed(&self, key: &K, hash: u64) -> Option<Slot> {
        self.index
            .find(hash, |&slot| self.slots[slot].key == *key)
            .copied()
    }

    /// Publishes a slot after its canonical key is installed. All indexed slots
    /// retain their keys while insertion may rehash the table.
    #[inline]
    fn index_slot(&mut self, slot: Slot, hash: u64) {
        let slots = &self.slots;
        let hasher = &self.hasher;
        let _ = self
            .index
            .insert_unique(hash, slot, |&slot| hasher.hash_one(&slots[slot].key));
    }

    /// Pushes a brand new slot holding `(key, value)` and returns its index.
    ///
    /// Only called while the cache is below capacity.
    fn grow(&mut self, key: K, value: V, state: P::SlotState, hash: u64) -> Slot {
        let slot = self.slots.len();
        self.slots.push(Entry {
            key,
            value,
            state,
            live: true,
        });
        self.index_slot(slot, hash);
        slot
    }

    /// Inserts `value` for a `key` known to be absent, returning its slot.
    fn insert_value(&mut self, key: K, value: V, hash: u64) -> Slot {
        let (slot, state) = self.claim_slot(&key, hash);
        match slot {
            Some(slot) => {
                self.slots[slot].key = key;
                self.slots[slot].value = value;
                self.slots[slot].state = state;
                self.slots[slot].live = true;
                self.index_slot(slot, hash);
                slot
            }
            None => self.grow(key, value, state, hash),
        }
    }

    /// Resolves the policy's insertion decision for a confirmed miss.
    ///
    /// The policy invokes the cache-provided claim exactly once. `claim(None)`
    /// asks the cache to use unused capacity. `claim(Some(slot))` asks it to
    /// evict that resident. The claim resolves the physical slot and returns
    /// either the assigned vacant slot or a borrowed victim key so the policy can
    /// finish updating its metadata.
    ///
    /// Returns `Some(slot)` when an existing slot can be reused. Returns `None`
    /// when the policy reserved the next slot and the caller must grow the
    /// cache.
    fn claim_slot(&mut self, key: &K, hash: u64) -> (Option<Slot>, P::SlotState) {
        let Self {
            index,
            slots,
            free,
            capacity,
            policy,
            hasher,
        } = self;
        let has_vacancy = !free.is_empty() || slots.len() < *capacity;
        let slots = slots.as_slice();

        let (slot, state) = policy.insert(
            &States(slots),
            HashContext::prehashed(key, hash, hasher),
            has_vacancy,
            |victim| {
                victim.map_or_else(
                    || {
                        assert!(has_vacancy, "policy requested unavailable cache capacity");

                        // Reuse a free slot before reserving the next slot for growth.
                        let slot = free.pop().unwrap_or(slots.len());
                        Claimed::Vacant(slot)
                    },
                    |slot| {
                        let resident = slots
                            .get(slot)
                            .expect("policy selected a slot outside the cache");
                        assert!(resident.live, "policy selected a nonresident slot");

                        // Policy state borrows the entries throughout insertion, so the
                        // victim key stays in place until the policy call returns.
                        let hash = hasher.hash_one(&resident.key);
                        index
                            .find_entry(hash, |&candidate| candidate == slot)
                            .expect("a live victim must be indexed")
                            .remove();

                        Claimed::Evicted {
                            key: &resident.key,
                            hash,
                        }
                    },
                )
            },
        );

        // Existing slots can be updated in place. The slot at `slots.len()` is
        // the next vector position and tells the caller to grow instead.
        ((slot != slots.len()).then_some(slot), state)
    }
}

impl<K: Hash + Eq + Default, V, P: Policy<K>> Cache<K, V, P>
where
    P::SlotState: Default,
{
    /// Pre-allocates all slots up to capacity, each holding a value from `make`,
    /// and leaves them free for reuse.
    ///
    /// After this call, the first `capacity` inserts reuse a pre-allocated slot
    /// instead of growing, so `make` (and any allocation it performs) runs only
    /// here. Use this to front-load value allocation at construction so
    /// steady-state inserts never allocate values. Free slots are seeded with the
    /// default key as a throwaway placeholder that is overwritten when the slot
    /// is first filled.
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

impl<K, V, P: Policy<K> + core::fmt::Debug> core::fmt::Debug for Cache<K, V, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cache")
            .field("len", &self.index.len())
            .field("capacity", &self.capacity)
            .field("policy", &self.policy)
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

    type TestCache<K, V> = Cache<K, V>;

    impl<K: Hash + Eq, V, P: Policy<K>> Cache<K, V, P> {
        /// Asserts the cache's structural invariants hold.
        pub(super) fn check_cache_invariants(&self) {
            assert!(self.slots.len() <= self.capacity());
            assert_eq!(self.index.len() + self.free.len(), self.slots.len());

            // The index is a bijection onto the live slots, each slot's key
            // round-trips, and live slots are disjoint from free slots.
            let free: HashSet<Slot> = self.free.iter().copied().collect();
            assert_eq!(free.len(), self.free.len(), "duplicate free slot");
            let mut seen = HashSet::new();
            for &slot in &self.index {
                assert!(slot < self.slots.len());
                assert!(!free.contains(&slot), "slot {slot} both live and free");
                assert!(seen.insert(slot), "slot {slot} mapped twice");
                assert_eq!(self.find_slot(&self.slots[slot].key), Some(slot));
                assert!(self.slots[slot].live, "indexed slot {slot} not live");
            }
            for &slot in &self.free {
                assert!(!self.slots[slot].live, "free slot {slot} still live");
            }
        }
    }

    #[test]
    fn test_basic_put_get_peek() {
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
    fn test_put_replaces_existing() {
        let mut cache = TestCache::new(NZUsize!(2));
        assert_eq!(cache.put(1u64, 10u64), None);
        assert_eq!(cache.put(1, 11), Some(10));
        assert_eq!(cache.get(&1).copied(), Some(11));
        assert_eq!(cache.len(), 1);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_capacity_one_reuses_its_only_slot() {
        let mut cache = TestCache::new(NZUsize!(1));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        assert!(!cache.contains(&1));
        assert_eq!(cache.get(&2).copied(), Some(20));
        assert_eq!(cache.len(), 1);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_get_or_insert_with_calls_factory_only_on_miss() {
        let mut cache = TestCache::new(NZUsize!(2));
        let calls = Cell::new(0);
        let compute = |key: u64| {
            calls.set(calls.get() + 1);
            key * 100
        };

        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        // A hit does not call the factory.
        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_try_get_or_insert_with_does_not_cache_errors() {
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
    fn test_remove_keeps_slot_for_reuse() {
        // A removed entry frees its slot for reuse without growing the slot
        // vector or calling the factory again.
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

        // Reusing the freed slot does not call the factory or grow.
        *cache
            .get_or_insert_mut(3, || {
                makes.set(makes.get() + 1);
                30
            })
            .1 = 30;

        assert_eq!(makes.get(), 2, "freed slot should not call the factory");
        assert_eq!(cache.slots.len(), 2);
        assert_eq!(cache.get(&3).copied(), Some(30));
        assert!(!cache.remove(&999));
        cache.check_cache_invariants();
    }

    #[test]
    fn test_retain_frees_slots_for_reuse() {
        let mut cache = TestCache::new(NZUsize!(4));
        for key in 0..4u64 {
            cache.put(key, key * 10);
        }
        // Keep even keys.
        cache.retain(|key, _| key % 2 == 0);
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&0));
        assert!(cache.contains(&2));
        assert!(!cache.contains(&1));
        assert!(!cache.contains(&3));

        // Freed slots are reused for new inserts.
        cache.put(10, 100);
        cache.put(12, 120);
        assert_eq!(cache.slots.len(), 4);
        assert_eq!(cache.len(), 4);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_get_or_insert_mut_reuses_allocations() {
        // The factory runs at most `capacity` times no matter how many distinct
        // keys churn through the cache, proving evicted slots are reused.
        let makes = Cell::new(0);
        let mut cache = TestCache::new(NZUsize!(3));
        for key in 0..100u64 {
            let (_, value) = cache.get_or_insert_mut(key, || {
                makes.set(makes.get() + 1);
                0
            });
            *value = key; // Overwrite the possibly stale reused value.
        }
        assert_eq!(makes.get(), 3, "factory should run only during growth");
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_prefill_allocates_once_and_reuses() {
        // Prefill runs the factory exactly `capacity` times. Subsequent inserts
        // reuse pre-allocated slots without growing or calling the factory.
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

        // Churn many keys without further factory calls or slot growth.
        for key in 0..100u64 {
            *cache
                .get_or_insert_mut(key, || {
                    makes.set(makes.get() + 1);
                    0
                })
                .1 = key;
        }
        assert_eq!(makes.get(), 3, "prefilled slots must be reused");
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_clear_drops_entries_and_allows_reuse() {
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
    fn test_values_are_dropped_on_replacement_and_clear() {
        let drops = Rc::new(Cell::new(0));
        let mut cache = TestCache::new(NZUsize!(2));
        for key in 0..2u64 {
            cache.put(key, Tracked(drops.clone()));
        }
        assert_eq!(drops.get(), 0);

        // Inserting a third entry evicts one and drops its value.
        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);

        // Replacing an existing key drops the old value.
        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 2);

        // Clearing drops the remaining two values.
        cache.clear();
        assert_eq!(drops.get(), 4);
    }

    #[test]
    fn test_remove_retains_value_until_reuse() {
        // remove does not drop the value. The freed slot keeps it until a
        // value-inserting method reuses the slot.
        let drops = Rc::new(Cell::new(0));
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1, Tracked(drops.clone()));
        assert!(cache.remove(&1));
        assert_eq!(drops.get(), 0, "remove must not drop the value");

        // Reusing the freed slot through a value insert drops the retained value.
        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn test_get_at_validates_key() {
        let mut cache = TestCache::new(NZUsize!(2));
        let (first, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (second, value) = cache.get_or_insert_mut(2u64, || 0u64);
        *value = 20;

        // A recorded slot resolves with a key comparison and no hash lookup.
        assert_eq!(cache.get_at(first, &1).copied(), Some(10));
        assert_eq!(cache.get_at(second, &2).copied(), Some(20));

        // The wrong key for a slot and an out-of-range slot are both misses.
        assert_eq!(cache.get_at(first, &2), None);
        assert_eq!(cache.get_at(cache.capacity(), &1), None);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_get_at_rejects_stale_evicted_slot() {
        // Evicting key 1 reuses its slot for key 3. The stale hint fails the key
        // comparison while the new key resolves at the same slot.
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
    fn test_get_at_rejects_freed_slot() {
        // remove keeps the slot's stale key for allocation reuse, but get_at
        // must reject a freed slot without requiring external index cleanup.
        let mut cache = TestCache::new(NZUsize!(2));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        assert!(cache.remove(&1));
        assert_eq!(cache.get_at(slot, &1), None);

        // Reusing the slot for another key resolves the new key only.
        let (reused, value) = cache.get_or_insert_mut(2u64, || 0u64);
        *value = 20;
        assert_eq!(reused, slot);
        assert_eq!(cache.get_at(slot, &1), None);
        assert_eq!(cache.get_at(slot, &2).copied(), Some(20));
        cache.check_cache_invariants();
    }

    #[test]
    fn test_get_or_insert_mut_slot_is_stable_on_hit() {
        let mut cache = TestCache::new(NZUsize!(2));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (hit_slot, value) = cache.get_or_insert_mut(1u64, || unreachable!());
        assert_eq!(slot, hit_slot);
        assert_eq!(*value, 10);
        cache.check_cache_invariants();
    }

    #[test]
    fn test_get_mut_updates_resident_value() {
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        assert_eq!(cache.get_mut(&2), None);
        *cache.get_mut(&1).unwrap() = 11;
        assert_eq!(cache.get(&1).copied(), Some(11));
        cache.check_cache_invariants();
    }

    struct EarlyEvictionPolicy<K> {
        residents: Vec<Slot>,
        history: Vec<K>,
    }

    impl<K: Hash + Eq + Clone> Policy<K> for EarlyEvictionPolicy<K> {
        type SlotState = ();

        fn new(_capacity: NonZeroUsize) -> Self {
            Self {
                residents: Vec::new(),
                history: Vec::new(),
            }
        }

        fn hit(&self, _slot: Slot, _state: &()) {}

        fn hit_mut(&mut self, _slot: Slot, _state: &mut ()) {}

        fn insert<'a, I, C>(
            &mut self,
            _states: &I,
            _key: HashContext<'_, K>,
            has_vacancy: bool,
            claim: C,
        ) -> (Slot, ())
        where
            K: 'a,
            I: Index<Slot, Output = ()>,
            C: FnOnce(Option<Slot>) -> Claimed<'a, K>,
        {
            let slot = if let Some(&victim) = self.residents.first() {
                let Claimed::Evicted { key, .. } = claim(Some(victim)) else {
                    unreachable!("early eviction policy must evict a resident");
                };
                self.residents.remove(0);
                self.history.push(key.clone());
                victim
            } else {
                assert!(has_vacancy);
                let Claimed::Vacant(slot) = claim(None) else {
                    unreachable!("early eviction policy must claim vacant capacity");
                };
                slot
            };
            self.residents.push(slot);
            (slot, ())
        }

        fn remove(&mut self, slot: Option<Slot>, key: HashContext<'_, K>) {
            if let Some(slot) = slot {
                let position = self
                    .residents
                    .iter()
                    .position(|resident| *resident == slot)
                    .unwrap();
                self.residents.remove(position);
            }
            self.history.retain(|historical| historical != key.key());
        }

        fn clear(&mut self) {
            self.residents.clear();
            self.history.clear();
        }
    }

    #[test]
    fn test_policy_retains_independent_history_for_borrowed_keys() {
        let names = [String::from("first"), String::from("second")];
        let first = vec![names[0].as_str()];
        let second = vec![names[1].as_str()];
        let mut cache = Cache::<_, u64, EarlyEvictionPolicy<Vec<&str>>>::new(NZUsize!(2));
        cache.put(first.clone(), 1);
        cache.put(second.clone(), 2);
        assert_eq!(cache.policy.history, vec![first.clone()]);
        assert_eq!(cache.get(&first), None);
        assert_eq!(cache.get(&second), Some(&2));
        assert!(!cache.remove(&first));
        assert!(cache.policy.history.is_empty());
        cache.check_cache_invariants();
    }

    #[test]
    fn test_policy_can_evict_before_capacity() {
        let mut cache = Cache::<u64, u64, EarlyEvictionPolicy<u64>>::new(NZUsize!(3));
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
        Clear,
    }

    fn op_strategy(keys: u8) -> impl Strategy<Value = Op> {
        prop_oneof![
            8 => (0..keys).prop_map(Op::Get),
            8 => (0..keys).prop_map(Op::Peek),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::Put(k, v)),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::GetOrInsert(k, v)),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::GetOrInsertMut(k, v)),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::GetMut(k, v)),
            8 => (0..keys).prop_map(Op::Remove),
            8 => (0..keys).prop_map(Op::Retain),
            1 => Just(Op::Clear),
        ]
    }

    fn exercise_policy<P, F>(
        capacity: usize,
        keys: u8,
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
        // Oracle: last value written for each live key. A key the cache
        // reports as present must hold its last-written value (no stale or
        // conjured values); an evicted key is simply absent.
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
                Op::Clear => {
                    cache.clear();
                    model.clear();
                    prop_assert!(cache.is_empty());
                }
            }

            prop_assert!(cache.len() <= capacity);
            // The slot vector never exceeds capacity, proving reuse.
            prop_assert!(cache.slots.len() <= capacity);
            // Every present key holds its last-written value and was logically
            // inserted; absent keys are an allowed (evicted) state.
            for key in 0..keys {
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
            ops in proptest::collection::vec(op_strategy(16), 0..256),
        ) {
            exercise_policy::<Clock, _>(capacity, 16, prefill, ops, |cache| {
                cache.check_policy_invariants();
            })?;
        }

        #[test]
        fn clock2qplus_invariants_hold(
            capacity in 1usize..8,
            prefill in any::<bool>(),
            ops in proptest::collection::vec(op_strategy(16), 0..256),
        ) {
            exercise_policy::<clock2qplus::Clock2QPlus<u8>, _>(capacity, 16, prefill, ops, |cache| {
                cache.check_policy_invariants();
            })?;
        }

        // Small needs at least two slots to exercise demotion, promotion, and
        // correlation-boundary repair.
        #[test]
        fn clock2qplus_invariants_hold_with_wide_small(
            capacity in 20usize..48,
            prefill in any::<bool>(),
            ops in proptest::collection::vec(op_strategy(64), 0..512),
        ) {
            exercise_policy::<clock2qplus::Clock2QPlus<u8>, _>(capacity, 64, prefill, ops, |cache| {
                cache.check_policy_invariants();
            })?;
        }
    }
}

#[cfg(test)]
mod slot_index_tests;
