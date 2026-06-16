//! A fixed-capacity cache with CLOCK eviction.
//!
//! [Clock] is a bounded key-value cache that uses the
//! [CLOCK](https://en.wikipedia.org/wiki/Page_replacement_algorithm#Clock)
//! (second-chance) replacement policy, a lightweight approximation of LRU. Each
//! slot carries a reference bit. Reading an entry sets its bit. When the cache
//! is full and a new entry must be inserted, a clock hand sweeps the slots:
//! every slot whose bit is set has it cleared and is skipped (granted a second
//! chance), and the first slot whose bit is clear is evicted.
//!
//! # Why CLOCK Instead of Exact LRU
//!
//! Exact LRU must move an entry to the front of a recency list on every read,
//! which requires exclusive (`&mut`) access. CLOCK only needs to set a reference
//! bit, which it does through a shared (`&self`) reference via an atomic. This
//! lets concurrent readers share the cache without serializing on a write lock,
//! at the cost of approximating (rather than exactly tracking) recency.
//!
//! # Allocation Reuse
//!
//! Slots are allocated lazily as the cache grows to capacity and are then reused
//! in place. Eviction, [Clock::remove], and [Clock::retain] never free
//! a slot's value; they detach the key and keep the slot (and its allocation)
//! for the next insert. [Clock::get_or_insert_mut] exposes the reused slot
//! as `&mut V` so callers holding pooled buffers can overwrite in place instead
//! of reallocating. The value-returning inserts ([Clock::put],
//! [Clock::get_or_insert_with]) drop the displaced value as usual.
//!
//! # Concurrency
//!
//! [Clock] performs no internal locking. [Clock::get] takes `&self`
//! and is the only lookup that records use, so the cache can be wrapped in a
//! reader-writer lock and queried concurrently on the hit path. Misses, which
//! must insert, take `&mut self` and therefore the write lock:
//!
//! ```
//! use commonware_utils::cache::Clock;
//! use core::num::NonZeroUsize;
//! use std::sync::RwLock;
//!
//! let cache = RwLock::new(Clock::<u64, u64>::new(NonZeroUsize::new(4).unwrap()));
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
//! use commonware_utils::cache::Clock;
//! use core::num::NonZeroUsize;
//!
//! let mut cache = Clock::new(NonZeroUsize::new(2).unwrap());
//!
//! // Compute an expensive value only on a miss.
//! let value = *cache.get_or_insert_with(1u64, || 1u64 * 1000);
//! assert_eq!(value, 1000);
//!
//! // A second lookup is served from the cache.
//! assert_eq!(cache.get(&1).copied(), Some(1000));
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{
    hash::{BuildHasher, Hash},
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(not(feature = "std"))]
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
type DefaultHashBuilder = std::collections::hash_map::RandomState;
#[cfg(not(feature = "std"))]
type DefaultHashBuilder = hashbrown::DefaultHashBuilder;

/// A single cache slot.
///
/// A slot is live when its key is present in the index, and free otherwise.
/// Free slots keep their (now stale) `key` and `value` until the slot is reused.
struct Slot<K, V> {
    key: K,
    value: V,
    referenced: AtomicBool,
}

/// A fixed-capacity key-value cache that evicts entries using the CLOCK
/// (second-chance) replacement policy.
///
/// See the [module documentation](self) for the policy, allocation reuse, and
/// concurrency details. `S` is the hash builder used for the key index; it
/// defaults to the standard library's DoS-resistant hasher (or hashbrown's
/// default under `no_std`). Use [Clock::with_hasher] to supply a faster
/// hasher when keys are not adversarial.
pub struct Clock<K, V, S = DefaultHashBuilder> {
    /// Maps each live key to the index of its slot in `slots`.
    ///
    /// `index.len() + free.len() == slots.len()` always holds.
    index: HashMap<K, usize, S>,
    /// Backing storage for slots, grown lazily up to `capacity` and then reused.
    slots: Vec<Slot<K, V>>,
    /// Slots detached from the index (by eviction overwrite never; by
    /// [Self::remove]/[Self::retain]) that are available for reuse.
    free: Vec<usize>,
    /// The clock hand: the next slot the evictor will examine.
    hand: usize,
    /// The maximum number of entries the cache will hold.
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V> Clock<K, V, DefaultHashBuilder> {
    /// Creates a cache that holds at most `capacity` entries, using the default
    /// hasher.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self::with_hasher(capacity, DefaultHashBuilder::default())
    }
}

impl<K: Hash + Eq + Clone, V, S: BuildHasher> Clock<K, V, S> {
    /// Creates a cache that holds at most `capacity` entries, using `hasher` for
    /// the key index.
    pub fn with_hasher(capacity: NonZeroUsize, hasher: S) -> Self {
        let capacity = capacity.get();
        Self {
            index: HashMap::with_capacity_and_hasher(capacity, hasher),
            slots: Vec::with_capacity(capacity),
            free: Vec::new(),
            hand: 0,
            capacity,
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
    /// Unlike [Self::get], this does not set the entry's reference bit, so it
    /// does not protect the entry from the next eviction sweep.
    #[inline]
    pub fn peek(&self, key: &K) -> Option<&V> {
        let &slot = self.index.get(key)?;
        Some(&self.slots[slot].value)
    }

    /// Returns a reference to the value for `key`, recording use.
    ///
    /// Recording use sets the entry's reference bit so the next eviction sweep
    /// grants it a second chance. This takes `&self` so it can be called
    /// concurrently behind a shared lock.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        let &index = self.index.get(key)?;
        let slot = &self.slots[index];
        slot.referenced.store(true, Ordering::Relaxed);
        Some(&slot.value)
    }

    /// Returns a mutable reference to the value for `key`, recording use.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let &index = self.index.get(key)?;
        let slot = &mut self.slots[index];
        slot.referenced.store(true, Ordering::Relaxed);
        Some(&mut slot.value)
    }

    /// Inserts `value` for `key`, recording use.
    ///
    /// If `key` was already present, replaces and returns the previous value. If
    /// inserting a new entry exceeds the capacity, the CLOCK evictor reclaims a
    /// slot first.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        if let Some(&slot) = self.index.get(&key) {
            self.slots[slot].referenced.store(true, Ordering::Relaxed);
            return Some(core::mem::replace(&mut self.slots[slot].value, value));
        }
        match self.take_slot() {
            Some(slot) => {
                self.slots[slot].key = key.clone();
                self.slots[slot].value = value;
                self.slots[slot].referenced.store(true, Ordering::Relaxed);
                self.index.insert(key, slot);
            }
            None => {
                self.grow(key, value);
            }
        }
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
                self.slots[slot].referenced.store(true, Ordering::Relaxed);
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
                self.slots[slot].referenced.store(true, Ordering::Relaxed);
                slot
            }
            None => self.insert_value(key, f()?),
        };
        Ok(&self.slots[slot].value)
    }

    /// Returns a mutable reference to the slot for `key`, recording use and
    /// reusing an existing allocation where possible.
    ///
    /// On a hit, returns the current value. On a miss into a reused slot (a
    /// freed slot or an eviction victim), the returned reference is the reused
    /// slot's stale value, which the caller is expected to overwrite. Only when
    /// the cache grows is `make` called to produce a fresh value. This lets
    /// callers holding pooled buffers overwrite in place rather than allocating
    /// on every insert.
    pub fn get_or_insert_mut<F: FnOnce() -> V>(&mut self, key: K, make: F) -> &mut V {
        let slot = match self.index.get(&key) {
            Some(&slot) => {
                self.slots[slot].referenced.store(true, Ordering::Relaxed);
                slot
            }
            None => match self.take_slot() {
                Some(slot) => {
                    self.slots[slot].key = key.clone();
                    self.slots[slot].referenced.store(true, Ordering::Relaxed);
                    self.index.insert(key, slot);
                    slot
                }
                None => {
                    let value = make();
                    self.grow(key, value)
                }
            },
        };
        &mut self.slots[slot].value
    }

    /// Removes `key`, returning whether it was present.
    ///
    /// The slot and its allocation are retained for reuse, so the value is not
    /// returned.
    pub fn remove(&mut self, key: &K) -> bool {
        match self.index.remove(key) {
            Some(slot) => {
                self.slots[slot].referenced.store(false, Ordering::Relaxed);
                self.free.push(slot);
                true
            }
            None => false,
        }
    }

    /// Retains only the entries for which `keep` returns `true`.
    ///
    /// Dropped entries' slots and allocations are retained for reuse.
    pub fn retain<F: FnMut(&K, &V) -> bool>(&mut self, mut keep: F) {
        let mut drop_keys: Vec<K> = Vec::new();
        for (key, &slot) in &self.index {
            if !keep(key, &self.slots[slot].value) {
                drop_keys.push(key.clone());
            }
        }
        for key in drop_keys {
            if let Some(slot) = self.index.remove(&key) {
                self.slots[slot].referenced.store(false, Ordering::Relaxed);
                self.free.push(slot);
            }
        }
    }

    /// Removes all entries, dropping their values and retaining the allocated
    /// capacity of the index and slot vector.
    pub fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.free.clear();
        self.hand = 0;
    }

    /// Pushes a brand new slot holding `(key, value)` and returns its index.
    ///
    /// Only called while the cache is below capacity.
    fn grow(&mut self, key: K, value: V) -> usize {
        let slot = self.slots.len();
        self.index.insert(key.clone(), slot);
        self.slots.push(Slot {
            key,
            value,
            referenced: AtomicBool::new(true),
        });
        slot
    }

    /// Inserts `value` for a `key` known to be absent, returning its slot.
    fn insert_value(&mut self, key: K, value: V) -> usize {
        match self.take_slot() {
            Some(slot) => {
                self.slots[slot].key = key.clone();
                self.slots[slot].value = value;
                self.slots[slot].referenced.store(true, Ordering::Relaxed);
                self.index.insert(key, slot);
                slot
            }
            None => self.grow(key, value),
        }
    }

    /// Selects a slot to receive a new entry, detaching it from the index.
    ///
    /// Returns a freed slot if any exist, otherwise an eviction victim chosen by
    /// the clock sweep. Returns `None` if the cache is below capacity and should
    /// grow instead. The returned slot keeps its stale value for reuse.
    fn take_slot(&mut self) -> Option<usize> {
        if let Some(slot) = self.free.pop() {
            return Some(slot);
        }
        if self.slots.len() < self.capacity {
            return None;
        }

        let len = self.slots.len();
        while self.slots[self.hand].referenced.load(Ordering::Relaxed) {
            self.slots[self.hand]
                .referenced
                .store(false, Ordering::Relaxed);
            self.hand = (self.hand + 1) % len;
        }
        let slot = self.hand;
        self.hand = (self.hand + 1) % len;
        let evicted = self.slots[slot].key.clone();
        self.index.remove(&evicted);
        Some(slot)
    }
}

impl<K: Hash + Eq + Clone + Default, V, S: BuildHasher> Clock<K, V, S> {
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
            self.slots.push(Slot {
                key: K::default(),
                value: make(),
                referenced: AtomicBool::new(false),
            });
            self.free.push(slot);
        }
        // The free list pops from the back, so reverse the new entries to hand
        // them out in ascending slot order (matching how growth assigns slots).
        self.free[start..].reverse();
    }
}

impl<K, V, S> core::fmt::Debug for Clock<K, V, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Clock")
            .field("len", &self.index.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NZUsize;
    use core::cell::Cell;
    use proptest::prelude::*;
    use std::{collections::HashMap, rc::Rc, thread};

    impl<K: Hash + Eq + Clone, V, S: BuildHasher> Clock<K, V, S> {
        /// Asserts the structural invariants hold (test-only).
        fn check_invariants(&self) {
            assert!(self.slots.len() <= self.capacity);
            assert_eq!(self.index.len() + self.free.len(), self.slots.len());
            if self.slots.is_empty() {
                assert_eq!(self.hand, 0);
            } else {
                assert!(self.hand < self.slots.len());
            }
            // The index is a bijection onto the live slots, each slot's key
            // round-trips, and live slots are disjoint from free slots.
            let free: std::collections::HashSet<usize> = self.free.iter().copied().collect();
            assert_eq!(free.len(), self.free.len(), "duplicate free slot");
            let mut seen = std::collections::HashSet::new();
            for (key, &slot) in &self.index {
                assert!(slot < self.slots.len());
                assert!(!free.contains(&slot), "slot {slot} both live and free");
                assert!(seen.insert(slot), "slot {slot} mapped twice");
                assert!(self.slots[slot].key == *key);
            }
        }
    }

    #[test]
    fn test_basic_put_get_peek() {
        let mut cache = Clock::new(NZUsize!(2));
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
        cache.check_invariants();
    }

    #[test]
    fn test_put_replaces_existing() {
        let mut cache = Clock::new(NZUsize!(2));
        assert_eq!(cache.put(1u64, 10u64), None);
        assert_eq!(cache.put(1, 11), Some(10));
        assert_eq!(cache.get(&1).copied(), Some(11));
        assert_eq!(cache.len(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_capacity_one_eviction() {
        let mut cache = Clock::new(NZUsize!(1));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        assert!(!cache.contains(&1));
        assert_eq!(cache.get(&2).copied(), Some(20));
        assert_eq!(cache.len(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_second_chance_protects_referenced_entry() {
        // New entries are inserted with their reference bit set, so a referenced
        // entry only beats an unreferenced one once some bits have been cleared.
        // Capacity 3, slots index by insertion order.
        let mut cache = Clock::new(NZUsize!(3));
        cache.put(1u64, 10u64); // slot 0, ref=1
        cache.put(2, 20); // slot 1, ref=1
        cache.put(3, 30); // slot 2, ref=1

        // Full and all referenced. Inserting key 4 sweeps slots 0,1,2 clearing
        // every bit, wraps to slot 0 (now clear), and evicts key 1. Hand -> 1.
        // State: slot0=key4(1), slot1=key2(0), slot2=key3(0).
        cache.put(4, 40);
        assert!(!cache.contains(&1));

        // Reference key 2 (slot 1), leaving key 3 (slot 2) unreferenced.
        assert_eq!(cache.get(&2).copied(), Some(20));

        // Inserting key 5 sweeps from slot 1: key 2's bit is set, so it is
        // cleared and skipped; slot 2 (key 3) is unreferenced and evicted.
        cache.put(5, 50);
        assert!(cache.contains(&2));
        assert!(!cache.contains(&3));
        assert!(cache.contains(&4));
        assert!(cache.contains(&5));
        cache.check_invariants();
    }

    #[test]
    fn test_all_referenced_evicts_hand_position() {
        // When every entry has been referenced, the sweep clears all bits and
        // evicts the slot the hand started on.
        let mut cache = Clock::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);
        assert!(cache.get(&1).is_some());
        assert!(cache.get(&2).is_some());
        assert!(cache.get(&3).is_some());

        // Hand is at slot 0 (key 1). Sweep clears all bits, lands back on slot 0.
        cache.put(4, 40);
        assert!(!cache.contains(&1));
        assert!(cache.contains(&2));
        assert!(cache.contains(&3));
        assert!(cache.contains(&4));
        cache.check_invariants();
    }

    #[test]
    fn test_get_or_insert_with_calls_f_only_on_miss() {
        let mut cache = Clock::new(NZUsize!(2));
        let calls = Cell::new(0);
        let compute = |k: u64| {
            calls.set(calls.get() + 1);
            k * 100
        };

        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        // Hit: f is not called.
        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_try_get_or_insert_with_does_not_cache_errors() {
        let mut cache = Clock::new(NZUsize!(2));

        let err: Result<&u64, &str> = cache.try_get_or_insert_with(1u64, || Err("bad"));
        assert_eq!(err, Err("bad"));
        assert!(!cache.contains(&1));

        let ok: Result<&u64, &str> = cache.try_get_or_insert_with(1, || Ok(10));
        assert_eq!(ok, Ok(&10));
        assert!(cache.contains(&1));
        cache.check_invariants();
    }

    #[test]
    fn test_remove_keeps_slot_for_reuse() {
        // A removed entry frees its slot for reuse without growing the slot
        // vector or calling the factory again.
        let makes = Cell::new(0);
        let mut cache: Clock<u64, u64> = Clock::new(NZUsize!(2));
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
        *cache.get_or_insert_mut(3, || {
            makes.set(makes.get() + 1);
            30
        }) = 30;
        assert_eq!(
            makes.get(),
            2,
            "freed slot should be reused, factory not called"
        );
        assert_eq!(cache.slots.len(), 2);
        assert_eq!(cache.get(&3).copied(), Some(30));
        assert!(!cache.remove(&999));
        cache.check_invariants();
    }

    #[test]
    fn test_retain() {
        let mut cache = Clock::new(NZUsize!(4));
        for i in 0..4u64 {
            cache.put(i, i * 10);
        }
        // Keep even keys.
        cache.retain(|k, _| k % 2 == 0);
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
        cache.check_invariants();
    }

    #[test]
    fn test_get_or_insert_mut_reuses_allocations() {
        // The factory runs at most `capacity` times no matter how many distinct
        // keys churn through the cache, proving evicted slots are reused.
        let makes = Cell::new(0);
        let mut cache: Clock<u64, u64> = Clock::new(NZUsize!(3));
        for k in 0..100u64 {
            let v = cache.get_or_insert_mut(k, || {
                makes.set(makes.get() + 1);
                0
            });
            *v = k; // overwrite the (possibly stale) reused slot
        }
        assert_eq!(makes.get(), 3, "factory should run only during growth");
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_invariants();
    }

    #[test]
    fn test_prefill_allocates_once_and_reuses() {
        // prefill runs the factory exactly capacity times; subsequent inserts
        // reuse pre-allocated slots without growing or calling the factory.
        let makes = Cell::new(0);
        let mut cache: Clock<u64, u64> = Clock::new(NZUsize!(3));
        cache.prefill(|| {
            makes.set(makes.get() + 1);
            0
        });
        assert_eq!(makes.get(), 3);
        assert_eq!(cache.slots.len(), 3);
        assert!(cache.is_empty());
        cache.check_invariants();

        // Churn many keys; no further factory calls, slot vector stays at capacity.
        for k in 0..100u64 {
            *cache.get_or_insert_mut(k, || {
                makes.set(makes.get() + 1);
                0
            }) = k;
        }
        assert_eq!(makes.get(), 3, "prefilled slots must be reused");
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_invariants();
    }

    #[test]
    fn test_clear() {
        let mut cache = Clock::new(NZUsize!(4));
        for i in 0..4u64 {
            cache.put(i, i);
        }
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.put(9, 9);
        assert_eq!(cache.get(&9).copied(), Some(9));
        cache.check_invariants();
    }

    #[test]
    fn test_with_hasher() {
        let mut cache: Clock<u64, u64, std::collections::hash_map::RandomState> =
            Clock::with_hasher(NZUsize!(2), std::collections::hash_map::RandomState::new());
        cache.put(1, 10);
        assert_eq!(cache.get(&1).copied(), Some(10));
        cache.check_invariants();
    }

    #[derive(Clone)]
    struct Tracked {
        _counter: Rc<Cell<usize>>,
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self._counter.set(self._counter.get() + 1);
        }
    }

    #[test]
    fn test_values_dropped_on_eviction_and_clear() {
        let drops = Rc::new(Cell::new(0));
        let mut cache: Clock<u64, Tracked> = Clock::new(NZUsize!(2));
        for i in 0..2u64 {
            cache.put(
                i,
                Tracked {
                    _counter: drops.clone(),
                },
            );
        }
        assert_eq!(drops.get(), 0);

        // Inserting a third entry evicts one (and drops its value).
        cache.put(
            2,
            Tracked {
                _counter: drops.clone(),
            },
        );
        assert_eq!(drops.get(), 1);

        // Replacing an existing key drops the old value.
        cache.put(
            2,
            Tracked {
                _counter: drops.clone(),
            },
        );
        assert_eq!(drops.get(), 2);

        // Clearing drops the remaining two values.
        cache.clear();
        assert_eq!(drops.get(), 4);
    }

    #[test]
    fn test_remove_retains_value_until_reuse() {
        // remove() does not drop the value; the freed slot keeps it until the
        // slot is reused by a value-inserting method.
        let drops = Rc::new(Cell::new(0));
        let mut cache: Clock<u64, Tracked> = Clock::new(NZUsize!(2));
        cache.put(
            1,
            Tracked {
                _counter: drops.clone(),
            },
        );
        assert!(cache.remove(&1));
        assert_eq!(drops.get(), 0, "remove must not drop the value");

        // Reusing the freed slot via a value insert drops the retained value.
        cache.put(
            2,
            Tracked {
                _counter: drops.clone(),
            },
        );
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn test_get_mut() {
        let mut cache = Clock::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        assert_eq!(cache.get_mut(&2), None);
        *cache.get_mut(&1).unwrap() = 11;
        assert_eq!(cache.get(&1).copied(), Some(11));
        cache.check_invariants();
    }

    #[test]
    fn test_peek_does_not_record_use() {
        // After this shared setup (capacity 3): slot1=key2 and slot2=key3 are
        // both unreferenced and the hand is at slot1. peek(&2) leaves key2
        // unreferenced, so the next insert evicts it; get(&2) sets its bit, so
        // key3 is evicted instead. This isolates the one behavioral difference
        // between peek and get.
        fn setup() -> Clock<u64, u64> {
            let mut c = Clock::new(NZUsize!(3));
            c.put(1, 10);
            c.put(2, 20);
            c.put(3, 30);
            c.put(4, 40); // evicts key1, clears key2/key3 bits, hand -> slot1
            c
        }

        // peek does NOT record use: key2 stays evictable.
        let mut c = setup();
        assert_eq!(c.peek(&2).copied(), Some(20));
        c.put(5, 50);
        assert!(!c.contains(&2), "peek must not protect key2 from eviction");
        assert!(c.contains(&3));

        // get DOES record use: key2 survives, key3 is evicted instead.
        let mut c = setup();
        assert_eq!(c.get(&2).copied(), Some(20));
        c.put(5, 50);
        assert!(c.contains(&2), "get must protect key2 from eviction");
        assert!(!c.contains(&3));
    }

    #[test]
    fn test_concurrent_get_is_sound() {
        // get(&self) records use through an atomic, so many threads can read
        // concurrently through a shared &Clock with no external lock.
        let mut cache: Clock<u64, u64> = Clock::new(NZUsize!(64));
        for i in 0..64u64 {
            cache.put(i, i * 10);
        }
        let cache = &cache;
        thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(move || {
                    for _ in 0..2_000 {
                        for i in 0..64u64 {
                            assert_eq!(cache.get(&i).copied(), Some(i * 10));
                        }
                    }
                });
            }
        });
        for i in 0..64u64 {
            assert_eq!(cache.get(&i).copied(), Some(i * 10));
        }
        cache.check_invariants();
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
            (0u8..16, any::<u16>()).prop_map(|(k, v)| Op::Put(k, v)),
            (0u8..16, any::<u16>()).prop_map(|(k, v)| Op::GetOrInsert(k, v)),
            (0u8..16, any::<u16>()).prop_map(|(k, v)| Op::GetOrInsertMut(k, v)),
            (0u8..16, any::<u16>()).prop_map(|(k, v)| Op::GetMut(k, v)),
            (0u8..16).prop_map(Op::Remove),
            (0u8..16).prop_map(Op::Retain),
        ]
    }

    const KEY_SPACE: u8 = 16;

    proptest! {
        #[test]
        fn prop_invariants_hold(
            cap in 1usize..8,
            prefill in any::<bool>(),
            ops in proptest::collection::vec(op_strategy(), 0..256),
        ) {
            let mut cache: Clock<u8, u16> = Clock::new(NonZeroUsize::new(cap).unwrap());
            if prefill {
                cache.prefill(|| 0u16);
            }
            // Oracle: last value written for each live key. A key the cache
            // reports as present must hold its last-written value (no stale or
            // conjured values); an evicted key is simply absent.
            let mut model: HashMap<u8, u16> = HashMap::new();
            for op in ops {
                match op {
                    Op::Get(k) => {
                        let got = cache.get(&k).copied();
                        prop_assert_eq!(got, cache.peek(&k).copied());
                    }
                    Op::Peek(k) => {
                        let _ = cache.peek(&k);
                    }
                    Op::Put(k, v) => {
                        cache.put(k, v);
                        model.insert(k, v);
                        prop_assert_eq!(cache.peek(&k).copied(), Some(v));
                    }
                    Op::GetOrInsert(k, v) => {
                        let stored = *cache.get_or_insert_with(k, || v);
                        model.insert(k, stored);
                        prop_assert_eq!(cache.peek(&k).copied(), Some(stored));
                    }
                    Op::GetOrInsertMut(k, v) => {
                        *cache.get_or_insert_mut(k, || v) = v;
                        model.insert(k, v);
                        prop_assert_eq!(cache.peek(&k).copied(), Some(v));
                    }
                    Op::GetMut(k, v) => {
                        if let Some(slot) = cache.get_mut(&k) {
                            *slot = v;
                            model.insert(k, v);
                        }
                    }
                    Op::Remove(k) => {
                        let had = cache.contains(&k);
                        prop_assert_eq!(cache.remove(&k), had);
                        model.remove(&k);
                        prop_assert!(!cache.contains(&k));
                    }
                    Op::Retain(k) => {
                        cache.retain(|key, _| *key < k);
                        model.retain(|key, _| *key < k);
                        prop_assert!(cache.len() <= usize::from(k).min(cap));
                    }
                }
                prop_assert!(cache.len() <= cap);
                // The slot vector never exceeds capacity, proving reuse.
                prop_assert!(cache.slots.len() <= cap);
                // Every present key holds its last-written value and was logically
                // inserted; absent keys are an allowed (evicted) state.
                for k in 0..KEY_SPACE {
                    let present = cache.contains(&k);
                    prop_assert_eq!(present, cache.peek(&k).is_some());
                    if present {
                        prop_assert_eq!(cache.peek(&k).copied(), model.get(&k).copied());
                    }
                }
                cache.check_invariants();
            }
        }
    }
}
