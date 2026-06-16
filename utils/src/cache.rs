//! A fixed-capacity cache with CLOCK eviction.
//!
//! [ClockCache] is a bounded key-value cache that uses the
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
//! # Concurrency
//!
//! [ClockCache] performs no internal locking. [ClockCache::get] takes `&self`
//! and is the only lookup that records use, so the cache can be wrapped in a
//! reader-writer lock and queried concurrently on the hit path. Misses, which
//! must insert, take `&mut self` and therefore the write lock:
//!
//! ```
//! use commonware_utils::ClockCache;
//! use core::num::NonZeroUsize;
//! use std::sync::RwLock;
//!
//! let cache = RwLock::new(ClockCache::<u64, u64>::new(NonZeroUsize::new(4).unwrap()));
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
//! use commonware_utils::ClockCache;
//! use core::num::NonZeroUsize;
//!
//! let mut cache = ClockCache::new(NonZeroUsize::new(2).unwrap());
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
    hash::Hash,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(not(feature = "std"))]
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

/// A single cache slot holding one live entry.
struct Slot<K, V> {
    key: K,
    value: V,
    referenced: AtomicBool,
}

/// A fixed-capacity key-value cache that evicts entries using the CLOCK
/// (second-chance) replacement policy.
///
/// See the [module documentation](self) for the policy and concurrency details.
pub struct ClockCache<K, V> {
    /// Maps each live key to the index of its slot in `slots`.
    ///
    /// Every slot is live and reachable from exactly one entry here, so
    /// `index.len() == slots.len()` always holds.
    index: HashMap<K, usize>,
    /// Backing storage for entries, grown lazily up to `capacity` and then
    /// reused in place as entries are evicted.
    slots: Vec<Slot<K, V>>,
    /// The clock hand: the next slot the evictor will examine.
    hand: usize,
    /// The maximum number of entries the cache will hold.
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V> ClockCache<K, V> {
    /// Creates a cache that holds at most `capacity` entries.
    pub fn new(capacity: NonZeroUsize) -> Self {
        let capacity = capacity.get();
        Self {
            index: HashMap::with_capacity(capacity),
            slots: Vec::with_capacity(capacity),
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
        let &slot = self.index.get(key)?;
        self.slots[slot].referenced.store(true, Ordering::Relaxed);
        Some(&self.slots[slot].value)
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
        self.insert_new(key, value);
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
            None => {
                let value = f();
                self.insert_new(key, value)
            }
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
            None => {
                let value = f()?;
                self.insert_new(key, value)
            }
        };
        Ok(&self.slots[slot].value)
    }

    /// Removes all entries, retaining the allocated capacity.
    pub fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.hand = 0;
    }

    /// Inserts a new entry (one whose key is absent) and returns its slot index.
    ///
    /// Grows into a fresh slot while below capacity; otherwise sweeps the clock
    /// hand to evict a slot and reuses it in place.
    fn insert_new(&mut self, key: K, value: V) -> usize {
        if self.slots.len() < self.capacity {
            let slot = self.slots.len();
            self.index.insert(key.clone(), slot);
            self.slots.push(Slot {
                key,
                value,
                referenced: AtomicBool::new(true),
            });
            return slot;
        }

        let len = self.slots.len();
        while self.slots[self.hand].referenced.load(Ordering::Relaxed) {
            self.slots[self.hand]
                .referenced
                .store(false, Ordering::Relaxed);
            self.hand = (self.hand + 1) % len;
        }

        let slot = self.hand;
        let evicted = core::mem::replace(&mut self.slots[slot].key, key.clone());
        self.slots[slot].value = value;
        self.slots[slot].referenced.store(true, Ordering::Relaxed);
        self.index.remove(&evicted);
        self.index.insert(key, slot);
        self.hand = (self.hand + 1) % len;
        slot
    }
}

impl<K, V> core::fmt::Debug for ClockCache<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClockCache")
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
    use std::rc::Rc;

    impl<K: Hash + Eq + Clone, V> ClockCache<K, V> {
        /// Asserts the structural invariants hold (test-only).
        fn check_invariants(&self) {
            assert!(self.slots.len() <= self.capacity);
            assert_eq!(self.index.len(), self.slots.len());
            if self.slots.is_empty() {
                assert_eq!(self.hand, 0);
            } else {
                assert!(self.hand < self.slots.len());
            }
            // Index is a bijection onto the live slots, and each slot's key
            // round-trips through the index.
            let mut seen = std::collections::HashSet::new();
            for (key, &slot) in &self.index {
                assert!(slot < self.slots.len());
                assert!(seen.insert(slot), "slot {slot} mapped twice");
                assert!(self.slots[slot].key == *key);
            }
        }
    }

    #[test]
    fn test_basic_put_get_peek() {
        let mut cache = ClockCache::new(NZUsize!(2));
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
        let mut cache = ClockCache::new(NZUsize!(2));
        assert_eq!(cache.put(1u64, 10u64), None);
        assert_eq!(cache.put(1, 11), Some(10));
        assert_eq!(cache.get(&1).copied(), Some(11));
        assert_eq!(cache.len(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_capacity_one_eviction() {
        let mut cache = ClockCache::new(NZUsize!(1));
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
        let mut cache = ClockCache::new(NZUsize!(3));
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
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);
        // Reference all three.
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
        let mut cache = ClockCache::new(NZUsize!(2));
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
        let mut cache = ClockCache::new(NZUsize!(2));

        let err: Result<&u64, &str> = cache.try_get_or_insert_with(1u64, || Err("bad"));
        assert_eq!(err, Err("bad"));
        assert!(!cache.contains(&1));

        let ok: Result<&u64, &str> = cache.try_get_or_insert_with(1, || Ok(10));
        assert_eq!(ok, Ok(&10));
        assert!(cache.contains(&1));
        cache.check_invariants();
    }

    #[test]
    fn test_clear() {
        let mut cache = ClockCache::new(NZUsize!(4));
        for i in 0..4u64 {
            cache.put(i, i);
        }
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        // Capacity and reuse still work after clear.
        cache.put(9, 9);
        assert_eq!(cache.get(&9).copied(), Some(9));
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
        let mut cache: ClockCache<u64, Tracked> = ClockCache::new(NZUsize!(2));
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

    #[derive(Clone, Debug)]
    enum Op {
        Get(u8),
        Peek(u8),
        Put(u8, u16),
        GetOrInsert(u8, u16),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..16).prop_map(Op::Get),
            (0u8..16).prop_map(Op::Peek),
            (0u8..16, any::<u16>()).prop_map(|(k, v)| Op::Put(k, v)),
            (0u8..16, any::<u16>()).prop_map(|(k, v)| Op::GetOrInsert(k, v)),
        ]
    }

    proptest! {
        #[test]
        fn prop_invariants_hold(
            cap in 1usize..8,
            ops in proptest::collection::vec(op_strategy(), 0..256),
        ) {
            let mut cache: ClockCache<u8, u16> = ClockCache::new(NonZeroUsize::new(cap).unwrap());
            for op in ops {
                match op {
                    Op::Get(k) => {
                        let got = cache.get(&k).copied();
                        prop_assert_eq!(got.is_some(), cache.contains(&k));
                    }
                    Op::Peek(k) => {
                        let peeked = cache.peek(&k).copied();
                        prop_assert_eq!(peeked.is_some(), cache.contains(&k));
                    }
                    Op::Put(k, v) => {
                        cache.put(k, v);
                        prop_assert_eq!(cache.get(&k).copied(), Some(v));
                    }
                    Op::GetOrInsert(k, v) => {
                        let existed = cache.contains(&k);
                        let stored = *cache.get_or_insert_with(k, || v);
                        if !existed {
                            prop_assert_eq!(stored, v);
                        }
                    }
                }
                prop_assert!(cache.len() <= cap);
                cache.check_invariants();
            }
        }
    }
}
