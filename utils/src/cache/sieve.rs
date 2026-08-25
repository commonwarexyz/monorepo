//! The SIEVE cache replacement policy.
//!
//! SIEVE keeps residents in a first-in, first-out queue ordered from the newest
//! entry at the head to the oldest entry at the tail. Each resident has one
//! visited bit, and an eviction hand moves from the tail toward the head.
//!
//! A hit sets the resident's visited bit without changing its queue position.
//! On a full-cache insertion, the hand examines residents until it finds an
//! unvisited victim. Visited residents have their bits cleared and remain in
//! place. The victim is removed, the hand remembers the next position toward
//! the head, and the new resident enters the head unvisited.
//!
//! Keeping survivors in place is the distinguishing feature of SIEVE. Older
//! residents that continue receiving hits survive repeated passes, while new
//! one-hit residents remain near the head and are reconsidered quickly as the
//! hand completes a pass. This provides scan resistance without moving queue
//! entries on the shared hit path.
//!
//! Resident keys and values remain in stable [super::Cache] slots. The visited
//! bit is stored inline as [Policy::SlotState], while insertion order and the
//! eviction hand are maintained by the policy.
//!
//! # References
//!
//! - [SIEVE is Simpler than LRU: an Efficient Turn-Key Eviction Algorithm for
//!   Web Caches](https://www.usenix.org/system/files/nsdi24-zhang-yazhuo.pdf),
//!   Algorithm 1.

use super::{Cache, Claimed, Policy, Slot};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{
    hash::Hash,
    num::NonZeroUsize,
    ops::Index,
    sync::atomic::{AtomicBool, Ordering},
};

/// Sentinel used when a policy-owned slot has no neighbor.
const UNLINKED: Slot = Slot::MAX;

/// Converts the internal link sentinel into an optional slot.
#[inline]
const fn linked(slot: Slot) -> Option<Slot> {
    if slot == UNLINKED { None } else { Some(slot) }
}

/// Policy-owned queue links for one stable cache slot.
#[derive(Clone, Copy)]
struct ResidentSlot {
    /// Previous resident toward the newer queue head.
    previous: Slot,
    /// Next resident toward the older queue tail.
    next: Slot,
}

impl Default for ResidentSlot {
    fn default() -> Self {
        Self {
            previous: UNLINKED,
            next: UNLINKED,
        }
    }
}

/// SIEVE admission and eviction policy.
///
/// SIEVE combines a FIFO queue with a backward-moving eviction hand. Shared
/// hits set one relaxed atomic bit and never mutate queue topology. Full-cache
/// insertions clear and skip visited residents, evict the first unvisited
/// resident, and insert the new resident at the queue head as unvisited.
pub struct Sieve {
    /// Queue links indexed by stable cache slot.
    slots: Vec<ResidentSlot>,
    /// Newest resident in insertion order.
    head: Option<Slot>,
    /// Oldest resident in insertion order.
    tail: Option<Slot>,
    /// Next resident examined during eviction.
    hand: Option<Slot>,
}

impl Sieve {
    /// Adds a detached slot at the queue head.
    #[inline]
    fn push(&mut self, slot: Slot) {
        let old_head = self.head;
        self.slots[slot] = ResidentSlot {
            previous: UNLINKED,
            next: old_head.unwrap_or(UNLINKED),
        };

        if let Some(head) = old_head {
            self.slots[head].previous = slot;
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
    }

    /// Detaches a resident from the queue and repairs the eviction hand.
    #[inline]
    fn unlink(&mut self, slot: Slot) {
        let ResidentSlot { previous, next } = self.slots[slot];

        if self.hand == Some(slot) {
            self.hand = linked(previous);
        }
        if previous != UNLINKED {
            self.slots[previous].next = next;
        } else {
            self.head = linked(next);
        }
        if next != UNLINKED {
            self.slots[next].previous = previous;
        } else {
            self.tail = linked(previous);
        }

        self.slots[slot] = ResidentSlot::default();
    }
}

impl<K> Policy<K> for Sieve {
    type SlotState = AtomicBool;

    #[inline]
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            slots: vec![ResidentSlot::default(); capacity.get()],
            head: None,
            tail: None,
            hand: None,
        }
    }

    #[inline]
    fn hit(&self, _slot: Slot, state: &AtomicBool) {
        // Skip the store when the bit is already set. Under concurrent readers,
        // an unconditional store would dirty the cache line on every hit and
        // bounce it between cores.
        if !state.load(Ordering::Relaxed) {
            state.store(true, Ordering::Relaxed);
        }
    }

    #[inline]
    fn hit_mut(&mut self, _slot: Slot, state: &mut AtomicBool) {
        *state.get_mut() = true;
    }

    #[inline]
    fn insert<I, C>(
        &mut self,
        states: &I,
        _key: &K,
        has_vacancy: bool,
        claim: C,
    ) -> (Slot, AtomicBool)
    where
        I: Index<Slot, Output = AtomicBool>,
        C: FnOnce(Option<Slot>) -> Claimed<K>,
    {
        if has_vacancy {
            let Claimed::Vacant(slot) = claim(None) else {
                unreachable!("vacancy claim returned an eviction");
            };
            self.push(slot);
            return (slot, AtomicBool::new(false));
        }

        let mut victim = self
            .hand
            .or(self.tail)
            .expect("a full SIEVE cache must have an eviction candidate");

        loop {
            let visited = &states[victim];
            if !visited.load(Ordering::Relaxed) {
                break;
            }

            // A visited resident survives in place. Clearing its bit gives the
            // next pass fresh evidence about whether it remains popular.
            visited.store(false, Ordering::Relaxed);
            victim = linked(self.slots[victim].previous)
                .or(self.tail)
                .expect("a full SIEVE cache must have a queue tail");
        }

        let next_hand = linked(self.slots[victim].previous);
        let Claimed::Evicted(_) = claim(Some(victim)) else {
            unreachable!("victim claim returned vacant capacity");
        };

        // Continue the next pass toward the head from the victim's previous
        // neighbor. A missing neighbor restarts the following pass at the tail.
        self.hand = next_hand;
        self.unlink(victim);
        self.push(victim);
        (victim, AtomicBool::new(false))
    }

    #[inline]
    fn remove(&mut self, slot: Option<Slot>, _key: &K) {
        if let Some(slot) = slot {
            self.unlink(slot);
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.slots.fill(ResidentSlot::default());
        self.head = None;
        self.tail = None;
        self.hand = None;
    }
}

impl<K: Hash + Eq + Clone, V> core::fmt::Debug for Cache<K, V, Sieve> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Sieve")
            .field("len", &self.index.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NZUsize, cache::Cache};
    use std::{collections::HashSet, sync::Arc, thread};

    type TestCache<K, V> = Cache<K, V, Sieve>;

    impl<K: Hash + Eq + Clone + core::fmt::Debug, V> Cache<K, V, Sieve> {
        /// Returns resident slots from the newest head to the oldest tail.
        fn order(&self) -> Vec<Slot> {
            let mut order = Vec::with_capacity(self.index.len());
            let mut current = self.policy.head;
            while let Some(slot) = current {
                order.push(slot);
                current = linked(self.policy.slots[slot].next);
            }
            order
        }

        /// Returns resident keys from the newest head to the oldest tail.
        fn keys(&self) -> Vec<K> {
            self.order()
                .into_iter()
                .map(|slot| self.slots[slot].key.clone())
                .collect()
        }

        /// Returns the key currently selected by the eviction hand.
        fn hand_key(&self) -> Option<&K> {
            self.policy.hand.map(|slot| &self.slots[slot].key)
        }

        /// Returns whether a resident's visited bit is set.
        fn visited(&self, key: &K) -> bool {
            let slot = self.index[key];
            self.slots[slot].state.load(Ordering::Relaxed)
        }

        /// Asserts the SIEVE policy's invariants hold.
        pub(crate) fn check_policy_invariants(&self) {
            assert_eq!(self.policy.slots.len(), self.capacity);
            assert_eq!(self.policy.head.is_none(), self.index.is_empty());
            assert_eq!(self.policy.tail.is_none(), self.index.is_empty());

            let mut resident = HashSet::new();
            let mut previous = UNLINKED;
            let mut current = self.policy.head;
            while let Some(slot) = current {
                assert!(slot < self.slots.len());
                assert!(resident.insert(slot), "duplicate SIEVE resident slot");
                assert!(self.slots[slot].live);
                assert_eq!(self.policy.slots[slot].previous, previous);
                assert_eq!(self.index.get(&self.slots[slot].key), Some(&slot));
                previous = slot;
                current = linked(self.policy.slots[slot].next);
            }
            assert_eq!(linked(previous), self.policy.tail);
            assert_eq!(resident.len(), self.index.len());

            for (key, &slot) in &self.index {
                assert!(resident.contains(&slot));
                assert_eq!(self.slots[slot].key, *key);
            }
            for slot in &self.free {
                assert!(!resident.contains(slot));
            }
            for slot in 0..self.slots.len() {
                if resident.contains(&slot) {
                    continue;
                }
                assert_eq!(self.policy.slots[slot].previous, UNLINKED);
                assert_eq!(self.policy.slots[slot].next, UNLINKED);
            }
            if let Some(hand) = self.policy.hand {
                assert!(resident.contains(&hand));
            }
        }

        /// Asserts both cache and SIEVE policy invariants hold.
        fn check_invariants(&self) {
            self.check_cache_invariants();
            self.check_policy_invariants();
        }
    }

    #[test]
    fn test_hand_moves_backward_without_moving_survivors() {
        // Algorithm 1 inserts at the head and begins the first pass at the
        // tail. Hits mark keys 1 and 3 without changing insertion order.
        let mut cache = TestCache::new(NZUsize!(4));
        for key in 1..=4u64 {
            cache.put(key, key * 10);
        }
        assert_eq!(cache.keys(), vec![4, 3, 2, 1]);
        assert_eq!(cache.hand_key(), None);
        assert_eq!(cache.get(&1), Some(&10));
        assert_eq!(cache.get(&3), Some(&30));

        // The first pass clears and retains key 1, then evicts unvisited key 2.
        // Key 1 remains at the tail and the hand continues at key 3.
        cache.put(5, 50);
        assert_eq!(cache.keys(), vec![5, 4, 3, 1]);
        assert_eq!(cache.hand_key(), Some(&3));
        assert!(cache.contains(&1));
        assert!(!cache.visited(&1));

        // The next pass retains key 3 in place and evicts key 4. Fresh key 5
        // is then unvisited at the head and is the following victim.
        cache.put(6, 60);
        assert_eq!(cache.keys(), vec![6, 5, 3, 1]);
        assert_eq!(cache.hand_key(), Some(&5));
        assert!(!cache.visited(&3));
        cache.put(7, 70);
        assert_eq!(cache.keys(), vec![7, 6, 3, 1]);
        assert_eq!(cache.hand_key(), Some(&6));
        assert!(!cache.contains(&5));
        cache.check_invariants();
    }

    #[test]
    fn test_full_visited_pass_wraps_and_clears_bits() {
        // When every resident has been visited, one full pass clears every bit
        // before wrapping to evict the oldest resident.
        let mut cache = TestCache::new(NZUsize!(3));
        for key in 1..=3u64 {
            cache.put(key, key);
            assert_eq!(cache.get(&key), Some(&key));
        }

        cache.put(4, 4);
        assert_eq!(cache.keys(), vec![4, 3, 2]);
        assert_eq!(cache.hand_key(), Some(&2));
        assert!(!cache.visited(&2));
        assert!(!cache.visited(&3));
        assert!(!cache.visited(&4));
        cache.check_invariants();
    }

    #[test]
    fn test_new_residents_enter_unvisited() {
        // Unlike CLOCK, SIEVE gives a new resident no automatic second chance.
        // With no intervening hit, the oldest entry is immediately eligible.
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        assert!(!cache.visited(&1));
        assert!(!cache.visited(&2));

        cache.put(3, 30);
        assert!(!cache.contains(&1));
        assert_eq!(cache.keys(), vec![3, 2]);
        assert!(!cache.visited(&3));
        cache.check_invariants();
    }

    #[test]
    fn test_existing_key_put_records_a_hit_without_reordering() {
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        cache.put(2, 20);

        // Replacing a resident value is a hit. It marks the entry visited but
        // leaves it at its original insertion position.
        assert_eq!(cache.put(1, 11), Some(10));
        assert_eq!(cache.keys(), vec![2, 1]);
        assert!(cache.visited(&1));

        // The recorded hit protects key 1 for this pass, so unvisited key 2 is
        // discarded even though it is newer in insertion order.
        cache.put(3, 30);
        assert!(cache.contains(&1));
        assert!(!cache.contains(&2));
        assert_eq!(cache.keys(), vec![3, 1]);
        cache.check_invariants();
    }

    #[test]
    fn test_capacity_one_clears_a_visit_then_reuses_the_slot() {
        let mut cache = TestCache::new(NZUsize!(1));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 10u64);
        assert_eq!(*value, 10);
        assert_eq!(cache.get(&1), Some(&10));

        // The only resident receives one pass to clear its bit, then its stable
        // slot and retained value are reused for the incoming key.
        let (reused, value) = cache.get_or_insert_mut(2, || unreachable!());
        assert_eq!(reused, slot);
        assert_eq!(*value, 10);
        *value = 20;
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&20));
        assert_eq!(cache.hand_key(), None);
        cache.check_invariants();
    }

    #[test]
    fn test_scan_retains_a_revisited_old_resident() {
        // Revisit the oldest resident before every insertion. Its visited bit
        // is refreshed between hand passes, so the scan entries are sifted out
        // while the resident remains in its original queue position.
        let mut cache = TestCache::new(NZUsize!(4));
        for key in 0..4u64 {
            cache.put(key, key);
        }
        for key in 4..100u64 {
            assert_eq!(cache.get(&0), Some(&0));
            cache.put(key, key);
            assert!(cache.contains(&0));
        }
        assert_eq!(cache.keys().last(), Some(&0));
        cache.check_invariants();
    }

    #[test]
    fn test_remove_and_retain_repair_the_hand_and_queue() {
        let mut cache = TestCache::new(NZUsize!(5));
        for key in 1..=5u64 {
            cache.put(key, key * 10);
        }
        assert_eq!(cache.get(&1), Some(&10));
        cache.put(6, 60);
        assert_eq!(cache.keys(), vec![6, 5, 4, 3, 1]);
        assert_eq!(cache.hand_key(), Some(&3));

        // Removing the hand advances it toward the head before detaching the
        // slot. Removing other residents preserves that repaired position.
        assert!(cache.remove(&3));
        assert_eq!(cache.hand_key(), Some(&4));
        assert!(!cache.remove(&3));
        cache.retain(|key, _| key % 2 == 1);
        assert_eq!(cache.keys(), vec![5, 1]);
        assert_eq!(cache.hand_key(), Some(&5));
        cache.check_invariants();

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.hand_key(), None);
        cache.check_invariants();
    }

    #[test]
    fn test_removing_non_hand_endpoints_preserves_the_hand() {
        let mut cache = TestCache::new(NZUsize!(4));
        for key in 1..=4u64 {
            cache.put(key, key);
        }
        assert_eq!(cache.get(&1), Some(&1));
        cache.put(5, 5);
        assert_eq!(cache.keys(), vec![5, 4, 3, 1]);
        assert_eq!(cache.hand_key(), Some(&3));

        // Removing the head or tail has no effect when neither is the current
        // hand. Their links are detached for later stable-slot reuse.
        let allocated = cache.slots.len();
        assert!(cache.remove(&5));
        assert_eq!(cache.hand_key(), Some(&3));
        assert!(cache.remove(&1));
        assert_eq!(cache.hand_key(), Some(&3));
        assert_eq!(cache.keys(), vec![4, 3]);

        cache.put(6, 6);
        cache.put(7, 7);
        assert_eq!(cache.slots.len(), allocated);
        assert_eq!(cache.keys(), vec![7, 6, 4, 3]);
        assert_eq!(cache.hand_key(), Some(&3));
        cache.check_invariants();
    }

    #[test]
    fn test_peek_does_not_mark_a_resident_visited() {
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        cache.put(2, 20);

        // A non-recording lookup leaves the oldest entry eligible, while get
        // would set its visited bit and protect it for this pass.
        assert_eq!(cache.peek(&1), Some(&10));
        cache.put(3, 30);
        assert!(!cache.contains(&1));
        assert!(cache.contains(&2));
        cache.check_invariants();
    }

    #[test]
    fn test_get_at_marks_a_resident_visited() {
        let mut cache = TestCache::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        let slot = cache.index[&1];

        // A validated stable-slot lookup records the same hit as a hash lookup.
        // The hand clears and skips key 1, then evicts unvisited key 2.
        assert_eq!(cache.get_at(slot, &1), Some(&10));
        cache.put(3, 30);
        assert!(cache.contains(&1));
        assert!(!cache.contains(&2));
        cache.check_invariants();
    }

    #[test]
    fn test_shared_hits_are_concurrent_and_do_not_reorder() {
        let mut cache = TestCache::new(NZUsize!(8));
        for key in 0..8u64 {
            cache.put(key, key);
        }
        let order = cache.keys();
        let cache = Arc::new(cache);
        let mut threads = Vec::new();
        for worker in 0..8u64 {
            let cache = Arc::clone(&cache);
            threads.push(thread::spawn(move || {
                for round in 0..10_000u64 {
                    let key = (worker + round) % 8;
                    assert_eq!(cache.get(&key), Some(&key));
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        // Shared hits update only relaxed atomic bits. The insertion-order
        // queue remains byte-for-byte equivalent from the policy's view.
        let cache = Arc::try_unwrap(cache).unwrap();
        assert_eq!(cache.keys(), order);
        assert!(cache.index.keys().all(|key| cache.visited(key)));
        cache.check_invariants();
    }
}
