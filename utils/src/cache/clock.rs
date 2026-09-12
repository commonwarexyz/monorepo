//! The CLOCK cache replacement policy.
//!
//! CLOCK approximates least-recently-used replacement with one reference bit
//! per cache slot. A hit sets the bit. When the cache is full, a clock hand
//! clears set bits and skips those slots once, then replaces the first slot
//! whose bit is clear.
//!
//! The reference bit is stored inline as [Policy::SlotState]. It uses relaxed
//! atomic operations so [super::Cache::get] can record hits through a shared
//! reference. Admission and eviction still require exclusive access to the
//! cache.

use super::{Claimed, Policy, Slot};
use core::{
    num::NonZeroUsize,
    ops::Index,
    sync::atomic::{AtomicBool, Ordering},
};

/// CLOCK admission and eviction policy.
pub struct Clock {
    /// Next slot examined during eviction.
    hand: Slot,
    /// Maximum number of resident slots.
    capacity: usize,
}

impl<K> Policy<K> for Clock {
    type SlotState = AtomicBool;

    #[inline]
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            hand: 0,
            capacity: capacity.get(),
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
            // CLOCK admits into available capacity without scanning. Mark the
            // new resident referenced so it receives a full second chance.
            let Claimed::Vacant(slot) = claim(None) else {
                unreachable!("vacancy claim returned an eviction");
            };
            return (slot, AtomicBool::new(true));
        }

        loop {
            let referenced = &states[self.hand];
            if !referenced.load(Ordering::Relaxed) {
                let victim = self.hand;
                let Claimed::Evicted(_) = claim(Some(victim)) else {
                    unreachable!("victim claim returned vacant capacity");
                };

                // Do not reconsider the new resident until the hand completes
                // a revolution.
                self.advance();
                return (victim, AtomicBool::new(true));
            }

            // A set bit grants one second chance. Clear it and continue from
            // the following slot.
            referenced.store(false, Ordering::Relaxed);
            self.advance();
        }
    }

    #[inline]
    fn remove(&mut self, _slot: Option<Slot>, _key: &K) {}

    #[inline]
    fn clear(&mut self) {
        self.hand = 0;
    }
}

impl Clock {
    #[inline]
    const fn advance(&mut self) {
        self.hand += 1;
        if self.hand == self.capacity {
            self.hand = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NZUsize, cache::Cache};
    use core::hash::Hash;
    use std::thread;

    type ClockCache<K, V> = Cache<K, V, Clock>;

    impl<K: Hash + Eq + Clone, V> Cache<K, V, Clock> {
        /// Asserts the CLOCK policy's invariants hold.
        pub(crate) fn check_policy_invariants(&self) {
            if self.slots.is_empty() {
                assert_eq!(self.policy.hand, 0);
            } else {
                assert!(self.policy.hand < self.slots.len());
            }
        }

        /// Asserts both the cache and policy invariants hold.
        fn check_invariants(&self) {
            self.check_cache_invariants();
            self.check_policy_invariants();
        }
    }

    #[test]
    fn test_second_chance_protects_referenced_entry() {
        // New entries have their reference bit set, so a referenced entry only
        // beats an unreferenced one after some bits have been cleared.
        // Capacity is 3 and slots follow insertion order.
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64); // slot 0, referenced
        cache.put(2, 20); // slot 1, referenced
        cache.put(3, 30); // slot 2, referenced

        // With all residents referenced, inserting key 4 clears all three
        // bits, wraps to slot 0, and evicts key 1. The hand advances to slot 1.
        // Slot 0 now holds referenced key 4. Keys 2 and 3 are unreferenced.
        cache.put(4, 40);
        assert!(!cache.contains(&1));

        // Reference key 2 in slot 1, leaving key 3 in slot 2 unreferenced.
        assert_eq!(cache.get(&2).copied(), Some(20));

        // Inserting key 5 starts at slot 1. It clears and skips key 2, then
        // evicts unreferenced key 3 from slot 2.
        cache.put(5, 50);
        assert!(cache.contains(&2));
        assert!(!cache.contains(&3));
        assert!(cache.contains(&4));
        assert!(cache.contains(&5));
        cache.check_invariants();
    }

    #[test]
    fn test_all_referenced_evicts_at_hand() {
        // When every resident is referenced, the sweep clears all bits and
        // evicts the slot where the hand started.
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);

        assert!(cache.get(&1).is_some());
        assert!(cache.get(&2).is_some());
        assert!(cache.get(&3).is_some());

        // The hand starts at slot 0. The sweep clears every bit, wraps, and
        // evicts key 1 from slot 0.
        cache.put(4, 40);
        assert!(!cache.contains(&1));
        assert!(cache.contains(&2));
        assert!(cache.contains(&3));
        assert!(cache.contains(&4));
        cache.check_invariants();
    }

    #[test]
    fn test_get_at_records_use() {
        // After this setup, keys 2 and 3 are unreferenced and the hand points
        // at key 2. get_at must set key 2's bit so key 3 is evicted next.
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);
        cache.put(4, 40); // Evicts key 1 and clears the other reference bits.

        let slot = *cache.index.get(&2).unwrap();
        assert_eq!(cache.get_at(slot, &2).copied(), Some(20));
        cache.put(5, 50);
        assert!(cache.contains(&2), "get_at must protect key 2");
        assert!(!cache.contains(&3));
        cache.check_invariants();
    }

    #[test]
    fn test_peek_does_not_record_use() {
        // After this shared setup, keys 2 and 3 are unreferenced and the hand
        // points at key 2. peek leaves key 2 unreferenced, while get sets its
        // bit. This isolates the behavioral difference between peek and get.
        fn setup() -> ClockCache<u64, u64> {
            let mut cache = ClockCache::new(NZUsize!(3));
            cache.put(1, 10);
            cache.put(2, 20);
            cache.put(3, 30);
            cache.put(4, 40); // Evicts key 1 and clears the other reference bits.
            cache
        }

        // peek does not record use, so key 2 remains the next victim.
        let mut cache = setup();
        assert_eq!(cache.peek(&2).copied(), Some(20));
        cache.put(5, 50);
        assert!(!cache.contains(&2), "peek must not protect key 2");
        assert!(cache.contains(&3));

        // get records use, so key 2 survives and key 3 is evicted instead.
        let mut cache = setup();
        assert_eq!(cache.get(&2).copied(), Some(20));
        cache.put(5, 50);
        assert!(cache.contains(&2), "get must protect key 2");
        assert!(!cache.contains(&3));
    }

    #[test]
    fn test_clear_resets_hand() {
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);
        cache.put(4, 40);

        // The first eviction moves the hand away from its initial position.
        assert_ne!(cache.policy.hand, 0);

        // Clearing restores the initial hand position for the next population.
        cache.clear();
        assert_eq!(cache.policy.hand, 0);
        cache.put(5, 50);
        cache.check_invariants();
    }

    #[test]
    fn test_concurrent_get_records_hits() {
        // get records use through an atomic, so many threads can read through
        // a shared cache reference without an external lock.
        let mut cache = ClockCache::new(NZUsize!(64));
        for i in 0..64u64 {
            cache.put(i, i * 10);
        }

        // Clear the insertion marks so the readers must set every bit.
        for entry in &mut cache.slots {
            *entry.state.get_mut() = false;
        }

        let cache = &cache;
        thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(move || {
                    for _ in 0..2_000 {
                        for i in 0..64u64 {
                            assert_eq!(cache.get(&i).copied(), Some(i * 10));
                        }
                    }
                });
            }
        });
        assert!(
            cache
                .slots
                .iter()
                .all(|entry| entry.state.load(Ordering::Relaxed))
        );
        for i in 0..64u64 {
            assert_eq!(cache.get(&i).copied(), Some(i * 10));
        }
        cache.check_invariants();
    }
}
