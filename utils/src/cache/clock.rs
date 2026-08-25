//! CLOCK cache policy.
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
        state.store(true, Ordering::Relaxed);
    }

    #[inline]
    fn insert<I, C>(&mut self, states: &I, _key: &K, has_vacancy: bool, claim: C) -> AtomicBool
    where
        I: Index<Slot, Output = AtomicBool>,
        C: FnOnce(Option<Slot>) -> Claimed<K>,
    {
        if has_vacancy {
            // CLOCK admits into available capacity without scanning. Mark the
            // new resident referenced so it receives a full second chance.
            let _ = claim(None);
            return AtomicBool::new(true);
        }

        loop {
            let referenced = &states[self.hand];
            if !referenced.load(Ordering::Relaxed) {
                let victim = self.hand;
                let _ = claim(Some(victim));
                // Do not reconsider the new resident until the hand completes
                // a revolution.
                self.advance();
                return AtomicBool::new(true);
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
    fn retain<F: FnMut(&K) -> bool>(&mut self, _keep: F) {}

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
        fn check_clock_invariants(&self) {
            self.check_cache_invariants();
            if self.slots.is_empty() {
                assert_eq!(self.policy.hand, 0);
            } else {
                assert!(self.policy.hand < self.slots.len());
            }
        }
    }

    #[test]
    fn second_chance_protects_referenced_entry() {
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);

        // Sweep all three initial reference bits and evict key 1.
        cache.put(4, 40);
        assert!(!cache.contains(&1));

        // Protect key 2. The hand skips it and evicts unreferenced key 3.
        assert_eq!(cache.get(&2).copied(), Some(20));
        cache.put(5, 50);
        assert!(cache.contains(&2));
        assert!(!cache.contains(&3));
        assert!(cache.contains(&4));
        assert!(cache.contains(&5));
        cache.check_clock_invariants();
    }

    #[test]
    fn all_referenced_evicts_at_hand() {
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);

        // Re-reference every resident. The sweep clears all three bits, wraps,
        // and evicts key 1 at the initial hand position.
        assert!(cache.get(&1).is_some());
        assert!(cache.get(&2).is_some());
        assert!(cache.get(&3).is_some());

        cache.put(4, 40);
        assert!(!cache.contains(&1));
        assert!(cache.contains(&2));
        assert!(cache.contains(&3));
        assert!(cache.contains(&4));
        cache.check_clock_invariants();
    }

    #[test]
    fn get_at_records_use() {
        let mut cache = ClockCache::new(NZUsize!(3));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        cache.put(3, 30);
        cache.put(4, 40);

        // get_at records use like get, so key 2 receives a second chance and
        // unreferenced key 3 becomes the next victim.
        let slot = *cache.index.get(&2).unwrap();
        assert_eq!(cache.get_at(slot, &2).copied(), Some(20));
        cache.put(5, 50);
        assert!(cache.contains(&2));
        assert!(!cache.contains(&3));
        cache.check_clock_invariants();
    }

    #[test]
    fn peek_does_not_record_use() {
        fn setup() -> ClockCache<u64, u64> {
            let mut cache = ClockCache::new(NZUsize!(3));
            cache.put(1, 10);
            cache.put(2, 20);
            cache.put(3, 30);
            cache.put(4, 40);
            cache
        }

        // peek leaves key 2 unreferenced, so it remains the next victim.
        let mut cache = setup();
        assert_eq!(cache.peek(&2).copied(), Some(20));
        cache.put(5, 50);
        assert!(!cache.contains(&2));
        assert!(cache.contains(&3));

        // get sets key 2's bit, so the hand skips it and evicts key 3.
        let mut cache = setup();
        assert_eq!(cache.get(&2).copied(), Some(20));
        cache.put(5, 50);
        assert!(cache.contains(&2));
        assert!(!cache.contains(&3));
    }

    #[test]
    fn clear_resets_hand() {
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
        cache.check_clock_invariants();
    }

    #[test]
    fn concurrent_get_records_hits() {
        let mut cache = ClockCache::new(NZUsize!(64));
        for i in 0..64u64 {
            cache.put(i, i * 10);
        }

        // Hits update only atomic reference bits, so shared readers can record
        // use concurrently.
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
        for i in 0..64u64 {
            assert_eq!(cache.get(&i).copied(), Some(i * 10));
        }
        cache.check_clock_invariants();
    }
}
