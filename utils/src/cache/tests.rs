use super::*;
use crate::{NZUsize, sync::RwLock};
use core::cell::Cell;
use proptest::{prelude::*, test_runner::TestCaseResult};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    rc::Rc,
    sync::{Arc, Barrier},
    thread,
};

#[test]
fn test_basic_put_get_peek() {
    let mut cache = Cache::new(NZUsize!(2));
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
    let mut cache = Cache::new(NZUsize!(2));
    assert_eq!(cache.put(1u64, 10u64), None);
    assert_eq!(cache.put(1, 11), Some(10));
    assert_eq!(cache.get(&1).copied(), Some(11));
    assert_eq!(cache.len(), 1);
    cache.check_invariants();
}

#[test]
fn test_capacity_one_reuses_its_only_slot() {
    let mut cache = Cache::new(NZUsize!(1));
    cache.put(1u64, 10u64);
    cache.put(2, 20);
    assert!(!cache.contains(&1));
    assert_eq!(cache.get(&2).copied(), Some(20));
    assert_eq!(cache.len(), 1);
    cache.check_invariants();
}

#[test]
fn test_get_or_insert_with_calls_factory_only_on_miss() {
    let mut cache = Cache::new(NZUsize!(2));
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
    cache.check_invariants();
}

#[test]
fn test_try_get_or_insert_with_does_not_cache_errors() {
    let mut cache = Cache::new(NZUsize!(2));

    let error: Result<&u64, &str> = cache.try_get_or_insert_with(1u64, || Err("bad"));
    assert_eq!(error, Err("bad"));
    assert!(!cache.contains(&1));

    let value: Result<&u64, &str> = cache.try_get_or_insert_with(1, || Ok(10));
    assert_eq!(value, Ok(&10));
    assert!(cache.contains(&1));
    cache.check_invariants();
}

#[test]
fn test_remove_keeps_slot_for_reuse() {
    // A removed entry frees its slot for reuse without growing the slot
    // vector or calling the factory again.
    let makes = Cell::new(0);
    let mut cache = Cache::new(NZUsize!(2));
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
    cache.check_invariants();
}

#[test]
fn test_remove_if_outcomes_panic_and_reuse() {
    let mut cache = Cache::<u64, u64>::new(NZUsize!(1));
    let (slot, value) = cache.get_or_insert_mut(1, || 10);
    assert_eq!(*value, 10);

    let calls = Cell::new(0);
    assert_eq!(
        cache.remove_if(&2, |_| {
            calls.set(calls.get() + 1);
            true
        }),
        None
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(cache.bits(slot), 0);

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cache.remove_if(&1, |value| {
            calls.set(calls.get() + 1);
            assert_eq!(*value, 10);
            panic!("predicate panic");
        });
    }));
    assert!(panic.is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(cache.peek(&1), Some(&10));
    assert_eq!(cache.bits(slot), 0);
    assert!(cache.free.is_empty());
    cache.check_invariants();

    assert_eq!(
        cache.remove_if(&1, |value| {
            calls.set(calls.get() + 1);
            *value == 11
        }),
        Some(false)
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(cache.peek(&1), Some(&10));
    assert_eq!(cache.bits(slot), REFERENCED);

    cache.slots[slot].state.reset();
    assert_eq!(
        cache.remove_if(&1, |value| {
            calls.set(calls.get() + 1);
            *value == 10
        }),
        Some(true)
    );
    assert_eq!(calls.get(), 3);
    assert!(!cache.contains(&1));
    assert_eq!(cache.bits(slot), 0);
    assert_eq!(cache.free, vec![slot]);

    let (reused, value) = cache.get_or_insert_mut(2, || unreachable!());
    assert_eq!(reused, slot);
    assert_eq!(*value, 10);
    cache.check_invariants();
}

#[test]
fn test_retain_frees_slots_for_reuse() {
    let mut cache = Cache::new(NZUsize!(4));
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
    cache.check_invariants();
}

#[test]
fn test_get_or_insert_mut_reuses_allocations() {
    // The factory runs at most `capacity` times no matter how many distinct
    // keys churn through the cache, proving evicted slots are reused.
    let makes = Cell::new(0);
    let mut cache = Cache::new(NZUsize!(3));
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
    cache.check_invariants();
}

#[test]
fn test_prefill_allocates_once_and_reuses() {
    // Prefill runs the factory exactly `capacity` times. Subsequent inserts
    // reuse pre-allocated slots without growing or calling the factory.
    let makes = Cell::new(0);
    let mut cache = Cache::new(NZUsize!(3));
    cache.prefill(|| {
        makes.set(makes.get() + 1);
        0
    });
    assert_eq!(makes.get(), 3);
    assert_eq!(cache.slots.len(), 3);
    assert!(cache.is_empty());
    cache.check_invariants();

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
    cache.check_invariants();
}

#[test]
fn test_clear_drops_entries_and_allows_reuse() {
    let mut cache = Cache::new(NZUsize!(4));
    for key in 0..4u64 {
        cache.put(key, key);
    }
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
    cache.put(9, 9);
    assert_eq!(cache.get(&9).copied(), Some(9));
    cache.check_invariants();
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
    let mut cache = Cache::new(NZUsize!(2));
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
    let mut cache = Cache::new(NZUsize!(2));
    cache.put(1, Tracked(drops.clone()));
    assert!(cache.remove(&1));
    assert_eq!(drops.get(), 0, "remove must not drop the value");

    // Reusing the freed slot through a value insert drops the retained value.
    cache.put(2, Tracked(drops.clone()));
    assert_eq!(drops.get(), 1);
}

#[test]
fn test_get_at_validates_key() {
    let mut cache = Cache::new(NZUsize!(2));
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
    cache.check_invariants();
}

#[test]
fn test_get_at_rejects_stale_evicted_slot() {
    // Evicting key 1 reuses its slot for key 3. The stale hint fails the key
    // comparison while the new key resolves at the same slot.
    let mut cache = Cache::new(NZUsize!(1));
    let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
    *value = 10;
    let (reused, value) = cache.get_or_insert_mut(3u64, || 0u64);
    *value = 30;

    assert_eq!(slot, reused);
    assert_eq!(cache.get_at(slot, &1), None);
    assert_eq!(cache.get_at(slot, &3).copied(), Some(30));
    cache.check_invariants();
}

#[test]
fn test_get_at_rejects_freed_slot() {
    // remove keeps the slot's stale key for allocation reuse, but get_at
    // must reject a freed slot without requiring external index cleanup.
    let mut cache = Cache::new(NZUsize!(2));
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
    cache.check_invariants();
}

#[test]
fn test_get_or_insert_mut_slot_is_stable_on_hit() {
    let mut cache = Cache::new(NZUsize!(2));
    let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
    *value = 10;
    let (hit_slot, value) = cache.get_or_insert_mut(1u64, || unreachable!());
    assert_eq!(slot, hit_slot);
    assert_eq!(*value, 10);
    cache.check_invariants();
}

#[test]
fn test_get_mut_updates_resident_value() {
    let mut cache = Cache::new(NZUsize!(2));
    cache.put(1u64, 10u64);
    assert_eq!(cache.get_mut(&2), None);
    *cache.get_mut(&1).unwrap() = 11;
    assert_eq!(cache.get(&1).copied(), Some(11));
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

fn exercise_cache(capacity: usize, keys: u8, prefill: bool, ops: Vec<Op>) -> TestCaseResult {
    let mut cache = Cache::<u8, u16>::new(NonZeroUsize::new(capacity).unwrap());
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
        cache.check_invariants();
    }

    Ok(())
}

proptest! {
    #[test]
    fn cache_invariants_hold(
        capacity in 1usize..8,
        prefill in any::<bool>(),
        ops in proptest::collection::vec(op_strategy(16), 0..256),
    ) {
        exercise_cache(capacity, 16, prefill, ops)?;
    }

    // Small needs at least two slots to exercise demotion, promotion, and
    // correlation-boundary repair.
    #[test]
    fn cache_invariants_hold_with_wide_small(
        capacity in 20usize..48,
        prefill in any::<bool>(),
        ops in proptest::collection::vec(op_strategy(64), 0..512),
    ) {
        exercise_cache(capacity, 64, prefill, ops)?;
    }
}
impl<K> GhostQueue<K> {
    fn check_free_slots(&self) -> HashSet<usize> {
        let mut free = HashSet::new();
        let mut current = self.free_head;
        while let Some(slot) = current {
            assert!(free.insert(slot), "duplicate Ghost free slot {slot}");
            let entry = &self.slots[slot];
            assert!(entry.key.is_none());
            assert_eq!(entry.prev, UNLINKED);
            current = linked(entry.next);
        }
        assert_eq!(self.index.len() + free.len(), self.slots.len());
        free
    }
}

impl<K: Hash + Eq, V> Cache<K, V> {
    /// Returns the inline replacement state for a resident slot.
    fn bits(&self, slot: Slot) -> u8 {
        self.slots[slot].state.0.load(Ordering::Relaxed)
    }

    /// Returns Small slot order from newest to oldest.
    fn small_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.small.len);
        let mut current = self.small.head;
        while let Some(slot) = current {
            order.push(slot);
            current = linked(self.topology[slot].next);
        }
        order
    }

    /// Returns Main slot order starting at the CLOCK hand.
    fn main_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.main.len);
        let Some(hand) = self.main.hand else {
            return order;
        };
        let mut current = hand;
        loop {
            order.push(current);
            current = self.topology[current].next;
            assert_ne!(current, UNLINKED);
            if current == hand {
                return order;
            }
        }
    }

    /// Returns Ghost slot order from newest to oldest.
    fn ghost_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.ghost.index.len());
        let mut current = self.ghost.head;
        while let Some(slot) = current {
            order.push(slot);
            current = linked(self.ghost.slots[slot].next);
        }
        order
    }

    /// Returns Small keys from newest to oldest.
    fn small_keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.small_order()
            .into_iter()
            .map(|slot| self.slots[slot].key.clone())
            .collect()
    }

    /// Returns Main keys starting at the CLOCK hand.
    fn main_keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.main_order()
            .into_iter()
            .map(|slot| self.slots[slot].key.clone())
            .collect()
    }

    /// Returns Ghost keys from newest to oldest.
    fn ghost_keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.ghost_order()
            .into_iter()
            .map(|slot| {
                self.ghost.slots[slot]
                    .key
                    .as_ref()
                    .expect("live Ghost entry must have a key")
                    .clone()
            })
            .collect()
    }

    /// Asserts resident ownership, queue topology, and exact history agree.
    pub(super) fn check_invariants(&self) {
        assert!(self.slots.len() <= self.capacity);
        assert_eq!(self.topology.len(), self.capacity);
        assert!(self.small.len <= self.small.capacity);
        assert!(self.main.len <= self.main.capacity);
        assert_eq!(self.index.len(), (self.small.len + self.main.len));
        assert_eq!(self.index.len() + self.free.len(), self.slots.len());

        let free: HashSet<_> = self.free.iter().copied().collect();
        assert_eq!(free.len(), self.free.len(), "duplicate resident free slot");
        let small = self.small_order();
        let main = self.main_order();
        assert_eq!(small.len(), self.small.len);
        assert_eq!(main.len(), self.main.len);
        let young_len = self
            .small
            .young_tail
            .map(|tail| {
                small
                    .iter()
                    .position(|slot| *slot == tail)
                    .expect("correlation boundary must belong to Small")
                    + 1
            })
            .unwrap_or(0);
        assert!(self.small.admissions <= ADMISSION_GENERATION_MASK);
        assert!(young_len <= self.small.correlation_window);
        assert!(young_len <= self.small.len);

        let mut resident = HashSet::new();
        for (rank, &slot) in small.iter().enumerate() {
            assert!(resident.insert(slot), "duplicate Small resident {slot}");
            assert!(self.slots[slot].live);
            assert_eq!(self.topology[slot].location(), Location::Small);
            let state = self.bits(slot);
            let young = rank < young_len;
            assert_eq!(state & CORRELATED != 0, young);
            if young {
                assert_eq!(state, CORRELATED);
                let age = self
                    .small
                    .admissions
                    .wrapping_sub(self.topology[slot].admitted_at())
                    & ADMISSION_GENERATION_MASK;
                assert!(age < self.small.correlation_window);
            }
            let expected_prev = rank.checked_sub(1).map(|rank| small[rank]);
            let expected_next = small.get(rank + 1).copied();
            assert_eq!(linked(self.topology[slot].prev), expected_prev);
            assert_eq!(linked(self.topology[slot].next), expected_next);
        }
        assert_eq!(self.small.head, small.first().copied());
        assert_eq!(self.small.tail, small.last().copied());
        let expected_young_tail = young_len
            .checked_sub(1)
            .and_then(|rank| small.get(rank))
            .copied();
        assert_eq!(self.small.young_tail, expected_young_tail);

        for (rank, &slot) in main.iter().enumerate() {
            assert!(resident.insert(slot), "resident {slot} in two queues");
            assert!(self.slots[slot].live);
            assert_eq!(self.topology[slot].location(), Location::Main);
            assert_eq!(self.topology[slot].admitted_at(), 0);
            assert_eq!(self.bits(slot) & CORRELATED, 0);
            assert_eq!(
                self.topology[slot].prev,
                main[(rank + main.len() - 1) % main.len()]
            );
            assert_eq!(self.topology[slot].next, main[(rank + 1) % main.len()]);
        }

        let indexed: HashSet<_> = self.index.iter().copied().collect();
        assert_eq!(indexed.len(), self.index.len(), "duplicate indexed slot");
        assert_eq!(indexed, resident);
        for &slot in &self.index {
            assert!(slot < self.slots.len());
            assert!(resident.contains(&slot));
            assert_eq!(self.find_slot(&self.slots[slot].key), Some(slot));
        }
        for slot in 0..self.slots.len() {
            if resident.contains(&slot) {
                assert!(!free.contains(&slot));
            } else {
                assert!(free.contains(&slot));
                assert!(!self.slots[slot].live);
                assert_eq!(self.topology[slot].location(), Location::Free);
                assert_eq!(self.topology[slot].admitted_at(), 0);
            }
        }
        for slot in self.slots.len()..self.topology.len() {
            assert_eq!(self.topology[slot].location(), Location::Free);
            assert_eq!(self.topology[slot].admitted_at(), 0);
        }

        assert!(self.ghost.index.len() <= self.ghost.capacity);
        let ghost = self.ghost_order();
        assert_eq!(ghost.len(), self.ghost.index.len());
        let ghost_free = self.ghost.check_free_slots();
        let mut seen_ghost = HashSet::new();
        for (rank, &slot) in ghost.iter().enumerate() {
            assert!(seen_ghost.insert(slot));
            assert!(!ghost_free.contains(&slot));
            let key = self.ghost.slots[slot]
                .key
                .as_ref()
                .expect("linked Ghost entry must have a key");
            assert_eq!(
                self.ghost
                    .index
                    .find(self.hasher.hash_one(key), |candidate| {
                        self.ghost.slots[*candidate].key.as_ref() == Some(key)
                    }),
                Some(&slot),
            );
            assert!(!self.contains(key));
            let expected_prev = rank.checked_sub(1).map(|rank| ghost[rank]);
            let expected_next = ghost.get(rank + 1).copied();
            assert_eq!(linked(self.ghost.slots[slot].prev), expected_prev);
            assert_eq!(linked(self.ghost.slots[slot].next), expected_next);
        }
        assert_eq!(self.ghost.head, ghost.first().copied());
        assert_eq!(self.ghost.tail, ghost.last().copied());
        for (slot, entry) in self.ghost.slots.iter().enumerate() {
            if seen_ghost.contains(&slot) {
                assert!(entry.key.is_some());
            } else {
                assert!(ghost_free.contains(&slot));
                assert!(entry.key.is_none());
            }
        }
    }
}

#[test]
fn test_resident_metadata_fits_three_words_and_preserves_links() {
    assert_eq!(
        core::mem::size_of::<ResidentSlot>(),
        3 * core::mem::size_of::<usize>()
    );

    let mut slot = ResidentSlot {
        prev: usize::MAX - 1,
        next: usize::MAX - 2,
        location_and_admission: Location::Small.pack(ADMISSION_GENERATION_MASK),
    };
    assert_eq!(slot.location(), Location::Small);
    assert_eq!(slot.admitted_at(), ADMISSION_GENERATION_MASK);
    assert_eq!(slot.prev, usize::MAX - 1);
    assert_eq!(slot.next, usize::MAX - 2);

    slot.location_and_admission = Location::Main.pack(0);
    assert_eq!(slot.location(), Location::Main);
    assert_eq!(slot.admitted_at(), 0);
    assert_eq!(slot.prev, usize::MAX - 1);
    assert_eq!(slot.next, usize::MAX - 2);

    slot.location_and_admission = Location::Free.pack(0);
    assert_eq!(slot.location(), Location::Free);
    assert_eq!(slot.admitted_at(), 0);
}

#[test]
fn test_partitions_round_for_tiny_capacities() {
    // Ratio-derived partitions round down and the correlation window rounds
    // up. Capacities above one still keep at least one Small slot, while
    // capacity one uses Main alone.
    let expected = [
        (1, 0, 1, 0, 0),
        (2, 1, 1, 1, 1),
        (10, 1, 9, 1, 5),
        (11, 1, 10, 1, 5),
        (20, 2, 18, 1, 10),
        (40, 4, 36, 2, 20),
    ];
    for (capacity, small, main, window, ghost) in expected {
        let cache = Cache::<u64, u64>::new(NonZeroUsize::new(capacity).unwrap());
        assert_eq!(cache.small.capacity, small);
        assert_eq!(cache.main.capacity, main);
        assert_eq!(cache.small.correlation_window, window);
        assert_eq!(cache.ghost.capacity, ghost);
        cache.check_invariants();
    }

    // Exercise every tiny partition through repeated replacement, where
    // off-by-one errors in the queue bounds are easiest to expose.
    for capacity in 1..=20 {
        let mut cache = Cache::new(NonZeroUsize::new(capacity).unwrap());
        for key in 0..200u64 {
            cache.put(key, key);
            cache.check_invariants();
        }
    }
}

#[test]
fn test_capacity_one_behaves_as_clock() {
    // With no Small or Ghost capacity, the only Main slot is replaced on
    // each cold insertion.
    let mut cache = Cache::new(NZUsize!(1));
    cache.put(1u64, 10u64);
    assert_eq!(cache.get(&1), Some(&10));
    cache.put(2, 20);
    assert_eq!(cache.get(&1), None);
    assert_eq!(cache.get(&2), Some(&20));
    assert!(cache.ghost_keys().is_empty());
    cache.check_invariants();
}

#[test]
fn test_warmup_fills_small_then_main_with_cold_entries() {
    // Warm-up fills the 10% Small partition first, then uses the remaining
    // vacant slots for unreferenced Main residents.
    let mut cache = Cache::new(NZUsize!(20));
    for key in 0..20u64 {
        cache.put(key, key);
    }

    assert_eq!(cache.small_keys(), vec![1, 0]);
    assert_eq!(cache.main_keys(), (2..20).collect::<Vec<_>>());
    for key in 2..20u64 {
        let slot = cache.find_slot(&key).unwrap();
        assert_eq!(cache.bits(slot) & REFERENCED, 0);
    }
    cache.check_invariants();
}

#[test]
fn test_empty_residents_preserve_precise_ghost_history() {
    // Resident filtering does not erase unrelated Ghost evidence. The
    // cache may therefore retain useful history with no live residents.
    let mut cache = Cache::new(NZUsize!(2));
    for key in 1..=3u64 {
        cache.put(key, key);
    }
    assert_eq!(cache.ghost_keys(), vec![1]);

    cache.retain(|key, _| *key == 1);
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.ghost_keys(), vec![1]);
    assert!(!cache.ghost.index.is_empty());

    cache.retain(|_, _| false);
    assert_eq!(cache.small.len + cache.main.len, 0);
    assert_eq!(cache.ghost_keys(), vec![1]);
    cache.check_invariants();
}

#[test]
fn test_remove_if_miss_preserves_ghost_history() {
    let mut cache = Cache::new(NZUsize!(2));
    for key in 1..=3u64 {
        cache.put(key, key);
    }
    assert_eq!(cache.ghost_keys(), vec![1]);

    assert_eq!(cache.remove_if(&1, |_| unreachable!()), None);
    assert_eq!(cache.ghost_keys(), vec![1]);
    cache.put(1, 10);
    assert!(cache.main_keys().contains(&1));
    assert!(!cache.ghost_keys().contains(&1));
    cache.check_invariants();

    let mut cache = Cache::new(NZUsize!(2));
    for key in 1..=3u64 {
        cache.put(key, key);
    }
    assert!(!cache.remove(&1));
    assert!(cache.ghost_keys().is_empty());
    cache.put(1, 10);
    assert!(cache.small_keys().contains(&1));
    assert!(!cache.main_keys().contains(&1));
    cache.check_invariants();
}

#[test]
fn test_correlation_window_ignores_only_young_hits() {
    // Key 4 is at the Small head, inside the two-entry correlation window.
    // Its hit must not set the bit, so a scan ages and evicts it to Ghost.
    let mut correlated = Cache::new(NZUsize!(40));
    for key in 1..=40u64 {
        correlated.put(key, key);
    }
    assert_eq!(correlated.small_keys(), vec![4, 3, 2, 1]);
    assert_eq!(correlated.get(&4), Some(&4));
    let slot = correlated.find_slot(&4).unwrap();
    assert_eq!(correlated.bits(slot) & REFERENCED, 0);
    for key in 41..=44u64 {
        correlated.put(key, key);
    }
    assert!(!correlated.contains(&4));
    assert!(!correlated.main_keys().contains(&4));
    assert!(correlated.ghost_keys().contains(&4));
    correlated.check_invariants();

    // Key 1 is already outside the window. Its hit marks it for promotion
    // to Main when the next insertion examines the Small tail.
    let mut reused = Cache::new(NZUsize!(40));
    for key in 1..=40u64 {
        reused.put(key, key);
    }
    assert_eq!(reused.get(&1), Some(&1));
    reused.put(41, 41);
    assert!(reused.small_keys().contains(&41));
    assert!(reused.main_keys().contains(&1));
    let slot = reused.find_slot(&1).unwrap();
    assert_eq!(reused.bits(slot) & REFERENCED, 0);
    assert!(reused.ghost_keys().is_empty());
    reused.check_invariants();
}

#[test]
fn test_removing_younger_entry_does_not_rewind_correlation_age() {
    let mut cache = Cache::new(NZUsize!(20));
    for key in 0..20u64 {
        cache.put(key, key);
    }

    // Key 0 has left the correlation window, so this hit makes it eligible
    // for promotion when it reaches the Small tail.
    assert_eq!(cache.get(&0), Some(&0));

    // Removing the younger key must not move key 0 back into the
    // correlation window or discard its eligible reference.
    assert!(cache.remove(&1));
    cache.put(20, 20);
    cache.put(21, 21);

    assert!(cache.main_keys().contains(&0));
    assert!(!cache.ghost_keys().contains(&0));
    cache.check_invariants();
}

#[test]
fn test_removing_younger_entry_does_not_delay_correlation_age() {
    let mut cache = Cache::new(NZUsize!(40));
    for key in 0..40u64 {
        cache.put(key, key);
    }
    assert_eq!(cache.small_keys(), vec![3, 2, 1, 0]);

    // Removing key 3 must not erase its admission from key 2's age. Key 40
    // is the second later Small admission, so key 2 leaves the window.
    assert!(cache.remove(&3));
    cache.put(40, 40);
    assert_eq!(cache.get(&2), Some(&2));

    // Advance key 2 to the Small tail. Its eligible hit must promote it
    // into Main instead of letting the final insertion evict it to Ghost.
    for key in 41..=43u64 {
        cache.put(key, key);
    }
    assert!(cache.main_keys().contains(&2));
    assert!(!cache.ghost_keys().contains(&2));
    cache.check_invariants();
}

#[test]
fn test_ghost_history_is_bounded_and_promotes_reuse() {
    // Cold churn fills the ten-entry Ghost queue and drops its oldest key.
    let mut cache = Cache::new(NZUsize!(20));
    for key in 0..=30u64 {
        cache.put(key, key);
    }
    assert_eq!(cache.small_keys(), vec![30, 29]);
    assert_eq!(cache.main_keys(), (2..20).collect::<Vec<_>>());
    assert_eq!(
        cache.ghost_keys(),
        (20..=28)
            .rev()
            .chain(core::iter::once(1))
            .collect::<Vec<_>>()
    );

    // Key 1 is still in Ghost, so reuse consumes its history and admits it
    // directly to Main without disturbing Small.
    let (_, value) = cache.get_or_insert_mut(1, || unreachable!());
    *value = 100;
    assert_eq!(cache.peek(&1), Some(&100));
    assert!(cache.main_keys().contains(&1));
    assert!(!cache.ghost_keys().contains(&1));
    assert_eq!(cache.small_keys(), vec![30, 29]);
    assert_eq!(cache.ghost_keys(), (20..=28).rev().collect::<Vec<_>>());

    // Key 0 has already aged out of Ghost and therefore enters Small as a
    // cold miss, evicting Small's tail into Ghost.
    cache.put(0, 200);
    assert_eq!(cache.small_keys()[0], 0);
    assert!(!cache.main_keys().contains(&0));
    assert_eq!(cache.ghost_keys()[0], 29);
    cache.check_invariants();
}

#[test]
fn test_main_evicts_despite_an_offered_vacancy() {
    // Removing the Small resident leaves a globally vacant slot while Main
    // remains full and key 1 remains in Ghost.
    let mut cache = Cache::new(NZUsize!(2));
    for key in 1..=3u64 {
        cache.put(key, key);
    }
    assert_eq!(cache.main_keys(), vec![2]);
    assert!(cache.remove(&3));
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.ghost_keys(), vec![1]);

    // Ghost reuse is constrained to Main, so it replaces Main key 2 and
    // deliberately leaves the Small vacancy unused.
    cache.put(1, 10);
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.main_keys(), vec![1]);
    assert!(!cache.contains(&2));
    assert_eq!(cache.free.len(), 1);
    cache.check_invariants();
}

#[test]
fn test_promoting_small_replaces_from_full_main() {
    // Reference the original Small tail so the next cold miss promotes it
    // while keeping both fixed-size resident partitions full.
    let mut cache = Cache::new(NZUsize!(20));
    for key in 0..20u64 {
        cache.put(key, key);
    }
    for key in 0..18u64 {
        assert_eq!(cache.get(&key), Some(&key));
    }
    cache.put(20, 20);
    assert_eq!(cache.main.len, cache.main.capacity);
    assert_eq!(cache.small.len, 2);
    let slot = cache.find_slot(&0).unwrap();
    assert_eq!(cache.bits(slot) & REFERENCED, 0);

    // The sweep evicted key 18 and left the hand on key 19. The promoted
    // key links immediately before the hand, so it is swept last.
    assert_eq!(
        cache.main_keys(),
        core::iter::once(19)
            .chain(2..=17)
            .chain(core::iter::once(0))
            .collect::<Vec<_>>()
    );

    // Repeat the transition with a full Main CLOCK. The promoted key keeps
    // its slot and starts in Main with a clear reference bit.
    let promoted = *cache.small_keys().last().unwrap();
    assert_eq!(promoted, 1);
    assert_eq!(cache.get(&promoted), Some(&promoted));
    cache.put(21, 21);

    // Key 19 was unreferenced at the hand, so it is evicted and the hand
    // moves to key 2. Key 1 links before the hand, after key 0.
    assert_eq!(
        cache.main_keys(),
        (2..=17).chain([0, 1]).collect::<Vec<_>>()
    );
    let slot = cache.find_slot(&promoted).unwrap();
    assert_eq!(cache.bits(slot) & REFERENCED, 0);
    assert!(cache.small_keys().contains(&21));
    assert_eq!(cache.main.len, cache.main.capacity);
    assert_eq!(cache.small.len, 2);
    cache.check_invariants();
}

#[test]
fn test_slot_stays_stable_on_promotion_and_goes_stale_on_reuse() {
    // Promotion changes only resident topology, so key 1 keeps its original
    // slot and the existing lookup hint remains valid.
    let mut cache = Cache::new(NZUsize!(40));
    let (slot1, value) = cache.get_or_insert_mut(1u64, || 0u64);
    *value = 10;
    let (slot2, value) = cache.get_or_insert_mut(2, || 0);
    *value = 20;
    for key in 3..=40u64 {
        cache.put(key, key * 10);
    }
    assert_eq!(cache.get_at(slot1, &1), Some(&10));
    cache.put(41, 410);
    assert_eq!(cache.get_at(slot1, &1), Some(&10));
    assert!(cache.main_keys().contains(&1));

    // An actual eviction reuses key 2's slot for key 42. The old hint then
    // fails full-key validation while the new key resolves in that slot.
    assert!(cache.slots[slot2].live);
    assert_eq!(cache.slots[slot2].key, 2);
    cache.put(42, 420);
    assert_eq!(cache.get_at(slot2, &2), None);
    let slot42 = cache.find_slot(&42).unwrap();
    assert_eq!(slot42, slot2);
    assert_eq!(cache.get_at(slot2, &2), None);
    assert_eq!(cache.get_at(slot42, &42), Some(&420));
    cache.check_invariants();
}

#[test]
fn test_scan_does_not_displace_main() {
    // Warm-up places keys 1 through 9 in Main. A one-cache-capacity scan is
    // absorbed by Small and leaves that Main working set intact.
    let mut cache = Cache::new(NZUsize!(10));
    for key in 0..10u64 {
        cache.put(key, key);
    }
    let mut protected = 1..10u64;
    assert_eq!(cache.main.len, 9);

    for key in 100..110u64 {
        cache.put(key, key);
    }
    assert!(protected.all(|key| cache.peek(&key).is_some()));
    cache.check_invariants();
}

#[test]
fn test_prefill_reuses_values_through_churn() {
    // Prefill allocates every value once. Replacement churn must keep reusing
    // those same stable slots without invoking the factory again.
    let mut makes = 0usize;
    let mut cache = Cache::<u64, Vec<u8>>::new(NZUsize!(20));
    cache.prefill(|| {
        makes += 1;
        vec![0; 32]
    });
    assert_eq!(makes, 20);

    for key in 0..2_000u64 {
        let (_, value) = cache.get_or_insert_mut(key, || unreachable!());
        value[0] = key as u8;
        cache.check_invariants();
    }
    assert_eq!(cache.slots.len(), 20);
    assert_eq!(makes, 20);
}

#[test]
fn test_remove_retain_and_clear_repair_resident_state() {
    // Exercise removal from Main and Ghost, then prove a removed Ghost key
    // returns as cold instead of receiving stale Main admission.
    let mut cache = Cache::new(NZUsize!(20));
    for key in 0..=30u64 {
        cache.put(key, key);
    }
    cache.put(1, 1);
    assert!(cache.remove(&1));
    assert!(!cache.remove(&1));

    let ghost = cache.ghost_keys()[0];
    assert!(!cache.remove(&ghost));
    assert!(!cache.ghost_keys().contains(&ghost));

    // Replace the vacancy left by the resident removal. With a full cache,
    // the forgotten Ghost key must now enter Small as a cold admission.
    cache.put(100, 100);
    cache.put(ghost, ghost);
    assert!(cache.small_keys().contains(&ghost));
    assert!(!cache.main_keys().contains(&ghost));

    // Retain detaches rejected residents but preserves unrelated Ghost
    // history. Clear resets both resident topology and Ghost history.
    cache.retain(|key, _| key % 2 == 0);
    assert!(!cache.ghost_keys().is_empty());
    assert!(
        cache
            .index
            .iter()
            .all(|&slot| cache.slots[slot].key % 2 == 0)
    );
    cache.check_invariants();

    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.small.len + cache.main.len, 0);
    assert!(cache.ghost.index.is_empty());
    assert!(cache.ghost_keys().is_empty());
    cache.check_invariants();
}

#[test]
fn test_shared_hits_are_concurrent() {
    // Shared lookups race only on the relaxed per-slot reference bit. The
    // accumulated hit must still protect key 1 on the next insertion.
    let mut cache = Cache::new(NZUsize!(40));
    for key in 1..=40u64 {
        cache.put(key, key);
    }
    let slot = cache.find_slot(&1).unwrap();
    let cache = Arc::new(RwLock::new(cache));
    let barrier = Arc::new(Barrier::new(5));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..1_000 {
                let guard = cache.read();
                assert_eq!(guard.get_at(slot, &1), Some(&1));
            }
        }));
    }
    barrier.wait();
    for thread in threads {
        thread.join().unwrap();
    }

    let mut cache = Arc::try_unwrap(cache).unwrap().into_inner();
    cache.put(41, 41);
    assert!(cache.main_keys().contains(&1));
    cache.check_invariants();
}

#[test]
fn test_fallible_factory_error_leaves_cache_unchanged() {
    // Key 1 is in Ghost. A failed factory must return before cache
    // insertion consumes that evidence or changes resident topology.
    let mut cache = Cache::new(NZUsize!(2));
    for key in 1..=3u64 {
        cache.put(key, key);
    }
    let small = cache.small_keys();
    let main = cache.main_keys();
    let ghost = cache.ghost_keys();
    let result = cache.try_get_or_insert_with(1, || Err::<u64, _>("failure"));
    assert_eq!(result, Err("failure"));
    assert_eq!(cache.small_keys(), small);
    assert_eq!(cache.main_keys(), main);
    assert_eq!(cache.ghost_keys(), ghost);
    cache.check_invariants();
}

#[test]
fn test_correlation_age_survives_admission_counter_wrap() {
    // Correlation ages are modular differences, so the packed generation can
    // wrap inside the window and leave the same Small state as a fresh run.
    let mut wrapped = Cache::new(NZUsize!(40));
    wrapped.small.admissions = ADMISSION_GENERATION_MASK - 1;
    let mut plain = Cache::new(NZUsize!(40));
    for key in 1..=40u64 {
        wrapped.put(key, key);
        plain.put(key, key);
    }
    assert_eq!(wrapped.small_keys(), plain.small_keys());
    for key in wrapped.small_keys() {
        assert_eq!(
            wrapped.bits(wrapped.find_slot(&key).unwrap()),
            plain.bits(plain.find_slot(&key).unwrap())
        );
    }

    // Key 1 left the window across the first wrap. Repeatedly remove both
    // young residents and cross the wrap with replacements. The older
    // survivor remains eligible because young_tail, not generation
    // equality, owns youth.
    assert_eq!(wrapped.get(&1), Some(&1));
    wrapped.retain(|key, _| *key != 4);
    assert!(wrapped.remove(&3));
    assert_eq!(wrapped.small.young_tail, None);

    for cycle in 0..8u64 {
        let first = 41 + 2 * cycle;
        let second = first + 1;
        wrapped.small.admissions = ADMISSION_GENERATION_MASK - 1;
        wrapped.put(first, first);
        let expected_young_tail = wrapped.find_slot(&first);
        wrapped.put(second, second);
        assert_eq!(wrapped.small.young_tail, expected_young_tail);
        wrapped.check_invariants();

        if cycle < 7 {
            wrapped.retain(|key, _| *key != second);
            assert!(wrapped.remove(&first));
            assert_eq!(wrapped.small.young_tail, None);
        }
    }

    wrapped.put(57, 57);
    assert!(wrapped.main_keys().contains(&1));
    wrapped.check_invariants();

    wrapped.clear();
    assert_eq!(wrapped.small.admissions, 0);
    wrapped.check_invariants();
}

#[derive(Debug, PartialEq, Eq)]
struct GhostKey {
    value: u64,
    owner: Rc<()>,
}

impl Hash for GhostKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write_u8(0);
    }
}

fn exercise_colliding_ghost(capacity: usize, reserve: bool) {
    let owner = Rc::new(());
    let hasher = Hasher::with_seeds(1, 2, 3, 4);
    let key = |value| GhostKey {
        value,
        owner: Rc::clone(&owner),
    };
    let mut ghost = GhostQueue::new(capacity);
    if !reserve {
        // Exercise the insertion callback through multiple table growths.
        ghost.index = HashTable::new();
    }
    let mut expected = VecDeque::new();
    for step in 0..2048u64 {
        let value = (step * 17 + step / 5) % 127;
        {
            let position = expected.iter().position(|entry| *entry == value);
            let requested = key(value);
            let requested_hash = hasher.hash_one(&requested);
            assert_eq!(
                ghost.discard(&requested, requested_hash),
                position.is_some()
            );
            if let Some(position) = position {
                expected.remove(position);
            }
            if step % 5 != 0 {
                let historical = key(value);
                let historical_hash = hasher.hash_one(&historical);
                ghost.push(historical, historical_hash, &hasher);
                if capacity != 0 {
                    expected.push_front(value);
                    expected.truncate(capacity);
                }
            }
        }
        if step == 777 || step == 1333 {
            ghost.clear();
            expected.clear();
        }

        let mut actual = Vec::new();
        let mut linked_slots = HashSet::new();
        let mut previous = None;
        let mut current = ghost.head;
        while let Some(slot) = current {
            assert!(linked_slots.insert(slot));
            let entry = &ghost.slots[slot];
            assert_eq!(linked(entry.prev), previous);
            actual.push(entry.key.as_ref().unwrap().value);
            previous = current;
            current = linked(entry.next);
        }
        assert_eq!(ghost.tail, previous);
        assert_eq!(actual, expected.iter().copied().collect::<Vec<_>>());
        assert_eq!(
            ghost.index.iter().copied().collect::<HashSet<_>>(),
            linked_slots
        );
        assert_eq!(ghost.index.len(), expected.len());
        assert!(ghost.slots.len() <= capacity);
        let free = ghost.check_free_slots();
        for (slot, entry) in ghost.slots.iter().enumerate() {
            assert_eq!(entry.key.is_some(), linked_slots.contains(&slot));
            assert_eq!(free.contains(&slot), entry.key.is_none());
        }

        // GhostKey is not Clone, and each live historical key owns one Rc.
        assert_eq!(Rc::strong_count(&owner), expected.len() + 1);
    }
    drop(ghost);
    assert_eq!(Rc::strong_count(&owner), 1);
}

#[test]
fn test_ghost_collision_churn_and_key_ownership() {
    for capacity in [0, 1, 2, 31] {
        exercise_colliding_ghost(capacity, true);
    }
}

#[test]
fn test_ghost_rehash_reads_live_keys() {
    exercise_colliding_ghost(31, false);
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CollidingKey(u64);

impl Hash for CollidingKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write_u8(0);
    }
}

#[test]
fn test_shared_hasher_drives_resident_and_ghost_rehashes() {
    let mut cache = Cache::new(NZUsize!(20));

    // Removing both reservations forces both indexes to call their rehash
    // callbacks while the public Cache API drives all replacement transitions.
    cache.index = HashTable::new();
    cache.ghost.index = HashTable::new();
    cache.hasher = Hasher::with_seeds(1, 2, 3, 4);

    let mut resident_grew = false;
    let mut ghost_grew = false;
    for key in 0..256 {
        let resident_capacity = cache.index.capacity();
        let ghost_capacity = cache.ghost.index.capacity();
        cache.put(CollidingKey(key), key);
        resident_grew |= cache.index.capacity() > resident_capacity;
        ghost_grew |= cache.ghost.index.capacity() > ghost_capacity;
        cache.check_invariants();
    }
    assert!(resident_grew, "resident index must rehash");
    assert!(ghost_grew, "Ghost index must rehash");

    let ghost = cache.ghost_keys();
    assert_eq!(ghost.len(), cache.ghost.capacity);
    assert_eq!(ghost.iter().collect::<HashSet<_>>().len(), ghost.len());
    assert!(ghost.iter().all(|key| !cache.contains(key)));

    // Constant hashes still consume only the exact requested history key.
    let requested = ghost[ghost.len() / 2].clone();
    cache.put(requested.clone(), u64::MAX);
    assert_eq!(cache.get(&requested), Some(&u64::MAX));
    assert!(!cache.ghost_keys().contains(&requested));
    cache.check_invariants();
}

#[test]
fn test_borrowed_keys_keep_independent_ghost_history() {
    let names = [
        String::from("first"),
        String::from("second"),
        String::from("third"),
    ];
    let mut cache = Cache::new(NZUsize!(2));
    for (value, name) in names.iter().enumerate() {
        cache.put(vec![name.as_str()], value);
    }
    assert_eq!(cache.ghost_keys(), vec![vec![names[0].as_str()]]);
    assert!(!cache.remove(&vec![names[0].as_str()]));
    assert!(cache.ghost_keys().is_empty());
    assert_eq!(cache.get(&vec![names[2].as_str()]), Some(&2));
    cache.check_invariants();
}

#[test]
fn test_main_sweep_reaches_unreferenced_resident_beyond_128() {
    let mut cache = Cache::new(NZUsize!(200));
    for key in 0..200u64 {
        cache.put(key, key);
    }
    for key in 20..149 {
        assert_eq!(cache.get(&key), Some(&key));
    }
    cache.put(200, 200);
    assert_eq!(cache.ghost_keys(), vec![0]);
    cache.put(0, 0);
    assert_eq!(cache.peek(&149), None);
    for key in 20..149 {
        assert_eq!(cache.peek(&key), Some(&key));
        assert_eq!(cache.bits(cache.find_slot(&key).unwrap()), 0);
    }
    cache.check_invariants();
}
