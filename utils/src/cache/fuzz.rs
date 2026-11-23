use super::*;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::{HashMap, HashSet};

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

impl Op {
    const fn from_bytes([tag, key, low, high]: [u8; 4], keys: u8) -> Self {
        let key = key % keys;
        let value = u16::from_le_bytes([low, high]);
        // Keep clears rare so most sequences can build up cache state.
        match tag % 65 {
            0..=7 => Self::Get(key),
            8..=15 => Self::Peek(key),
            16..=23 => Self::Put(key, value),
            24..=31 => Self::GetOrInsert(key, value),
            32..=39 => Self::GetOrInsertMut(key, value),
            40..=47 => Self::GetMut(key, value),
            48..=55 => Self::Remove(key),
            56..=63 => Self::Retain(key),
            _ => Self::Clear,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Plan<const WIDE: bool> {
    capacity: usize,
    prefill: bool,
    ops: Vec<Op>,
}

impl<const WIDE: bool> Plan<WIDE> {
    const KEYS: u8 = if WIDE { 64 } else { 16 };

    pub(crate) fn run(self) {
        exercise_cache(self.capacity, Self::KEYS, self.prefill, self.ops);
    }
}

impl<const WIDE: bool> Arbitrary<'_> for Plan<WIDE> {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let capacity = u.int_in_range(if WIDE { 20..=47 } else { 1..=7 })?;
        let prefill = u.arbitrary()?;
        let (ops, _) = u.bytes(u.len())?.as_chunks();
        let ops = ops
            .iter()
            .map(|&op| Op::from_bytes(op, Self::KEYS))
            .collect();
        Ok(Self {
            capacity,
            prefill,
            ops,
        })
    }
}

fn exercise_cache(capacity: usize, keys: u8, prefill: bool, ops: Vec<Op>) {
    let mut cache = Cache::<u8, u16>::new(NonZeroUsize::new(capacity).unwrap());
    if prefill {
        cache.prefill(|| 0u16);
    }
    // Oracle: last value written for each live key. A key the cache
    // reports as present must hold its last-written value (no stale or
    // conjured values). An evicted key is simply absent.
    let mut model = HashMap::new();
    for op in ops {
        match op {
            Op::Get(key) => {
                let value = cache.get(&key).copied();
                assert_eq!(value, cache.peek(&key).copied());
            }
            Op::Peek(key) => {
                let _ = cache.peek(&key);
            }
            Op::Put(key, value) => {
                cache.put(key, value);
                model.insert(key, value);
                assert_eq!(cache.peek(&key).copied(), Some(value));
            }
            Op::GetOrInsert(key, value) => {
                let stored = *cache.get_or_insert_with(key, || value);
                model.insert(key, stored);
                assert_eq!(cache.peek(&key).copied(), Some(stored));
            }
            Op::GetOrInsertMut(key, value) => {
                *cache.get_or_insert_mut(key, || value).1 = value;
                model.insert(key, value);
                assert_eq!(cache.peek(&key).copied(), Some(value));
            }
            Op::GetMut(key, value) => {
                if let Some(stored) = cache.get_mut(&key) {
                    *stored = value;
                    model.insert(key, value);
                }
            }
            Op::Remove(key) => {
                let present = cache.contains(&key);
                assert_eq!(cache.remove(&key), present);
                model.remove(&key);
                assert!(!cache.contains(&key));
            }
            Op::Retain(key) => {
                cache.retain(|resident, _| *resident < key);
                model.retain(|resident, _| *resident < key);
                assert!(cache.len() <= usize::from(key).min(capacity));
            }
            Op::Clear => {
                cache.clear();
                model.clear();
                assert!(cache.is_empty());
            }
        }

        assert!(cache.len() <= capacity);
        // The slot vector never exceeds capacity, proving reuse.
        assert!(cache.slots.len() <= capacity);
        // Every present key holds its last-written value and was logically
        // inserted. Absent keys are an allowed (evicted) state.
        for key in 0..keys {
            let present = cache.contains(&key);
            assert_eq!(present, cache.peek(&key).is_some());
            if present {
                assert_eq!(cache.peek(&key).copied(), model.get(&key).copied());
            }
        }
        cache.check_invariants();
    }
}

impl<K> GhostQueue<K> {
    pub(super) fn check_free_slots(&self) -> HashSet<usize> {
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
    pub(super) fn bits(&self, slot: Slot) -> u8 {
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
    #[cfg(test)]
    pub(super) fn small_keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.small_order()
            .into_iter()
            .map(|slot| self.slots[slot].key.clone())
            .collect()
    }

    /// Returns Main keys starting at the CLOCK hand.
    #[cfg(test)]
    pub(super) fn main_keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.main_order()
            .into_iter()
            .map(|slot| self.slots[slot].key.clone())
            .collect()
    }

    /// Returns Ghost keys from newest to oldest.
    #[cfg(test)]
    pub(super) fn ghost_keys(&self) -> Vec<K>
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
            } else {
                assert_eq!(self.topology[slot].admitted_at(), 0);
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
        for slot in self.topology.iter().skip(self.slots.len()) {
            assert_eq!(slot.location(), Location::Free);
            assert_eq!(slot.admitted_at(), 0);
        }

        assert!(self.ghost.index.len() <= self.ghost.capacity);
        assert!(self.ghost.slots.len() <= self.ghost.capacity);
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
