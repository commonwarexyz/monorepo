#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::cache::Cache;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
};

/// Keys are confined to a small space so a small-capacity cache churns and
/// evicts heavily, exercising eviction sweeps, Ghost history, and slot reuse.
const KEY_SPACE: u8 = 64;

/// Largest cache capacity. Clock2Q+ gives Small more than one slot only from
/// capacity 20, so the range must reach well past it.
const MAX_CAPACITY: u8 = 48;

#[derive(Arbitrary, Debug)]
enum Op {
    Get(u8),
    Peek(u8),
    Contains(u8),
    GetMut(u8, u16),
    Put(u8, u16),
    GetOrInsert(u8, u16),
    GetOrInsertMut(u8, u16),
    GetOrInsertMutWithPriorKey(u8, u16),
    Remove(u8),
    RemoveReturningSlot(u8),
    RemoveAt(u8),
    Retain(u8),
    Len,
    IsEmpty,
    Clear,
}

#[derive(Arbitrary, Debug)]
struct Plan {
    capacity: u8,
    prefill: bool,
    ops: Vec<Op>,
}

fn run(plan: Plan) {
    let cap = (plan.capacity % MAX_CAPACITY) as usize + 1;
    let mut cache: Cache<u8, u16> = Cache::new(NonZeroUsize::new(cap).unwrap());
    if plan.prefill {
        cache.prefill(|| 0u16);
    }

    // Oracle: last value written for each logically-present key. A key the cache
    // reports as present must hold its last-written value (no stale or conjured
    // values); an evicted key is simply absent.
    let mut model: HashMap<u8, u16> = HashMap::new();

    for op in plan.ops {
        match op {
            Op::Get(k) => {
                let k = k % KEY_SPACE;
                assert_eq!(cache.get(&k).copied(), cache.peek(&k).copied());
            }
            Op::Peek(k) => {
                let _ = cache.peek(&(k % KEY_SPACE));
            }
            Op::Contains(k) => {
                let k = k % KEY_SPACE;
                assert_eq!(cache.contains(&k), cache.peek(&k).is_some());
            }
            Op::GetMut(k, v) => {
                let k = k % KEY_SPACE;
                if let Some(slot) = cache.get_mut(&k) {
                    *slot = v;
                    model.insert(k, v);
                }
            }
            Op::Put(k, v) => {
                let k = k % KEY_SPACE;
                cache.put(k, v);
                model.insert(k, v);
                assert_eq!(cache.peek(&k).copied(), Some(v));
            }
            Op::GetOrInsert(k, v) => {
                let k = k % KEY_SPACE;
                let stored = *cache.get_or_insert_with(k, || v);
                model.insert(k, stored);
                assert_eq!(cache.peek(&k).copied(), Some(stored));
            }
            Op::GetOrInsertMut(k, v) => {
                let k = k % KEY_SPACE;
                *cache.get_or_insert_mut(k, || v).1 = v;
                model.insert(k, v);
                assert_eq!(cache.peek(&k).copied(), Some(v));
            }
            Op::GetOrInsertMutWithPriorKey(k, v) => {
                // The prior key held the returned slot before the call. It is the key itself on a
                // hit, a resident evicted to make room, or nothing when the key took unused
                // capacity.
                let k = k % KEY_SPACE;
                let before: Vec<Option<u8>> =
                    (0..cap).map(|slot| cache.key_at(slot).copied()).collect();
                let len = cache.len();
                let (slot, stored, prior) = cache.get_or_insert_mut_with_prior_key(k, || v);
                *stored = v;
                assert_eq!(prior, before[slot]);
                assert_eq!(cache.key_at(slot), Some(&k));
                match prior {
                    Some(prior) if prior == k => assert_eq!(cache.len(), len),
                    Some(evicted) => {
                        assert_eq!(cache.len(), len);
                        assert!(!cache.contains(&evicted));
                        assert!(model.remove(&evicted).is_some());
                    }
                    None => assert_eq!(cache.len(), len + 1),
                }
                model.insert(k, v);
                assert_eq!(cache.peek(&k).copied(), Some(v));
            }
            Op::Remove(k) => {
                let k = k % KEY_SPACE;
                let had = cache.contains(&k);
                assert_eq!(cache.remove(&k), had);
                model.remove(&k);
                assert!(!cache.contains(&k));
            }
            Op::RemoveReturningSlot(k) => {
                let k = k % KEY_SPACE;
                let held = (0..cap).find(|&slot| cache.key_at(slot) == Some(&k));
                assert_eq!(cache.remove_returning_slot(&k), held);
                model.remove(&k);
                assert!(!cache.contains(&k));
                if let Some(slot) = held {
                    assert_eq!(cache.key_at(slot), None);
                }
            }
            Op::RemoveAt(slot) => {
                // Slot numbers range past every capacity, covering out-of-range slots.
                let slot = usize::from(slot);
                let key = cache.key_at(slot).copied();
                assert_eq!(cache.remove_at(slot), key.is_some());
                assert_eq!(cache.key_at(slot), None);
                if let Some(k) = key {
                    model.remove(&k);
                    assert!(!cache.contains(&k));
                }
            }
            Op::Retain(k) => {
                let k = k % KEY_SPACE;
                cache.retain(|key, _| *key < k);
                model.retain(|key, _| *key < k);
            }
            Op::Len => {
                assert!(cache.len() <= cap);
            }
            Op::IsEmpty => {
                let _ = cache.is_empty();
            }
            Op::Clear => {
                cache.clear();
                model.clear();
                assert!(cache.is_empty());
            }
        }

        // Global invariants after every op. All keys live in `KEY_SPACE`, so the
        // present-count over that range must equal `len`.
        assert!(cache.len() <= cap);
        let mut present = 0usize;
        for k in 0..KEY_SPACE {
            let is_present = cache.contains(&k);
            assert_eq!(is_present, cache.peek(&k).is_some());
            if is_present {
                present += 1;
                assert_eq!(cache.peek(&k).copied(), model.get(&k).copied());
            }
        }
        assert_eq!(cache.len(), present);
        assert_eq!(cache.is_empty(), present == 0);

        // Live slots hold exactly the present keys, each in one slot, and no slot lies past
        // capacity.
        let mut live = HashSet::new();
        for slot in 0..cap {
            if let Some(&k) = cache.key_at(slot) {
                assert!(live.insert(k));
                assert!(cache.contains(&k));
            }
        }
        assert_eq!(live.len(), present);
        assert_eq!(cache.key_at(cap), None);
    }
}

fuzz_target!(|plan: Plan| {
    run(plan);
});
