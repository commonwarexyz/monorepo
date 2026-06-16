#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::cache::Clock;
use libfuzzer_sys::fuzz_target;
use std::{collections::HashMap, num::NonZeroUsize};

/// Keys are confined to a small space so a small-capacity cache churns and
/// evicts heavily, exercising the CLOCK sweep and slot reuse.
const KEY_SPACE: u8 = 24;

#[derive(Arbitrary, Debug)]
enum Op {
    Get(u8),
    Peek(u8),
    Contains(u8),
    GetMut(u8, u16),
    Put(u8, u16),
    GetOrInsert(u8, u16),
    GetOrInsertMut(u8, u16),
    Remove(u8),
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
    let cap = (plan.capacity % 16) as usize + 1;
    let mut cache: Clock<u8, u16> = Clock::new(NonZeroUsize::new(cap).unwrap());
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
                *cache.get_or_insert_mut(k, || v) = v;
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
    }
}

fuzz_target!(|plan: Plan| {
    run(plan);
});
