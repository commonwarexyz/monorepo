use super::{Cache, Clock, Policy};
use core::{
    hash::{Hash, Hasher},
    num::NonZeroUsize,
};
use hashbrown::HashTable;
use std::collections::HashMap;

#[derive(Clone, Default, Eq, PartialEq)]
struct ProbeKey<const COLLIDE: bool>(String);
impl<const COLLIDE: bool> Hash for ProbeKey<COLLIDE> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if COLLIDE {
            0u8.hash(state);
        } else {
            self.0.hash(state);
        }
    }
}

fn exercise_rehash<const COLLIDE: bool, P: Policy<ProbeKey<COLLIDE>>>()
where
    P::SlotState: Default,
{
    for capacity in [1, 2, 31, 64] {
        for prefill in [false, true] {
            let mut cache =
                Cache::<ProbeKey<COLLIDE>, Vec<u8>, P>::new(NonZeroUsize::new(capacity).unwrap());

            // Zero reserve forces actual rehash callbacks during lazy growth and
            // publication into prefilled storage, even with constant hashes.
            cache.index = HashTable::new();
            cache.hasher = super::Hasher::with_seeds(1, 2, 3, 4);
            if prefill {
                cache.prefill(Vec::new);
            }
            let mut hints = Vec::new();
            let mut live = HashMap::new();
            let mut grew = false;
            for step in 0..1024usize {
                let key = ProbeKey::<COLLIDE>(format!("key-{step}"));
                let before = cache.index.capacity();
                let (slot, value) = cache.get_or_insert_mut(key.clone(), Vec::new);
                value.clear();
                value.extend_from_slice(&step.to_le_bytes());
                let value_address = value as *const Vec<u8>;
                grew |= cache.index.capacity() > before;
                live.retain(|old_key, old: &mut (usize, *const Vec<u8>)| {
                    if old.0 == slot {
                        assert!(cache.get_at(old.0, old_key).is_none());
                        false
                    } else {
                        true
                    }
                });
                live.insert(key.clone(), (slot, value_address));
                hints.push((slot, key));
                if step % 11 == 5 {
                    let removed = ProbeKey::<COLLIDE>(format!("key-{}", step.saturating_sub(1)));
                    assert_eq!(cache.remove(&removed), live.remove(&removed).is_some());
                }
                if step % 37 == 9 {
                    cache.retain(|key, _| key.0.as_bytes().last().unwrap() % 2 == 0);
                    live.retain(|key, _| key.0.as_bytes().last().unwrap() % 2 == 0);
                }
                if step % 127 == 100 {
                    cache.clear();
                    live.clear();
                    if prefill {
                        cache.prefill(Vec::new);
                    }
                }
                assert_eq!(cache.len(), live.len());
                cache.check_cache_invariants();
                for (key, &(slot, address)) in &live {
                    let value = cache.peek(key).unwrap();
                    let expected = key.0[4..].parse::<usize>().unwrap();
                    assert_eq!(value.as_slice(), expected.to_le_bytes());
                    assert_eq!(value as *const Vec<u8>, address);
                    assert_eq!(cache.get_at(slot, key), Some(value));
                }
                for (slot, key) in &hints {
                    let expected = live.get(key).filter(|entry| entry.0 == *slot);
                    assert_eq!(cache.get_at(*slot, key).is_some(), expected.is_some());
                }
                assert!(
                    cache
                        .get_at(usize::MAX, &ProbeKey::<COLLIDE>::default())
                        .is_none()
                );
            }
            assert!(grew, "the test must exercise index growth");
        }
    }
}

#[test]
fn collisions_rehash_and_stable_values_clock() {
    exercise_rehash::<true, Clock>();
}

#[test]
fn distinct_hashes_rehash_and_stable_values_clock() {
    exercise_rehash::<false, Clock>();
}
