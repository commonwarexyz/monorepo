use super::Cache;
use core::{
    hash::{Hash, Hasher},
    num::NonZeroUsize,
};
use hashbrown::HashTable;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

#[derive(Clone)]
struct CountingKey {
    id: usize,
    hashes: Rc<Cell<usize>>,
    comparisons: Rc<Cell<usize>>,
}

impl CountingKey {
    fn new(id: usize) -> Self {
        Self {
            id,
            hashes: Rc::new(Cell::new(0)),
            comparisons: Rc::new(Cell::new(0)),
        }
    }

    fn hashes(&self) -> usize {
        self.hashes.get()
    }

    fn comparisons(&self) -> usize {
        self.comparisons.get()
    }

    fn reset_counts(&self) {
        self.hashes.set(0);
        self.comparisons.set(0);
    }
}

impl PartialEq for CountingKey {
    fn eq(&self, other: &Self) -> bool {
        self.comparisons.set(self.comparisons.get() + 1);
        self.id == other.id
    }
}

impl Eq for CountingKey {}

impl Hash for CountingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hashes.set(self.hashes.get() + 1);
        self.id.hash(state);
    }
}

#[test]
fn shared_hashes_without_rehash_steps() {
    let one = CountingKey::new(1);
    let two = CountingKey::new(2);
    let three = CountingKey::new(3);
    let mut cache = Cache::<CountingKey, usize>::new(NonZeroUsize::new(2).unwrap());

    // The reserved resident and Ghost tables cannot rehash during this short
    // sequence, so every count belongs to the key's explicit operation path.
    cache.put(one.clone(), 1);
    cache.put(two.clone(), 2);
    assert_eq!(one.hashes(), 1);
    assert_eq!(two.hashes(), 1);

    // Key 3 replaces Small's key 1. Each incoming key and the transferred
    // victim is hashed once across its resident and Ghost operations.
    cache.put(three.clone(), 3);
    assert_eq!(one.hashes(), 2);
    assert_eq!(two.hashes(), 1);
    assert_eq!(three.hashes(), 1);

    // A nonresident removal shares the resident-miss hash with Ghost discard.
    assert!(!cache.remove(&one));
    assert_eq!(one.hashes(), 3);

    // Resident retain and clear operate from canonical table/slot ownership
    // and do not need a new key hash.
    cache.retain(|key, _| key.id != 3);
    assert_eq!(three.hashes(), 1);
    cache.clear();
    assert_eq!(two.hashes(), 1);
    assert_eq!(three.hashes(), 1);
}

#[test]
fn remove_if_reuses_the_resident_probe() {
    let key = CountingKey::new(7);
    let mut cache = Cache::<CountingKey, usize>::new(NonZeroUsize::new(1).unwrap());
    cache.put(key.clone(), 70);

    key.reset_counts();
    assert_eq!(cache.remove_if(&key, |value| *value == 71), Some(false));
    assert_eq!(key.hashes(), 1);
    assert_eq!(key.comparisons(), 1);

    key.reset_counts();
    assert_eq!(cache.remove_if(&key, |value| *value == 70), Some(true));
    assert_eq!(key.hashes(), 1);
    assert_eq!(key.comparisons(), 1);

    key.reset_counts();
    assert_eq!(cache.remove_if(&key, |_| unreachable!()), None);
    assert_eq!(key.hashes(), 1);
    assert_eq!(key.comparisons(), 0);
}

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

fn exercise_rehash<const COLLIDE: bool>() {
    for capacity in [1, 2, 31, 64] {
        for prefill in [false, true] {
            let mut cache =
                Cache::<ProbeKey<COLLIDE>, Vec<u8>>::new(NonZeroUsize::new(capacity).unwrap());

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
                cache.check_invariants();
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
fn collisions_rehash_and_stable_values() {
    exercise_rehash::<true>();
}

#[test]
fn remove_if_validates_full_keys_under_collisions() {
    let first = ProbeKey::<true>("first".into());
    let second = ProbeKey::<true>("second".into());
    let absent = ProbeKey::<true>("absent".into());
    let mut cache = Cache::<_, usize>::new(NonZeroUsize::new(2).unwrap());
    cache.put(first.clone(), 1);
    cache.put(second.clone(), 2);

    let calls = Cell::new(0);
    assert_eq!(
        cache.remove_if(&absent, |_| {
            calls.set(calls.get() + 1);
            true
        }),
        None
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(cache.peek(&first), Some(&1));
    assert_eq!(cache.peek(&second), Some(&2));

    assert_eq!(cache.remove_if(&second, |value| *value == 2), Some(true));
    assert_eq!(cache.peek(&first), Some(&1));
    assert!(!cache.contains(&second));
    cache.check_invariants();
}

#[derive(Default)]
struct Counts {
    owners: RefCell<HashMap<usize, usize>>,
    clones: RefCell<Vec<usize>>,
    values: Cell<usize>,
}
struct OwnedKey {
    id: usize,
    counts: Rc<Counts>,
}
impl OwnedKey {
    fn new(id: usize, counts: &Rc<Counts>) -> Self {
        *counts.owners.borrow_mut().entry(id).or_default() += 1;
        Self {
            id,
            counts: Rc::clone(counts),
        }
    }
}
impl Clone for OwnedKey {
    fn clone(&self) -> Self {
        self.counts.clones.borrow_mut().push(self.id);
        Self::new(self.id, &self.counts)
    }
}
impl PartialEq for OwnedKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for OwnedKey {}
impl Hash for OwnedKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        0u8.hash(state);
    }
}
impl Drop for OwnedKey {
    fn drop(&mut self) {
        *self.counts.owners.borrow_mut().get_mut(&self.id).unwrap() -= 1;
    }
}
struct OwnedValue(Rc<Counts>);
impl Drop for OwnedValue {
    fn drop(&mut self) {
        self.0.values.set(self.0.values.get() + 1);
    }
}

#[test]
fn eviction_does_not_clone_keys() {
    let counts = Rc::new(Counts::default());
    let mut cache = Cache::<OwnedKey, OwnedValue>::new(NonZeroUsize::new(2).unwrap());
    for id in 0..8 {
        cache.put(OwnedKey::new(id, &counts), OwnedValue(Rc::clone(&counts)));
    }
    assert!(counts.clones.borrow().is_empty());
    assert_eq!(counts.values.get(), 6);
    drop(cache);
    assert!(counts.owners.borrow().values().all(|&n| n == 0));
    assert_eq!(counts.values.get(), 8);
}

#[test]
fn canonical_key_move_and_ghost_drop_ownership() {
    let counts = Rc::new(Counts::default());
    let mut cache = Cache::<OwnedKey, OwnedValue>::new(NonZeroUsize::new(2).unwrap());
    for id in 0..2 {
        cache.put(OwnedKey::new(id, &counts), OwnedValue(Rc::clone(&counts)));
    }
    assert!(
        counts.clones.borrow().is_empty(),
        "vacant insertion owns the incoming key directly"
    );
    assert!(counts.owners.borrow().values().all(|&n| n == 1));
    cache.get_or_insert_mut(OwnedKey::new(2, &counts), || {
        panic!("eviction must reuse V")
    });
    assert!(counts.clones.borrow().is_empty());
    assert_eq!(
        *counts.owners.borrow(),
        HashMap::from([(0, 1), (1, 1), (2, 1)])
    );

    // Key 0 is historical: its admission must consume Ghost and evict Main's 1.
    cache.get_or_insert_mut(OwnedKey::new(0, &counts), || {
        panic!("Ghost hit must reuse V")
    });
    assert!(counts.clones.borrow().is_empty());
    assert_eq!(
        *counts.owners.borrow(),
        HashMap::from([(0, 1), (1, 0), (2, 1)])
    );
    assert!(cache.remove(&OwnedKey::new(2, &counts)));
    assert_eq!(
        counts.owners.borrow()[&2],
        1,
        "free slots retain their stale key"
    );
    cache.get_or_insert_mut(OwnedKey::new(3, &counts), || {
        panic!("free slot must reuse V")
    });
    assert!(
        counts.clones.borrow().is_empty(),
        "free reuse must not clone keys"
    );
    assert_eq!(counts.owners.borrow()[&2], 0);
    assert_eq!(counts.values.get(), 0);
    cache.retain(|_, _| false);
    assert!(cache.is_empty());
    assert_eq!(counts.values.get(), 0);
    cache.clear();
    assert!(counts.owners.borrow().values().all(|&n| n == 0));
    assert_eq!(counts.values.get(), 2);
    cache.put(OwnedKey::new(4, &counts), OwnedValue(Rc::clone(&counts)));
    drop(cache);
    assert!(counts.owners.borrow().values().all(|&n| n == 0));
    assert_eq!(counts.values.get(), 3);
}

#[test]
fn distinct_hashes_rehash_and_stable_values() {
    exercise_rehash::<false>();
}

// Equality ignores metadata so an incoming key can differ from Ghost's owner.
#[derive(Debug)]
struct NonCloneKey {
    id: usize,
    metadata: usize,
}
impl PartialEq for NonCloneKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for NonCloneKey {}
impl Hash for NonCloneKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        0u8.hash(state);
    }
}

#[test]
fn non_clone_keys_keep_incoming_metadata_on_ghost_hits() {
    let mut cache = Cache::new(NonZeroUsize::new(2).unwrap());
    let key = |id, metadata| NonCloneKey { id, metadata };
    let (original_slot, _) = cache.get_or_insert_mut(key(0, 10), || 0);
    cache.put(key(1, 11), 1);
    cache.put(key(2, 12), 2);
    assert_eq!(cache.get_at(original_slot, &key(0, 0)), None);
    cache.check_invariants();

    // The historical key is consumed while the caller's key becomes canonical.
    let (slot, value) = cache.get_or_insert_mut(key(0, 20), || unreachable!());
    *value = 20;
    assert_eq!(cache.get_at(slot, &key(0, 0)), Some(&20));
    cache.retain(|key, value| {
        if key.id == 0 {
            assert_eq!(key.metadata, 20);
            assert_eq!(*value, 20);
        }
        true
    });
    cache.check_invariants();

    assert!(cache.remove(&key(0, 0)));
    assert_eq!(cache.get_at(slot, &key(0, 0)), None);
    let (reused, value) = cache.get_or_insert_mut(key(3, 30), || unreachable!());
    assert_eq!(reused, slot);
    assert_eq!(*value, 20);
    cache.check_invariants();
    cache.clear();
    cache.check_invariants();
}

struct PanickingKey {
    id: usize,
    panic_on: Rc<Cell<Option<usize>>>,
}
impl PartialEq for PanickingKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for PanickingKey {}
impl Hash for PanickingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
impl Drop for PanickingKey {
    fn drop(&mut self) {
        if self.panic_on.get() == Some(self.id) {
            self.panic_on.set(None);
            panic!("key destructor panic");
        }
    }
}

#[test]
fn displaced_key_destructors_follow_replacement_bookkeeping() {
    let panic_on = Rc::new(Cell::new(None));
    let key = |id| PanickingKey {
        id,
        panic_on: Rc::clone(&panic_on),
    };
    let mut cache = Cache::new(NonZeroUsize::new(2).unwrap());
    for id in 0..3 {
        cache.put(key(id), id);
    }

    // A full Ghost replaces its oldest history before dropping that old key.
    panic_on.set(Some(0));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.put(key(3), 3)));
    assert!(result.is_err());
    assert_eq!(cache.peek(&key(3)), Some(&3));
    cache.check_invariants();

    // Discard returns the historical slot to its free list before dropping.
    panic_on.set(Some(2));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.remove(&key(2))));
    assert!(result.is_err());
    cache.check_invariants();
    cache.put(key(4), 4);
    cache.check_invariants();

    // A Ghost hit replaces Main's canonical key with the caller's owned key.
    panic_on.set(Some(1));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.put(key(3), 30)));
    assert!(result.is_err());
    assert_eq!(cache.peek(&key(3)), Some(&30));
    cache.check_invariants();

    // A freed resident retains its stale key until the next published admission.
    assert!(cache.remove(&key(4)));
    panic_on.set(Some(4));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.put(key(5), 5)));
    assert!(result.is_err());
    assert_eq!(cache.peek(&key(5)), Some(&5));
    cache.check_invariants();
}
