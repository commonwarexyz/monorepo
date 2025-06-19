use crate::index::Translator;
use commonware_runtime::Metrics;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{
    hash_map::{Entry, OccupiedEntry, VacantEntry},
    HashMap,
};

/// The initial capacity of the internal hashmap. This is a guess at the number of unique keys we will
/// encounter. The hashmap will grow as needed, but this is a good starting point (covering
/// the entire [super::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

/// Panic message shown when `next()` is not called after `Cursor` creation or after `insert()` or ``delete()`.
const MUST_CALL_NEXT: &str = "must call Cursor::next()";

/// Panic message shown when `update()` is called after `Cursor` has returned `None` or after `insert()`
/// or `delete()` (but before `next()`).
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Each key is mapped to a `Record` that contains a linked list of potential values for that key.
///
/// We avoid using a `Vec` to store values because the common case (where there are no collisions) would
/// require an additional 24 bytes of memory for each value (the `len`, `capacity`, and `ptr` fields).
///
/// Again optimizing for the common case, we store the first value directly in the `Record` to avoid
/// indirection (heap jumping).
#[derive(PartialEq, Eq)]
struct Record<V: Eq> {
    value: V,
    next: Option<Box<Record<V>>>,
}

/// Phases of the `Cursor` during iteration.
#[derive(PartialEq, Eq)]
enum Phase<V: Eq> {
    /// Before iteration starts.
    Initial,

    /// The current entry.
    Entry,
    /// Some item after the current entry.
    Next(Box<Record<V>>),

    /// Iteration is done.
    Done,
    /// The current entry has no valid item.
    EntryDeleted,

    /// The current entry has been deleted and we've updated its value in-place
    /// to be the value of the next record.
    PostDeleteEntry,
    /// The item has been deleted and we may be pointing to the next item.
    PostDeleteNext(Option<Box<Record<V>>>),
    /// An item has been inserted.
    PostInsert(Box<Record<V>>),
}

/// A mutable iterator over the values associated with a translated key, allowing in-place modifications.
///
/// The `Cursor` provides a way to traverse and modify the linked list of `Record`s while maintaining its
/// structure. It supports:
///
/// - Iteration via `next()` to access values.
/// - Modification via `update()` to change the current value.
/// - Insertion via `insert()` to add new values.
/// - Deletion via `delete()` to remove values.
///
/// # Safety
///
/// - Must call `next()` before `update()`, `insert()`, or `delete()` to establish a valid position.
/// - Once `next()` returns `None`, only `insert()` can be called.
/// - Dropping the `Cursor` automatically restores the list structure by reattaching any detached `next` nodes.
///
/// _If you don't need advanced functionality, just use `insert()`, `insert_and_prune()`, or `remove()` instead._
pub struct Cursor<'a, T: Translator, V: Eq> {
    phase: Phase<V>,

    entry: Option<OccupiedEntry<'a, T::Key, Record<V>>>,
    past: Option<Box<Record<V>>>,

    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, T: Translator, V: Eq> Cursor<'a, T, V> {
    /// Creates a new `Cursor` from a mutable record reference, detaching its `next` chain for iteration.
    fn new(
        entry: OccupiedEntry<'a, T::Key, Record<V>>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            phase: Phase::Initial,

            entry: Some(entry),
            past: None,

            keys,
            items,
            pruned,
        }
    }

    /// Pushes a `Record` to the past list, maintaining the linked list structure.
    fn past_push(&mut self, mut new: Box<Record<V>>) {
        if self.past.is_none() {
            self.past = Some(new);
        } else {
            let past = self.past.take().unwrap();
            new.next = Some(past);
            self.past = Some(new);
        }
    }

    /// Updates the value at the current position in the iteration.
    ///
    /// Panics if called before `next()` or after iteration is complete (`Status::Done` phase).
    pub fn update(&mut self, v: V) {
        match &mut self.phase {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                self.entry.as_mut().unwrap().get_mut().value = v;
            }
            Phase::Next(next) => {
                next.value = v;
            }
            Phase::Done
            | Phase::EntryDeleted
            | Phase::PostDeleteEntry
            | Phase::PostDeleteNext(_)
            | Phase::PostInsert(_) => unreachable!("{NO_ACTIVE_ITEM}"),
        }
    }

    /// If we are in a phase where we could return a value, return it.
    fn value(&self) -> Option<&V> {
        match &self.phase {
            Phase::Initial => unreachable!(),
            Phase::Entry => self.entry.as_ref().map(|r| &r.get().value),
            Phase::Next(current) => Some(&current.value),
            Phase::Done | Phase::EntryDeleted => None,
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) | Phase::PostInsert(_) => {
                unreachable!()
            }
        }
    }

    /// Advances the cursor to the next value in the chain, returning a reference to it.
    ///
    /// This method must be called before any other operations (`insert()`, `delete()`, etc.). If
    /// either `insert()` or `delete()` is called, `next()` must be called to set a new active
    /// item. If after `insert()`, the next active item is the item after the inserted item. If after
    /// `delete()`, the next active item is the item after the deleted item.
    ///
    /// Handles transitions between phases and adjusts for deletions. Returns `None` when the list is exhausted.
    /// It is safe to call `next()` even after it returns `None`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&V> {
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial | Phase::PostDeleteEntry => {
                // We must start with some entry, so this will always be some non-None value.
                self.phase = Phase::Entry;
            }
            Phase::Entry => {
                // If there is a record after, we set it to be the current record.
                if let Some(next) = self.entry.as_mut().unwrap().get_mut().next.take() {
                    self.phase = Phase::Next(next);
                }
            }
            Phase::Next(mut current) | Phase::PostInsert(mut current) => {
                // Take the next record and push the current one to the past list.
                let next = current.next.take();
                self.past_push(current);

                // Set the next record to be the current record.
                if let Some(next) = next {
                    self.phase = Phase::Next(next);
                }
            }
            Phase::Done => {}
            Phase::EntryDeleted => {
                self.phase = Phase::EntryDeleted;
            }
            Phase::PostDeleteNext(current) => {
                // If the stale value is some, we set it to be the current record.
                if let Some(current) = current {
                    self.phase = Phase::Next(current);
                }
            }
        }
        self.value()
    }

    /// Inserts a new value at the current position.
    pub fn insert(&mut self, v: V) {
        self.items.inc();
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                // Create a new record that points to entry's next.
                let new = Box::new(Record {
                    value: v,
                    next: self.entry.as_mut().unwrap().get_mut().next.take(),
                });

                // Set the phase to the new record.
                self.phase = Phase::PostInsert(new);
            }
            Phase::Next(mut current) => {
                // Take next.
                let next = current.next.take();

                // Add current to the past list.
                self.past_push(current);

                // Create a new record that points to the next's next.
                let new = Box::new(Record { value: v, next });
                self.phase = Phase::PostInsert(new);
            }
            Phase::Done => {
                // If we are done, we need to create a new record and
                // immediately push it to the past list.
                let new = Box::new(Record {
                    value: v,
                    next: None,
                });
                self.past_push(new);
            }
            Phase::EntryDeleted => {
                // If entry is deleted, we need to update it.
                self.entry.as_mut().unwrap().get_mut().value = v;

                // We don't consider overwriting a deleted entry a collision.
            }
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) | Phase::PostInsert(_) => {
                unreachable!("{MUST_CALL_NEXT}")
            }
        }
    }

    /// Deletes the current value, adjusting the list structure.
    pub fn delete(&mut self) {
        self.pruned.inc();
        self.items.dec();
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                // Attempt to overwrite the entry with the next value.
                let entry = self.entry.as_mut().unwrap().get_mut();
                if let Some(next) = entry.next.take() {
                    entry.value = next.value;
                    entry.next = next.next;
                    self.phase = Phase::PostDeleteEntry;
                    return;
                }

                // If there is no next, we consider the entry deleted.
                self.phase = Phase::EntryDeleted;
                // We wait to update metrics until `drop()`.
            }
            Phase::Next(mut current) => {
                // Drop current instead of pushing it to the past list.
                let next = current.next.take();
                self.phase = Phase::PostDeleteNext(next);
            }
            Phase::Done | Phase::EntryDeleted => unreachable!("{NO_ACTIVE_ITEM}"),
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) | Phase::PostInsert(_) => {
                unreachable!("{MUST_CALL_NEXT}")
            }
        }
    }
}

impl<T: Translator, V> Drop for Cursor<'_, T, V>
where
    V: Eq,
{
    fn drop(&mut self) {
        // Take the entry.
        let mut entry = self.entry.take().unwrap();

        // If there is a dangling next, we should add it to past.
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial | Phase::Entry => {
                // No action needed.
            }
            Phase::Next(next) => {
                // If there is a next, we should add it to past.
                self.past_push(next);
            }
            Phase::Done => {
                // No action needed.
            }
            Phase::EntryDeleted => {
                // If the entry is deleted, we should remove it.
                self.keys.dec();
                entry.remove();
                return;
            }
            Phase::PostDeleteEntry => {
                // No action needed.
            }
            Phase::PostDeleteNext(Some(next)) => {
                // If there is a stale record, we should add it to past.
                self.past_push(next);
            }
            Phase::PostDeleteNext(None) => {
                // No action needed.
            }
            Phase::PostInsert(next) => {
                // If there is a current record, we should add it to past.
                self.past_push(next);
            }
        }

        // Attach the tip of past to the entry.
        if let Some(past) = self.past.take() {
            entry.get_mut().next = Some(past);
        }
    }
}

/// An immutable iterator over the values associated with a translated key.
pub struct ImmutableCursor<'a, V: Eq> {
    current: Option<&'a Record<V>>,
}

impl<'a, V: Eq> ImmutableCursor<'a, V> {
    /// Creates a new `ImmutableCursor` from a `Record`.
    fn new(record: &'a Record<V>) -> Self {
        Self {
            current: Some(record),
        }
    }
}

impl<'a, V: Eq> Iterator for ImmutableCursor<'a, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        self.current.map(|record| {
            let value = &record.value;
            self.current = record.next.as_deref();
            value
        })
    }
}

/// A memory-efficient index that maps translated keys to arbitrary values.
pub struct Index<T: Translator, V: Eq> {
    translator: T,
    map: HashMap<T::Key, Record<V>, T>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Eq> Index<T, V> {
    /// Create a new index with the given translator.
    pub fn init(ctx: impl Metrics, tr: T) -> Self {
        let s = Self {
            translator: tr.clone(),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, tr),

            keys: Gauge::default(),
            items: Gauge::default(),
            pruned: Counter::default(),
        };
        ctx.register(
            "keys",
            "Number of translated keys in the index",
            s.keys.clone(),
        );
        ctx.register("items", "Number of items in the index", s.items.clone());
        ctx.register("pruned", "Number of items pruned", s.pruned.clone());
        s
    }

    #[inline]
    /// Returns the number of translated keys in the index.
    pub fn keys(&self) -> usize {
        self.map.len()
    }

    /// Returns an iterator over all values associated with a translated key.
    pub fn get(&self, key: &[u8]) -> impl Iterator<Item = &V> {
        let k = self.translator.transform(key);
        self.map
            .get(&k)
            .map(|record| ImmutableCursor::new(record))
            .into_iter()
            .flatten()
    }

    /// Provides mutable access to the values associated with a translated key, if the key exists.
    pub fn get_mut(&mut self, key: &[u8]) -> Option<Cursor<T, V>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                Some(Cursor::new(entry, &self.keys, &self.items, &self.pruned))
            }
            Entry::Vacant(_) => None,
        }
    }

    /// Create a new entry in the index.
    fn create(keys: &Gauge, items: &Gauge, vacant: VacantEntry<T::Key, Record<V>>, v: V) {
        keys.inc();
        items.inc();
        vacant.insert(Record {
            value: v,
            next: None,
        });
    }

    /// Provides mutable access to the values associated with a translated key (if the key exists), otherwise
    /// inserts a new value and returns `None`.
    pub fn get_mut_or_insert(&mut self, key: &[u8], v: V) -> Option<Cursor<T, V>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                Some(Cursor::new(entry, &self.keys, &self.items, &self.pruned))
            }
            Entry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, v);
                None
            }
        }
    }

    /// Remove all values at the given translated key.
    pub fn remove(&mut self, key: &[u8]) {
        // To ensure metrics are accurate, we iterate over all
        // conflicting values and remove them one-by-one (rather
        // than just removing the entire entry).
        self.prune(key, |_| true);
    }

    /// Insert a value at the given translated key.
    pub fn insert(&mut self, key: &[u8], v: V) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);
                cursor.next();
                cursor.insert(v);
            }
            Entry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, v);
            }
        }
    }

    /// Insert a value at the given translated key, and prune any values that are no longer valid.
    ///
    /// If the value is prunable, it will not be inserted.
    pub fn insert_and_prune(&mut self, key: &[u8], v: V, prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                // Get entry
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);

                // Remove anything that is prunable.
                loop {
                    let Some(old) = cursor.next() else {
                        break;
                    };
                    if prune(old) {
                        cursor.delete();
                    }
                }

                // Add our new value (if not prunable).
                if !prune(&v) {
                    cursor.insert(v);
                }
            }
            Entry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, v);
            }
        }
    }

    /// Remove all values associated with a translated key that match the `prune` predicate.
    pub fn prune(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                // Get cursor
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);

                // Remove anything that is prunable.
                loop {
                    let Some(old) = cursor.next() else {
                        break;
                    };
                    if prune(old) {
                        cursor.delete();
                    }
                }
            }
            Entry::Vacant(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::translator::TwoCap;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics};
    use rand::Rng;
    use std::collections::HashMap;

    #[test_traced]
    fn test_index_basic() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));

        // Generate a collision and check metrics to make sure it's captured
        let key = b"duplicate".as_slice();
        index.insert(key, 1);
        index.insert(key, 2);
        index.insert(key, 3);
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 3"));

        // Check that the values are in the correct order
        assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![1, 3, 2]);

        // Ensure cursor terminates
        {
            let mut cursor = index.get_mut(key).unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 3);
            assert_eq!(*cursor.next().unwrap(), 2);
            assert!(cursor.next().is_none());
        }

        // Make sure we can remove keys with a predicate
        index.insert(key, 3);
        index.insert(key, 4);
        index.prune(key, |i| *i == 3);
        assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![1, 2, 4]);
        index.prune(key, |_| true);
        // Try removing all of a keys values.
        assert_eq!(
            index.get(key).copied().collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));

        // Removing a key that doesn't exist should be a no-op.
        index.prune(key, |_| true);
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));
    }

    #[test_traced]
    fn test_index_many_keys() {
        let mut context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Insert enough keys to generate some collisions, then confirm each value we inserted
        // remains retrievable.
        let mut expected = HashMap::new();
        const NUM_KEYS: usize = 2000; // enough to generate some collisions
        while expected.len() < NUM_KEYS {
            let mut key_array = [0u8; 32];
            context.fill(&mut key_array);
            let key = key_array.to_vec();

            let loc = expected.len() as u64;
            index.insert(&key, loc);
            expected.insert(key, loc);
        }
        assert!(context.encode().contains("keys 1975"));
        assert!(context.encode().contains("items 2000"));

        for (key, loc) in expected.iter() {
            let mut values = index.get(key);
            let res = values.find(|i| *i == loc);
            assert!(res.is_some());
        }
    }

    #[test_traced]
    fn test_index_key_lengths_and_key_item_metrics() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Insert keys of different lengths
        index.insert(b"a", 1); // Shorter than cap (1 byte -> "a\0")
        index.insert(b"ab", 2); // Equal to cap (2 bytes -> "ab")
        index.insert(b"abc", 3); // Longer than cap (3 bytes -> "ab")
        assert!(context.encode().contains("keys 2"));
        assert!(context.encode().contains("items 3"));

        // Check that "a" maps to "a\0"
        assert_eq!(index.get(b"a").copied().collect::<Vec<_>>(), vec![1]);

        // Check that "ab" and "abc" map to "ab" due to TwoCap truncation
        let values = index.get(b"ab").copied().collect::<Vec<_>>();
        assert_eq!(values, vec![2, 3]);

        let values = index.get(b"abc").copied().collect::<Vec<_>>();
        assert_eq!(values, vec![2, 3]);

        // Insert another value for "ab"
        index.insert(b"ab", 4);
        assert_eq!(index.get(b"ab").copied().collect::<Vec<_>>(), vec![2, 4, 3]);
        assert!(context.encode().contains("keys 2"));
        assert!(context.encode().contains("items 4"));

        // Remove a specific value
        index.prune(b"ab", |v| *v == 4);
        assert_eq!(index.get(b"ab").copied().collect::<Vec<_>>(), vec![2, 3]);
        assert!(context.encode().contains("keys 2"));
        assert!(context.encode().contains("items 3"));

        // Remove all values for "ab"
        index.prune(b"ab", |_| true);
        assert_eq!(
            index.get(b"ab").copied().collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 1"));

        // Check that "a" is still present
        assert_eq!(index.get(b"a").copied().collect::<Vec<_>>(), vec![1]);
    }

    #[test_traced]
    fn test_index_value_order() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        // Values should be in stack order (last in first).
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 3, 2]
        );
    }

    #[test_traced]
    fn test_index_remove_specific() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        // Remove value 2
        index.prune(b"key", |v| *v == 2);
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1, 3]);

        // Remove head value 1
        index.prune(b"key", |v| *v == 1);
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![3]);
    }

    #[test_traced]
    fn test_index_empty_key() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"", 0); // Maps to [0, 0]
        index.insert(b"\0", 1); // Maps to [0, 0]
        index.insert(b"\0\0", 2); // Maps to [0, 0]

        // All keys map to [0, 0], so all values should be returned
        let mut values = index.get(b"").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        let mut values = index.get(b"\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        let mut values = index.get(b"\0\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        // Remove a specific value
        index.prune(b"", |v| *v == 1);
        let mut values = index.get(b"").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 2]);
    }

    #[test_traced]
    fn test_index_mutate_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        {
            let mut cursor = index.get_mut(b"key").unwrap();
            loop {
                let Some(old) = cursor.next() else {
                    break;
                };
                // Mutate the value
                let new = *old + 10;
                cursor.update(new);
            }
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![11, 12, 13]
        );
    }

    #[test_traced]
    fn test_index_remove_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        index.insert(b"key", 4);

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 4, 3, 2]
        );
        assert!(context.encode().contains("pruned_total 0"));

        // Test removing first value from the list.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
            assert!(context.encode().contains("pruned_total 1"));
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 2]
        );

        index.insert(b"key", 1);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 1, 3, 2]
        );

        // Test removing from the middle.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 4);
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
            assert!(context.encode().contains("pruned_total 2"));
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 2, 1]
        );
        index.insert(b"key", 3);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 2, 1]
        );

        // Test removing last value.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 4);
            assert_eq!(*cursor.next().unwrap(), 3);
            assert_eq!(*cursor.next().unwrap(), 2);
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
            assert!(context.encode().contains("pruned_total 3"));
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 2, 3]
        );

        // Test removing all values.
        index.remove(b"key");
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));
        assert!(context.encode().contains("pruned_total 6"));
    }

    #[test_traced]
    fn test_index_insert_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Add values to the index
        index.insert(b"key", 1);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.insert(3);
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1, 3]);
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 2"));

        // Try inserting into an iterator while iterating.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.insert(42);
        }
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 3"));

        // Verify second value is new one
        {
            let mut iter = index.get(b"key");
            assert_eq!(*iter.next().unwrap(), 1);
            assert_eq!(*iter.next().unwrap(), 42);
        }

        // Insert a new value
        index.insert(b"key", 100);

        // Iterate to end
        let mut iter = index.get(b"key");
        assert_eq!(*iter.next().unwrap(), 1);
        assert_eq!(*iter.next().unwrap(), 100);
        assert_eq!(*iter.next().unwrap(), 42);
        assert_eq!(*iter.next().unwrap(), 3);
        assert!(iter.next().is_none());
    }

    #[test_traced]
    fn test_index_remove_middle_then_next() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0, 3, 2, 1]
        for i in 0..4 {
            index.insert(b"key", i);
        }

        // Remove middle: [0, 1]
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0); // head
            assert_eq!(*cursor.next().unwrap(), 3); // middle
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 2); // middle
            cursor.delete();
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test_traced]
    fn test_index_remove_to_nothing() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0, 3, 2, 1]
        for i in 0..4 {
            index.insert(b"key", i);
        }

        // Remove middle: []
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
            assert_eq!(cursor.next(), None);
        }

        // Ensure item is deleted from index
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));
    }

    #[test_traced]
    fn test_index_remove_to_nothing_then_add() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0, 3, 2, 1]
        for i in 0..4 {
            index.insert(b"key", i);
        }

        // Remove middle: [4, 5]
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
            assert_eq!(cursor.next(), None);
            cursor.insert(4);
            assert_eq!(cursor.next(), None);
            cursor.insert(5);
        }

        // Ensure remaining values are correct
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test_traced]
    fn test_index_insert_and_remove_cursor() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0]
        index.insert(b"key", 0);

        // Remove item: []
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0); // head
            cursor.delete();
        }
        index.remove(b"key");
        assert!(index.get(b"key").copied().collect::<Vec<i32>>().is_empty());
    }

    #[test_traced]
    fn test_insert_and_prune_vacant() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Inserting into a *vacant* key behaves just like `insert`: 1 key, 1 item, nothing pruned.
        index.insert_and_prune(b"key", 1u64, |_| false);

        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1]);
        assert!(ctx.encode().contains("items 1"));
        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("pruned_total 0"));
    }

    #[test_traced]
    fn test_insert_and_prune_replace_one() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Add a value to the index
        index.insert(b"key", 1u64); // 0 collisions
        index.insert_and_prune(b"key", 2u64, |v| *v == 1); // replace

        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![2]);
        assert!(ctx.encode().contains("items 1"));
        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("pruned_total 1"));
    }

    #[test_traced]
    fn test_insert_and_prune_dead_insert() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Add multiple values to the same key
        index.insert(b"key", 10u64); // 0 collisions
        index.insert(b"key", 20u64); // +1 collision

        // Update an item if it matches the predicate
        index.insert_and_prune(b"key", 30u64, |_| true); // +2 pruned (and last value not added)

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<u64>>(),
            Vec::<u64>::new()
        );
        assert!(ctx.encode().contains("items 0"));
        assert!(ctx.encode().contains("keys 0"));
        assert!(ctx.encode().contains("pruned_total 2"));
    }

    #[test_traced]
    fn test_cursor_delete_then_next_returns_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        // Build list: [1, 2]
        index.insert(b"key", 1);
        index.insert(b"key", 2);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 1); // Phase::Current

        // After deleting the current element, `next` should yield the element that was
        // copied in from the old `next` node (the iterator does not advance).
        cursor.delete(); // remove 1, copy 2 into place
        assert_eq!(*cursor.next().unwrap(), 2); // should yield 2
        assert!(cursor.next().is_none()); // now exhausted
    }

    #[test_traced]
    fn test_cursor_insert_after_done_appends() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 10);

        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 10);
            assert!(cursor.next().is_none()); // Phase::Done

            // Inserting after we've already iterated to the end should append a new node.
            cursor.insert(20); // append while Done
        }

        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![10, 20]);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_cursor_update_before_next_panics() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        // Calling `update` before `next` is a logic error and should panic.
        cursor.update(321); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_cursor_delete_before_next_panics() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        // Calling `delete` before `next` is a logic error and should panic.
        cursor.delete(); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_cursor_update_after_done() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert!(cursor.next().is_none()); // Phase::Done

        // Calling `update` after `next` is a logic error and should panic.
        cursor.update(321); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_cursor_insert_before_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();

        // Calling `insert` after `next` is a logic error and should panic.
        cursor.insert(321); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_cursor_delete_after_done() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert!(cursor.next().is_none()); // Phase::Done

        // Calling `delete` after `next` is a logic error and should panic.
        cursor.delete(); // triggers unreachable! branch
    }

    #[test_traced]
    fn test_cursor_insert_with_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);
        index.insert(b"key", 456);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert_eq!(*cursor.next().unwrap(), 456);

        // Insert while in Phase::Next
        cursor.insert(789);

        // Call next to advance to Phase::Done
        assert_eq!(cursor.next(), None);

        // Add another value while in Phase::Done
        cursor.insert(999);

        // Check that everything worked
        drop(cursor);
        let mut values = index.get(b"key").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![123, 456, 789, 999]);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_cursor_double_delete() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);
        index.insert(b"key", 456);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        cursor.delete();

        // Attempt to delete again (will panic)
        cursor.delete();
    }

    #[test_traced]
    fn test_cursor_delete_last_then_next() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Insert two values
        index.insert(b"key", 1);
        index.insert(b"key", 2);

        // Get mutable cursor
        let mut cursor = index.get_mut(b"key").unwrap();

        // Iterate to the second value
        assert_eq!(*cursor.next().unwrap(), 1); // Phase::Entry
        assert_eq!(*cursor.next().unwrap(), 2); // Phase::Next

        // Delete the second value
        cursor.delete();

        // Call next() once, should return None
        assert!(cursor.next().is_none());

        // Call next() again, should keep returning None
        assert!(cursor.next().is_none());

        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 1"));
    }

    #[test_traced]
    fn test_delete_in_middle_then_continue() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 1); // Entry
        assert_eq!(*cur.next().unwrap(), 3); // Next
        cur.delete(); // remove 3
                      // iterator must yield 2, then None, then keep returning None
        assert_eq!(*cur.next().unwrap(), 2);
        assert!(cur.next().is_none());
        assert!(cur.next().is_none());
    }

    #[test_traced]
    fn test_delete_first() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 1); // Entry
            cur.delete(); // remove 1
            assert_eq!(*cur.next().unwrap(), 3); // Next
            assert_eq!(*cur.next().unwrap(), 2);
            assert!(cur.next().is_none());
            assert!(cur.next().is_none());
        }

        // Check that the values are still in the index
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![3, 2]);
    }

    #[test_traced]
    fn test_delete_first_and_insert() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        // Ensure the values are in the index
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 3, 2]
        );

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 1); // Entry
            cur.delete(); // remove 1
            assert_eq!(*cur.next().unwrap(), 3); // Next
            cur.insert(4); // insert 4
            assert_eq!(*cur.next().unwrap(), 2);
            assert!(cur.next().is_none());
            assert!(cur.next().is_none());
        }

        // Check that new values are around
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![3, 2, 4]
        );
    }

    #[test_traced]
    fn test_insert_at_entry_then_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2); // [1, 2]

        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 1); // Entry
        cur.insert(99); // [1, 99, 2]  (move from Phase::Entry to Phase::Next)

        // cursor must now iterate 99 to 2 to None
        assert_eq!(*cur.next().unwrap(), 2); // Next
        assert!(cur.next().is_none());
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_insert_at_entry_then_delete_head() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"key", 10);
        index.insert(b"key", 20); // [10, 20]

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 10);
            cur.insert(15);
            cur.delete();
        }
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_delete_then_insert_without_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"key", 10);
        index.insert(b"key", 20);

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 10);
            assert_eq!(*cur.next().unwrap(), 20);
            cur.delete();
            cur.insert(15);
        }
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_inserts_without_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"key", 10);
        index.insert(b"key", 20);

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 10);
            cur.insert(15);
            cur.insert(25);
        }
    }

    #[test_traced]
    fn test_delete_last_then_insert_while_done() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"k", 7);

        {
            let mut cur = index.get_mut(b"k").unwrap();
            assert_eq!(*cur.next().unwrap(), 7); // Entry
            cur.delete(); // list emptied, Done
            assert!(cur.next().is_none()); // Done

            cur.insert(8); // append while Done
            assert!(cur.next().is_none()); // still Done
            cur.insert(9); // another append while Done
            assert!(cur.next().is_none()); // still Done
        }

        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("items 2"));
        assert_eq!(index.get(b"k").copied().collect::<Vec<_>>(), vec![8, 9]);
    }

    #[test_traced]
    fn test_drop_mid_iteration_relinks() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        for i in 0..5 {
            index.insert(b"z", i);
        }

        {
            let mut cur = index.get_mut(b"z").unwrap();
            cur.next(); // Entry (0)
            cur.next(); // Next (4)
                        // cursor is dropped here after visiting two nodes
        }

        // All five values must still be visible and in stack order
        assert_eq!(
            index.get(b"z").copied().collect::<Vec<_>>(),
            vec![0, 4, 3, 2, 1]
        );
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_update_before_next_panics() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"p", 1);
        let mut cur = index.get_mut(b"p").unwrap();
        cur.update(2); // still illegal
    }

    #[test_traced]
    fn test_entry_replacement_not_a_collision() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"a", 1); // collisions = 0
        let mut cur = index.get_mut(b"a").unwrap();
        cur.next(); // Entry
        cur.delete(); // list empty, pruned = 1
        cur.next(); // Done
        cur.insert(2); // replacement, *not* collision

        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("items 1"));
    }
}
