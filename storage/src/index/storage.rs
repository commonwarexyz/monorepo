use crate::index::Translator;
use commonware_runtime::Metrics;
use prometheus_client::metrics::counter::Counter;
use std::collections::{
    hash_map::{Entry, OccupiedEntry},
    HashMap,
};

/// The initial capacity of the internal hashmap. This is a guess at the number of unique keys we will
/// encounter. The hashmap will grow as needed, but this is a good starting point (covering
/// the entire [super::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

/// Each key is mapped to a `Record` that contains a linked list of potential values for that key.
///
/// We avoid using a `Vec` to store values because the common case (where there are no collisions) would
/// require an additional 24 bytes of memory for each value (the `len`, `capacity`, and `ptr` fields).
///
/// Again optimizing for the common case, we store the first value directly in the `Record` to avoid
/// indirection (heap jumping).
struct Record<V> {
    value: V,
    next: Option<Box<Record<V>>>,
}

/// Phases of the `Cursor` during iteration.
#[derive(PartialEq, Eq)]
enum Phase {
    /// Before iteration starts.
    Initial,
    /// Pointing to the entry.
    Entry,
    /// Pointing to the next record in the list.
    Next,
    /// Iteration is done (only insertions can occur).
    Done,
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
pub struct Cursor<'a, T: Translator, V> {
    phase: Phase,

    entry: Option<OccupiedEntry<'a, T::Key, Record<V>>>,
    next: Option<Box<Record<V>>>,
    past: Option<Box<Record<V>>>,

    last_deleted: bool,
    entry_deleted: bool,

    collisions: &'a Counter,
    pruned: &'a Counter,
}

impl<'a, T: Translator, V> Cursor<'a, T, V> {
    /// Creates a new `Cursor` from a mutable record reference, detaching its `next` chain for iteration.
    fn new(
        mut entry: OccupiedEntry<'a, T::Key, Record<V>>,
        collisions: &'a Counter,
        pruned: &'a Counter,
    ) -> Self {
        let next = entry.get_mut().next.take();
        Self {
            phase: Phase::Initial,

            entry: Some(entry),
            next,
            past: None,

            last_deleted: false,
            entry_deleted: false,

            collisions,
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
        assert!(!self.last_deleted);
        match self.phase {
            Phase::Initial => {
                unreachable!("must call Cursor::next() before interacting")
            }
            Phase::Entry => {
                self.entry.as_mut().unwrap().get_mut().value = v;
            }
            Phase::Next => {
                self.next.as_mut().unwrap().value = v;
            }
            Phase::Done => {
                unreachable!(
                    "only Cursor::insert() can be called after Cursor::next() returns None"
                )
            }
        }
    }

    /// Advances the cursor to the next value in the chain, returning a reference to it.
    ///
    /// Handles transitions between phases and adjusts for deletions. Returns `None` when the list is exhausted.
    /// It is safe to call `next()` even after it returns `None`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&V> {
        let last_deleted = self.last_deleted;
        self.last_deleted = false;
        match self.phase {
            Phase::Initial => {
                self.phase = Phase::Entry;
                return self.entry.as_ref().map(|r| &r.get().value);
            }
            Phase::Entry => {
                // If the last operation was a delete, do nothing.
                if last_deleted {
                    return self.entry.as_ref().map(|r| &r.get().value);
                }

                // If there is an entry after, we set it to be the current record.
                if self.next.is_none() {
                    // If there is no next, we are done.
                    self.phase = Phase::Done;
                    return None;
                }
                self.phase = Phase::Next;
                return self.next.as_deref().map(|r| &r.value);
            }
            Phase::Next => {
                // If last deleted, do noting.
                if last_deleted {
                    return self.next.as_deref().map(|r| &r.value);
                }

                // Take ownership of all records.
                let mut next = self.next.take().unwrap();
                let next_next = next.next.take();

                // Add next to the past list.
                self.past_push(next);

                // Set next to be next's next.
                self.next = next_next;

                // If we have a next record, return it.
                if self.next.is_some() {
                    return self.next.as_deref().map(|r| &r.value);
                }
                self.phase = Phase::Done;
            }
            Phase::Done => {
                // We allow calling next() unnecessarily as inner ops may move us to `Phase::Done` (unbenownst to
                // the caller).
            }
        }
        None
    }

    /// Inserts a new value at the current position.
    ///
    /// Increments the `collisions` counter as this adds to an existing key's chain.
    pub fn insert(&mut self, v: V) {
        assert!(!self.last_deleted);
        self.collisions.inc();
        match self.phase {
            Phase::Initial => {
                unimplemented!("must call Cursor::next() before interacting")
            }
            Phase::Entry => {
                // Create a new record that points to next.
                let new = Box::new(Record {
                    value: v,
                    next: self.next.take(),
                });

                // Set current next to be the new record.
                self.next = Some(new);
            }
            Phase::Next => {
                // Take next
                let mut next = self.next.take().unwrap();
                let next_next = next.next.take();

                // Add next to the past list.
                self.past_push(next);

                // Create a new record that points to next's next.
                let new = Box::new(Record {
                    value: v,
                    next: next_next,
                });
                self.next = Some(new);
            }
            Phase::Done => {
                // If entry is deleted, we need to update it.
                if self.entry_deleted {
                    self.entry_deleted = false;
                    self.entry.as_mut().unwrap().get_mut().value = v;
                    return;
                }

                // If not, we should add to past.
                let new = Box::new(Record {
                    value: v,
                    next: None,
                });
                self.past_push(new);
            }
        }
    }

    /// Deletes the current value, adjusting the list structure.
    ///
    /// Increments the `pruned` counter to track removals.
    pub fn delete(&mut self) {
        assert!(!self.last_deleted);
        self.last_deleted = true;
        self.pruned.inc();
        match self.phase {
            Phase::Initial => {
                unreachable!("must call Cursor::next() before interacting")
            }
            Phase::Entry => {
                // Attempt to overwrite the entry with the next value.
                let Some(mut next) = self.next.take() else {
                    // If there is no next, we are done.
                    self.phase = Phase::Done;
                    self.entry_deleted = true;
                    return;
                };

                // Update in-place.
                let next_next = next.next.take();
                self.entry.as_mut().unwrap().get_mut().value = next.value;
                self.next = next_next;
            }
            Phase::Next => {
                let next = self.next.take().unwrap();
                self.next = next.next;
            }
            Phase::Done => {
                unreachable!(
                    "only Cursor::insert() can be called after Cursor::next() returns None"
                )
            }
        }
    }
}

impl<T: Translator, V> Drop for Cursor<'_, T, V> {
    fn drop(&mut self) {
        // Take entry
        let mut entry = self.entry.take().unwrap();

        // If there is nothing left, delete the entry.
        if self.entry_deleted {
            entry.remove();
            return;
        }

        // If there is a next, we should add it to past.
        if let Some(next) = self.next.take() {
            if self.past.is_none() {
                self.past = Some(next);
            } else {
                let mut past = self.past.take().unwrap();
                past.next = Some(next);
                self.past = Some(past);
            }
        }

        // Take past and attach it to the entry.
        let past = self.past.take();
        entry.get_mut().next = past;
    }
}

/// An immutable iterator over the values associated with a translated key.
pub struct ImmutableCursor<'a, V> {
    current: Option<&'a Record<V>>,
}

impl<'a, V> ImmutableCursor<'a, V> {
    /// Creates a new `ImmutableCursor` from a `Record`.
    fn new(record: &'a Record<V>) -> Self {
        Self {
            current: Some(record),
        }
    }
}

impl<'a, V> Iterator for ImmutableCursor<'a, V> {
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
pub struct Index<T: Translator, V> {
    translator: T,
    map: HashMap<T::Key, Record<V>, T>,
    collisions: Counter,
    pruned: Counter,
}

impl<T: Translator, V> Index<T, V> {
    /// Create a new index with the given translator.
    pub fn init(ctx: impl Metrics, tr: T) -> Self {
        let s = Self {
            translator: tr.clone(),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, tr),
            collisions: Counter::default(),
            pruned: Counter::default(),
        };
        ctx.register("pruned", "Number of items pruned", s.pruned.clone());
        ctx.register(
            "collisions",
            "Number of item collisions",
            s.collisions.clone(),
        );
        s
    }

    /// Return the number of translated keys in the index (there may
    /// be many more total entries, with multiple keys per translated
    /// key).
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Return whether the index is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
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
            Entry::Occupied(entry) => Some(Cursor::new(entry, &self.collisions, &self.pruned)),
            Entry::Vacant(_) => None,
        }
    }

    /// Provides mutable access to the values associated with a translated key (if the key exists), otherwise
    /// inserts a new value and returns `None`.
    pub fn get_mut_or_insert(&mut self, key: &[u8], v: V) -> Option<Cursor<T, V>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => Some(Cursor::new(entry, &self.collisions, &self.pruned)),
            Entry::Vacant(entry) => {
                let record = Record {
                    value: v,
                    next: None,
                };
                entry.insert(record);
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
                let mut cursor = Cursor::<'_, T, V>::new(entry, &self.collisions, &self.pruned);
                cursor.next();
                cursor.insert(v);
            }
            Entry::Vacant(entry) => {
                entry.insert(Record {
                    value: v,
                    next: None,
                });
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
                let mut cursor = Cursor::<'_, T, V>::new(entry, &self.collisions, &self.pruned);

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
                // No collision, so we can just insert the value.
                entry.insert(Record {
                    value: v,
                    next: None,
                });
            }
        }
    }

    /// Remove all values associated with a translated key that match the `prune` predicate.
    pub fn prune(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                // Get cursor
                let mut cursor = Cursor::<'_, T, V>::new(entry, &self.collisions, &self.pruned);

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
