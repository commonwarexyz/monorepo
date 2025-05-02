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
struct Record<V: PartialEq + Eq> {
    value: V,
    next: Option<Box<Record<V>>>,
}

/// Phases of the `Cursor` during iteration.
#[derive(PartialEq, Eq)]
enum Phase<V: PartialEq + Eq> {
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
pub struct Cursor<'a, T: Translator, V: PartialEq + Eq> {
    phase: Phase<V>,

    entry: Option<OccupiedEntry<'a, T::Key, Record<V>>>,
    past: Option<Box<Record<V>>>,

    keys: &'a Gauge,
    items: &'a Gauge,
    collisions: &'a Counter,
    pruned: &'a Counter,
}

impl<'a, T: Translator, V: PartialEq + Eq> Cursor<'a, T, V> {
    /// Creates a new `Cursor` from a mutable record reference, detaching its `next` chain for iteration.
    fn new(
        entry: OccupiedEntry<'a, T::Key, Record<V>>,
        keys: &'a Gauge,
        items: &'a Gauge,
        collisions: &'a Counter,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            phase: Phase::Initial,

            entry: Some(entry),
            past: None,

            keys,
            items,
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
    ///
    /// Increments the `collisions` counter as this adds to an existing key's chain.
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
                self.collisions.inc();
            }
            Phase::Next(mut current) => {
                // Take next.
                let next = current.next.take();

                // Add current to the past list.
                self.past_push(current);

                // Create a new record that points to the next's next.
                let new = Box::new(Record { value: v, next });
                self.phase = Phase::PostInsert(new);
                self.collisions.inc();
            }
            Phase::Done => {
                // If we are done, we need to create a new record and
                // immediately push it to the past list.
                let new = Box::new(Record {
                    value: v,
                    next: None,
                });
                self.past_push(new);
                self.collisions.inc();
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
    ///
    /// Increments the `pruned` counter to track removals.
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
    V: PartialEq + Eq,
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
pub struct ImmutableCursor<'a, V: PartialEq + Eq> {
    current: Option<&'a Record<V>>,
}

impl<'a, V: PartialEq + Eq> ImmutableCursor<'a, V> {
    /// Creates a new `ImmutableCursor` from a `Record`.
    fn new(record: &'a Record<V>) -> Self {
        Self {
            current: Some(record),
        }
    }
}

impl<'a, V: PartialEq + Eq> Iterator for ImmutableCursor<'a, V> {
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
pub struct Index<T: Translator, V: PartialEq + Eq> {
    translator: T,
    map: HashMap<T::Key, Record<V>, T>,

    keys: Gauge,
    items: Gauge,
    collisions: Counter,
    pruned: Counter,
}

impl<T: Translator, V: PartialEq + Eq> Index<T, V> {
    /// Create a new index with the given translator.
    pub fn init(ctx: impl Metrics, tr: T) -> Self {
        let s = Self {
            translator: tr.clone(),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, tr),

            keys: Gauge::default(),
            items: Gauge::default(),
            collisions: Counter::default(),
            pruned: Counter::default(),
        };
        ctx.register(
            "keys",
            "Number of translated keys in the index",
            s.keys.clone(),
        );
        ctx.register("items", "Number of items in the index", s.items.clone());
        ctx.register("pruned", "Number of items pruned", s.pruned.clone());
        ctx.register(
            "collisions",
            "Number of item collisions",
            s.collisions.clone(),
        );
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
            Entry::Occupied(entry) => Some(Cursor::new(
                entry,
                &self.keys,
                &self.items,
                &self.collisions,
                &self.pruned,
            )),
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
            Entry::Occupied(entry) => Some(Cursor::new(
                entry,
                &self.keys,
                &self.items,
                &self.collisions,
                &self.pruned,
            )),
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
                let mut cursor = Cursor::<'_, T, V>::new(
                    entry,
                    &self.keys,
                    &self.items,
                    &self.collisions,
                    &self.pruned,
                );
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
                let mut cursor = Cursor::<'_, T, V>::new(
                    entry,
                    &self.keys,
                    &self.items,
                    &self.collisions,
                    &self.pruned,
                );

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
                let mut cursor = Cursor::<'_, T, V>::new(
                    entry,
                    &self.keys,
                    &self.items,
                    &self.collisions,
                    &self.pruned,
                );

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
