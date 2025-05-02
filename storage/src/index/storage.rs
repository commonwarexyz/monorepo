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

#[derive(PartialEq, Eq)]
enum Phase<V: PartialEq + Eq> {
    Initial,
    Entry,
    Next(Box<Record<V>>),
    Done,
    PostDeleteEntry,
    PostDeleteNext(Option<Box<Record<V>>>),
}

pub struct Cursor<'a, T: Translator, V: PartialEq + Eq> {
    phase: Phase<V>,
    entry: Option<OccupiedEntry<'a, T::Key, Record<V>>>,
    entry_deleted: bool,
    past: Option<Box<Record<V>>>,
    collisions: &'a Counter,
    pruned: &'a Counter,
}

impl<'a, T: Translator, V: PartialEq + Eq> Cursor<'a, T, V> {
    fn new(
        entry: OccupiedEntry<'a, T::Key, Record<V>>,
        collisions: &'a Counter,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            phase: Phase::Initial,
            entry: Some(entry),
            entry_deleted: false,
            past: None,
            collisions,
            pruned,
        }
    }

    fn past_push(&mut self, new: Box<Record<V>>) {
        let mut new = new;
        new.next = self.past.take();
        self.past = Some(new);
    }

    pub fn update(&mut self, v: V) {
        match &mut self.phase {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                self.entry.as_mut().unwrap().get_mut().value = v;
            }
            Phase::Next(next) => {
                next.value = v;
            }
            Phase::Done => unreachable!("{NO_ACTIVE_ITEM}"),
            Phase::PostDeleteEntry => unreachable!("{NO_ACTIVE_ITEM}"),
            Phase::PostDeleteNext(_) => unreachable!("{NO_ACTIVE_ITEM}"),
        }
    }

    pub fn next(&mut self) -> Option<&V> {
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial => {
                self.phase = Phase::Entry;
                self.entry.as_ref().map(|r| &r.get().value)
            }
            Phase::Entry => {
                let next = self.entry.as_mut().unwrap().get_mut().next.take();
                if let Some(next) = next {
                    self.phase = Phase::Next(next);
                    if let Phase::Next(ref current) = self.phase {
                        Some(&current.value)
                    } else {
                        unreachable!()
                    }
                } else {
                    None
                }
            }
            Phase::Next(mut current) => {
                let next = current.next.take();
                self.past_push(current);
                if let Some(next) = next {
                    self.phase = Phase::Next(next);
                    if let Phase::Next(ref current) = self.phase {
                        Some(&current.value)
                    } else {
                        unreachable!()
                    }
                } else {
                    None
                }
            }
            Phase::PostDeleteEntry => {
                let value = self.entry.as_ref().map(|r| &r.get().value);
                if value.is_some() {
                    self.phase = Phase::Entry;
                } else {
                    self.phase = Phase::Done;
                }
                value
            }
            Phase::PostDeleteNext(current) => {
                if current.is_some() {
                    self.phase = Phase::Next(current.unwrap());
                    if let Phase::Next(ref current) = self.phase {
                        Some(&current.value)
                    } else {
                        unreachable!()
                    }
                } else {
                    None
                }
            }
            Phase::Done => None,
        }
    }

    pub fn insert(&mut self, v: V) {
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                let new = Box::new(Record {
                    value: v,
                    next: self.entry.as_mut().unwrap().get_mut().next.take(),
                });
                self.phase = Phase::Next(new);
                self.collisions.inc();
            }
            Phase::Next(mut current) => {
                let mut next = current.next.take().unwrap();
                let next_next = next.next.take();
                let new = Box::new(Record {
                    value: v,
                    next: next_next,
                });
                self.phase = Phase::Next(new);
                self.collisions.inc();
            }
            Phase::Done => {
                if self.entry_deleted {
                    self.entry_deleted = false;
                    self.entry.as_mut().unwrap().get_mut().value = v;
                    self.phase = Phase::Entry;
                } else {
                    let new = Box::new(Record {
                        value: v,
                        next: None,
                    });
                    self.past_push(new);
                }
                self.collisions.inc();
            }
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) => unreachable!("{MUST_CALL_NEXT}"),
        }
    }

    pub fn delete(&mut self) {
        self.pruned.inc();
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                let next = self.entry.as_mut().unwrap().get_mut().next.take();
                if let Some(next) = next {
                    self.entry.as_mut().unwrap().get_mut().value = next.value;
                    self.entry.as_mut().unwrap().get_mut().next = next.next;
                    self.phase = Phase::PostDeleteEntry;
                } else {
                    self.phase = Phase::Done;
                    self.entry_deleted = true;
                }
            }
            Phase::Next(mut current) => {
                let next = current.next.take();
                self.phase = Phase::PostDeleteNext(next);
            }
            Phase::Done => unreachable!("{NO_ACTIVE_ITEM}"),
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) => unreachable!("{NO_ACTIVE_ITEM}"),
        }
    }
}

impl<T: Translator, V> Drop for Cursor<'_, T, V>
where
    V: PartialEq + Eq,
{
    fn drop(&mut self) {
        let mut entry = self.entry.take().unwrap();
        if self.entry_deleted {
            entry.remove();
            return;
        }
        entry.get_mut().next = self.past.take();
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
    collisions: Counter,
    pruned: Counter,
}

impl<T: Translator, V: PartialEq + Eq> Index<T, V> {
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
