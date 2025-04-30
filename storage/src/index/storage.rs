use crate::index::Translator;
use commonware_runtime::Metrics;
use prometheus_client::metrics::counter::Counter;
use std::collections::{hash_map::Entry, HashMap};

/// The initial capacity of the hashmap. This is a guess at the number of unique keys we will
/// encounter. The hashmap will grow as needed, but this is a good starting point (covering
/// the entire [super::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

/// Each key is mapped to a `Record` that contains a value and optionally a `Vec` of values.
///
/// In the common case (where a single value is associated with a key), we store the value directly in the `Record`
/// to avoid both indirection (heap jumping) and unnecessary allocations (storing `Vec` directly would make all
/// `Record`s larger).
pub struct Record<V> {
    value: V,
    next: Option<Box<Record<V>>>,
}

impl<V> Record<V> {
    pub fn get(&self) -> &V {
        &self.value
    }

    pub fn peek(&self) -> Option<&V> {
        self.next.as_deref().map(|r| r.get())
    }

    pub fn update(&mut self, v: V) {
        self.value = v;
    }

    pub fn next(&self) -> Option<&Record<V>> {
        self.next.as_deref()
    }

    pub fn next_mut(&mut self) -> Option<&mut Record<V>> {
        self.next.as_deref_mut()
    }

    pub fn delete(&mut self) -> bool {
        let Some(next) = self.next.take() else {
            return false;
        };
        self.value = next.value;
        self.next = next.next;
        true
    }

    pub fn delete_next(&mut self) {
        let Some(next) = self.next.take() else {
            return;
        };
        self.next = next.next;
    }

    pub fn add(&mut self, v: V) {
        let next = Box::new(Record {
            value: v,
            next: self.next.take(),
        });
        self.next = Some(next);
    }
}

enum Phase {
    Initial,
    Current,
    Next,
    Done,
}

pub struct Cursor<'a, V> {
    phase: Phase,
    current: Option<&'a mut Record<V>>,
    next: Option<Box<Record<V>>>,

    collisions: &'a Counter,
    pruned: &'a Counter,
}

impl<'a, V> Cursor<'a, V> {
    pub fn new(record: &'a mut Record<V>, collisions: &'a Counter, pruned: &'a Counter) -> Self {
        let next = record.next.take();
        Self {
            phase: Phase::Initial,
            current: Some(record),
            next,

            collisions,
            pruned,
        }
    }

    pub fn update(&mut self, v: V) {
        match self.phase {
            Phase::Initial => {
                unreachable!("must call Cursor::next() before interacting")
            }
            Phase::Current => {
                self.current.as_mut().unwrap().update(v);
            }
            Phase::Next => {
                self.next.as_mut().unwrap().update(v);
            }
            Phase::Done => {
                unreachable!("Cursor::next() returned false")
            }
        }
    }

    pub fn next(&mut self) -> Option<&V> {
        match self.phase {
            Phase::Initial => {
                self.phase = Phase::Current;
                return self.current.as_deref().map(|r| r.get());
            }
            Phase::Current => {
                if self.next.is_some() {
                    self.phase = Phase::Next;
                    return self.next.as_deref().map(|r| r.get());
                }
                self.phase = Phase::Done;
                return None;
            }
            Phase::Next => {
                // Take ownership of all records.
                let current = self.current.take().unwrap();
                let mut next = self.next.take().unwrap();
                let next_next = next.next.take();

                // Repair current.
                current.next = Some(next);

                // Set current to be next (via a mutable reference to current).
                self.current = current.next_mut();

                // Set next to be the next record.
                self.next = next_next;

                // If we have a next record, return it.
                if self.next.is_some() {
                    return self.next.as_deref().map(|r| r.get());
                }
                self.phase = Phase::Done;
            }
            Phase::Done => {
                unreachable!("Cursor::next() returned false")
            }
        }
        None
    }

    pub fn insert(mut self, v: V) {
        self.collisions.inc();
        match self.phase {
            Phase::Initial => {
                unreachable!("must call Cursor::next() before interacting")
            }
            Phase::Current => {
                let new = Box::new(Record {
                    value: v,
                    next: self.next.take(),
                });
                self.next = Some(new);
            }
            Phase::Next => {
                // Take ownership of all records.
                let current = self.current.take().unwrap();
                let mut next = self.next.take().unwrap();
                let next_next = next.next.take();

                // Repair current.
                current.next = Some(next);

                // Set current to be next (via a mutable reference to current).
                self.current = current.next_mut();

                // Create a new record.
                let new = Box::new(Record {
                    value: v,
                    next: next_next,
                });
                self.next = Some(new);
            }
            Phase::Done => {
                // If we are done, next must be empty.
                let new = Box::new(Record {
                    value: v,
                    next: None,
                });
                self.next = Some(new);
            }
        }
    }

    pub fn delete(mut self) -> bool {
        self.pruned.inc();
        match self.phase {
            Phase::Initial => {
                unreachable!("must call Cursor::next() before interacting")
            }
            Phase::Current => {
                let Some(next) = self.next.take() else {
                    return false;
                };
                let current = self.current.as_mut().unwrap();
                current.value = next.value;
                current.next = next.next;
            }
            Phase::Next => {
                let next = self.next.take().unwrap();
                self.next = next.next;
            }
            Phase::Done => {
                unreachable!("Cursor::next() returned false")
            }
        }

        // If we make it here, there is at least one record left.
        true
    }
}

impl<V> Drop for Cursor<'_, V> {
    fn drop(&mut self) {
        // Re-inject the next record into the current record (if it exists).
        if let Some(next) = self.next.take() {
            if let Some(current) = self.current.take() {
                current.next = Some(next);
            }
        }
    }
}

/// An iterator over the values in a `Record` chain.
pub struct RecordIter<'a, V> {
    current: Option<&'a Record<V>>,
}

impl<'a, V> Iterator for RecordIter<'a, V> {
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

    pub fn get(&self, key: &[u8]) -> impl Iterator<Item = &V> {
        let k = self.translator.transform(key);
        self.map
            .get(&k)
            .map(|record| RecordIter {
                current: Some(record),
            })
            .into_iter()
            .flatten()
    }

    pub fn get_mut(&mut self, key: &[u8]) -> Option<Cursor<V>> {
        let k = self.translator.transform(key);
        self.map
            .get_mut(&k)
            .map(|record| Cursor::new(record, &self.collisions, &self.pruned))
    }

    /// Remove all values at the given translated key.
    pub fn remove(&mut self, key: &[u8]) {
        // We use `prune()` to ensure we count all dropped values.
        self.prune(key, |_| true);
    }

    /// Insert a value at the given translated key.
    ///
    /// If no value exists at the key, inserting via `insert()` will be more efficient than
    /// `mut_iter()` + `insert()`.
    pub fn insert(&mut self, key: &[u8], v: V) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut entry) => {
                self.collisions.inc();
                let entry = entry.get_mut();
                entry.add(v);
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
    /// If no value exists at the key or only 1 value exists at a key, inserting via `insert_and_prune()`
    /// will be more efficient than `mut_iter()` + `remove()` + `insert()`.
    pub fn insert_and_prune(&mut self, key: &[u8], v: V, prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut entry) => {
                // Get entry
                self.collisions.inc();
                let mut entry = entry.get_mut();

                // Check if first value should be changed
                let old = entry.get();
                if prune(old) {
                    entry.update(v);
                    self.pruned.inc();
                } else {
                    // If the first value is not pruned, we add the new value next.
                    entry.add(v);
                    entry = entry.next_mut().unwrap();
                }

                // Delete any prunable values.
                loop {
                    let Some(peek) = entry.peek() else {
                        break;
                    };
                    if prune(peek) {
                        entry.delete_next();
                        self.pruned.inc();
                    } else {
                        let Some(next) = entry.next_mut() else {
                            break;
                        };
                        entry = next;
                    }
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

    /// Remove a value at the given translated key, and prune any values that are no longer valid.
    ///
    /// If no value exists at the key or only 1 value exists at a key, this is more efficient than
    /// `mut_iter()` + `remove()`.
    pub fn prune(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut entry) => {
                let mut record = entry.get_mut();

                // Loop until we find a value that is not pruned.
                let remove = loop {
                    let old = record.get();
                    if prune(old) {
                        self.pruned.inc();
                        if !record.delete() {
                            // If there are no more values, remove the entry.
                            break true;
                        }
                        continue;
                    }
                    break false;
                };
                if remove {
                    entry.remove();
                    return;
                }

                // Now that we have some value that won't be pruned, we need to see if
                // we should prune any of the next values.
                loop {
                    let Some(peek) = record.peek() else {
                        break;
                    };
                    if prune(peek) {
                        record.delete_next();
                        self.pruned.inc();
                    } else {
                        let Some(next) = record.next_mut() else {
                            break;
                        };
                        record = next;
                    }
                }
            }
            Entry::Vacant(_) => {}
        }
    }
}
