use crate::index::Translator;
use commonware_runtime::Metrics;
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{
        hash_map::{Entry, OccupiedEntry, VacantEntry},
        HashMap,
    },
    mem::swap,
};

/// The initial capacity of the hashmap. This is a guess at the number of unique keys we will
/// encounter. The hashmap will grow as needed, but this is a good starting point (covering
/// the entire [super::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

/// Each key is mapped to a `Record` that contains a linked list of potential values for the key.
///
/// In the common case of a single value associated with a key, the value is stored within the
/// HashMap entry and can be read without additional indirection (heap jumping).
struct Record<V> {
    value: V,

    next: Option<Box<Record<V>>>,
}

/// An iterator over all values associated with a translated key.
pub struct ValueIterator<'a, V> {
    next: Option<&'a Record<V>>,
}

impl<V> ValueIterator<'_, V> {
    /// Create a `ValueIterator` that returns no items.
    fn empty() -> Self {
        ValueIterator { next: None }
    }
}

impl<'a, V> Iterator for ValueIterator<'a, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next {
            Some(next) => {
                let value = &next.value;
                match next.next {
                    Some(ref next_next) => self.next = Some(next_next),
                    None => self.next = None,
                }
                Some(value)
            }
            None => None,
        }
    }
}

/// An iterator over all values associated with a translated key, allowing for mutation of the
/// current element and insertion of new elements at the front of the list.
pub struct UpdateValueIterator<'a, K, V> {
    /// The record holding the next value to return if set, otherwise there are no (more) elements
    /// to return.
    next: Option<*mut Record<V>>,

    /// The occupied entry from the hashmap whose records we're iterating over.
    o_entry: Option<OccupiedEntry<'a, K, Record<V>>>,

    /// The vacant entry from the hashmap whose records we're iterating over if the hashmap had no
    /// elements for the key.
    v_entry: Option<VacantEntry<'a, K, Record<V>>>,

    collisions_counter: &'a Counter,
}

/// UpdateValueIterator must be sendable across threads so it can be held across a journal's read
/// async boundary.
unsafe impl<K, V> Send for UpdateValueIterator<'_, K, V> {}

impl<'a, K, V> Iterator for UpdateValueIterator<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next {
            Some(next) => {
                // Return the value of the record pointed at by self.next, and update self.next to
                // point at the record after it.
                let current = unsafe { &mut (*next) };
                self.next = current.next.as_mut().map(|next| next.as_mut() as *mut _);

                Some(&mut current.value)
            }
            None => None,
        }
    }
}

impl<K, V> UpdateValueIterator<'_, K, V> {
    /// Insert a new value at the front of the list. We always add to the front so behavior is
    /// consistently last in, first out. This means most recently added values will be returned
    /// first by the iterators, providing an LRU like behavior. Calls to next() after insert() will
    /// always return None.
    pub fn insert(&mut self, mut value: V) {
        self.next = None; // self.next could end up invalidated by the insert, so we reset it.
        if let Some(ref mut o_entry) = self.o_entry {
            // Mutate the existing head of the list to have the new value, and create a new
            // record that will contain the previous first value.
            let record = o_entry.get_mut();
            swap(&mut record.value, &mut value);
            record.next = Some(Box::new(Record {
                value,
                next: record.next.take(),
            }));
            self.collisions_counter.inc();
            return;
        }
        if let Some(v_entry) = self.v_entry.take() {
            // Key had no associated values, so just turn the vacant entry into an occupied one.
            let occupied_entry = v_entry.insert_entry(Record { value, next: None });
            self.o_entry = Some(occupied_entry);
            return;
        }
        unreachable!("UpdateValueIterator should always have an entry");
    }
}

/// An iterator over all values associated with a translated key, allowing for mutation and removal
/// of the current element.
pub struct RemoveValueIterator<'a, K, V> {
    /// The previous element to the last returned value, if any.
    prev: Option<*mut Record<V>>,

    /// The last returned value if it hasn't been removed.
    last_returned: Option<*mut Record<V>>,

    /// The entry from the hashmap whose records we're iterating over, or None if there are no more
    /// elements to iterate over.
    entry: Option<OccupiedEntry<'a, K, Record<V>>>,

    /// The counter to increment each time we remove a value.
    pruned_counter: &'a Counter,
}

/// RemoveValueIterator must be sendable across threads so it can be held across a journal's read
/// async boundary.
unsafe impl<K, V> Send for RemoveValueIterator<'_, K, V> {}

impl<K, V> RemoveValueIterator<'_, K, V> {
    pub fn next(&mut self) -> Option<&mut V> {
        let entry = self.entry.as_mut()?;

        if let Some(last_returned) = self.last_returned {
            // Happy case: last returned value exists.
            let next = unsafe { (*last_returned).next.as_mut() };
            let Some(next) = next else {
                self.entry.take();
                return None;
            };
            let next = next.as_mut();
            self.prev = Some(last_returned);
            self.last_returned = Some(next);
            return Some(&mut next.value);
        }

        match self.prev {
            Some(prev) => {
                // Last returned value was removed, so we resume iterating from prev.next.
                let next = unsafe { (*prev).next.as_mut() };
                let Some(next) = next else {
                    self.entry.take();
                    return None;
                };
                let next = next.as_mut();
                self.last_returned = Some(next as *mut Record<V>);

                Some(&mut next.value)
            }
            None => {
                // This is the first call to next(), so we start from the head of the list.
                let next = entry.get_mut() as *mut Record<V>;
                self.last_returned = Some(next);
                let val = unsafe { &mut (*next).value };

                Some(val)
            }
        }
    }
}

impl<K, V> RemoveValueIterator<'_, K, V> {
    /// Consume the iterator and remove the last returned value, if any.
    pub fn remove(mut self) {
        self.unsafe_remove();
    }

    /// Remove the value last returned from this iterator from the map. If no value has been
    /// returned yet, or if the last returned value was removed already, then this is a no-op.
    ///
    /// ## Warning
    ///
    /// This operation invalidates the reference last returned by the iterator, and any accesses to
    /// it after this call may result in a crash.
    pub(crate) fn unsafe_remove(&mut self) {
        let Some(last_returned) = self.last_returned else {
            return;
        };
        let Some(occupied_entry) = self.entry.as_mut() else {
            unreachable!("occupied_entry should be set if last_returned is set");
        };
        self.pruned_counter.inc();

        match self.prev {
            None => {
                // We are removing the head of the list.
                let head = occupied_entry.get_mut();
                match head.next.take() {
                    Some(next) => {
                        // There is a linked element, so just make it the new head.
                        *head = *next;
                        self.prev = None;
                    }
                    None => {
                        // This is the only element, so removing it requires we remove the map entry
                        // entirely.
                        self.entry.take().unwrap().remove();
                        self.prev = None;
                    }
                }
            }
            Some(prev) => unsafe {
                (*prev).next = (*last_returned).next.take();
            },
        }
        self.last_returned = None;
    }
}

impl<V> Record<V> {
    fn iter(&self) -> ValueIterator<V> {
        ValueIterator { next: Some(self) }
    }
}

/// An index that maps translated keys to values.
pub struct Index<T: Translator, V> {
    translator: T,
    map: HashMap<T::Key, Record<V>, T>,

    collisions: Counter,
    keys_pruned: Counter,
}

impl<T: Translator, V> Index<T, V> {
    /// Create a new index.
    pub fn init(context: impl Metrics, translator: T) -> Self {
        let s = Self {
            translator: translator.clone(),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, translator),
            collisions: Counter::default(),
            keys_pruned: Counter::default(),
        };
        context.register("pruned", "Number of keys pruned", s.keys_pruned.clone());
        context.register(
            "collisions",
            "Number of translated key collisions",
            s.collisions.clone(),
        );

        s
    }

    /// The number of unique keys in the index after translation (so two keys that collide after
    /// translation will only be counted as one).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns if the index currently holds no values.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Insert a new record into the index. If there is a collision, then the new value will be
    /// added in front of the rest of values for this translated key.
    pub fn insert(&mut self, key: &[u8], mut value: V) {
        let translated_key = self.translator.transform(key);

        match self.map.entry(translated_key) {
            Entry::Occupied(mut occupied_entry) => {
                let record = occupied_entry.get_mut();
                swap(&mut record.value, &mut value); // puts the new value at the front
                record.next = Some(Box::new(Record {
                    value,
                    next: record.next.take(),
                }));
                self.collisions.inc();
            }
            Entry::Vacant(entry) => {
                entry.insert(Record { value, next: None });
            }
        };
    }

    /// Retrieve all values associated with a translated key.
    pub fn get_iter(&self, key: &[u8]) -> ValueIterator<V> {
        let translated_key = self.translator.transform(key);
        match self.map.get(&translated_key) {
            Some(head) => head.iter(),
            None => ValueIterator::empty(),
        }
    }

    /// Retrieve all values associated with a translated key, allowing for mutation & insertion if
    /// the key you are trying to update isn't currently active.
    pub fn update_iter(&mut self, key: &[u8]) -> UpdateValueIterator<T::Key, V> {
        let translated_key = self.translator.transform(key);
        let entry = self.map.entry(translated_key);
        match entry {
            Entry::Occupied(occupied_entry) => {
                let mut r = UpdateValueIterator {
                    next: None,
                    o_entry: Some(occupied_entry),
                    v_entry: None,
                    collisions_counter: &self.collisions,
                };
                r.next = r.o_entry.as_mut().map(|entry| entry.get_mut() as *mut _);

                r
            }
            Entry::Vacant(vacant_entry) => UpdateValueIterator {
                next: None,
                o_entry: None,
                v_entry: Some(vacant_entry),
                collisions_counter: &self.collisions,
            },
        }
    }

    /// Retrieve all values associated with a translated key, allowing for mutation and removal.
    pub fn remove_iter(&mut self, key: &[u8]) -> RemoveValueIterator<T::Key, V> {
        let translated_key = self.translator.transform(key);
        let entry = self.map.entry(translated_key);
        match entry {
            Entry::Occupied(occupied_entry) => RemoveValueIterator {
                prev: None,
                entry: Some(occupied_entry),
                last_returned: None,
                pruned_counter: &self.keys_pruned,
            },
            Entry::Vacant(_) => RemoveValueIterator {
                prev: None,
                last_returned: None,
                entry: None,
                pruned_counter: &self.keys_pruned,
            },
        }
    }

    /// Remove all values associated with a translated key that match the `prune` predicate.
    pub fn remove(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let mut iter = self.remove_iter(key);
        while let Some(value) = iter.next() {
            if prune(value) {
                iter.unsafe_remove();
            }
        }
    }
}
