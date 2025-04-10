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
                let loc = &next.value;
                match next.next {
                    Some(ref next_next) => self.next = Some(next_next),
                    None => self.next = None,
                }
                Some(loc)
            }
            None => None,
        }
    }
}

/// A wrapper for the hashmap entry when it can be either occupied or vacant.
enum OccupiedOrVacant<'a, K, V> {
    Occupied(OccupiedEntry<'a, K, Record<V>>),
    Vacant(VacantEntry<'a, K, Record<V>>),
}

/// An iterator over all values associated with a translated key, allowing for mutation of the
/// current element and insertion of new elements at the front of the list.
pub struct UpdateValueIterator<'a, K, V> {
    next: Option<*mut Record<V>>,
    entry: Option<OccupiedOrVacant<'a, K, V>>,
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
                let current = unsafe { &mut (*next) };
                let loc = &mut current.value;
                self.next = current
                    .next
                    .as_mut()
                    .map(|next_next| next_next.as_mut() as *mut _);
                Some(loc)
            }
            None => None,
        }
    }
}

impl<K, V> UpdateValueIterator<'_, K, V> {
    /// Insert a new value at the front of the list. We always add to the front so behavior is
    /// consistently last in, first out. This means most recently added values will be returned
    /// first by the iterators, providing an LRU like behavior.
    pub fn insert(&mut self, mut value: V) {
        let entry = self.entry.take().unwrap();

        let mut occupied_entry = match entry {
            OccupiedOrVacant::Occupied(occupied_entry) => occupied_entry,
            OccupiedOrVacant::Vacant(vacant_entry) => {
                // Key had no associated values, so just turn the vacant entry into an occupied one.
                let record = Record { value, next: None };
                let occupied_entry = vacant_entry.insert_entry(record);
                self.entry = Some(OccupiedOrVacant::Occupied(occupied_entry));
                return;
            }
        };

        // This key already has a value, so add the new value to the front of the list.
        let record = occupied_entry.get_mut();
        swap(&mut record.value, &mut value); // puts the new value at the front
        record.next = Some(Box::new(Record {
            value,
            next: record.next.take(),
        }));
        self.entry = Some(OccupiedOrVacant::Occupied(occupied_entry));

        self.collisions_counter.inc();
    }
}

/// An iterator over all values associated with a translated key, allowing for mutation and deletion
/// of the current element.
pub struct DeleteValueIterator<'a, K, V> {
    prev: Option<*mut Record<V>>,
    next: Option<*mut Record<V>>,
    entry: Option<OccupiedEntry<'a, K, Record<V>>>,
    pruned_counter: &'a Counter,
}

/// DeleteValueIterator must be sendable across threads so it can be held across a journal's read
/// async boundary.
unsafe impl<K, V> Send for DeleteValueIterator<'_, K, V> {}

impl<'a, K, V> Iterator for DeleteValueIterator<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next {
            Some(next) => {
                let current = unsafe { &mut (*next) };
                let loc = &mut current.value;
                self.prev = self.next;
                self.next = current
                    .next
                    .as_mut()
                    .map(|next_next| next_next.as_mut() as *mut _);
                Some(loc)
            }
            None => None,
        }
    }
}

impl<K, V> DeleteValueIterator<'_, K, V> {
    /// Remove the value last returned from this iterator from the map. If no value has been
    /// returned yet, or if the last returned value was deleted already, then this is a no-op.
    pub fn remove(&mut self) {
        // This implementation is linear in the length of the linked list since it searches the list
        // from the beginning even when the current value is positioned towards the end. We could
        // make this constant time by storing an extra pointer, but since these lists are generally
        // tiny, it's unlikely to improve performance.
        let delete_me = match self.prev {
            Some(prev) => prev,
            None => return,
        };
        let occupied_entry = match self.entry.as_mut() {
            Some(entry) => entry,
            None => unreachable!("self.entry should not be None if self.prev is not None"),
        };
        let head = occupied_entry.get_mut();
        let head_ptr = head as *mut Record<V>;

        // If the element we are deleting is at the front, we simply update the map entry to point
        // to the next item (if any).
        if head_ptr == delete_me {
            match head.next.take() {
                Some(next) => {
                    // There is a linked element, so just make it the new head.
                    *head = *next;
                    self.prev = None;
                    self.next = Some(head as *mut Record<V>);
                    self.pruned_counter.inc();
                }
                None => {
                    // This is the only element, so removing it requires we remove the map entry
                    // entirely.
                    self.entry.take().unwrap().remove();
                    self.prev = None;
                    self.next = None;
                    self.pruned_counter.inc();
                }
            }
            return;
        }

        // The element must be one of the linked elements.
        let mut cursor = head_ptr;

        // Iterate through the linked list to find the element pointing to delete_me
        while let Some(next_box) = unsafe { (*cursor).next.as_mut() } {
            let next_ptr = next_box.as_mut() as *mut Record<V>;
            if next_ptr == delete_me {
                // Remove the element from the linked list
                unsafe {
                    let removed = (*cursor).next.take();
                    (*cursor).next = removed.unwrap().next
                };
                self.pruned_counter.inc();
                return;
            }
            cursor = next_ptr;
        }

        // delete_me (which was initialized with self.prev) should always point to an element
        // somewhere the list, otherwise something is very wrong.
        unreachable!("delete_me should always be in the list");
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
    map: HashMap<T::Key, Record<V>>,

    collisions: Counter,
    keys_pruned: Counter,
}

impl<T: Translator, V> Index<T, V> {
    /// Create a new index.
    pub fn init(context: impl Metrics, translator: T) -> Self {
        let s = Self {
            translator,
            map: HashMap::new(),
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
            Entry::Occupied(mut occupied_entry) => {
                let record_ptr = occupied_entry.get_mut();
                UpdateValueIterator {
                    next: Some(record_ptr),
                    entry: Some(OccupiedOrVacant::Occupied(occupied_entry)),
                    collisions_counter: &self.collisions,
                }
            }
            Entry::Vacant(vacant_entry) => UpdateValueIterator {
                next: None,
                entry: Some(OccupiedOrVacant::Vacant(vacant_entry)),
                collisions_counter: &self.collisions,
            },
        }
    }

    /// Retrieve all values associated with a translated key, allowing for mutation and deletion.
    pub fn delete_iter(&mut self, key: &[u8]) -> DeleteValueIterator<T::Key, V> {
        let translated_key = self.translator.transform(key);
        let entry = self.map.entry(translated_key);
        match entry {
            Entry::Occupied(mut occupied_entry) => {
                let record_ptr = occupied_entry.get_mut();
                DeleteValueIterator {
                    prev: None,
                    next: Some(record_ptr),
                    entry: Some(occupied_entry),
                    pruned_counter: &self.keys_pruned,
                }
            }
            Entry::Vacant(_) => DeleteValueIterator {
                prev: None,
                next: None,
                entry: None,
                pruned_counter: &self.keys_pruned,
            },
        }
    }

    /// Remove all values associated with a translated key that match the `prune` predicate.
    pub fn remove(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let mut iter = self.delete_iter(key);
        while let Some(value) = iter.next() {
            if prune(value) {
                iter.remove();
            }
        }
    }
}
