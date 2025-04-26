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

/// A wrapper for the hashmap entry when it can be either occupied or vacant.
enum MapEntry<'a, K, V> {
    Occupied(OccupiedEntry<'a, K, Record<V>>),
    Vacant(VacantEntry<'a, K, Record<V>>),
}

/// An iterator over all values associated with a translated key, allowing for mutation of the
/// current element and insertion of new elements at the front of the list.
pub struct UpdateValueIterator<'a, K, V> {
    next: Option<*mut Record<V>>,
    entry: Option<MapEntry<'a, K, V>>,
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
                let value = &mut current.value;
                self.next = current
                    .next
                    .as_mut()
                    .map(|next_next| next_next.as_mut() as *mut _);
                Some(value)
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
            MapEntry::Occupied(occupied_entry) => occupied_entry,
            MapEntry::Vacant(vacant_entry) => {
                // Key had no associated values, so just turn the vacant entry into an occupied one.
                let record = Record { value, next: None };
                let occupied_entry = vacant_entry.insert_entry(record);
                self.entry = Some(MapEntry::Occupied(occupied_entry));
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
        self.entry = Some(MapEntry::Occupied(occupied_entry));

        self.collisions_counter.inc();
    }
}

/// An iterator over all values associated with a translated key, allowing for mutation and removal
/// of the current element.
pub struct RemoveValueIterator<'a, K, V> {
    can_remove: bool, //  false means remove should be a no-op
    prev_prev: Option<*mut Record<V>>,
    prev: Option<*mut Record<V>>,
    next: Option<*mut Record<V>>,
    entry: Option<OccupiedEntry<'a, K, Record<V>>>,
    pruned_counter: &'a Counter,
}

/// RemoveValueIterator must be sendable across threads so it can be held across a journal's read
/// async boundary.
unsafe impl<K, V> Send for RemoveValueIterator<'_, K, V> {}

impl<'a, K, V> Iterator for RemoveValueIterator<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next {
            Some(next) => {
                let current = unsafe { &mut (*next) };
                let value = &mut current.value;
                self.prev_prev = self.prev;
                self.prev = self.next;
                self.next = current
                    .next
                    .as_mut()
                    .map(|next_next| next_next.as_mut() as *mut _);
                self.can_remove = true;
                Some(value)
            }
            None => None,
        }
    }
}

impl<K, V> RemoveValueIterator<'_, K, V> {
    /// Remove the value last returned from this iterator from the map. If no value has been
    /// returned yet, or if the last returned value was removed already, then this is a no-op.
    pub fn remove(&mut self) {
        if !self.can_remove {
            return;
        }
        self.can_remove = false;
        self.pruned_counter.inc();

        if let Some(prev_prev) = self.prev_prev {
            unsafe {
                (*prev_prev).next = (*self.prev.unwrap()).next.take();
            }
            return;
        }

        let Some(occupied_entry) = self.entry.as_mut() else {
            unreachable!("can_remove should prevent this");
        };

        // The element we are removing is at the front.
        let head = occupied_entry.get_mut();

        match head.next.take() {
            Some(next) => {
                // There is a linked element, so just make it the new head.
                *head = *next;
                self.prev = None;
                self.next = Some(head as *mut Record<V>);
            }
            None => {
                // This is the only element, so removing it requires we remove the map entry
                // entirely.
                self.entry.take().unwrap().remove();
                self.prev = None;
                self.next = None;
            }
        }
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
            Entry::Occupied(mut occupied_entry) => {
                let record_ptr = occupied_entry.get_mut();
                UpdateValueIterator {
                    next: Some(record_ptr),
                    entry: Some(MapEntry::Occupied(occupied_entry)),
                    collisions_counter: &self.collisions,
                }
            }
            Entry::Vacant(vacant_entry) => UpdateValueIterator {
                next: None,
                entry: Some(MapEntry::Vacant(vacant_entry)),
                collisions_counter: &self.collisions,
            },
        }
    }

    /// Retrieve all values associated with a translated key, allowing for mutation and removal.
    pub fn remove_iter(&mut self, key: &[u8]) -> RemoveValueIterator<T::Key, V> {
        let translated_key = self.translator.transform(key);
        let entry = self.map.entry(translated_key);
        match entry {
            Entry::Occupied(mut occupied_entry) => {
                let record_ptr = occupied_entry.get_mut();
                RemoveValueIterator {
                    can_remove: false,
                    prev_prev: None,
                    prev: None,
                    next: Some(record_ptr),
                    entry: Some(occupied_entry),
                    pruned_counter: &self.keys_pruned,
                }
            }
            Entry::Vacant(_) => RemoveValueIterator {
                can_remove: false,
                prev_prev: None,
                prev: None,
                next: None,
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
                iter.remove();
            }
        }
    }
}
