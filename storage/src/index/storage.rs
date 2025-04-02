use crate::index::Translator;
use commonware_runtime::Metrics;
use prometheus_client::metrics::counter::Counter;
use std::collections::{hash_map::Entry, HashMap};

/// Each key is mapped to a `Record` that contains a linked list of potential values for the key.
///
/// In the common case of a single value associated with a key, the value is stored within the HashMap
/// entry and can be read without additional indirection (heap jumping).
struct Record<V: Clone> {
    value: V,

    next: Option<Box<Record<V>>>,
}

/// An iterator over all values associated with a translated key.
pub struct ValueIterator<'a, V: Clone> {
    next: Option<&'a Record<V>>,
}

impl<V: Clone> ValueIterator<'_, V> {
    /// Create a `ValueIterator` that returns no items.
    fn empty() -> Self {
        ValueIterator { next: None }
    }
}

impl<V: Clone> Iterator for ValueIterator<'_, V> {
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next {
            Some(next) => {
                let loc = next.value.clone();
                self.next = next.next.as_deref();
                Some(loc)
            }
            None => None,
        }
    }
}

impl<V: Clone> Record<V> {
    fn iter(&self) -> ValueIterator<V> {
        ValueIterator { next: Some(self) }
    }
}

/// An index that maps translated keys to values.
pub struct Index<T: Translator, V: Clone> {
    translator: T,
    map: HashMap<T::Key, Record<V>>,

    collisions: Counter,
    keys_pruned: Counter,
}

impl<T: Translator, V: Clone> Index<T, V> {
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

    /// The number of unique keys in the index after translation (so two keys that collide after translation will only
    /// be counted as one).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns if the index currently holds no values.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Insert a new record into the index.
    pub fn insert(&mut self, key: &[u8], value: V) {
        let translated_key = self.translator.transform(key);

        match self.map.entry(translated_key) {
            Entry::Occupied(entry) => {
                let entry: &mut Record<V> = entry.into_mut();
                entry.next = Some(Box::new(Record {
                    value,
                    next: entry.next.take(),
                }));
                self.collisions.inc();
            }
            Entry::Vacant(entry) => {
                entry.insert(Record { value, next: None });
            }
        };
    }

    /// Retrieve all values associated with a translated key.
    pub fn get(&self, key: &[u8]) -> ValueIterator<V> {
        let translated_key = self.translator.transform(key);
        match self.map.get(&translated_key) {
            Some(head) => head.iter(),
            None => ValueIterator::empty(),
        }
    }

    /// Remove values associated with the key that match the `prune` predicate.
    ///
    /// If this function is never called, the amount of memory used by old values will grow
    /// unbounded.
    pub fn remove(&mut self, key: &[u8], prune: impl Fn(&V) -> bool) {
        let translated_key = self.translator.transform(key);
        let head = match self.map.get_mut(&translated_key) {
            Some(head) => head,
            None => return,
        };

        // Advance the head of the linked list to the first entry that will be retained, if any.
        loop {
            if !prune(&head.value) {
                break;
            }
            self.keys_pruned.inc();
            match head.next {
                Some(ref mut next) => {
                    head.value = next.value.clone();
                    head.next = next.next.take();
                }
                None => {
                    // No retained entries, so remove the key from the map.
                    self.map.remove(&translated_key);
                    return;
                }
            }
        }

        // Prune the remainder of the list.
        let mut cursor = head;
        while let Some(value) = cursor.next.as_ref().map(|next| &next.value) {
            if prune(value) {
                cursor.next = cursor.next.as_mut().unwrap().next.take();
                self.keys_pruned.inc();
                continue;
            }
            cursor = cursor.next.as_mut().unwrap();
        }
    }
}
