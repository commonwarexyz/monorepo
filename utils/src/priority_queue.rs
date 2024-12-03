//! A generic priority queue that ensures any item is only included at most once.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

/// A generic priority queue that ensures any item is only included at most once.
pub struct PriorityQueue<I: Ord + Hash + Clone, V: Ord + Clone> {
    entries: BTreeMap<V, HashSet<I>>,
    keys: HashMap<I, V>,
}

impl<I: Ord + Hash + Clone, V: Ord + Clone> PriorityQueue<I, V> {
    /// Create a new priority queue.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            keys: HashMap::new(),
        }
    }

    /// Insert an item with a value, overwriting the previous value if it exists.
    pub fn put(&mut self, item: I, value: V) {
        // Check if the item already exists
        if let Some(old_value) = self.keys.insert(item.clone(), value.clone()) {
            // Remove the item from the old value's set
            if let Some(items) = self.entries.get_mut(&old_value) {
                items.remove(&item);
                if items.is_empty() {
                    self.entries.remove(&old_value);
                }
            }
        }

        // Insert the item into the new value's set
        self.entries.entry(value).or_default().insert(item);
    }

    /// Remove all previously inserted items not included in `items`
    /// and add any items not yet seen with a value of `initial`.
    pub fn retain(&mut self, initial: V, items: &[I]) {
        // Remove items not in the new set
        let new_items: HashSet<_> = items.iter().cloned().collect();
        self.keys.retain(|item, value| {
            if new_items.contains(item) {
                true
            } else {
                if let Some(items_set) = self.entries.get_mut(value) {
                    items_set.remove(item);
                    if items_set.is_empty() {
                        self.entries.remove(value);
                    }
                }
                false
            }
        });

        // Add new items with the initial value
        for item in new_items {
            if !self.keys.contains_key(&item) {
                self.put(item, initial.clone());
            }
        }
    }

    /// Iterate over all items in priority order.
    pub fn iter(&self) -> impl Iterator<Item = (&I, &V)> {
        self.entries
            .iter()
            .flat_map(|(value, items)| items.iter().map(move |item| (item, value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_put_and_iter() {
        let mut pq = PriorityQueue::new();

        let key1 = "key1";
        let key2 = "key2";

        pq.put(key1, Duration::from_secs(10));
        pq.put(key2, Duration::from_secs(5));

        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(*entries[0].0, key2);
        assert_eq!(*entries[1].0, key1);
    }

    #[test]
    fn test_update() {
        let mut pq = PriorityQueue::new();

        let key = "key";

        pq.put(key, Duration::from_secs(10));
        pq.put(key, Duration::from_secs(5));

        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].1, Duration::from_secs(5));
    }

    #[test]
    fn test_retain() {
        let mut pq = PriorityQueue::new();

        let key1 = "key1";
        let key2 = "key2";
        let key3 = "key3";

        pq.put(key1, Duration::from_secs(10));
        pq.put(key2, Duration::from_secs(5));

        pq.retain(Duration::from_secs(2), &[key1, key3]);

        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| *e.0 == key1 && *e.1 == Duration::from_secs(10)));
        assert!(entries
            .iter()
            .any(|e| *e.0 == key3 && *e.1 == Duration::from_secs(2)));
    }
}
