use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

#[derive(Eq, PartialEq, Clone)]
struct Entry<I: Ord + Hash + Clone, V: Ord + Clone> {
    item: I,
    value: V,
}

impl<I: Ord + Hash + Clone, V: Ord + Clone> Ord for Entry<I, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.value.cmp(&other.value) {
            Ordering::Equal => self.item.cmp(&other.item),
            other => other,
        }
    }
}

impl<I: Ord + Hash + Clone, V: Ord + Clone> PartialOrd for Entry<I, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A generic priority queue that enforces item uniqueness and optimizes for
/// fast priority-ordered iteration rather than memory usage.
pub struct PriorityQueue<I: Ord + Hash + Clone, V: Ord + Clone> {
    entries: BTreeSet<Entry<I, V>>,
    keys: HashMap<I, V>,
}

impl<I: Ord + Hash + Clone, V: Ord + Clone> PriorityQueue<I, V> {
    /// Create a new priority queue.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            keys: HashMap::new(),
        }
    }

    /// Insert an item with a value, overwriting the previous value if it exists.
    pub fn put(&mut self, item: I, value: V) {
        // Check if the item already exists
        if let Some(old_value) = self.keys.insert(item.clone(), value.clone()) {
            // Remove the item from the old value's set
            let old_entry = Entry {
                item: item.clone(),
                value: old_value,
            };
            self.entries.remove(&old_entry);
        }

        // Insert the item into the new value's set
        let entry = Entry { item, value };
        self.entries.insert(entry);
    }

    /// Remove all previously inserted items not included in `keep`
    /// and add any items not yet seen with a value of `initial`.
    pub fn retain(&mut self, keep: &[I], initial: V) {
        // Remove items not in keep
        let mut retained: HashSet<_> = keep.iter().collect();
        self.keys.retain(|item, value| {
            if retained.remove(item) {
                true
            } else {
                let entry = Entry {
                    item: item.clone(),
                    value: value.clone(),
                };
                self.entries.remove(&entry);
                false
            }
        });

        // Add any items not yet removed with the initial value
        for item in retained {
            self.put(item.clone(), initial.clone());
        }
    }

    /// Iterate over all items in priority order.
    pub fn iter(&self) -> impl Iterator<Item = (&I, &V)> {
        self.entries.iter().map(|entry| (&entry.item, &entry.value))
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

        pq.retain(&[key1, key3], Duration::from_secs(2));

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
