use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

#[derive(Eq, PartialEq, Clone)]
struct Entry<I: Ord + Hash + Clone, V: Ord + Copy> {
    item: I,
    value: V,
}

impl<I: Ord + Hash + Clone, V: Ord + Copy> Ord for Entry<I, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.value.cmp(&other.value) {
            Ordering::Equal => self.item.cmp(&other.item),
            other => other,
        }
    }
}

impl<I: Ord + Hash + Clone, V: Ord + Copy> PartialOrd for Entry<I, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A set that offers fast, priority-ordered iteration over
/// its elements.
pub struct PrioritySet<I: Ord + Hash + Clone, V: Ord + Copy> {
    entries: BTreeSet<Entry<I, V>>,
    keys: HashMap<I, V>,
}

impl<I: Ord + Hash + Clone, V: Ord + Copy> PrioritySet<I, V> {
    /// Create a new `PrioritySet`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            keys: HashMap::new(),
        }
    }

    /// Insert an item with a value, overwriting the previous value if it exists.
    pub fn put(&mut self, item: I, value: V) {
        // Remove old entry, if it exists
        let entry = if let Some(old_value) = self.keys.remove(&item) {
            // Remove the item from the old value's set
            let mut old_entry = Entry {
                item: item.clone(),
                value: old_value,
            };
            self.entries.remove(&old_entry);

            // We reuse the entry to avoid another item clone
            old_entry.value = value;
            old_entry
        } else {
            Entry { item, value }
        };

        // Insert the entry
        self.keys.insert(entry.item.clone(), entry.value);
        self.entries.insert(entry);
    }

    /// Get the current priority of an item.
    pub fn get(&self, item: &I) -> Option<V> {
        self.keys.get(item).cloned()
    }

    /// Remove all previously inserted items not included in `keep`
    /// and add any items not yet seen with a priority of `initial`.
    pub fn reconcile(&mut self, keep: &[I], initial: V) {
        // Remove items not in keep
        let mut retained: HashSet<_> = keep.iter().collect();
        let to_remove = self
            .keys
            .keys()
            .filter(|item| !retained.remove(*item))
            .cloned()
            .collect::<Vec<_>>();
        for item in to_remove {
            let value = self.keys.remove(&item).unwrap();
            let entry = Entry { item, value };
            self.entries.remove(&entry);
        }

        // Add any items not yet removed with the initial value
        for item in retained {
            self.put(item.clone(), initial);
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
        let mut pq = PrioritySet::new();

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
        let mut pq = PrioritySet::new();

        let key = "key";

        pq.put(key, Duration::from_secs(10));
        pq.put(key, Duration::from_secs(5));

        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].1, Duration::from_secs(5));
    }

    #[test]
    fn test_reconcile() {
        let mut pq = PrioritySet::new();

        let key1 = "key1";
        let key2 = "key2";
        let key3 = "key3";

        pq.put(key1, Duration::from_secs(10));
        pq.put(key2, Duration::from_secs(5));

        pq.reconcile(&[key1, key3], Duration::from_secs(2));

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
