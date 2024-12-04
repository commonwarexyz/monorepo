use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

/// An entry in the `PrioritySet`.
#[derive(Eq, PartialEq, Clone)]
struct Entry<I: Ord + Hash + Clone, P: Ord + Copy> {
    item: I,
    priority: P,
}

impl<I: Ord + Hash + Clone, P: Ord + Copy> Ord for Entry<I, P> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.priority.cmp(&other.priority) {
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
pub struct PrioritySet<I: Ord + Hash + Clone, P: Ord + Copy> {
    entries: BTreeSet<Entry<I, P>>,
    keys: HashMap<I, P>,
}

impl<I: Ord + Hash + Clone, P: Ord + Copy> PrioritySet<I, P> {
    /// Create a new `PrioritySet`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            keys: HashMap::new(),
        }
    }

    /// Insert an item with a priority, overwriting the previous priority if it exists.
    pub fn put(&mut self, item: I, priority: P) {
        // Remove old entry, if it exists
        let entry = if let Some(old_priority) = self.keys.remove(&item) {
            // Remove the item from the old priority's set
            let mut old_entry = Entry {
                item: item.clone(),
                priority: old_priority,
            };
            self.entries.remove(&old_entry);

            // We reuse the entry to avoid another item clone
            old_entry.priority = priority;
            old_entry
        } else {
            Entry { item, priority }
        };

        // Insert the entry
        self.keys.insert(entry.item.clone(), entry.priority);
        self.entries.insert(entry);
    }

    /// Get the current priority of an item.
    pub fn get(&self, item: &I) -> Option<P> {
        self.keys.get(item).cloned()
    }

    /// Remove all previously inserted items not included in `keep`
    /// and add any items not yet seen with a priority of `initial`.
    pub fn reconcile(&mut self, keep: &[I], initial: P) {
        // Remove items not in keep
        let mut retained: HashSet<_> = keep.iter().collect();
        let to_remove = self
            .keys
            .keys()
            .filter(|item| !retained.remove(*item))
            .cloned()
            .collect::<Vec<_>>();
        for item in to_remove {
            let priority = self.keys.remove(&item).unwrap();
            let entry = Entry { item, priority };
            self.entries.remove(&entry);
        }

        // Add any items not yet removed with the initial priority
        for item in retained {
            self.put(item.clone(), initial);
        }
    }

    /// Iterate over all items in priority order.
    pub fn iter(&self) -> impl Iterator<Item = (&I, &P)> {
        self.entries
            .iter()
            .map(|entry| (&entry.item, &entry.priority))
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
