use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap, HashSet},
    hash::Hash,
};

/// An entry in the `PrioritySet`.
#[derive(Eq, PartialEq)]
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

/// A set that offers efficient iteration over
/// its elements in priority-ascending order.
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

    /// Remove an item from the set.
    /// Returns `true` if the item was present.
    pub fn remove(&mut self, item: &I) -> bool {
        let Some(entry) = self.keys.remove(item).map(|priority| Entry {
            item: item.clone(),
            priority,
        }) else {
            return false;
        };
        assert!(self.entries.remove(&entry));
        true
    }

    /// Remove all previously inserted items not included in `keep`
    /// and add any items not yet seen with a priority of `initial`.
    pub fn reconcile(&mut self, keep: &[I], default: P) {
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
            self.put(item.clone(), default);
        }
    }

    /// Returns `true` if the set contains the item.
    pub fn contains(&self, item: &I) -> bool {
        self.keys.contains_key(item)
    }

    /// Returns the item with the highest priority.
    pub fn peek(&self) -> Option<(&I, &P)> {
        self.entries
            .iter()
            .next()
            .map(|entry| (&entry.item, &entry.priority))
    }

    /// Removes and returns the item with the highest priority.
    pub fn pop(&mut self) -> Option<(I, P)> {
        self.entries
            .pop_first()
            .map(|entry| (entry.item, entry.priority))
    }

    /// Returns an iterator over all items in the set in priority-ascending order.
    pub fn iter(&self) -> impl Iterator<Item = (&I, &P)> {
        self.entries
            .iter()
            .map(|entry| (&entry.item, &entry.priority))
    }

    /// Returns the number of items in the set.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_put_remove_and_iter() {
        // Create a new PrioritySet
        let mut pq = PrioritySet::new();

        // Add items with different priorities
        let key1 = "key1";
        let key2 = "key2";
        pq.put(key1, Duration::from_secs(10));
        pq.put(key2, Duration::from_secs(5));

        // Verify iteration order
        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(*entries[0].0, key2);
        assert_eq!(*entries[1].0, key1);

        // Remove existing item
        pq.remove(&key1);

        // Verify new iteration order
        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].0, key2);

        // Remove non-existing item
        pq.remove(&key1);

        // Verify iteration order is still the same
        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].0, key2);
    }

    #[test]
    fn test_update() {
        // Create a new PrioritySet
        let mut pq = PrioritySet::new();

        // Add an item with a priority and verify it can be retrieved
        let key = "key";
        pq.put(key, Duration::from_secs(10));
        assert_eq!(pq.get(&key).unwrap(), Duration::from_secs(10));

        // Update the priority and verify it has changed
        pq.put(key, Duration::from_secs(5));
        assert_eq!(pq.get(&key).unwrap(), Duration::from_secs(5));

        // Verify updated priority is in the iteration
        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].1, Duration::from_secs(5));
    }

    #[test]
    fn test_reconcile() {
        // Create a new PrioritySet
        let mut pq = PrioritySet::new();

        // Add 2 items with different priorities
        let key1 = "key1";
        let key2 = "key2";
        pq.put(key1, Duration::from_secs(10));
        pq.put(key2, Duration::from_secs(5));

        // Introduce a new item and remove an existing one
        let key3 = "key3";
        pq.reconcile(&[key1, key3], Duration::from_secs(2));

        // Verify iteration over only the kept items
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
