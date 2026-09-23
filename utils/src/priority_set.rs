use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap, HashSet, hash_map::Entry as HashMapEntry},
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
    /// Creates an empty `PrioritySet`.
    ///
    /// To support efficient temporary replacement, this does not allocate heap storage.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            keys: HashMap::new(),
        }
    }

    /// Insert an item with a priority, replacing any equal item and its priority.
    pub fn put(&mut self, item: I, priority: P) {
        // Remove the old entry, if it exists
        if let Some((old_item, old_priority)) = self.keys.remove_entry(&item) {
            self.entries.remove(&Entry {
                item: old_item,
                priority: old_priority,
            });
        }

        // Insert the entry
        self.keys.insert(item.clone(), priority);
        self.entries.insert(Entry { item, priority });
    }

    /// Insert an item with a priority if no equal item is present.
    ///
    /// Returns `true` if the item was inserted. If an equal item is present, leaves it and its
    /// priority unchanged and returns `false`.
    pub fn insert(&mut self, item: I, priority: P) -> bool {
        let HashMapEntry::Vacant(slot) = self.keys.entry(item) else {
            return false;
        };
        self.entries.insert(Entry {
            item: slot.key().clone(),
            priority,
        });
        slot.insert(priority);
        true
    }

    /// Updates an existing item's priority using its current priority.
    ///
    /// Returns the updated priority, or `None` if the item is absent. The closure's result is
    /// stored even if it compares equal to the current priority. The closure is only called if
    /// the item exists. If it panics, the set is unchanged.
    pub fn update(&mut self, item: &I, f: impl FnOnce(P) -> P) -> Option<P> {
        let priority = self.keys.get_mut(item)?;
        let next = f(*priority);
        let mut entry = self
            .entries
            .take(&Entry {
                item: item.clone(),
                priority: *priority,
            })
            .expect("item missing from priority set");
        entry.priority = next;
        self.entries.insert(entry);
        *priority = next;
        Some(next)
    }

    /// Get the current priority of an item.
    pub fn get(&self, item: &I) -> Option<P> {
        self.keys.get(item).cloned()
    }

    /// Remove an item from the set.
    ///
    /// Returns `true` if the item was present.
    pub fn remove(&mut self, item: &I) -> bool {
        let Some((item, priority)) = self.keys.remove_entry(item) else {
            return false;
        };
        assert!(self.entries.remove(&Entry { item, priority }));
        true
    }

    /// Remove all previously inserted items not included in `keep`
    /// and add any items not already present with a priority of `default`.
    pub fn reconcile(&mut self, keep: &[I], default: P) {
        // Remove items not in keep
        let mut retained: HashSet<_> = keep.iter().collect();
        for (item, priority) in self.keys.extract_if(|item, _| !retained.remove(item)) {
            self.entries.remove(&Entry { item, priority });
        }

        // Add the items of keep that were not already present
        for item in retained {
            self.insert(item.clone(), default);
        }
    }

    /// Retains only the items where the key satisfies the predicate.
    pub fn retain(&mut self, predicate: impl Fn(&I) -> bool) {
        self.entries.retain(|entry| {
            let keep = predicate(&entry.item);
            if !keep {
                self.keys.remove(&entry.item);
            }
            keep
        });
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
        self.entries.pop_first().map(|entry| {
            self.keys.remove(&entry.item);
            (entry.item, entry.priority)
        })
    }

    /// Remove all items from the set.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.keys.clear();
    }

    /// Returns an iterator over all items in the set in priority-ascending order.
    pub fn iter(&self) -> impl Iterator<Item = (&I, &P)> {
        self.entries
            .iter()
            .map(|entry| (&entry.item, &entry.priority))
    }

    /// Returns the number of items in the set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
        time::Duration,
    };

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
    fn test_put_overwrite() {
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
    fn test_update() {
        let mut pq = PrioritySet::new();
        pq.put("a", 10);
        pq.put("b", 20);
        pq.put("c", 30);

        assert_eq!(pq.update(&"missing", |_| panic!("missing item")), None);
        assert_eq!(pq.update(&"a", |priority| priority + 30), Some(40));
        assert_eq!(pq.get(&"a"), Some(40));
        assert_eq!(pq.peek(), Some((&"b", &20)));

        assert_eq!(pq.update(&"c", |priority| priority - 10), Some(20));
        assert_eq!(pq.update(&"b", |priority| priority), Some(20));
        assert_eq!(pq.len(), 3);
        assert_eq!(
            pq.iter()
                .map(|(&item, &priority)| (item, priority))
                .collect::<Vec<_>>(),
            vec![("b", 20), ("c", 20), ("a", 40)]
        );

        assert!(pq.remove(&"c"));
        assert_eq!(pq.pop(), Some(("b", 20)));
        assert_eq!(pq.pop(), Some(("a", 40)));
        assert!(pq.is_empty());
        assert_eq!(pq.get(&"a"), None);
        assert_eq!(pq.get(&"b"), None);
        assert_eq!(pq.get(&"c"), None);
    }

    #[test]
    fn test_put_replaces_item() {
        let mut pq = PrioritySet::new();
        pq.put(Arc::new("item"), 10);

        let replacement = Arc::new("item");
        pq.put(replacement.clone(), 11);
        assert_eq!(pq.len(), 1);
        assert!(Arc::ptr_eq(pq.peek().unwrap().0, &replacement));
        assert!(Arc::ptr_eq(pq.keys.keys().next().unwrap(), &replacement));
    }

    #[test]
    fn test_update_preserves_item() {
        let mut pq = PrioritySet::new();
        let item = Arc::new("item");
        pq.put(item.clone(), 10);

        let lookup = Arc::new("item");
        assert_eq!(pq.update(&lookup, |priority| priority + 1), Some(11));
        assert!(Arc::ptr_eq(pq.peek().unwrap().0, &item));
        assert!(Arc::ptr_eq(pq.keys.keys().next().unwrap(), &item));
    }

    #[test]
    fn test_insert() {
        let mut pq = PrioritySet::new();
        let item = Arc::new("item");
        assert!(pq.insert(item.clone(), 10));

        let duplicate = Arc::new("item");
        assert!(!pq.insert(duplicate, 5));
        assert_eq!(pq.get(&item), Some(10));
        assert_eq!(pq.len(), 1);
        assert!(Arc::ptr_eq(pq.peek().unwrap().0, &item));
        assert!(Arc::ptr_eq(pq.keys.keys().next().unwrap(), &item));
    }

    /// A priority whose ordering ignores `tag`.
    #[derive(Clone, Copy)]
    struct Tagged {
        rank: u32,
        tag: u32,
    }

    impl PartialEq for Tagged {
        fn eq(&self, other: &Self) -> bool {
            self.rank == other.rank
        }
    }

    impl Eq for Tagged {}

    impl PartialOrd for Tagged {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Tagged {
        fn cmp(&self, other: &Self) -> Ordering {
            self.rank.cmp(&other.rank)
        }
    }

    #[test]
    fn test_update_stores_equal_priority() {
        let mut pq = PrioritySet::new();
        pq.put("a", Tagged { rank: 1, tag: 10 });

        let updated = pq.update(&"a", |priority| Tagged {
            tag: 20,
            ..priority
        });
        assert_eq!(updated.map(|priority| priority.tag), Some(20));
        assert_eq!(pq.get(&"a").map(|priority| priority.tag), Some(20));
        assert_eq!(pq.peek().map(|(_, priority)| priority.tag), Some(20));
        assert_eq!(pq.pop().map(|(_, priority)| priority.tag), Some(20));
    }

    #[test]
    fn test_update_panic_preserves_set() {
        let mut pq = PrioritySet::new();
        pq.put("a", 10);
        pq.put("b", 20);

        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                pq.update(&"a", |_| panic!("update failed"));
            }))
            .is_err()
        );
        assert_eq!(pq.get(&"a"), Some(10));
        assert_eq!(pq.get(&"b"), Some(20));
        assert_eq!(pq.pop(), Some(("a", 10)));
        assert_eq!(pq.pop(), Some(("b", 20)));
        assert!(pq.is_empty());
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
        assert!(
            entries
                .iter()
                .any(|e| *e.0 == key1 && *e.1 == Duration::from_secs(10))
        );
        assert!(
            entries
                .iter()
                .any(|e| *e.0 == key3 && *e.1 == Duration::from_secs(2))
        );
    }

    #[test]
    fn test_retain() {
        // Create a new PrioritySet
        let mut pq = PrioritySet::new();

        // Add items with different priorities
        pq.put("key1", Duration::from_secs(10));
        pq.put("key2", Duration::from_secs(5));
        pq.put("item3", Duration::from_secs(15));

        // Retain only items that start with "key"
        pq.retain(|key| key.starts_with("key"));

        // Verify that only "key1" and "key2" are present
        assert_eq!(pq.len(), 2);
        assert!(pq.contains(&"key1"));
        assert!(pq.contains(&"key2"));
        assert!(!pq.contains(&"item3"));

        // Verify iteration order
        let entries: Vec<_> = pq.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(*entries[0].0, "key2");
        assert_eq!(*entries[1].0, "key1");
    }

    #[test]
    fn test_clear() {
        // Create a new PrioritySet
        let mut pq = PrioritySet::new();

        // Add some items
        pq.put("key1", Duration::from_secs(10));
        pq.put("key2", Duration::from_secs(5));

        // Clear the set
        pq.clear();

        // Verify the set is empty
        assert_eq!(pq.len(), 0);
        assert!(pq.is_empty());
        assert!(pq.iter().next().is_none());
        assert!(pq.peek().is_none());
    }
}
