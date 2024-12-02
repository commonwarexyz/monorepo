use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

#[derive(Eq, PartialEq, Clone)]
pub struct Entry<I: Ord, V: Ord> {
    pub item: I,
    pub value: V,
}

impl<I: Ord, V: Ord> Ord for Entry<I, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.value.cmp(&other.value) {
            Ordering::Equal => self.item.cmp(&other.item),
            other => other,
        }
    }
}

impl<I: Ord, V: Ord> PartialOrd for Entry<I, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct PriorityQueue<I: Ord + Hash + Clone, V: Ord + Clone> {
    entries: BTreeSet<Entry<I, V>>,
    keys: HashMap<I, V>,
}

impl<I: Ord + Hash + Clone, V: Ord + Clone> PriorityQueue<I, V> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            keys: HashMap::new(),
        }
    }

    pub fn put(&mut self, item: I, value: V) {
        // Check if entry previously existed
        if let Some(old_value) = self.keys.get(&item) {
            // Remove old entry
            let old_entry = Entry {
                item: item.clone(),
                value: old_value.clone(),
            };
            self.entries.remove(&old_entry);
        }
        // Insert new entry
        let entry = Entry {
            item: item.clone(),
            value: value.clone(),
        };
        self.entries.insert(entry);
        self.keys.insert(item, value);
    }

    pub fn retain(&mut self, initial: V, items: &[I]) {
        // Turn new items into a set
        let new_items: HashSet<_> = items.iter().cloned().collect();

        // If a key is not in new keys, remove it
        self.keys.retain(|item, value| {
            if items.contains(item) {
                true
            } else {
                self.entries.remove(&Entry {
                    item: item.clone(),
                    value: value.clone(),
                });
                false
            }
        });

        // If a key is in new keys but not in old keys, add it
        for item in new_items {
            if !self.keys.contains_key(&item) {
                self.put(item, initial.clone());
            }
        }
    }

    // Iterate over the entries
    pub fn iter(&self) -> impl Iterator<Item = &Entry<I, V>> {
        self.entries.iter()
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

        let entries: Vec<_> = pq.iter().cloned().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].item, key2);
        assert_eq!(entries[1].item, key1);
    }

    #[test]
    fn test_update() {
        let mut pq = PriorityQueue::new();

        let key = "key";

        pq.put(key, Duration::from_secs(10));
        pq.put(key, Duration::from_secs(5));

        let entries: Vec<_> = pq.iter().cloned().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, Duration::from_secs(5));
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

        let entries: Vec<_> = pq.iter().cloned().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.item == key1 && e.value == Duration::from_secs(10)));
        assert!(entries
            .iter()
            .any(|e| e.item == key3 && e.value == Duration::from_secs(2)));
    }
}
