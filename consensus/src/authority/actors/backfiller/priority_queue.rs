use commonware_cryptography::PublicKey;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

#[derive(Eq, PartialEq, Clone)]
struct Entry {
    duration: Duration,
    pub public_key: PublicKey,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.duration.cmp(&other.duration) {
            Ordering::Equal => self.public_key.cmp(&other.public_key),
            other => other,
        }
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct PriorityQueue {
    entries: BTreeSet<Entry>,
    keys: HashMap<PublicKey, Duration>,
}

impl PriorityQueue {
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            keys: HashMap::new(),
        }
    }

    pub fn put(&mut self, public_key: PublicKey, duration: Duration) {
        // Check if entry previously existed
        if let Some(&old_duration) = self.keys.get(&public_key) {
            // Remove old entry
            let old_entry = Entry {
                duration: old_duration,
                public_key: public_key.clone(),
            };
            self.entries.remove(&old_entry);
        }
        // Insert new entry
        let entry = Entry {
            duration,
            public_key: public_key.clone(),
        };
        self.entries.insert(entry);
        self.keys.insert(public_key, duration);
    }

    pub fn retain(&mut self, keys: &Vec<PublicKey>) {
        // Turn new keys into a set
        let new_keys: HashSet<_> = keys.iter().cloned().collect();

        // If a key is not in new keys, remove it
        self.keys.retain(|key, duration| {
            if new_keys.contains(key) {
                true
            } else {
                self.entries.remove(&Entry {
                    duration: *duration,
                    public_key: key.clone(),
                });
                false
            }
        });

        // If a key is in new keys but not in old keys, add it
        for key in new_keys {
            if !self.keys.contains_key(&key) {
                self.put(key, Duration::default());
            }
        }
    }

    // Iterate over the entries
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Ed25519, Scheme};
    use std::time::Duration;

    #[test]
    fn test_put_and_iter() {
        let mut pq = PriorityQueue::new();

        let key1 = Ed25519::from_seed(0).public_key();
        let key2 = Ed25519::from_seed(1).public_key();

        pq.put(key1.clone(), Duration::from_secs(10));
        pq.put(key2.clone(), Duration::from_secs(5));

        let entries: Vec<_> = pq.iter().cloned().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].public_key, key2);
        assert_eq!(entries[1].public_key, key1);
    }

    #[test]
    fn test_update() {
        let mut pq = PriorityQueue::new();

        let key = Ed25519::from_seed(0).public_key();

        pq.put(key.clone(), Duration::from_secs(10));
        pq.put(key.clone(), Duration::from_secs(5));

        let entries: Vec<_> = pq.iter().cloned().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].duration, Duration::from_secs(5));
    }

    #[test]
    fn test_retain() {
        let mut pq = PriorityQueue::new();

        let key1 = Ed25519::from_seed(0).public_key();
        let key2 = Ed25519::from_seed(1).public_key();
        let key3 = Ed25519::from_seed(2).public_key();

        pq.put(key1.clone(), Duration::from_secs(10));
        pq.put(key2.clone(), Duration::from_secs(5));

        pq.retain(&vec![key1.clone(), key3.clone()]);

        let entries: Vec<_> = pq.iter().cloned().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.public_key == key1 && e.duration == Duration::from_secs(10)));
        assert!(entries
            .iter()
            .any(|e| e.public_key == key3 && e.duration == Duration::default()));
    }
}
