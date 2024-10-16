use crate::Hash;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash as StdHash,
};

pub struct TrieSet<K: PartialEq + PartialOrd + Eq + StdHash + Clone> {
    index: BTreeMap<u64, Hash>,
    stored: HashMap<Hash, (Hash, HashSet<K>)>,
    pending: BTreeMap<u64, HashSet<K>>,
}

impl<K: PartialEq + PartialOrd + Eq + StdHash + Clone> TrieSet<K> {
    /// Prune clears all entries less than a given index.
    pub fn prune(&mut self, min: u64) {
        // Clean container index
        let keys_to_remove: Vec<u64> = self
            .index
            .iter()
            .filter(|(key, _)| **key < min)
            .map(|(key, _)| *key)
            .collect();
        for key in keys_to_remove {
            let hash = self.index.remove(&key).unwrap();
            self.stored.remove(&hash);
        }

        // Clean pending index
        let keys_to_remove: Vec<u64> = self
            .pending
            .keys()
            .cloned()
            .filter(|key| *key < min)
            .collect();
        for key in keys_to_remove {
            self.pending.remove(&key);
        }
    }

    pub fn pending(&self, parent: &Hash) -> Vec<K> {
        let mut possible = self.pending.values().flatten().collect::<HashSet<_>>();
        let mut next = parent;
        loop {
            if let Some((hash, set)) = self.stored.get(next) {
                let mut to_remove = Vec::new();
                for key in &possible {
                    if set.contains(key) {
                        to_remove.push(key.clone());
                    }
                }
                for key in to_remove {
                    possible.remove(&key);
                }
                next = hash;
            } else {
                break;
            }
        }

        // Collect all remaining possible
        possible.into_iter().cloned().collect()
    }

    pub fn discover(&mut self, keys: Vec<(u64, K)>) {
        for (index, key) in keys {
            let entry = self.pending.entry(index).or_default();
            entry.insert(key);
        }
    }

    pub fn track(&mut self, item: Hash, index: u64, parent: Hash, keys: Vec<K>) {
        let mut set = HashSet::new();
        for key in keys.into_iter() {
            set.insert(key);
        }
        self.stored.insert(item.clone(), (parent, set));
        self.index.insert(index, item);
    }

    /// Check all ancestors for an overlapping key in a particular ancestry.
    pub fn check(&self, parent: &Hash, keys: Vec<&K>) -> bool {
        let mut next = parent;
        loop {
            if let Some((hash, set)) = self.stored.get(next) {
                for key in keys.iter() {
                    if set.contains(*key) {
                        return true;
                    }
                }
                next = hash;
            } else {
                return false;
            }
        }
    }
}
