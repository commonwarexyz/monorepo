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
        self.index.retain(|&key, hash| {
            if key >= min {
                return true;
            }
            self.stored.remove(hash);
            false
        });

        // Clean pending index
        self.pending.retain(|key, _| *key >= min);
    }

    pub fn pending(&self, parent: &Hash) -> Vec<K> {
        let mut possible = self.pending.values().flatten().collect::<HashSet<_>>();
        let mut next = parent;

        // Iterate through all ancestors we know about and remove from possible
        // if already included.
        while let Some((hash, set)) = self.stored.get(next) {
            possible.retain(|key| !set.contains(key));
            next = hash;
        }

        // Collect all remaining possible
        possible.into_iter().cloned().collect()
    }

    pub fn discover(&mut self, keys: Vec<(u64, K)>) {
        for (index, key) in keys {
            self.pending.entry(index).or_default().insert(key);
        }
    }

    pub fn track(&mut self, item: Hash, index: u64, parent: Hash, keys: Vec<K>) {
        let keys = keys.into_iter().collect();
        self.stored.insert(item.clone(), (parent, keys));
        self.index.insert(index, item);
    }

    /// Check all ancestors for an overlapping key in a particular ancestry.
    pub fn check(&self, parent: &Hash, keys: Vec<&K>) -> bool {
        let mut next = parent;
        while let Some((hash, set)) = self.stored.get(next) {
            if keys.iter().any(|key| set.contains(*key)) {
                return true;
            }
            next = hash;
        }
        false
    }
}
