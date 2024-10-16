use crate::Hash;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash as StdHash,
};

#[derive(Default)]
pub struct AncestrySet<K: Eq + StdHash + Clone> {
    index: BTreeMap<u64, HashSet<Hash>>,
    containers: HashMap<Hash, (Hash, HashSet<K>)>,
    pending: BTreeMap<u64, HashSet<K>>,
}

impl<K: Eq + StdHash + Clone> AncestrySet<K> {
    /// Prune clears all entries less than a given index.
    pub fn prune(&mut self, min: u64) {
        // Clean container index
        self.index.retain(|&key, hashes| {
            if key >= min {
                return true;
            }
            for hash in hashes.iter() {
                self.containers.remove(hash);
            }
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
        while let Some((hash, set)) = self.containers.get(next) {
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

    /// Track a new container in the set.
    ///
    /// It is safe to add a duplicate container, it is a no-op.
    pub fn track(&mut self, container: Hash, index: u64, parent: Hash, keys: Vec<K>) {
        let keys = keys.into_iter().collect();
        self.containers.insert(container.clone(), (parent, keys));
        self.index.entry(index).or_default().insert(container);
    }

    /// Check all ancestors for an overlapping key in a particular ancestry.
    pub fn check(&self, parent: &Hash, keys: Vec<&K>) -> bool {
        let mut next = parent;
        while let Some((hash, set)) = self.containers.get(next) {
            if keys.iter().any(|key| set.contains(*key)) {
                return true;
            }
            next = hash;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_track_and_pending() {
        let mut set = AncestrySet::default();

        // Discover some keys
        set.discover(vec![(0, 1), (0, 2), (0, 3), (4, 10)]);

        // Track a container
        set.track("container".into(), 1, "parent".into(), vec![1, 3]);

        // Track another container at the same index
        set.track("container2".into(), 1, "parent".into(), vec![2, 3]);

        // Gather pending
        let mut unused = set.pending(&"container".into());
        unused.sort();
        assert_eq!(unused, vec![2, 10]);

        // Gather pending on top of other container
        let mut unused = set.pending(&"container2".into());
        unused.sort();
        assert_eq!(unused, vec![1, 10]);

        // Check for overlapping keys
        assert!(set.check(&"container".into(), vec![&1]));
        assert!(set.check(&"container".into(), vec![&3]));
        assert!(!set.check(&"container".into(), vec![&2]));

        // Prune
        set.prune(1);

        // Gather pending
        let mut unused = set.pending(&"container".into());
        unused.sort();
        assert_eq!(unused, vec![10]);
    }

    #[test]
    fn test_multiple_tracking() {
        let mut set = AncestrySet::default();

        // Discover some keys
        set.discover(vec![(0, 1), (0, 2), (0, 3), (4, 10)]);

        // Track some containers
        set.track("container".into(), 1, "parent".into(), vec![1, 3]);
        set.track("container2".into(), 2, "container".into(), vec![2, 4]);
        set.track("container3".into(), 3, "container2".into(), vec![10]);
        set.track("container4".into(), 3, "container2".into(), vec![5, 7]);

        // Gather pending
        let unused = set.pending(&"container3".into());
        assert!(unused.is_empty());

        // Gather pending on top of other container
        let mut unused = set.pending(&"container4".into());
        unused.sort();
        assert_eq!(unused, vec![10]);

        // Check for overlapping keys
        assert!(set.check(&"container3".into(), vec![&10]));
        assert!(!set.check(&"container4".into(), vec![&10]));

        // Prune
        set.prune(3);

        // Gather pending
        let mut unused = set.pending(&"container4".into());
        unused.sort();
        assert_eq!(unused, vec![10]);

        // Prune
        set.prune(5);

        // Gather pending
        let unused = set.pending(&"container4".into());
        assert!(unused.is_empty());
    }
}
