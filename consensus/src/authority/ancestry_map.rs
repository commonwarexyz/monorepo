use crate::Hash;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash as StdHash,
};

#[derive(Default)]
pub struct AncestryMap<K: Eq + StdHash + Clone, V: Clone> {
    container_index: BTreeMap<u64, HashSet<Hash>>,
    containers: HashMap<Hash, (Hash, HashSet<K>)>,

    pending: BTreeMap<u64, HashMap<K, V>>,
}

impl<K: Eq + StdHash + Clone, V: Clone> AncestryMap<K, V> {
    // TODO: track votes by both container and index? Faults don't need this
    // but included votes/finalizes need to be?
    // TODO: could alternatively store view number and require any referenced items
    // to be in the view hierarchy (can then translate to height to prune). ->
    // this doesn't solve the problem that faults behave slightly differently (just don't want any repeats
    // in the ancestry, not additionally that must only include items that reference blocks in view)
    pub fn add(&mut self, index: u64, key: K, value: V) {
        self.pending.entry(index).or_default().insert(key, value);
    }

    /// Return all unassigned keys given the parent.
    pub fn unassigned(&self, parent: &Hash, mut depth: u64) -> Vec<(K, V)> {
        let mut possible = self.pending.values().flatten().collect::<HashMap<_, _>>();
        let mut next = parent;

        // Iterate through all ancestors we know about and remove from possible
        // if already included.
        while let Some((hash, set)) = self.containers.get(next) {
            possible.retain(|key, _| !set.contains(key));
            next = hash;
            if depth == 0 {
                break;
            }
            depth -= 1;
        }

        // Collect all remaining possible
        let mut result = Vec::with_capacity(possible.len());
        for (k, v) in possible {
            result.push((k.clone(), v.clone()));
        }
        result
    }

    /// Assign a vector of keys to a container at a given index.
    pub fn assign(&mut self, container: Hash, index: u64, parent: Hash, keys: Vec<K>) -> bool {
        // Check that none of the keys are already in the ancestry.
        let mut next = &parent;
        while let Some((hash, set)) = self.containers.get(next) {
            if keys.iter().any(|key| set.contains(key)) {
                return false;
            }
            next = hash;
        }

        // Insert into set
        let keys = keys.into_iter().collect();
        self.containers.insert(container.clone(), (parent, keys));
        self.container_index
            .entry(index)
            .or_default()
            .insert(container);
        true
    }

    /// Prune clears all entries less than a given index.
    pub fn prune(&mut self, min: u64) {
        // Clean container index
        self.container_index.retain(|&key, hashes| {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_track_and_pending() {
        let mut map: AncestryMap<i32, Option<i32>> = AncestryMap::default();

        // Discover some keys
        map.add(0, 1, None);
        map.add(0, 2, None);
        map.add(0, 3, None);
        map.add(4, 10, None);

        // Track a container
        assert!(map.assign("container".into(), 1, "parent".into(), vec![1, 3]));

        // Track another container at the same index
        assert!(map.assign("container2".into(), 1, "parent".into(), vec![2, 3]));

        // Gather pending
        let mut unused = map.unassigned(&"container".into(), 10);
        unused.sort();
        assert_eq!(unused, vec![(2, None), (10, None)]);

        // Gather pending on top of other container
        let mut unused = map.unassigned(&"container2".into(), 10);
        unused.sort();
        assert_eq!(unused, vec![(1, None), (10, None)]);

        // Try to add with overlapping keys
        assert!(!map.assign("container3".into(), 1, "container2".into(), vec![3]));

        // Prune
        map.prune(1);

        // Gather pending
        let mut unused = map.unassigned(&"container".into(), 10);
        unused.sort();
        assert_eq!(unused, vec![(10, None)]);
    }

    // #[test]
    // fn test_multiple_tracking() {
    //     let mut set = AncestrySet::default();

    //     // Discover some keys
    //     set.discover(vec![(0, 1), (0, 2), (0, 3), (4, 10)]);

    //     // Track some containers
    //     assert!(set.track("container".into(), 1, "parent".into(), vec![1, 3]));
    //     assert!(set.track("container2".into(), 2, "container".into(), vec![2, 4]));
    //     assert!(set.track("container3".into(), 3, "container2".into(), vec![10]));
    //     assert!(set.track("container4".into(), 3, "container2".into(), vec![5, 7]));

    //     // Gather pending
    //     let unused = set.pending(&"container3".into());
    //     assert!(unused.is_empty());

    //     // Gather pending on top of other container
    //     let mut unused = set.pending(&"container4".into());
    //     unused.sort();
    //     assert_eq!(unused, vec![10]);

    //     // Try to add with overlapping keys
    //     assert!(!set.track("container5".into(), 4, "container3".into(), vec![10]));

    //     // Prune
    //     set.prune(3);

    //     // Gather pending
    //     let mut unused = set.pending(&"container4".into());
    //     unused.sort();
    //     assert_eq!(unused, vec![10]);

    //     // Prune
    //     set.prune(5);

    //     // Gather pending
    //     let unused = set.pending(&"container4".into());
    //     assert!(unused.is_empty());
    // }
}
