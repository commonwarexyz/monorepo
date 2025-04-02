//! A memory-efficient index for mapping keys to values.
//!
//! Keys are transformed into a compressed, fixed-size representation using a `Translator`. Depending
//! on the size of the representation, this can lead to a non-negligible number of collisions (even
//! if the original keys are collision-free). To workaround this issue, `get` returns all values
//! that map to the same transformed key. If the same key is inserted multiple times (and old values
//! are not `removed`), all values will be returned.
//!
//! # Warning
//!
//! If the `Translator` maps many keys to the same transformed key, the performance of `Index` will
//! degrade substantially (each conflicting key may contain the desired value).

mod storage;
pub use storage::{Index, ValueIterator};
pub mod translator;

use std::hash::Hash;

/// Translate keys into an internal representation used by `Index`.
///
/// # Warning
///
/// If invoking `transform` on keys results in many conflicts, the performance of `Index` will
/// degrade substantially.
pub trait Translator: Clone {
    type Key: Eq + Hash + Send + Sync + Clone;

    /// Transform a key into its internal representation.
    fn transform(&self, key: &[u8]) -> Self::Key;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::translator::TwoCap;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Metrics};
    use rand::Rng;
    use std::collections::HashMap;

    #[test_traced]
    fn test_index_basic() {
        let (_, context, _) = Executor::default();
        let mut index = Index::init(context.clone(), TwoCap);
        assert_eq!(index.len(), 0);

        // Generate a collision and check metrics to make sure it's captured
        let key = b"duplicate".as_slice();
        index.insert(key, 1);
        index.insert(key, 2);
        assert_eq!(index.len(), 1);
        let buffer = context.encode();
        assert!(buffer.contains("collisions_total 1"));

        // Make sure we can remove keys with a predicate
        index.insert(key, 3);
        index.insert(key, 4);
        index.remove(key, |i| *i == 3);
        assert_eq!(index.get(key).collect::<Vec<_>>(), vec![1, 4, 2]);
        index.remove(key, |_| true);
        // Try removing all of a keys values.
        assert_eq!(index.get(key).collect::<Vec<_>>(), Vec::<u64>::new());
        assert!(index.is_empty());

        // Removing a key that doesn't exist should be a no-op.
        index.remove(key, |_| true);
        assert!(index.is_empty());
    }

    #[test_traced]
    fn test_index_many_keys() {
        let (_, mut context, _) = Executor::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Insert enough keys to generate some collisions, then confirm each value we inserted
        // remains retrievable.
        let mut expected = HashMap::new();
        const NUM_KEYS: usize = 2000; // enough to generate some collisions
        while expected.len() < NUM_KEYS {
            let mut key_array = [0u8; 32];
            context.fill(&mut key_array);
            let key = key_array.to_vec();

            let loc = expected.len() as u64;
            index.insert(&key, loc);
            expected.insert(key, loc);
        }

        for (key, loc) in expected.iter() {
            let mut values = index.get(key);
            let res = values.find(|i| i == loc);
            assert!(res.is_some());
        }
    }
}
