//! A memory-efficient index for mapping large keys to values.
//!
//! Keys are transformed into a compressed, fixed size representation using a `Translator`, which
//! can result in collisions even if the original keys are collision free. As a result, a get call
//! can return multiple values for a key, and it's up to the application to disambiguate them.

mod storage;
pub use storage::{Index, ValueIterator};
pub mod translator;

use std::hash::Hash;

/// Translate keys into an internal representation used by `Index`.
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
