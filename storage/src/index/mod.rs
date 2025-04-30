//! A memory-efficient index for mapping keys to values.
//!
//! Keys are translated into a compressed, fixed-size representation using a `Translator`. Depending
//! on the size of the representation, this can lead to a non-negligible number of collisions (even
//! if the original keys are collision-free). To workaround this issue, `get` returns all values
//! that map to the same translated key. If the same key is inserted multiple times (and old values
//! are not `removed`), all values will be returned.
//!
//! # Warning
//!
//! If the `Translator` maps many keys to the same translated key, the performance of `Index` will
//! degrade substantially (each conflicting key may contain the desired value).

mod storage;
pub use storage::Index;
pub mod translator;

use std::hash::{BuildHasher, Hash};

/// Translate keys into an internal representation used by `Index`.
///
/// # Warning
///
/// The output of `transform` is used as the key in a hash table. If the output is not uniformly
/// distributed, the performance of [Index] will degrade substantially.
pub trait Translator: Clone + BuildHasher {
    /// The type of the internal representation of keys.
    ///
    /// Although `Translator` is a [BuildHasher], the `Key` type must still implement [Hash] for compatibility
    /// with the [std::collections::HashMap] used internally by [Index].
    type Key: Eq + Hash + Copy;

    /// Transform a key into its internal representation.
    fn transform(&self, key: &[u8]) -> Self::Key;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::translator::{OneCap, TwoCap};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics};
    use rand::Rng;
    use std::collections::HashMap;

    #[test_traced]
    fn test_index_basic() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);
        assert_eq!(index.len(), 0);

        // Generate a collision and check metrics to make sure it's captured
        let key = b"duplicate".as_slice();
        index.insert(key, 1);
        index.insert(key, 2);
        assert_eq!(index.len(), 1);
        assert!(context.encode().contains("collisions_total 1"));

        // Make sure we can remove keys with a predicate
        index.insert(key, 3);
        index.insert(key, 4);
        index.prune(key, |i| *i == 3);
        assert_eq!(index.iter(key).copied().collect::<Vec<_>>(), vec![1, 4, 2]);
        index.prune(key, |_| true);
        // Try removing all of a keys values.
        assert_eq!(
            index.iter(key).copied().collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
        assert!(index.is_empty());

        // Removing a key that doesn't exist should be a no-op.
        index.prune(key, |_| true);
        assert!(index.is_empty());
    }

    #[test_traced]
    fn test_index_many_keys() {
        let mut context = deterministic::Context::default();
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
            let mut values = index.iter(key);
            let res = values.find(|i| *i == loc);
            assert!(res.is_some());
        }
    }

    #[test_traced]
    fn test_index_key_lengths_and_collisions() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Insert keys of different lengths
        index.insert(b"a", 1); // Shorter than cap (1 byte -> "a\0")
        index.insert(b"ab", 2); // Equal to cap (2 bytes -> "ab")
        index.insert(b"abc", 3); // Longer than cap (3 bytes -> "ab")

        // Check that "a" maps to "a\0"
        assert_eq!(index.iter(b"a").copied().collect::<Vec<_>>(), vec![1]);

        // Check that "ab" and "abc" map to "ab" due to TwoCap truncation
        let mut values = index.iter(b"ab").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![2, 3]);

        let mut values = index.iter(b"abc").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![2, 3]);

        // Insert another value for "ab"
        index.insert(b"ab", 4);
        // Expected order: head=2 (first "ab"), then 4 (new "ab"), then 3 (from "abc")

        assert_eq!(
            index.iter(b"ab").copied().collect::<Vec<_>>(),
            vec![4, 3, 2]
        );

        // Remove a specific value
        index.prune(b"ab", |v| *v == 4);
        assert_eq!(index.iter(b"ab").copied().collect::<Vec<_>>(), vec![3, 2]);

        // Remove all values for "ab"
        index.prune(b"ab", |_| true);
        assert_eq!(
            index.iter(b"ab").copied().collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
        assert_eq!(index.len(), 1); // Only "a" remains

        // Check that "a" is still present
        assert_eq!(index.iter(b"a").copied().collect::<Vec<_>>(), vec![1]);
    }

    #[test_traced]
    fn test_index_value_order() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        // Values should be in stack order (last in first).
        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
    }

    #[test_traced]
    fn test_index_remove_specific() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        // Remove value 2
        index.prune(b"key", |v| *v == 2);
        assert_eq!(index.iter(b"key").copied().collect::<Vec<_>>(), vec![3, 1]);

        // Remove head value 1
        index.prune(b"key", |v| *v == 1);
        assert_eq!(index.iter(b"key").copied().collect::<Vec<_>>(), vec![3]);
    }

    #[test_traced]
    fn test_index_empty_key() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"", 0); // Maps to [0, 0]
        index.insert(b"\0", 1); // Maps to [0, 0]
        index.insert(b"\0\0", 2); // Maps to [0, 0]

        // All keys map to [0, 0], so all values should be returned
        let mut values = index.iter(b"").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        let mut values = index.iter(b"\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        let mut values = index.iter(b"\0\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        // Remove a specific value
        index.prune(b"", |v| *v == 1);
        let mut values = index.iter(b"").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 2]);
    }

    #[test_traced]
    fn test_index_mutate_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        let mut record = index.get_mut(b"key");
        while let Some(this) = record {
            // Mutate the value
            let old = this.get();
            this.update(old + 10);
            record = this.next_mut();
        }

        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![13, 12, 11]
        );
    }

    #[test_traced]
    fn test_index_remove_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        index.insert(b"key", 4);

        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![1, 4, 3, 2]
        );
        assert!(context.encode().contains("pruned_total 0"));

        // Test removing first value from the list.
        {
            let item = index.get_mut(b"key").unwrap();
            assert!(item.delete());
            assert_eq!(*item.get(), 4);
            assert!(context.encode().contains("pruned_total 1"));
        }

        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 2]
        );

        index.insert(b"key", 1);
        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![4, 1, 3, 2]
        );

        // Test removing from the middle.
        {
            let mut iter = index.get_mut(b"key").unwrap();
            assert_eq!(*iter.get(), 4);
            iter = iter.next_mut().unwrap();
            assert_eq!(*iter.get(), 1);
            iter = iter.next_mut().unwrap();
            assert_eq!(*iter.get(), 3);
            assert!(iter.delete());
        }

        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![4, 1, 2]
        );
        index.insert(b"key", 3);
        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 1, 2]
        );

        // Test removing last value.
        {
            let mut iter = index.get_mut(b"key").unwrap();
            assert_eq!(*iter.get(), 4);
            iter = iter.next_mut().unwrap();
            assert_eq!(*iter.get(), 3);
            iter = iter.next_mut().unwrap();
            assert_eq!(*iter.get(), 1);
            iter = iter.next_mut().unwrap();
            assert_eq!(*iter.get(), 2);
            assert!(!iter.delete());
            assert!(context.encode().contains("pruned_total 3"));
        }

        assert_eq!(
            index.iter(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 1, 2]
        );

        // Test removing all values.
        index.remove(b"key");
        assert_eq!(index.len(), 0);
        assert!(context.encode().contains("pruned_total 6"));
    }

    #[test_traced]
    fn test_index_insert_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Add values to the index
        {
            index.insert(b"key", 1);
            let record = index.get_mut(b"key").unwrap();
            record.add(3);
            assert!(context.encode().contains("collisions_total 1"));
        }
        assert_eq!(index.iter(b"key").copied().collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(index.len(), 1);

        // Try inserting into an iterator while iterating.
        {
            let mut iter = index.get_mut(b"key").unwrap();
            assert_eq!(*iter.get(), 1);
            iter = iter.next_mut().unwrap();
            iter.add(42);
            assert!(context.encode().contains("collisions_total 2"));
        }

        // Verify first value is new one
        {
            let mut iter = index.iter(b"key");
            assert_eq!(*iter.next().unwrap(), 42);
        }

        // Insert a new value
        index.insert(b"key", 100);
        assert!(context.encode().contains("collisions_total 3"));

        // Iterate to end
        let mut iter = index.iter(b"key");
        assert_eq!(*iter.next().unwrap(), 100);
        assert_eq!(*iter.next().unwrap(), 42);
        assert_eq!(*iter.next().unwrap(), 3);
        assert_eq!(*iter.next().unwrap(), 1);
        assert!(iter.next().is_none());
    }

    #[test_traced]
    fn test_index_remove_middle_then_next() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0, 3, 2, 1]
        for i in 0..4 {
            index.insert(b"key", i);
        }

        // Remove middle: [3, 0]
        {
            let mut iter = index.get_mut(b"key").unwrap();
            assert_eq!(*iter.get(), 0); // head
            iter = iter.next_mut().unwrap();
            assert_eq!(*iter.get(), 3); // middle
            iter.delete();
            assert_eq!(*iter.get(), 2); // middle (removed)
            iter.delete();
        }
        assert_eq!(index.iter(b"key").copied().collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test_traced]
    fn test_index_many_conflicts() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), OneCap);

        // Add 1000 entries to the same key (pruning 100 behind)
        let key = b"key";
        for i in 0..1000 {
            index.insert(key, i);

            if i < 100 {
                continue;
            }
            let lower_bound = i - 100;
            index.prune(key, |v| *v < lower_bound);
            assert_eq!(
                (lower_bound..=i).rev().collect::<Vec<_>>(),
                index.iter(key).copied().collect::<Vec<_>>()
            );
        }

        // Remove everything
        index.prune(key, |v| *v < 1000);
        assert!(index.iter(key).collect::<Vec<_>>().is_empty());

        // Add again
        for i in 1000..2000 {
            index.insert(key, i);
            if i < 1100 {
                continue;
            }
            let lower_bound = i - 100;
            index.prune(key, |v| *v < lower_bound);
            assert_eq!(
                (lower_bound..=i).rev().collect::<Vec<_>>(),
                index.iter(key).copied().collect::<Vec<_>>()
            );
        }
    }

    #[test_traced]
    fn test_insert_and_prune_vacant() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Inserting into a *vacant* key behaves just like `insert`
        // (no collisions and nothing to prune).
        index.insert_and_prune(b"key", 1u64, |_| false);

        assert_eq!(index.iter(b"key").copied().collect::<Vec<_>>(), vec![1]);
        assert!(ctx.encode().contains("collisions_total 0"));
        assert!(ctx.encode().contains("pruned_total 0"));
    }

    #[test_traced]
    fn test_insert_and_prune_replace_one() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // If a key currently has *one* value and the predicate matches,
        // the value is *replaced* in-place (1 prune, 1 collision).
        index.insert(b"key", 1u64); // 0 → collisions
        index.insert_and_prune(b"key", 2u64, |_| true); // +1 collision, +1 prune

        assert_eq!(index.iter(b"key").copied().collect::<Vec<_>>(), vec![2]);
        assert!(ctx.encode().contains("collisions_total 1"));
        assert!(ctx.encode().contains("pruned_total 1"));
    }

    #[test_traced]
    fn test_insert_and_prune_prune_many_and_demote() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Add multiple values to the same key
        index.insert(b"key", 10u64); // 0 → collisions
        index.insert(b"key", 20u64); // +1 collision

        // When multiple values exist, `insert_and_prune` should:
        // 1. remove all matching values,
        // 2. push the new one,
        // 3. *demote* back to `One` when only a single value remains.
        index.insert_and_prune(b"key", 30u64, |_| true); // +1 collision, +2 pruned

        assert_eq!(index.iter(b"key").copied().collect::<Vec<_>>(), vec![30]);
        assert!(ctx.encode().contains("collisions_total 2"));
        assert!(ctx.encode().contains("pruned_total 2"));
    }
}
