//! Memory-efficient index structures for mapping translated keys to values.
//!
//! # Multiple Values for a Key
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

pub mod ordered;
pub mod partitioned;
pub mod unordered;

use crate::translator::Translator;
use commonware_runtime::Metrics;

/// A mutable iterator over the values associated with a translated key, allowing in-place
/// modifications.
///
/// The [Cursor] provides a way to traverse and modify the linked list of values associated with a
/// translated key by an index while maintaining its structure. It supports:
///
/// - Iteration via `next()` to access values.
/// - Modification via `update()` to change the current value.
/// - Insertion via `insert()` to add new values.
/// - Deletion via `delete()` to remove values.
///
/// # Safety
///
/// - Must call `next()` before `update()`, `insert()`, or `delete()` to establish a valid position.
/// - Once `next()` returns `None`, only `insert()` can be called.
/// - Dropping the `Cursor` automatically restores the list structure by reattaching any detached
///   `next` nodes.
///
/// _If you don't need advanced functionality, just use `insert()`, `insert_and_prune()`, or
/// `remove()` from [Unordered] instead._
pub trait Cursor {
    /// The type of values the cursor iterates over.
    type Value: Eq;

    /// Advances the cursor to the next value in the chain, returning a reference to it.
    ///
    /// This method must be called before any other operations (`insert()`, `delete()`, etc.). If
    /// either `insert()` or `delete()` is called, `next()` must be called to set a new active item.
    /// If after `insert()`, the next active item is the item after the inserted item. If after
    /// `delete()`, the next active item is the item after the deleted item.
    ///
    /// Handles transitions between phases and adjusts for deletions. Returns `None` when the list
    /// is exhausted. It is safe to call `next()` even after it returns `None`.
    #[allow(clippy::should_implement_trait)]
    fn next(&mut self) -> Option<&Self::Value>;

    /// Inserts a new value at the current position.
    fn insert(&mut self, value: Self::Value);

    /// Deletes the current value, adjusting the list structure.
    fn delete(&mut self);

    /// Updates the value at the current position in the iteration.
    ///
    /// Panics if called before `next()` or after iteration is complete (`Status::Done` phase).
    fn update(&mut self, value: Self::Value);

    /// Removes anything in the cursor that satisfies the predicate.
    fn prune(&mut self, predicate: &impl Fn(&Self::Value) -> bool);

    /// Advances the cursor until finding a value matching the predicate.
    ///
    /// Returns `true` if a matching value is found, with the cursor positioned at that element.
    /// Returns `false` if no match is found and the cursor is exhausted.
    ///
    /// After a successful find (returning `true`), the cursor is positioned at the found element,
    /// allowing operations like `update()` or `delete()` to be called on it without requiring
    /// another call to `next()`.
    ///
    /// This method follows similar semantics to `Iterator::find`, consuming items until a match is
    /// found or the iterator is exhausted.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut cursor = index.get_mut(&key)?;
    /// if cursor.find(|&value| value == 42) {
    ///     // Cursor is positioned at the element with value 42
    ///     cursor.update(100); // Update it to 100
    /// }
    /// ```
    fn find(&mut self, predicate: impl Fn(&Self::Value) -> bool) -> bool {
        loop {
            match self.next() {
                Some(value) if predicate(value) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    }
}

/// A trait defining the operations provided by a memory-efficient index that maps translated keys
/// to arbitrary values, with no ordering assumed over the key space.
pub trait Unordered<T: Translator> {
    /// The type of values the index stores.
    type Value: Eq;

    /// The type of cursor returned by this index to iterate over values with conflicting keys.
    type Cursor<'a>: Cursor<Value = Self::Value>
    where
        Self: 'a;

    /// Initializes a new [Unordered] with the given translator.
    fn init(ctx: impl Metrics, translator: T) -> Self;

    /// Returns an iterator over all values associated with a translated key.
    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a Self::Value> + 'a
    where
        Self::Value: 'a;

    /// Provides mutable access to the values associated with a translated key, if the key exists.
    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>>;

    /// Provides mutable access to the values associated with a translated key (if the key exists),
    /// otherwise inserts a new value and returns `None`.
    fn get_mut_or_insert<'a>(
        &'a mut self,
        key: &[u8],
        value: Self::Value,
    ) -> Option<Self::Cursor<'a>>;

    /// Inserts a new value at the current position.
    fn insert(&mut self, key: &[u8], value: Self::Value);

    /// Insert a value at the given translated key, and prune any values that are no longer valid.
    ///
    /// If the value is prunable, it will not be inserted.
    fn insert_and_prune(
        &mut self,
        key: &[u8],
        value: Self::Value,
        predicate: impl Fn(&Self::Value) -> bool,
    );

    /// Remove all values associated with a translated key that match `predicate`.
    fn prune(&mut self, key: &[u8], predicate: impl Fn(&Self::Value) -> bool);

    /// Remove all values associated with a translated key.
    fn remove(&mut self, key: &[u8]);

    /// Returns the number of translated keys in the index.
    #[cfg(test)]
    fn keys(&self) -> usize;

    /// Returns the number of items in the index, for use in testing. The number of items is always
    /// at least as large as the number of keys, but may be larger in the case of collisions.
    #[cfg(test)]
    fn items(&self) -> usize;

    /// Returns the total number of items pruned from the index, for use in testing.
    #[cfg(test)]
    fn pruned(&self) -> usize;
}

/// A trait defining the additional operations provided by a memory-efficient index that allows
/// ordered traversal of the indexed keys.
pub trait Ordered<T: Translator>: Unordered<T> {
    // Returns an iterator over all values associated with a translated key that lexicographically
    // precedes the result of translating `key`.
    fn prev_translated_key<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a Self::Value> + 'a
    where
        Self::Value: 'a;

    // Returns an iterator over all values associated with a translated key that lexicographically
    // follows the result of translating `key`.
    fn next_translated_key<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a Self::Value> + 'a
    where
        Self::Value: 'a;

    // Returns an iterator over all values associated with the lexicographically first translated
    // key.
    fn first_translated_key<'a>(&'a self) -> impl Iterator<Item = &'a Self::Value> + 'a
    where
        Self::Value: 'a;

    // Returns an iterator over all values associated with the lexicographically last translated
    // key.
    fn last_translated_key<'a>(&'a self) -> impl Iterator<Item = &'a Self::Value> + 'a
    where
        Self::Value: 'a;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        index::partitioned::{
            ordered::Index as PartitionedOrdered, unordered::Index as PartitionedUnordered,
        },
        translator::{OneCap, TwoCap},
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use rand::Rng;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        thread,
    };

    fn run_index_basic<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        // Generate a collision and check metrics to make sure it's captured
        let key = b"duplicate".as_slice();
        index.insert(key, 1);
        index.insert(key, 2);
        index.insert(key, 3);
        assert_eq!(index.keys(), 1);

        // Check that the values are in the correct order
        assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![1, 3, 2]);

        // Ensure cursor terminates
        {
            let mut cursor = index.get_mut(key).unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 3);
            assert_eq!(*cursor.next().unwrap(), 2);
            assert!(cursor.next().is_none());
        }

        // Make sure we can remove keys with a predicate
        index.insert(key, 3);
        index.insert(key, 4);
        index.prune(key, |i| *i == 3);
        assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![1, 4, 2]);
        index.prune(key, |_| true);
        // Try removing all of a keys values.
        assert_eq!(
            index.get(key).copied().collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
        assert_eq!(index.keys(), 0);

        assert!(index.get_mut(key).is_none());

        // Removing a key that doesn't exist should be a no-op.
        index.prune(key, |_| true);
    }

    fn new_unordered(context: deterministic::Context) -> unordered::Index<TwoCap, u64> {
        unordered::Index::<_, u64>::init(context.clone(), TwoCap)
    }

    fn new_ordered(context: deterministic::Context) -> ordered::Index<TwoCap, u64> {
        ordered::Index::<_, u64>::init(context, TwoCap)
    }

    fn new_partitioned_unordered(
        context: deterministic::Context,
    ) -> PartitionedUnordered<OneCap, unordered::Index<OneCap, u64>, 1> {
        // A one byte prefix and a OneCap translator yields behavior that matches TwoCap translator
        // on an un-partitioned index.
        PartitionedUnordered::<_, _, 1>::init(context.clone(), OneCap)
    }

    fn new_partitioned_ordered(
        context: deterministic::Context,
    ) -> PartitionedOrdered<OneCap, ordered::Index<OneCap, u64>, 1> {
        // Same translator choice as the unordered variant to keep collision behavior consistent.
        PartitionedOrdered::<_, _, 1>::init(context.clone(), OneCap)
    }

    #[test_traced]
    fn test_hash_index_basic() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            assert_eq!(index.keys(), 0);
            run_index_basic(&mut index);
            assert_eq!(index.keys(), 0);
        });
    }

    #[test_traced]
    fn test_ordered_index_basic() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            assert_eq!(index.keys(), 0);
            run_index_basic(&mut index);
            assert_eq!(index.keys(), 0);
        });
    }

    #[test_traced]
    fn test_partitioned_index_basic() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                assert_eq!(index.keys(), 0);
                run_index_basic(&mut index);
                assert_eq!(index.keys(), 0);
            }
            {
                let mut index = new_partitioned_ordered(context);
                assert_eq!(index.keys(), 0);
                run_index_basic(&mut index);
                assert_eq!(index.keys(), 0);
            }
        });
    }

    fn run_index_cursor_find<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        let key = b"test_key";

        // Insert multiple values with collisions
        index.insert(key, 10);
        index.insert(key, 20);
        index.insert(key, 30);
        index.insert(key, 40);

        // Test finding an element that exists
        {
            let mut cursor = index.get_mut(key).unwrap();
            assert!(cursor.find(|&v| v == 30));
            // Cursor should be positioned at 30, so we can update it
            cursor.update(35);
        }

        // Verify the update worked
        let values: Vec<u64> = index.get(key).copied().collect();
        assert!(values.contains(&35));
        assert!(!values.contains(&30));

        // Test finding an element that doesn't exist
        {
            let mut cursor = index.get_mut(key).unwrap();
            assert!(!cursor.find(|&v| v == 100));
            // Cursor should be exhausted, so next() returns None
            assert!(cursor.next().is_none());
        }

        // Test finding and deleting
        {
            let mut cursor = index.get_mut(key).unwrap();
            assert!(cursor.find(|&v| v == 20));
            cursor.delete();
        }

        // Verify the delete worked
        let values: Vec<u64> = index.get(key).copied().collect();
        assert!(!values.contains(&20));
        assert_eq!(values.len(), 3); // 10, 35, 40
    }

    #[test_traced]
    fn test_unordered_index_cursor_find() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_find(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_cursor_find() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_find(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_cursor_find() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_find(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_find(&mut index);
            }
        });
    }

    fn run_index_many_keys<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
        mut fill: impl FnMut(&mut [u8]),
    ) {
        let mut expected = HashMap::new();
        const NUM_KEYS: usize = 2000;
        while expected.len() < NUM_KEYS {
            let mut key_array = [0u8; 32];
            fill(&mut key_array);
            let key = key_array.to_vec();

            let loc = expected.len() as u64;
            index.insert(&key, loc);
            expected.insert(key, loc);
        }
        assert_eq!(index.keys(), 1975);
        assert_eq!(index.items(), 2000);

        for (key, loc) in expected.iter() {
            let mut values = index.get(key);
            let res = values.find(|i| *i == loc);
            assert!(res.is_some());
        }
    }

    #[test_traced]
    fn test_hash_index_many_keys() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let mut index = new_unordered(context.clone());
            run_index_many_keys(&mut index, |bytes| context.fill(bytes));
        });
    }

    #[test_traced]
    fn test_ordered_index_many_keys() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let mut index = new_ordered(context.clone());
            run_index_many_keys(&mut index, |bytes| context.fill(bytes));
        });
    }

    #[test_traced]
    fn test_partitioned_index_many_keys() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_many_keys(&mut index, |bytes| context.fill(bytes));
            }
        });

        // Since we use context's random byte generator we need to run the two variants from the
        // same initial context state to ensure the expected identical outcome.
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let mut index = new_partitioned_ordered(context.clone());
            run_index_many_keys(&mut index, |bytes| context.fill(bytes));
        });
    }

    fn run_index_key_lengths_and_metrics<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"a", 1);
        index.insert(b"ab", 2);
        index.insert(b"abc", 3);

        assert_eq!(index.get(b"ab").copied().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(index.get(b"abc").copied().collect::<Vec<_>>(), vec![2, 3]);

        index.insert(b"ab", 4);
        assert_eq!(index.get(b"ab").copied().collect::<Vec<_>>(), vec![2, 4, 3]);
        assert_eq!(index.keys(), 2);
        assert_eq!(index.items(), 4);

        index.prune(b"ab", |v| *v == 4);
        assert_eq!(index.get(b"ab").copied().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(index.keys(), 2);
        assert_eq!(index.items(), 3);

        index.prune(b"ab", |_| true);
        assert_eq!(
            index.get(b"ab").copied().collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
        assert_eq!(index.keys(), 1);
        assert_eq!(index.items(), 1);
        assert_eq!(index.get(b"a").copied().collect::<Vec<_>>(), vec![1]);
    }

    #[test_traced]
    fn test_hash_index_key_lengths_and_key_item_metrics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_key_lengths_and_metrics(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_key_lengths_and_key_item_metrics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_key_lengths_and_metrics(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_key_lengths_and_key_item_metrics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_key_lengths_and_metrics(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_key_lengths_and_metrics(&mut index);
            }
        });
    }

    fn run_index_value_order<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 3, 2]
        );
    }

    #[test_traced]
    fn test_hash_index_value_order() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_value_order(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_value_order() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_value_order(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_value_order() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_value_order(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_value_order(&mut index);
            }
        });
    }

    fn run_index_remove_specific<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        index.prune(b"key", |v| *v == 2);
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1, 3]);
        index.prune(b"key", |v| *v == 1);
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![3]);
    }

    #[test_traced]
    fn test_hash_index_remove_specific() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_remove_specific(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_remove_specific() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_remove_specific(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_remove_specific() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_remove_specific(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_remove_specific(&mut index);
            }
        });
    }

    fn run_index_empty_key<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        index.insert(b"", 0);
        index.insert(b"\0", 1);
        index.insert(b"\0\0", 2);

        let mut values = index.get(b"").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);
        let mut values = index.get(b"\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);
        let mut values = index.get(b"\0\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        index.prune(b"", |v| *v == 1);
        let mut values = index.get(b"").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 2]);
    }

    #[test_traced]
    fn test_hash_index_empty_key() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_empty_key(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_empty_key() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_empty_key(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_empty_key() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_empty_key(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_empty_key(&mut index);
            }
        });
    }

    fn run_index_mutate_through_iterator<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            while let Some(old) = cursor.next().copied() {
                cursor.update(old + 10);
            }
        }
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![11, 13, 12]
        );
    }

    #[test_traced]
    fn test_hash_index_mutate_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_mutate_through_iterator(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_mutate_through_index() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_mutate_through_iterator(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_mutate_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_mutate_through_iterator(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_mutate_through_iterator(&mut index);
            }
        });
    }

    fn run_index_mutate_middle_of_four<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        index.insert(b"key", 4);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 4, 3, 2]
        );
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 4);
            let _ = cursor.next().unwrap();
            cursor.update(99);
        }
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 4, 99, 2]
        );
    }

    #[test_traced]
    fn test_hash_index_mutate_middle_of_four() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_mutate_middle_of_four(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_mutate_middle_of_four() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_mutate_middle_of_four(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_mutate_middle_of_four() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_mutate_middle_of_four(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_mutate_middle_of_four(&mut index);
            }
        });
    }

    fn run_index_remove_through_iterator<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        index.insert(b"key", 4);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 4, 3, 2]
        );
        assert_eq!(index.pruned(), 0);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
        }
        assert_eq!(index.pruned(), 1);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 2]
        );
        index.insert(b"key", 1);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 1, 3, 2]
        );
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 4);
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
        }
        assert_eq!(index.pruned(), 2);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 1, 2]
        );
        index.insert(b"key", 3);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 1, 2]
        );
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 4);
            assert_eq!(*cursor.next().unwrap(), 3);
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
        }
        assert_eq!(index.pruned(), 3);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 1]
        );
        index.remove(b"key");
        assert_eq!(index.keys(), 0);
        assert_eq!(index.items(), 0);
        assert_eq!(index.pruned(), 6);
    }

    #[test_traced]
    fn test_hash_index_remove_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_remove_through_iterator(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_remove_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_remove_through_iterator(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_remove_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_remove_through_iterator(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_remove_through_iterator(&mut index);
            }
        });
    }
    fn run_index_insert_through_iterator<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I)
    where
        I::Value: PartialEq<u64> + Eq,
    {
        index.insert(b"key", 1);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.insert(3);
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(index.keys(), 1);
        assert_eq!(index.items(), 2);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.insert(42);
        }
        assert_eq!(index.keys(), 1);
        assert_eq!(index.items(), 3);
        {
            let mut iter = index.get(b"key");
            assert_eq!(*iter.next().unwrap(), 1);
            assert_eq!(*iter.next().unwrap(), 42);
        }
        index.insert(b"key", 100);
        let mut iter = index.get(b"key");
        assert_eq!(*iter.next().unwrap(), 1);
        assert_eq!(*iter.next().unwrap(), 100);
        assert_eq!(*iter.next().unwrap(), 42);
        assert_eq!(*iter.next().unwrap(), 3);
        assert!(iter.next().is_none());
    }

    #[test_traced]
    fn test_hash_index_insert_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_insert_through_iterator(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_insert_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_insert_through_iterator(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_insert_through_iterator() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_insert_through_iterator(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_insert_through_iterator(&mut index);
            }
        });
    }

    fn run_index_cursor_insert_after_done_appends<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 10);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 10);
            assert!(cursor.next().is_none());
            cursor.insert(20);
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![10, 20]);
    }

    #[test_traced]
    fn test_hash_index_cursor_insert_after_done_appends() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_insert_after_done_appends(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_cursor_insert_after_done_appends() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_insert_after_done_appends(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_cursor_insert_after_done_appends() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_insert_after_done_appends(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_insert_after_done_appends(&mut index);
            }
        });
    }

    fn run_index_remove_to_nothing_then_add<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        for i in 0..4 {
            index.insert(b"key", i);
        }
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
            assert_eq!(cursor.next(), None);
            cursor.insert(4);
            assert_eq!(cursor.next(), None);
            cursor.insert(5);
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test_traced]
    fn test_hash_index_remove_to_nothing_then_add() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_remove_to_nothing_then_add(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_remove_to_nothing_then_add() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_remove_to_nothing_then_add(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_remove_to_nothing_then_add() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_remove_to_nothing_then_add(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_remove_to_nothing_then_add(&mut index);
            }
        });
    }

    fn run_index_insert_and_remove_cursor<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 0);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0);
            cursor.delete();
        }
        index.remove(b"key");
        assert!(index.get(b"key").copied().collect::<Vec<_>>().is_empty());
    }

    #[test_traced]
    fn test_hash_index_insert_and_remove_cursor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_insert_and_remove_cursor(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_insert_and_remove_cursor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_insert_and_remove_cursor(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_insert_and_remove_cursor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_insert_and_remove_cursor(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_insert_and_remove_cursor(&mut index);
            }
        });
    }

    fn run_index_insert_and_prune_vacant<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert_and_prune(b"key", 1u64, |_| false);
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1]);
        assert_eq!(index.items(), 1);
        assert_eq!(index.keys(), 1);
        assert_eq!(index.pruned(), 0);
    }

    #[test_traced]
    fn test_hash_index_insert_and_prune_vacant() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_insert_and_prune_vacant(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_insert_and_prune_vacant() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_insert_and_prune_vacant(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_insert_and_prune_vacant() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_insert_and_prune_vacant(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_insert_and_prune_vacant(&mut index);
            }
        });
    }

    fn run_index_insert_and_prune_replace_one<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 1u64);
        index.insert_and_prune(b"key", 2u64, |v| *v == 1);
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![2]);
        assert_eq!(index.items(), 1);
        assert_eq!(index.keys(), 1);
        assert_eq!(index.pruned(), 1);
    }

    #[test_traced]
    fn test_hash_index_insert_and_prune_replace_one() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_insert_and_prune_replace_one(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_insert_and_prune_replace_one() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_insert_and_prune_replace_one(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_insert_and_prune_replace_one() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_insert_and_prune_replace_one(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_insert_and_prune_replace_one(&mut index);
            }
        });
    }

    fn run_index_insert_and_prune_dead_insert<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 10u64);
        index.insert(b"key", 20u64);
        index.insert_and_prune(b"key", 30u64, |_| true);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<u64>>(),
            Vec::<u64>::new()
        );
        assert_eq!(index.items(), 0);
        assert_eq!(index.keys(), 0);
        assert_eq!(index.pruned(), 2);
    }

    #[test_traced]
    fn test_hash_index_insert_and_prune_dead_insert() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_insert_and_prune_dead_insert(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_insert_and_prune_dead_insert() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_insert_and_prune_dead_insert(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_insert_and_prune_dead_insert() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_insert_and_prune_dead_insert(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_insert_and_prune_dead_insert(&mut index);
            }
        });
    }

    fn run_index_cursor_across_threads<T: Translator, I>(index: Arc<Mutex<I>>)
    where
        I: Unordered<T, Value = u64> + Send + 'static,
    {
        // Insert some initial data
        {
            let mut index = index.lock().unwrap();
            index.insert(b"test_key1", 100);
            index.insert(b"test_key2", 200);
        }

        // Spawn a thread that will get a cursor and modify values
        let index_clone = Arc::clone(&index);
        let handle = thread::spawn(move || {
            // Limit the lifetime of the lock and the cursor so they drop before returning
            let result = {
                let mut index = index_clone.lock().unwrap();
                let mut updated = false;
                if let Some(mut cursor) = index.get_mut(b"test_key2") {
                    if cursor.find(|&value| value == 200) {
                        cursor.update(250);
                        updated = true;
                    }
                }
                updated
            };
            result
        });

        // Wait for the thread to complete
        let result = handle.join().unwrap();
        assert!(result);

        // Verify the update was applied (and collision retained)
        {
            let index = index.lock().unwrap();
            let values: Vec<u64> = index.get(b"test_key2").copied().collect();
            assert!(values.contains(&100));
            assert!(values.contains(&250));
            assert!(!values.contains(&200));
        }
    }

    #[test_traced]
    fn test_hash_index_cursor_across_threads() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let index = Arc::new(Mutex::new(new_unordered(context)));
            run_index_cursor_across_threads(index);
        });
    }

    #[test_traced]
    fn test_ordered_index_cursor_across_threads() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let index = Arc::new(Mutex::new(new_ordered(context)));
            run_index_cursor_across_threads(index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_cursor_across_threads() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let index = Arc::new(Mutex::new(new_partitioned_unordered(context.clone())));
                run_index_cursor_across_threads(index);
            }
            {
                let index = Arc::new(Mutex::new(new_partitioned_ordered(context)));
                run_index_cursor_across_threads(index);
            }
        });
    }

    fn run_index_remove_middle_then_next<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        for i in 0..4 {
            index.insert(b"key", i);
        }
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0);
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test_traced]
    fn test_hash_index_remove_middle_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_remove_middle_then_next(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_remove_middle_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_remove_middle_then_next(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_remove_middle_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_remove_middle_then_next(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_remove_middle_then_next(&mut index);
            }
        });
    }

    fn run_index_remove_to_nothing<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        for i in 0..4 {
            index.insert(b"key", i);
        }
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
            assert_eq!(cursor.next(), None);
        }
        assert_eq!(index.keys(), 0);
        assert_eq!(index.items(), 0);
    }

    #[test_traced]
    fn test_hash_index_remove_to_nothing() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_remove_to_nothing(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_remove_to_nothing() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_remove_to_nothing(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_remove_to_nothing() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_remove_to_nothing(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_remove_to_nothing(&mut index);
            }
        });
    }

    fn run_index_cursor_update_before_next_panics<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 123);
        let mut cursor = index.get_mut(b"key").unwrap();
        cursor.update(321);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_cursor_update_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_update_before_next_panics(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_cursor_update_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_update_before_next_panics(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_partitioned_index_cursor_update_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_update_before_next_panics(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_update_before_next_panics(&mut index);
            }
        });
    }

    fn run_index_cursor_delete_before_next_panics<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 123);
        let mut cursor = index.get_mut(b"key").unwrap();
        cursor.delete();
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_cursor_delete_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_delete_before_next_panics(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_cursor_delete_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_delete_before_next_panics(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_partitioned_index_cursor_delete_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_delete_before_next_panics(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_delete_before_next_panics(&mut index);
            }
        });
    }

    fn run_index_cursor_update_after_done<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 123);
        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert!(cursor.next().is_none());
        cursor.update(321);
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_hash_index_cursor_update_after_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_update_after_done(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_ordered_index_cursor_update_after_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_update_after_done(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_partitioned_index_cursor_update_after_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_update_after_done(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_update_after_done(&mut index);
            }
        });
    }

    fn run_index_cursor_insert_before_next<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 123);
        let mut cursor = index.get_mut(b"key").unwrap();
        cursor.insert(321);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_cursor_insert_before_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_insert_before_next(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_cursor_insert_before_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_insert_before_next(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_partitioned_index_cursor_insert_before_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_insert_before_next(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_insert_before_next(&mut index);
            }
        });
    }

    fn run_index_cursor_delete_after_done<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 123);
        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert!(cursor.next().is_none());
        cursor.delete();
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_hash_index_cursor_delete_after_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_delete_after_done(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_ordered_index_cursor_delete_after_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_delete_after_done(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_partitioned_index_cursor_delete_after_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_delete_after_done(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_delete_after_done(&mut index);
            }
        });
    }

    fn run_index_cursor_insert_with_next<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 123);
        index.insert(b"key", 456);
        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert_eq!(*cursor.next().unwrap(), 456);
        cursor.insert(789);
        assert_eq!(cursor.next(), None);
        cursor.insert(999);
        drop(cursor);
        let mut values = index.get(b"key").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![123, 456, 789, 999]);
    }

    #[test_traced]
    fn test_hash_index_cursor_insert_with_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_insert_with_next(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_cursor_insert_with_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_insert_with_next(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_cursor_insert_with_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_insert_with_next(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_insert_with_next(&mut index);
            }
        });
    }

    fn run_index_cursor_double_delete<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        index.insert(b"key", 123);
        index.insert(b"key", 456);
        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        cursor.delete();
        cursor.delete();
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_cursor_double_delete() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_double_delete(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_cursor_double_delete() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_double_delete(&mut index);
        });
    }

    fn run_index_cursor_delete_last_then_next<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
            assert!(cursor.next().is_none());
            assert!(cursor.next().is_none());
        }
        assert_eq!(index.keys(), 1);
        assert_eq!(index.items(), 1);
    }

    #[test_traced]
    fn test_hash_index_cursor_delete_last_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_cursor_delete_last_then_next(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_cursor_delete_last_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_cursor_delete_last_then_next(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_cursor_delete_last_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_cursor_delete_last_then_next(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_cursor_delete_last_then_next(&mut index);
            }
        });
    }

    fn run_index_delete_in_middle_then_continue<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 1);
        assert_eq!(*cur.next().unwrap(), 3);
        cur.delete();
        assert_eq!(*cur.next().unwrap(), 2);
        assert!(cur.next().is_none());
        assert!(cur.next().is_none());
    }

    #[test_traced]
    fn test_hash_index_delete_in_middle_then_continue() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_delete_in_middle_then_continue(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_delete_in_middle_then_continue() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_delete_in_middle_then_continue(&mut index);
        });
    }

    fn run_index_delete_first<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 1);
            cur.delete();
            assert_eq!(*cur.next().unwrap(), 3);
            assert_eq!(*cur.next().unwrap(), 2);
            assert!(cur.next().is_none());
            assert!(cur.next().is_none());
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![3, 2]);
    }

    #[test_traced]
    fn test_hash_index_delete_first() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_delete_first(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_delete_first() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_delete_first(&mut index);
        });
    }

    fn run_index_delete_first_and_insert<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 3, 2]
        );
        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 1);
            cur.delete();
            assert_eq!(*cur.next().unwrap(), 3);
            cur.insert(4);
            assert_eq!(*cur.next().unwrap(), 2);
            assert!(cur.next().is_none());
            assert!(cur.next().is_none());
        }
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![3, 4, 2]
        );
    }

    #[test_traced]
    fn test_hash_index_delete_first_and_insert() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_delete_first_and_insert(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_delete_first_and_insert() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_delete_first_and_insert(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_delete_first_and_insert() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_delete_first_and_insert(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_delete_first_and_insert(&mut index);
            }
        });
    }

    fn run_index_insert_at_entry_then_next<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 1);
        index.insert(b"key", 2);
        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 1);
        cur.insert(99);
        assert_eq!(*cur.next().unwrap(), 2);
        assert!(cur.next().is_none());
    }

    #[test_traced]
    fn test_hash_index_insert_at_entry_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_insert_at_entry_then_next(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_insert_at_entry_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_insert_at_entry_then_next(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_insert_at_entry_then_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_insert_at_entry_then_next(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_insert_at_entry_then_next(&mut index);
            }
        });
    }

    fn run_index_insert_at_entry_then_delete_head<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 10);
        index.insert(b"key", 20);
        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 10);
        cur.insert(15);
        cur.delete();
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_insert_at_entry_then_delete_head() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_insert_at_entry_then_delete_head(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_insert_at_entry_then_delete_head() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_insert_at_entry_then_delete_head(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_partitioned_index_insert_at_entry_then_delete_head() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_insert_at_entry_then_delete_head(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_insert_at_entry_then_delete_head(&mut index);
            }
        });
    }

    fn run_index_delete_then_insert_without_next<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"key", 10);
        index.insert(b"key", 20);
        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 10);
        assert_eq!(*cur.next().unwrap(), 20);
        cur.delete();
        cur.insert(15);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_delete_then_insert_without_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_delete_then_insert_without_next(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_delete_then_insert_without_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_delete_then_insert_without_next(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_partitioned_index_delete_then_insert_without_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_delete_then_insert_without_next(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_delete_then_insert_without_next(&mut index);
            }
        });
    }

    fn run_index_inserts_without_next<T: Translator, I: Unordered<T, Value = u64>>(index: &mut I) {
        index.insert(b"key", 10);
        index.insert(b"key", 20);
        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 10);
        cur.insert(15);
        cur.insert(25);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_inserts_without_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_inserts_without_next(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_inserts_without_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_inserts_without_next(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_partitioned_index_inserts_without_next() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_inserts_without_next(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_inserts_without_next(&mut index);
            }
        });
    }

    fn run_index_delete_last_then_insert_while_done<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"k", 7);
        {
            let mut cur = index.get_mut(b"k").unwrap();
            assert_eq!(*cur.next().unwrap(), 7);
            cur.delete();
            assert!(cur.next().is_none());
            cur.insert(8);
            assert!(cur.next().is_none());
            cur.insert(9);
            assert!(cur.next().is_none());
        }
        assert_eq!(index.keys(), 1);
        assert_eq!(index.items(), 2);
        assert_eq!(index.get(b"k").copied().collect::<Vec<_>>(), vec![8, 9]);
    }

    #[test_traced]
    fn test_hash_index_delete_last_then_insert_while_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_delete_last_then_insert_while_done(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_delete_last_then_insert_while_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_delete_last_then_insert_while_done(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_delete_last_then_insert_while_done() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_delete_last_then_insert_while_done(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_delete_last_then_insert_while_done(&mut index);
            }
        });
    }

    fn run_index_drop_mid_iteration_relinks<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        for i in 0..5 {
            index.insert(b"z", i);
        }
        {
            let mut cur = index.get_mut(b"z").unwrap();
            cur.next();
            cur.next();
        }
        assert_eq!(
            index.get(b"z").copied().collect::<Vec<_>>(),
            vec![0, 4, 3, 2, 1]
        );
    }

    #[test_traced]
    fn test_hash_index_drop_mid_iteration_relinks() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_drop_mid_iteration_relinks(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_drop_mid_iteration_relinks() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_drop_mid_iteration_relinks(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_drop_mid_iteration_relinks() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_drop_mid_iteration_relinks(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_drop_mid_iteration_relinks(&mut index);
            }
        });
    }

    fn run_index_update_before_next_panics<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"p", 1);
        let mut cur = index.get_mut(b"p").unwrap();
        cur.update(2);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_hash_index_update_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_update_before_next_panics(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_ordered_index_update_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_update_before_next_panics(&mut index);
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_partitioned_index_update_before_next_panics() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_update_before_next_panics(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_update_before_next_panics(&mut index);
            }
        });
    }

    fn run_index_entry_replacement_not_a_collision<T: Translator, I: Unordered<T, Value = u64>>(
        index: &mut I,
    ) {
        index.insert(b"a", 1);
        {
            let mut cur = index.get_mut(b"a").unwrap();
            cur.next();
            cur.delete();
            cur.next();
            cur.insert(2);
        }
        assert_eq!(index.keys(), 1);
        assert_eq!(index.items(), 1);
    }

    #[test_traced]
    fn test_hash_index_entry_replacement_not_a_collision() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_entry_replacement_not_a_collision(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_entry_replacement_not_a_collision() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_entry_replacement_not_a_collision(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_entry_replacement_not_a_collision() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_entry_replacement_not_a_collision(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_entry_replacement_not_a_collision(&mut index);
            }
        });
    }

    fn run_index_large_collision_chain_stack_overflow<
        T: Translator,
        I: Unordered<T, Value = u64>,
    >(
        index: &mut I,
    ) {
        for i in 0..50000 {
            index.insert(b"", i as u64);
        }
    }

    #[test_traced]
    fn test_hash_index_large_collision_chain_stack_overflow() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_unordered(context);
            run_index_large_collision_chain_stack_overflow(&mut index);
        });
    }

    #[test_traced]
    fn test_ordered_index_large_collision_chain_stack_overflow() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = new_ordered(context);
            run_index_large_collision_chain_stack_overflow(&mut index);
        });
    }

    #[test_traced]
    fn test_partitioned_index_large_collision_chain_stack_overflow() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            {
                let mut index = new_partitioned_unordered(context.clone());
                run_index_large_collision_chain_stack_overflow(&mut index);
            }
            {
                let mut index = new_partitioned_ordered(context);
                run_index_large_collision_chain_stack_overflow(&mut index);
            }
        });
    }
}
