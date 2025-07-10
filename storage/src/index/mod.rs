//! A memory-efficient index for mapping translated keys to values.
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
pub use storage::{Cursor, Index};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics};
    use rand::Rng;
    use std::collections::HashMap;

    #[test_traced]
    fn test_index_basic() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));

        // Generate a collision and check metrics to make sure it's captured
        let key = b"duplicate".as_slice();
        index.insert(key, 1);
        index.insert(key, 2);
        index.insert(key, 3);
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 3"));

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
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));

        // Removing a key that doesn't exist should be a no-op.
        index.prune(key, |_| true);
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));
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
        assert!(context.encode().contains("keys 1975"));
        assert!(context.encode().contains("items 2000"));

        for (key, loc) in expected.iter() {
            let mut values = index.get(key);
            let res = values.find(|i| *i == loc);
            assert!(res.is_some());
        }
    }

    #[test_traced]
    fn test_index_key_lengths_and_key_item_metrics() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Insert keys of different lengths
        index.insert(b"a", 1); // Shorter than cap (1 byte -> "a\0")
        index.insert(b"ab", 2); // Equal to cap (2 bytes -> "ab")
        index.insert(b"abc", 3); // Longer than cap (3 bytes -> "ab")
        assert!(context.encode().contains("keys 2"));
        assert!(context.encode().contains("items 3"));

        // Check that "a" maps to "a\0"
        assert_eq!(index.get(b"a").copied().collect::<Vec<_>>(), vec![1]);

        // Check that "ab" and "abc" map to "ab" due to TwoCap truncation
        let values = index.get(b"ab").copied().collect::<Vec<_>>();
        assert_eq!(values, vec![2, 3]);

        let values = index.get(b"abc").copied().collect::<Vec<_>>();
        assert_eq!(values, vec![2, 3]);

        // Insert another value for "ab"
        index.insert(b"ab", 4);
        assert_eq!(index.get(b"ab").copied().collect::<Vec<_>>(), vec![2, 4, 3]);
        assert!(context.encode().contains("keys 2"));
        assert!(context.encode().contains("items 4"));

        // Remove a specific value
        index.prune(b"ab", |v| *v == 4);
        assert_eq!(index.get(b"ab").copied().collect::<Vec<_>>(), vec![2, 3]);
        assert!(context.encode().contains("keys 2"));
        assert!(context.encode().contains("items 3"));

        // Remove all values for "ab"
        index.prune(b"ab", |_| true);
        assert_eq!(
            index.get(b"ab").copied().collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 1"));

        // Check that "a" is still present
        assert_eq!(index.get(b"a").copied().collect::<Vec<_>>(), vec![1]);
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
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 3, 2]
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
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1, 3]);

        // Remove head value 1
        index.prune(b"key", |v| *v == 1);
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![3]);
    }

    #[test_traced]
    fn test_index_empty_key() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        index.insert(b"", 0); // Maps to [0, 0]
        index.insert(b"\0", 1); // Maps to [0, 0]
        index.insert(b"\0\0", 2); // Maps to [0, 0]

        // All keys map to [0, 0], so all values should be returned
        let mut values = index.get(b"").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        let mut values = index.get(b"\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        let mut values = index.get(b"\0\0").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![0, 1, 2]);

        // Remove a specific value
        index.prune(b"", |v| *v == 1);
        let mut values = index.get(b"").copied().collect::<Vec<_>>();
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

        {
            let mut cursor = index.get_mut(b"key").unwrap();
            loop {
                let Some(old) = cursor.next() else {
                    break;
                };
                // Mutate the value
                let new = *old + 10;
                cursor.update(new);
            }
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![11, 13, 12]
        );
    }

    #[test_traced]
    fn test_index_mutate_middle_of_four_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);
        index.insert(b"key", 4);

        let values = index.get(b"key").copied().collect::<Vec<_>>();
        assert_eq!(values, vec![1, 4, 3, 2]);

        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 4);
            let old = *cursor.next().unwrap();
            assert_eq!(old, 3);
            cursor.update(99);
        }

        let values = index.get(b"key").copied().collect::<Vec<_>>();
        assert_eq!(values, vec![1, 4, 99, 2]);
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
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 4, 3, 2]
        );
        assert!(context.encode().contains("pruned_total 0"));

        // Test removing first value from the list.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.delete();
            assert!(context.encode().contains("pruned_total 1"));
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 2]
        );

        index.insert(b"key", 1);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 1, 3, 2]
        );

        // Test removing from the middle.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 4);
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 3);
            cursor.delete();
            assert!(context.encode().contains("pruned_total 2"));
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 1, 2]
        );
        index.insert(b"key", 3);
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 1, 2]
        );

        // Test removing last value.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 4);
            assert_eq!(*cursor.next().unwrap(), 3);
            assert_eq!(*cursor.next().unwrap(), 1);
            assert_eq!(*cursor.next().unwrap(), 2);
            cursor.delete();
            assert!(context.encode().contains("pruned_total 3"));
        }

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![4, 3, 1]
        );

        // Test removing all values.
        index.remove(b"key");
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));
        assert!(context.encode().contains("pruned_total 6"));
    }

    #[test_traced]
    fn test_index_insert_through_iterator() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Add values to the index
        index.insert(b"key", 1);
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.insert(3);
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1, 3]);
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 2"));

        // Try inserting into an iterator while iterating.
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 1);
            cursor.insert(42);
        }
        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 3"));

        // Verify second value is new one
        {
            let mut iter = index.get(b"key");
            assert_eq!(*iter.next().unwrap(), 1);
            assert_eq!(*iter.next().unwrap(), 42);
        }

        // Insert a new value
        index.insert(b"key", 100);

        // Iterate to end
        let mut iter = index.get(b"key");
        assert_eq!(*iter.next().unwrap(), 1);
        assert_eq!(*iter.next().unwrap(), 100);
        assert_eq!(*iter.next().unwrap(), 42);
        assert_eq!(*iter.next().unwrap(), 3);
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

        // Remove middle: [0, 1]
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0); // head
            assert_eq!(*cursor.next().unwrap(), 3); // middle
            cursor.delete();
            assert_eq!(*cursor.next().unwrap(), 2); // middle
            cursor.delete();
        }
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test_traced]
    fn test_index_remove_to_nothing() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0, 3, 2, 1]
        for i in 0..4 {
            index.insert(b"key", i);
        }

        // Remove middle: []
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

        // Ensure item is deleted from index
        assert!(context.encode().contains("keys 0"));
        assert!(context.encode().contains("items 0"));
    }

    #[test_traced]
    fn test_index_remove_to_nothing_then_add() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0, 3, 2, 1]
        for i in 0..4 {
            index.insert(b"key", i);
        }

        // Remove middle: [4, 5]
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

        // Ensure remaining values are correct
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test_traced]
    fn test_index_insert_and_remove_cursor() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Build list: [0]
        index.insert(b"key", 0);

        // Remove item: []
        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 0); // head
            cursor.delete();
        }
        index.remove(b"key");
        assert!(index.get(b"key").copied().collect::<Vec<i32>>().is_empty());
    }

    #[test_traced]
    fn test_index_insert_and_prune_vacant() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Inserting into a *vacant* key behaves just like `insert`: 1 key, 1 item, nothing pruned.
        index.insert_and_prune(b"key", 1u64, |_| false);

        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![1]);
        assert!(ctx.encode().contains("items 1"));
        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("pruned_total 0"));
    }

    #[test_traced]
    fn test_index_insert_and_prune_replace_one() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Add a value to the index
        index.insert(b"key", 1u64); // 0 collisions
        index.insert_and_prune(b"key", 2u64, |v| *v == 1); // replace

        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![2]);
        assert!(ctx.encode().contains("items 1"));
        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("pruned_total 1"));
    }

    #[test_traced]
    fn test_index_insert_and_prune_dead_insert() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        // Add multiple values to the same key
        index.insert(b"key", 10u64); // 0 collisions
        index.insert(b"key", 20u64); // +1 collision

        // Update an item if it matches the predicate
        index.insert_and_prune(b"key", 30u64, |_| true); // +2 pruned (and last value not added)

        assert_eq!(
            index.get(b"key").copied().collect::<Vec<u64>>(),
            Vec::<u64>::new()
        );
        assert!(ctx.encode().contains("items 0"));
        assert!(ctx.encode().contains("keys 0"));
        assert!(ctx.encode().contains("pruned_total 2"));
    }

    #[test_traced]
    fn test_index_cursor_delete_then_next_returns_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        // Build list: [1, 2]
        index.insert(b"key", 1);
        index.insert(b"key", 2);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 1); // Phase::Current

        // After deleting the current element, `next` should yield the element that was
        // copied in from the old `next` node (the iterator does not advance).
        cursor.delete(); // remove 1, copy 2 into place
        assert_eq!(*cursor.next().unwrap(), 2); // should yield 2
        assert!(cursor.next().is_none()); // now exhausted
    }

    #[test_traced]
    fn test_index_cursor_insert_after_done_appends() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 10);

        {
            let mut cursor = index.get_mut(b"key").unwrap();
            assert_eq!(*cursor.next().unwrap(), 10);
            assert!(cursor.next().is_none()); // Phase::Done

            // Inserting after we've already iterated to the end should append a new node.
            cursor.insert(20); // append while Done
        }

        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![10, 20]);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_cursor_update_before_next_panics() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        // Calling `update` before `next` is a logic error and should panic.
        cursor.update(321); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_cursor_delete_before_next_panics() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        // Calling `delete` before `next` is a logic error and should panic.
        cursor.delete(); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_index_cursor_update_after_done() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert!(cursor.next().is_none()); // Phase::Done

        // Calling `update` after `next` is a logic error and should panic.
        cursor.update(321); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_cursor_insert_before_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();

        // Calling `insert` after `next` is a logic error and should panic.
        cursor.insert(321); // triggers unreachable! branch
    }

    #[test_traced]
    #[should_panic(expected = "no active item in Cursor")]
    fn test_index_cursor_delete_after_done() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert!(cursor.next().is_none()); // Phase::Done

        // Calling `delete` after `next` is a logic error and should panic.
        cursor.delete(); // triggers unreachable! branch
    }

    #[test_traced]
    fn test_index_cursor_insert_with_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);
        index.insert(b"key", 456);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        assert_eq!(*cursor.next().unwrap(), 456);

        // Insert while in Phase::Next
        cursor.insert(789);

        // Call next to advance to Phase::Done
        assert_eq!(cursor.next(), None);

        // Add another value while in Phase::Done
        cursor.insert(999);

        // Check that everything worked
        drop(cursor);
        let mut values = index.get(b"key").copied().collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, vec![123, 456, 789, 999]);
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_cursor_double_delete() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"key", 123);
        index.insert(b"key", 456);

        let mut cursor = index.get_mut(b"key").unwrap();
        assert_eq!(*cursor.next().unwrap(), 123);
        cursor.delete();

        // Attempt to delete again (will panic)
        cursor.delete();
    }

    #[test_traced]
    fn test_index_cursor_delete_last_then_next() {
        let context = deterministic::Context::default();
        let mut index = Index::init(context.clone(), TwoCap);

        // Insert two values
        index.insert(b"key", 1);
        index.insert(b"key", 2);

        // Get mutable cursor
        let mut cursor = index.get_mut(b"key").unwrap();

        // Iterate to the second value
        assert_eq!(*cursor.next().unwrap(), 1); // Phase::Entry
        assert_eq!(*cursor.next().unwrap(), 2); // Phase::Next

        // Delete the second value
        cursor.delete();

        // Call next() once, should return None
        assert!(cursor.next().is_none());

        // Call next() again, should keep returning None
        assert!(cursor.next().is_none());

        assert!(context.encode().contains("keys 1"));
        assert!(context.encode().contains("items 1"));
    }

    #[test_traced]
    fn test_index_delete_in_middle_then_continue() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 1); // Entry
        assert_eq!(*cur.next().unwrap(), 3); // Next
        cur.delete(); // remove 3
                      // iterator must yield 2, then None, then keep returning None
        assert_eq!(*cur.next().unwrap(), 2);
        assert!(cur.next().is_none());
        assert!(cur.next().is_none());
    }

    #[test_traced]
    fn test_index_delete_first() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 1); // Entry
            cur.delete(); // remove 1
            assert_eq!(*cur.next().unwrap(), 3); // Next
            assert_eq!(*cur.next().unwrap(), 2);
            assert!(cur.next().is_none());
            assert!(cur.next().is_none());
        }

        // Check that the values are still in the index
        assert_eq!(index.get(b"key").copied().collect::<Vec<_>>(), vec![3, 2]);
    }

    #[test_traced]
    fn test_index_delete_first_and_insert() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2);
        index.insert(b"key", 3);

        // Ensure the values are in the index
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![1, 3, 2]
        );

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 1); // Entry
            cur.delete(); // remove 1
            assert_eq!(*cur.next().unwrap(), 3); // Next
            cur.insert(4); // insert 4
            assert_eq!(*cur.next().unwrap(), 2);
            assert!(cur.next().is_none());
            assert!(cur.next().is_none());
        }

        // Check that new values are around
        assert_eq!(
            index.get(b"key").copied().collect::<Vec<_>>(),
            vec![3, 4, 2]
        );
    }

    #[test_traced]
    fn test_index_insert_at_entry_then_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);

        index.insert(b"key", 1);
        index.insert(b"key", 2); // [1, 2]

        let mut cur = index.get_mut(b"key").unwrap();
        assert_eq!(*cur.next().unwrap(), 1); // Entry
        cur.insert(99); // [1, 99, 2]  (move from Phase::Entry to Phase::Next)

        // cursor must now iterate 99 to 2 to None
        assert_eq!(*cur.next().unwrap(), 2); // Next
        assert!(cur.next().is_none());
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_insert_at_entry_then_delete_head() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"key", 10);
        index.insert(b"key", 20); // [10, 20]

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 10);
            cur.insert(15);
            cur.delete();
        }
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_delete_then_insert_without_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"key", 10);
        index.insert(b"key", 20);

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 10);
            assert_eq!(*cur.next().unwrap(), 20);
            cur.delete();
            cur.insert(15);
        }
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_inserts_without_next() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"key", 10);
        index.insert(b"key", 20);

        {
            let mut cur = index.get_mut(b"key").unwrap();
            assert_eq!(*cur.next().unwrap(), 10);
            cur.insert(15);
            cur.insert(25);
        }
    }

    #[test_traced]
    fn test_index_delete_last_then_insert_while_done() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"k", 7);

        {
            let mut cur = index.get_mut(b"k").unwrap();
            assert_eq!(*cur.next().unwrap(), 7); // Entry
            cur.delete(); // list emptied, Done
            assert!(cur.next().is_none()); // Done

            cur.insert(8); // append while Done
            assert!(cur.next().is_none()); // still Done
            cur.insert(9); // another append while Done
            assert!(cur.next().is_none()); // still Done
        }

        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("items 2"));
        assert_eq!(index.get(b"k").copied().collect::<Vec<_>>(), vec![8, 9]);
    }

    #[test_traced]
    fn test_index_drop_mid_iteration_relinks() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        for i in 0..5 {
            index.insert(b"z", i);
        }

        {
            let mut cur = index.get_mut(b"z").unwrap();
            cur.next(); // Entry (0)
            cur.next(); // Next (4)
                        // cursor is dropped here after visiting two nodes
        }

        // All five values must still be visible and in stack order
        assert_eq!(
            index.get(b"z").copied().collect::<Vec<_>>(),
            vec![0, 4, 3, 2, 1]
        );
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_index_update_before_next_panics() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx, TwoCap);
        index.insert(b"p", 1);
        let mut cur = index.get_mut(b"p").unwrap();
        cur.update(2); // still illegal
    }

    #[test_traced]
    fn test_index_entry_replacement_not_a_collision() {
        let ctx = deterministic::Context::default();
        let mut index = Index::init(ctx.clone(), TwoCap);

        index.insert(b"a", 1); // collisions = 0
        let mut cur = index.get_mut(b"a").unwrap();
        cur.next(); // Entry
        cur.delete(); // list empty, pruned = 1
        cur.next(); // Done
        cur.insert(2); // replacement, *not* collision

        assert!(ctx.encode().contains("keys 1"));
        assert!(ctx.encode().contains("items 1"));
    }
}
