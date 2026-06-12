#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Runner, Supervisor as _};
use commonware_storage::{
    index::{ordered::Index, partitioned, Cursor as _, Factory, Ordered},
    translator::TwoCap,
};
use commonware_utils::FuzzRng;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum IndexOperation {
    Insert {
        key: Vec<u8>,
        value: u64,
    },
    Get {
        key: Vec<u8>,
    },
    GetMut {
        key: Vec<u8>,
    },
    GetMutOrInsert {
        key: Vec<u8>,
        value: u64,
    },
    Remove {
        key: Vec<u8>,
    },
    Prune {
        key: Vec<u8>,
        prune_value: u64,
    },
    InsertAndPrune {
        key: Vec<u8>,
        value: u64,
        prune_value: u64,
    },
    // Edge case operations
    InsertLargeKey {
        value: u64,
    },
    InsertMany {
        key: Vec<u8>,
        count: u8,
    },
    PruneAll {
        key: Vec<u8>,
    },
    // Cursor operations
    CursorIterate {
        key: Vec<u8>,
    },
    CursorUpdate {
        key: Vec<u8>,
        new_value: u64,
    },
    CursorDelete {
        key: Vec<u8>,
    },
    CursorInsert {
        key: Vec<u8>,
        value: u64,
    },
    // Ordered trait operations
    GetMany {
        keys: Vec<Vec<u8>>,
    },
    NextTranslatedKey {
        key: Vec<u8>,
    },
    PrevTranslatedKey {
        key: Vec<u8>,
    },
    FirstTranslatedKey,
    LastTranslatedKey,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<IndexOperation>,
    raw_bytes: Vec<u8>,
}

fn run<I: Factory<TwoCap> + Ordered<Value = u64>>(
    context: deterministic::Context,
    operations: &[IndexOperation],
) {
    let mut index = I::new(context.child("storage"), TwoCap);

    for op in operations.iter() {
        match op {
            IndexOperation::Insert { key, value } => {
                index.insert(key, *value);
            }

            IndexOperation::Get { key } => {
                let _values: Vec<_> = index.get(key).collect();
            }

            IndexOperation::GetMut { key } => {
                if let Some(mut cursor) = index.get_mut(key) {
                    // Iterate through all values
                    while cursor.next().is_some() {
                        // Just iterate, don't modify
                    }
                }
            }

            IndexOperation::GetMutOrInsert { key, value } => {
                if let Some(mut cursor) = index.get_mut_or_insert(key, *value) {
                    // Iterate through existing values
                    while cursor.next().is_some() {
                        // Just iterate
                    }
                }
            }

            IndexOperation::Remove { key } => {
                index.remove(key);
            }

            IndexOperation::Prune { key, prune_value } => {
                index.retain(key, |v| *v != *prune_value);
            }

            IndexOperation::InsertAndPrune {
                key,
                value,
                prune_value,
            } => {
                index.insert_and_retain(key, *value, |v| *v != *prune_value);
            }

            IndexOperation::InsertLargeKey { value } => {
                // Create a large key to test translator behavior
                let large_key = vec![0u8; 1000];
                index.insert(&large_key, *value);
            }

            IndexOperation::InsertMany { key, count } => {
                // Insert multiple values for the same key to test collisions
                for i in 0..*count {
                    index.insert(key, i as u64);
                }
            }

            IndexOperation::PruneAll { key } => {
                // Remove all values for a key
                index.retain(key, |_| false);
            }

            IndexOperation::CursorIterate { key } => {
                if let Some(mut cursor) = index.get_mut(key) {
                    // Iterate through all values
                    while cursor.next().is_some() {
                        // Just iterate
                    }
                }
            }

            IndexOperation::CursorUpdate { key, new_value } => {
                if let Some(mut cursor) = index.get_mut(key) {
                    if cursor.next().is_some() {
                        cursor.update(*new_value);
                    }
                }
            }

            IndexOperation::CursorDelete { key } => {
                if let Some(mut cursor) = index.get_mut(key) {
                    if cursor.next().is_some() {
                        cursor.delete();
                    }
                }
            }

            IndexOperation::CursorInsert { key, value } => {
                if let Some(mut cursor) = index.get_mut_or_insert(key, *value) {
                    cursor.next();
                    cursor.insert(*value);
                }
            }

            IndexOperation::GetMany { keys } => {
                let mut visited = 0usize;
                index.get_many(keys, |key_idx, _value| {
                    assert!(key_idx < keys.len(), "get_many visited invalid key index");
                    visited += 1;
                });
                let expected: usize = keys.iter().map(|key| index.get(key).count()).sum();
                assert_eq!(visited, expected, "get_many visit count mismatch");
            }

            IndexOperation::NextTranslatedKey { key } => {
                if let Some((iter, _wrapped)) = index.next_translated_key(key) {
                    assert!(iter.count() > 0, "next_translated_key returned empty chain");
                } else {
                    assert!(
                        index.first_translated_key().is_none(),
                        "next_translated_key returned None on non-empty index"
                    );
                }
            }

            IndexOperation::PrevTranslatedKey { key } => {
                if let Some((iter, _wrapped)) = index.prev_translated_key(key) {
                    assert!(iter.count() > 0, "prev_translated_key returned empty chain");
                } else {
                    assert!(
                        index.last_translated_key().is_none(),
                        "prev_translated_key returned None on non-empty index"
                    );
                }
            }

            IndexOperation::FirstTranslatedKey => {
                if let Some(iter) = index.first_translated_key() {
                    assert!(
                        iter.count() > 0,
                        "first_translated_key returned empty chain"
                    );
                }
            }

            IndexOperation::LastTranslatedKey => {
                if let Some(iter) = index.last_translated_key() {
                    assert!(iter.count() > 0, "last_translated_key returned empty chain");
                }
            }
        }
    }
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes)));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|context| async move {
        // Run the same operations against every index type sharing the Ordered API.
        run::<Index<TwoCap, u64>>(context.child("plain"), &input.operations);
        run::<partitioned::ordered::Index<TwoCap, u64, 1>>(
            context.child("partitioned"),
            &input.operations,
        );
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
