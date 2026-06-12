#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Runner, Supervisor as _};
use commonware_storage::{
    index::{partitioned, unordered::Index, Cursor as _, Factory, Unordered},
    translator::{Cap, FourCap, Hashed, Translator, TwoCap},
};
use commonware_utils::FuzzRng;
use libfuzzer_sys::fuzz_target;
use rand::RngCore;

#[derive(Arbitrary, Debug, Clone)]
enum TranslatorChoice {
    TwoCap,
    FourCap,
    HashedFourCap,
    HashedCap3,
    HashedTwoCap,
}

#[derive(Arbitrary, Debug, Clone)]
enum IndexOperation {
    Insert {
        key: Vec<u8>,
        value: u64,
    },
    Get {
        key: Vec<u8>,
    },
    GetMany {
        keys: Vec<Vec<u8>>,
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
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    translator: TranslatorChoice,
    operations: Vec<IndexOperation>,
    raw_bytes: Vec<u8>,
}

fn run<T: Translator, I: Factory<T> + Unordered<Value = u64>>(
    context: deterministic::Context,
    translator: T,
    operations: &[IndexOperation],
) {
    let mut index = I::new(context.child("storage"), translator);

    for op in operations {
        match op {
            IndexOperation::Insert { key, value } => {
                index.insert(key, *value);
            }

            IndexOperation::Get { key } => {
                let _values: Vec<_> = index.get(key).collect();
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
        }
    }
}

/// Run the same operations against every index type sharing the [Unordered] API.
fn run_all<T: Translator>(
    context: deterministic::Context,
    translator: T,
    operations: &[IndexOperation],
) {
    run::<T, Index<T, u64>>(context.child("plain"), translator.clone(), operations);
    run::<T, partitioned::unordered::Index<T, u64, 1>>(
        context.child("partitioned"),
        translator,
        operations,
    );
}

fn fuzz(input: FuzzInput) {
    let cfg =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|context| async move {
        let mut rng = FuzzRng::new(input.raw_bytes);
        match input.translator {
            TranslatorChoice::TwoCap => run_all(context, TwoCap, &input.operations),
            TranslatorChoice::FourCap => run_all(context, FourCap, &input.operations),
            TranslatorChoice::HashedFourCap => {
                run_all(
                    context,
                    Hashed::from_seed(rng.next_u64(), FourCap),
                    &input.operations,
                );
            }
            TranslatorChoice::HashedCap3 => {
                run_all(
                    context,
                    Hashed::from_seed(rng.next_u64(), Cap::<3>::new()),
                    &input.operations,
                );
            }
            TranslatorChoice::HashedTwoCap => {
                run_all(
                    context,
                    Hashed::from_seed(rng.next_u64(), TwoCap),
                    &input.operations,
                );
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
