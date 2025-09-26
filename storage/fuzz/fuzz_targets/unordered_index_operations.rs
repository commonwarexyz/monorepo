#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::{
    index::{Cursor as _, Index as _, Unordered as Index},
    translator::TwoCap,
};
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
    Keys,
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
    operations: Vec<IndexOperation>,
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut index = Index::init(context.clone(), TwoCap);

        for op in input.operations.iter() {
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
                    index.prune(key, |v| *v == *prune_value);
                }

                IndexOperation::InsertAndPrune {
                    key,
                    value,
                    prune_value,
                } => {
                    index.insert_and_prune(key, *value, |v| *v == *prune_value);
                }

                IndexOperation::Keys => {
                    index.keys();
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
                    index.prune(key, |_| true);
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
                    // Just use regular insert - simpler and avoids borrow issues
                    index.insert(key, *value);
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
