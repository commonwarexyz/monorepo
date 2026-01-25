#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Metrics, Runner};
use commonware_storage::ordinal::{Config, Ordinal};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

#[derive(Debug, Clone)]
enum OrdinalOperation {
    Put { index: u64, value: Vec<u8> },
    Get { index: u64 },
    Has { index: u64 },
    NextGap { index: u64 },
    Sync,
    Prune { min: u64 },
    Destroy,
    // Edge case operations
    PutSparse { indices: Vec<u64> },
    PutLargeBatch { start: u32, count: u8 },
    ReopenAfterOperations,
}

const MAX_SPARSE_INDICES: usize = 10;

impl<'a> Arbitrary<'a> for OrdinalOperation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 10 {
            0 => Ok(OrdinalOperation::Put {
                index: u.arbitrary()?,
                value: u.arbitrary()?,
            }),
            1 => Ok(OrdinalOperation::Get {
                index: u.arbitrary()?,
            }),
            2 => Ok(OrdinalOperation::Has {
                index: u.arbitrary()?,
            }),
            3 => Ok(OrdinalOperation::NextGap {
                index: u.arbitrary()?,
            }),
            4 => Ok(OrdinalOperation::Sync),
            5 => Ok(OrdinalOperation::Prune {
                min: u.arbitrary()?,
            }),
            6 => Ok(OrdinalOperation::Destroy),
            7 => {
                let num_indices = u.int_in_range(1..=MAX_SPARSE_INDICES)?;
                let indices = (0..num_indices)
                    .map(|_| u.arbitrary())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(OrdinalOperation::PutSparse { indices })
            }
            8 => Ok(OrdinalOperation::PutLargeBatch {
                start: u.arbitrary()?,
                count: u.arbitrary()?,
            }),
            9 => Ok(OrdinalOperation::ReopenAfterOperations),
            _ => unreachable!(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    items_per_blob: u16,
    operations: Vec<OrdinalOperation>,
}

fn fuzz(input: FuzzInput) {
    // Initialize the runtime
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        // Initialize the ordinal
        let items_per_blob = NZU64!(input.items_per_blob.clamp(1, u16::MAX) as u64);
        let cfg = Config {
            partition: "ordinal_operations_fuzz_test".to_string(),
            items_per_blob,
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(64 * 1024),
        };
        let mut store = Some(Ordinal::<_, FixedBytes<32>>::init(context.clone(), cfg.clone()).await.expect("failed to init ordinal"));
        let mut restarts = 0usize;

        // Run operations
        let mut expected_data: HashMap<u64, FixedBytes<32>> = HashMap::new();
        let mut synced_data: HashMap<u64, FixedBytes<32>> = HashMap::new();
        for op in input.operations.iter() {
            match op {
                OrdinalOperation::Put { index, value } => {
                    if let Some(ordinal) = store.as_mut() {
                        let mut fixed_value = [0u8; 32];
                        let len = value.len().min(32);
                        fixed_value[..len].copy_from_slice(&value[..len]);
                        let value = FixedBytes::new(fixed_value);

                        if ordinal.put(*index, value.clone()).await.is_ok() {
                            expected_data.insert(*index, value);
                        } else {
                            panic!("failed to put value into store");
                        }
                    }
                }

                OrdinalOperation::Get { index } => {
                    if let Some(ordinal) = store.as_ref() {
                        match ordinal.get(*index).await {
                            Ok(Some(value)) => {
                                if let Some(expected) = expected_data.get(index) {
                                    assert_eq!(
                                        &value, expected,
                                        "Get returned unexpected value at index {index}",
                                    );
                                } else {
                                    panic!(
                                        "Get returned value for index {index} that wasn't put",
                                    );
                                }
                            }
                            Ok(None) => {
                                assert!(
                                    !expected_data.contains_key(index),
                                    "Get returned None for index {index} that should exist",
                                );
                            }
                            Err(e) => {
                                panic!("Failed to get ordinal at index {index}: {e:?}");
                            }
                        }
                    }
                }

                OrdinalOperation::Has { index } => {
                    if let Some(ordinal) = store.as_ref() {
                        let has = ordinal.has(*index);
                        let expected = expected_data.contains_key(index);
                        assert_eq!(
                            has, expected,
                            "Has returned {has} for index {index}, expected {expected}",
                        );
                    }
                }

                OrdinalOperation::NextGap { index } => {
                    if let Some(ordinal) = store.as_ref() {
                        let (current_end, next_start) = ordinal.next_gap(*index);

                        if let Some(end) = current_end {
                            assert!(ordinal.has(end), "current_end {end} should exist");
                            if end < u64::MAX {
                                assert!(
                                    !ordinal.has(end + 1),
                                    "Gap should exist after current_end {end}",
                                );
                            }
                        }

                        if let Some(start) = next_start {
                            assert!(ordinal.has(start), "next_start {start} should exist");
                            if start > 0 {
                                assert!(
                                    !ordinal.has(start - 1),
                                    "Gap should exist before next_start {start}",
                                );
                            }
                        }
                    }
                }

                OrdinalOperation::Sync => {
                    if let Some(ordinal) = store.as_mut() {
                        if ordinal.sync().await.is_ok() {
                            // After sync, all expected data should be persisted
                            synced_data = expected_data.clone();
                        }
                    }
                }

                OrdinalOperation::Prune { min } => {
                    if let Some(ordinal) = store.as_mut() {
                        let min_blob = *min / items_per_blob;
                        if ordinal.prune(*min).await.is_ok() {
                            // Remove all data in pruned blobs from expected state
                            expected_data.retain(|&index, _| index / items_per_blob >= min_blob);
                            synced_data.retain(|&index, _| index / items_per_blob >= min_blob);
                        }
                    }
                }


                OrdinalOperation::Destroy => {
                    if let Some(o) = store.take() {
                        o.destroy().await.expect("failed to destroy store");
                        return;
                    }
                }

                OrdinalOperation::PutSparse { indices } => {
                    if let Some(ordinal) = store.as_mut() {
                        // Put values at sparse indices to test gap handling
                        for (i, &index) in indices.iter().enumerate() {
                            let mut value = [0u8; 32];
                            value[0] = i as u8;
                            let value = FixedBytes::new(value);

                            if ordinal.put(index, value.clone()).await.is_ok() {
                                expected_data.insert(index, value);
                            }
                        }

                        // Sync after batch operation to test persistence
                        if !indices.is_empty() && ordinal.sync().await.is_ok() {
                            synced_data = expected_data.clone();
                        }
                    }
                }

                OrdinalOperation::PutLargeBatch { start, count } => {
                    if let Some(ordinal) = store.as_mut() {
                        // Put many consecutive values to test blob handling
                        let count = (*count) as u32;
                        let start = *start;

                        for i in 0..count {
                            let index = start as u64 + i as u64;
                            let mut value = [0u8; 32];
                            value[0] = i as u8;
                            let value = FixedBytes::new(value);

                            if ordinal.put(index, value.clone()).await.is_ok() {
                                expected_data.insert(index, value);
                            }
                        }

                        // Sync after large batch to test buffer flushing
                        if count > 0 && ordinal.sync().await.is_ok() {
                            synced_data = expected_data.clone();
                        }
                    }
                }

                OrdinalOperation::ReopenAfterOperations => {
                    if let Some(mut o) = store.take() {
                        // Sync and drop the current ordinal
                        o.sync().await.expect("failed to sync store before reopen failed");
                        drop(o);

                        // Update synced_data
                        synced_data = expected_data.clone();

                        // Reopen and verify synced data persisted
                        match Ordinal::<_, FixedBytes<32>>::init(context.with_label("ordinal").with_attribute("instance", restarts), cfg.clone()).await
                        {
                            Ok(new_ordinal) => {
                                restarts += 1;
                                // Verify all synced data is still accessible
                                for (&index, expected_value) in synced_data.iter() {
                                    match new_ordinal.get(index).await {
                                        Ok(Some(value)) => {
                                            assert_eq!(
                                                &value, expected_value,
                                                "Value at index {index} doesn't match after reopen",
                                            );
                                        }
                                        Ok(None) => {
                                            panic!(
                                                "Synced value at index {index} missing after reopen",
                                            );
                                        }
                                        Err(e) => {
                                            panic!("Synced value at index {index} doesn't match after reopen: {e:?}");
                                        }
                                    }
                                }

                                // Continue with the new ordinal
                                store = Some(new_ordinal);
                                // Expected data remains the same after reopen
                            }
                            Err(e) => {
                                panic!("Failed to reopen ordinal: {e:?}");
                            }
                        }
                    }
                }
            }
        }

        if let Some(o) = store.take() {
            o.destroy().await.expect("failed to destroy store");
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
