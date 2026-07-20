#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Runner, Supervisor as _};
use commonware_storage::{
    ordinal::{Config, Error, Ordinal},
    rmap::RMap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize};
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

/// Size of a `FixedBytes<32>` record (value plus CRC32).
const RECORD_SIZE: u64 = 36;

/// Bound for written indices. Records live at `index * RECORD_SIZE` in one blob, and the
/// volume's per-blob bookkeeping grows with the blob's logical size, so unbounded sparse
/// indices would balloon the run instead of exercising the store.
const MAX_INDEX: u64 = 1 << 20;

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
    operations: Vec<OrdinalOperation>,
}

/// The model state driving expectations for every put.
struct Model {
    /// All live values (pending or synced).
    expected_data: HashMap<u64, FixedBytes<32>>,
    /// The values durable at the last successful sync.
    synced_data: HashMap<u64, FixedBytes<32>>,
    /// One past the highest index ever written (the blob's size in records).
    max_written: u64,
    /// The current pruning boundary.
    floor_index: u64,
}

impl Model {
    /// Whether the record's byte range is representable in a `u64`.
    fn addressable(index: u64) -> bool {
        index
            .checked_mul(RECORD_SIZE)
            .and_then(|offset| offset.checked_add(RECORD_SIZE))
            .is_some()
    }

    /// Drive one put against the model, asserting the outcome matches.
    async fn put(
        &mut self,
        ordinal: &mut Ordinal<deterministic::Context, FixedBytes<32>>,
        index: u64,
        value: FixedBytes<32>,
    ) {
        let result = ordinal.put(index, value.clone()).await;
        if !Self::addressable(index) {
            assert!(
                matches!(result, Err(Error::IndexOverflow(_))),
                "put at unaddressable index {index} must fail",
            );
            return;
        }
        if index < self.floor_index {
            assert!(
                matches!(result, Err(Error::IndexPruned(_))),
                "put below the pruning boundary {index} must fail",
            );
            return;
        }
        result.expect("failed to put value into store");
        self.expected_data.insert(index, value);
        self.max_written = self.max_written.max(index + 1);
    }
}

fn fuzz(input: FuzzInput) {
    // Initialize the runtime
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        // Initialize the ordinal
        let cfg = Config {
            partition: "ordinal-operations-fuzz-test".into(),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(64 * 1024),
        };
        let mut store = Some(Ordinal::<_, FixedBytes<32>>::init(context.child("storage"), cfg.clone(), None).await.expect("failed to init ordinal"));
        let mut restarts = 0usize;

        // Run operations
        let mut model = Model {
            expected_data: HashMap::new(),
            synced_data: HashMap::new(),
            max_written: 0,
            floor_index: 0,
        };
        for op in input.operations.iter() {
            match op {
                OrdinalOperation::Put { index, value } => {
                    if let Some(ordinal) = store.as_mut() {
                        let mut fixed_value = [0u8; 32];
                        let len = value.len().min(32);
                        fixed_value[..len].copy_from_slice(&value[..len]);
                        model.put(ordinal, *index % MAX_INDEX, FixedBytes::new(fixed_value)).await;
                    }
                }

                OrdinalOperation::Get { index } => {
                    if let Some(ordinal) = store.as_ref() {
                        match ordinal.get(*index).await {
                            Ok(Some(value)) => {
                                if let Some(expected) = model.expected_data.get(index) {
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
                                    !model.expected_data.contains_key(index),
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
                        let expected = model.expected_data.contains_key(index);
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
                            model.synced_data = model.expected_data.clone();
                        }
                    }
                }

                OrdinalOperation::Prune { min } => {
                    if let Some(ordinal) = store.as_mut() {
                        // Pruning is exact but capped to the written range.
                        let capped = (*min).min(model.max_written);
                        if ordinal.prune(*min).await.is_ok() {
                            model.floor_index = model.floor_index.max(capped);
                            model.expected_data.retain(|&index, _| index >= capped);
                            model.synced_data.retain(|&index, _| index >= capped);
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
                            model.put(ordinal, index % MAX_INDEX, FixedBytes::new(value)).await;
                        }

                        // Sync after batch operation to test persistence
                        if !indices.is_empty() && ordinal.sync().await.is_ok() {
                            model.synced_data = model.expected_data.clone();
                        }
                    }
                }

                OrdinalOperation::PutLargeBatch { start, count } => {
                    if let Some(ordinal) = store.as_mut() {
                        // Put many consecutive values to test write buffering
                        let count = (*count) as u32;
                        let start = *start;

                        for i in 0..count {
                            let index = start as u64 + i as u64;
                            let mut value = [0u8; 32];
                            value[0] = i as u8;
                            model.put(ordinal, index, FixedBytes::new(value)).await;
                        }

                        // Sync after large batch to test buffer flushing
                        if count > 0 && ordinal.sync().await.is_ok() {
                            model.synced_data = model.expected_data.clone();
                        }
                    }
                }

                OrdinalOperation::ReopenAfterOperations => {
                    if let Some(mut o) = store.take() {
                        // Sync and drop the current ordinal
                        o.sync().await.expect("failed to sync store before reopen failed");
                        drop(o);

                        // Update synced_data
                        model.synced_data = model.expected_data.clone();

                        // Reopen and verify synced data persisted
                        let committed: RMap = model.synced_data.keys().copied().collect();
                        match Ordinal::<_, FixedBytes<32>>::init(context.child("ordinal").with_attribute("instance", restarts), cfg.clone(), Some(committed)).await
                        {
                            Ok(new_ordinal) => {
                                restarts += 1;
                                // Verify all synced data is still accessible
                                for (&index, expected_value) in model.synced_data.iter() {
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
