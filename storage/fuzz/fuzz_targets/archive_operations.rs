#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    archive::{
        prunable::{Archive, Config},
        Archive as _, Identifier,
    },
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroUsize;

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type RawKey = [u8; 16];
type RawValue = [u8; 32];

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum ArchiveOperation {
    Put {
        index: u64,
        key_data: RawKey,
        value_data: RawValue,
    },
    GetByIndex(u64),
    GetByKey(RawKey),
    HasByKey(RawKey),
    Prune(u64),
    Sync,
    NextGap {
        start: u64,
    },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<ArchiveOperation>,
}

const PAGE_SIZE: NonZeroUsize = NZUsize!(555);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(100);

fn fuzz(data: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config {
            translator: EightCap,
            key_partition: "test_key".into(),
            key_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: "test_value".into(),
            items_per_section: NZU64!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024 * 1024),
            compression: None,
            codec_config: (),
        };

        let mut archive = Archive::<_, _, Key, Value>::init(context.clone(), cfg.clone()).await.expect("init failed");

        // Keep a map of inserted items for verification
        let mut items = Vec::new();

        // Track the oldest allowed index for pruning
        let mut oldest_allowed: Option<u64> = None;

        // Track written indices
        let mut written_indices = std::collections::HashSet::new();

        for op in &data.operations {
            match op {
                ArchiveOperation::Put {
                    index,
                    key_data,
                    value_data,
                } => {
                    // Skip if we've pruned this index
                    if let Some(already_pruned) = oldest_allowed {
                        if *index < already_pruned {
                            continue;
                        }
                    }
                    let key = Key::new(*key_data);
                    let value = Value::new(*value_data);

                    // Put the item into the archive
                    archive.put(*index, key, value).await.expect("put failed");
                    // Only add if not already written (Archive doesn't allow overwrites)
                    if !written_indices.contains(index) {
                        items.push((*index, *key_data, *value_data));
                        written_indices.insert(*index);
                    }
                }

                ArchiveOperation::GetByIndex(index) => {
                    // Skip if we've pruned this index
                    if let Some(already_pruned) = oldest_allowed {
                        if *index < already_pruned {
                            continue;
                        }
                    }

                    let result = archive.get(Identifier::Index(*index)).await;

                    if let Ok(Some(value)) = result {
                        // Find the matching item in our tracked list
                        if let Some((_, _, expected_value)) =
                            items.iter().find(|(i, _, _)| *i == *index)
                        {
                            // Convert value to its raw form for comparison
                            let value_bytes: &[u8; 32] = value.as_ref().try_into().unwrap();

                            // Check that the value matches what we expect
                            assert_eq!(
                                value_bytes, expected_value,
                                "Value mismatch for index {index}",
                            );
                        }
                    } else {
                        // then we also should not have that index
                        assert!(!written_indices.contains(index));
                    }
                }

                ArchiveOperation::GetByKey(key_data) => {
                    let key = Key::new(*key_data);
                    let result = archive.get(Identifier::Key(&key)).await;

                    if let Ok(Some(value)) = result {
                        // Find all items with this exact key that haven't been pruned
                        let matching_items: Vec<_> = items.iter()
                            .filter(|(idx, k, _)| {
                                let not_pruned = if let Some(threshold) = oldest_allowed {
                                    *idx >= threshold
                                } else {
                                    true
                                };
                                not_pruned && *k == *key_data
                            })
                            .collect();

                        if matching_items.is_empty() {
                            panic!("Got value for key {key_data:?} that we didn't insert or was pruned");
                        }

                        // Convert value to its raw form for comparison
                        let value_bytes: &[u8; 32] = value.as_ref().try_into().unwrap();

                        // Check if the returned value matches ANY of the values we inserted for this key
                        let found_match = matching_items.iter().any(|(_, _, expected_value)| {
                            value_bytes == expected_value
                        });

                        if !found_match {
                            panic!(
                                "Value mismatch for key {key_data:?}. Got {:?}, but expected one of: {:?}",
                                value_bytes,
                                matching_items.iter().map(|(idx, _, v)| (idx, v)).collect::<Vec<_>>()
                            );
                        }
                    } else {
                        // If archive doesn't have it, we shouldn't have it either (or it was pruned)
                        let should_not_exist = !items.iter().any(|(idx, k, _)| {
                            let not_pruned = if let Some(threshold) = oldest_allowed {
                                *idx >= threshold
                            } else {
                                true
                            };
                            not_pruned && *k == *key_data
                        });
                        assert!(should_not_exist, "Archive should have key {key_data:?}");
                    }
                }

                ArchiveOperation::HasByKey(key_data) => {
                    let key = Key::new(*key_data);
                    let result = archive.has(Identifier::Key(&key)).await;
                    let our_result = items.iter().find(|(_, k, _)| *k == *key);

                    // Verify the result against our tracked items
                    if let Ok(has) = result {
                        if has {
                            assert!(our_result.is_some(), "stub archive doesn't have key {key_data:?} that we added");
                        } else {
                            assert!(our_result.is_none(), "Archive doesn't have key {key_data:?} that we added");
                        }
                    }
                }

                ArchiveOperation::Prune(min) => {
                    let min = min - min % cfg.items_per_section.get();
                    archive.prune(min).await.expect("prune failed");
                    match oldest_allowed {
                        None => {
                            oldest_allowed = Some(min);
                            items.retain(|(i, _, _)| *i >= min);
                            written_indices.retain(|i| *i >= min);
                        }
                        Some(already_pruned) => {
                            if min > already_pruned {
                                oldest_allowed = Some(min);
                                items.retain(|(i, _, _)| *i >= min);
                                written_indices.retain(|i| *i >= min);
                            }
                        }
                    }
                }

                ArchiveOperation::Sync => {
                    archive.sync().await.expect("sync failed");
                }

                ArchiveOperation::NextGap { start } => {
                    let (gap, next_written) = archive.next_gap(*start);

                    if let Some(gap_index) = gap {
                        // Gap should be at or after start
                        assert!(gap_index >= *start, "Gap {gap_index} before requested start {start}");

                        // If pruned, gap should be above threshold
                        if let Some(threshold) = oldest_allowed {
                            if gap_index < threshold {
                                panic!("Warning: next_gap returned gap {gap_index} below pruning threshold {threshold}");
                            }
                        }
                    }

                    if let Some(next_index) = next_written {
                        if next_index < *start {
                            panic!("Warning: next_written {next_index} is before start {start}");
                        }
                    }
                }
            }
        }

        archive.sync().await.expect("final sync failed");

        let total_items = items.len();
        let total_written = written_indices.len();
        assert_eq!(total_items, total_written, "Items count {total_items} doesn't match written indices count {total_written}");

        archive.sync().await.expect("Archive sync failed");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
