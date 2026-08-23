#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    archive::{
        Archive as _, Identifier, MultiArchive as _,
        prunable::{Archive, Config},
    },
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::num::{NonZeroU16, NonZeroUsize};

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type RawKey = [u8; 16];
type RawValue = [u8; 32];
type TestArchive = Archive<EightCap, deterministic::Context, Key, Value>;

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum ArchiveOperation {
    Put {
        index: u64,
        key_data: RawKey,
        value_data: RawValue,
    },
    PutMulti {
        section: u8,
        slot: u8,
        key_id: u8,
        value_id: u8,
    },
    GetByIndex(u64),
    GetAll {
        section: u8,
        slot: u8,
    },
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

const PAGE_SIZE: NonZeroU16 = NZU16!(456);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(100);

// Exact duplicate keys and translated-key collisions are otherwise vanishingly unlikely in
// arbitrary byte strings. Use 16 exact keys spread across four EightCap translations so the
// target composes both cases.
fn canonical_key(raw: RawKey) -> RawKey {
    let id = raw[0] & 0x0f;
    let mut key = [0; 16];
    key[0] = id & 0x03;
    key[8] = id >> 2;
    key
}

// Draw MultiArchive indices from a small domain spanning multiple sections. This makes exact
// duplicate indices common enough to exercise position ordering while retaining cross-section
// replay permutations.
fn multi_index(section: u8, slot: u8, items_per_section: u64) -> u64 {
    u64::from(section & 0x01) * items_per_section + u64::from(slot & 0x03)
}

async fn assert_index_matches(
    archive: &TestArchive,
    items: &[(u64, RawKey, RawValue)],
    index: u64,
) {
    let expected: Vec<Value> = items
        .iter()
        .filter_map(|(item_index, _, value)| (*item_index == index).then_some(Value::new(*value)))
        .collect();
    let actual = archive
        .get(Identifier::Index(index))
        .await
        .unwrap_or_else(|err| panic!("get by index {index} failed: {err:?}"));
    assert_eq!(
        actual,
        expected.first().cloned(),
        "first value mismatch for index {index}",
    );

    let actual_all = archive
        .get_all(index)
        .await
        .unwrap_or_else(|err| panic!("get_all for index {index} failed: {err:?}"));
    let expected_all = (!expected.is_empty()).then_some(expected);
    assert_eq!(
        actual_all, expected_all,
        "insertion order mismatch for index {index}",
    );
}

async fn assert_key_matches(
    archive: &TestArchive,
    items: &[(u64, RawKey, RawValue)],
    key_data: RawKey,
) {
    let key = Key::new(key_data);
    let actual = archive
        .get(Identifier::Key(&key))
        .await
        .unwrap_or_else(|err| panic!("get by key {key_data:?} failed: {err:?}"));
    let expected: Vec<_> = items
        .iter()
        .filter_map(|(_, key, value)| (*key == key_data).then_some(value))
        .collect();

    match actual {
        Some(actual) => assert!(
            expected.iter().any(|value| actual.as_ref() == *value),
            "key {key_data:?} returned unmodeled value {:?}; expected one of {expected:?}",
            actual.as_ref(),
        ),
        None => {
            assert!(
                expected.is_empty(),
                "key {key_data:?} is unexpectedly missing"
            )
        }
    }
}

fn fuzz(data: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config {
            translator: EightCap,
            metadata_partition: "test-metadata".into(),
            key_partition: "test-key".into(),
            key_page_cache: CacheRef::from_pooler(
                &context,
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            ),
            value_partition: "test-value".into(),
            items_per_section: NZU64!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024 * 1024),
            compression: None,
            codec_config: (),
        };
        let items_per_section = cfg.items_per_section.get();

        let mut archive = Archive::<_, _, Key, Value>::init(context.child("storage"), cfg.clone()).await.expect("init failed");

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
                    let key_data = canonical_key(*key_data);
                    let key = Key::new(key_data);
                    let value = Value::new(*value_data);

                    // Put the item into the archive. A put below the prune floor is
                    // satisfied without storing, so the model only records puts at or
                    // above the floor.
                    archive = archive.put(*index, key, value).await.expect("put failed");
                    let below_floor = oldest_allowed.is_some_and(|min| *index < min);

                    // Only add if not already written (Archive doesn't allow overwrites)
                    if !below_floor && !written_indices.contains(index) {
                        items.push((*index, key_data, *value_data));
                        written_indices.insert(*index);
                    }

                    assert_key_matches(&archive, &items, key_data).await;
                    assert_index_matches(&archive, &items, *index).await;
                }

                ArchiveOperation::PutMulti {
                    section,
                    slot,
                    key_id,
                    value_id,
                } => {
                    let index = multi_index(*section, *slot, items_per_section);
                    let key_data = canonical_key([*key_id; 16]);
                    let value_data = [*value_id; 32];
                    let key = Key::new(key_data);
                    let value = Value::new(value_data);

                    archive = archive
                        .put_multi(index, key, value)
                        .await
                        .expect("put_multi failed");
                    let below_floor = oldest_allowed.is_some_and(|min| index < min);
                    if !below_floor {
                        items.push((index, key_data, value_data));
                        written_indices.insert(index);
                    }

                    assert_key_matches(&archive, &items, key_data).await;
                    assert_index_matches(&archive, &items, index).await;
                }

                ArchiveOperation::GetByIndex(index) => {
                    assert_index_matches(&archive, &items, *index).await;
                }

                ArchiveOperation::GetAll { section, slot } => {
                    let index = multi_index(*section, *slot, items_per_section);
                    assert_index_matches(&archive, &items, index).await;
                }

                ArchiveOperation::GetByKey(key_data) => {
                    assert_key_matches(&archive, &items, canonical_key(*key_data)).await;
                }

                ArchiveOperation::HasByKey(key_data) => {
                    let key_data = canonical_key(*key_data);
                    let key = Key::new(key_data);
                    let actual = archive
                        .has(Identifier::Key(&key))
                        .await
                        .unwrap_or_else(|err| panic!("has by key {key_data:?} failed: {err:?}"));
                    let expected = items.iter().any(|(_, key, _)| *key == key_data);
                    assert_eq!(actual, expected, "has mismatch for key {key_data:?}");
                }

                ArchiveOperation::Prune(min) => {
                    let min = min - min % cfg.items_per_section.get();
                    archive = archive.prune(min).await.expect("prune failed");
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
                    archive = archive.sync().await.expect("sync failed");
                }

                ArchiveOperation::NextGap { start } => {
                    let (gap, next_written) = archive.next_gap(*start);

                    if let Some(gap_index) = gap {
                        // Gap should be at or after start
                        assert!(gap_index >= *start, "Gap {gap_index} before requested start {start}");

                        // If pruned, gap should be above threshold
                        if let Some(threshold) = oldest_allowed
                            && gap_index < threshold {
                                panic!("Warning: next_gap returned gap {gap_index} below pruning threshold {threshold}");
                            }
                    }

                    if let Some(next_index) = next_written
                        && next_index < *start {
                            panic!("Warning: next_written {next_index} is before start {start}");
                        }
                }
            }
        }

        archive = archive.sync().await.expect("final sync failed");

        let modeled_indices: std::collections::HashSet<_> =
            items.iter().map(|(index, _, _)| *index).collect();
        assert_eq!(modeled_indices, written_indices, "written-index model drifted");

        drop(archive);
        let archive = Archive::<_, _, Key, Value>::init(context.child("storage"), cfg)
            .await
            .expect("restart init failed");
        for key_id in 0..16 {
            let key = canonical_key([key_id; 16]);
            assert_key_matches(&archive, &items, key).await;
        }
        let retained_indices: std::collections::BTreeSet<_> =
            items.iter().map(|(index, _, _)| *index).collect();
        for index in retained_indices {
            assert_index_matches(&archive, &items, index).await;
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
