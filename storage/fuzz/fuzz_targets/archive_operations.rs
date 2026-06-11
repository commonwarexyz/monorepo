#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Supervisor as _};
use commonware_storage::{
    archive::{
        immutable::{Archive as ImmutableArchive, Config as ImmutableConfig},
        prunable::{Archive as PrunableArchive, Config as PrunableConfig},
        Archive as ArchiveTrait, Error as ArchiveError, Identifier, MultiArchive as _,
    },
    translator::{EightCap, FourCap, Translator},
};
use commonware_utils::{sequence::FixedBytes, FuzzRng, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashSet,
    num::{NonZeroU16, NonZeroUsize},
};

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type RawKey = [u8; 16];
type RawValue = [u8; 32];
type Context = deterministic::Context;
type Prunable<T> = PrunableArchive<T, Context, Key, Value>;
type Immutable = ImmutableArchive<Context, Key, Value>;

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq)]
enum ArchiveKind {
    PrunableEight,
    PrunableFourCompressed,
    ImmutableCompressed,
}

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
    HasByIndex(u64),
    PutMulti {
        index: u64,
        key_data: RawKey,
        value_data: RawValue,
    },
    PutMultiSync {
        index: u64,
        key_data: RawKey,
        value_data: RawValue,
    },
    GetAll(u64),
    Prune(u64),
    Sync,
    Restart,
    Ranges,
    RangesFrom(u64),
    FirstLastIndex,
    MissingItems {
        start: u64,
        max: u8,
    },
    NextGap {
        start: u64,
    },
    Destroy,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    archive: ArchiveKind,
    operations: Vec<ArchiveOperation>,
    raw_bytes: Vec<u8>,
}

const PAGE_SIZE: NonZeroU16 = NZU16!(456);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(100);

trait ArchiveHarness: ArchiveTrait<Key = Key, Value = Value> + Sized {
    type Config: Clone;

    const SUPPORTS_MULTI: bool;
    const SUPPORTS_PRUNE: bool;

    async fn init(context: Context, cfg: Self::Config) -> Self;

    fn items_per_section(cfg: &Self::Config) -> u64;

    async fn put_multi_harness(
        &mut self,
        _index: u64,
        _key: Key,
        _value: Value,
    ) -> Result<(), ArchiveError> {
        Ok(())
    }

    async fn put_multi_sync_harness(
        &mut self,
        index: u64,
        key: Key,
        value: Value,
    ) -> Result<(), ArchiveError> {
        self.put_multi_harness(index, key, value).await?;
        self.sync().await
    }

    async fn get_all_harness(&self, _index: u64) -> Result<Option<Vec<Value>>, ArchiveError> {
        Ok(None)
    }

    async fn prune_harness(&mut self, _min: u64) -> Result<(), ArchiveError> {
        Ok(())
    }
}

impl<T: Translator> ArchiveHarness for Prunable<T> {
    type Config = PrunableConfig<T, ()>;

    const SUPPORTS_MULTI: bool = true;
    const SUPPORTS_PRUNE: bool = true;

    async fn init(context: Context, cfg: Self::Config) -> Self {
        Self::init(context, cfg).await.expect("init failed")
    }

    fn items_per_section(cfg: &Self::Config) -> u64 {
        cfg.items_per_section.get()
    }

    async fn put_multi_harness(
        &mut self,
        index: u64,
        key: Key,
        value: Value,
    ) -> Result<(), ArchiveError> {
        self.put_multi(index, key, value).await
    }

    async fn put_multi_sync_harness(
        &mut self,
        index: u64,
        key: Key,
        value: Value,
    ) -> Result<(), ArchiveError> {
        self.put_multi_sync(index, key, value).await
    }

    async fn get_all_harness(&self, index: u64) -> Result<Option<Vec<Value>>, ArchiveError> {
        self.get_all(index).await
    }

    async fn prune_harness(&mut self, min: u64) -> Result<(), ArchiveError> {
        self.prune(min).await
    }
}

impl ArchiveHarness for Immutable {
    type Config = ImmutableConfig<()>;

    const SUPPORTS_MULTI: bool = false;
    const SUPPORTS_PRUNE: bool = false;

    async fn init(context: Context, cfg: Self::Config) -> Self {
        Self::init(context, cfg).await.expect("init failed")
    }

    fn items_per_section(cfg: &Self::Config) -> u64 {
        cfg.items_per_section.get()
    }
}

fn prunable_cfg<T: Translator>(
    context: &Context,
    translator: T,
    suffix: &str,
    compression: Option<u8>,
) -> PrunableConfig<T, ()> {
    PrunableConfig {
        translator,
        key_partition: format!("test-key-{suffix}"),
        key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        value_partition: format!("test-value-{suffix}"),
        items_per_section: NZU64!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024 * 1024),
        compression,
        codec_config: (),
    }
}

fn immutable_cfg(context: &Context, suffix: &str, compression: Option<u8>) -> ImmutableConfig<()> {
    ImmutableConfig {
        metadata_partition: format!("immutable-metadata-{suffix}"),
        freezer_table_partition: format!("immutable-table-{suffix}"),
        freezer_table_initial_size: 1024,
        freezer_table_resize_frequency: 4,
        freezer_table_resize_chunk_size: 1024,
        freezer_key_partition: format!("immutable-key-{suffix}"),
        freezer_key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        freezer_value_partition: format!("immutable-value-{suffix}"),
        freezer_value_target_size: 1024,
        freezer_value_compression: compression,
        ordinal_partition: format!("immutable-ordinal-{suffix}"),
        items_per_section: NZU64!(1),
        freezer_key_write_buffer: NZUsize!(1024),
        freezer_value_write_buffer: NZUsize!(1024),
        ordinal_write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024 * 1024),
        codec_config: (),
    }
}

fn ranges(indices: &HashSet<u64>) -> Vec<(u64, u64)> {
    let mut values: Vec<_> = indices.iter().copied().collect();
    values.sort_unstable();

    let mut ranges = Vec::new();
    let mut iter = values.into_iter();
    let Some(first) = iter.next() else {
        return ranges;
    };

    let mut start = first;
    let mut end = first;
    for value in iter {
        if end != u64::MAX && value == end + 1 {
            end = value;
            continue;
        }
        ranges.push((start, end));
        start = value;
        end = value;
    }
    ranges.push((start, end));
    ranges
}

fn missing_items(indices: &HashSet<u64>, start: u64, max: usize) -> Vec<u64> {
    let ranges = ranges(indices);
    let mut current = start;
    let mut missing = Vec::with_capacity(max);

    loop {
        if let Some((_, end)) = ranges
            .iter()
            .find(|(range_start, range_end)| *range_start <= current && current <= *range_end)
        {
            if *end == u64::MAX {
                break missing;
            }
            current = end + 1;
            continue;
        }

        let Some((next_start, _)) = ranges
            .iter()
            .find(|(range_start, _)| *range_start > current)
        else {
            break missing;
        };

        let items_needed = max - missing.len();
        let gap_end = (next_start - 1).min(current.saturating_add(items_needed as u64 - 1));
        for value in current..=gap_end {
            missing.push(value);
        }

        if missing.len() >= max {
            break missing;
        }
        current = *next_start;
    }
}

async fn run_archive<A: ArchiveHarness>(
    context: Context,
    cfg: A::Config,
    operations: &[ArchiveOperation],
) {
    let mut archive = A::init(context.child("storage"), cfg.clone()).await;
    let mut restarts = 0usize;

    // Keep a map of inserted items for verification
    let mut items = Vec::new();

    // Track the oldest allowed index for pruning
    let mut oldest_allowed: Option<u64> = None;

    // Track written indices
    let mut written_indices = HashSet::new();

    for op in operations {
        match op {
            ArchiveOperation::Put {
                index,
                key_data,
                value_data,
            } => {
                let key = Key::new(*key_data);
                let value = Value::new(*value_data);

                // Put the item into the archive
                match archive.put(*index, key, value).await {
                    Ok(()) => {}
                    Err(ArchiveError::AlreadyPrunedTo(pruned_to)) => {
                        assert!(*index < pruned_to);
                        return;
                    }
                    Err(error) => panic!("put failed: {error}"),
                }

                // Only add if not already written (Archive doesn't allow overwrites)
                if !written_indices.contains(index) {
                    items.push((*index, *key_data, *value_data));
                    written_indices.insert(*index);
                }
            }

            ArchiveOperation::PutMulti {
                index,
                key_data,
                value_data,
            } => {
                if !A::SUPPORTS_MULTI {
                    continue;
                }
                let key = Key::new(*key_data);
                let value = Value::new(*value_data);

                match archive.put_multi_harness(*index, key, value).await {
                    Ok(()) => {}
                    Err(ArchiveError::AlreadyPrunedTo(pruned_to)) => {
                        assert!(*index < pruned_to);
                        return;
                    }
                    Err(error) => panic!("put_multi failed: {error}"),
                }
                items.push((*index, *key_data, *value_data));
                written_indices.insert(*index);
            }

            ArchiveOperation::PutMultiSync {
                index,
                key_data,
                value_data,
            } => {
                if !A::SUPPORTS_MULTI {
                    continue;
                }
                let key = Key::new(*key_data);
                let value = Value::new(*value_data);

                match archive.put_multi_sync_harness(*index, key, value).await {
                    Ok(()) => {}
                    Err(ArchiveError::AlreadyPrunedTo(pruned_to)) => {
                        assert!(*index < pruned_to);
                        return;
                    }
                    Err(error) => panic!("put_multi_sync failed: {error}"),
                }
                items.push((*index, *key_data, *value_data));
                written_indices.insert(*index);
            }

            ArchiveOperation::GetByIndex(index) => {
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

            ArchiveOperation::GetAll(index) => {
                if !A::SUPPORTS_MULTI {
                    continue;
                }
                let result = archive
                    .get_all_harness(*index)
                    .await
                    .expect("get_all failed");
                let expected: Vec<_> = items
                    .iter()
                    .filter(|(i, _, _)| *i == *index)
                    .map(|(_, _, value)| *value)
                    .collect();
                match result {
                    Some(values) => {
                        let actual: Vec<RawValue> = values
                            .iter()
                            .map(|value| {
                                let value: &RawValue = value.as_ref().try_into().unwrap();
                                *value
                            })
                            .collect();
                        assert_eq!(actual, expected);
                    }
                    None => {
                        assert!(expected.is_empty());
                    }
                }
            }

            ArchiveOperation::GetByKey(key_data) => {
                let key = Key::new(*key_data);
                let result = archive.get(Identifier::Key(&key)).await;

                if let Ok(Some(value)) = result {
                    // Find all items with this exact key that haven't been pruned
                    let matching_items: Vec<_> = items
                        .iter()
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
                        panic!(
                            "Got value for key {key_data:?} that we didn't insert or was pruned"
                        );
                    }

                    // Convert value to its raw form for comparison
                    let value_bytes: &[u8; 32] = value.as_ref().try_into().unwrap();

                    // Check if the returned value matches ANY of the values we inserted for this key
                    let found_match = matching_items
                        .iter()
                        .any(|(_, _, expected_value)| value_bytes == expected_value);

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

            ArchiveOperation::HasByIndex(index) => {
                let result = archive.has(Identifier::Index(*index)).await;
                if let Ok(has) = result {
                    assert_eq!(has, written_indices.contains(index));
                }
            }

            ArchiveOperation::HasByKey(key_data) => {
                let key = Key::new(*key_data);
                let result = archive.has(Identifier::Key(&key)).await;
                let our_result = items.iter().find(|(_, k, _)| *k == *key);

                // Verify the result against our tracked items
                if let Ok(has) = result {
                    if has {
                        assert!(
                            our_result.is_some(),
                            "stub archive doesn't have key {key_data:?} that we added"
                        );
                    } else {
                        assert!(
                            our_result.is_none(),
                            "Archive doesn't have key {key_data:?} that we added"
                        );
                    }
                }
            }

            ArchiveOperation::Prune(min) => {
                if !A::SUPPORTS_PRUNE {
                    continue;
                }
                let min = min - min % A::items_per_section(&cfg);
                archive.prune_harness(min).await.expect("prune failed");
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

            ArchiveOperation::Restart => {
                archive.sync().await.expect("sync before restart failed");
                drop(archive);
                archive = A::init(
                    context
                        .child("storage")
                        .with_attribute("instance", restarts),
                    cfg.clone(),
                )
                .await;
                restarts += 1;
                oldest_allowed = None;
            }

            ArchiveOperation::Ranges => {
                let actual: Vec<_> = archive.ranges().collect();
                assert_eq!(actual, ranges(&written_indices));
            }

            ArchiveOperation::RangesFrom(from) => {
                let actual: Vec<_> = archive.ranges_from(*from).collect();
                let expected: Vec<_> = ranges(&written_indices)
                    .into_iter()
                    .filter(|(_, end)| end >= from)
                    .collect();
                assert_eq!(actual, expected);
            }

            ArchiveOperation::FirstLastIndex => {
                assert_eq!(archive.first_index(), written_indices.iter().min().copied());
                assert_eq!(archive.last_index(), written_indices.iter().max().copied());
            }

            ArchiveOperation::MissingItems { start, max } => {
                let max = usize::from(*max % 64) + 1;
                assert_eq!(
                    archive.missing_items(*start, max),
                    missing_items(&written_indices, *start, max)
                );
            }

            ArchiveOperation::NextGap { start } => {
                let (gap, next_written) = archive.next_gap(*start);

                if let Some(gap_index) = gap {
                    // Gap should be at or after start
                    assert!(
                        gap_index >= *start,
                        "Gap {gap_index} before requested start {start}"
                    );

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

            ArchiveOperation::Destroy => {
                archive.destroy().await.expect("destroy failed");
                return;
            }
        }
    }

    archive.sync().await.expect("final sync failed");

    let indices_with_items: HashSet<_> = items.iter().map(|(index, _, _)| *index).collect();
    assert_eq!(indices_with_items, written_indices);

    archive.sync().await.expect("Archive sync failed");
}

fn fuzz(data: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(data.raw_bytes)));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| async move {
        match data.archive {
            ArchiveKind::PrunableEight => {
                run_archive::<Prunable<EightCap>>(
                    context.child("prunable_eight"),
                    prunable_cfg(&context, EightCap, "eight", None),
                    &data.operations,
                )
                .await;
            }
            ArchiveKind::PrunableFourCompressed => {
                run_archive::<Prunable<FourCap>>(
                    context.child("prunable_four_compressed"),
                    prunable_cfg(&context, FourCap, "four_compressed", Some(1)),
                    &data.operations,
                )
                .await;
            }
            ArchiveKind::ImmutableCompressed => {
                run_archive::<Immutable>(
                    context.child("immutable_compressed"),
                    immutable_cfg(&context, "compressed", Some(1)),
                    &data.operations,
                )
                .await;
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
