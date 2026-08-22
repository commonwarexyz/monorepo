#![no_main]

//! Prunable archive recovery under supported partial-write crash cuts.
//!
//! Recovery CRC-validates only value suffixes not covered by a durable per-section checkpoint.
//! This target snapshots every synchronous range helper before any asynchronous probe, checks that
//! the snapshot exactly matches the independently decoded readable values, repairs every discovered
//! hole through the public put APIs, and reopens the synced result.

use arbitrary::Arbitrary;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, release_pending_syncs},
};
use commonware_storage::{
    archive::{Archive as _, Identifier, MultiArchive as _, prunable},
    rmap::RMap,
    translator::EightCap,
};
use commonware_utils::{NZU16, NZUsize, Probability, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeSet, num::NonZeroU64};

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type TestArchive = prunable::Archive<EightCap, deterministic::Context, Key, Value>;

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    seed: u64,
    count: u8,
    items_per_section: u8,
    retention: u8,
    subset: bool,
    multi: bool,
    first_probe: u8,
}

#[derive(Clone, Debug)]
struct Entry {
    index: u64,
    key: Key,
    value: Value,
}

fn config(
    context: &impl BufferPooler,
    items_per_section: NonZeroU64,
) -> prunable::Config<EightCap, ()> {
    prunable::Config {
        translator: EightCap,
        key_partition: "archive-recovery-index".into(),
        metadata_partition: "archive-recovery-metadata".into(),
        key_page_cache: CacheRef::from_pooler(context, NZU16!(128), NZUsize!(8)),
        value_partition: "archive-recovery-values".into(),
        compression: None,
        codec_config: (),
        items_per_section,
        key_write_buffer: NZUsize!(4096),
        value_write_buffer: NZUsize!(4096),
        replay_buffer: NZUsize!(4096),
    }
}

fn entries(input: &FuzzInput, items_per_section: u64) -> Vec<Entry> {
    let count = usize::from(input.count % 24) + 1;
    (0..count)
        .map(|id| {
            let id = id as u8;
            let index = if input.multi {
                u64::from(id & 0x03) + u64::from((id >> 2) & 0x01) * items_per_section
            } else {
                u64::from(id)
            };
            let mut key = [0u8; 16];
            // IDs 16 apart reuse both the exact key and (in multi mode) the index. This exercises
            // mixed readable/unreadable occurrences for one exact `(index, key)` pair.
            key[0] = id & 0x03;
            key[8] = (id >> 2) & 0x03;
            Entry {
                index,
                key: Key::new(key),
                value: Value::new([id; 32]),
            }
        })
        .collect()
}

fn replacement(entry: &Entry) -> Entry {
    let id = entry.value.as_ref()[0] ^ 0x80;
    Entry {
        index: entry.index,
        key: entry.key.clone(),
        value: Value::new([id; 32]),
    }
}

fn indices(entries: &[Entry]) -> BTreeSet<u64> {
    entries.iter().map(|entry| entry.index).collect()
}

fn assert_subsequence(actual: &[Value], expected: &[Value], index: u64) {
    let mut cursor = 0;
    for value in actual {
        let Some(relative) = expected[cursor..]
            .iter()
            .position(|candidate| candidate == value)
        else {
            panic!("index {index} returned an unknown or reordered value {value:?}");
        };
        cursor += relative + 1;
    }
}

#[derive(Debug)]
struct RangeSnapshot {
    ranges: Vec<(u64, u64)>,
    first: Option<u64>,
    last: Option<u64>,
    probes: Vec<RangeProbe>,
}

#[derive(Debug)]
struct RangeProbe {
    start: u64,
    ranges: Vec<(u64, u64)>,
    next_gap: (Option<u64>, Option<u64>),
    missing: Vec<u64>,
}

fn snapshot_range_helpers(archive: &TestArchive, candidates: &BTreeSet<u64>) -> RangeSnapshot {
    let mut starts = BTreeSet::from([0]);
    for &index in candidates {
        starts.insert(index);
        if let Some(next) = index.checked_add(1) {
            starts.insert(next);
        }
    }
    let probes = starts
        .into_iter()
        .map(|start| RangeProbe {
            start,
            ranges: archive.ranges_from(start).collect(),
            next_gap: archive.next_gap(start),
            missing: archive.missing_items(start, 8),
        })
        .collect();
    RangeSnapshot {
        ranges: archive.ranges().collect(),
        first: archive.first_index(),
        last: archive.last_index(),
        probes,
    }
}

fn snapshot_indexed_helpers(archive: &TestArchive, candidates: &BTreeSet<u64>) -> RangeSnapshot {
    let mut starts = BTreeSet::from([0]);
    for &index in candidates {
        starts.insert(index);
        if let Some(next) = index.checked_add(1) {
            starts.insert(next);
        }
    }
    let ranges: Vec<_> = archive.indexed_ranges_from(0).collect();
    let probes = starts
        .into_iter()
        .map(|start| RangeProbe {
            start,
            ranges: archive.indexed_ranges_from(start).collect(),
            next_gap: archive.indexed_next_gap(start),
            missing: archive.indexed_missing_items(start, 8),
        })
        .collect();
    RangeSnapshot {
        first: ranges.first().map(|(start, _)| *start),
        last: archive.indexed_last_index(),
        ranges,
        probes,
    }
}

fn assert_range_snapshot(snapshot: &RangeSnapshot, expected: &BTreeSet<u64>) {
    let mut model = RMap::new();
    for &index in expected {
        model.insert(index);
    }
    let expected_ranges: Vec<_> = model.iter().map(|(&start, &end)| (start, end)).collect();
    let mut actual = BTreeSet::new();
    for &(start, end) in &snapshot.ranges {
        assert!(start <= end);
        assert!(
            end < 64,
            "archive exposed an unmodeled index range {start}..={end}"
        );
        actual.extend(start..=end);
    }
    assert_eq!(snapshot.ranges, expected_ranges);
    assert_eq!(
        &actual, expected,
        "range metadata disagrees with readable values"
    );

    assert_eq!(snapshot.first, model.first_index());
    assert_eq!(snapshot.last, model.last_index());
    for probe in &snapshot.probes {
        let expected_from: Vec<_> = model
            .iter_from(probe.start)
            .map(|(&range_start, &range_end)| (range_start, range_end))
            .collect();
        assert_eq!(probe.ranges, expected_from);
        assert_eq!(probe.next_gap, model.next_gap(probe.start));
        assert_eq!(probe.missing, model.missing_items(probe.start, 8));
    }
}

fn assert_range_helpers(archive: &TestArchive, expected: &BTreeSet<u64>) {
    assert_range_snapshot(&snapshot_range_helpers(archive, expected), expected);
}

fn indexed_indices(snapshot: &RangeSnapshot) -> BTreeSet<u64> {
    let mut indices = BTreeSet::new();
    for &(start, end) in &snapshot.ranges {
        assert!(start <= end);
        assert!(
            end < 64,
            "archive exposed an unmodeled indexed range {start}..={end}"
        );
        indices.extend(start..=end);
    }
    indices
}

fn assert_indexed_snapshot(
    snapshot: &RangeSnapshot,
    intended: &BTreeSet<u64>,
    readable: &BTreeSet<u64>,
) -> BTreeSet<u64> {
    let indexed = indexed_indices(snapshot);
    assert_range_snapshot(snapshot, &indexed);
    assert!(
        readable.is_subset(&indexed),
        "a readable value is missing from the physical index view"
    );
    assert!(
        indexed.is_subset(intended),
        "the physical index view exposed an unintended index"
    );
    indexed
}

fn assert_indexed_helpers(archive: &TestArchive, expected: &BTreeSet<u64>) {
    let snapshot = snapshot_indexed_helpers(archive, expected);
    let indexed = assert_indexed_snapshot(&snapshot, expected, expected);
    assert_eq!(&indexed, expected);
}

async fn collect_readable(
    archive: &TestArchive,
    intended: &[Entry],
    first_probe: u8,
) -> Vec<Entry> {
    let mut readable = Vec::new();
    for index in indices(intended) {
        let expected: Vec<_> = intended
            .iter()
            .filter(|entry| entry.index == index)
            .map(|entry| entry.value.clone())
            .collect();
        let probed_index = if first_probe % 3 == 1 {
            Some(archive.get(Identifier::Index(index)).await.unwrap())
        } else {
            None
        };
        if first_probe % 3 == 2 {
            let mut keys = Vec::new();
            for entry in intended.iter().filter(|entry| entry.index == index) {
                if keys.contains(&entry.key) {
                    continue;
                }
                keys.push(entry.key.clone());
                if let Some(value) = archive.get(Identifier::Key(&entry.key)).await.unwrap() {
                    assert!(
                        intended
                            .iter()
                            .any(|candidate| candidate.key == entry.key && candidate.value == value),
                        "key-first probe returned an unauthentic value",
                    );
                }
            }
        }
        let actual = archive
            .get_all(index)
            .await
            .unwrap_or_else(|err| panic!("get_all({index}) failed after recovery: {err:?}"))
            .unwrap_or_default();
        assert_subsequence(&actual, &expected, index);
        if let Some(probed) = probed_index {
            assert_eq!(probed, actual.first().cloned());
        }
        assert_eq!(
            archive.get(Identifier::Index(index)).await.unwrap(),
            actual.first().cloned(),
        );

        let mut checked_keys = Vec::new();
        for entry in intended.iter().filter(|entry| entry.index == index) {
            let present = actual.iter().any(|value| value == &entry.value);
            if present {
                readable.push(entry.clone());
            }
            if checked_keys.contains(&entry.key) {
                continue;
            }
            checked_keys.push(entry.key.clone());
            let key_present = intended.iter().any(|candidate| {
                candidate.index == index
                    && candidate.key == entry.key
                    && actual.contains(&candidate.value)
            });
            assert_eq!(
                archive.has_at(index, &entry.key).await.unwrap(),
                key_present,
            );
        }
        assert_eq!(
            archive.has(Identifier::Index(index)).await.unwrap(),
            !actual.is_empty(),
        );
    }

    let readable_indices = indices(&readable);
    assert_range_helpers(archive, &readable_indices);
    for entry in intended {
        let expected: Vec<_> = readable
            .iter()
            .filter(|candidate| candidate.key == entry.key)
            .map(|candidate| candidate.value.clone())
            .collect();
        let actual = archive.get(Identifier::Key(&entry.key)).await.unwrap();
        assert_eq!(
            archive.has(Identifier::Key(&entry.key)).await.unwrap(),
            !expected.is_empty()
        );
        match actual {
            Some(value) => assert!(expected.contains(&value)),
            None => assert!(expected.is_empty()),
        }
    }
    readable
}

async fn assert_exact(archive: &TestArchive, expected: &[Entry]) {
    for index in indices(expected) {
        let values: Vec<_> = expected
            .iter()
            .filter(|entry| entry.index == index)
            .map(|entry| entry.value.clone())
            .collect();
        assert_eq!(archive.get_all(index).await.unwrap(), Some(values.clone()));
        assert_eq!(
            archive.get(Identifier::Index(index)).await.unwrap(),
            values.first().cloned(),
        );
        assert!(archive.has(Identifier::Index(index)).await.unwrap());
        for entry in expected.iter().filter(|entry| entry.index == index) {
            assert!(archive.has_at(index, &entry.key).await.unwrap());
        }
    }
    let expected_indices = indices(expected);
    assert_range_helpers(archive, &expected_indices);
    assert_indexed_helpers(archive, &expected_indices);
    for entry in expected {
        let actual = archive
            .get(Identifier::Key(&entry.key))
            .await
            .unwrap()
            .expect("readable key is missing");
        assert!(
            expected
                .iter()
                .any(|candidate| candidate.key == entry.key && candidate.value == actual)
        );
    }
}

fn fuzz(input: FuzzInput) {
    let items_per_section = NonZeroU64::new(u64::from(input.items_per_section % 8) + 1).unwrap();
    let intended = entries(&input, items_per_section.get());
    let baseline_count = intended.len() / 2;
    let baseline = intended[..baseline_count].to_vec();
    let first_phase_entries = intended.clone();
    let first_phase_input = input.clone();
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let (_, checkpoint) = runner.start_and_recover(move |context| async move {
        let fault_config = context.storage_fault_config();
        let pending = PendingSyncs::default();
        let context = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };
        let cfg = config(&context, items_per_section);
        let mut archive =
            prunable::Archive::<EightCap, _, Key, Value>::init(context.child("archive"), cfg)
                .await
                .expect("initial archive init failed");
        for (offset, entry) in first_phase_entries.into_iter().enumerate() {
            if offset == baseline_count && baseline_count > 0 {
                let handle;
                (archive, handle) = archive
                    .start_sync()
                    .await
                    .expect("baseline start_sync failed");
                assert!(!pending.lock().is_empty(), "baseline syncs must be held");
                release_pending_syncs(&pending);
                handle.await.expect("baseline sync failed");
            }
            archive = if first_phase_input.multi {
                archive
                    .put_multi(entry.index, entry.key, entry.value)
                    .await
                    .expect("put_multi failed")
            } else {
                archive
                    .put(entry.index, entry.key, entry.value)
                    .await
                    .expect("put failed")
            };
        }

        // Hold both durability barriers open after their buffered writes have reached storage.
        // The checkpoint can then retain independent byte subsets from the index and value
        // journals, including an authenticated index entry whose value frame has a bad CRC.
        *fault_config.write() = deterministic::FaultConfig {
            write_rate: Some(WriteConfig {
                failure_rate: Probability::new(0, 1).unwrap(),
                retention_rate: Probability::new(
                    900 + u64::from(first_phase_input.retention % 101),
                    1000,
                )
                .unwrap(),
                mode: if first_phase_input.subset {
                    PartialWriteMode::Subset
                } else {
                    PartialWriteMode::Prefix
                },
            }),
            ..Default::default()
        };
        let (archive, handle) = archive.start_sync().await.expect("start_sync failed");
        assert!(
            !pending.lock().is_empty(),
            "faulted journal syncs must be held"
        );
        drop(handle);
        drop(archive);
    });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let cfg = config(&context, items_per_section);
        let mut archive = TestArchive::init(context.child("archive"), cfg.clone())
            .await
            .expect("archive recovery failed");
        let mut intended = intended;

        // Capture synchronous metadata before any async method can participate in the oracle. The
        // subsequent decoded values determine the expected set independently of this snapshot.
        let intended_indices = indices(&intended);
        let startup_ranges = snapshot_range_helpers(&archive, &intended_indices);
        let startup_indexed = snapshot_indexed_helpers(&archive, &intended_indices);
        let mut expected = collect_readable(&archive, &intended, input.first_probe).await;
        let readable_indices = indices(&expected);
        assert_range_snapshot(&startup_ranges, &readable_indices);
        let indexed =
            assert_indexed_snapshot(&startup_indexed, &intended_indices, &readable_indices);
        assert!(
            indices(&baseline).is_subset(&indexed),
            "a synchronized index occurrence was lost",
        );
        for entry in &baseline {
            assert!(
                expected
                    .iter()
                    .any(|candidate| candidate.value == entry.value),
                "a value from the synchronized baseline was lost",
            );
        }
        if input.retention % 101 == 100 {
            assert_exact(&archive, &intended).await;
        }

        // For single-item archives, one retransmission must either preserve the existing readable
        // value or install a replacement for an invalid occurrence.
        if !input.multi {
            let first_unsynced = baseline_count.min(intended.len() - 1);
            let target =
                first_unsynced + usize::from(input.first_probe) % (intended.len() - first_unsynced);
            let repair = replacement(&intended[target]);
            archive = archive
                .put(repair.index, repair.key.clone(), repair.value.clone())
                .await
                .expect("first-operation retransmission failed");
            let value = archive
                .get(Identifier::Index(repair.index))
                .await
                .expect("first-operation retransmission read failed")
                .expect("one retransmission must leave a readable value");
            if value == repair.value {
                expected.retain(|entry| entry.index != repair.index);
                expected.push(repair.clone());
                intended[target] = repair;
            } else {
                assert_eq!(
                    value, intended[target].value,
                    "retransmission exposed an unauthentic value"
                );
            }
            assert_range_helpers(&archive, &indices(&expected));
        }

        for entry in &intended {
            if expected
                .iter()
                .any(|candidate| candidate.value == entry.value)
            {
                continue;
            }
            let repair = replacement(entry);
            archive = if input.multi {
                archive
                    .put_multi(repair.index, repair.key.clone(), repair.value.clone())
                    .await
                    .expect("put_multi repair failed")
            } else {
                archive
                    .put(repair.index, repair.key.clone(), repair.value.clone())
                    .await
                    .expect("put repair failed")
            };
            expected.push(repair);
        }

        assert_exact(&archive, &expected).await;
        archive = archive.sync().await.expect("repair sync failed");
        drop(archive);

        let archive = TestArchive::init(context.child("reopen"), cfg)
            .await
            .expect("reopen after repair failed");
        assert_exact(&archive, &expected).await;
        archive.destroy().await.expect("destroy failed");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
