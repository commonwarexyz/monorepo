#![no_main]

//! Prunable archive recovery under supported partial-write crash cuts.
//!
//! Recovery CRC-validates only value suffixes not covered by a durable per-section boundary.
//! This target reconstructs the expected prefix directly from the raw index and value crash image
//! before opening the archive, checks every public read and range helper, restarts before
//! repairing truncated suffixes, and reopens the synced result.

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt as _, FixedSize, Read, ReadExt as _};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, Buf, BufferPooler, ReadOptions, Runner, Storage as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, release_pending_syncs},
};
use commonware_storage::{
    archive::{Archive as _, Identifier, MultiArchive as _, prunable},
    rmap::RMap,
    translator::EightCap,
};
use commonware_utils::{NZUsize, Probability, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU64},
};

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type TestArchive = prunable::Archive<EightCap, deterministic::Context, Key, Value>;

const INDEX_PAGE_SIZE: usize = 128;
const PAGE_CHECKSUM_RECORD_SIZE: usize = 12;
const VALUE_CHECKSUM_SIZE: usize = 4;

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    seed: u64,
    count: u8,
    items_per_section: u8,
    retention: u8,
    subset: bool,
    multi: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    index: u64,
    key: Key,
    value: Value,
}

struct IndexRecord {
    index: u64,
    key: Key,
    value_offset: u64,
    value_size: u32,
}

impl Read for IndexRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            index: u64::read(buf)?,
            key: Key::read(buf)?,
            value_offset: u64::read(buf)?,
            value_size: u32::read(buf)?,
        })
    }
}

impl FixedSize for IndexRecord {
    const SIZE: usize = u64::SIZE + Key::SIZE + u64::SIZE + u32::SIZE;
}

fn config(
    context: &impl BufferPooler,
    items_per_section: NonZeroU64,
) -> prunable::Config<EightCap, ()> {
    prunable::Config {
        translator: EightCap,
        metadata_partition: "archive-recovery-metadata".into(),
        key_partition: "archive-recovery-index".into(),
        key_page_cache: CacheRef::from_pooler(
            context,
            NonZeroU16::new(INDEX_PAGE_SIZE as u16).unwrap(),
            NZUsize!(8),
        ),
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
            // IDs 16 apart reuse both the exact key and, in multi mode, the index.
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

fn indices(entries: &[Entry]) -> BTreeSet<u64> {
    entries.iter().map(|entry| entry.index).collect()
}

async fn read_value(
    context: &deterministic::Context,
    partition: &str,
    section: u64,
    record: &IndexRecord,
) -> Option<Value> {
    let size = usize::try_from(record.value_size).ok()?;
    if size < VALUE_CHECKSUM_SIZE {
        return None;
    }
    let end = record
        .value_offset
        .checked_add(u64::from(record.value_size))?;
    let (blob, blob_size) = context.open(partition, &section.to_be_bytes()).await.ok()?;
    if end > blob_size {
        return None;
    }
    let frame = blob
        .read_at(record.value_offset, size, ReadOptions::default())
        .await
        .ok()?
        .coalesce();
    let data_len = size - VALUE_CHECKSUM_SIZE;
    let stored = u32::from_be_bytes(frame.as_ref()[data_len..].try_into().ok()?);
    if Crc32::checksum(&frame.as_ref()[..data_len]) != stored {
        return None;
    }
    Value::decode(&frame.as_ref()[..data_len]).ok()
}

/// Select a page's authoritative checksum slot, falling back to the other slot if a write tore.
fn valid_page_len(page: &[u8]) -> Option<usize> {
    let footer = page.get(INDEX_PAGE_SIZE..)?;
    if footer.len() != PAGE_CHECKSUM_RECORD_SIZE {
        return None;
    }
    let slots = [
        (
            u16::from_be_bytes(footer[0..2].try_into().unwrap()) as usize,
            u32::from_be_bytes(footer[2..6].try_into().unwrap()),
        ),
        (
            u16::from_be_bytes(footer[6..8].try_into().unwrap()) as usize,
            u32::from_be_bytes(footer[8..12].try_into().unwrap()),
        ),
    ];
    let authoritative = usize::from(slots[1].0 > slots[0].0);
    for slot in [authoritative, authoritative ^ 1] {
        let (len, checksum) = slots[slot];
        if len > 0 && len <= INDEX_PAGE_SIZE && Crc32::checksum(&page[..len]) == checksum {
            return Some(len);
        }
    }
    None
}

/// Decode the contiguous, whole-record prefix of each raw index section without repairing it.
async fn read_index_sections(
    context: &deterministic::Context,
    partition: &str,
) -> BTreeMap<u64, Vec<IndexRecord>> {
    let physical_page_size = INDEX_PAGE_SIZE + PAGE_CHECKSUM_RECORD_SIZE;
    let mut sections = BTreeMap::new();
    for name in context
        .scan(partition)
        .await
        .expect("oracle index scan failed")
    {
        let section = u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
        let (blob, size) = context
            .open(partition, &name)
            .await
            .expect("oracle index open failed");
        let pages = usize::try_from(size).expect("oracle index size overflow") / physical_page_size;
        let mut logical = Vec::with_capacity(pages * INDEX_PAGE_SIZE);
        for page in 0..pages {
            let physical = blob
                .read_at(
                    (page * physical_page_size) as u64,
                    physical_page_size,
                    ReadOptions::default(),
                )
                .await
                .expect("oracle index read failed")
                .coalesce();
            let Some(len) = valid_page_len(physical.as_ref()) else {
                break;
            };
            logical.extend_from_slice(&physical.as_ref()[..len]);
            if len < INDEX_PAGE_SIZE {
                break;
            }
        }
        logical.truncate(logical.len() - logical.len() % IndexRecord::SIZE);
        let records = logical
            .chunks_exact(IndexRecord::SIZE)
            .map(|record| IndexRecord::decode(record).expect("oracle index record failed"))
            .collect();
        sections.insert(section, records);
    }
    sections
}

async fn recover_expected(
    context: &deterministic::Context,
    cfg: &prunable::Config<EightCap, ()>,
    intended: &[Entry],
) -> (Vec<Entry>, BTreeMap<u64, u64>) {
    let sections = read_index_sections(context, &cfg.key_partition).await;
    let mut value_sizes: BTreeMap<_, _> = sections.keys().map(|&section| (section, 0)).collect();
    let mut expected = Vec::new();
    for (section, records) in sections {
        for record in records {
            let Some(value) = read_value(context, &cfg.value_partition, section, &record).await
            else {
                break;
            };
            let value_end = record
                .value_offset
                .checked_add(u64::from(record.value_size))
                .expect("oracle value end overflow");
            let entry = Entry {
                index: record.index,
                key: record.key,
                value,
            };
            assert!(
                intended.contains(&entry),
                "crash image contains an unauthentic CRC-valid entry {entry:?}"
            );
            value_sizes.insert(section, value_end);
            expected.push(entry);
        }
    }
    (expected, value_sizes)
}

async fn assert_value_sizes(
    context: &deterministic::Context,
    partition: &str,
    expected: &BTreeMap<u64, u64>,
) {
    let mut actual = BTreeMap::new();
    for name in context.scan(partition).await.expect("value scan failed") {
        let section = u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
        let (_, size) = context
            .open(partition, &name)
            .await
            .expect("value section open failed");
        actual.insert(section, size);
    }
    assert_eq!(
        &actual, expected,
        "archive recovery left unindexed or trailing value bytes"
    );
}

fn assert_range_helpers(
    archive: &TestArchive,
    candidates: &BTreeSet<u64>,
    expected: &BTreeSet<u64>,
) {
    let mut model = RMap::new();
    for &index in expected {
        model.insert(index);
    }
    let expected_ranges: Vec<_> = model.iter().map(|(&start, &end)| (start, end)).collect();
    let ranges: Vec<_> = archive.ranges().collect();
    let mut actual = BTreeSet::new();
    for &(start, end) in &ranges {
        assert!(start <= end);
        assert!(
            end < 64,
            "archive exposed an unmodeled index range {start}..={end}"
        );
        actual.extend(start..=end);
    }
    assert_eq!(ranges, expected_ranges);
    assert_eq!(
        &actual, expected,
        "range metadata disagrees with retained values"
    );

    assert_eq!(archive.first_index(), model.first_index());
    assert_eq!(archive.last_index(), model.last_index());
    let mut starts = BTreeSet::from([0]);
    for &index in candidates {
        starts.insert(index);
        if let Some(next) = index.checked_add(1) {
            starts.insert(next);
        }
    }
    for start in starts {
        let expected_from: Vec<_> = model
            .iter_from(start)
            .map(|(&range_start, &range_end)| (range_start, range_end))
            .collect();
        assert_eq!(
            archive.ranges_from(start).collect::<Vec<_>>(),
            expected_from
        );
        assert_eq!(archive.next_gap(start), model.next_gap(start));
        assert_eq!(
            archive.missing_items(start, 8),
            model.missing_items(start, 8)
        );
    }
}

async fn assert_view(archive: &TestArchive, intended: &[Entry], expected: &[Entry]) {
    let intended_indices = indices(intended);
    for &index in &intended_indices {
        let values: Vec<_> = expected
            .iter()
            .filter(|entry| entry.index == index)
            .map(|entry| entry.value.clone())
            .collect();
        assert_eq!(
            archive.get_all(index).await.unwrap(),
            (!values.is_empty()).then_some(values.clone()),
        );
        assert_eq!(
            archive.get(Identifier::Index(index)).await.unwrap(),
            values.first().cloned(),
        );
        assert_eq!(
            archive.has(Identifier::Index(index)).await.unwrap(),
            !values.is_empty(),
        );

        let mut checked_keys = Vec::new();
        for entry in intended.iter().filter(|entry| entry.index == index) {
            if checked_keys.contains(&entry.key) {
                continue;
            }
            checked_keys.push(entry.key.clone());
            let present = expected
                .iter()
                .any(|candidate| candidate.index == index && candidate.key == entry.key);
            assert_eq!(archive.has_at(index, &entry.key).await.unwrap(), present);
        }
    }

    assert_range_helpers(archive, &intended_indices, &indices(expected));
    let mut checked_keys = Vec::new();
    for entry in intended {
        if checked_keys.contains(&entry.key) {
            continue;
        }
        checked_keys.push(entry.key.clone());
        let values: Vec<_> = expected
            .iter()
            .filter(|candidate| candidate.key == entry.key)
            .map(|candidate| candidate.value.clone())
            .collect();
        let actual = archive.get(Identifier::Key(&entry.key)).await.unwrap();
        assert_eq!(
            archive.has(Identifier::Key(&entry.key)).await.unwrap(),
            !values.is_empty(),
        );
        match actual {
            Some(value) => assert!(values.contains(&value)),
            None => assert!(values.is_empty()),
        }
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
        // The crash image can then retain independent byte subsets from the index and value
        // journals, including a retained index entry whose value frame has a bad CRC.
        *fault_config.write() = deterministic::FaultConfig {
            write_rate: Some(WriteConfig {
                failure_rate: Probability::new(0, 1).unwrap(),
                retention_rate: Probability::new(u64::from(first_phase_input.retention % 101), 100)
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

    let recovery_intended = intended.clone();
    let recovery_baseline = baseline.clone();
    let recovery_input = input.clone();
    let ((expected, expected_value_sizes), checkpoint) = deterministic::Runner::from(checkpoint)
        .start_and_recover(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let cfg = config(&context, items_per_section);
            let (expected, expected_value_sizes) =
                recover_expected(&context, &cfg, &recovery_intended).await;
            let archive = TestArchive::init(context.child("archive"), cfg.clone())
                .await
                .expect("archive recovery failed");

            for entry in &recovery_baseline {
                assert!(
                    expected.contains(entry),
                    "a value from the synchronized baseline was lost",
                );
            }
            if recovery_input.retention % 101 == 100 {
                assert_eq!(
                    expected.len(),
                    recovery_intended.len(),
                    "a fully retained extension lost an entry",
                );
                assert!(
                    recovery_intended
                        .iter()
                        .all(|entry| expected.contains(entry)),
                    "a fully retained extension changed an entry"
                );
            }
            assert_view(&archive, &recovery_intended, &expected).await;
            assert_value_sizes(&context, &cfg.value_partition, &expected_value_sizes).await;
            drop(archive);
            (expected, expected_value_sizes)
        });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let cfg = config(&context, items_per_section);
        let mut archive = TestArchive::init(context.child("archive"), cfg.clone())
            .await
            .expect("second recovery failed");

        assert_view(&archive, &intended, &expected).await;
        assert_value_sizes(&context, &cfg.value_partition, &expected_value_sizes).await;

        for entry in &intended {
            if expected.contains(entry) {
                continue;
            }
            archive = if input.multi {
                archive
                    .put_multi(entry.index, entry.key.clone(), entry.value.clone())
                    .await
                    .expect("put_multi repair failed")
            } else {
                archive
                    .put(entry.index, entry.key.clone(), entry.value.clone())
                    .await
                    .expect("put repair failed")
            };
        }

        assert_view(&archive, &intended, &intended).await;
        archive = archive.sync().await.expect("repair sync failed");
        drop(archive);

        let archive = TestArchive::init(context.child("reopen"), cfg)
            .await
            .expect("reopen after repair failed");
        assert_view(&archive, &intended, &intended).await;
        archive.destroy().await.expect("destroy failed");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
