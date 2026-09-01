#![no_main]

//! Prunable archive recovery under supported partial-write crash cuts.
//!
//! The op phase pipelines start_sync requests whose completions stay parked until an op
//! releases them, drives prunes with remove faults armed so a prune can fail between the
//! index and value section removals, and optionally appends through put_multi with repeated
//! indices. The faulted crash takes one of three shapes: an abandoned sync request, an
//! interrupted blocking sync, or an interrupted prune. The oracle reconstructs the retained
//! entries and repaired section sizes from the raw crash image (recover_expected), asserts
//! every entry covered by a completed sync survived, checks the recovered index and value
//! blob sizes exactly, then repairs the archive and proves the full view survives a sync
//! and reopen.

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt as _, FixedSize, Read, ReadExt as _};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, Buf, BufferPooler, Handle, ReadOptions, Runner, Storage as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, release_pending_syncs},
};
use commonware_storage::{
    archive::{Archive as _, Identifier, MultiArchive as _, prunable},
    rmap::RMap,
    translator::EightCap,
};
use commonware_storage_fuzz::{
    bounded_entropy, faulted_recovery, poll_interrupted, valid_page_len,
};
use commonware_utils::{FuzzRng, NZUsize, Probability, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU64},
};

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type TestArchive = prunable::Archive<EightCap, deterministic::Context, Key, Value>;

const INDEX_PAGE_SIZE: usize = 128;
const PAGE_CHECKSUM_RECORD_SIZE: usize = commonware_runtime::buffer::paged::CHECKSUM_SIZE as usize;
const VALUE_CHECKSUM_SIZE: usize = 4;

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    /// Number of entries to append (1..=24).
    count: u8,
    /// Entries per section (1..=8).
    items_per_section: u8,
    /// Crash retention rate (percent) for unsynced bytes.
    retention: u8,
    /// Partial-write mode: Subset when set, Prefix otherwise.
    subset: bool,
    /// Use put_multi with repeated indices instead of put.
    multi: bool,
    /// Per-entry action applied after its put: pipeline a sync, release one held completion,
    /// settle everything held, or prune.
    ops: [u8; 24],
    /// Shape of the faulted crash: an abandoned sync request, an interrupted blocking sync,
    /// or an interrupted prune.
    final_op: u8,
    /// Remove failure rate (percent) armed around every prune, sampled per section-blob
    /// removal so a prune can fail after removing an index section but before its value
    /// section, leaving an orphan value section for recovery to clean.
    remove_failure: u8,
    /// Byte stream driving the runtime rng: all in-run randomness, fault sampling, and the
    /// faulted recovery chain's depth and shapes.
    #[arbitrary(with = bounded_entropy)]
    entropy: Vec<u8>,
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

/// Build the prunable archive configuration used by this target.
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

/// Generate the append stream, including repeated indices in multi-value mode.
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

            // IDs 16 apart reuse both the exact key and, in multi mode, the index.
            let mut key = [0u8; 16];
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

/// Return the distinct indices represented by `entries`.
fn indices(entries: &[Entry]) -> BTreeSet<u64> {
    entries.iter().map(|entry| entry.index).collect()
}

/// Read and validate a value frame, returning `None` when the frame is not recoverable.
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
    // The value blob is created before any index bytes can exist, and reads are never
    // fault-injected, so open and read failures here are real bugs, not crash shapes.
    let (blob, blob_size) = context
        .open(partition, &section.to_be_bytes())
        .await
        .expect("oracle value open failed");
    if end > blob_size {
        return None;
    }
    let frame = blob
        .read_at(record.value_offset, size, ReadOptions::default())
        .await
        .expect("oracle value read failed")
        .coalesce();
    let data_len = size - VALUE_CHECKSUM_SIZE;
    let stored = u32::from_be_bytes(frame.as_ref()[data_len..].try_into().ok()?);
    if Crc32::checksum(&frame.as_ref()[..data_len]) != stored {
        return None;
    }
    Value::decode(&frame.as_ref()[..data_len]).ok()
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
            let Some(len) = valid_page_len(physical.as_ref(), INDEX_PAGE_SIZE) else {
                break;
            };
            logical.extend_from_slice(&physical.as_ref()[..len]);
            if len < INDEX_PAGE_SIZE {
                break;
            }
        }
        logical.truncate(logical.len() - logical.len() % IndexRecord::SIZE);
        let records = logical
            .as_chunks::<{ IndexRecord::SIZE }>()
            .0
            .iter()
            .map(|record| IndexRecord::decode(&record[..]).expect("oracle index record failed"))
            .collect();
        sections.insert(section, records);
    }
    sections
}

/// Reconstruct retained entries and repaired section sizes from the raw crash image.
async fn recover_expected(
    context: &deterministic::Context,
    cfg: &prunable::Config<EightCap, ()>,
    intended: &[Entry],
) -> (Vec<Entry>, BTreeMap<u64, u64>, BTreeMap<u64, u64>) {
    let sections = read_index_sections(context, &cfg.key_partition).await;
    let mut index_sizes: BTreeMap<_, _> = sections.keys().map(|&section| (section, 0)).collect();
    let mut value_sizes: BTreeMap<_, _> = sections.keys().map(|&section| (section, 0)).collect();
    let mut expected = Vec::new();
    for (section, records) in sections {
        let mut retained = 0usize;
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
            retained += 1;
        }
        let logical_size = retained * IndexRecord::SIZE;
        let physical_size =
            logical_size.div_ceil(INDEX_PAGE_SIZE) * (INDEX_PAGE_SIZE + PAGE_CHECKSUM_RECORD_SIZE);
        index_sizes.insert(section, physical_size as u64);
    }
    (expected, index_sizes, value_sizes)
}

/// Assert each partition's section sizes match the recovery oracle.
async fn assert_blob_sizes(
    context: &deterministic::Context,
    partition: &str,
    expected: &BTreeMap<u64, u64>,
    kind: &str,
) {
    let mut actual = BTreeMap::new();
    for name in context.scan(partition).await.expect("blob scan failed") {
        let section = u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
        let (_, size) = context
            .open(partition, &name)
            .await
            .expect("blob section open failed");
        actual.insert(section, size);
    }
    assert_eq!(
        &actual, expected,
        "archive recovery left trailing or missing {kind} bytes"
    );
}

/// Compare range, gap, and missing-item helpers with the expected index set.
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
        assert!(start <= end, "archive exposed an inverted index range");
        assert!(
            end < 64,
            "archive exposed an unmodeled index range {start}..={end}"
        );
        actual.extend(start..=end);
    }
    assert_eq!(
        ranges, expected_ranges,
        "range iteration disagrees with the expected index set"
    );
    assert_eq!(
        &actual, expected,
        "range metadata disagrees with retained values"
    );

    assert_eq!(
        archive.first_index(),
        model.first_index(),
        "first_index disagrees with the expected index set"
    );
    assert_eq!(
        archive.last_index(),
        model.last_index(),
        "last_index disagrees with the expected index set"
    );
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
            expected_from,
            "ranges_from disagrees with the expected index set"
        );
        assert_eq!(
            archive.next_gap(start),
            model.next_gap(start),
            "next_gap disagrees with the expected index set"
        );
        assert_eq!(
            archive.missing_items(start, 8),
            model.missing_items(start, 8),
            "missing_items disagrees with the expected index set"
        );
    }
}

/// Compare index, key, value, and range views with the expected entries.
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
            "get_all disagrees with the retained entries"
        );
        assert_eq!(
            archive.get(Identifier::Index(index)).await.unwrap(),
            values.first().cloned(),
            "get by index disagrees with the retained entries"
        );
        assert_eq!(
            archive.has(Identifier::Index(index)).await.unwrap(),
            !values.is_empty(),
            "has by index disagrees with the retained entries"
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
            assert_eq!(
                archive.has_at(index, &entry.key).await.unwrap(),
                present,
                "has_at disagrees with the retained entries"
            );
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
            "has by key disagrees with the retained entries"
        );
        match actual {
            Some(value) => assert!(
                values.contains(&value),
                "get by key returned a value not among the retained entries"
            ),
            None => assert!(
                values.is_empty(),
                "get by key returned nothing while entries are retained"
            ),
        }
    }
}

/// Run the archive through faulted appends, recovery, and tail repair.
fn fuzz(input: FuzzInput) {
    let items_per_section = NonZeroU64::new(u64::from(input.items_per_section % 8) + 1).unwrap();
    let retention_percent = input.retention % 101;
    let final_op = input.final_op;
    let intended = entries(&input, items_per_section.get());
    let baseline_count = intended.len() / 2;
    let first_phase_entries = intended.clone();
    let first_phase_input = input.clone();
    let cfg =
        deterministic::Config::default().with_rng(Box::new(FuzzRng::new(input.entropy.clone())));
    let runner = deterministic::Runner::new(cfg);
    let ((durable, exempt_below, pruned), checkpoint) =
        runner.start_and_recover(move |context| async move {
            let fault_config = context.storage_fault_config();
            let remove_rate =
                Probability::new(u64::from(first_phase_input.remove_failure) % 101, 100).unwrap();
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
            let mut held: Vec<(usize, Handle<()>)> = Vec::new();
            let mut durable = 0usize;
            let total = first_phase_entries.len();
            let mut exempt_below = 0u64;
            let mut pruned = false;
            for (offset, entry) in first_phase_entries.into_iter().enumerate() {
                if offset == baseline_count && baseline_count > 0 {
                    // A prior pipelined request may still hold this section's fsync open, and
                    // the writer awaits it before starting another sync.
                    release_pending_syncs(&pending);
                    let handle;
                    (archive, handle) = archive
                        .start_sync()
                        .await
                        .expect("baseline start_sync failed");
                    release_pending_syncs(&pending);
                    handle.await.expect("baseline sync failed");
                    durable = durable.max(offset);
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

                // Every sync completion below stays parked until an op resolves it, so requests
                // pipeline and marker generations observe completions in op-chosen order.
                let op = first_phase_input.ops[offset % first_phase_input.ops.len()];
                match op & 0x07 {
                    1 => {
                        // Release (without observing) any parked completions so the new
                        // request cannot block on a prior fsync of the same section.
                        // Completions resolve out of order and stay unobserved until a later
                        // request polls them.
                        release_pending_syncs(&pending);
                        let handle;
                        (archive, handle) = archive
                            .start_sync()
                            .await
                            .expect("pipelined start_sync failed");
                        held.push((offset + 1, handle));
                    }
                    2 => {
                        let mut parked = pending.lock();
                        if !parked.is_empty() {
                            let idx = usize::from(op >> 3) % parked.len();
                            let sync = parked.remove(idx);
                            let _ = sync.release.send(Ok(()));
                        }
                    }
                    3 => {
                        release_pending_syncs(&pending);
                        for (covered, handle) in held.drain(..) {
                            handle.await.expect("pipelined sync failed");
                            durable = durable.max(covered);
                        }
                    }
                    4 => {
                        // Settle held pipelines first: a no-op prune completes without
                        // stalling, so the drive below may never release their completions.
                        release_pending_syncs(&pending);
                        for (covered, handle) in held.drain(..) {
                            handle.await.expect("pipelined sync failed");
                            durable = durable.max(covered);
                        }

                        // The archive rounds prune requests down to a section boundary, so only
                        // indices below that boundary can actually disappear. Input-driven
                        // remove faults can fail the prune partway, leaving an index section
                        // deleted while its value section survives, an orphan image the
                        // recovery assertions must observe being cleaned.
                        let min = u64::from(op >> 3);
                        let floor = (min / items_per_section) * items_per_section.get();
                        *fault_config.write() = deterministic::FaultConfig {
                            remove_rate: Some(remove_rate),
                            ..Default::default()
                        };
                        let result = drive_pending_syncs(&pending, archive.prune(min)).await;
                        *fault_config.write() = deterministic::FaultConfig::default();
                        match result {
                            Ok(next) => archive = next,
                            Err(_) => {
                                // The failed prune consumed the archive after durably removing
                                // the markers below the floor, so sections below it may be
                                // partially removed. The exemption covers the lost indices and
                                // the prune flag disables the full-retention assertion, since
                                // the run crashes here with nothing flushed by a final op.
                                exempt_below = exempt_below.max(floor);
                                return (durable, exempt_below, true);
                            }
                        }
                        pruned |= floor > 0;
                        exempt_below = exempt_below.max(floor);
                    }
                    _ => {}
                }
            }

            // Settle every pipelined sync before the fault window opens: an abandoned lazy
            // handle never runs its underlying fsync, which would silently discard flushed
            // bytes at the crash and fail the full-retention assertion on legal behavior.
            release_pending_syncs(&pending);
            for (covered, handle) in held.drain(..) {
                handle.await.expect("pipelined sync failed");
                durable = durable.max(covered);
            }

            // Hold both durability barriers open after their buffered writes have reached storage.
            // The crash image can then retain independent byte subsets from the index and value
            // journals, including a retained index entry whose value frame has a bad CRC.
            *fault_config.write() = deterministic::FaultConfig {
                write_rate: Some(WriteConfig {
                    failure_rate: Probability::new(0, 1).unwrap(),
                    retention_rate: Probability::new(u64::from(retention_percent), 100).unwrap(),
                    mode: if first_phase_input.subset {
                        PartialWriteMode::Subset
                    } else {
                        PartialWriteMode::Prefix
                    },
                }),
                // Removes happen only inside the interrupted-prune arm, where a fault can
                // fail the prune between the two journals' section removals.
                remove_rate: Some(remove_rate),
                ..Default::default()
            };
            match first_phase_input.final_op % 3 {
                1 => {
                    // Interrupt a blocking sync mid-flight: each iteration releases the
                    // oldest parked completion, advancing the sync one durability barrier
                    // per poll, then drop the future (the owner-consuming contract retires
                    // the instance) so the crash lands between its internal barriers. A
                    // sync that runs to completion is an observed barrier: it must succeed
                    // and every accepted write becomes durable.
                    let polls = usize::from(first_phase_input.final_op >> 2) % 8 + 1;
                    if let Some(result) = poll_interrupted(&pending, archive.sync(), polls).await {
                        drop(result.expect("interrupted sync failed"));
                        durable = durable.max(total);
                    }
                }
                2 => {
                    // Interrupt a prune mid-flight: the armed gate parks it at the
                    // marker-removal metadata sync (the only parking point, so a second
                    // poll after the release runs the prune onward). Markers must be
                    // removed durably before any section storage disappears, so both cut
                    // points must recover. The armed remove faults can also fail the prune
                    // between section removals, consuming the archive with them partially
                    // applied. Only indices below the section-rounded floor can disappear,
                    // and the exemption below covers completed, abandoned, and failed
                    // prunes alike.
                    let min = u64::from(first_phase_input.final_op >> 2);
                    let floor = (min / items_per_section) * items_per_section.get();
                    pruned |= floor > 0;
                    exempt_below = exempt_below.max(floor);
                    pending.arm();
                    let polls = usize::from(first_phase_input.final_op >> 5) % 2 + 1;
                    drop(poll_interrupted(&pending, archive.prune(min), polls).await);
                }
                _ => {
                    let (archive, handle) = archive.start_sync().await.expect("start_sync failed");
                    drop(handle);
                    drop(archive);
                }
            }
            (durable, exempt_below, pruned)
        });

    // A failed recovery instance is abandoned. Its crash checkpoint must remain recoverable by
    // the same ordinary initialization path with faults disabled.
    let checkpoint = faulted_recovery(checkpoint, move |context| async move {
        TestArchive::init(
            context.child("faulted_recovery"),
            config(&context, items_per_section),
        )
        .await
    });

    // Clean recovery: derive the expected view from the raw crash image, then verify the
    // recovered archive against it with faults disabled.
    let recovery_intended = intended.clone();
    let ((expected, expected_index_sizes, expected_value_sizes), checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let cfg = config(&context, items_per_section);
            let (expected, expected_index_sizes, expected_value_sizes) =
                recover_expected(&context, &cfg, &recovery_intended).await;
            let archive = TestArchive::init(context.child("archive"), cfg.clone())
                .await
                .expect("archive recovery failed");

            // The baseline sync's coverage is carried by `durable`, which a failed op-phase
            // prune caps at the point the run crashed, so no entry is claimed before its
            // sync actually completed.
            for entry in &recovery_intended[..durable.min(recovery_intended.len())] {
                assert!(
                    expected.contains(entry) || entry.index < exempt_below,
                    "a value from a completed sync was lost",
                );
            }
            // Only the abandoned-request arm flushes every buffered byte before the crash:
            // an interrupted sync or prune legitimately strands unwritten appends.
            if retention_percent == 100 && !pruned && final_op.is_multiple_of(3) {
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
            assert_blob_sizes(&context, &cfg.key_partition, &expected_index_sizes, "index").await;
            assert_blob_sizes(
                &context,
                &cfg.value_partition,
                &expected_value_sizes,
                "value",
            )
            .await;
            drop(archive);
            (expected, expected_index_sizes, expected_value_sizes)
        });

    // Usability: recover once more, re-put every lost entry, and prove the repaired archive
    // serves the full intended view across a sync and reopen.
    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let cfg = config(&context, items_per_section);
        let mut archive = TestArchive::init(context.child("archive"), cfg.clone())
            .await
            .expect("second recovery failed");

        assert_view(&archive, &intended, &expected).await;
        assert_blob_sizes(&context, &cfg.key_partition, &expected_index_sizes, "index").await;
        assert_blob_sizes(
            &context,
            &cfg.value_partition,
            &expected_value_sizes,
            "value",
        )
        .await;

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
