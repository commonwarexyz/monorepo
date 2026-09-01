#![no_main]

//! Oversized journal crash recovery under supported partial-write crash cuts, in inferred and
//! marker-tracked recovery modes.
//!
//! The oracle derives each section's retained prefix from the raw crash image (see
//! `recover_expected` for the per-mode rules and marker-floor invariants). It asserts that
//! entries covered by a completed sync survive, that recovery removes orphan value sections
//! and truncates each value glob to the last retained entry, that a second recovery mutates
//! nothing, and that sentinel appends land at the repaired tail and reopen intact.

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt as _, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, Buf, BufMut, BufferPooler, Handle, ReadOptions, Runner, Storage as _,
    Supervisor as _,
    buffer::paged::{CacheRef, page_len},
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, release_pending_syncs},
};
use commonware_storage::{
    Context,
    journal::{
        Error as JournalError,
        segmented::oversized::{Config, Oversized, Record},
    },
    metadata::{Config as MetadataConfig, Metadata},
};
use commonware_storage_fuzz::{faulted_recovery, poll_interrupted};
use commonware_utils::{Entropy, NZU16, NZUsize, Probability, sequence::U64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroUsize},
};

const PAGE_SIZE: NonZeroU16 = NZU16!(128);
const PAGE_CHECKSUM_RECORD_SIZE: usize = commonware_runtime::buffer::paged::CHECKSUM_SIZE as usize;
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(4);
const VALUE_CHECKSUM_SIZE: usize = 4;
const SECTIONS: u64 = 4;
const INDEX_PARTITION: &str = "fuzz-index";
const VALUE_PARTITION: &str = "fuzz-values";
const METADATA_PARTITION: &str = "fuzz-markers";

/// Test index entry that stores a u64 id and references a value.
#[derive(Debug, Clone, PartialEq)]
struct TestEntry {
    id: u64,
    value_offset: u64,
    value_size: u32,
}

impl TestEntry {
    fn new(id: u64) -> Self {
        Self {
            id,
            value_offset: 0,
            value_size: 0,
        }
    }
}

impl Write for TestEntry {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.value_offset.write(buf);
        self.value_size.write(buf);
    }
}

impl Read for TestEntry {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl Buf,
        _: &Self::Cfg,
    ) -> std::result::Result<Self, commonware_codec::Error> {
        let id = u64::read(buf)?;
        let value_offset = u64::read(buf)?;
        let value_size = u32::read(buf)?;
        Ok(Self {
            id,
            value_offset,
            value_size,
        })
    }
}

impl FixedSize for TestEntry {
    const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE;
}

impl Record for TestEntry {
    fn value_location(&self) -> (u64, u32) {
        (self.value_offset, self.value_size)
    }

    fn with_location(mut self, offset: u64, size: u32) -> Self {
        self.value_offset = offset;
        self.value_size = size;
        self
    }
}

type TestValue = [u8; 16];

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    /// Number of entries to append (1..=24).
    count: u8,
    /// Crash retention rate (percent) for unsynced bytes.
    retention: u8,
    /// Partial-write mode: Subset when set, Prefix otherwise.
    subset: bool,
    /// Drive the whole execution through marker-tracked recovery: the op-phase instance and
    /// every recovery attempt (interrupted or clean) open the sidecar, replay, and finish
    /// tracked. Mixing tracked images with inferred inits is a different product scenario, so
    /// one input never mixes modes.
    tracked: bool,
    /// Per-entry target section selector.
    routes: [u8; 24],
    /// Per-entry action applied after its append: pipeline a sync of its section, release one
    /// held completion, settle everything held, sync one section, or sync everything. Tracked
    /// mode adds an empty flush that publishes marker debt, a prune, and a section rewind.
    /// These ops complete before the fault window opens, so the marker-before-data ordering
    /// inside rewind is not falsifiable here. Prune's ordering is made falsifiable by the
    /// interrupted-prune final op and by the remove faults armed around every prune.
    ops: [u8; 24],
    /// Shape of the faulted crash: flush everything then abandon the requests (also the
    /// fallback for the prune arm when untracked), interrupt a blocking sync of every
    /// section, interrupt a blocking sync of one section, or abandon a tracked prune
    /// mid-flight.
    final_op: u8,
    /// Remove failure rate (percent) armed around every prune, sampled per section-blob
    /// removal so a prune can fail after removing an index section but before its value
    /// section, leaving an orphan value section for recovery to clean.
    remove_failure: u8,
    /// Byte stream driving the runtime rng: all in-run randomness, fault sampling, and the
    /// faulted recovery chain's depth and shapes.
    entropy: Entropy,
}

fn config(pooler: &impl BufferPooler) -> Config<()> {
    Config {
        index_partition: INDEX_PARTITION.into(),
        value_partition: VALUE_PARTITION.into(),
        index_page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        // The fully-retained-section assert relies on no buffer-fill flush being issued
        // before the fault window opens: at most 24 entries of 20 bytes stay under these
        // 512-byte buffers. Raising the entry count or size, or shrinking these buffers,
        // would tear supposedly lossless sections through an unrecorded early flush.
        index_write_buffer: NZUsize!(512),
        value_write_buffer: NZUsize!(512),
        replay_buffer: NZUsize!(4096),
        compression: None,
        codec_config: (),
    }
}

/// Run the full tracked recovery: open the marker sidecar, drain the marker-aware replay, and
/// finish. The sidecar opens under the same context as the journals, so its writes see the same
/// fault shapes, and an error at any stage abandons the interrupted image to the next attempt.
async fn init_tracked<E: Context>(
    context: E,
    cfg: Config<()>,
) -> Result<Oversized<E, TestEntry, TestValue>, JournalError> {
    let mut replay = Oversized::<_, TestEntry, TestValue>::init_with_metadata(
        &context,
        cfg,
        METADATA_PARTITION.into(),
        ReadOptions::default(),
    )
    .await?;
    while let Some(result) = replay.next().await {
        result?;
    }
    replay.finish_tracked().await
}

/// The scripted append stream: `(section, id)` per operation, ids in append order.
fn items(input: &FuzzInput) -> Vec<(u64, u64)> {
    let count = usize::from(input.count % 24) + 1;
    (0..count as u64)
        .map(|id| {
            let section = u64::from(input.routes[id as usize % input.routes.len()]) % SECTIONS;
            (section, id)
        })
        .collect()
}

/// Return whether `entry` references an in-bounds value frame whose checksum verifies against
/// the raw value bytes.
async fn frame_valid(
    context: &deterministic::Context,
    section: u64,
    entry: &TestEntry,
) -> Option<bool> {
    let (offset, size) = entry.value_location();
    let size = usize::try_from(size).ok()?;
    if size < VALUE_CHECKSUM_SIZE {
        return Some(false);
    }
    let end = offset.checked_add(size as u64)?;
    let Ok((blob, blob_size)) = context.open(VALUE_PARTITION, &section.to_be_bytes()).await else {
        return Some(false);
    };
    if end > blob_size {
        return Some(false);
    }
    let frame = blob
        .read_at(offset, size, ReadOptions::default())
        .await
        .ok()?
        .coalesce();
    let data_len = size - VALUE_CHECKSUM_SIZE;
    let stored = u32::from_be_bytes(frame.as_ref()[data_len..].try_into().unwrap());
    Some(Crc32::checksum(&frame.as_ref()[..data_len]) == stored)
}

/// Reconstruct each section's expected recovery outcome from the raw crash image without
/// repairing it.
///
/// Reads each index blob's valid-page whole-record prefix, then derives the retained prefix per
/// mode. Inferred recovery (`floors` is `None`) scans backward for the last record with an
/// in-bounds, checksum-valid value frame: it retains exactly the records through it, adopting
/// earlier records whose frames were damaged (their reads must fail loud). Tracked recovery
/// adopts each section's marker floor without value checks and validates forward from it,
/// truncating at the first invalid value.
///
/// Markers trail durability: under crash cuts (no bit rot) a floor was published only after a
/// completed joint sync covered it, and prune or rewind durably move markers before data can
/// shrink, so a floor can never exceed the section's durable record count and every frame below
/// it must still be in bounds and checksum-valid. Both halves are asserted here against the
/// image-derived boundaries.
///
/// Maps each section to `(id, value readable)` per retained position, asserting identity against
/// the intended append stream since an in-model crash cut cannot forge a CRC-valid record.
///
/// Also returns each scanned section's terminal value end (zero when nothing is retained),
/// which repair must truncate the glob to.
async fn recover_expected(
    context: &deterministic::Context,
    intended: &BTreeMap<u64, Vec<u64>>,
    floors: Option<&BTreeMap<u64, u64>>,
) -> (BTreeMap<u64, Vec<(u64, bool)>>, BTreeMap<u64, u64>) {
    let page_size = usize::from(PAGE_SIZE.get());
    let physical_page_size = page_size + PAGE_CHECKSUM_RECORD_SIZE;
    let mut value_ends = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut sections: BTreeMap<u64, Vec<(u64, bool)>> =
        (0..SECTIONS).map(|section| (section, Vec::new())).collect();
    for name in context
        .scan(INDEX_PARTITION)
        .await
        .expect("oracle index scan failed")
    {
        let section = u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
        seen.insert(section);
        let (blob, size) = context
            .open(INDEX_PARTITION, &name)
            .await
            .expect("oracle index open failed");
        let pages = usize::try_from(size).expect("oracle index size overflow") / physical_page_size;
        let mut logical = Vec::with_capacity(pages * page_size);
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
            let Some(len) = page_len(physical.as_ref(), page_size) else {
                break;
            };
            logical.extend_from_slice(&physical.as_ref()[..len]);
            if len < page_size {
                break;
            }
        }
        logical.truncate(logical.len() - logical.len() % TestEntry::SIZE);
        let records: Vec<TestEntry> = logical
            .as_chunks::<{ TestEntry::SIZE }>()
            .0
            .iter()
            .map(|record| TestEntry::decode(&record[..]).expect("oracle index record failed"))
            .collect();

        let mut validity = Vec::with_capacity(records.len());
        for record in &records {
            validity.push(
                frame_valid(context, section, record)
                    .await
                    .expect("oracle frame read failed"),
            );
        }
        let retained = match floors {
            // Inferred recovery retains the prefix through the last record with a valid frame.
            None => validity
                .iter()
                .rposition(|&valid| valid)
                .map_or(0, |last| last + 1),
            Some(floors) => {
                // The marker must trail the durable index boundary and, because publication
                // followed a completed joint sync, every frame below it must be in bounds and
                // valid (frame validity implies the value boundary).
                let floor = usize::try_from(floors.get(&section).copied().unwrap_or(0))
                    .expect("oracle floor overflow");
                assert!(
                    floor <= records.len(),
                    "marker exceeds the durable index boundary in section {section}"
                );
                assert!(
                    validity[..floor].iter().all(|&valid| valid),
                    "marker exceeds the durable value boundary in section {section}"
                );

                // Tracked recovery adopts the floor prefix and truncates at the first invalid
                // value above it.
                floor
                    + validity[floor..]
                        .iter()
                        .position(|&valid| !valid)
                        .unwrap_or(records.len() - floor)
            }
        };
        let value_end = records[..retained].last().map_or(0, |record| {
            let (offset, size) = record.value_location();
            offset
                .checked_add(u64::from(size))
                .expect("oracle value end overflow")
        });
        value_ends.insert(section, value_end);

        let intended = intended.get(&section).map_or(&[][..], Vec::as_slice);
        let mut expected = Vec::with_capacity(retained);
        for (position, (record, &readable)) in
            records.iter().zip(&validity).take(retained).enumerate()
        {
            let id = *intended
                .get(position)
                .expect("crash image retains an unauthentic index record");
            assert_eq!(
                record.id, id,
                "crash image changed a CRC-valid index record"
            );
            expected.push((id, readable));
        }
        sections.insert(section, expected);
    }

    // A positive marker proves its records durable, so its section must survive in the image.
    if let Some(floors) = floors {
        for (&section, &floor) in floors {
            assert!(
                floor == 0 || seen.contains(&section),
                "marker names section {section} missing from the crash image"
            );
        }
    }
    (sections, value_ends)
}

/// Assert the recovered journal serves exactly the expected view: identity for every retained
/// entry and loud failure for interior-damaged values. When `sealed`, nothing has been appended
/// past the recovered prefix yet, so reading one position past it must fail.
async fn assert_view(
    oversized: &Oversized<deterministic::Context, TestEntry, TestValue>,
    expected: &BTreeMap<u64, Vec<(u64, bool)>>,
    sealed: bool,
) {
    for (&section, entries) in expected {
        for (position, &(id, readable)) in entries.iter().enumerate() {
            let entry = oversized
                .get(section, position as u64)
                .await
                .expect("retained index entry missing");
            assert_eq!(entry.id, id, "retained index entry changed");
            let (offset, size) = entry.value_location();
            let value = oversized.get_value(section, offset, size).await;
            if readable {
                assert_eq!(
                    value.expect("retained value missing"),
                    [id as u8; 16],
                    "retained value changed"
                );
            } else {
                assert!(
                    value.is_err(),
                    "an interior-damaged value read must fail loud"
                );
            }
        }
        if sealed {
            match oversized.get(section, entries.len() as u64).await {
                Err(JournalError::ItemOutOfRange(_) | JournalError::SectionOutOfRange(_)) => {}
                other => panic!("read past the retained prefix must fail: {other:?}"),
            }
        }
    }
}

/// Snapshot every blob's size in both partitions.
async fn blob_sizes(context: &deterministic::Context) -> BTreeMap<(bool, u64), u64> {
    let mut sizes = BTreeMap::new();
    for (is_index, partition) in [(true, INDEX_PARTITION), (false, VALUE_PARTITION)] {
        for name in context.scan(partition).await.expect("size scan failed") {
            let section =
                u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
            let (_, size) = context
                .open(partition, &name)
                .await
                .expect("size open failed");
            sizes.insert((is_index, section), size);
        }
    }
    sizes
}

fn fuzz(input: FuzzInput) {
    let intended = items(&input);
    let retention_percent = input.retention % 101;
    let tracked = input.tracked;

    let first_phase_input = input.clone();
    let cfg = deterministic::Config::default().with_rng(input.entropy);
    let runner = deterministic::Runner::new(cfg);
    let ((durable, model, flushed_all), checkpoint) =
        runner.start_and_recover(move |context| async move {
            let fault_config = context.storage_fault_config();
            let remove_rate =
                Probability::new(u64::from(first_phase_input.remove_failure) % 101, 100).unwrap();
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = config(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> = if tracked {
                init_tracked(context.child("initial"), cfg)
                    .await
                    .expect("initial tracked init failed")
            } else {
                Oversized::init(context.child("initial"), cfg)
                    .await
                    .expect("initial init failed")
            };

            // Every sync completion below stays parked until an op resolves it, so requests pipeline
            // and completions resolve in op-chosen order. The model mirrors each section's logical
            // ids through appends, prunes, and rewinds.
            let mut counts: BTreeMap<u64, u64> = BTreeMap::new();
            let mut durable: BTreeMap<u64, u64> = BTreeMap::new();
            let mut model: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
            let mut held: Vec<(u64, u64, Handle<()>)> = Vec::new();
            let mut prune_floor = 0u64;
            for (offset, &(section, id)) in intended.iter().enumerate() {
                // Route appends above the prune floor: mutating a pruned section fails.
                let section = if section < prune_floor {
                    prune_floor + section % (SECTIONS - prune_floor)
                } else {
                    section
                };
                let value: TestValue = [id as u8; 16];
                (oversized, _, _, _) = oversized
                    .append(section, TestEntry::new(id), &value)
                    .await
                    .expect("append failed");
                *counts.entry(section).or_default() += 1;
                model.entry(section).or_default().push(id);

                let op = first_phase_input.ops[offset % first_phase_input.ops.len()];
                match op & 0x07 {
                    1 => {
                        // Release (without observing) any parked completions so the new request
                        // cannot block on a prior fsync of the same section.
                        release_pending_syncs(&pending);
                        let handle;
                        (oversized, handle) = oversized
                            .start_sync(section)
                            .await
                            .expect("pipelined start_sync failed");
                        held.push((section, counts[&section], handle));
                    }
                    2 => {
                        // Resolve one parked completion out of order without observing it.
                        let mut parked = pending.lock();
                        if !parked.is_empty() {
                            let idx = usize::from(op >> 3) % parked.len();
                            let sync = parked.remove(idx);
                            let _ = sync.release.send(Ok(()));
                        }
                    }
                    3 => {
                        // Settle every held pipeline, crediting the entries each request covered.
                        release_pending_syncs(&pending);
                        for (covered_section, covered, handle) in held.drain(..) {
                            handle.await.expect("pipelined sync failed");
                            let durable = durable.entry(covered_section).or_default();
                            *durable = (*durable).max(covered);
                        }
                    }
                    4 => {
                        // Complete a blocking sync of this entry's section, driving it through any
                        // parked completions it stalls on.
                        oversized = drive_pending_syncs(&pending, oversized.sync(section))
                            .await
                            .expect("section sync failed");
                        durable.insert(section, counts[&section]);
                    }
                    5 => {
                        // Complete a blocking sync of every section: everything appended so far
                        // becomes durable.
                        oversized = drive_pending_syncs(&pending, oversized.sync_all())
                            .await
                            .expect("sync_all failed");
                        durable = counts.clone();
                    }
                    6 if tracked => {
                        // Empty flush: with no active sections, every settled durability proof
                        // publishes as a marker generation under the parked completions.
                        oversized =
                            drive_pending_syncs(&pending, oversized.sync(Vec::<u64>::new()))
                                .await
                                .expect("empty flush failed");
                    }
                    7 if tracked => {
                        // Settle held pipelines first: a completion credited after the truncation
                        // below would claim durability for entries the operation removed.
                        release_pending_syncs(&pending);
                        for (covered_section, covered, handle) in held.drain(..) {
                            handle.await.expect("pipelined sync failed");
                            let durable = durable.entry(covered_section).or_default();
                            *durable = (*durable).max(covered);
                        }
                        if op & 0x08 == 0 {
                            // Prune: tracked floors are durably removed before section data
                            // disappears. Input-driven remove faults can fail the prune partway,
                            // leaving an index section deleted while its value section survives,
                            // an orphan image the recovery assertions must observe being cleaned.
                            let min = u64::from(op >> 4) % SECTIONS;
                            *fault_config.write() = deterministic::FaultConfig {
                                remove_rate: Some(remove_rate),
                                ..Default::default()
                            };
                            let result = drive_pending_syncs(&pending, oversized.prune(min)).await;
                            *fault_config.write() = deterministic::FaultConfig::default();
                            match result {
                                Ok((journal, did_prune)) => {
                                    oversized = journal;
                                    if did_prune {
                                        prune_floor = prune_floor.max(min);
                                        counts.retain(|&section, _| section >= min);
                                        durable.retain(|&section, _| section >= min);
                                        model.retain(|&section, _| section >= min);
                                    }
                                }
                                Err(_) => {
                                    // The failed prune consumed the journal after durably removing
                                    // the markers below the floor, so sections below it may be
                                    // partially removed. Durability claims below the floor are
                                    // dropped while the intended stream is kept, since surviving
                                    // records must stay authentic. The run crashes here with
                                    // nothing flushed by a final op.
                                    durable.retain(|&section, _| section >= min);
                                    return (durable, model, false);
                                }
                            }
                        } else {
                            // Rewind one live section below its current length: its tracked floor
                            // durably lowers before the freed index and value ranges can be reused.
                            let live: Vec<u64> = counts.keys().copied().collect();
                            if let Some(&section) =
                                live.get(usize::from(op >> 4) % live.len().max(1))
                            {
                                let count = counts[&section];
                                let keep = count * u64::from(op >> 6) / 4;
                                oversized = drive_pending_syncs(
                                    &pending,
                                    oversized
                                        .rewind_section(section, keep * TestEntry::SIZE as u64),
                                )
                                .await
                                .expect("rewind failed");
                                counts.insert(section, keep);
                                model
                                    .get_mut(&section)
                                    .expect("rewound section is modeled")
                                    .truncate(keep as usize);
                                if let Some(durable) = durable.get_mut(&section) {
                                    *durable = (*durable).min(keep);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Settle every pipelined sync before the fault window opens: an abandoned lazy handle
            // never runs its underlying fsync, which would silently discard flushed bytes at the
            // crash. After the window opens, completions are no longer credited as durable.
            release_pending_syncs(&pending);
            for (covered_section, covered, handle) in held.drain(..) {
                handle.await.expect("pipelined sync failed");
                let durable = durable.entry(covered_section).or_default();
                *durable = (*durable).max(covered);
            }
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
                // Removes happen only inside the interrupted-prune arm, where a fault can fail
                // the prune between the two journals' section removals.
                remove_rate: Some(remove_rate),
                ..Default::default()
            };
            let mut flushed_all = false;
            match first_phase_input.final_op % 4 {
                1 => {
                    // Interrupt a blocking sync of every section behind the armed one-shot
                    // gate: the first barrier to arrive parks with its blob's flush left
                    // volatile while every other blob syncs durably. Releasing the gate and
                    // polling again instead completes the sync before the crash.
                    pending.arm();
                    let polls = usize::from(first_phase_input.final_op >> 2) % 2 + 1;
                    if let Some(result) =
                        poll_interrupted(&pending, oversized.sync_all(), polls).await
                    {
                        // A sync that ran to completion is an observed barrier: it must
                        // succeed and every appended entry becomes durable.
                        drop(result.expect("interrupted sync_all failed"));
                        durable = counts.clone();
                    }
                }
                2 => {
                    // Interrupt a blocking sync of one section behind the armed gate, with
                    // the same parked-or-completed split as above. Pruned sections reject
                    // mutations, so the target is remapped above the floor.
                    pending.arm();
                    let mut section = u64::from(first_phase_input.final_op >> 2) % SECTIONS;
                    if section < prune_floor {
                        section = prune_floor + section % (SECTIONS - prune_floor);
                    }
                    let polls = usize::from(first_phase_input.final_op >> 5) % 2 + 1;
                    if let Some(result) =
                        poll_interrupted(&pending, oversized.sync(section), polls).await
                    {
                        // A completed section sync must succeed and makes that section's
                        // appended entries durable.
                        drop(result.expect("interrupted section sync failed"));
                        if let Some(&count) = counts.get(&section) {
                            durable.insert(section, count);
                        }
                    }
                }
                3 if tracked => {
                    // Interrupt a prune behind the armed gate and abandon it mid-flight. This arm
                    // makes prune's internal ordering falsifiable: the marker removal must be
                    // durably synced before any section blob is removed, or a crash image can hold
                    // a positive marker naming a section it no longer contains. The input-derived
                    // poll count lands the crash before the future first runs, while its marker
                    // sync is parked at the gate, or after the whole prune completed. The armed
                    // remove faults can also fail the prune between section removals.
                    pending.arm();
                    let min = u64::from(first_phase_input.final_op >> 2) % SECTIONS;
                    let polls = usize::from(first_phase_input.final_op >> 4) % 3;
                    let mut completed = false;
                    // A prune that ran to completion durably removed the markers and
                    // section blobs below the floor before returning. One that failed on a
                    // section removal consumed the journal with those removals partially
                    // applied, which the durability drop below covers.
                    if let Some(Ok((journal, did_prune))) =
                        poll_interrupted(&pending, oversized.prune(min), polls).await
                    {
                        drop(journal);
                        if did_prune {
                            durable.retain(|&section, _| section >= min);
                            model.retain(|&section, _| section >= min);
                        }
                        completed = true;
                    }

                    // The oracle must not depend on where the abandoned or failed future stopped,
                    // so durability claims below the floor are dropped rather than assuming the
                    // removals never started. The intended stream is kept because the sections
                    // may equally have survived, and surviving records must stay authentic.
                    if !completed && polls > 0 {
                        durable.retain(|&section, _| section >= min);
                    }
                }
                _ => {
                    // Flush every buffered append through the fault layer, then abandon the sync
                    // requests so the crash discards their barriers but samples their writes.
                    flushed_all = true;
                    for section in prune_floor..SECTIONS {
                        let handle;
                        (oversized, handle) = oversized
                            .start_sync(section)
                            .await
                            .expect("final start_sync failed");
                        drop(handle);
                    }
                    drop(oversized);
                }
            }
            (durable, model, flushed_all)
        });

    // A failed recovery instance is abandoned. Its crash checkpoint must remain recoverable by
    // the same recovery path, tracked or inferred, with faults disabled.
    let checkpoint = if tracked {
        faulted_recovery(checkpoint, |context| async move {
            init_tracked(context.child("faulted_recovery"), config(&context)).await
        })
    } else {
        faulted_recovery(checkpoint, |context| async move {
            Oversized::<_, TestEntry, TestValue>::init(
                context.child("faulted_recovery"),
                config(&context),
            )
            .await
        })
    };

    let recovery_model = model.clone();
    let ((expected, sizes), checkpoint) = deterministic::Runner::from(checkpoint)
        .start_and_recover(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let cfg = config(&context);

            // Read the sidecar floors with the production parser before recovery reconciles
            // them: init adopts the newest valid marker generation and durably resets only the
            // one copy a crash left torn, which the tracked recovery below repeats identically.
            let floors = if tracked {
                let metadata: Metadata<_, U64, u64> = Metadata::init(
                    context.child("floors"),
                    MetadataConfig {
                        partition: METADATA_PARTITION.into(),
                        codec_config: (),
                    },
                )
                .await
                .expect("sidecar oracle init failed");
                Some(
                    metadata
                        .keys()
                        .map(|key| {
                            (
                                u64::from(key),
                                *metadata.get(key).expect("marker key must have a floor"),
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                )
            } else {
                None
            };
            let (expected, value_ends) =
                recover_expected(&context, &recovery_model, floors.as_ref()).await;
            let recovered: Oversized<_, TestEntry, TestValue> = if tracked {
                init_tracked(context.child("recovered"), cfg)
                    .await
                    .expect("tracked recovery failed")
            } else {
                Oversized::init(context.child("recovered"), cfg)
                    .await
                    .expect("recovery failed")
            };

            // Entries covered by a completed sync must survive, and a crash that retained every
            // faulted byte after flushing everything loses nothing at all.
            for (section, &count) in &durable {
                let retained = expected.get(section).map_or(0, Vec::len) as u64;
                assert!(
                    retained >= count,
                    "section {section} lost entries covered by a completed sync"
                );
            }
            if retention_percent == 100 && flushed_all {
                for (section, ids) in &recovery_model {
                    let retained: Vec<u64> = expected
                        .get(section)
                        .map_or(&[][..], Vec::as_slice)
                        .iter()
                        .map(|&(id, _)| id)
                        .collect();
                    assert_eq!(
                        &retained, ids,
                        "a fully retained flushed section lost an entry"
                    );
                }
            }
            assert_view(&recovered, &expected, true).await;
            drop(recovered);
            let sizes = blob_sizes(&context).await;

            // Repair must pair every index section with a glob truncated to the last
            // retained entry's end and remove value sections with no index counterpart,
            // so stale value bytes can never satisfy a later append's range.
            for (&(is_index, section), &size) in &sizes {
                if is_index {
                    assert!(
                        sizes.contains_key(&(false, section)),
                        "index section {section} recovered without its value section"
                    );
                    continue;
                }
                assert!(
                    sizes.contains_key(&(true, section)),
                    "recovery kept an orphan value section {section}"
                );
                assert_eq!(
                    size, value_ends[&section],
                    "recovery left the wrong value size in section {section}"
                );
            }
            (expected, sizes)
        });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let cfg = config(&context);
        let mut oversized: Oversized<_, TestEntry, TestValue> = if tracked {
            init_tracked(context.child("reopened"), cfg.clone())
                .await
                .expect("second tracked recovery failed")
        } else {
            Oversized::init(context.child("reopened"), cfg.clone())
                .await
                .expect("second recovery failed")
        };

        // Recovery is idempotent: a second initialization serves the same view and rewrites
        // nothing.
        assert_eq!(
            blob_sizes(&context).await,
            sizes,
            "a second recovery mutated the repaired image"
        );
        assert_view(&oversized, &expected, true).await;

        // Appends land at the repaired tail, survive a sync, and reopen intact.
        let mut sentinels = Vec::new();
        for section in 0..SECTIONS {
            let sentinel = u64::MAX - section;
            let position;
            (oversized, position, _, _) = oversized
                .append(section, TestEntry::new(sentinel), &[0xFF; 16])
                .await
                .expect("sentinel append failed");
            assert_eq!(
                position,
                expected.get(&section).map_or(0, Vec::len) as u64,
                "sentinel landed past the retained prefix"
            );
            sentinels.push((section, position, sentinel));
        }
        oversized = oversized.sync_all().await.expect("sentinel sync failed");
        drop(oversized);

        let reopened: Oversized<_, TestEntry, TestValue> = if tracked {
            init_tracked(context.child("sentinels"), cfg)
                .await
                .expect("reopen after sentinel sync failed")
        } else {
            Oversized::init(context.child("sentinels"), cfg)
                .await
                .expect("reopen after sentinel sync failed")
        };
        assert_view(&reopened, &expected, false).await;
        for (section, position, sentinel) in sentinels {
            let entry = reopened
                .get(section, position)
                .await
                .expect("sentinel index missing");
            assert_eq!(entry.id, sentinel);
            let (offset, size) = entry.value_location();
            assert_eq!(
                reopened
                    .get_value(section, offset, size)
                    .await
                    .expect("sentinel value missing"),
                [0xFF; 16],
            );
        }
        reopened.destroy().await.expect("destroy failed");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
