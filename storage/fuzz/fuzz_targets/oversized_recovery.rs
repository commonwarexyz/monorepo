#![no_main]

//! Oversized journal crash recovery under supported partial-write crash cuts.
//!
//! Inferred recovery (no checkpoint) retains each section's prefix through its last valid entry:
//! the entry must sit inside the index's valid-page whole-record prefix and reference an
//! in-bounds, checksum-valid value frame. Interior value damage below that boundary is adopted
//! lazily and surfaces as a read error. This target reconstructs that prefix directly from the
//! raw crash image before opening the journal, asserts identity for every retained entry (an
//! in-model crash cut never forges a frame), proves entries covered by completed syncs survive,
//! checks recovery is idempotent across reopen, and lands sentinel appends on the repaired tail.
//!
//! Between appends, the op stream pipelines non-blocking sync requests whose completions resolve
//! out of order. The crash itself lands under fault-injected writes (prefix or subset retention)
//! and can interrupt a blocking sync mid-flight. Completions after the fault window opens are
//! never credited as durable.

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt as _, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, Buf, BufMut, BufferPooler, Handle, ReadOptions, Runner, Storage as _,
    Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, release_pending_syncs},
};
use commonware_storage::journal::{
    Error as JournalError,
    segmented::oversized::{Config, Oversized, Record},
};
use commonware_utils::{NZU16, NZUsize, Probability};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroUsize},
};

const PAGE_SIZE: NonZeroU16 = NZU16!(128);
const PAGE_CHECKSUM_RECORD_SIZE: usize = commonware_runtime::buffer::paged::CHECKSUM_SIZE as usize;
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(4);
const VALUE_CHECKSUM_SIZE: usize = 4;
const SECTIONS: u64 = 4;
const INDEX_PARTITION: &str = "fuzz-index";
const VALUE_PARTITION: &str = "fuzz-values";

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
    seed: u64,
    count: u8,
    retention: u8,
    subset: bool,
    /// Per-entry target section selector.
    routes: [u8; 24],
    /// Per-entry action applied after its append: pipeline a sync of its section, release one
    /// held completion, settle everything held, sync one section, or sync everything.
    ops: [u8; 24],
    /// Shape of the faulted crash: flush everything then abandon the requests, or interrupt a
    /// blocking sync mid-flight.
    final_op: u8,
}

fn config(pooler: &impl BufferPooler) -> Config<()> {
    Config {
        index_partition: INDEX_PARTITION.into(),
        value_partition: VALUE_PARTITION.into(),
        index_page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        index_write_buffer: NZUsize!(512),
        value_write_buffer: NZUsize!(512),
        replay_buffer: NZUsize!(4096),
        compression: None,
        codec_config: (),
    }
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

/// Select a page's authoritative checksum slot, falling back to the other slot if a write tore.
fn valid_page_len(page: &[u8]) -> Option<usize> {
    let page_size = usize::from(PAGE_SIZE.get());
    let footer = page.get(page_size..)?;
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
        if len > 0 && len <= page_size && Crc32::checksum(&page[..len]) == checksum {
            return Some(len);
        }
    }
    None
}

/// Return whether `entry` references an in-bounds value frame whose checksum verifies against
/// the raw glob bytes.
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
/// Reads each index blob's valid-page whole-record prefix, then scans backward for the last
/// record with an in-bounds, checksum-valid value frame: recovery retains exactly the records
/// through it, adopting earlier records whose frames were damaged (their reads must fail loud).
/// Maps each section to `(id, value readable)` per retained position, asserting identity against
/// the intended append stream since an in-model crash cut cannot forge a CRC-valid record.
async fn recover_expected(
    context: &deterministic::Context,
    intended: &BTreeMap<u64, Vec<u64>>,
) -> BTreeMap<u64, Vec<(u64, bool)>> {
    let page_size = usize::from(PAGE_SIZE.get());
    let physical_page_size = page_size + PAGE_CHECKSUM_RECORD_SIZE;
    let mut sections: BTreeMap<u64, Vec<(u64, bool)>> =
        (0..SECTIONS).map(|section| (section, Vec::new())).collect();
    for name in context
        .scan(INDEX_PARTITION)
        .await
        .expect("oracle index scan failed")
    {
        let section = u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
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
            let Some(len) = valid_page_len(physical.as_ref()) else {
                break;
            };
            logical.extend_from_slice(&physical.as_ref()[..len]);
            if len < page_size {
                break;
            }
        }
        logical.truncate(logical.len() - logical.len() % TestEntry::SIZE);
        let records: Vec<TestEntry> = logical
            .chunks_exact(TestEntry::SIZE)
            .map(|record| TestEntry::decode(record).expect("oracle index record failed"))
            .collect();

        // Recovery retains the prefix through the last record with a valid value frame.
        let mut validity = Vec::with_capacity(records.len());
        for record in &records {
            validity.push(
                frame_valid(context, section, record)
                    .await
                    .expect("oracle frame read failed"),
            );
        }
        let retained = validity
            .iter()
            .rposition(|&valid| valid)
            .map_or(0, |last| last + 1);

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
    sections
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
    let mut appended: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &(section, id) in &intended {
        appended.entry(section).or_default().push(id);
    }

    let first_phase_input = input.clone();
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let (durable, checkpoint) = runner.start_and_recover(move |context| async move {
        let fault_config = context.storage_fault_config();
        let pending = PendingSyncs::default();
        let context = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };
        let cfg = config(&context);
        let mut oversized: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.child("initial"), cfg, None)
                .await
                .expect("initial init failed");

        // Every sync completion below stays parked until an op resolves it, so requests pipeline
        // and completions resolve in op-chosen order.
        let mut counts: BTreeMap<u64, u64> = BTreeMap::new();
        let mut durable: BTreeMap<u64, u64> = BTreeMap::new();
        let mut held: Vec<(u64, u64, Handle<()>)> = Vec::new();
        for (offset, &(section, id)) in intended.iter().enumerate() {
            let value: TestValue = [id as u8; 16];
            (oversized, _, _, _) = oversized
                .append(section, TestEntry::new(id), &value)
                .await
                .expect("append failed");
            *counts.entry(section).or_default() += 1;

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
        match first_phase_input.final_op % 3 {
            1 => {
                // Interrupt a blocking sync of every section mid-flight: poll until it parks on
                // a held completion, then drop the future, so the crash lands between its
                // internal barriers with only a prefix of the sections flushed.
                pending.arm();
                let mut sync = Box::pin(oversized.sync_all());
                for _ in 0..usize::from(first_phase_input.final_op >> 2) % 8 + 1 {
                    if futures::future::poll_immediate(sync.as_mut())
                        .await
                        .is_some()
                    {
                        break;
                    }
                }
                drop(sync);
            }
            2 => {
                // Interrupt a blocking sync of one section mid-flight.
                pending.arm();
                let section = u64::from(first_phase_input.final_op >> 2) % SECTIONS;
                let mut sync = Box::pin(oversized.sync(section));
                for _ in 0..usize::from(first_phase_input.final_op >> 5) % 8 + 1 {
                    if futures::future::poll_immediate(sync.as_mut())
                        .await
                        .is_some()
                    {
                        break;
                    }
                }
                drop(sync);
            }
            _ => {
                // Flush every buffered append through the fault layer, then abandon the sync
                // requests so the crash discards their barriers but samples their writes.
                for section in 0..SECTIONS {
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
        durable
    });

    let recovery_appended = appended.clone();
    let recovery_input = input.clone();
    let ((expected, sizes), checkpoint) = deterministic::Runner::from(checkpoint)
        .start_and_recover(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let cfg = config(&context);
            let expected = recover_expected(&context, &recovery_appended).await;
            let recovered: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("recovered"), cfg, None)
                    .await
                    .expect("recovery failed");

            // Entries covered by a completed sync must survive, and a crash that retained every
            // faulted byte after flushing everything loses nothing at all.
            for (section, &count) in &durable {
                let retained = expected.get(section).map_or(0, Vec::len) as u64;
                assert!(
                    retained >= count,
                    "section {section} lost entries covered by a completed sync"
                );
            }
            if recovery_input.retention % 101 == 100 && recovery_input.final_op.is_multiple_of(3) {
                for (section, ids) in &recovery_appended {
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
            (expected, sizes)
        });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let cfg = config(&context);
        let mut oversized: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.child("reopened"), cfg.clone(), None)
                .await
                .expect("second recovery failed");

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

        let reopened: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.child("sentinels"), cfg, None)
                .await
                .expect("reopen after sentinel sync failed");
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
