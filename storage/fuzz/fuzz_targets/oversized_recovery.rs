#![no_main]

//! Fuzz test for oversized journal crash recovery.
//!
//! This test creates valid data, randomly corrupts storage, and verifies
//! that recovery doesn't panic and leaves the journal in a consistent state.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, Buf, BufMut, BufferPooler, Runner, Storage as _, Supervisor as _,
    buffer::paged::CacheRef, deterministic,
};
use commonware_storage::journal::{
    Error as JournalError,
    segmented::oversized::{Config, Oversized, Record},
};
use commonware_storage_fuzz::{RNG_BYTES, batch_faults, fuzz_runner};
use commonware_utils::{NZU16, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroUsize},
};

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
type Expected = BTreeMap<u64, Vec<(TestEntry, TestValue)>>;
type TestJournal = Oversized<deterministic::Context, TestEntry, TestValue>;

#[derive(Debug, Clone)]
enum CorruptionType {
    /// Truncate index to a random size
    TruncateIndex { section: u64, size_factor: u8 },
    /// Truncate glob to a random size
    TruncateGlob { section: u64, size_factor: u8 },
    /// Write random bytes at a random offset in index
    CorruptIndexBytes {
        section: u64,
        offset_factor: u8,
        data: [u8; 4],
    },
    /// Write random bytes at a random offset in glob
    CorruptGlobBytes {
        section: u64,
        offset_factor: u8,
        data: [u8; 4],
    },
    /// Delete index section
    DeleteIndex { section: u64 },
    /// Delete glob section
    DeleteGlob { section: u64 },
    /// Extend index with garbage
    ExtendIndex { section: u64, garbage: [u8; 32] },
    /// Extend glob with garbage
    ExtendGlob { section: u64, garbage: [u8; 64] },
}

impl<'a> Arbitrary<'a> for CorruptionType {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let variant = u.int_in_range(0..=7)?;
        match variant {
            0 => Ok(CorruptionType::TruncateIndex {
                section: u.int_in_range(1..=3)?,
                size_factor: u.arbitrary()?,
            }),
            1 => Ok(CorruptionType::TruncateGlob {
                section: u.int_in_range(1..=3)?,
                size_factor: u.arbitrary()?,
            }),
            2 => Ok(CorruptionType::CorruptIndexBytes {
                section: u.int_in_range(1..=3)?,
                offset_factor: u.arbitrary()?,
                data: u.arbitrary()?,
            }),
            3 => Ok(CorruptionType::CorruptGlobBytes {
                section: u.int_in_range(1..=3)?,
                offset_factor: u.arbitrary()?,
                data: u.arbitrary()?,
            }),
            4 => Ok(CorruptionType::DeleteIndex {
                section: u.int_in_range(1..=3)?,
            }),
            5 => Ok(CorruptionType::DeleteGlob {
                section: u.int_in_range(1..=3)?,
            }),
            6 => Ok(CorruptionType::ExtendIndex {
                section: u.int_in_range(1..=3)?,
                garbage: u.arbitrary()?,
            }),
            _ => Ok(CorruptionType::ExtendGlob {
                section: u.int_in_range(1..=3)?,
                garbage: u.arbitrary()?,
            }),
        }
    }
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum SyncMode {
    BackgroundUnpublished,
    BlockingStaleFloor,
    BlockingFullFloor,
}

#[derive(Debug)]
struct CorruptionInput {
    /// Fuzzer-controlled randomness for deterministic runtime choices.
    raw_bytes: [u8; RNG_BYTES],
    /// Number of entries per section (1-10)
    entries_per_section: [u8; 3],
    /// Corruptions to apply before recovery
    corruptions: Vec<CorruptionType>,
    /// Durability operation and checkpoint publication state before corruption.
    sync_mode: SyncMode,
}

impl<'a> Arbitrary<'a> for CorruptionInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let raw_bytes = u.arbitrary()?;
        let entries_per_section = u.arbitrary()?;
        let corruption_count = u.int_in_range(0..=MAX_CORRUPTIONS)?;
        let corruptions = (0..corruption_count)
            .map(|_| u.arbitrary())
            .collect::<Result<_>>()?;
        let sync_mode = u.arbitrary()?;
        Ok(Self {
            raw_bytes,
            entries_per_section,
            corruptions,
            sync_mode,
        })
    }
}

#[derive(Arbitrary, Debug)]
struct CrashRecoveryInput {
    /// Fuzzer-controlled randomness for deterministic runtime choices and crash persistence.
    raw_bytes: [u8; RNG_BYTES],
    /// Whether to compress values with a fixed valid zstd level.
    compression: bool,
    /// Number of entries per section (1-10)
    entries_per_section: [u8; 3],
    /// First section to retain when exercising pruning after recovery.
    prune_min: u8,
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Corruption(CorruptionInput),
    CrashRecovery(CrashRecoveryInput),
}

const PAGE_SIZE: NonZeroU16 = NZU16!(128);
const CRASH_PAGE_SIZE: NonZeroU16 = NZU16!(4);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(4);
const MAX_CORRUPTIONS: usize = 16;
const INDEX_PARTITION: &str = "fuzz-index";
const VALUE_PARTITION: &str = "fuzz-values";
// Paged index blobs store a 12-byte checksum record after each logical page.
const INDEX_CHECKSUM_SIZE: u64 = (2 * (u16::SIZE + u32::SIZE)) as u64;

#[derive(Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    fn intersects(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Default)]
struct Damage {
    index: BTreeMap<u64, Vec<ByteRange>>,
    values: BTreeMap<u64, Vec<ByteRange>>,
    index_after: BTreeMap<u64, Vec<u8>>,
}

/// Return the logical length selected by the paged writer's two-slot checksum format.
fn recoverable_index_page_len(page: &[u8]) -> Option<u64> {
    let logical_page_size = PAGE_SIZE.get() as usize;
    if page.len() != logical_page_size + INDEX_CHECKSUM_SIZE as usize {
        return None;
    }

    let mut footer = &page[logical_page_size..];
    let first = (u16::read(&mut footer).ok()?, u32::read(&mut footer).ok()?);
    let second = (u16::read(&mut footer).ok()?, u32::read(&mut footer).ok()?);
    let slots = if first.0 >= second.0 {
        [first, second]
    } else {
        [second, first]
    };
    slots.into_iter().find_map(|(len, checksum)| {
        let len = len as usize;
        (len != 0 && len <= logical_page_size && Crc32::checksum(&page[..len]) == checksum)
            .then_some(len as u64)
    })
}

impl Damage {
    fn differing_ranges(before: &[u8], after: &[u8]) -> Vec<ByteRange> {
        let len = before.len().max(after.len());
        let mut ranges = Vec::new();
        let mut start = None;
        for offset in 0..len {
            if before.get(offset) != after.get(offset) {
                start.get_or_insert(offset);
            } else if let Some(start) = start.take() {
                ranges.push(ByteRange {
                    start: start as u64,
                    end: offset as u64,
                });
            }
        }
        if let Some(start) = start {
            ranges.push(ByteRange {
                start: start as u64,
                end: len as u64,
            });
        }
        ranges
    }

    fn from_snapshots(
        index_before: &BTreeMap<u64, Vec<u8>>,
        index_after: &BTreeMap<u64, Vec<u8>>,
        values_before: &BTreeMap<u64, Vec<u8>>,
        values_after: &BTreeMap<u64, Vec<u8>>,
    ) -> Self {
        let mut damage = Self {
            index_after: index_after.clone(),
            ..Self::default()
        };
        for section in 1u64..=3 {
            let empty = Vec::new();
            let ranges = Self::differing_ranges(
                index_before.get(&section).unwrap_or(&empty),
                index_after.get(&section).unwrap_or(&empty),
            );
            if !ranges.is_empty() {
                damage.index.insert(section, ranges);
            }
            let ranges = Self::differing_ranges(
                values_before.get(&section).unwrap_or(&empty),
                values_after.get(&section).unwrap_or(&empty),
            );
            if !ranges.is_empty() {
                damage.values.insert(section, ranges);
            }
        }
        damage
    }

    /// Whether corruption leaves any page needed by `logical_range` without a checksum-valid
    /// prefix covering those bytes.
    fn index_range_unreadable(&self, section: u64, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        let Some(ranges) = self.index.get(&section) else {
            return false;
        };
        let after = self.index_after.get(&section).map(Vec::as_slice);
        let logical_page_size = u64::from(PAGE_SIZE.get());
        let physical_page_size = logical_page_size + INDEX_CHECKSUM_SIZE;
        let first_page = start / logical_page_size;
        let last_page = (end - 1) / logical_page_size;

        (first_page..=last_page).any(|page| {
            let logical_page_start = page * logical_page_size;
            let physical_page_start = page * physical_page_size;
            let physical_page = ByteRange {
                start: physical_page_start,
                end: physical_page_start + physical_page_size,
            };
            if !ranges.iter().any(|range| range.intersects(physical_page)) {
                return false;
            }

            let Some(page_bytes) = after.and_then(|bytes| {
                let start = usize::try_from(physical_page_start).ok()?;
                let end = usize::try_from(physical_page.end).ok()?;
                bytes.get(start..end)
            }) else {
                return true;
            };
            let required_end = end
                .min(logical_page_start + logical_page_size)
                .saturating_sub(logical_page_start);
            recoverable_index_page_len(page_bytes).is_none_or(|len| len < required_end)
        })
    }

    /// Whether any logical payload byte in `logical_range` changed, regardless of whether a
    /// checksum slot was also changed to authenticate the new payload.
    fn index_payload_damaged(&self, section: u64, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        let Some(ranges) = self.index.get(&section) else {
            return false;
        };
        let logical_page_size = u64::from(PAGE_SIZE.get());
        let physical_page_size = logical_page_size + INDEX_CHECKSUM_SIZE;
        let first_page = start / logical_page_size;
        let last_page = (end - 1) / logical_page_size;

        (first_page..=last_page).any(|page| {
            let logical_page_start = page * logical_page_size;
            let physical_page_start = page * physical_page_size;
            let target = ByteRange {
                start: physical_page_start + start.saturating_sub(logical_page_start),
                end: physical_page_start
                    + end
                        .min(logical_page_start + logical_page_size)
                        .saturating_sub(logical_page_start),
            };
            ranges.iter().any(|range| range.intersects(target))
        })
    }

    fn index_range_damaged(&self, section: u64, start: u64, end: u64) -> bool {
        self.index_range_unreadable(section, start, end)
            || self.index_payload_damaged(section, start, end)
    }

    fn value_range_damaged(&self, section: u64, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        self.values.get(&section).is_some_and(|ranges| {
            let target = ByteRange { start, end };
            ranges.iter().any(|range| range.intersects(target))
        })
    }

    fn section_damaged(&self, section: u64) -> bool {
        self.index.contains_key(&section) || self.values.contains_key(&section)
    }
}

async fn snapshot_partition<E: commonware_runtime::Storage>(
    context: &E,
    partition: &str,
) -> BTreeMap<u64, Vec<u8>> {
    let mut snapshot = BTreeMap::new();
    for name in context.scan(partition).await.expect("snapshot scan failed") {
        let Ok(name) = <[u8; 8]>::try_from(name.as_slice()) else {
            continue;
        };
        let section = u64::from_be_bytes(name);
        let (blob, size) = context
            .open(partition, &name)
            .await
            .expect("snapshot open failed");
        let bytes = if size == 0 {
            Vec::new()
        } else {
            blob.read_at(0, usize::try_from(size).expect("snapshot blob too large"))
                .await
                .expect("snapshot read failed")
                .coalesce()
                .as_ref()
                .to_vec()
        };
        snapshot.insert(section, bytes);
    }
    snapshot
}

fn corruption_section(message: &str) -> Option<u64> {
    let section = message.strip_prefix("section ")?;
    section[..section.find(' ')?].parse().ok()
}

fn boundary_value_range(
    expected: &BTreeMap<u64, Vec<(TestEntry, TestValue)>>,
    section: u64,
    index_size: u64,
) -> Option<ByteRange> {
    let count = usize::try_from(index_size / TestEntry::SIZE as u64)
        .expect("fuzzed entry count fits usize");
    if count == 0 {
        return None;
    }
    let (entry, _) = expected
        .get(&section)
        .and_then(|entries| entries.get(count - 1))
        .expect("checkpoint cannot exceed generated entries");
    let (offset, size) = entry.value_location();
    Some(ByteRange {
        start: offset,
        end: offset + u64::from(size),
    })
}

fn test_cfg(pooler: &impl BufferPooler) -> Config<()> {
    Config {
        index_partition: INDEX_PARTITION.into(),
        value_partition: VALUE_PARTITION.into(),
        index_page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        index_write_buffer: NZUsize!(512),
        value_write_buffer: NZUsize!(512),
        compression: None,
        codec_config: (),
    }
}

fn crash_cfg(pooler: &impl BufferPooler, compression: bool) -> Config<()> {
    Config {
        index_partition: INDEX_PARTITION.into(),
        value_partition: VALUE_PARTITION.into(),
        // An entry spans several pages and both write buffers flush immediately, leaving actual
        // dirty index/value writes for the runtime to sample at the crash boundary.
        index_page_cache: CacheRef::from_pooler(pooler, CRASH_PAGE_SIZE, PAGE_CACHE_SIZE),
        index_write_buffer: NZUsize!(1),
        value_write_buffer: NZUsize!(1),
        compression: compression.then_some(3),
        codec_config: (),
    }
}

async fn populate(
    context: deterministic::Context,
    cfg: Config<()>,
    entries_per_section: [u8; 3],
) -> (TestJournal, Expected) {
    let mut replay =
        Oversized::<_, TestEntry, TestValue>::init(context, cfg, BTreeMap::new(), NZUsize!(512))
            .await
            .expect("setup init failed");
    while let Some(result) = replay.next().await {
        result.expect("setup replay failed");
    }
    let mut journal = replay.finish().expect("setup replay finish failed");

    let mut entry_id = 0u64;
    let mut expected = Expected::new();
    for (section_idx, count) in entries_per_section.into_iter().enumerate() {
        let section = (section_idx + 1) as u64;
        let count = (count % 10) + 1;
        for _ in 0..count {
            let value = [entry_id as u8; 16];
            let (position, offset, size);
            (journal, position, offset, size) = journal
                .append(section, TestEntry::new(entry_id), &value)
                .await
                .expect("setup append failed");
            assert_eq!(
                position as usize,
                expected.entry(section).or_default().len()
            );
            expected
                .get_mut(&section)
                .expect("section was just inserted")
                .push((TestEntry::new(entry_id).with_location(offset, size), value));
            entry_id += 1;
        }
    }
    (journal, expected)
}

async fn recover(
    context: deterministic::Context,
    cfg: Config<()>,
    checkpoint: BTreeMap<u64, u64>,
) -> Result<TestJournal, JournalError> {
    let mut replay =
        Oversized::<_, TestEntry, TestValue>::init(context, cfg, checkpoint, NZUsize!(512)).await?;
    while let Some(result) = replay.next().await {
        result?;
    }
    replay.finish()
}

/// Verify organic crash recovery returned exact prefixes of the attempted section contents.
async fn recovered_prefix(journal: &TestJournal, expected: &Expected) -> Expected {
    let chunk = TestEntry::SIZE as u64;
    let mut actual = Expected::new();
    for (&section, attempted) in expected {
        let retained = match journal.size(section) {
            Ok(retained) => retained,
            Err(JournalError::SectionOutOfRange(_)) => 0,
            Err(err) => panic!("recovered section size failed: {err:?}"),
        };
        assert!(retained.is_multiple_of(chunk));
        let retained_count = usize::try_from(retained / chunk).unwrap();
        assert!(
            retained_count <= attempted.len(),
            "section {section} recovered {retained_count} entries after {} appends",
            attempted.len()
        );

        let recovered = actual.entry(section).or_default();
        for (position, (expected_entry, expected_value)) in
            attempted.iter().take(retained_count).enumerate()
        {
            let entry = journal
                .get(section, position as u64)
                .await
                .expect("retained crash-recovered entry must be readable");
            assert_eq!(entry, *expected_entry, "recovered entry changed");
            let (offset, size) = entry.value_location();
            let value = journal
                .get_value(section, offset, size)
                .await
                .expect("retained crash-recovered value must be readable");
            assert_eq!(value, *expected_value, "recovered value changed");
            recovered.push((entry, value));
        }
        assert!(matches!(
            journal.get(section, retained_count as u64).await,
            Err(JournalError::ItemOutOfRange(_) | JournalError::SectionOutOfRange(_))
        ));
    }
    actual
}

fn fuzz_corruption(input: CorruptionInput) {
    let runner = fuzz_runner(&input.raw_bytes);

    let (recovery, runtime_checkpoint) = runner.start_and_recover(move |context| async move {
        let cfg = test_cfg(&context);

        // Phase 1: Create valid data.
        let (oversized, expected) = populate(
            context.child("initial"),
            cfg.clone(),
            input.entries_per_section,
        )
        .await;

        // Both branches await durability, so every retained byte is acknowledged. They differ
        // only in how much of that the caller published as its floor.
        let oversized = match input.sync_mode {
            SyncMode::BackgroundUnpublished => {
                let (journal, handle) = oversized
                    .start_sync([1, 2, 3])
                    .await
                    .expect("setup start_sync failed");
                handle.await.expect("setup background sync failed");
                journal
            }
            SyncMode::BlockingStaleFloor | SyncMode::BlockingFullFloor => {
                oversized.sync_all().await.expect("setup sync_all failed")
            }
        };
        let synced = (1u64..=3)
            .filter_map(|section| oversized.size(section).ok().map(|size| (section, size)))
            .collect::<BTreeMap<_, _>>();
        drop(oversized);

        // A background sync publishes nothing until a later sync carries it, a blocking sync
        // publishes the sizes it just proved durable, and a skipped publication leaves a floor
        // one interval behind. Floors must be item-aligned.
        let chunk = TestEntry::SIZE as u64;
        let checkpoint = match input.sync_mode {
            SyncMode::BackgroundUnpublished => BTreeMap::new(),
            SyncMode::BlockingStaleFloor => synced
                .iter()
                .map(|(&section, &size)| (section, (size / (2 * chunk)) * chunk))
                .collect(),
            SyncMode::BlockingFullFloor => synced.clone(),
        };
        let index_before = snapshot_partition(&context, INDEX_PARTITION).await;
        let values_before = snapshot_partition(&context, VALUE_PARTITION).await;

        // Phase 2: Apply corruptions
        for corruption in &input.corruptions {
            match corruption {
                CorruptionType::TruncateIndex {
                    section,
                    size_factor,
                } => {
                    if let Ok((blob, size)) =
                        context.open(INDEX_PARTITION, &section.to_be_bytes()).await
                    {
                        let new_size = (size * (*size_factor as u64)) / 256;
                        let _ = blob.resize(new_size).await;
                        let _ = blob.sync().await;
                    }
                }
                CorruptionType::TruncateGlob {
                    section,
                    size_factor,
                } => {
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                    {
                        let new_size = (size * (*size_factor as u64)) / 256;
                        let _ = blob.resize(new_size).await;
                        let _ = blob.sync().await;
                    }
                }
                CorruptionType::CorruptIndexBytes {
                    section,
                    offset_factor,
                    data,
                } => {
                    if let Ok((blob, size)) =
                        context.open(INDEX_PARTITION, &section.to_be_bytes()).await
                        && size > 0
                    {
                        let offset = (size * (*offset_factor as u64)) / 256;
                        let _ = blob.write_at_sync(offset, data.to_vec()).await;
                    }
                }
                CorruptionType::CorruptGlobBytes {
                    section,
                    offset_factor,
                    data,
                } => {
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                        && size > 0
                    {
                        let offset = (size * (*offset_factor as u64)) / 256;
                        let _ = blob.write_at_sync(offset, data.to_vec()).await;
                    }
                }
                CorruptionType::DeleteIndex { section } => {
                    let _ = context
                        .remove(INDEX_PARTITION, Some(&section.to_be_bytes()))
                        .await;
                }
                CorruptionType::DeleteGlob { section } => {
                    let _ = context
                        .remove(VALUE_PARTITION, Some(&section.to_be_bytes()))
                        .await;
                }
                CorruptionType::ExtendIndex { section, garbage } => {
                    if let Ok((blob, size)) =
                        context.open(INDEX_PARTITION, &section.to_be_bytes()).await
                    {
                        let _ = blob.write_at_sync(size, garbage.to_vec()).await;
                    }
                }
                CorruptionType::ExtendGlob { section, garbage } => {
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                    {
                        let _ = blob.write_at_sync(size, garbage.to_vec()).await;
                    }
                }
            }
        }

        let index_after = snapshot_partition(&context, INDEX_PARTITION).await;
        let values_after = snapshot_partition(&context, VALUE_PARTITION).await;
        let damage =
            Damage::from_snapshots(&index_before, &index_after, &values_before, &values_after);

        // Only damage to bytes vouched for by a section's own checkpoint can justify a loud
        // recovery failure. For the paged index, classify the actual post-corruption page through
        // both checksum slots so a damaged inactive slot cannot excuse an unrelated failure.
        let mut durable_damage_sections = BTreeSet::new();
        for (&section, &floor) in &checkpoint {
            // Recovery eagerly validates only the boundary value at the floor. Earlier values
            // are authenticated lazily by get_value and therefore cannot explain init failure.
            let boundary_value_damaged = boundary_value_range(&expected, section, floor)
                .is_some_and(|range| damage.value_range_damaged(section, range.start, range.end));
            if damage.index_range_damaged(section, 0, floor) || boundary_value_damaged {
                durable_damage_sections.insert(section);
            }
        }

        // Phase 3: Recovery - this should not panic
        let recovery = async {
            let mut replay = Oversized::<_, TestEntry, TestValue>::init(
                context.child("recovered"),
                cfg.clone(),
                checkpoint.clone(),
                NZUsize!(512),
            )
            .await?;
            while let Some(result) = replay.next().await {
                result?;
            }
            replay.finish()
        }
        .await;
        let mut recovered: Oversized<_, TestEntry, TestValue> = match recovery {
            Ok(recovered) => recovered,
            // Corruption identifies its section. Do not let damage in one section excuse a
            // failure in another, or damage above that section's floor excuse durable-prefix loss.
            Err(JournalError::Corruption(message))
                if corruption_section(&message)
                    .is_some_and(|section| durable_damage_sections.contains(&section)) =>
            {
                return None;
            }
            Err(err) => panic!("Unexpected recovery failure: {err:?}"),
        };

        // Verify every unaffected entry/value that recovery is required to retain. The durable
        // floor is always required. Above it, the contiguous prefix before the first damaged pair
        // is required; later valid pairs may legitimately be discarded with a damaged suffix.
        let chunk = TestEntry::SIZE as u64;
        for section in 1u64..=3 {
            let entries = &expected[&section];
            let index_size = synced[&section];
            let floor_count = (checkpoint.get(&section).copied().unwrap_or(0) / chunk) as usize;
            let boundary_index_damaged = if floor_count == 0 {
                false
            } else {
                let start = (floor_count - 1) as u64 * chunk;
                let end = floor_count as u64 * chunk;
                damage.index_range_damaged(section, start, end)
            };
            let required_count = if boundary_index_damaged {
                // A checksum-valid mutation of the unauthenticated boundary entry can change the
                // value anchor and make every otherwise intact pair above the floor noncontiguous.
                floor_count
            } else {
                (floor_count..entries.len())
                    .find(|&position| {
                        let logical_start = position as u64 * chunk;
                        let (entry, _) = &entries[position];
                        let (offset, size) = entry.value_location();
                        damage.index_range_damaged(section, logical_start, logical_start + chunk)
                            || damage.value_range_damaged(section, offset, offset + u64::from(size))
                    })
                    .unwrap_or(entries.len())
            };

            let retained = recovered
                .size(section)
                .expect("recovered section size must be readable");
            // The unauthenticated format may adopt a checksum-valid suffix forged by corruption.
            // Clamp to the generated extent so such a suffix cannot satisfy an original-prefix
            // retention requirement.
            let retained_generated = retained.min(entries.len() as u64 * chunk);
            assert!(
                retained_generated >= required_count as u64 * chunk,
                "section {section} retained {retained_generated} generated bytes, below required intact prefix of {}",
                required_count as u64 * chunk
            );
            if !damage.section_damaged(section) {
                assert_eq!(
                    retained, index_size,
                    "untouched section {section} changed size during recovery"
                );
            }

        }

        // Phase 4: Every position recovery claims to retain, including any checksum-valid forged
        // suffix, must be readable and contiguous. Values below the durable boundary are checked
        // lazily, so deliberately damaged ones may still fail on access; every retained value above
        // the boundary was validated during repair.
        for section in 1u64..=3 {
            let retained = recovered
                .size(section)
                .expect("recovered section size must be readable");
            assert!(retained.is_multiple_of(chunk));
            let retained_count = retained / chunk;
            let floor_count = checkpoint.get(&section).copied().unwrap_or(0) / chunk;
            let mut contiguous_end = None;
            for position in 0..retained_count {
                let entry = recovered
                    .get(section, position)
                    .await
                    .expect("retained entry must be readable");
                let (offset, size) = entry.value_location();
                let value = recovered.get_value(section, offset, size).await;
                if position >= floor_count {
                    if let Some(expected_offset) = contiguous_end {
                        assert_eq!(
                            offset, expected_offset,
                            "recovered tail is not contiguous in section {section} at position {position}"
                        );
                    }
                    contiguous_end = Some(
                        offset
                            .checked_add(u64::from(size))
                            .expect("recovered value range must not overflow"),
                    );
                } else if position + 1 == floor_count {
                    contiguous_end = Some(
                        offset
                            .checked_add(u64::from(size))
                            .expect("durable boundary value range must not overflow"),
                    );
                }
                if position >= floor_count {
                    value
                        .as_ref()
                        .expect("recovery must validate every retained tail value");
                }

                let Some((expected_entry, expected_value)) =
                    expected[&section].get(position as usize)
                else {
                    continue;
                };
                let logical_start = position * chunk;
                if !damage.index_range_damaged(section, logical_start, logical_start + chunk) {
                    assert_eq!(entry, *expected_entry, "unaffected retained entry changed");
                }
                let (expected_offset, expected_size) = expected_entry.value_location();
                if entry == *expected_entry
                    && !damage.value_range_damaged(
                        section,
                        expected_offset,
                        expected_offset + u64::from(expected_size),
                    )
                {
                    assert_eq!(
                        value.expect("unaffected retained value must be readable"),
                        *expected_value,
                        "unaffected retained value changed"
                    );
                }
            }
            assert!(matches!(
                recovered.get(section, retained_count).await,
                Err(JournalError::ItemOutOfRange(_) | JournalError::SectionOutOfRange(_))
            ));
        }

        // Phase 5: Append distinct sentinels and make both the repairs and sentinels durable.
        let mut sentinels = BTreeMap::new();
        for section in 1u64..=3 {
            let value: TestValue = [0xFF; 16];
            let id = u64::MAX - section;
            let (position, offset, size);
            (recovered, position, offset, size) = recovered
                .append(section, TestEntry::new(id), &value)
                .await
                .expect("append after corruption recovery should succeed");
            sentinels.insert(
                section,
                (
                    position,
                    TestEntry::new(id).with_location(offset, size),
                    value,
                ),
            );
        }

        recovered = recovered
            .sync_all()
            .await
            .expect("post-corruption recovery sync should succeed");
        let durable_ends = (1u64..=3)
            .map(|section| (section, recovered.size(section).unwrap()))
            .collect::<BTreeMap<_, _>>();
        drop(recovered);
        Some((sentinels, durable_ends))
    });

    let Some((sentinels, durable_ends)) = recovery else {
        return;
    };

    // Cross a real crash boundary and prove the successfully repaired state remains appendable and
    // durable on the next boot.
    deterministic::Runner::from(runtime_checkpoint).start(move |context| async move {
        let cfg = test_cfg(&context);
        let journal = recover(context.child("final"), cfg, durable_ends.clone())
            .await
            .expect("final corruption recovery should succeed");
        for (&section, (position, expected_entry, expected_value)) in &sentinels {
            assert_eq!(journal.size(section).unwrap(), durable_ends[&section]);
            let entry = journal
                .get(section, *position)
                .await
                .expect("durable corruption-recovery sentinel must be readable");
            assert_eq!(entry, *expected_entry, "durable sentinel entry changed");
            let (offset, size) = entry.value_location();
            let value = journal
                .get_value(section, offset, size)
                .await
                .expect("durable corruption-recovery sentinel value must be readable");
            assert_eq!(value, *expected_value, "durable sentinel value changed");
        }
        journal
            .destroy()
            .await
            .expect("destroy after corruption recovery should succeed");
    });
}

fn fuzz_crash_recovery(input: CrashRecoveryInput) {
    let runner = fuzz_runner(&input.raw_bytes);
    let compression = input.compression;
    let entries_per_section = input.entries_per_section;
    let prune_min = u64::from(input.prune_min % 4) + 1;

    // Tiny buffers make every accepted index/value append reach the runtime as a dirty write.
    // Recovering the checkpoint then samples arbitrary surviving subsets of those writes.
    let (attempted, runtime_checkpoint) = runner.start_and_recover(move |context| async move {
        let cfg = crash_cfg(&context, compression);
        let (journal, expected) =
            populate(context.child("initial"), cfg, entries_per_section).await;
        drop(journal);
        expected
    });

    // Recover an exact prefix from each section, append a sentinel, and make the resulting model
    // durable before crossing a second crash boundary.
    let ((expected, durable_ends), runtime_checkpoint) = deterministic::Runner::from(
        runtime_checkpoint,
    )
    .start_and_recover(move |context| async move {
        let cfg = crash_cfg(&context, compression);
        let mut journal = recover(context.child("recovered"), cfg, BTreeMap::new())
            .await
            .expect("organic crash recovery should succeed");
        let mut actual = recovered_prefix(&journal, &attempted).await;

        (journal, _) = journal
            .prune(prune_min)
            .await
            .expect("prune after organic crash recovery should succeed");
        for section in 1..prune_min {
            actual.insert(section, Vec::new());
        }

        for section in prune_min..=3 {
            let value = [0xFF; 16];
            let id = u64::MAX - section;
            let (position, offset, size);
            (journal, position, offset, size) = journal
                .append(section, TestEntry::new(id), &value)
                .await
                .expect("append after organic crash recovery should succeed");
            let section_entries = actual.get_mut(&section).unwrap();
            assert_eq!(position as usize, section_entries.len());
            section_entries.push((TestEntry::new(id).with_location(offset, size), value));
        }

        journal = journal
            .sync_all()
            .await
            .expect("post-recovery sync should succeed");
        let durable_ends = (prune_min..=3)
            .map(|section| (section, journal.size(section).unwrap()))
            .collect();
        drop(journal);
        (actual, durable_ends)
    });

    const INTERRUPTED_PRUNE_MIN: u64 = 12;
    let ((expected, post_prune_checkpoint, prune_completed), runtime_checkpoint) =
        deterministic::Runner::from(runtime_checkpoint).start_and_recover(
            move |context| async move {
                let cfg = crash_cfg(&context, compression);
                let mut journal = recover(context.child("final"), cfg, durable_ends)
                    .await
                    .expect("final organic crash recovery should succeed");
                assert_eq!(recovered_prefix(&journal, &expected).await, expected);

                let mut expected = expected;
                for section in 10..=INTERRUPTED_PRUNE_MIN {
                    let value = [section as u8; 16];
                    let (position, offset, size);
                    (journal, position, offset, size) = journal
                        .append(section, TestEntry::new(section), &value)
                        .await
                        .expect("pre-prune append should succeed");
                    let entries = expected.entry(section).or_default();
                    assert_eq!(position as usize, entries.len());
                    entries.push((TestEntry::new(section).with_location(offset, size), value));
                }
                journal = journal
                    .sync_all()
                    .await
                    .expect("pre-prune sync should succeed");

                // Invalidate checkpoint floors below the requested prune before production removes
                // their sections. Recovery may retain all old physical sections or discard them
                // through the one atomic removal batch.
                let post_prune_checkpoint = expected
                    .keys()
                    .filter(|&&section| section >= INTERRUPTED_PRUNE_MIN)
                    .filter_map(|&section| journal.size(section).ok().map(|size| (section, size)))
                    .collect();
                *context.storage_fault_config().write() = batch_faults();
                let prune_completed = journal.prune(INTERRUPTED_PRUNE_MIN).await.is_ok();
                (expected, post_prune_checkpoint, prune_completed)
            },
        );

    deterministic::Runner::from(runtime_checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let cfg = crash_cfg(&context, compression);
        let journal = recover(context.child("prune_recovery"), cfg, post_prune_checkpoint)
            .await
            .expect("oversized journal must reopen after interrupted prune");
        let recovered = recovered_prefix(&journal, &expected).await;
        let mut fully_pruned = expected.clone();
        for (&section, entries) in &mut fully_pruned {
            if section < INTERRUPTED_PRUNE_MIN {
                entries.clear();
            }
        }
        if prune_completed {
            assert_eq!(
                recovered, fully_pruned,
                "completed prune did not recover its committed state"
            );
        } else {
            assert!(
                recovered == expected || recovered == fully_pruned,
                "interrupted atomic prune recovered neither its old nor committed state"
            );
        }

        let (journal, _) = journal
            .prune(INTERRUPTED_PRUNE_MIN)
            .await
            .expect("prune retry must succeed");
        journal
            .destroy()
            .await
            .expect("cleanup destroy must succeed");
    });
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::Corruption(input) => fuzz_corruption(input),
        FuzzInput::CrashRecovery(input) => fuzz_crash_recovery(input),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
