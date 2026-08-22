#![no_main]

//! Fuzz test for oversized journal crash recovery.
//!
//! This test creates valid data, randomly corrupts storage, and verifies
//! that recovery doesn't panic and leaves the journal in a consistent state.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use commonware_runtime::{
    Blob as _, Buf, BufMut, BufferPooler, Error as RuntimeError, Runner, Storage as _,
    Supervisor as _, WriteOptions, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::journal::{
    Error as JournalError,
    segmented::oversized::{Config, Oversized, Record},
};
use commonware_storage_fuzz::IndexMutations;
use commonware_utils::{NZU16, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeSet,
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
    ExtendIndex { section: u64 },
    /// Extend glob with garbage
    ExtendGlob { section: u64 },
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
            }),
            _ => Ok(CorruptionType::ExtendGlob {
                section: u.int_in_range(1..=3)?,
            }),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Number of entries per section (1-10)
    entries_per_section: [u8; 3],
    /// Corruptions to apply before recovery
    corruptions: Vec<CorruptionType>,
    /// Whether to sync before corruption
    sync_before_corrupt: bool,
}

const PAGE_SIZE: NonZeroU16 = NZU16!(128);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(4);
const INDEX_PARTITION: &str = "fuzz-index";
const VALUE_PARTITION: &str = "fuzz-values";

// Fixed invalid extensions cannot replay an authenticated page or value frame into a truncated
// section, so every CRC-valid record remains suitable for the entry-identity oracle.
const INDEX_EXTENSION: [u8; 32] = [0xFF; 32];
const VALUE_EXTENSION: [u8; 64] = [0xFF; 64];

fn overlaps_existing_blob(offset: u64, write_len: usize, blob_size: u64) -> bool {
    let end = offset.saturating_add(write_len as u64);
    offset < blob_size && end > offset
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

async fn assert_adopted_entries_consistent(
    oversized: &Oversized<deterministic::Context, TestEntry, TestValue>,
) {
    for section in 1u64..=3 {
        let mut position = 0;
        loop {
            let entry = match oversized.get(section, position).await {
                Ok(entry) => entry,
                Err(
                    JournalError::AlreadyPrunedToSection(_)
                    | JournalError::ItemOutOfRange(_)
                    | JournalError::SectionOutOfRange(_),
                ) => break,
                Err(err) => {
                    panic!("entry {section}:{position} produced an unexpected index error: {err:?}")
                }
            };
            let (offset, size) = entry.value_location();
            match oversized.get_value(section, offset, size).await {
                Ok(value) => assert_eq!(
                    value, [entry.id as u8; 16],
                    "entry {section}:{position} adopted another record's value bytes",
                ),
                Err(JournalError::ChecksumMismatch(_, _)) => {}
                Err(err) => {
                    panic!("entry {section}:{position} produced an unexpected value error: {err:?}")
                }
            }
            position += 1;
        }
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = test_cfg(&context);

        // Phase 1: Create valid data
        let mut oversized: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.child("initial"), cfg.clone(), None)
                .await
                .expect("Failed to init");

        let mut entry_id = 0u64;
        for (section_idx, &count) in input.entries_per_section.iter().enumerate() {
            let section = (section_idx + 1) as u64;
            let count = (count % 10) + 1; // 1-10 entries per section

            for _ in 0..count {
                let value: TestValue = [entry_id as u8; 16];
                let entry = TestEntry::new(entry_id);
                (oversized, _, _, _) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("setup append failed");
                entry_id += 1;
            }
            oversized = oversized.sync(section).await.expect("setup sync failed");
        }

        if input.sync_before_corrupt {
            let _ = oversized.sync_all().await.expect("setup sync_all failed");
        } else {
            drop(oversized);
        }

        // Phase 2: Apply corruptions
        // A successful checksum authenticates bytes for this oracle. Limit each journal section
        // to one byte-producing mutation so the mutator cannot assemble a replacement payload and
        // matching checksum across an extension and later overwrite. Truncations remain composable.
        let mut index_mutations = IndexMutations::default();
        let mut modified_value_sections = BTreeSet::new();
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
                    if !index_mutations.can_modify(*section) {
                        continue;
                    }
                    if let Ok((blob, size)) =
                        context.open(INDEX_PARTITION, &section.to_be_bytes()).await
                        && size > 0
                    {
                        let offset = (size * (*offset_factor as u64)) / 256;
                        // Overwriting existing index bytes can invalidate the fixed-journal
                        // page-integrity checks. Pure extensions/truncations are handled by
                        // lower-level tail trimming and should not require this allowance.
                        let result = blob
                            .write_at(offset, data.to_vec(), WriteOptions::SYNC)
                            .await;
                        if result.is_ok() && overlaps_existing_blob(offset, data.len(), size) {
                            index_mutations.record_overwrite(*section);
                        }
                    }
                }
                CorruptionType::CorruptGlobBytes {
                    section,
                    offset_factor,
                    data,
                } => {
                    if modified_value_sections.contains(section) {
                        continue;
                    }
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                        && size > 0
                    {
                        let offset = (size * (*offset_factor as u64)) / 256;
                        let result = blob
                            .write_at(offset, data.to_vec(), WriteOptions::SYNC)
                            .await;
                        if result.is_ok() && overlaps_existing_blob(offset, data.len(), size) {
                            modified_value_sections.insert(*section);
                        }
                    }
                }
                CorruptionType::DeleteIndex { section } => {
                    if context
                        .remove(INDEX_PARTITION, Some(&section.to_be_bytes()))
                        .await
                        .is_ok()
                    {
                        index_mutations.remove(*section);
                    }
                }
                CorruptionType::DeleteGlob { section } => {
                    if context
                        .remove(VALUE_PARTITION, Some(&section.to_be_bytes()))
                        .await
                        .is_ok()
                    {
                        modified_value_sections.remove(section);
                    }
                }
                CorruptionType::ExtendIndex { section } => {
                    if !index_mutations.can_modify(*section) {
                        continue;
                    }
                    if let Ok((blob, size)) =
                        context.open(INDEX_PARTITION, &section.to_be_bytes()).await
                        && blob
                            .write_at(size, INDEX_EXTENSION.to_vec(), WriteOptions::SYNC)
                            .await
                            .is_ok()
                    {
                        index_mutations.record_extension(*section);
                    }
                }
                CorruptionType::ExtendGlob { section } => {
                    if modified_value_sections.contains(section) {
                        continue;
                    }
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                        && blob
                            .write_at(size, VALUE_EXTENSION.to_vec(), WriteOptions::SYNC)
                            .await
                            .is_ok()
                    {
                        modified_value_sections.insert(*section);
                    }
                }
            }
        }

        // Phase 3: Recovery - this should not panic
        let mut recovered: Oversized<_, TestEntry, TestValue> =
            match Oversized::init(context.child("recovered"), cfg.clone(), None).await {
                Ok(recovered) => recovered,
                // Existing-byte overwrites in the paged index can invalidate fixed-journal
                // integrity checks before oversized recovery has a chance to inspect entries.
                Err(JournalError::Runtime(RuntimeError::InvalidChecksum))
                    if index_mutations.may_accept_invalid_checksum() =>
                {
                    return;
                }
                Err(err) => panic!("Unexpected recovery failure: {err:?}"),
            };

        // Phase 4: Every readable value must still belong to the entry that references it. Older
        // value checksums are lazy and may fail, but a valid retained frame cannot be adopted by a
        // different entry after truncation and offset reuse.
        assert_adopted_entries_consistent(&recovered).await;

        // Phase 5: Append after recovery, make the new locations durable, and reopen. This turns
        // stale-index/offset-reuse bugs into a value-identity failure rather than merely proving
        // that the first append call returned successfully.
        let mut sentinels = Vec::new();
        for section in 1u64..=3 {
            let value: TestValue = [0xFF; 16];
            let entry = TestEntry::new(u64::MAX);
            let position;
            (recovered, position, _, _) = recovered
                .append(section, entry, &value)
                .await
                .unwrap_or_else(|err| panic!("append to section {section} failed: {err:?}"));
            sentinels.push((section, position));
        }
        recovered = recovered.sync_all().await.expect("sentinel sync failed");
        drop(recovered);

        let reopened: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.child("reopened"), cfg, None)
                .await
                .expect("reopen after sentinel sync failed");
        assert_adopted_entries_consistent(&reopened).await;
        for (section, position) in sentinels {
            let entry = reopened
                .get(section, position)
                .await
                .expect("sentinel index missing");
            assert_eq!(entry.id, u64::MAX);
            let (offset, size) = entry.value_location();
            assert_eq!(
                reopened
                    .get_value(section, offset, size)
                    .await
                    .expect("sentinel value missing"),
                [0xFF; 16],
            );
        }

        let _ = reopened.destroy().await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
