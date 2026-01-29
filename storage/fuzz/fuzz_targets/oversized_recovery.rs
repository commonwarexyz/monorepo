#![no_main]

//! Fuzz test for oversized journal crash recovery.
//!
//! This test creates valid data, randomly corrupts storage, and verifies
//! that recovery doesn't panic and leaves the journal in a consistent state.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Blob as _, Buf, BufMut, Metrics, Runner, Storage as _,
};
use commonware_storage::journal::segmented::oversized::{Config, Oversized, Record};
use commonware_utils::{NZUsize, NZU16};
use libfuzzer_sys::fuzz_target;
use std::num::{NonZeroU16, NonZeroUsize};

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
const INDEX_PARTITION: &str = "fuzz_index";
const VALUE_PARTITION: &str = "fuzz_values";

fn test_cfg() -> Config<()> {
    Config {
        index_partition: INDEX_PARTITION.to_string(),
        value_partition: VALUE_PARTITION.to_string(),
        index_page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        index_write_buffer: NZUsize!(512),
        value_write_buffer: NZUsize!(512),
        compression: None,
        codec_config: (),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = test_cfg();

        // Phase 1: Create valid data
        let mut oversized: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.with_label("initial"), cfg.clone())
                .await
                .expect("Failed to init");

        let mut entry_id = 0u64;
        for (section_idx, &count) in input.entries_per_section.iter().enumerate() {
            let section = (section_idx + 1) as u64;
            let count = (count % 10) + 1; // 1-10 entries per section

            for _ in 0..count {
                let value: TestValue = [entry_id as u8; 16];
                let entry = TestEntry::new(entry_id);
                let _ = oversized.append(section, entry, &value).await;
                entry_id += 1;
            }
            let _ = oversized.sync(section).await;
        }

        if input.sync_before_corrupt {
            let _ = oversized.sync_all().await;
        }
        drop(oversized);

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
                    {
                        if size > 0 {
                            let offset = (size * (*offset_factor as u64)) / 256;
                            let _ = blob.write_at(offset, data.to_vec()).await;
                            let _ = blob.sync().await;
                        }
                    }
                }
                CorruptionType::CorruptGlobBytes {
                    section,
                    offset_factor,
                    data,
                } => {
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                    {
                        if size > 0 {
                            let offset = (size * (*offset_factor as u64)) / 256;
                            let _ = blob.write_at(offset, data.to_vec()).await;
                            let _ = blob.sync().await;
                        }
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
                        let _ = blob.write_at(size, garbage.to_vec()).await;
                        let _ = blob.sync().await;
                    }
                }
                CorruptionType::ExtendGlob { section, garbage } => {
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                    {
                        let _ = blob.write_at(size, garbage.to_vec()).await;
                        let _ = blob.sync().await;
                    }
                }
            }
        }

        // Phase 3: Recovery - this should not panic
        let mut recovered: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.with_label("recovered"), cfg.clone())
                .await
                .expect("Recovery should not fail");

        // Phase 4: Verify get operations don't panic
        // Note: Value checksums are verified lazily on read, not during recovery.
        // So an entry may exist but get_value() may return ChecksumMismatch - this is expected.
        for section in 1u64..=3 {
            let mut pos = 0u64;
            while let Ok(entry) = recovered.get(section, pos).await {
                // Entry exists, verify get_value doesn't panic (may return error)
                let (offset, size) = entry.value_location();
                let _ = recovered.get_value(section, offset, size).await;
                pos += 1;
            }
        }

        // Phase 5: Verify we can append after recovery
        for section in 1u64..=3 {
            let value: TestValue = [0xFF; 16];
            let entry = TestEntry::new(u64::MAX);
            let append_result = recovered.append(section, entry, &value).await;

            // Append should succeed (recovery should have left journal in appendable state)
            assert!(
                append_result.is_ok(),
                "Should be able to append to section {section} after recovery"
            );
        }

        let _ = recovered.destroy().await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
