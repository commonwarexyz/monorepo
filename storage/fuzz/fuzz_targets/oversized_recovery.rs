#![no_main]

//! Fuzz test for oversized journal crash recovery.
//!
//! This test creates valid data, randomly corrupts storage, and verifies
//! that recovery doesn't panic and leaves the journal in a consistent state.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, Buf, BufMut, BufferPooler, Error as RuntimeError, ReadOptions, Runner, Storage as _,
    Supervisor as _, WriteOptions, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::journal::{
    Error as JournalError,
    segmented::oversized::{Config, Oversized, Record},
};
use commonware_utils::{NZU16, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
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
const PAGE_CHECKSUM_RECORD_SIZE: usize = 12;
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(4);
const INDEX_PARTITION: &str = "fuzz-index";
const VALUE_PARTITION: &str = "fuzz-values";

#[derive(Clone, Copy)]
struct AuthenticatedIndex {
    logical_len: u64,
    surviving_physical_extent: u64,
}

/// Return whether changing a byte can alter the original checksum-proven index prefix.
///
/// Setup writes each page once, leaving the first checksum slot active and the second slot's
/// length at zero. While a section remains authenticated, earlier raw writes can only have changed
/// page padding, the inactive slot's checksum, or bytes beyond the original physical extent.
fn authenticates_original_index_byte(authenticated: AuthenticatedIndex, offset: u64) -> bool {
    if offset >= authenticated.surviving_physical_extent {
        return false;
    }
    let page_size = u64::from(PAGE_SIZE.get());
    let physical_page_size = page_size + PAGE_CHECKSUM_RECORD_SIZE as u64;
    let page = offset / physical_page_size;
    let in_page = offset % physical_page_size;
    let logical_start = page * page_size;
    if in_page < page_size {
        let authenticated_on_page = authenticated
            .logical_len
            .saturating_sub(logical_start)
            .min(page_size);
        return in_page < authenticated_on_page;
    }

    // The active slot and both slot lengths select the authenticated prefix. The final four bytes
    // are the checksum of the still-inactive second slot and have no effect while its length is 0.
    in_page - page_size < 8
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

/// Return whether any currently retained complete page lost bytes from the originally
/// authenticated logical prefix. Truncation and deletion are recoverable and therefore do not
/// count. Writes confined to page padding, an inactive footer slot, or an extension do not count.
async fn has_invalid_authenticated_index_page(
    context: &deterministic::Context,
    authenticated: &BTreeMap<u64, AuthenticatedIndex>,
) -> bool {
    let page_size = u64::from(PAGE_SIZE.get());
    let physical_page_size = page_size + PAGE_CHECKSUM_RECORD_SIZE as u64;
    for (&section, authenticated) in authenticated {
        let Ok((blob, size)) = context.open(INDEX_PARTITION, &section.to_be_bytes()).await else {
            continue;
        };
        let complete_pages = (size.min(authenticated.surviving_physical_extent)
            / physical_page_size)
            .min(authenticated.logical_len.div_ceil(page_size));
        for page in 0..complete_pages {
            let physical = blob
                .read_at(
                    page * physical_page_size,
                    physical_page_size as usize,
                    ReadOptions::default(),
                )
                .await
                .expect("oracle index read failed")
                .coalesce();
            let required = (authenticated.logical_len - page * page_size).min(page_size) as usize;
            if valid_page_len(physical.as_ref()).is_none_or(|len| len < required) {
                return true;
            }
        }
    }
    false
}

async fn exercise_readable_entries(
    oversized: &Oversized<deterministic::Context, TestEntry, TestValue>,
    authenticated: &BTreeMap<u64, Vec<u64>>,
) {
    for section in 1u64..=3 {
        if let Some(ids) = authenticated.get(&section) {
            for (position, &id) in ids.iter().enumerate() {
                let entry = oversized
                    .get(section, position as u64)
                    .await
                    .expect("authenticated index entry missing");
                assert_eq!(entry.id, id, "authenticated index entry changed");
                let (offset, size) = entry.value_location();
                assert_eq!(
                    oversized
                        .get_value(section, offset, size)
                        .await
                        .expect("authenticated value missing"),
                    [id as u8; 16],
                    "authenticated value changed",
                );
            }
            continue;
        }

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

            // This section's original bytes were externally mutated, and a CRC-valid index
            // rewrite can forge any value range. Exercise the read for bounded-error coverage.
            // Sections with preserved provenance and independently appended sentinels retain the
            // identity oracles.
            let (offset, size) = entry.value_location();
            let _ = oversized.get_value(section, offset, size).await;
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
        let mut authenticated_entries = BTreeMap::<u64, Vec<u64>>::new();
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
                authenticated_entries
                    .entry(section)
                    .or_default()
                    .push(entry_id);
                entry_id += 1;
            }
            oversized = oversized.sync(section).await.expect("setup sync failed");
        }

        if input.sync_before_corrupt {
            let _ = oversized.sync_all().await.expect("setup sync_all failed");
        } else {
            drop(oversized);
        }

        let page_size = u64::from(PAGE_SIZE.get());
        let physical_page_size = page_size + PAGE_CHECKSUM_RECORD_SIZE as u64;
        let mut authenticated_indices = input
            .entries_per_section
            .iter()
            .enumerate()
            .map(|(section, count)| {
                let logical_len = u64::from((count % 10) + 1) * TestEntry::SIZE as u64;
                (
                    section as u64 + 1,
                    AuthenticatedIndex {
                        logical_len,
                        surviving_physical_extent: logical_len.div_ceil(page_size)
                            * physical_page_size,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        // Phase 2: Apply corruptions.
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
                        if blob.resize(new_size).await.is_ok() {
                            authenticated_entries.remove(section);
                            if let Some(authenticated) = authenticated_indices.get_mut(section) {
                                authenticated.surviving_physical_extent =
                                    authenticated.surviving_physical_extent.min(new_size);
                            }
                            let _ = blob.sync().await;
                        }
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
                        if blob.resize(new_size).await.is_ok() {
                            authenticated_entries.remove(section);
                            let _ = blob.sync().await;
                        }
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
                        let existing = (size - offset).min(data.len() as u64) as usize;
                        let original = blob
                            .read_at(offset, existing, ReadOptions::default())
                            .await
                            .expect("oracle index read failed")
                            .coalesce();
                        let taints = authenticated_entries.contains_key(section)
                            && authenticated_indices
                                .get(section)
                                .is_some_and(|authenticated| {
                                    original.as_ref().iter().zip(data).enumerate().any(
                                        |(index, (&before, &after))| {
                                            before != after
                                                && authenticates_original_index_byte(
                                                    *authenticated,
                                                    offset + index as u64,
                                                )
                                        },
                                    )
                                });
                        if blob
                            .write_at(offset, data.to_vec(), WriteOptions::SYNC)
                            .await
                            .is_ok()
                            && taints
                        {
                            authenticated_entries.remove(section);
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
                        && size > 0
                    {
                        let offset = (size * (*offset_factor as u64)) / 256;
                        let existing = (size - offset).min(data.len() as u64) as usize;
                        let original = blob
                            .read_at(offset, existing, ReadOptions::default())
                            .await
                            .expect("oracle value read failed")
                            .coalesce();
                        let authenticated_len =
                            authenticated_entries.get(section).map_or(0, |ids| {
                                ids.len() as u64 * (TestValue::SIZE + u32::SIZE) as u64
                            });
                        let taints = original.as_ref().iter().zip(data).enumerate().any(
                            |(index, (&before, &after))| {
                                before != after && offset + (index as u64) < authenticated_len
                            },
                        );
                        if blob
                            .write_at(offset, data.to_vec(), WriteOptions::SYNC)
                            .await
                            .is_ok()
                            && taints
                        {
                            authenticated_entries.remove(section);
                        }
                    }
                }
                CorruptionType::DeleteIndex { section } => {
                    if context
                        .remove(INDEX_PARTITION, Some(&section.to_be_bytes()))
                        .await
                        .is_ok()
                    {
                        authenticated_indices.remove(section);
                        authenticated_entries.remove(section);
                    }
                }
                CorruptionType::DeleteGlob { section } => {
                    if context
                        .remove(VALUE_PARTITION, Some(&section.to_be_bytes()))
                        .await
                        .is_ok()
                    {
                        authenticated_entries.remove(section);
                    }
                }
                CorruptionType::ExtendIndex { section, garbage } => {
                    if let Ok((blob, size)) =
                        context.open(INDEX_PARTITION, &section.to_be_bytes()).await
                    {
                        let _ = blob
                            .write_at(size, garbage.to_vec(), WriteOptions::SYNC)
                            .await;
                    }
                }
                CorruptionType::ExtendGlob { section, garbage } => {
                    if let Ok((blob, size)) =
                        context.open(VALUE_PARTITION, &section.to_be_bytes()).await
                    {
                        let _ = blob
                            .write_at(size, garbage.to_vec(), WriteOptions::SYNC)
                            .await;
                    }
                }
            }
        }

        // Phase 3: Recovery - this should not panic
        let mut recovered: Oversized<_, TestEntry, TestValue> =
            match Oversized::init(context.child("recovered"), cfg.clone(), None).await {
                Ok(recovered) => recovered,
                Err(err @ JournalError::Runtime(RuntimeError::InvalidChecksum)) => {
                    // External writes may make an originally authenticated page unreadable before
                    // oversized recovery can inspect its entries. Permit that loud failure only
                    // when the current raw image independently proves such damage. Truncation,
                    // deletion, page padding, inactive checksum slots, and pure extensions cannot
                    // suppress the recovery oracle.
                    if has_invalid_authenticated_index_page(&context, &authenticated_indices).await
                    {
                        return;
                    }
                    panic!("Unexpected recovery failure: {err:?}");
                }
                Err(err) => panic!("Unexpected recovery failure: {err:?}"),
            };

        // Phase 4: Preserve exact identity where external mutations left the original entries and
        // values untouched. Elsewhere, arbitrary raw rewrites can create a different decodable
        // frame with a matching CRC, so reads retain only a bounded-result contract.
        exercise_readable_entries(&recovered, &authenticated_entries).await;

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
            if let Some(ids) = authenticated_entries.get(&section) {
                assert_eq!(position, ids.len() as u64);
            }
            sentinels.push((section, position));
        }
        recovered = recovered.sync_all().await.expect("sentinel sync failed");
        drop(recovered);

        let reopened: Oversized<_, TestEntry, TestValue> =
            Oversized::init(context.child("reopened"), cfg, None)
                .await
                .expect("reopen after sentinel sync failed");
        exercise_readable_entries(&reopened, &authenticated_entries).await;
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
