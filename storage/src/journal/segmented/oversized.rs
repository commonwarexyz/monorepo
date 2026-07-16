//! Segmented journal for oversized values.
//!
//! This module combines [super::fixed::Journal] with [super::glob::Glob] to handle
//! entries that reference variable-length "oversized" values. It provides coordinated
//! operations and built-in crash recovery.
//!
//! # Architecture
//!
//! ```text
//! +-------------------+     +-------------------+
//! | Fixed Journal     |     | Glob (Values)     |
//! | (Index Entries)   |     |                   |
//! +-------------------+     +-------------------+
//! | entry_0           | --> | value_0           |
//! | entry_1           | --> | value_1           |
//! | ...               |     | ...               |
//! +-------------------+     +-------------------+
//! ```
//!
//! Each index entry contains `(value_offset, value_size)` pointing to its value in glob.
//!
//! # Crash Recovery
//!
//! Every mutation that could skew the two journals commits as ONE atomic batch
//! ([commonware_runtime::WriteBatch]): `sync`, `start_sync`, and `sync_all` stage both
//! journals' dirty blobs in one commit, `prune` stages both journals' section removals in
//! one commit, `destroy` stages every blob's removal in one commit, and an append that
//! opens a fresh section stages both blobs' creation in one commit. After a crash, a
//! section's index and glob therefore read back from the same commit: durable index
//! entries always reference values the durable glob holds. Initialization verifies this
//! (each section's last entry must have its value range within the durable glob) and any
//! violation is [Error::Corruption], a state no crash can produce.
//!
//! Two states remain reachable across a crash, both unreferenced storage and both benign:
//! - A crash during `rewind` (which removes trailing sections index-first, then glob) can
//!   leave glob sections with no index section. They are left in place: appends reuse
//!   them (values write after the existing bytes) and `prune` reclaims them.
//! - Glob bytes past the last indexed value (e.g. within such a reused section) are
//!   likewise left in place: subsequent appends write after them and the space is
//!   reclaimed when the section is pruned.

use super::{
    fixed::{Config as FixedConfig, Journal as FixedJournal},
    glob::{Config as GlobConfig, Glob},
};
use crate::journal::Error;
use commonware_codec::{Codec, CodecFixed, CodecShared};
use commonware_runtime::{Batchable, BufferPooler, Handle, Metrics, Storage, WriteBatch as _};
use futures::stream::Stream;
use std::{collections::BTreeSet, num::NonZeroUsize};

/// Trait for index entries that reference oversized values in glob storage.
///
/// Implementations must provide access to the value location for cross-journal
/// validation at initialization, and a way to set the location when appending.
pub trait Record: CodecFixed<Cfg = ()> + Clone {
    /// Returns `(value_offset, value_size)` for crash recovery validation.
    fn value_location(&self) -> (u64, u32);

    /// Returns a new entry with the value location set.
    ///
    /// Called during `append` after the value is written to glob storage.
    fn with_location(self, offset: u64, size: u32) -> Self;
}

/// Configuration for oversized journal.
#[derive(Clone)]
pub struct Config<C> {
    /// Partition for the fixed index journal.
    pub index_partition: String,

    /// Partition for the glob value storage.
    pub value_partition: String,

    /// Page cache for index journal caching.
    pub index_page_cache: commonware_runtime::buffer::paged::CacheRef,

    /// Write buffer size for the index journal.
    pub index_write_buffer: NonZeroUsize,

    /// Write buffer size for the value journal.
    pub value_write_buffer: NonZeroUsize,

    /// Optional compression level for values (using zstd).
    pub compression: Option<u8>,

    /// Codec configuration for values.
    pub codec_config: C,
}

/// Segmented journal for entries with oversized values.
///
/// Combines a fixed-size index journal with glob storage for variable-length values.
/// Provides coordinated operations and crash recovery.
pub struct Oversized<E: BufferPooler + Storage + Metrics, I: Record, V: Codec> {
    context: E,
    index: FixedJournal<E, I>,
    values: Glob<E, V>,
}

impl<E: BufferPooler + Batchable + Metrics, I: Record + Send + Sync, V: CodecShared>
    Oversized<E, I, V>
{
    /// Initialize with cross-journal verification.
    ///
    /// Every mutation commits both journals as one atomic batch, so an index entry
    /// referencing bytes beyond the durable glob is [Error::Corruption], not a crash
    /// state to repair.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize both journals
        let index_cfg = FixedConfig {
            partition: cfg.index_partition,
            page_cache: cfg.index_page_cache,
            write_buffer: cfg.index_write_buffer,
        };
        let index = FixedJournal::init(context.child("index"), index_cfg).await?;

        let value_cfg = GlobConfig {
            partition: cfg.value_partition,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            write_buffer: cfg.value_write_buffer,
        };
        let values = Glob::init(context.child("values"), value_cfg).await?;

        let oversized = Self {
            context,
            index,
            values,
        };
        oversized.verify_alignment().await?;

        Ok(oversized)
    }

    /// Verify that every index entry's value range is within the durable glob.
    ///
    /// Value offsets are appended in monotone order within a section, so checking the
    /// last entry covers all earlier ones. When could this fail? Only through corruption
    /// or external tampering: every commit that captures one of a section's blobs
    /// captures both (creation, sync, prune, and destroy are single atomic batches), so
    /// no crash leaves durable index entries whose values never landed.
    async fn verify_alignment(&self) -> Result<(), Error> {
        for section in self.index.sections() {
            let Some(last) = self.index.last(section).await? else {
                continue;
            };
            let (offset, size) = last.value_location();
            let entry_end = offset.saturating_add(u64::from(size));
            let glob_size = self.values.size(section)?;
            if entry_end > glob_size {
                return Err(Error::Corruption(format!(
                    "section {section} index references {entry_end} glob bytes but only {glob_size} are durable"
                )));
            }
        }

        Ok(())
    }

    /// Append entry + value.
    ///
    /// Writes value to glob first, then writes index entry with the value location. An
    /// append that opens a fresh section stages both journals' blob creation in one
    /// atomic batch, so a crash can never leave one journal's section blob without the
    /// other.
    ///
    /// Returns `(position, offset, size)` where:
    /// - `position`: Position in the index journal
    /// - `offset`: Byte offset in glob
    /// - `size`: Size of value in glob
    pub async fn append(
        &mut self,
        section: u64,
        entry: I,
        value: &V,
    ) -> Result<(u64, u64, u32), Error> {
        // Create any missing section blob in one commit. Either journal may already hold
        // the section (e.g. a glob section orphaned by a rewind crash), so only the
        // missing side is created. The glob is staged before the index so a sequentially
        // replayed batch (the test-only mock fallback) creates the value store first.
        let create_values = !self.values.contains(section)?;
        let create_index = !self.index.contains(section)?;
        if create_values || create_index {
            let mut batch = self.context.batch().await?;
            if create_values {
                self.values.create_into(section, &mut batch).await?;
            }
            if create_index {
                self.index.create_into(section, &mut batch).await?;
            }
            batch.apply_sync().await?;
        }

        // Write value first (glob). This will typically write to an in-memory
        // buffer and return quickly (only blocks when the buffer is full).
        let (offset, size) = self.values.append(section, value).await?;

        // Update entry with actual location and write to index
        let entry_with_location = entry.with_location(offset, size);
        let position = self.index.append(section, &entry_with_location).await?;

        Ok((position, offset, size))
    }

    /// Get entry at position (index entry only, not value).
    pub async fn get(&self, section: u64, position: u64) -> Result<I, Error> {
        self.index.get(section, position).await
    }

    /// Get the last entry for a section, if any.
    ///
    /// Returns `Ok(None)` if the section is empty.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    pub async fn last(&self, section: u64) -> Result<Option<I>, Error> {
        self.index.last(section).await
    }

    /// Get value using offset/size from entry.
    ///
    /// The offset should be the byte offset from `append()` or from the entry's `value_location()`.
    pub async fn get_value(&self, section: u64, offset: u64, size: u32) -> Result<V, Error> {
        self.values.get(section, offset, size).await
    }

    /// Replay index entries starting from given section.
    ///
    /// Returns a stream of `(section, position, entry)` tuples.
    pub async fn replay(
        &mut self,
        start_section: u64,
        start_position: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, I), Error>> + Send + '_, Error> {
        self.index
            .replay(start_section, start_position, buffer)
            .await
    }

    /// Sync both journals for the given `sections` as ONE atomic commit: durable index
    /// entries can never reference values that never landed.
    pub async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        let mut batch = self.context.batch().await?;
        self.sync_into(sections, &mut batch).await?;
        batch.apply_sync().await?;
        Ok(())
    }

    /// Stage the durability of both journals' `sections` with `batch`: the
    /// batch commits both together. Values are staged before the index, so
    /// a sequentially replayed batch (the test-only mock fallback) never
    /// syncs index entries ahead of the values they reference.
    pub async fn sync_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        sections: impl crate::Sections,
        batch: &mut T,
    ) -> Result<(), Error> {
        let sections = sections.sections().collect::<Vec<_>>();
        self.values.sync_into(&sections, batch).await?;
        self.index.sync_into(&sections, batch).await
    }

    /// Start syncing both journals for the given `sections` as ONE atomic commit.
    ///
    /// The runtime's blob `start_sync` is itself inline today (the volume commits before
    /// returning a resolved handle), so this honestly applies the batch before returning
    /// and the handle is already resolved. Should the volume ever gain a truly
    /// asynchronous commit, [commonware_runtime::WriteBatch] (e.g. an `apply_start_sync`)
    /// and this method should be extended in kind.
    pub async fn start_sync(
        &mut self,
        sections: impl crate::Sections,
    ) -> Result<Handle<()>, Error> {
        self.sync(sections).await?;
        Ok(Handle::ready(Ok(())))
    }

    /// Sync all sections of both journals as ONE atomic commit.
    pub async fn sync_all(&mut self) -> Result<(), Error> {
        let sections: BTreeSet<u64> = self
            .index
            .sections()
            .chain(self.values.sections())
            .collect();
        self.sync(&sections).await
    }

    /// Prune both journals as ONE atomic commit: both journals' section removals land
    /// together, so a crash can never leave one journal's sections without the other's.
    /// Returns true if any sections were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        // The index is staged before the glob so a sequentially replayed batch (the
        // test-only mock fallback) never removes a value store still referenced by a
        // durable index section.
        let mut batch = self.context.batch().await?;
        let index_pruned = self.index.prune_into(min, &mut batch).await?;
        let value_pruned = self.values.prune_into(min, &mut batch).await?;
        if !(index_pruned || value_pruned) {
            return Ok(false);
        }
        batch.apply_sync().await?;
        Ok(true)
    }

    /// Rewind both journals to a specific section and index size.
    ///
    /// This rewinds the section to the given index size and removes all sections
    /// after the given section. The value size is derived from the last entry.
    ///
    /// The index is rewound before the glob, so a crash mid-rewind can only leave glob
    /// sections whose index section is already gone: unreferenced bytes that later
    /// appends reuse and `prune` reclaims (see the module docs). The target section's
    /// truncations are not durable until the next sync, which commits both atomically.
    pub async fn rewind(&mut self, section: u64, index_size: u64) -> Result<(), Error> {
        // Rewind index first (this also removes sections after `section`)
        self.index.rewind(section, index_size).await?;

        // Derive value size from last entry (section may not exist if empty)
        let value_size = match self.index.last(section).await {
            Ok(Some(entry)) => {
                let (offset, size) = entry.value_location();
                offset
                    .checked_add(u64::from(size))
                    .ok_or(Error::OffsetOverflow)?
            }
            Ok(None) => 0,
            Err(Error::SectionOutOfRange(_)) if index_size == 0 => 0,
            Err(e) => return Err(e),
        };

        // Rewind values (this also removes sections after `section`)
        self.values.rewind(section, value_size).await
    }

    /// Rewind only the given section to a specific index size.
    ///
    /// Unlike `rewind`, this does not affect other sections.
    /// The value size is derived from the last entry after rewinding the index.
    pub async fn rewind_section(&mut self, section: u64, index_size: u64) -> Result<(), Error> {
        // Rewind index first
        self.index.rewind_section(section, index_size).await?;

        // Derive value size from last entry (section may not exist if empty)
        let value_size = match self.index.last(section).await {
            Ok(Some(entry)) => {
                let (offset, size) = entry.value_location();
                offset
                    .checked_add(u64::from(size))
                    .ok_or(Error::OffsetOverflow)?
            }
            Ok(None) => 0,
            Err(Error::SectionOutOfRange(_)) if index_size == 0 => 0,
            Err(e) => return Err(e),
        };

        // Rewind values
        self.values.rewind_section(section, value_size).await
    }

    /// Get index size for checkpoint.
    ///
    /// The value size can be derived from the last entry's location when needed.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.index.size(section)
    }

    /// Get the value size for a section, derived from the last entry's location.
    pub async fn value_size(&self, section: u64) -> Result<u64, Error> {
        match self.index.last(section).await {
            Ok(Some(entry)) => {
                let (offset, size) = entry.value_location();
                offset
                    .checked_add(u64::from(size))
                    .ok_or(Error::OffsetOverflow)
            }
            Ok(None) | Err(Error::SectionOutOfRange(_)) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Returns the oldest section number, if any exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.index.oldest_section()
    }

    /// Returns the newest section number, if any exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.index.newest_section()
    }

    /// Destroy all underlying storage.
    ///
    /// Every blob's removal and both partitions' land in ONE atomic commit, so
    /// destruction is all-or-nothing.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context.batch().await?;
        self.destroy_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch` (see
    /// [super::manager::Manager::destroy_into] for the caller contract).
    pub(crate) async fn destroy_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        self,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.index.destroy_into(batch).await?;
        self.values.destroy_into(batch).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{FixedSize, Read, ReadExt, Write};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Blob as _, Buf, BufMut, BufferPooler, Runner,
        Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU16};

    /// Convert offset + size to byte end position (for truncation tests).
    fn byte_end(offset: u64, size: u32) -> u64 {
        offset + u64::from(size)
    }

    /// Test index entry that stores a u64 id and references a value.
    #[derive(Debug, Clone, PartialEq)]
    struct TestEntry {
        id: u64,
        value_offset: u64,
        value_size: u32,
    }

    impl TestEntry {
        fn new(id: u64, value_offset: u64, value_size: u32) -> Self {
            Self {
                id,
                value_offset,
                value_size,
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

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
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

    fn test_cfg(pooler: &impl BufferPooler) -> Config<()> {
        Config {
            index_partition: "test-index".into(),
            value_partition: "test-values".into(),
            index_page_cache: CacheRef::from_pooler(pooler, NZU16!(64), NZUsize!(8)),
            index_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            compression: None,
            codec_config: (),
        }
    }

    /// Simple test value type with unit config.
    type TestValue = [u8; 16];

    #[test_traced]
    fn test_oversized_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            // Append entry with value
            let value: TestValue = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
            let entry = TestEntry::new(42, 0, 0);
            let (position, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");

            assert_eq!(position, 0);

            // Get entry
            let retrieved_entry = oversized.get(1, position).await.expect("Failed to get");
            assert_eq!(retrieved_entry.id, 42);

            // Get value
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_truncated_is_corruption() {
        // Every commit captures a section's index and glob together, so a durable glob
        // shorter than the last durable entry's value range cannot arise from a crash:
        // init rejects it as corruption.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate oversized journal
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append multiple entries
            let mut locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate glob to lose the last 2 values
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(locations[2].1, locations[2].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_oversized_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(123, 0, 0);
            let (position, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Reopen and verify
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            let retrieved_entry = oversized.get(1, position).await.expect("Failed to get");
            assert_eq!(retrieved_entry.id, 123);

            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // One sub-page entry/value per section stays buffered until synced.
            let mut located = Vec::new();
            for section in 1u64..=3 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                let (position, offset, size) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                located.push((section, position, offset, size, value));
            }

            // Sync sections 1 and 3 (both index and values); a nonexistent section (99) is
            // skipped, not an error.
            oversized
                .sync(&[1, 3, 99])
                .await
                .expect("Failed to sync sections");
            drop(oversized);

            // Only the synced sections' data survives the unclean drop (section 2's blobs
            // exist from the creation commit, but its buffered writes are gone).
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");
            for &(section, position, offset, size, value) in &located {
                let result = oversized.get(section, position).await;
                if section == 2 {
                    assert!(result.is_err(), "unsynced section 2 must not be durable");
                    continue;
                }
                assert_eq!(result.expect("synced entry durable").id, section);
                let retrieved = oversized
                    .get_value(section, offset, size)
                    .await
                    .expect("synced value durable");
                assert_eq!(retrieved, value);
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            // Append to multiple sections
            for section in 1u64..=5 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized.sync(section).await.expect("Failed to sync");
            }

            // Prune sections < 3
            oversized.prune(3).await.expect("Failed to prune");

            // Sections 1, 2 should be gone
            assert!(oversized.get(1, 0).await.is_err());
            assert!(oversized.get(2, 0).await.is_err());

            // Sections 3, 4, 5 should exist
            assert!(oversized.get(3, 0).await.is_ok());
            assert!(oversized.get(4, 0).await.is_ok());
            assert!(oversized.get(5, 0).await.is_ok());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_fresh_section_creation_survives_crash() {
        // An append that opens a fresh section commits both journals' blobs in one
        // batch, so after a crash (before any sync) the section exists in BOTH journals,
        // empty.
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("storage"), cfg)
                    .await
                    .expect("Failed to init");

            let value: TestValue = [7; 16];
            oversized
                .append(1, TestEntry::new(7, 0, 0), &value)
                .await
                .expect("Failed to append");
            // No sync: the appended data is lost to the crash, the creation is not.
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("recovered"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Both journals hold the (empty) section.
            assert_eq!(oversized.oldest_section(), Some(1));
            assert_eq!(oversized.newest_section(), Some(1));
            assert_eq!(oversized.size(1).unwrap(), 0);
            assert_eq!(oversized.value_size(1).await.unwrap(), 0);

            // The section remains appendable.
            let value: TestValue = [8; 16];
            let (pos, offset, size) = oversized
                .append(1, TestEntry::new(8, 0, 0), &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 0);
            oversized.sync(1).await.expect("Failed to sync");
            assert_eq!(oversized.get_value(1, offset, size).await.unwrap(), value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_start_sync_durable_at_return() {
        // start_sync applies the batch inline (the volume's commit is inline), so the
        // returned handle is already resolved and the data survives a crash without
        // awaiting it.
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("storage"), cfg)
                    .await
                    .expect("Failed to init");

            let value: TestValue = [3; 16];
            oversized
                .append(1, TestEntry::new(3, 0, 0), &value)
                .await
                .expect("Failed to append");
            let handle = oversized.start_sync(1).await.expect("Failed to start sync");
            handle.await.expect("sync handle should complete");
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_cfg(&context);
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("recovered"), cfg)
                    .await
                    .expect("Failed to reinit");

            let entry = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 3);
            let (offset, size) = entry.value_location();
            assert_eq!(oversized.get_value(1, offset, size).await.unwrap(), [3; 16]);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_empty_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create oversized journal
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append to section 2 only (section 1 remains empty after being opened)
            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            oversized
                .append(2, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(2).await.expect("Failed to sync");
            drop(oversized);

            // Reinitialize - recovery should handle the empty/non-existent section 1
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 2 entry should be valid
            let entry = oversized.get(2, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 1);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_truncated_to_zero_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 5 entries
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate glob to 0 bytes: every durable entry now references missing bytes,
            // a state no crash can produce.
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_glob_truncated_one_section_is_corruption() {
        // A single tampered section is corruption even when every other section is
        // consistent.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut section2_locations = Vec::new();
            for section in 1u64..=3 {
                for i in 0..3u8 {
                    let value: TestValue = [(section as u8) * 10 + i; 16];
                    let entry = TestEntry::new(section * 100 + i as u64, 0, 0);
                    let loc = oversized
                        .append(section, entry, &value)
                        .await
                        .expect("Failed to append");
                    if section == 2 {
                        section2_locations.push(loc);
                    }
                }
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Truncate only section 2's glob to keep its first entry. Sections 1 and 3
            // remain intact.
            let (blob, _) = context
                .open(&cfg.value_partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(section2_locations[0].1, section2_locations[0].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_corrupted_last_index_entry_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 5 entries
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Overwrite the last entry with junk whose decoded value location points far
            // past the glob: a state no crash can produce.
            let (blob, size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 5 * TestEntry::SIZE as u64);
            blob.write_at_sync(size - TestEntry::SIZE as u64, vec![0xFF; TestEntry::SIZE])
                .await
                .expect("Failed to corrupt");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_recovery_all_entries_valid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append entries to multiple sections
            for section in 1u64..=3 {
                for i in 0..10u8 {
                    let value: TestValue = [(section as u8) * 10 + i; 16];
                    let entry = TestEntry::new(section * 100 + i as u64, 0, 0);
                    oversized
                        .append(section, entry, &value)
                        .await
                        .expect("Failed to append");
                }
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Reinitialize with no corruption - should be fast
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // All entries should be valid
            for section in 1u64..=3 {
                for i in 0..10u8 {
                    let entry = oversized
                        .get(section, i as u64)
                        .await
                        .expect("Failed to get");
                    assert_eq!(entry.id, section * 100 + i as u64);
                }
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_off_by_one_is_corruption() {
        // The verification is byte-exact: a glob one byte short of the last entry's
        // value range is corruption.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let loc = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push(loc);
            }
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate glob to be off by 1 byte from the last entry's end
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let last = &locations[2];
            let truncate_to = byte_end(last.1, last.2) - 1;
            blob.resize(truncate_to).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_glob_missing_entirely_is_corruption() {
        // Prune and destroy remove a section's index and glob in one commit, so a
        // missing glob under a populated index section cannot arise from a crash.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Delete the glob file entirely
            context
                .remove(&cfg.value_partition, Some(&1u64.to_be_bytes()))
                .await
                .expect("Failed to remove");

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_recovery_index_partition_deleted() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=3 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Delete index blob for section 2 (simulate corruption/loss)
            context
                .remove(&cfg.index_partition, Some(&2u64.to_be_bytes()))
                .await
                .expect("Failed to remove index");

            // Reinitialize - should handle gracefully. Section 2 is gone from the index;
            // its glob section is retained as unreferenced storage.
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 and 3 should still be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(3, 0).await.is_ok());

            // Section 2 should be gone (index file deleted)
            assert!(oversized.get(2, 0).await.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_synced_but_index_not() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so each entry is exactly one page.
            // This allows truncating by entry count to equal truncating by full pages,
            // maintaining page-level integrity.
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append entries and sync
            let mut locations = Vec::new();
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let loc = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push(loc);
            }
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate the INDEX but leave the GLOB intact: the glob ends with
            // unreferenced trailing bytes, which the journal tolerates by design (see the
            // module docs).
            let (blob, _size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Keep only the first 2 index entries
            blob.resize(2 * TestEntry::SIZE as u64)
                .await
                .expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - glob has orphan data from entry 3
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid
            for i in 0..2u8 {
                let (position, offset, size) = locations[i as usize];
                let entry = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // Entry at position 2 should fail (index was truncated)
            assert!(oversized.get(1, 2).await.is_err());

            // Append new entries - should work despite orphan data in glob
            let mut new_locations = Vec::new();
            for i in 10..13u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append after recovery");

                // New entries start at position 2 (after the 2 valid entries)
                assert_eq!(position, (i - 10 + 2) as u64);
                new_locations.push((position, offset, size, i));

                // Verify we can read the new entry
                let retrieved = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(retrieved.id, i as u64);

                let retrieved_value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(retrieved_value, value);
            }

            // Sync and restart again to verify persistence with orphan data
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Reinitialize after adding data on top of orphan glob data
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("third"), cfg)
                    .await
                    .expect("Failed to reinit after append");

            // Read all valid entries in the index
            // First 2 entries from original data
            for i in 0..2u8 {
                let (position, offset, size) = locations[i as usize];
                let entry = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // New entries added after recovery
            for (position, offset, size, expected_id) in &new_locations {
                let entry = oversized
                    .get(1, *position)
                    .await
                    .expect("Failed to get new entry after restart");
                assert_eq!(entry.id, *expected_id as u64);

                let value = oversized
                    .get_value(1, *offset, *size)
                    .await
                    .expect("Failed to get new value after restart");
                assert_eq!(value, [*expected_id; 16]);
            }

            // Verify total entry count: 2 original + 3 new = 5
            assert!(oversized.get(1, 4).await.is_ok());
            assert!(oversized.get(1, 5).await.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_partial_index_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 3 entries
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // A durable partial entry cannot arise from a crash (per-blob atomic sync), so
            // init rejects it as corruption.
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let partial_size = 3 * TestEntry::SIZE as u64 + 10; // 3 full entries + partial
            blob.resize(partial_size).await.expect("Failed to resize");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_recovery_only_partial_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with single entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate index to only partial data (less than one full entry): a durable
            // partial entry cannot arise from a crash, so init rejects it as corruption.
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(10).await.expect("Failed to resize"); // Less than chunk size
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_oversized_get_value_invalid_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (_, offset, _size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");

            // Size 0 - should fail
            assert!(oversized.get_value(1, offset, 0).await.is_err());

            // Size < value size - should fail with a codec error
            for size in 1..4u32 {
                let result = oversized.get_value(1, offset, size).await;
                assert!(
                    matches!(result, Err(Error::Codec(_))),
                    "expected error, got: {:?}",
                    result
                );
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_get_value_wrong_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (_, offset, correct_size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");

            // Size too small - will fail to decode
            let result = oversized.get_value(1, offset, correct_size - 1).await;
            assert!(
                matches!(result, Err(Error::Codec(_))),
                "expected Codec error, got: {:?}",
                result
            );

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_values_has_orphan_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with sections 1 and 2
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=2 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Manually create an orphan value section (section 3) without corresponding index
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");
            let orphan_value: TestValue = [99; 16];
            glob.append(3, &orphan_value)
                .await
                .expect("Failed to append orphan");
            glob.sync(3).await.expect("Failed to sync glob");
            drop(glob);

            // Reinitialize - the orphan section is retained as unreferenced storage
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Sections 1 and 2 should still be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(2, 0).await.is_ok());

            // Newest section is index-derived, so the orphan does not surface
            assert_eq!(oversized.newest_section(), Some(2));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_values_has_multiple_orphan_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with only section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Manually create multiple orphan value sections (2, 3, 4)
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in 2u64..=4 {
                let orphan_value: TestValue = [section as u8; 16];
                glob.append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Reinitialize - orphan sections are retained as unreferenced storage
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 should still be valid
            assert!(oversized.get(1, 0).await.is_ok());

            // Newest section is index-derived, so the orphans do not surface
            assert_eq!(oversized.newest_section(), Some(1));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_index_empty_but_values_exist() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Manually create value sections without any index entries
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in 1u64..=3 {
                let orphan_value: TestValue = [section as u8; 16];
                glob.append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Initialize oversized - the orphan value sections are retained but do not
            // surface (sections are index-derived)
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // No sections should exist
            assert_eq!(oversized.newest_section(), None);
            assert_eq!(oversized.oldest_section(), None);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_orphan_section_append_after() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (_, offset1, size1) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Manually create orphan value sections (2, 3)
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in 2u64..=3 {
                let orphan_value: TestValue = [section as u8; 16];
                glob.append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Reinitialize - orphan sections are retained as unreferenced storage
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 should still be valid
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 1);
            let value = oversized
                .get_value(1, offset1, size1)
                .await
                .expect("Failed to get value");
            assert_eq!(value, [1; 16]);

            // Should be able to append to section 2 after recovery
            let new_value: TestValue = [42; 16];
            let new_entry = TestEntry::new(42, 0, 0);
            let (pos, offset, size) = oversized
                .append(2, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 0);

            // Verify the new entry
            let retrieved = oversized.get(2, 0).await.expect("Failed to get");
            assert_eq!(retrieved.id, 42);
            let retrieved_value = oversized
                .get_value(2, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, new_value);

            // Sync and restart to verify persistence
            oversized.sync(2).await.expect("Failed to sync");
            drop(oversized);

            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("third"), cfg)
                    .await
                    .expect("Failed to reinit after append");

            // Both sections should be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(2, 0).await.is_ok());
            assert_eq!(oversized.newest_section(), Some(2));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_no_orphan_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with sections 1, 2, 3 (no orphans)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=3 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Reinitialize - everything is consistent
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // All sections should be valid
            for section in 1u64..=3 {
                let entry = oversized.get(section, 0).await.expect("Failed to get");
                assert_eq!(entry.id, section);
            }
            assert_eq!(oversized.newest_section(), Some(3));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_orphan_with_empty_index_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate section 1 with entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Manually create orphan value section 2
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");
            let orphan_value: TestValue = [2; 16];
            glob.append(2, &orphan_value)
                .await
                .expect("Failed to append orphan");
            glob.sync(2).await.expect("Failed to sync glob");
            drop(glob);

            // Now truncate index section 1 to 0 (making it empty but still tracked)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - the empty index section and the orphan value section are
            // both tolerated
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 1 should exist but have no entries (empty after truncation)
            assert!(oversized.get(1, 0).await.is_err());

            // Orphan section 2 does not surface (sections are index-derived)
            assert_eq!(oversized.newest_section(), Some(1));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_orphan_sections_with_gaps() {
        // Test non-contiguous sections: index has [1, 3, 5], values has [1, 2, 3, 4, 5, 6]
        // Orphan sections 2, 4, 6 are retained but do not surface
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create index with sections 1, 3, 5 (gaps)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in [1u64, 3, 5] {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Manually create orphan value sections 2, 4, 6 (filling gaps and beyond)
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in [2u64, 4, 6] {
                let orphan_value: TestValue = [section as u8; 16];
                glob.append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Reinitialize - orphan sections 2, 4, 6 are retained as unreferenced storage
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Sections 1, 3, 5 should still be valid
            for section in [1u64, 3, 5] {
                let entry = oversized.get(section, 0).await.expect("Failed to get");
                assert_eq!(entry.id, section);
            }

            // Verify only sections 1, 3, 5 surface (sections are index-derived)
            assert_eq!(oversized.oldest_section(), Some(1));
            assert_eq!(oversized.newest_section(), Some(5));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_trailing_bytes_retained() {
        // Glob bytes past the last indexed value are unreferenced and tolerated (e.g. a
        // glob section orphaned by a rewind crash and reused by later appends).
        // Initialization leaves them in place and subsequent appends write after them.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 2 entries
            let mut locations = Vec::new();
            for i in 0..2u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let loc = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push(loc);
            }
            oversized.sync(1).await.expect("Failed to sync");

            // Record where next entry SHOULD start (end of entry 1)
            let expected_next_offset = byte_end(locations[1].1, locations[1].2);
            drop(oversized);

            // Simulate crash: write garbage to glob (simulating partial value write)
            let (blob, size) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, expected_next_offset);

            // Write 100 bytes of garbage (simulating partial/failed value write)
            let garbage = vec![0xDE; 100];
            blob.write_at_sync(size, garbage)
                .await
                .expect("Failed to write garbage");
            drop(blob);

            // Verify glob now has trailing garbage
            let (blob, new_size) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(new_size, expected_next_offset + 100);
            drop(blob);

            // Reinitialize - the trailing bytes are unreferenced and retained
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should still be valid
            for i in 0..2u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Append new entry - starts after the retained trailing bytes
            let new_value: TestValue = [99; 16];
            let new_entry = TestEntry::new(99, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");

            // Verify position is 2 (after the 2 existing entries)
            assert_eq!(pos, 2);

            // Verify offset is past the trailing bytes
            assert_eq!(offset, expected_next_offset + 100);

            // Verify we can read the new entry and its value
            let retrieved = oversized.get(1, 2).await.expect("Failed to get new entry");
            assert_eq!(retrieved.id, 99);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get new value");
            assert_eq!(retrieved_value, new_value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_entry_with_overflow_offset_is_corruption() {
        // An entry whose offset near u64::MAX would overflow when added to its size is
        // corruption (the verification's saturating end always exceeds the glob).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so one entry per page
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate with valid entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Overwrite the entry with a semantically-invalid one whose offset near u64::MAX
            // overflows when added to its size.
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Build entry data: id (8) + value_offset (8) + value_size (4) = 20 bytes
            let mut entry_data = Vec::new();
            1u64.write(&mut entry_data); // id
            (u64::MAX - 10).write(&mut entry_data); // value_offset (near max)
            100u32.write(&mut entry_data); // value_size (offset + size overflows)
            assert_eq!(entry_data.len(), TestEntry::SIZE);
            blob.write_at_sync(0, entry_data)
                .await
                .expect("Failed to write corrupted entry");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_empty_section_persistence() {
        // Tests that sections that become empty (all entries removed/rewound)
        // are handled correctly across restart cycles.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate section 1 with entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized.sync(1).await.expect("Failed to sync");

            // Also create section 2 to ensure it survives
            let value2: TestValue = [10; 16];
            let entry2 = TestEntry::new(10, 0, 0);
            oversized
                .append(2, entry2, &value2)
                .await
                .expect("Failed to append to section 2");
            oversized.sync(2).await.expect("Failed to sync section 2");
            drop(oversized);

            // Truncate section 1's index to 0 (making it empty)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // First restart - recovery should handle empty section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 should exist but have no entries
            assert!(oversized.get(1, 0).await.is_err());

            // Section 2 should still be valid
            let entry = oversized.get(2, 0).await.expect("Failed to get section 2");
            assert_eq!(entry.id, 10);

            // Section 1 should still be tracked (blob exists but is empty)
            assert_eq!(oversized.oldest_section(), Some(1));

            // Append to empty section 1
            // Note: When index is truncated to 0 but the index blob still exists,
            // the glob is NOT truncated (the section isn't considered an orphan).
            // The glob still has orphan DATA from the old entries, but this doesn't
            // affect correctness - new entries simply append after the orphan data.
            let new_value: TestValue = [99; 16];
            let new_entry = TestEntry::new(99, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append to empty section");
            assert_eq!(pos, 0);
            // Glob offset is non-zero because orphan data wasn't truncated
            assert!(offset > 0);
            oversized.sync(1).await.expect("Failed to sync");

            // Verify the new entry is readable despite orphan data before it
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 99);
            let value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(value, new_value);

            drop(oversized);

            // Second restart - verify persistence
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("third"), cfg.clone())
                    .await
                    .expect("Failed to reinit again");

            // Section 1's new entry should be valid
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 99);

            // Section 2 should still be valid
            let entry = oversized.get(2, 0).await.expect("Failed to get section 2");
            assert_eq!(entry.id, 10);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_maximum_section_numbers() {
        // Section numbers near u64::MAX work end to end (no overflow panics in creation
        // or verification), and a tampered section among them is still corruption.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Use section numbers near u64::MAX
            let large_sections = [u64::MAX - 3, u64::MAX - 2, u64::MAX - 1];

            // Create and populate with large section numbers
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for &section in &large_sections {
                let value: TestValue = [(section & 0xFF) as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // A restart with everything intact succeeds
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");
            for &section in &large_sections {
                let entry = oversized.get(section, 0).await.expect("Failed to get");
                assert_eq!(entry.id, section);
            }
            drop(oversized);

            // Truncate the middle section's glob mid-value: corruption
            let middle_section = large_sections[1];
            let (blob, size) = context
                .open(&cfg.value_partition, &middle_section.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size / 2).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init(context.child("third"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_rewind_to_zero_index_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            oversized
                .append(0, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(0).await.expect("Failed to sync");

            oversized
                .rewind(0, 0)
                .await
                .expect("rewind to zero index_size must not fail");

            assert_eq!(oversized.last(0).await.unwrap(), None);
            assert_eq!(oversized.size(0).unwrap(), 0);
            assert_eq!(oversized.value_size(0).await.unwrap(), 0);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_rewind_to_zero_on_missing_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            oversized
                .rewind(0, 0)
                .await
                .expect("rewind on missing section must not fail");

            assert!(matches!(
                oversized.last(0).await,
                Err(Error::SectionOutOfRange(0))
            ));
            assert_eq!(oversized.value_size(0).await.unwrap(), 0);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_rewind_nonzero_on_missing_section_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            let result = oversized.rewind(0, 1).await;
            assert!(
                matches!(result, Err(Error::SectionOutOfRange(0))),
                "nonzero index_size on missing section must fail, got: {result:?}"
            );

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_rewind_section_nonzero_on_missing_section_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            let result = oversized.rewind_section(0, 1).await;
            assert!(
                matches!(result, Err(Error::SectionOutOfRange(0))),
                "nonzero index_size on missing section must fail, got: {result:?}"
            );

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_last_pruned_section_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context, cfg).await.expect("Failed to init");

            let value: TestValue = [1; 16];
            oversized
                .append(0, TestEntry::new(1, 0, 0), &value)
                .await
                .expect("Failed to append");
            oversized
                .append(1, TestEntry::new(2, 0, 0), &value)
                .await
                .expect("Failed to append");
            oversized.sync_all().await.expect("Failed to sync");

            oversized.prune(1).await.expect("Failed to prune");

            assert!(matches!(
                oversized.last(0).await,
                Err(Error::AlreadyPrunedToSection(1))
            ));
            assert!(oversized.last(1).await.unwrap().is_some());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }
}
