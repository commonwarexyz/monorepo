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
//! On unclean shutdown, the index journal and glob may have different lengths:
//! - Index entry pointing to non-existent glob data (dangerous)
//! - Glob value without index entry (orphan - acceptable but cleaned up)
//! - Glob sections without corresponding index sections (orphan sections - removed)
//!
//! During initialization, crash recovery is performed:
//! 1. Each index entry's glob reference is validated (`value_offset + value_size <= glob_size`)
//! 2. Invalid entries are skipped and the index journal is rewound
//! 3. Orphan value sections (sections in glob but not in index) are removed
//!
//! This allows async writes (glob first, then index) while ensuring consistency
//! after recovery.
//!
//! _Recovery only validates that index entries point to valid byte ranges
//! within the glob. It does **not** verify value checksums during recovery (this would
//! require reading all values). Value checksums are verified lazily when values are
//! read via `get_value()`. If the underlying storage is corrupted, `get_value()` will
//! return a checksum error even though the index entry exists._

use super::{
    fixed::{Config as FixedConfig, Journal as FixedJournal},
    glob::{Config as GlobConfig, Glob},
};
use crate::journal::Error;
use commonware_codec::{Codec, CodecFixed, CodecShared};
use commonware_runtime::{Metrics, Storage};
use futures::{future::try_join, stream::Stream};
use std::{collections::HashSet, num::NonZeroUsize};
use tracing::{debug, warn};

/// Trait for index entries that reference oversized values in glob storage.
///
/// Implementations must provide access to the value location for crash recovery validation,
/// and a way to set the location when appending.
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

    /// Buffer pool for index journal caching.
    pub index_buffer_pool: commonware_runtime::buffer::PoolRef,

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
pub struct Oversized<E: Storage + Metrics, I: Record, V: Codec> {
    index: FixedJournal<E, I>,
    values: Glob<E, V>,
}

impl<E: Storage + Metrics, I: Record + Send + Sync, V: CodecShared> Oversized<E, I, V> {
    /// Initialize with crash recovery validation.
    ///
    /// Validates each index entry's glob reference during replay. Invalid entries
    /// (pointing beyond glob size) are skipped, and the index journal is rewound
    /// to exclude trailing invalid entries.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize both journals
        let index_cfg = FixedConfig {
            partition: cfg.index_partition,
            buffer_pool: cfg.index_buffer_pool,
            write_buffer: cfg.index_write_buffer,
        };
        let index = FixedJournal::init(context.with_label("index"), index_cfg).await?;

        let value_cfg = GlobConfig {
            partition: cfg.value_partition,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            write_buffer: cfg.value_write_buffer,
        };
        let values = Glob::init(context.with_label("values"), value_cfg).await?;

        let mut oversized = Self { index, values };

        // Perform crash recovery validation
        oversized.recover().await?;

        Ok(oversized)
    }

    /// Perform crash recovery by validating index entries against glob sizes.
    ///
    /// Only checks the last entry in each section. Since entries are appended sequentially
    /// and value offsets are monotonically increasing within a section, if the last entry
    /// is valid then all earlier entries must be valid too.
    async fn recover(&mut self) -> Result<(), Error> {
        let chunk_size = FixedJournal::<E, I>::CHUNK_SIZE as u64;
        let sections: Vec<u64> = self.index.sections().collect();

        for section in sections {
            let index_size = self.index.size(section).await?;
            if index_size == 0 {
                continue;
            }

            let glob_size = match self.values.size(section).await {
                Ok(size) => size,
                Err(Error::AlreadyPrunedToSection(oldest)) => {
                    // This shouldn't happen in normal operation: prune() prunes the index
                    // first, then the glob. A crash between these would leave the glob
                    // NOT pruned (opposite of this case). We handle this defensively in
                    // case of external manipulation or future changes.
                    warn!(
                        section,
                        oldest, "index has section that glob already pruned"
                    );
                    0
                }
                Err(e) => return Err(e),
            };

            // Truncate any trailing partial entry
            let entry_count = index_size / chunk_size;
            let aligned_size = entry_count * chunk_size;
            if aligned_size < index_size {
                warn!(
                    section,
                    index_size, aligned_size, "trailing bytes detected: truncating"
                );
                self.index.rewind_section(section, aligned_size).await?;
            }

            // If there is nothing, we can exit early and rewind values to 0
            if entry_count == 0 {
                warn!(
                    section,
                    index_size, "trailing bytes detected: truncating to 0"
                );
                self.values.rewind_section(section, 0).await?;
                continue;
            }

            // Find last valid entry and target glob size
            let (valid_count, glob_target) = self
                .find_last_valid_entry(section, entry_count, glob_size)
                .await;

            // Rewind index if any entries are invalid
            if valid_count < entry_count {
                let valid_size = valid_count * chunk_size;
                debug!(section, entry_count, valid_count, "rewinding index");
                self.index.rewind_section(section, valid_size).await?;
            }

            // Truncate glob trailing garbage (can occur when value was written but
            // index entry wasn't, or when index was truncated but glob wasn't)
            if glob_size > glob_target {
                debug!(
                    section,
                    glob_size, glob_target, "truncating glob trailing garbage"
                );
                self.values.rewind_section(section, glob_target).await?;
            }
        }

        // Clean up orphan value sections that don't exist in index
        self.cleanup_orphan_value_sections().await?;

        Ok(())
    }

    /// Remove any value sections that don't have corresponding index sections.
    ///
    /// This can happen if a crash occurs after writing to values but before
    /// writing to index for a new section. Since sections don't have to be
    /// contiguous, we compare the actual sets of sections rather than just
    /// comparing the newest section numbers.
    async fn cleanup_orphan_value_sections(&mut self) -> Result<(), Error> {
        // Collect index sections into a set for O(1) lookup
        let index_sections: HashSet<u64> = self.index.sections().collect();

        // Find value sections that don't exist in index
        let orphan_sections: Vec<u64> = self
            .values
            .sections()
            .filter(|s| !index_sections.contains(s))
            .collect();

        // Remove each orphan section
        for section in orphan_sections {
            warn!(section, "removing orphan value section");
            self.values.remove_section(section).await?;
        }

        Ok(())
    }

    /// Find the number of valid entries and the corresponding glob target size.
    ///
    /// Scans backwards from the last entry until a valid one is found.
    /// Returns `(valid_count, glob_target)` where `glob_target` is the end offset
    /// of the last valid entry's value.
    async fn find_last_valid_entry(
        &self,
        section: u64,
        entry_count: u64,
        glob_size: u64,
    ) -> (u64, u64) {
        for pos in (0..entry_count).rev() {
            match self.index.get(section, pos).await {
                Ok(entry) => {
                    let (offset, size) = entry.value_location();
                    let entry_end = offset.saturating_add(u64::from(size));
                    if entry_end <= glob_size {
                        return (pos + 1, entry_end);
                    }
                    if pos == entry_count - 1 {
                        warn!(
                            section,
                            pos, glob_size, entry_end, "invalid entry: glob truncated"
                        );
                    }
                }
                Err(_) => {
                    if pos == entry_count - 1 {
                        warn!(section, pos, "corrupted last entry, scanning backwards");
                    }
                }
            }
        }
        (0, 0)
    }

    /// Append entry + value.
    ///
    /// Writes value to glob first, then writes index entry with the value location.
    ///
    /// Returns `(position, offset, size)` where:
    /// - `position`: Position in the index journal
    /// - `offset`: Byte offset in glob
    /// - `size`: Size of value in glob (including checksum)
    pub async fn append(
        &mut self,
        section: u64,
        entry: I,
        value: &V,
    ) -> Result<(u64, u64, u32), Error> {
        // Write value first (glob). This will typically write to an in-memory
        // buffer and return quickly (only blocks when the buffer is full).
        let (offset, size) = self.values.append(section, value).await?;

        // Update entry with actual location and write to index
        let entry_with_location = entry.with_location(offset, size);
        let position = self.index.append(section, entry_with_location).await?;

        Ok((position, offset, size))
    }

    /// Get entry at position (index entry only, not value).
    pub async fn get(&self, section: u64, position: u64) -> Result<I, Error> {
        self.index.get(section, position).await
    }

    /// Get the last entry for a section, if any.
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
        &self,
        start_section: u64,
        start_position: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, I), Error>> + Send + '_, Error> {
        self.index
            .replay(start_section, start_position, buffer)
            .await
    }

    /// Sync both journals for given section.
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        try_join(self.index.sync(section), self.values.sync(section))
            .await
            .map(|_| ())
    }

    /// Sync all sections.
    pub async fn sync_all(&self) -> Result<(), Error> {
        try_join(self.index.sync_all(), self.values.sync_all())
            .await
            .map(|_| ())
    }

    /// Prune both journals. Returns true if any sections were pruned.
    ///
    /// Prunes index first, then glob. This order ensures crash safety:
    /// - If crash after index prune but before glob: orphan data in glob (acceptable)
    /// - If crash before index prune: no change, retry works
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        let index_pruned = self.index.prune(min).await?;
        let value_pruned = self.values.prune(min).await?;
        Ok(index_pruned || value_pruned)
    }

    /// Rewind both journals to a specific section and index size.
    ///
    /// This rewinds the section to the given index size and removes all sections
    /// after the given section. The value size is derived from the last entry.
    pub async fn rewind(&mut self, section: u64, index_size: u64) -> Result<(), Error> {
        // Rewind index first (this also removes sections after `section`)
        self.index.rewind(section, index_size).await?;

        // Derive value size from last entry
        let value_size = match self.index.last(section).await? {
            Some(entry) => {
                let (offset, size) = entry.value_location();
                offset
                    .checked_add(u64::from(size))
                    .ok_or(Error::OffsetOverflow)?
            }
            None => 0,
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

        // Derive value size from last entry
        let value_size = match self.index.last(section).await? {
            Some(entry) => {
                let (offset, size) = entry.value_location();
                offset
                    .checked_add(u64::from(size))
                    .ok_or(Error::OffsetOverflow)?
            }
            None => 0,
        };

        // Rewind values
        self.values.rewind_section(section, value_size).await
    }

    /// Get index size for checkpoint.
    ///
    /// The value size can be derived from the last entry's location when needed.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.index.size(section).await
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
            Ok(None) => Ok(0),
            Err(Error::SectionOutOfRange(_)) => Ok(0),
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
    pub async fn destroy(self) -> Result<(), Error> {
        try_join(self.index.destroy(), self.values.destroy())
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BufMut};
    use commonware_codec::{FixedSize, Read, ReadExt, Write};
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Blob as _, Runner};
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

    fn test_cfg() -> Config<()> {
        Config {
            index_partition: "test_index".to_string(),
            value_partition: "test_values".to_string(),
            index_buffer_pool: PoolRef::new(NZU16!(64), NZUsize!(8)),
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
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), test_cfg())
                    .await
                    .expect("Failed to init");

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
    fn test_oversized_crash_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate oversized journal
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Simulate crash: truncate glob to lose last 2 values
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Calculate size to keep first 3 entries
            let keep_size = byte_end(locations[2].1, locations[2].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should recover and rewind index
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 3 entries should still be valid
            for i in 0..3u8 {
                let (position, offset, size) = locations[i as usize];
                let entry = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // Entry at position 3 should fail (index was rewound)
            let result = oversized.get(1, 3).await;
            assert!(result.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
                Oversized::init(context.clone(), cfg)
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
    fn test_oversized_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), test_cfg())
                    .await
                    .expect("Failed to init");

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
    fn test_recovery_empty_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create oversized journal
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 2 entry should be valid
            let entry = oversized.get(2, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 1);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_all_entries_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Truncate glob to 0 bytes - ALL entries become invalid
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should recover and rewind index to 0
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // No entries should be accessible
            let result = oversized.get(1, 0).await;
            assert!(result.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 0);

            let retrieved = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_multiple_sections_mixed_validity() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Section 1: 3 entries
            let mut section1_locations = Vec::new();
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let loc = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                section1_locations.push(loc);
            }
            oversized.sync(1).await.expect("Failed to sync");

            // Section 2: 5 entries
            let mut section2_locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [10 + i; 16];
                let entry = TestEntry::new(10 + i as u64, 0, 0);
                let loc = oversized
                    .append(2, entry, &value)
                    .await
                    .expect("Failed to append");
                section2_locations.push(loc);
            }
            oversized.sync(2).await.expect("Failed to sync");

            // Section 3: 2 entries
            for i in 0..2u8 {
                let value: TestValue = [20 + i; 16];
                let entry = TestEntry::new(20 + i as u64, 0, 0);
                oversized
                    .append(3, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized.sync(3).await.expect("Failed to sync");
            drop(oversized);

            // Truncate section 1 glob to keep only first entry
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(section1_locations[0].1, section1_locations[0].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Truncate section 2 glob to keep first 3 entries
            let (blob, _) = context
                .open(&cfg.value_partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(section2_locations[2].1, section2_locations[2].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Section 3 remains intact

            // Reinitialize
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 1: only position 0 valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(1, 1).await.is_err());
            assert!(oversized.get(1, 2).await.is_err());

            // Section 2: positions 0,1,2 valid
            assert!(oversized.get(2, 0).await.is_ok());
            assert!(oversized.get(2, 1).await.is_ok());
            assert!(oversized.get(2, 2).await.is_ok());
            assert!(oversized.get(2, 3).await.is_err());
            assert!(oversized.get(2, 4).await.is_err());

            // Section 3: both positions valid
            assert!(oversized.get(3, 0).await.is_ok());
            assert!(oversized.get(3, 1).await.is_ok());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_corrupted_last_index_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so each entry is on its own page.
            // This allows corrupting just the last entry's page without affecting others.
            // Physical page size = TestEntry::SIZE (20) + 12 (CRC record) = 32 bytes.
            let cfg = Config {
                index_partition: "test_index".to_string(),
                value_partition: "test_values".to_string(),
                index_buffer_pool: PoolRef::new(NZU16!(TestEntry::SIZE as u16), NZUsize!(8)),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 5 entries (each on its own page)
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

            // Corrupt the last page's CRC to trigger page-level integrity failure
            let (blob, size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Physical page size = 20 + 12 = 32 bytes
            // 5 entries = 5 pages = 160 bytes total
            // Last page CRC starts at offset 160 - 12 = 148
            assert_eq!(size, 160);
            let last_page_crc_offset = size - 12;
            blob.write_at(vec![0xFF; 12], last_page_crc_offset)
                .await
                .expect("Failed to corrupt");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should detect page corruption and truncate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 4 entries should be valid (on pages 0-3)
            for i in 0..4u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entry 4 should be gone (its page was corrupted)
            assert!(oversized.get(1, 4).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 4);

            let retrieved = oversized.get(1, 4).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_all_entries_valid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
                Oversized::init(context.clone(), cfg)
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
    fn test_recovery_single_entry_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate with single entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Truncate glob to 0 - single entry becomes invalid
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // Entry should be gone
            assert!(oversized.get(1, 0).await.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_last_entry_off_by_one() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Truncate glob to be off by 1 byte from last entry
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Last entry needs: offset + size bytes
            // Truncate to offset + size - 1 (missing 1 byte)
            let last = &locations[2];
            let truncate_to = byte_end(last.1, last.2) - 1;
            blob.resize(truncate_to).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(1, 1).await.is_ok());

            // Entry 2 should be gone (truncated)
            assert!(oversized.get(1, 2).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 2);

            let retrieved = oversized.get(1, 2).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_missing_entirely() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Reinitialize - glob size will be 0, all entries invalid
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // All entries should be gone
            assert!(oversized.get(1, 0).await.is_err());
            assert!(oversized.get(1, 1).await.is_err());
            assert!(oversized.get(1, 2).await.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_can_append_after_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
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

            // Truncate glob to keep only first 2 entries
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(locations[1].1, locations[1].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Verify first 2 entries exist
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(1, 1).await.is_ok());
            assert!(oversized.get(1, 2).await.is_err());

            // Append new entries after recovery
            for i in 10..15u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append after recovery");
            }
            oversized.sync(1).await.expect("Failed to sync");

            // Verify new entries at positions 2, 3, 4, 5, 6
            for i in 0..5u8 {
                let entry = oversized
                    .get(1, 2 + i as u64)
                    .await
                    .expect("Failed to get new entry");
                assert_eq!(entry.id, (10 + i) as u64);
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_pruned_but_index_not() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Simulate crash during prune: prune ONLY the glob, not the index
            // This creates the "glob pruned but index not" scenario
            use crate::journal::segmented::glob::{Config as GlobConfig, Glob};
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");
            glob.prune(2).await.expect("Failed to prune glob");
            glob.sync_all().await.expect("Failed to sync glob");
            drop(glob);

            // Reinitialize - should recover gracefully with warning
            // Index section 1 will be rewound to 0 entries
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 entries should be gone (index rewound due to glob pruned)
            assert!(oversized.get(1, 0).await.is_err());

            // Sections 2 and 3 should still be valid
            assert!(oversized.get(2, 0).await.is_ok());
            assert!(oversized.get(3, 0).await.is_ok());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_index_partition_deleted() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Reinitialize - should handle gracefully
            // Section 2 is gone from index, orphan data in glob is acceptable
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
    fn test_recovery_index_synced_but_glob_not() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Add more entries WITHOUT syncing (simulates unsynced writes)
            for i in 10..15u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            // Note: NOT calling sync() here
            drop(oversized);

            // Simulate crash where index was synced but glob wasn't:
            // Truncate glob back to the synced size (3 entries)
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let synced_size = byte_end(locations[2].1, locations[2].2);
            blob.resize(synced_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should rewind index to match glob
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 3 entries should be valid
            for i in 0..3u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entries 3-7 should be gone (unsynced, index rewound)
            assert!(oversized.get(1, 3).await.is_err());

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
                index_partition: "test_index".to_string(),
                value_partition: "test_values".to_string(),
                index_buffer_pool: PoolRef::new(NZU16!(TestEntry::SIZE as u16), NZUsize!(8)),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Simulate crash: truncate INDEX but leave GLOB intact
            // This creates orphan data in glob (glob ahead of index)
            let (blob, _size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Keep only first 2 index entries (2 full pages)
            // Physical page size = logical (20) + CRC record (12) = 32 bytes
            let physical_page_size = (TestEntry::SIZE + 12) as u64;
            blob.resize(2 * physical_page_size)
                .await
                .expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - glob has orphan data from entry 3
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
                Oversized::init(context.clone(), cfg)
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
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Simulate crash during write: truncate index to partial entry
            // Each entry is TestEntry::SIZE (20) + 4 (CRC32) = 24 bytes
            // Truncate to 3 full entries + 10 bytes of partial entry
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let partial_size = 3 * 24 + 10; // 3 full entries + partial
            blob.resize(partial_size).await.expect("Failed to resize");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should handle partial entry gracefully
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 3 entries should still be valid
            for i in 0..3u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entry 3 should not exist (partial entry was removed)
            assert!(oversized.get(1, 3).await.is_err());

            // Append new entry after recovery
            let value: TestValue = [42; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 3);

            // Verify we can read the new entry
            let retrieved = oversized.get(1, 3).await.expect("Failed to get new entry");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get new value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_only_partial_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate with single entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Truncate index to only partial data (less than one full entry)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(10).await.expect("Failed to resize"); // Less than chunk size
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should handle gracefully (rewind to 0)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // No entries should exist
            assert!(oversized.get(1, 0).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 0);

            let retrieved = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_crash_during_rewind_index_ahead() {
        // Simulates crash where index was rewound but glob wasn't
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so each entry is exactly one page.
            // This allows truncating by entry count to equal truncating by full pages,
            // maintaining page-level integrity.
            let cfg = Config {
                index_partition: "test_index".to_string(),
                value_partition: "test_values".to_string(),
                index_buffer_pool: PoolRef::new(NZU16!(TestEntry::SIZE as u16), NZUsize!(8)),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
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

            // Simulate crash during rewind: truncate index to 2 entries but leave glob intact
            // This simulates: rewind(index) succeeded, crash before rewind(glob)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Physical page size = logical (20) + CRC record (12) = 32 bytes
            let physical_page_size = (TestEntry::SIZE + 12) as u64;
            blob.resize(2 * physical_page_size)
                .await
                .expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - recovery should succeed (glob has orphan data)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid
            for i in 0..2u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entries 2-4 should be gone (index was truncated)
            assert!(oversized.get(1, 2).await.is_err());

            // Should be able to append new entries
            let (pos, _, _) = oversized
                .append(1, TestEntry::new(100, 0, 0), &[100u8; 16])
                .await
                .expect("Failed to append");
            assert_eq!(pos, 2);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_crash_during_rewind_glob_ahead() {
        // Simulates crash where glob was rewound but index wasn't
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
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

            // Simulate crash during rewind: truncate glob to 2 entries but leave index intact
            // This simulates: rewind(glob) succeeded, crash before rewind(index)
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(locations[1].1, locations[1].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - recovery should detect index entries pointing beyond glob
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid (index rewound to match glob)
            for i in 0..2u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entries 2-4 should be gone (index rewound during recovery)
            assert!(oversized.get(1, 2).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 2);

            let retrieved = oversized.get(1, 2).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_get_value_invalid_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), test_cfg())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (_, offset, _size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");

            // Size 0 - should fail
            assert!(oversized.get_value(1, offset, 0).await.is_err());

            // Size < value size - should fail with codec error, checksum mismatch, or
            // insufficient length (if size < 4 bytes for checksum)
            for size in 1..4u32 {
                let result = oversized.get_value(1, offset, size).await;
                assert!(
                    matches!(
                        result,
                        Err(Error::Codec(_))
                            | Err(Error::ChecksumMismatch(_, _))
                            | Err(Error::Runtime(_))
                    ),
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
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), test_cfg())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (_, offset, correct_size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");

            // Size too small - will fail to decode or checksum mismatch
            // (checksum mismatch can occur because we read wrong bytes as the checksum)
            let result = oversized.get_value(1, offset, correct_size - 1).await;
            assert!(
                matches!(
                    result,
                    Err(Error::Codec(_)) | Err(Error::ChecksumMismatch(_, _))
                ),
                "expected Codec or ChecksumMismatch error, got: {:?}",
                result
            );

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_values_has_orphan_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate with sections 1 and 2
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");
            let orphan_value: TestValue = [99; 16];
            glob.append(3, &orphan_value)
                .await
                .expect("Failed to append orphan");
            glob.sync(3).await.expect("Failed to sync glob");
            drop(glob);

            // Reinitialize - should detect and remove the orphan section
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Sections 1 and 2 should still be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(2, 0).await.is_ok());

            // Newest section should be 2 (orphan was removed)
            assert_eq!(oversized.newest_section(), Some(2));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_values_has_multiple_orphan_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate with only section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
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

            // Reinitialize - should detect and remove all orphan sections
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 should still be valid
            assert!(oversized.get(1, 0).await.is_ok());

            // Newest section should be 1 (orphans removed)
            assert_eq!(oversized.newest_section(), Some(1));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_index_empty_but_values_exist() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Manually create value sections without any index entries
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
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

            // Initialize oversized - should remove all orphan value sections
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
            let cfg = test_cfg();

            // Create and populate with section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
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

            // Reinitialize - should remove orphan sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
                Oversized::init(context.clone(), cfg)
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
            let cfg = test_cfg();

            // Create and populate with sections 1, 2, 3 (no orphans)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Reinitialize - no orphan cleanup needed
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
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
            let cfg = test_cfg();

            // Create and populate section 1 with entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
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

            // Reinitialize - should handle empty index section and remove orphan value section
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 1 should exist but have no entries (empty after truncation)
            assert!(oversized.get(1, 0).await.is_err());

            // Orphan section 2 should be removed
            assert_eq!(oversized.newest_section(), Some(1));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_orphan_sections_with_gaps() {
        // Test non-contiguous sections: index has [1, 3, 5], values has [1, 2, 3, 4, 5, 6]
        // Orphan sections 2, 4, 6 should be removed
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create index with sections 1, 3, 5 (gaps)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
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

            // Reinitialize - should remove orphan sections 2, 4, 6
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // Sections 1, 3, 5 should still be valid
            for section in [1u64, 3, 5] {
                let entry = oversized.get(section, 0).await.expect("Failed to get");
                assert_eq!(entry.id, section);
            }

            // Verify only sections 1, 3, 5 exist (orphans removed)
            assert_eq!(oversized.oldest_section(), Some(1));
            assert_eq!(oversized.newest_section(), Some(5));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_trailing_garbage_truncated() {
        // Tests the bug fix: when value is written to glob but index entry isn't
        // (crash after value write, before index write), recovery should truncate
        // the glob trailing garbage so subsequent appends start at correct offset.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
            blob.write_at(garbage, size)
                .await
                .expect("Failed to write garbage");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Verify glob now has trailing garbage
            let (blob, new_size) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(new_size, expected_next_offset + 100);
            drop(blob);

            // Reinitialize - should truncate the trailing garbage
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should still be valid
            for i in 0..2u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Append new entry - should start at expected_next_offset, NOT at garbage end
            let new_value: TestValue = [99; 16];
            let new_entry = TestEntry::new(99, 0, 0);
            let (pos, offset, _size) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");

            // Verify position is 2 (after the 2 existing entries)
            assert_eq!(pos, 2);

            // Verify offset is at expected_next_offset (garbage was truncated)
            assert_eq!(offset, expected_next_offset);

            // Verify we can read the new entry
            let retrieved = oversized.get(1, 2).await.expect("Failed to get new entry");
            assert_eq!(retrieved.id, 99);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_entry_with_overflow_offset() {
        // Tests that an entry with offset near u64::MAX that would overflow
        // when added to size is detected as invalid during recovery.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so one entry per page
            let cfg = Config {
                index_partition: "test_index".to_string(),
                value_partition: "test_values".to_string(),
                index_buffer_pool: PoolRef::new(NZU16!(TestEntry::SIZE as u16), NZUsize!(8)),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate with valid entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Build a corrupted entry with offset near u64::MAX that would overflow.
            // We need to write a valid page (with correct page-level CRC) containing
            // the semantically-invalid entry data.
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

            // Build page-level CRC record (12 bytes):
            // len1 (2) + crc1 (4) + len2 (2) + crc2 (4)
            let crc = Crc32::checksum(&entry_data);
            let len1 = TestEntry::SIZE as u16;
            let mut crc_record = Vec::new();
            crc_record.extend_from_slice(&len1.to_be_bytes()); // len1
            crc_record.extend_from_slice(&crc.to_be_bytes()); // crc1
            crc_record.extend_from_slice(&0u16.to_be_bytes()); // len2 (unused)
            crc_record.extend_from_slice(&0u32.to_be_bytes()); // crc2 (unused)
            assert_eq!(crc_record.len(), 12);

            // Write the complete physical page: entry_data + crc_record
            let mut page = entry_data;
            page.extend_from_slice(&crc_record);
            blob.write_at(page, 0)
                .await
                .expect("Failed to write corrupted page");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - recovery should detect the invalid entry
            // (offset + size would overflow, and even with saturating_add it exceeds glob_size)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // The corrupted entry should have been rewound (invalid)
            assert!(oversized.get(1, 0).await.is_err());

            // Should be able to append after recovery
            let new_value: TestValue = [99; 16];
            let new_entry = TestEntry::new(99, 0, 0);
            let (pos, new_offset, _) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");

            // Position should be 0 (corrupted entry was removed)
            assert_eq!(pos, 0);
            // Offset should be 0 (glob was truncated to 0)
            assert_eq!(new_offset, 0);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_empty_section_persistence() {
        // Tests that sections that become empty (all entries removed/rewound)
        // are handled correctly across restart cycles.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate section 1 with entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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
                Oversized::init(context.clone(), cfg.clone())
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
                Oversized::init(context.clone(), cfg.clone())
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
    fn test_get_value_size_equals_crc_size() {
        // Tests the boundary condition where size = 4 (just CRC, no data).
        // This should fail because there's no actual data to decode.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), test_cfg())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (_, offset, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");

            // Size = 4 (exactly CRC_SIZE) means 0 bytes of actual data
            // This should fail with ChecksumMismatch or decode error
            let result = oversized.get_value(1, offset, 4).await;
            assert!(result.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_get_value_size_just_over_crc() {
        // Tests size = 5 (CRC + 1 byte of data).
        // This should fail because the data is too short to decode.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), test_cfg())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (_, offset, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized.sync(1).await.expect("Failed to sync");

            // Size = 5 means 1 byte of actual data (after stripping CRC)
            // This should fail with checksum mismatch since we're reading wrong bytes
            let result = oversized.get_value(1, offset, 5).await;
            assert!(result.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_maximum_section_numbers() {
        // Test recovery with very large section numbers near u64::MAX to check
        // for overflow edge cases in section arithmetic.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Use section numbers near u64::MAX
            let large_sections = [u64::MAX - 3, u64::MAX - 2, u64::MAX - 1];

            // Create and populate with large section numbers
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for &section in &large_sections {
                let value: TestValue = [(section & 0xFF) as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                let loc = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((section, loc));
                oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Simulate crash: truncate glob for middle section
            let middle_section = large_sections[1];
            let (blob, size) = context
                .open(&cfg.value_partition, &middle_section.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size / 2).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should recover without overflow panics
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First and last sections should still be valid
            let entry = oversized
                .get(large_sections[0], 0)
                .await
                .expect("Failed to get first section");
            assert_eq!(entry.id, large_sections[0]);

            let entry = oversized
                .get(large_sections[2], 0)
                .await
                .expect("Failed to get last section");
            assert_eq!(entry.id, large_sections[2]);

            // Middle section should have been rewound (no entries)
            assert!(oversized.get(middle_section, 0).await.is_err());

            // Verify we can still append to these large sections
            let new_value: TestValue = [0xAB; 16];
            let new_entry = TestEntry::new(999, 0, 0);
            let mut oversized = oversized;
            oversized
                .append(middle_section, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_crash_during_recovery_rewind() {
        // Tests a nested crash scenario: initial crash leaves inconsistent state,
        // then a second crash occurs during recovery's rewind operation.
        // This simulates the worst-case where recovery itself is interrupted.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Phase 1: Create valid data with 5 entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
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

            // Phase 2: Simulate first crash - truncate glob to lose last 2 entries
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(locations[2].1, locations[2].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Phase 3: Simulate crash during recovery's rewind
            // Recovery would try to rewind index from 5 entries to 3 entries.
            // Simulate partial rewind by manually truncating index to 4 entries
            // (as if crash occurred mid-rewind).
            let chunk_size = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let (index_blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open index blob");
            let partial_rewind_size = 4 * chunk_size; // 4 entries instead of 3
            index_blob
                .resize(partial_rewind_size)
                .await
                .expect("Failed to resize");
            index_blob.sync().await.expect("Failed to sync");
            drop(index_blob);

            // Phase 4: Second recovery attempt should handle the inconsistent state
            // Index has 4 entries, but glob only supports 3.
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to reinit after nested crash");

            // Only first 3 entries should be valid (recovery should rewind again)
            for i in 0..3u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let (_, offset, size) = locations[i as usize];
                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // Entry 3 should not exist (index was rewound to match glob)
            assert!(oversized.get(1, 3).await.is_err());

            // Verify append works after nested crash recovery
            let new_value: TestValue = [0xFF; 16];
            let new_entry = TestEntry::new(100, 0, 0);
            let mut oversized = oversized;
            let (pos, offset, _size) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append");
            assert_eq!(pos, 3); // Should be position 3 (after the 3 valid entries)

            // Verify the offset starts where entry 2 ended (no gaps)
            assert_eq!(offset, byte_end(locations[2].1, locations[2].2));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_crash_during_orphan_cleanup() {
        // Tests crash during orphan section cleanup: recovery starts removing
        // orphan value sections, but crashes mid-cleanup.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Phase 1: Create valid data in section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // Phase 2: Create orphan value sections 2, 3, 4 (no index entries)
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.with_label("glob"), glob_cfg)
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

            // Phase 3: Simulate partial orphan cleanup (section 2 removed, 3 and 4 remain)
            // This simulates a crash during cleanup_orphan_value_sections()
            context
                .remove(&cfg.value_partition, Some(&2u64.to_be_bytes()))
                .await
                .expect("Failed to remove section 2");

            // Phase 4: Recovery should complete the cleanup
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg.clone())
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

            // No orphan sections should remain
            assert_eq!(oversized.oldest_section(), Some(1));
            assert_eq!(oversized.newest_section(), Some(1));

            // Should be able to append to section 2 (now clean)
            let new_value: TestValue = [42; 16];
            let new_entry = TestEntry::new(42, 0, 0);
            let (pos, _, _) = oversized
                .append(2, new_entry, &new_value)
                .await
                .expect("Failed to append to section 2");
            assert_eq!(pos, 0); // First entry in new section

            oversized.destroy().await.expect("Failed to destroy");
        });
    }
}
