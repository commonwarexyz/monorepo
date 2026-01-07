//! Segmented journal for oversized values with crash recovery.
//!
//! This module combines a fixed-size index journal with a glob (value storage) to handle
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
//! - Glob value without index entry (orphan - acceptable)
//!
//! During initialization, each index entry's glob reference is validated:
//! 1. Check `value_offset + value_size <= glob_size`
//! 2. Invalid entries are skipped
//! 3. Index journal is rewound to exclude trailing invalid entries
//!
//! This allows async writes (glob first, then index) while ensuring consistency
//! after recovery.

use super::{
    fixed::{Config as FixedConfig, Journal as FixedJournal},
    glob::{Config as GlobConfig, Glob},
};
use crate::journal::Error;
use commonware_codec::{Codec, CodecFixed};
use commonware_runtime::{Metrics, Storage};
use futures::{future::join, stream::Stream};
use std::{marker::PhantomData, num::NonZeroUsize};
use tracing::{debug, warn};

/// Trait for index entries that reference oversized values in glob storage.
///
/// Implementations must provide access to the value location for crash recovery validation,
/// and a way to set the location when appending.
pub trait OversizedEntry: CodecFixed<Cfg = ()> + Clone {
    /// Returns `(value_offset, value_size)` for crash recovery validation.
    fn value_location(&self) -> (u64, u64);

    /// Returns a new entry with the value location set.
    ///
    /// Called during `append` after the value is written to glob storage.
    fn with_location(self, offset: u64, size: u64) -> Self;
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

    /// Write buffer size for both journals.
    pub write_buffer: NonZeroUsize,

    /// Optional compression level for values (using zstd).
    pub compression: Option<u8>,

    /// Codec configuration for values.
    pub codec_config: C,
}

/// Segmented journal for entries with oversized values.
///
/// Combines a fixed-size index journal with glob storage for variable-length values.
/// Provides coordinated operations and crash recovery.
pub struct Oversized<E: Storage + Metrics, I: OversizedEntry, V: Codec> {
    index: FixedJournal<E, I>,
    values: Glob<E, V>,
    _phantom: PhantomData<I>,
}

impl<E: Storage + Metrics, I: OversizedEntry, V: Codec> Oversized<E, I, V> {
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
            write_buffer: cfg.write_buffer,
        };
        let index = FixedJournal::init(context.with_label("index"), index_cfg).await?;

        let value_cfg = GlobConfig {
            partition: cfg.value_partition,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            write_buffer: cfg.write_buffer,
        };
        let values = Glob::init(context.with_label("values"), value_cfg).await?;

        let mut oversized = Self {
            index,
            values,
            _phantom: PhantomData,
        };

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

        // Collect sections to avoid borrowing issues
        let sections: Vec<u64> = self.index.sections().collect();

        for section in sections {
            let index_size = self.index.size(section).await?;
            if index_size == 0 {
                continue;
            }

            let glob_size = match self.values.size(section).await {
                Ok(size) => size,
                Err(Error::AlreadyPrunedToSection(oldest)) => {
                    warn!(
                        section,
                        oldest, "index has section that glob already pruned (crash during prune?)"
                    );
                    0
                }
                Err(e) => return Err(e),
            };
            let entry_count = index_size / chunk_size;

            // Check the LAST entry
            let last_pos = entry_count - 1;
            match self.index.get(section, last_pos).await {
                Ok(entry) => {
                    let (value_offset, value_size) = entry.value_location();
                    let entry_end = value_offset + value_size;

                    if entry_end <= glob_size {
                        // Last entry valid - all entries in this section are valid
                        continue;
                    }

                    // Last entry invalid - find last valid entry by scanning backwards
                    warn!(
                        section,
                        last_pos, glob_size, entry_end, "invalid entry: glob truncated"
                    );

                    let mut valid_count: u64 = 0;
                    for pos in (0..last_pos).rev() {
                        match self.index.get(section, pos).await {
                            Ok(entry) => {
                                let (offset, size) = entry.value_location();
                                if offset + size <= glob_size {
                                    valid_count = pos + 1;
                                    break;
                                }
                            }
                            Err(_) => {
                                // Corrupted entry - continue scanning
                                continue;
                            }
                        }
                    }

                    // Rewind to last valid entry
                    let valid_size = valid_count * chunk_size;
                    debug!(section, index_size, valid_size, "rewinding index journal");
                    self.index.rewind_section(section, valid_size).await?;
                }
                Err(_) => {
                    // Last entry corrupted - need to scan backwards
                    warn!(
                        section,
                        last_pos, "corrupted last entry, scanning backwards"
                    );

                    let mut valid_count: u64 = 0;
                    for pos in (0..last_pos).rev() {
                        match self.index.get(section, pos).await {
                            Ok(entry) => {
                                let (offset, size) = entry.value_location();
                                if offset + size <= glob_size {
                                    valid_count = pos + 1;
                                    break;
                                }
                            }
                            Err(_) => continue,
                        }
                    }

                    let valid_size = valid_count * chunk_size;
                    debug!(section, index_size, valid_size, "rewinding index journal");
                    self.index.rewind_section(section, valid_size).await?;
                }
            }
        }

        Ok(())
    }

    /// Append entry + value atomically (glob first, then index).
    ///
    /// The entry's value location is automatically set after the value is written.
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
    ) -> Result<(u64, u64, u64), Error> {
        // Write value first (glob)
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

    /// Get value using offset/size from entry.
    ///
    /// The offset should be the byte offset from `append()` or from the entry's `value_location()`.
    pub async fn get_value(&self, section: u64, offset: u64, size: u64) -> Result<V, Error> {
        self.values.get(section, offset, size).await
    }

    /// Replay index entries starting from given section.
    ///
    /// Returns a stream of `(section, position, entry)` tuples.
    pub async fn replay(
        &self,
        start_section: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, I), Error>> + '_, Error> {
        self.index.replay(start_section, buffer).await
    }

    /// Sync both journals for given section.
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        let (index_result, value_result) =
            join(self.index.sync(section), self.values.sync(section)).await;
        index_result?;
        value_result?;
        Ok(())
    }

    /// Sync all sections.
    pub async fn sync_all(&self) -> Result<(), Error> {
        let (index_result, value_result) =
            join(self.index.sync_all(), self.values.sync_all()).await;
        index_result?;
        value_result?;
        Ok(())
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

    /// Rewind both journals to specific sizes for a section.
    pub async fn rewind(
        &mut self,
        section: u64,
        index_size: u64,
        value_size: u64,
    ) -> Result<(), Error> {
        let (index_result, value_result) = join(
            self.index.rewind_section(section, index_size),
            self.values.rewind(section, value_size),
        )
        .await;
        index_result?;
        value_result?;
        Ok(())
    }

    /// Get sizes for checkpoint.
    ///
    /// Returns `(index_size, value_size)` for the given section.
    pub async fn sizes(&self, section: u64) -> Result<(u64, u64), Error> {
        let (index_size, value_size) =
            join(self.index.size(section), self.values.size(section)).await;
        Ok((index_size?, value_size?))
    }

    /// Returns the oldest section number, if any exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.index.oldest_section()
    }

    /// Destroy all underlying storage.
    pub async fn destroy(self) -> Result<(), Error> {
        let (index_result, value_result) = join(self.index.destroy(), self.values.destroy()).await;
        index_result?;
        value_result?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BufMut};
    use commonware_codec::{FixedSize, Read, ReadExt, Write};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Blob as _, Runner};
    use commonware_utils::NZUsize;

    /// Convert offset + size to byte end position (for truncation tests).
    fn byte_end(offset: u64, size: u64) -> u64 {
        offset + size
    }

    /// Test index entry that stores a u64 id and references a value.
    #[derive(Debug, Clone, PartialEq)]
    struct TestEntry {
        id: u64,
        value_offset: u64,
        value_size: u64,
    }

    impl TestEntry {
        fn new(id: u64, value_offset: u64, value_size: u64) -> Self {
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
            let value_size = u64::read(buf)?;
            Ok(Self {
                id,
                value_offset,
                value_size,
            })
        }
    }

    impl FixedSize for TestEntry {
        const SIZE: usize = u64::SIZE + u64::SIZE + u64::SIZE;
    }

    impl OversizedEntry for TestEntry {
        fn value_location(&self) -> (u64, u64) {
            (self.value_offset, self.value_size)
        }

        fn with_location(mut self, offset: u64, size: u64) -> Self {
            self.value_offset = offset;
            self.value_size = size;
            self
        }
    }

    fn test_cfg() -> Config<()> {
        Config {
            index_partition: "test_index".to_string(),
            value_partition: "test_values".to_string(),
            index_buffer_pool: PoolRef::new(NZUsize!(64), NZUsize!(8)),
            write_buffer: NZUsize!(1024),
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
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // No entries should be accessible
            let result = oversized.get(1, 0).await;
            assert!(result.is_err());

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

            // Corrupt the last index entry's checksum
            let (blob, size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Each entry is TestEntry::SIZE (16) + 4 (CRC32) = 20 bytes
            // Corrupt the CRC of the last entry
            let last_entry_crc_offset = size - 4;
            blob.write_at(vec![0xFF, 0xFF, 0xFF, 0xFF], last_entry_crc_offset)
                .await
                .expect("Failed to corrupt");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should detect corruption and scan backwards
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 4 entries should be valid
            for i in 0..4u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entry 4 should be gone (corrupted and rewound)
            assert!(oversized.get(1, 4).await.is_err());

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
            let oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init(context.clone(), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(1, 1).await.is_ok());

            // Entry 2 should be gone (truncated)
            assert!(oversized.get(1, 2).await.is_err());

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
                write_buffer: cfg.write_buffer,
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
            drop(oversized);

            // Simulate crash: truncate INDEX but leave GLOB intact
            // This creates orphan data in glob (glob ahead of index)
            let (blob, _size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Keep only first 2 index entries
            let chunk_size = (TestEntry::SIZE + 4) as u64; // entry + CRC32
            blob.resize(2 * chunk_size)
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
}
