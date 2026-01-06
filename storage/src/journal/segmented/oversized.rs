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
use futures::{future::join, pin_mut, stream::Stream, StreamExt};
use std::{collections::BTreeMap, marker::PhantomData, num::NonZeroUsize};
use tracing::{debug, warn};

/// Trait for index entries that reference oversized values in glob storage.
///
/// Implementations must provide access to the value location for crash recovery validation,
/// and a way to set the location when appending.
pub trait OversizedEntry: CodecFixed<Cfg = ()> + Clone {
    /// Returns `(value_offset, value_size)` for crash recovery validation.
    fn value_location(&self) -> (u32, u32);

    /// Returns a new entry with the value location set.
    ///
    /// Called during `append` after the value is written to glob storage.
    fn with_location(self, offset: u32, size: u32) -> Self;
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

    /// Replay buffer size for streaming entries.
    pub replay_buffer: NonZeroUsize,

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
        oversized.recover(cfg.replay_buffer).await?;

        Ok(oversized)
    }

    /// Perform crash recovery by validating index entries against glob sizes.
    async fn recover(&mut self, replay_buffer: NonZeroUsize) -> Result<(), Error> {
        // First pass: collect glob sizes for all sections
        // We need to know glob sizes before we can validate entries
        let mut glob_sizes: BTreeMap<u64, u64> = BTreeMap::new();

        // Track last valid index size per section
        let mut valid_index_sizes: BTreeMap<u64, u64> = BTreeMap::new();

        // Track sections that have invalid entries (need rewinding)
        let mut invalid_sections: BTreeMap<u64, u64> = BTreeMap::new();

        // Replay index entries and validate
        // Collect all entries first to avoid borrow issues
        let entries: Vec<(u64, u32, I)> = {
            let stream = self.index.replay(0, replay_buffer).await?;
            pin_mut!(stream);

            let mut entries = Vec::new();
            while let Some(result) = stream.next().await {
                entries.push(result?);
            }
            entries
        };

        // Now validate each entry
        for (section, position, entry) in entries {
            // Get or fetch glob size for this section
            let glob_size = match glob_sizes.get(&section) {
                Some(&size) => size,
                None => {
                    let size = self.values.size(section).await.unwrap_or(0);
                    glob_sizes.insert(section, size);
                    size
                }
            };

            // Skip entries in sections we've already marked as invalid
            if invalid_sections.contains_key(&section) {
                continue;
            }

            // Validate entry's glob reference
            let (value_offset, value_size) = entry.value_location();
            let entry_end = value_offset as u64 + value_size as u64;

            if entry_end > glob_size {
                // Invalid entry - glob data doesn't exist
                warn!(
                    section,
                    position, glob_size, entry_end, "invalid entry: glob truncated"
                );

                // Mark this section as needing rewind to last valid size
                let rewind_to = valid_index_sizes.get(&section).copied().unwrap_or(0);
                invalid_sections.insert(section, rewind_to);
                continue;
            }

            // Valid entry - track its position
            // Fixed journal stores: entry + CRC32 checksum (4 bytes)
            let chunk_size = I::SIZE + std::mem::size_of::<u32>();
            let valid_size = (position as u64 + 1) * chunk_size as u64;
            valid_index_sizes.insert(section, valid_size);
        }

        // Rewind sections with trailing invalid entries
        for (section, valid_size) in invalid_sections {
            let current_size = self.index.size(section).await?;
            if current_size > valid_size {
                debug!(section, current_size, valid_size, "rewinding index journal");
                self.index.rewind_section(section, valid_size).await?;
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
    /// - `offset`: Byte offset in glob where value is stored
    /// - `size`: Size of value in glob (including checksum)
    pub async fn append(
        &mut self,
        section: u64,
        entry: I,
        value: &V,
    ) -> Result<(u32, u32, u32), Error> {
        // Write value first (glob)
        let (offset, size) = self.values.append(section, value).await?;

        // Update entry with actual location and write to index
        let entry_with_location = entry.with_location(offset, size);
        let position = self.index.append(section, entry_with_location).await?;

        Ok((position, offset, size))
    }

    /// Get entry at position (index entry only, not value).
    pub async fn get(&self, section: u64, position: u32) -> Result<I, Error> {
        self.index.get(section, position).await
    }

    /// Get value using offset/size from entry.
    pub async fn get_value(&self, section: u64, offset: u32, size: u32) -> Result<V, Error> {
        self.values.get(section, offset, size).await
    }

    /// Replay index entries starting from given section.
    ///
    /// Returns a stream of `(section, position, entry)` tuples.
    pub async fn replay(
        &self,
        start_section: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u32, I), Error>> + '_, Error> {
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

    /// Prune both journals.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        let (index_result, value_result) =
            join(self.index.prune(min), self.values.prune(min)).await;
        index_result?;
        value_result?;
        Ok(())
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

    /// Test index entry that stores a u64 id and references a value.
    #[derive(Debug, Clone, PartialEq)]
    struct TestEntry {
        id: u64,
        value_offset: u32,
        value_size: u32,
    }

    impl TestEntry {
        fn new(id: u64, value_offset: u32, value_size: u32) -> Self {
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
            let value_offset = u32::read(buf)?;
            let value_size = u32::read(buf)?;
            Ok(Self {
                id,
                value_offset,
                value_size,
            })
        }
    }

    impl FixedSize for TestEntry {
        const SIZE: usize = u64::SIZE + u32::SIZE + u32::SIZE;
    }

    impl OversizedEntry for TestEntry {
        fn value_location(&self) -> (u32, u32) {
            (self.value_offset, self.value_size)
        }

        fn with_location(mut self, offset: u32, size: u32) -> Self {
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
            replay_buffer: NZUsize!(1024),
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
            let keep_size = locations[2].1 as u64 + locations[2].2 as u64;
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
}
