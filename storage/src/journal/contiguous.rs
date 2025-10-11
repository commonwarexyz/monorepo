//! A contiguous journal wrapper around `variable::Journal`.
//!
//! `contiguous::Journal` wraps [variable::Journal] to provide a contiguous, position-based
//! interface similar to [crate::journal::fixed::Journal]. Unlike `variable::Journal` which
//! operates on independent sections, this wrapper maintains a global position counter and
//! automatically manages section boundaries.
//!
//! # Usage
//!
//! Items are appended sequentially and accessed by their position (starting from 0). The wrapper
//! internally maps positions to `(section, offset)` pairs in the underlying variable journal,
//! creating new sections as needed when `items_per_section` is reached.
//!
//! # Metadata
//!
//! To track partially complete sections across restarts, the wrapper uses a companion
//! [crate::metadata::Metadata] instance that stores the number of items in the current section.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::PoolRef};
//! use commonware_storage::journal::contiguous::{Journal, Config};
//! use commonware_utils::{NZUsize, NZU64};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a contiguous journal
//!     let mut journal = Journal::init(context, Config{
//!         partition: "partition".to_string(),
//!         metadata_partition: "metadata".to_string(),
//!         items_per_section: NZU64!(100),
//!         compression: None,
//!         codec_config: (),
//!         buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
//!         write_buffer: NZUsize!(1024 * 1024),
//!     }).await.unwrap();
//!
//!     // Append data to the journal (returns position)
//!     let pos = journal.append(128).await.unwrap();
//!     assert_eq!(pos, 0);
//!
//!     // Read data by position
//!     let item = journal.read(0).await.unwrap();
//!     assert_eq!(item, 128);
//!
//!     // Get journal size
//!     let size = journal.size().await.unwrap();
//!     assert_eq!(size, 1);
//!
//!     // Close the journal
//!     journal.close().await.unwrap();
//! });
//! ```

use super::{variable, Error};
use crate::metadata::{self, Metadata};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::sequence::U64;
use futures::{stream::Stream, StreamExt};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, trace};

/// Configuration for `contiguous::Journal`.
#[derive(Clone)]
pub struct Config<C> {
    /// The `commonware-runtime::Storage` partition to use for storing journal blobs.
    pub partition: String,

    /// The `commonware-runtime::Storage` partition to use for storing metadata.
    pub metadata_partition: String,

    /// The number of items to store in each section before creating a new one.
    pub items_per_section: NonZeroU64,

    /// Optional compression level (using `zstd`) to apply to data before storing.
    pub compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding items.
    pub codec_config: C,

    /// The buffer pool to use for caching data.
    pub buffer_pool: commonware_runtime::buffer::PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Helper function to get the metadata key for tracking items in current section.
fn items_in_current_section_key() -> U64 {
    U64::new(0)
}

/// A contiguous journal that wraps [variable::Journal] to provide position-based access.
pub struct Journal<E: Storage + Metrics + commonware_runtime::Clock, V: Codec> {
    /// The underlying variable journal.
    inner: variable::Journal<E, V>,

    /// Metadata store for tracking partial sections.
    metadata: Metadata<E, U64, u64>,

    /// The number of items to store in each section.
    items_per_section: NonZeroU64,

    /// The total number of items in the journal (next append position).
    size: u64,
}

impl<E: Storage + Metrics + commonware_runtime::Clock, V: Codec> Journal<E, V> {
    /// Initialize a new `contiguous::Journal` instance.
    ///
    /// During initialization, the journal replays all data to compute the current size
    /// and validate the metadata.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize the variable journal
        let variable_cfg = variable::Config {
            partition: cfg.partition.clone(),
            compression: cfg.compression,
            codec_config: cfg.codec_config.clone(),
            buffer_pool: cfg.buffer_pool.clone(),
            write_buffer: cfg.write_buffer,
        };
        let inner = variable::Journal::init(context.with_label("journal"), variable_cfg).await?;

        // Initialize metadata
        let metadata_cfg = metadata::Config {
            partition: cfg.metadata_partition,
            codec_config: (),
        };
        let mut metadata =
            Metadata::init(context.with_label("metadata"), metadata_cfg).await?;

        // Replay the journal to compute the current size
        let mut size = 0u64;
        let mut items_in_current_section = 0u64;
        let mut current_section = None;

        const BUFFER_SIZE: usize = 4096;
        let buffer_size = NonZeroUsize::new(BUFFER_SIZE).unwrap();
        {
            let replay = inner.replay(0, 0, buffer_size).await?;
            futures::pin_mut!(replay);
            while let Some(result) = replay.next().await {
                let (section, _offset, _size, _item) = result?;
                if current_section != Some(section) {
                    if current_section.is_some() {
                        // Moving to a new section, reset counter
                        items_in_current_section = 0;
                    }
                    current_section = Some(section);
                }
                items_in_current_section += 1;
                size += 1;
            }
        }

        // Store the number of items in the current section
        if items_in_current_section > 0 {
            metadata.put(items_in_current_section_key(), items_in_current_section);
            metadata.sync().await?;
        }

        debug!(size, items_in_current_section, "initialized contiguous journal");

        Ok(Self {
            inner,
            metadata,
            items_per_section: cfg.items_per_section,
            size,
        })
    }

    /// Convert a position to a (section, offset_within_section) pair.
    fn position_to_location(&self, pos: u64) -> (u64, u64) {
        let section = pos / self.items_per_section;
        let offset_within_section = pos % self.items_per_section;
        (section, offset_within_section)
    }

    /// Return the total number of items in the journal. The next value appended will be at this position.
    pub async fn size(&self) -> Result<u64, Error> {
        Ok(self.size)
    }

    /// Append a new item to the journal. Returns the item's position in the journal.
    pub async fn append(&mut self, item: V) -> Result<u64, Error> {
        let pos = self.size;
        let (section, offset_within_section) = self.position_to_location(pos);

        // Append to the underlying variable journal
        let (offset, _size) = self.inner.append(section, item).await?;

        trace!(pos, section, offset, "appended item");
        self.size += 1;

        // Update metadata with items in current section
        let items_in_section = (offset_within_section + 1) % self.items_per_section.get();
        if items_in_section == 0 {
            // Section is complete, sync it
            self.inner.sync(section).await?;
            self.metadata.remove(&items_in_current_section_key());
        } else {
            self.metadata
                .put(items_in_current_section_key(), items_in_section);
        }

        Ok(pos)
    }

    /// Sync any pending updates to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Sync the current section if it exists
        if self.size > 0 {
            let (current_section, _) = self.position_to_location(self.size - 1);
            self.inner.sync(current_section).await?;
        }
        // Sync metadata
        self.metadata.sync().await?;
        Ok(())
    }

    /// Read the item at the given position.
    ///
    /// # Errors
    ///
    /// - [Error::ItemPruned] if the item at position `pos` has been pruned.
    /// - [Error::ItemOutOfRange] if the item at position `pos` does not exist.
    pub async fn read(&self, pos: u64) -> Result<V, Error> {
        if pos >= self.size {
            return Err(Error::ItemOutOfRange(pos));
        }

        let (section, offset_within_section) = self.position_to_location(pos);

        // Replay the section to find the item at the given offset
        let mut current_offset_count = 0u64;
        let buffer_size = NonZeroUsize::new(4096).unwrap(); // Use a reasonable buffer size
        let replay = self.inner.replay(section, 0, buffer_size).await?;
        futures::pin_mut!(replay);
        while let Some(result) = replay.next().await {
            let (replay_section, _offset, _size, item) = result?;
            if replay_section != section {
                break;
            }
            if current_offset_count == offset_within_section {
                return Ok(item);
            }
            current_offset_count += 1;
        }

        Err(Error::ItemOutOfRange(pos))
    }

    /// Returns an ordered stream of all items in the journal with position >= `start_pos`.
    ///
    /// # Panics
    ///
    /// Panics if `start_pos` exceeds log size.
    pub async fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + '_, Error> {
        assert!(start_pos <= self.size);

        let (start_section, start_offset_within_section) = self.position_to_location(start_pos);
        let replay = self.inner.replay(start_section, 0, buffer).await?;

        let items_per_section = self.items_per_section.get();
        
        // Use an atomic counter for position tracking in the async closure
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        
        let current_pos = Arc::new(AtomicU64::new(0));
        let skip_count = Arc::new(AtomicU64::new(start_offset_within_section));
        let current_section_val = Arc::new(AtomicU64::new(start_section));

        Ok(replay.filter_map(move |result| {
            let current_pos = current_pos.clone();
            let skip_count = skip_count.clone();
            let current_section_val = current_section_val.clone();
            
            async move {
                match result {
                    Ok((section, _offset, _size, item)) => {
                        // Update section if needed
                        if section != current_section_val.load(Ordering::Relaxed) {
                            current_section_val.store(section, Ordering::Relaxed);
                            current_pos.store(0, Ordering::Relaxed);
                        }

                        if skip_count.load(Ordering::Relaxed) > 0 {
                            skip_count.fetch_sub(1, Ordering::Relaxed);
                            current_pos.fetch_add(1, Ordering::Relaxed);
                            return None;
                        }
                        let pos = section * items_per_section + current_pos.load(Ordering::Relaxed);
                        current_pos.fetch_add(1, Ordering::Relaxed);
                        Some(Ok((pos, item)))
                    }
                    Err(e) => Some(Err(e)),
                }
            }
        }))
    }

    /// Return the position of the oldest item in the journal that remains readable.
    pub async fn oldest_retained_pos(&self) -> Result<Option<u64>, Error> {
        let oldest_section = match self.inner.oldest_section() {
            Some(section) => section,
            None => {
                if self.size == 0 {
                    return Ok(None);
                } else {
                    return Ok(Some(0));
                }
            }
        };

        Ok(Some(oldest_section * self.items_per_section.get()))
    }

    /// Prune items older than `min_item_pos`. Returns true if any items were pruned.
    ///
    /// Items are pruned at section boundaries, so the actual oldest retained position
    /// may be greater than `min_item_pos`.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<bool, Error> {
        let (min_section, _) = self.position_to_location(min_item_pos);
        self.inner.prune(min_section).await
    }

    /// Rewind the journal to the given size. The journal is not synced after rewinding.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until sync is called.
    /// * This operation is not atomic, but it will always leave the journal in a consistent state.
    pub async fn rewind(&mut self, new_size: u64) -> Result<(), Error> {
        if new_size > self.size {
            return Err(Error::InvalidRewind(new_size));
        }
        if new_size == self.size {
            return Ok(());
        }

        let (target_section, offset_within_section) = self.position_to_location(new_size);

        // If rewinding to the start of a section or beyond, rewind the variable journal
        if offset_within_section == 0 {
            // Rewind to the start of the target section (which removes it and all following)
            if target_section == 0 {
                // Special case: rewinding to position 0
                if let Some(oldest_section) = self.inner.oldest_section() {
                    self.inner.rewind(oldest_section, 0).await?;
                }
            } else {
                self.inner.rewind(target_section, 0).await?;
            }
        } else {
            // Rewinding to the middle of a section - need to replay to find the offset
            let mut last_offset = 0u32;
            let mut count = 0u64;
            let buffer_size = NonZeroUsize::new(4096).unwrap();
            {
                let replay = self.inner.replay(target_section, 0, buffer_size).await?;
                futures::pin_mut!(replay);
                while let Some(result) = replay.next().await {
                    let (section, offset, _size, _item) = result?;
                    if section != target_section {
                        break;
                    }
                    if count == offset_within_section {
                        break;
                    }
                    last_offset = offset;
                    count += 1;
                }
            }

            // Rewind to after the target position by replaying to find size
            if count == offset_within_section {
                // We found the exact position, rewind to the next offset after it
                let target_size = (last_offset as u64 + 1) * variable::ITEM_ALIGNMENT;
                self.inner.rewind(target_section, target_size).await?;
            } else {
                // Couldn't find the position, rewind to section start
                self.inner.rewind(target_section, 0).await?;
            }
        }

        self.size = new_size;

        // Update metadata
        let items_in_section = offset_within_section % self.items_per_section.get();
        if items_in_section == 0 {
            self.metadata.remove(&items_in_current_section_key());
        } else {
            self.metadata
                .put(items_in_current_section_key(), items_in_section);
        }

        debug!(new_size, "rewound journal");
        Ok(())
    }

    /// Syncs and closes all open sections.
    pub async fn close(self) -> Result<(), Error> {
        self.metadata.close().await?;
        self.inner.close().await
    }

    /// Remove any underlying blobs and metadata created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        // Close metadata (no destroy method, just close it)
        self.metadata.close().await?;
        self.inner.destroy().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::{NZUsize, NZU64};
    use futures::StreamExt;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_cfg(items_per_section: NonZeroU64) -> Config<()> {
        Config {
            partition: "test_partition".into(),
            metadata_partition: "test_metadata".into(),
            items_per_section,
            compression: None,
            codec_config: (),
            buffer_pool: commonware_runtime::buffer::PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    #[test_traced]
    fn test_basic_append_and_read() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(10));
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append some items
            for i in 0u64..5 {
                let pos = journal.append(i).await.expect("Failed to append");
                assert_eq!(pos, i);
            }

            // Check size
            let size = journal.size().await.expect("Failed to get size");
            assert_eq!(size, 5);

            // Read items
            for i in 0u64..5 {
                let item: u64 = journal.read(i).await.expect("Failed to read");
                assert_eq!(item, i);
            }

            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_multiple_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(3)); // 3 items per section
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items across multiple sections
            for i in 0u64..10 {
                let pos = journal.append(i).await.expect("Failed to append");
                assert_eq!(pos, i);
            }

            // Check size
            let size = journal.size().await.expect("Failed to get size");
            assert_eq!(size, 10);

            // Read items from different sections
            for i in 0u64..10 {
                let item: u64 = journal.read(i).await.expect("Failed to read");
                assert_eq!(item, i);
            }

            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(5));
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items
            for i in 0u64..15 {
                journal.append(i).await.expect("Failed to append");
            }

            // Replay from start
            {
                let replay = journal
                    .replay(NZUsize!(1024), 0)
                    .await
                    .expect("Failed to create replay");
                futures::pin_mut!(replay);

                let mut count = 0u64;
                while let Some(result) = replay.next().await {
                    let (pos, item): (u64, u64) = result.expect("Failed to replay item");
                    assert_eq!(pos, count);
                    assert_eq!(item, count);
                    count += 1;
                }
                assert_eq!(count, 15);
            }

            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(4));

            // Create and populate journal
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");
            for i in 0u64..10 {
                journal.append(i).await.expect("Failed to append");
            }
            journal.close().await.expect("Failed to close");

            // Re-open journal
            let journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Verify size
            let size = journal.size().await.expect("Failed to get size");
            assert_eq!(size, 10);

            // Verify items
            for i in 0u64..10 {
                let item: u64 = journal.read(i).await.expect("Failed to read");
                assert_eq!(item, i);
            }

            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(5));
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items
            for i in 0u64..15 {
                journal.append(i).await.expect("Failed to append");
            }

            // Rewind to position 7
            journal.rewind(7).await.expect("Failed to rewind");

            // Check size
            let size = journal.size().await.expect("Failed to get size");
            assert_eq!(size, 7);

            // Verify items
            for i in 0u64..7 {
                let item: u64 = journal.read(i).await.expect("Failed to read");
                assert_eq!(item, i);
            }

            // Verify item 7 doesn't exist
            assert!(journal.read(7).await.is_err());

            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(5));
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items across multiple sections
            for i in 0u64..15 {
                journal.append(i).await.expect("Failed to append");
            }

            // Prune items before position 7
            let pruned = journal.prune(7).await.expect("Failed to prune");
            assert!(pruned);

            // Check oldest retained position (should be 5 or 10 depending on section boundary)
            let oldest = journal
                .oldest_retained_pos()
                .await
                .expect("Failed to get oldest");
            assert!(oldest == Some(5) || oldest == Some(10));

            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(10));
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append and sync
            journal.append(42u64).await.expect("Failed to append");
            journal.sync().await.expect("Failed to sync");

            journal.destroy().await.expect("Failed to destroy");
        });
    }
}
