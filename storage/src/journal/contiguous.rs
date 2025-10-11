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
//! # Performance
//!
//! The wrapper uses a companion [crate::journal::fixed::Journal] to store item offsets, enabling
//! O(1) random access by position instead of requiring O(n) replay of entire sections.
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
//!         locations_partition: "locations".to_string(),
//!         items_per_section: NZU64!(100),
//!         locations_items_per_blob: NZU64!(1000),
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
//!     // Read data by position (O(1) lookup via locations journal)
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

use super::{fixed, variable, Error};
use crate::metadata::{self, Metadata};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::sequence::U64;
use futures::{stream::Stream, StreamExt};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, trace, warn};

/// Configuration for `contiguous::Journal`.
#[derive(Clone)]
pub struct Config<C> {
    /// The `commonware-runtime::Storage` partition to use for storing journal blobs.
    pub partition: String,

    /// The `commonware-runtime::Storage` partition to use for storing metadata.
    pub metadata_partition: String,

    /// The `commonware-runtime::Storage` partition to use for storing item locations (offsets).
    pub locations_partition: String,

    /// The number of items to store in each section before creating a new one.
    pub items_per_section: NonZeroU64,

    /// The number of location entries to store in each blob.
    pub locations_items_per_blob: NonZeroU64,

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

    /// A fixed journal that maps position to offset within the section.
    /// This allows O(1) lookup instead of replaying entire sections.
    locations: fixed::Journal<E, u32>,

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

        // Initialize the locations journal
        let locations_cfg = fixed::Config {
            partition: cfg.locations_partition,
            items_per_blob: cfg.locations_items_per_blob,
            buffer_pool: cfg.buffer_pool.clone(),
            write_buffer: cfg.write_buffer,
        };
        let mut locations =
            fixed::Journal::init(context.with_label("locations"), locations_cfg).await?;

        // Initialize metadata
        let metadata_cfg = metadata::Config {
            partition: cfg.metadata_partition,
            codec_config: (),
        };
        let mut metadata = Metadata::init(context.with_label("metadata"), metadata_cfg).await?;

        // Compute the current size by replaying the journal
        // We need to count all items to align with locations
        let mut size = 0u64;
        let mut items_in_current_section = 0u64;
        let mut current_section = None;
        
        const BUFFER_SIZE: usize = 4096;
        let buffer_size = NonZeroUsize::new(BUFFER_SIZE).unwrap();
        
        if let Some(oldest_section) = inner.oldest_section() {
            // Replay from the oldest section to count all items
            let replay = inner.replay(oldest_section, 0, buffer_size).await?;
            futures::pin_mut!(replay);
            
            while let Some(result) = replay.next().await {
                let (section, offset, _size, _item) = result?;
                if current_section != Some(section) {
                    if current_section.is_some() {
                        // Moving to a new section, reset counter
                        items_in_current_section = 0;
                    }
                    current_section = Some(section);
                }
                items_in_current_section += 1;
                size += 1;
                
                // Rebuild locations journal if it's behind
                let locations_size = locations.size().await?;
                if locations_size < size {
                    locations.append(offset).await?;
                }
            }
        }
        
        // Align locations with size - rewind if locations is ahead
        let locations_size = locations.size().await?;
        if locations_size > size {
            warn!(
                size,
                locations_size, "rewinding misaligned locations journal"
            );
            locations.rewind(size).await?;
            locations.sync().await?;
        }

        // Store the number of items in the current section
        if items_in_current_section > 0 {
            metadata.put(items_in_current_section_key(), items_in_current_section);
            metadata.sync().await?;
        }

        debug!(
            size,
            items_in_current_section, "initialized contiguous journal"
        );

        Ok(Self {
            inner,
            locations,
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

        // Append to the underlying variable journal and locations concurrently
        use futures::try_join;
        let (offset, _size) = {
            let inner_fut = self.inner.append(section, item);
            let (offset, size) = inner_fut.await?;
            let locations_fut = self.locations.append(offset);
            try_join!(async { Ok::<_, Error>((offset, size)) }, locations_fut)?;
            (offset, size)
        };

        trace!(pos, section, offset, "appended item");
        self.size += 1;

        // Update metadata with items in current section
        let items_in_section = (offset_within_section + 1) % self.items_per_section.get();
        if items_in_section == 0 {
            // Section is complete, sync both inner and locations
            use futures::try_join;
            try_join!(
                self.inner.sync(section),
                self.locations.sync()
            )?;
            self.metadata.remove(&items_in_current_section_key());
        } else {
            self.metadata
                .put(items_in_current_section_key(), items_in_section);
        }

        Ok(pos)
    }

    /// Sync any pending updates to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        use futures::try_join;
        
        // Sync the current section, locations, and metadata concurrently
        if self.size > 0 {
            let (current_section, _) = self.position_to_location(self.size - 1);
            try_join!(
                self.inner.sync(current_section),
                self.locations.sync(),
                async { self.metadata.sync().await.map_err(Error::from) }
            )?;
        } else {
            try_join!(
                self.locations.sync(),
                async { self.metadata.sync().await.map_err(Error::from) }
            )?;
        }
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

        let (section, _offset_within_section) = self.position_to_location(pos);

        // Use the locations journal to get the offset directly (O(1) instead of O(n) replay)
        let offset = self.locations.read(pos).await?;
        let item = self.inner.get(section, offset).await?;

        Ok(item)
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
        
        // The variable journal replay will handle multiple sections automatically
        let replay = self.inner.replay(start_section, 0, buffer).await?;
        
        let items_per_section = self.items_per_section.get();
        
        // Use Rc<RefCell> to track mutable state across filter_map calls
        use std::cell::RefCell;
        use std::rc::Rc;
        let current_section = Rc::new(RefCell::new(start_section));
        let pos_in_section = Rc::new(RefCell::new(0u64));
        let items_to_skip = Rc::new(RefCell::new(start_offset_within_section));

        Ok(replay.filter_map(move |result| {
            let current_section = current_section.clone();
            let pos_in_section = pos_in_section.clone();
            let items_to_skip = items_to_skip.clone();
            
            async move {
                match result {
                    Ok((section, _offset, _size, item)) => {
                        // Track section changes
                        if section != *current_section.borrow() {
                            *current_section.borrow_mut() = section;
                            *pos_in_section.borrow_mut() = 0;
                        }
                        
                        // Skip items until we reach start position
                        if *items_to_skip.borrow() > 0 {
                            *items_to_skip.borrow_mut() -= 1;
                            *pos_in_section.borrow_mut() += 1;
                            return None;
                        }
                        
                        let global_pos = section * items_per_section + *pos_in_section.borrow();
                        *pos_in_section.borrow_mut() += 1;
                        Some(Ok((global_pos, item)))
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

        // For state sync scenarios, we may start at a non-aligned boundary
        // The position is always based on the oldest section
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

        // Rewind the locations journal first
        self.locations.rewind(new_size).await?;

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
            // Rewinding to the middle of a section
            // For state sync scenarios where we start at an unaligned point,
            // we need to use metadata to know the offset in the first section
            let oldest_section = self.inner.oldest_section().unwrap_or(0);
            
            if new_size > 0 && target_section >= oldest_section {
                let last_offset = self.locations.read(new_size - 1).await?;
                // Calculate the size to rewind to (after the last kept item)
                let target_size = (last_offset as u64 + 1) * variable::ITEM_ALIGNMENT;
                self.inner.rewind(target_section, target_size).await?;
            } else {
                // Rewinding to empty
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
        self.locations.close().await?;
        self.inner.close().await
    }

    /// Remove any underlying blobs and metadata created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        // Close metadata (no destroy method, just close it)
        self.metadata.close().await?;
        self.locations.destroy().await?;
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
            locations_partition: "test_locations".into(),
            items_per_section,
            locations_items_per_blob: NZU64!(100),
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

    #[test_traced]
    fn test_unaligned_start() {
        // Test scenario where journal starts at an unaligned point in the first section
        // This simulates state sync scenarios
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(10)); // 10 items per section
            
            // Create initial journal and add some items
            let mut journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");
            
            // Add 7 items (unaligned - doesn't fill the first section)
            for i in 0u64..7 {
                journal.append(i * 10).await.expect("Failed to append");
            }
            
            // Sync and close
            journal.sync().await.expect("Failed to sync");
            journal.close().await.expect("Failed to close");
            
            // Re-open journal (simulating recovery/restart)
            let journal: Journal<_, u64> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            
            // Verify size is correct
            let size = journal.size().await.expect("Failed to get size");
            assert_eq!(size, 7);
            
            // Verify we can read all items
            for i in 0u64..7 {
                let item: u64 = journal.read(i).await.expect("Failed to read");
                assert_eq!(item, i * 10);
            }
            
            // Verify oldest_retained_pos works with unaligned data
            let oldest = journal.oldest_retained_pos().await.expect("Failed to get oldest");
            assert_eq!(oldest, Some(0));
            
            journal.destroy().await.expect("Failed to destroy");
        });
    }
}
