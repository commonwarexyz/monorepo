//! An append-only log for storing fixed length _items_ on disk.
//!
//! In addition to replay, stored items can be fetched directly by their `position` in the journal,
//! where position is defined as the item's order of insertion starting from 0, unaffected by
//! pruning.
//!
//! _See [super::variable] for a journal that supports variable length items._
//!
//! # Format
//!
//! Data stored in a `fixed::Journal` is persisted in one of many Blobs. Each `Blob` contains a
//! configurable maximum of `items_per_blob`, with page-level data integrity provided by a buffer
//! pool.
//!
//! ```text
//! +--------+----- --+--- -+----------+
//! | item_0 | item_1 | ... | item_n-1 |
//! +--------+-----------+--------+----0
//!
//! n = config.items_per_blob
//! ```
//!
//! The most recent blob may not necessarily be full, in which case it will contain fewer than the
//! maximum number of items.
//!
//! Data fetched from disk is always checked for integrity before being returned. If the data is
//! found to be invalid, an error is returned instead.
//!
//! # Open Blobs
//!
//! All `Blobs` in a given `partition` are kept open during the lifetime of `Journal`. You can limit
//! the number of open blobs by using a higher number of `items_per_blob` and/or pruning old items.
//!
//! # Consistency
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the caller
//! to determine when to force pending data to be written to `Storage` using the `sync` method. When
//! calling `close`, all pending data is automatically synced and any open blobs are closed.
//!
//! # Pruning
//!
//! The `prune` method allows the `Journal` to prune blobs consisting entirely of items prior to a
//! given point in history.
//!
//! # State Sync
//!
//! `Journal::init_sync` initializes a journal for state sync, handling existing data appropriately:
//! - If no data exists, creates a journal at the sync range start
//! - If data exists within range, prunes to the lower bound
//! - If data exceeds the range, returns an error
//! - If data is stale (before range), destroys and recreates
//!
//! # Replay
//!
//! The `replay` method supports fast reading of all unpruned items into memory.

use crate::{
    journal::{
        contiguous::MutableContiguous,
        segmented::fixed::{Config as SegmentedConfig, Journal as SegmentedJournal},
        Error,
    },
    mmr::Location,
    Persistable,
};
use commonware_codec::CodecFixedShared;
use commonware_runtime::{buffer::PoolRef, Metrics, Storage};
use futures::{stream::Stream, StreamExt};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
};
use tracing::debug;

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use for storing journal blobs.
    pub partition: String,

    /// The maximum number of journal items to store in each blob.
    ///
    /// Any unpruned historical blobs will contain exactly this number of items.
    /// Only the newest blob may contain fewer items.
    pub items_per_blob: NonZeroU64,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Implementation of `Journal` storage.
///
/// This is implemented as a wrapper around [SegmentedJournal] that provides position-based access
/// where positions are automatically mapped to (section, position_in_section) pairs.
///
/// # Repair
///
/// Like
/// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
/// and
/// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
/// the first invalid data read will be considered the new end of the journal (and the
/// underlying blob will be truncated to the last valid item). Repair is performed
/// by the underlying [SegmentedJournal] during init.
pub struct Journal<E: Storage + Metrics, A: CodecFixedShared> {
    inner: SegmentedJournal<E, A>,

    /// The maximum number of items per blob (section).
    items_per_blob: u64,

    /// Total number of items appended (not affected by pruning).
    size: u64,
}

impl<E: Storage + Metrics, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry in bytes.
    pub const CHUNK_SIZE: usize = SegmentedJournal::<E, A>::CHUNK_SIZE;

    /// Size of each entry in bytes (as u64).
    pub const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. The `replay` method can be
    /// used to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        let items_per_blob = cfg.items_per_blob.get();

        let segmented_cfg = SegmentedConfig {
            partition: cfg.partition,
            buffer_pool: cfg.buffer_pool,
            write_buffer: cfg.write_buffer,
        };

        let mut inner = SegmentedJournal::init(context, segmented_cfg).await?;

        // Calculate size and pruning_boundary from the inner journal's state
        let oldest_section = inner.oldest_section();
        let newest_section = inner.newest_section();

        let size = match (oldest_section, newest_section) {
            (Some(_), Some(newest)) => {
                // Compute size from the tail (newest) section
                let tail_len = inner.section_len(newest).await?;
                newest * items_per_blob + tail_len
            }
            _ => 0,
        };

        // Invariant: Tail blob must exist, even if empty. This ensures we can reconstruct size on
        // reopen even after pruning all items. The tail blob is at `size / items_per_blob` (where
        // the next append would go).
        let tail_section = size / items_per_blob;
        inner.ensure_section_exists(tail_section).await?;

        Ok(Self {
            inner,
            items_per_blob,
            size,
        })
    }

    /// Initialize a new `Journal` instance in a pruned state at a given size.
    ///
    /// This is used for state sync to create a journal that appears to have had `size` items
    /// appended and then pruned up to that point.
    ///
    /// # Arguments
    /// * `context` - The storage context
    /// * `cfg` - Configuration for the journal
    /// * `size` - The number of operations that have been "pruned"
    ///
    /// # Behavior
    /// - Creates only the tail blob at the section that would contain position `size-1`
    /// - The items in the tail blob before `size` are filled with zeros (dummy data)
    /// - `oldest_retained_pos()` returns the start of the tail section, matching behavior if the
    ///   journal were reopened normally
    /// - Positions within the tail section but before `size` contain dummy zero data
    ///
    /// # Invariants
    /// - The directory given by `cfg.partition` should be empty
    pub async fn init_at_size(context: E, cfg: Config, size: u64) -> Result<Self, Error> {
        let items_per_blob = cfg.items_per_blob.get();

        // Calculate the tail blob section and items within it
        let tail_section = size / items_per_blob;
        let tail_items = size % items_per_blob;

        // Initialize the segmented journal (empty)
        let segmented_cfg = SegmentedConfig {
            partition: cfg.partition,
            buffer_pool: cfg.buffer_pool,
            write_buffer: cfg.write_buffer,
        };

        let mut inner = SegmentedJournal::init(context, segmented_cfg).await?;

        // Initialize the tail section with zero-filled items if needed. This uses resize internally
        // which appropriately uses the underlying page-oriented layout with checksums.
        inner.init_section_at_size(tail_section, tail_items).await?;
        inner.sync_all().await?;

        Ok(Self {
            inner,
            items_per_blob,
            size,
        })
    }

    /// Initialize a journal for synchronization, reusing existing data if possible.
    ///
    /// Handles sync scenarios based on existing journal data vs. the given sync range:
    ///
    /// 1. **No existing data**: Creates journal at `range.start` (or empty if `range.start == 0`)
    /// 2. **Data within range**: Prunes to `range.start` and reuses existing data
    /// 3. **Data exceeds range**: Returns error
    /// 4. **Stale data**: Destroys and recreates at `range.start`
    pub(crate) async fn init_sync(
        context: E,
        cfg: Config,
        range: Range<u64>,
    ) -> Result<Self, crate::qmdb::Error> {
        assert!(!range.is_empty(), "range must not be empty");

        debug!(
            range.start,
            range.end,
            items_per_blob = cfg.items_per_blob.get(),
            "initializing contiguous fixed journal for sync"
        );

        let mut journal = Self::init(context.with_label("journal"), cfg.clone()).await?;
        let size = journal.size();

        // No existing data - initialize at the start of the sync range if needed
        if size == 0 {
            if range.start == 0 {
                debug!("no existing journal data, returning empty journal");
                return Ok(journal);
            } else {
                debug!(
                    range.start,
                    "no existing journal data, initializing at sync range start"
                );
                journal.destroy().await?;
                return Ok(Self::init_at_size(context, cfg, range.start).await?);
            }
        }

        // Check if data exceeds the sync range
        if size > range.end {
            return Err(crate::qmdb::Error::UnexpectedData(Location::new_unchecked(
                size,
            )));
        }

        // If all existing data is before our sync range, destroy and recreate fresh
        if size <= range.start {
            debug!(
                size,
                range.start, "existing journal data is stale, re-initializing at start position"
            );
            journal.destroy().await?;
            return Ok(Self::init_at_size(context, cfg, range.start).await?);
        }

        // Prune to lower bound if needed
        let oldest = journal.oldest_retained_pos();
        if let Some(oldest_pos) = oldest {
            if oldest_pos < range.start {
                debug!(
                    oldest_pos,
                    range.start, "pruning journal to sync range start"
                );
                journal.prune(range.start).await?;
            }
        }

        Ok(journal)
    }

    /// Convert a global position to (section, position_in_section).
    #[inline]
    const fn position_to_section(&self, position: u64) -> (u64, u64) {
        let section = position / self.items_per_blob;
        let pos_in_section = position % self.items_per_blob;
        (section, pos_in_section)
    }

    /// Sync any pending updates to disk.
    ///
    /// Only the tail section can have pending updates since historical sections are synced
    /// when they become full.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let tail_section = self.size / self.items_per_blob;
        self.inner.sync(tail_section).await
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Append a new item to the journal. Return the item's position in the journal, or error if the
    /// operation fails.
    pub async fn append(&mut self, item: A) -> Result<u64, Error> {
        let position = self.size;
        let (section, _pos_in_section) = self.position_to_section(position);

        self.inner.append(section, item).await?;
        self.size += 1;

        // If we just filled up a section, sync it and create the next tail blob. This maintains the
        // invariant that the tail blob always exists.
        if self.size.is_multiple_of(self.items_per_blob) {
            self.inner.sync(section).await?;
            // Create the new tail blob.
            self.inner.ensure_section_exists(section + 1).await?;
        }

        Ok(position)
    }

    /// Rewind the journal to the given `size`. Returns [Error::InvalidRewind] if the rewind point
    /// precedes the oldest retained element point. The journal is not synced after rewinding.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until sync is called.
    /// * This operation is not atomic, but it will always leave the journal in a consistent state
    ///   in the event of failure since blobs are always removed from newest to oldest.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        match size.cmp(&self.size) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }

        if size < self.pruning_boundary() {
            return Err(Error::InvalidRewind(size));
        }

        let (section, pos_in_section) = self.position_to_section(size);
        let byte_offset = pos_in_section * SegmentedJournal::<E, A>::CHUNK_SIZE as u64;

        self.inner.rewind(section, byte_offset).await?;
        self.size = size;

        Ok(())
    }

    /// Return the position of the oldest item in the journal that remains readable.
    ///
    /// Note that this value could be older than the `min_item_pos` last passed to prune.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        if self.pruning_boundary() == self.size {
            return None;
        }
        Some(self.pruning_boundary())
    }

    /// Return the location before which all items have been pruned.
    pub fn pruning_boundary(&self) -> u64 {
        self.inner
            .oldest_section()
            .expect("journal should have at least one section")
            * self.items_per_blob
    }

    /// Read the item at position `pos` in the journal.
    ///
    /// # Errors
    ///
    ///  - [Error::ItemPruned] if the item at position `pos` is pruned.
    ///  - [Error::ItemOutOfRange] if the item at position `pos` does not exist.
    pub async fn read(&self, pos: u64) -> Result<A, Error> {
        if pos >= self.size {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.pruning_boundary() {
            return Err(Error::ItemPruned(pos));
        }

        // Get the relevant blob to read from.
        let (section, pos_in_section) = self.position_to_section(pos);

        self.inner.get(section, pos_in_section).await.map_err(|e| {
            // Since we check bounds above, any failure here is unexpected.
            match e {
                Error::SectionOutOfRange(e)
                | Error::AlreadyPrunedToSection(e)
                | Error::ItemOutOfRange(e) => {
                    Error::Corruption(format!("section/item should be found, but got: {e}"))
                }
                other => other,
            }
        })
    }

    /// Returns an ordered stream of all items in the journal with position >= `start_pos`.
    ///
    /// # Integrity
    ///
    /// If any corrupted data is found, or if any non-tail section has fewer items than
    /// `items_per_blob`, the stream will return an error.
    pub async fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + '_, Error> {
        if start_pos > self.size {
            return Err(Error::ItemOutOfRange(start_pos));
        }

        let (start_section, start_pos_in_section) = self.position_to_section(start_pos);
        let items_per_blob = self.items_per_blob;

        // Check all non-tail sections in range are complete before starting the stream.
        let oldest = self.inner.oldest_section().unwrap_or(start_section);
        if let Some(newest) = self.inner.newest_section() {
            for section in start_section.max(oldest)..newest {
                let len = self.inner.section_len(section).await?;
                if len < items_per_blob {
                    return Err(Error::Corruption(format!(
                        "section {section} incomplete: expected {items_per_blob} items, got {len}"
                    )));
                }
            }
        }

        let inner_stream = self
            .inner
            .replay(start_section, start_pos_in_section, buffer)
            .await?;

        // Transform (section, pos_in_section, item) to (global_pos, item).
        let stream = inner_stream.map(move |result| {
            result.map(|(section, pos_in_section, item)| {
                let global_pos = section * items_per_blob + pos_in_section;
                (global_pos, item)
            })
        });

        Ok(stream)
    }

    /// Allow the journal to prune items older than `min_item_pos`. The journal may not prune all
    /// such items in order to preserve blob boundaries, but the amount of such items will always be
    /// less than the configured number of items per blob. Returns true if any items were pruned.
    ///
    /// Note that this operation may NOT be atomic, however it's guaranteed not to leave gaps in the
    /// event of failure as items are always pruned in order from oldest to newest.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<bool, Error> {
        // Calculate the section that would contain min_item_pos
        let target_section = min_item_pos / self.items_per_blob;

        // Calculate the tail section.
        let tail_section = self.size / self.items_per_blob;

        // Cap to tail section. The tail section is guaranteed to exist by our invariant.
        let min_section = std::cmp::min(target_section, tail_section);

        self.inner.prune(min_section).await
    }

    /// Remove any underlying blobs created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        self.inner.destroy().await
    }
}

// Implement Contiguous trait for fixed-length journals
impl<E: Storage + Metrics, A: CodecFixedShared> super::Contiguous for Journal<E, A> {
    type Item = A;

    fn size(&self) -> u64 {
        Self::size(self)
    }

    fn oldest_retained_pos(&self) -> Option<u64> {
        Self::oldest_retained_pos(self)
    }

    fn pruning_boundary(&self) -> u64 {
        Self::pruning_boundary(self)
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + '_, Error> {
        Self::replay(self, buffer, start_pos).await
    }

    async fn read(&self, position: u64) -> Result<Self::Item, Error> {
        Self::read(self, position).await
    }
}

impl<E: Storage + Metrics, A: CodecFixedShared> MutableContiguous for Journal<E, A> {
    async fn append(&mut self, item: Self::Item) -> Result<u64, Error> {
        Self::append(self, item).await
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        Self::prune(self, min_position).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        Self::rewind(self, size).await
    }
}

impl<E: Storage + Metrics, A: CodecFixedShared> Persistable for Journal<E, A> {
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Self::destroy(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self, Context},
        Blob, Runner, Storage,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use futures::{pin_mut, StreamExt};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    /// Generate a SHA-256 digest for the given value.
    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    fn test_cfg(items_per_blob: NonZeroU64) -> Config {
        Config {
            partition: "test_partition".into(),
            items_per_blob,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    #[test_traced]
    fn test_fixed_journal_append_and_prune() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(NZU64!(2));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append an item to the journal
            let mut pos = journal
                .append(test_digest(0))
                .await
                .expect("failed to append data 0");
            assert_eq!(pos, 0);

            // Drop the journal and re-initialize it to simulate a restart
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            let cfg = test_cfg(NZU64!(2));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size(), 1);

            // Append two more items to the journal to trigger a new blob creation
            pos = journal
                .append(test_digest(1))
                .await
                .expect("failed to append data 1");
            assert_eq!(pos, 1);
            pos = journal
                .append(test_digest(2))
                .await
                .expect("failed to append data 2");
            assert_eq!(pos, 2);

            // Read the items back
            let item0 = journal.read(0).await.expect("failed to read data 0");
            assert_eq!(item0, test_digest(0));
            let item1 = journal.read(1).await.expect("failed to read data 1");
            assert_eq!(item1, test_digest(1));
            let item2 = journal.read(2).await.expect("failed to read data 2");
            assert_eq!(item2, test_digest(2));
            let err = journal.read(3).await.expect_err("expected read to fail");
            assert!(matches!(err, Error::ItemOutOfRange(3)));

            // Sync the journal
            journal.sync().await.expect("failed to sync journal");

            // Pruning to 1 should be a no-op because there's no blob with only older items.
            journal.prune(1).await.expect("failed to prune journal 1");

            // Pruning to 2 should allow the first blob to be pruned.
            journal.prune(2).await.expect("failed to prune journal 2");
            assert_eq!(journal.oldest_retained_pos(), Some(2));

            // Reading from the first blob should fail since it's now pruned
            let result0 = journal.read(0).await;
            assert!(matches!(result0, Err(Error::ItemPruned(0))));
            let result1 = journal.read(1).await;
            assert!(matches!(result1, Err(Error::ItemPruned(1))));

            // Third item should still be readable
            let result2 = journal.read(2).await.unwrap();
            assert_eq!(result2, test_digest(2));

            // Should be able to continue to append items
            for i in 3..10 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            // Check no-op pruning
            journal.prune(0).await.expect("no-op pruning failed");
            assert_eq!(journal.inner.oldest_section(), Some(1));
            assert_eq!(journal.inner.newest_section(), Some(5));
            assert_eq!(journal.oldest_retained_pos(), Some(2));

            // Prune first 3 blobs (6 items)
            journal
                .prune(3 * cfg.items_per_blob.get())
                .await
                .expect("failed to prune journal 2");
            assert_eq!(journal.inner.oldest_section(), Some(3));
            assert_eq!(journal.inner.newest_section(), Some(5));
            assert_eq!(journal.oldest_retained_pos(), Some(6));

            // Try pruning (more than) everything in the journal.
            journal
                .prune(10000)
                .await
                .expect("failed to max-prune journal");
            let size = journal.size();
            assert_eq!(size, 10);
            assert_eq!(journal.inner.oldest_section(), Some(5));
            assert_eq!(journal.inner.newest_section(), Some(5));
            // Since the size of the journal is currently a multiple of items_per_blob, the newest blob
            // will be empty, and there will be no retained items.
            assert_eq!(journal.oldest_retained_pos(), None);
            // Pruning boundary should equal size when oldest_retained is None.
            assert_eq!(journal.pruning_boundary(), size);

            {
                let stream = journal
                    .replay(NZUsize!(1024), 0)
                    .await
                    .expect("failed to replay journal");
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                assert_eq!(items, Vec::<u64>::new());
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Append a lot of data to make sure we exercise buffer pool paging boundaries.
    #[test_traced]
    fn test_fixed_journal_append_a_lot_of_data() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10000);
        executor.start(|context| async move {
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            // Append 2 blobs worth of items.
            for i in 0u64..ITEMS_PER_BLOB.get() * 2 - 1 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            // Sync, reopen, then read back.
            journal.sync().await.expect("failed to sync journal");
            drop(journal);
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            for i in 0u64..10000 {
                let item: Digest = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i));
            }
            journal.destroy().await.expect("failed to destroy journal");
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay() {
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            // Read them back the usual way.
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let item: Digest = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i), "i={i}");
            }

            // Replay should return all items
            {
                let stream = journal
                    .replay(NZUsize!(1024), 0)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item, "pos={pos}, item={item:?}");
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }

                // Make sure all items were replayed
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
                );
                items.sort();
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos);
                }
            }

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Corrupt one of the bytes and make sure it's detected.
            let (blob, _) = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Write junk bytes.
            let bad_bytes = 123456789u32;
            blob.write_at(bad_bytes.to_be_bytes().to_vec(), 1)
                .await
                .expect("Failed to write bad bytes");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Make sure reading an item that resides in the corrupted page fails.
            let err = journal
                .read(40 * ITEMS_PER_BLOB.get() + 1)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Runtime(_)));

            // Replay all items.
            {
                let mut error_found = false;
                let stream = journal
                    .replay(NZUsize!(1024), 0)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
                        }
                        Err(err) => {
                            error_found = true;
                            assert!(matches!(err, Error::Runtime(_)));
                            break;
                        }
                    }
                }
                assert!(error_found); // error should abort replay
            }
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_with_corrupted_historical_blobs() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually truncate a non-tail blob to make sure it's detected during initialization.
            // The segmented journal will trim the incomplete blob on init, resulting in the blob
            // missing one item. This should be detected during init because all non-tail blobs
            // must be full.
            let (blob, size) = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // The segmented journal will trim the incomplete blob on init, resulting in the blob
            // missing one item. This should be detected as corruption during replay.
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Journal size is computed from the tail section, so it's unchanged
            // despite the corruption in section 40.
            let expected_size = ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2;
            assert_eq!(journal.size(), expected_size);

            // Replay should detect corruption (incomplete section) in section 40
            match journal.replay(NZUsize!(1024), 0).await {
                Err(Error::Corruption(msg)) => {
                    assert!(
                        msg.contains("section 40"),
                        "Error should mention section 40, got: {msg}"
                    );
                }
                Err(e) => panic!("Expected Corruption error for section 40, got: {:?}", e),
                Ok(_) => panic!("Expected replay to fail with corruption"),
            };
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay_with_missing_historical_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(NZU64!(2));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0u64..5 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            drop(journal);

            context
                .remove(&cfg.partition, Some(&1u64.to_be_bytes()))
                .await
                .expect("failed to remove blob");

            // Init won't detect the corruption.
            let result = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("init shouldn't fail");

            // But replay will.
            match result.replay(NZUsize!(1024), 0).await {
                Err(Error::Corruption(_)) => {}
                Err(err) => panic!("expected Corruption, got: {err}"),
                Ok(_) => panic!("expected Corruption, got ok"),
            };

            // As will trying to read an item that was in the deleted blob.
            match result.read(2).await {
                Err(Error::Corruption(_)) => {}
                Err(err) => panic!("expected Corruption, got: {err}"),
                Ok(_) => panic!("expected Corruption, got ok"),
            };
        });
    }

    #[test_traced]
    fn test_fixed_journal_test_trim_blob() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Fill one blob and put 3 items in the second.
            let item_count = ITEMS_PER_BLOB.get() + 3;
            for i in 0u64..item_count {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size(), item_count);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Truncate the tail blob by one byte, which should result in the last item being
            // discarded during replay (detected via corruption).
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // The truncation invalidates the last page (bad checksum), which is removed.
            // This loses one item.
            assert_eq!(journal.size(), item_count - 1);

            // Cleanup.
            journal.destroy().await.expect("Failed to destroy journal");
        });
    }

    #[test_traced]
    fn test_fixed_journal_partial_replay() {
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        // 53 % 7 = 4, which will trigger a non-trivial seek in the starting blob to reach the
        // starting position.
        const START_POS: u64 = 53;

        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            // Replay should return all items except the first `START_POS`.
            {
                let stream = journal
                    .replay(NZUsize!(1024), START_POS)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert!(pos >= START_POS, "pos={pos}, expected >= {START_POS}");
                            assert_eq!(
                                test_digest(pos),
                                item,
                                "Item at position {pos} did not match expected digest"
                            );
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }

                // Make sure all items were replayed
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
                        - START_POS as usize
                );
                items.sort();
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos - START_POS);
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_from_partial_write() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 3 items per blob.
            let cfg = test_cfg(NZU64!(3));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for i in 0..5 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size(), 5);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // truncate the most recent blob by 1 byte which corrupts the most recent item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            // The truncation invalidates the last page, which is removed. This loses one item.
            assert_eq!(journal.size(), 4);
            drop(journal);

            // Delete the second blob and re-init
            context
                .remove(&cfg.partition, Some(&1u64.to_be_bytes()))
                .await
                .expect("Failed to remove blob");
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            // Only the first blob remains
            assert_eq!(journal.size(), 3);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_to_empty_from_partial_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = test_cfg(NZU64!(10));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            // Add only a single item
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size(), 1);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Truncate the most recent blob by 1 byte which corrupts the one appended item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Since there was only a single item appended which we then corrupted, recovery should
            // leave us in the state of an empty journal.
            assert_eq!(journal.size(), 0);
            assert_eq!(journal.oldest_retained_pos(), None);
            // Make sure journal still works for appending.
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size(), 1);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_journal_recover_from_unwritten_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = test_cfg(NZU64!(10));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Add only a single item
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size(), 1);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually extend the blob to simulate a failure where the file was extended, but no
            // bytes were written due to failure.
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at(vec![0u8; PAGE_SIZE.get() as usize * 3], size)
                .await
                .expect("Failed to extend blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // The zero-filled pages are detected as invalid (bad checksum) and truncated.
            // No items should be lost since we called sync before the corruption.
            assert_eq!(journal.size(), 1);

            // Make sure journal still works for appending.
            journal
                .append(test_digest(1))
                .await
                .expect("failed to append data");

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewinding() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(NZU64!(2));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert!(matches!(
                journal.rewind(1).await,
                Err(Error::InvalidRewind(1))
            ));

            // Append an item to the journal
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data 0");
            assert_eq!(journal.size(), 1);
            assert!(matches!(journal.rewind(1).await, Ok(()))); // should be no-op
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size(), 0);

            // append 7 items
            for i in 0..7 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }
            assert_eq!(journal.size(), 7);

            // rewind back to item #4, which should prune 2 blobs
            assert!(matches!(journal.rewind(4).await, Ok(())));
            assert_eq!(journal.size(), 4);

            // rewind back to empty and ensure all blobs are rewound over
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size(), 0);

            // stress test: add 100 items, rewind 49, repeat x10.
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal.rewind(journal.size() - 49).await.unwrap();
            }
            const ITEMS_REMAINING: u64 = 10 * (100 - 49);
            assert_eq!(journal.size(), ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Repeat with a different blob size (3 items per blob)
            let mut cfg = test_cfg(NZU64!(3));
            cfg.partition = "test_partition_2".into();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal.rewind(journal.size() - 49).await.unwrap();
            }
            assert_eq!(journal.size(), ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Make sure re-opened journal is as expected
            let mut journal: Journal<_, Digest> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size(), 10 * (100 - 49));

            // Make sure rewinding works after pruning
            journal.prune(300).await.expect("pruning failed");
            assert_eq!(journal.size(), ITEMS_REMAINING);
            // Rewinding prior to our prune point should fail.
            assert!(matches!(
                journal.rewind(299).await,
                Err(Error::InvalidRewind(299))
            ));
            // Rewinding to the prune point should work.
            // always remain in the journal.
            assert!(matches!(journal.rewind(300).await, Ok(())));
            assert_eq!(journal.size(), 300);
            assert_eq!(journal.oldest_retained_pos(), None);

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when blob is truncated to a page boundary with item size not dividing page size.
    ///
    /// This tests the scenario where:
    /// 1. Items (32 bytes) don't divide evenly into page size (44 bytes)
    /// 2. Data spans multiple pages
    /// 3. Blob is truncated to a page boundary (simulating crash before last page was written)
    /// 4. Journal should recover correctly on reopen
    #[test_traced]
    fn test_fixed_journal_recover_from_page_boundary_truncation() {
        let executor = deterministic::Runner::default();
        executor.start(|context: Context| async move {
            // Use a small items_per_blob to keep the test focused on a single blob
            let cfg = test_cfg(NZU64!(100));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Item size is 32 bytes (Digest), page size is 44 bytes.
            // 32 doesn't divide 44, so items will cross page boundaries.
            // Physical page size = 44 + 12 (CRC) = 56 bytes.
            //
            // Write enough items to span multiple pages:
            // - 10 items = 320 logical bytes
            // - This spans ceil(320/44) = 8 logical pages
            for i in 0u64..10 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size(), 10);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Open the blob directly and truncate to a page boundary.
            // Physical page size = PAGE_SIZE + CHECKSUM_SIZE = 44 + 12 = 56
            let physical_page_size = PAGE_SIZE.get() as u64 + 12;
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Calculate how many full physical pages we have and truncate to lose the last one.
            let full_pages = size / physical_page_size;
            assert!(full_pages >= 2, "need at least 2 pages for this test");
            let truncate_to = (full_pages - 1) * physical_page_size;

            blob.resize(truncate_to)
                .await
                .expect("Failed to truncate blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal - it should recover by truncating to valid data
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal after page truncation");

            // The journal should have fewer items now (those that fit in the remaining pages).
            // With logical page size 44 and item size 32:
            // - After truncating to (full_pages-1) physical pages, we have (full_pages-1)*44 logical bytes
            // - Number of complete items = floor(logical_bytes / 32)
            let remaining_logical_bytes = (full_pages - 1) * PAGE_SIZE.get() as u64;
            let expected_items = remaining_logical_bytes / 32; // 32 = Digest::SIZE
            assert_eq!(
                journal.size(),
                expected_items,
                "Journal should recover to {} items after truncation",
                expected_items
            );

            // Verify we can still read the remaining items
            for i in 0..expected_items {
                let item = journal
                    .read(i)
                    .await
                    .expect("failed to read recovered item");
                assert_eq!(item, test_digest(i), "item {} mismatch after recovery", i);
            }

            journal.destroy().await.expect("Failed to destroy journal");
        });
    }

    /// Test the contiguous fixed journal with items_per_blob: 1.
    ///
    /// This is an edge case where each item creates its own blob, and the
    /// tail blob is always empty after sync (because the item fills the blob
    /// and a new empty one is created).
    #[test_traced]
    fn test_single_item_per_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "single_item_per_blob".into(),
                items_per_blob: NZU64!(1),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(2048),
            };

            // === Test 1: Basic single item operation ===
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Verify empty state
            assert_eq!(journal.size(), 0);
            assert_eq!(journal.oldest_retained_pos(), None);

            // Append 1 item
            let pos = journal
                .append(test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos, 0);
            assert_eq!(journal.size(), 1);

            // Sync
            journal.sync().await.expect("failed to sync");

            // Read from size() - 1
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(0));

            // === Test 2: Multiple items with single item per blob ===
            for i in 1..10u64 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append");
                assert_eq!(pos, i);
                assert_eq!(journal.size(), i + 1);

                // Verify we can read the just-appended item at size() - 1
                let value = journal
                    .read(journal.size() - 1)
                    .await
                    .expect("failed to read");
                assert_eq!(value, test_digest(i));
            }

            // Verify all items can be read
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.sync().await.expect("failed to sync");

            // === Test 3: Pruning with single item per blob ===
            // Prune to position 5 (removes positions 0-4)
            journal.prune(5).await.expect("failed to prune");

            // Size should still be 10
            assert_eq!(journal.size(), 10);

            // oldest_retained_pos should be 5
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Reading from size() - 1 (position 9) should still work
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(9));

            // Reading from pruned positions should return ItemPruned
            for i in 0..5 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            // Reading from retained positions should work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            // Append more items after pruning
            for i in 10..15u64 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append");
                assert_eq!(pos, i);

                // Verify we can read from size() - 1
                let value = journal
                    .read(journal.size() - 1)
                    .await
                    .expect("failed to read");
                assert_eq!(value, test_digest(i));
            }

            journal.sync().await.expect("failed to sync");
            drop(journal);

            // === Test 4: Restart persistence with single item per blob ===
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Verify size is preserved
            assert_eq!(journal.size(), 15);

            // Verify oldest_retained_pos is preserved
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Reading from size() - 1 should work after restart
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(14));

            // Reading all retained positions should work
            for i in 5..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.destroy().await.expect("failed to destroy journal");

            // === Test 5: Restart after pruning with non-zero index ===
            // Fresh journal for this test
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append 10 items (positions 0-9)
            for i in 0..10u64 {
                journal.append(test_digest(i + 100)).await.unwrap();
            }

            // Prune to position 5 (removes positions 0-4)
            journal.prune(5).await.unwrap();
            assert_eq!(journal.size(), 10);
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Sync and restart
            journal.sync().await.unwrap();
            drop(journal);

            // Re-open journal
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Verify state after restart
            assert_eq!(journal.size(), 10);
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Reading from size() - 1 (position 9) should work
            let value = journal.read(journal.size() - 1).await.unwrap();
            assert_eq!(value, test_digest(109));

            // Verify all retained positions (5-9) work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i + 100));
            }

            journal.destroy().await.expect("failed to destroy journal");

            // === Test 6: Prune all items (edge case) ===
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..5u64 {
                journal.append(test_digest(i + 200)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune all items
            journal.prune(5).await.unwrap();
            assert_eq!(journal.size(), 5); // Size unchanged
            assert_eq!(journal.oldest_retained_pos(), None); // All pruned

            // size() - 1 = 4, but position 4 is pruned
            let result = journal.read(journal.size() - 1).await;
            assert!(matches!(result, Err(Error::ItemPruned(4))));

            // After appending, reading works again
            journal.append(test_digest(205)).await.unwrap();
            assert_eq!(journal.oldest_retained_pos(), Some(5));
            assert_eq!(
                journal.read(journal.size() - 1).await.unwrap(),
                test_digest(205)
            );

            journal.destroy().await.expect("failed to destroy journal");
        });
    }
}
