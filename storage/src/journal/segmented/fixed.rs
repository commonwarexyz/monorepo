//! Segmented journal for fixed-size items.
//!
//! # Format
//!
//! Data is stored in one blob per section. Items are stored sequentially:
//!
//! ```text
//! +--------+--------+--------+----------+
//! | item_0 | item_1 |   ...  | item_n-1 |
//! +--------+--------+--------+----------+
//! ```
//!
//! # Sync
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. Use the
//! `sync` method to force pending data to be written.
//!
//! # Pruning
//!
//! All data must be assigned to a `section`. This allows pruning entire sections
//! (and their corresponding blobs) independently.

use super::manager::{AppendFactory, Config as ManagerConfig, Manager};
use crate::journal::Error;
use commonware_codec::{CodecFixed, CodecFixedShared, DecodeExt as _, ReadExt as _};
use commonware_runtime::{
    buffer::pool::{PoolRef, Replay},
    Blob, Buf, IoBufMut, Metrics, Storage,
};
use futures::{
    stream::{self, Stream},
    StreamExt,
};
use std::{marker::PhantomData, num::NonZeroUsize};
use tracing::{trace, warn};

/// State for replaying a single section's blob.
struct ReplayState<B: Blob> {
    section: u64,
    replay: Replay<B>,
    position: u64,
    done: bool,
}

/// Configuration for the fixed segmented journal.
#[derive(Clone)]
pub struct Config {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// A segmented journal with fixed-size entries.
///
/// Each section is stored in a separate blob. Within each blob, items are fixed-size.
///
/// # Repair
///
/// Like
/// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
/// and
/// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
/// the first invalid data read will be considered the new end of the journal (and the
/// underlying [Blob] will be truncated to the last valid item). Repair occurs during
/// init by checking each blob's size.
pub struct Journal<E: Storage + Metrics, A: CodecFixed> {
    manager: Manager<E, AppendFactory>,
    _array: PhantomData<A>,
}

impl<E: Storage + Metrics, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry.
    pub const CHUNK_SIZE: usize = A::SIZE;
    const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. Use `replay`
    /// to iterate over all items.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: AppendFactory {
                write_buffer: cfg.write_buffer,
                pool_ref: cfg.buffer_pool,
            },
        };
        let mut manager = Manager::init(context, manager_cfg).await?;

        // Repair any blobs with trailing bytes (incomplete items from crash)
        let sections: Vec<_> = manager.sections().collect();
        for section in sections {
            let size = manager.size(section).await?;
            if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
                let valid_size = size - (size % Self::CHUNK_SIZE_U64);
                warn!(
                    section,
                    invalid_size = size,
                    new_size = valid_size,
                    "trailing bytes detected: truncating"
                );
                manager.rewind_section(section, valid_size).await?;
            }
        }

        Ok(Self {
            manager,
            _array: PhantomData,
        })
    }

    /// Append a new item to the journal in the given section.
    ///
    /// Returns the position of the item within the section (0-indexed).
    pub async fn append(&mut self, section: u64, item: A) -> Result<u64, Error> {
        let blob = self.manager.get_or_create(section).await?;

        let size = blob.size().await;
        if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::InvalidBlobSize(section, size));
        }
        let position = size / Self::CHUNK_SIZE_U64;

        // Encode the item
        let buf = item.encode_mut();
        blob.append(&buf).await?;
        trace!(section, position, "appended item");

        Ok(position)
    }

    /// Read the item at the given section and position.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    /// - [Error::ItemOutOfRange] if the position is beyond the blob size.
    pub async fn get(&self, section: u64, position: u64) -> Result<A, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let offset = position
            .checked_mul(Self::CHUNK_SIZE_U64)
            .ok_or(Error::ItemOutOfRange(position))?;
        let end = offset
            .checked_add(Self::CHUNK_SIZE_U64)
            .ok_or(Error::ItemOutOfRange(position))?;
        if end > blob.size().await {
            return Err(Error::ItemOutOfRange(position));
        }

        let buf = blob
            .read_at(offset, IoBufMut::zeroed(Self::CHUNK_SIZE))
            .await?;
        A::decode(buf.coalesce()).map_err(Error::Codec)
    }

    /// Read the last item in a section, if any.
    pub async fn last(&self, section: u64) -> Result<Option<A>, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let size = blob.size().await;
        if size < Self::CHUNK_SIZE_U64 {
            return Ok(None);
        }

        let last_position = (size / Self::CHUNK_SIZE_U64) - 1;
        let offset = last_position * Self::CHUNK_SIZE_U64;
        let buf = blob
            .read_at(offset, IoBufMut::zeroed(Self::CHUNK_SIZE))
            .await?;
        A::decode(buf.coalesce()).map_err(Error::Codec).map(Some)
    }

    /// Returns a stream of all items starting from the given section.
    ///
    /// Each item is returned as (section, position, item).
    pub async fn replay(
        &self,
        start_section: u64,
        start_position: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, A), Error>> + Send + '_, Error> {
        // Pre-create readers from blobs (async operation)
        let mut blob_info = Vec::new();
        for (&section, blob) in self.manager.sections_from(start_section) {
            let blob_size = blob.size().await;
            let mut replay = blob.replay(buffer).await?;
            // For the first section, seek to the start position
            let initial_position = if section == start_section {
                let start = start_position * Self::CHUNK_SIZE_U64;
                if start > blob_size {
                    return Err(Error::ItemOutOfRange(start_position));
                }
                replay.seek_to(start).await?;
                start_position
            } else {
                0
            };
            blob_info.push((section, replay, initial_position));
        }

        // Stream items as they are read to avoid occupying too much memory.
        // Each blob is processed sequentially, yielding batches of items that are then
        // flattened into individual stream elements.
        Ok(
            stream::iter(blob_info).flat_map(move |(section, replay, initial_position)| {
                stream::unfold(
                    ReplayState {
                        section,
                        replay,
                        position: initial_position,
                        done: false,
                    },
                    move |mut state| async move {
                        if state.done {
                            return None;
                        }

                        let mut batch: Vec<Result<(u64, u64, A), Error>> = Vec::new();
                        loop {
                            // Ensure we have enough data for one item
                            match state.replay.ensure(Self::CHUNK_SIZE).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    // Reader exhausted - we're done with this blob
                                    state.done = true;
                                    return if batch.is_empty() {
                                        None
                                    } else {
                                        Some((batch, state))
                                    };
                                }
                                Err(err) => {
                                    batch.push(Err(Error::Runtime(err)));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            }

                            // Decode items from buffer
                            while state.replay.remaining() >= Self::CHUNK_SIZE {
                                match A::read(&mut state.replay) {
                                    Ok(item) => {
                                        batch.push(Ok((state.section, state.position, item)));
                                        state.position += 1;
                                    }
                                    Err(err) => {
                                        batch.push(Err(Error::Codec(err)));
                                        state.done = true;
                                        return Some((batch, state));
                                    }
                                }
                            }

                            // Return batch if we have items
                            if !batch.is_empty() {
                                return Some((batch, state));
                            }
                        }
                    },
                )
                .flat_map(stream::iter)
            }),
        )
    }

    /// Sync the given section to storage.
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        self.manager.sync(section).await
    }

    /// Sync all sections to storage.
    pub async fn sync_all(&self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.manager.prune(min).await
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.manager.sections_from(0).map(|(section, _)| *section)
    }

    /// Returns the number of items in the given section.
    pub async fn section_len(&self, section: u64) -> Result<u64, Error> {
        let size = self.manager.size(section).await?;
        Ok(size / Self::CHUNK_SIZE_U64)
    }

    /// Returns the byte size of the given section.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section).await
    }

    /// Rewind the journal to a specific section and byte offset.
    ///
    /// This truncates the section to the given size. All sections
    /// after `section` are removed.
    pub async fn rewind(&mut self, section: u64, offset: u64) -> Result<(), Error> {
        self.manager.rewind(section, offset).await
    }

    /// Rewind only the given section to a specific byte offset.
    ///
    /// Unlike `rewind`, this does not affect other sections.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind_section(section, size).await
    }

    /// Remove all underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }

    /// Clear all data, resetting the journal to an empty state.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused.
    pub async fn clear(&mut self) -> Result<(), Error> {
        self.manager.clear().await
    }

    /// Initialize a section with a specific number of zero-filled items.
    ///
    /// This creates the section's blob and fills it with `item_count` items worth of zeros.
    /// The data is written through the Append wrapper which handles checksums properly.
    ///
    /// # Arguments
    /// * `section` - The section number to initialize
    /// * `item_count` - Number of zero-filled items to write
    pub(crate) async fn init_section_at_size(
        &mut self,
        section: u64,
        item_count: u64,
    ) -> Result<(), Error> {
        // Get or create the blob for this section
        let blob = self.manager.get_or_create(section).await?;

        // Calculate the target byte size
        let target_size = item_count * Self::CHUNK_SIZE_U64;

        // Resize grows the blob by appending zeros, which handles checksums properly
        blob.resize(target_size).await?;

        Ok(())
    }

    /// Ensure a section exists, creating an empty blob if needed.
    ///
    /// This is used to maintain the invariant that at least one blob always exists
    /// (the "tail" blob), which allows reconstructing journal size on reopen.
    pub(crate) async fn ensure_section_exists(&mut self, section: u64) -> Result<(), Error> {
        self.manager.get_or_create(section).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Metrics, Runner};
    use commonware_utils::{NZUsize, NZU16};
    use core::num::NonZeroU16;
    use futures::{pin_mut, StreamExt};

    const PAGE_SIZE: NonZeroU16 = NZU16!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    fn test_cfg() -> Config {
        Config {
            partition: "test_partition".into(),
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    #[test_traced]
    fn test_segmented_fixed_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            let pos0 = journal
                .append(1, test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos0, 0);

            let pos1 = journal
                .append(1, test_digest(1))
                .await
                .expect("failed to append");
            assert_eq!(pos1, 1);

            let pos2 = journal
                .append(2, test_digest(2))
                .await
                .expect("failed to append");
            assert_eq!(pos2, 0);

            let item0 = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item0, test_digest(0));

            let item1 = journal.get(1, 1).await.expect("failed to get");
            assert_eq!(item1, test_digest(1));

            let item2 = journal.get(2, 0).await.expect("failed to get");
            assert_eq!(item2, test_digest(2));

            let err = journal.get(1, 2).await;
            assert!(matches!(err, Err(Error::ItemOutOfRange(2))));

            let err = journal.get(3, 0).await;
            assert!(matches!(err, Err(Error::SectionOutOfRange(3))));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..10 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            for i in 10u64..20 {
                journal
                    .append(2, test_digest(i))
                    .await
                    .expect("failed to append");
            }

            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            let items = {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((section, pos, item)) => items.push((section, pos, item)),
                        Err(err) => panic!("replay error: {err}"),
                    }
                }
                items
            };

            assert_eq!(items.len(), 20);
            for (i, item) in items.iter().enumerate().take(10) {
                assert_eq!(item.0, 1);
                assert_eq!(item.1, i as u64);
                assert_eq!(item.2, test_digest(i as u64));
            }
            for (i, item) in items.iter().enumerate().skip(10).take(10) {
                assert_eq!(item.0, 2);
                assert_eq!(item.1, (i - 10) as u64);
                assert_eq!(item.2, test_digest(i as u64));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay_with_start_offset() {
        // Test that replay with a non-zero start_position correctly skips items.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append 10 items to section 1
            for i in 0u64..10 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            // Append 5 items to section 2
            for i in 10u64..15 {
                journal
                    .append(2, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Replay from section 1, position 5 - should get items 5-9 from section 1 and all of section 2
            {
                let stream = journal
                    .replay(1, 5, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }

                assert_eq!(
                    items.len(),
                    10,
                    "Should have 5 items from section 1 + 5 from section 2"
                );

                // Check section 1 items (positions 5-9)
                for (i, (section, pos, item)) in items.iter().enumerate().take(5) {
                    assert_eq!(*section, 1);
                    assert_eq!(*pos, (i + 5) as u64);
                    assert_eq!(*item, test_digest((i + 5) as u64));
                }

                // Check section 2 items (positions 0-4)
                for (i, (section, pos, item)) in items.iter().enumerate().skip(5) {
                    assert_eq!(*section, 2);
                    assert_eq!(*pos, (i - 5) as u64);
                    assert_eq!(*item, test_digest((i + 5) as u64));
                }
            }

            // Replay from section 1, position 9 - should get only item 9 from section 1 and all of section 2
            {
                let stream = journal
                    .replay(1, 9, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }

                assert_eq!(
                    items.len(),
                    6,
                    "Should have 1 item from section 1 + 5 from section 2"
                );
                assert_eq!(items[0], (1, 9, test_digest(9)));
                for (i, (section, pos, item)) in items.iter().enumerate().skip(1) {
                    assert_eq!(*section, 2);
                    assert_eq!(*pos, (i - 1) as u64);
                    assert_eq!(*item, test_digest((i + 9) as u64));
                }
            }

            // Replay from section 2, position 3 - should get only items 3-4 from section 2
            {
                let stream = journal
                    .replay(2, 3, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }

                assert_eq!(items.len(), 2, "Should have 2 items from section 2");
                assert_eq!(items[0], (2, 3, test_digest(13)));
                assert_eq!(items[1], (2, 4, test_digest(14)));
            }

            // Replay from position past the end should return ItemOutOfRange error
            let result = journal.replay(1, 100, NZUsize!(1024)).await;
            assert!(matches!(result, Err(Error::ItemOutOfRange(100))));
            drop(result);

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            for section in 1u64..=5 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            journal.prune(3).await.expect("failed to prune");

            let err = journal.get(1, 0).await;
            assert!(matches!(err, Err(Error::AlreadyPrunedToSection(3))));

            let err = journal.get(2, 0).await;
            assert!(matches!(err, Err(Error::AlreadyPrunedToSection(3))));

            let item = journal.get(3, 0).await.expect("should exist");
            assert_eq!(item, test_digest(3));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1, 2, 3
            for section in 1u64..=3 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            // Verify all sections exist
            for section in 1u64..=3 {
                let size = journal.size(section).await.expect("failed to get size");
                assert!(size > 0, "section {section} should have data");
            }

            // Rewind to section 1 (should remove sections 2, 3)
            let size = journal.size(1).await.expect("failed to get size");
            journal.rewind(1, size).await.expect("failed to rewind");

            // Verify section 1 still has data
            let size = journal.size(1).await.expect("failed to get size");
            assert!(size > 0, "section 1 should still have data");

            // Verify sections 2, 3 are removed
            for section in 2u64..=3 {
                let size = journal.size(section).await.expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data in section 1 is still readable
            let item = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item, test_digest(1));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind_many_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1-10
            for section in 1u64..=10 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            // Rewind to section 5 (should remove sections 6-10)
            let size = journal.size(5).await.expect("failed to get size");
            journal.rewind(5, size).await.expect("failed to rewind");

            // Verify sections 1-5 still have data
            for section in 1u64..=5 {
                let size = journal.size(section).await.expect("failed to get size");
                assert!(size > 0, "section {section} should still have data");
            }

            // Verify sections 6-10 are removed
            for section in 6u64..=10 {
                let size = journal.size(section).await.expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data integrity via replay
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, item) = result.expect("failed to read");
                    items.push((section, item));
                }
                assert_eq!(items.len(), 5);
                for (i, (section, item)) in items.iter().enumerate() {
                    assert_eq!(*section, (i + 1) as u64);
                    assert_eq!(*item, test_digest((i + 1) as u64));
                }
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create sections 1-5
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");
            for section in 1u64..=5 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            // Rewind to section 2
            let size = journal.size(2).await.expect("failed to get size");
            journal.rewind(2, size).await.expect("failed to rewind");
            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Re-init and verify only sections 1-2 exist
            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Verify sections 1-2 have data
            for section in 1u64..=2 {
                let size = journal.size(section).await.expect("failed to get size");
                assert!(size > 0, "section {section} should have data after restart");
            }

            // Verify sections 3-5 are gone
            for section in 3u64..=5 {
                let size = journal.size(section).await.expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be gone after restart");
            }

            // Verify data integrity
            let item1 = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item1, test_digest(1));
            let item2 = journal.get(2, 0).await.expect("failed to get");
            assert_eq!(item2, test_digest(2));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_corruption_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("failed to open blob");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");

            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            let count = {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut count = 0;
                while let Some(result) = stream.next().await {
                    result.expect("should be ok");
                    count += 1;
                }
                count
            };
            assert_eq!(count, 4);

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate journal
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Reopen and verify data persisted
            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg)
                .await
                .expect("failed to re-init");

            for i in 0u64..5 {
                let item = journal.get(1, i).await.expect("failed to get");
                assert_eq!(item, test_digest(i));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_section_len() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            assert_eq!(journal.section_len(1).await.unwrap(), 0);

            for i in 0u64..5 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }

            assert_eq!(journal.section_len(1).await.unwrap(), 5);
            assert_eq!(journal.section_len(2).await.unwrap(), 0);

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_non_contiguous_sections() {
        // Test that sections with gaps in numbering work correctly.
        // Sections 1, 5, 10 should all be independent and accessible.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections with gaps: 1, 5, 10
            journal
                .append(1, test_digest(100))
                .await
                .expect("failed to append");
            journal
                .append(5, test_digest(500))
                .await
                .expect("failed to append");
            journal
                .append(10, test_digest(1000))
                .await
                .expect("failed to append");
            journal.sync_all().await.expect("failed to sync");

            // Verify random access to each section
            assert_eq!(journal.get(1, 0).await.unwrap(), test_digest(100));
            assert_eq!(journal.get(5, 0).await.unwrap(), test_digest(500));
            assert_eq!(journal.get(10, 0).await.unwrap(), test_digest(1000));

            // Verify non-existent sections return appropriate errors
            for missing_section in [0u64, 2, 3, 4, 6, 7, 8, 9, 11] {
                let result = journal.get(missing_section, 0).await;
                assert!(
                    matches!(result, Err(Error::SectionOutOfRange(_))),
                    "Expected SectionOutOfRange for section {}, got {:?}",
                    missing_section,
                    result
                );
            }

            // Drop and reopen to test replay
            drop(journal);
            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Replay and verify all items in order
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }

                assert_eq!(items.len(), 3, "Should have 3 items");
                assert_eq!(items[0], (1, test_digest(100)));
                assert_eq!(items[1], (5, test_digest(500)));
                assert_eq!(items[2], (10, test_digest(1000)));
            }

            // Test replay starting from middle section (5)
            {
                let stream = journal
                    .replay(5, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay from section 5");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }

                assert_eq!(items.len(), 2, "Should have 2 items from section 5 onwards");
                assert_eq!(items[0], (5, test_digest(500)));
                assert_eq!(items[1], (10, test_digest(1000)));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_empty_section_in_middle() {
        // Test that replay correctly handles an empty section between sections with data.
        // Section 1 has data, section 2 is empty, section 3 has data.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append to section 1
            journal
                .append(1, test_digest(100))
                .await
                .expect("failed to append");

            // Create section 2 but make it empty via rewind
            journal
                .append(2, test_digest(200))
                .await
                .expect("failed to append");
            journal.sync(2).await.expect("failed to sync");
            journal
                .rewind_section(2, 0)
                .await
                .expect("failed to rewind");

            // Append to section 3
            journal
                .append(3, test_digest(300))
                .await
                .expect("failed to append");

            journal.sync_all().await.expect("failed to sync");

            // Verify section lengths
            assert_eq!(journal.section_len(1).await.unwrap(), 1);
            assert_eq!(journal.section_len(2).await.unwrap(), 0);
            assert_eq!(journal.section_len(3).await.unwrap(), 1);

            // Drop and reopen to test replay
            drop(journal);
            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Replay all - should get items from sections 1 and 3, skipping empty section 2
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }

                assert_eq!(
                    items.len(),
                    2,
                    "Should have 2 items (skipping empty section)"
                );
                assert_eq!(items[0], (1, test_digest(100)));
                assert_eq!(items[1], (3, test_digest(300)));
            }

            // Replay starting from empty section 2 - should get only section 3
            {
                let stream = journal
                    .replay(2, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay from section 2");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }

                assert_eq!(items.len(), 1, "Should have 1 item from section 3");
                assert_eq!(items[0], (3, test_digest(300)));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_truncation_recovery_across_page_boundary() {
        // Test that truncating a single byte from a blob that has items straddling a page boundary
        // correctly recovers by removing the incomplete item.
        //
        // With PAGE_SIZE=44 and ITEM_SIZE=32:
        // - Item 0: bytes 0-31
        // - Item 1: bytes 32-63 (straddles page boundary at 44)
        // - Item 2: bytes 64-95 (straddles page boundary at 88)
        //
        // After 3 items we have 96 bytes = 2 full pages + 8 bytes. Truncating 1 byte leaves 95
        // bytes, which is not a multiple of 32. Recovery should truncate to 64 bytes (2 complete
        // items).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append 3 items (just over 2 pages worth)
            for i in 0u64..3 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            // Verify all 3 items are readable
            for i in 0u64..3 {
                let item = journal.get(1, i).await.expect("failed to get");
                assert_eq!(item, test_digest(i));
            }
            drop(journal);

            // Truncate the blob by exactly 1 byte to simulate partial write
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("failed to open blob");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");
            drop(blob);

            // Reopen journal - should recover by truncating last page due to failed checksum, and
            // end up with a correct blob size due to partial-item trimming.
            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Verify section now has only 2 items
            assert_eq!(journal.section_len(1).await.unwrap(), 2);

            // Verify size is the expected multiple of ITEM_SIZE (this would fail if we didn't trim
            // items and just relied on page-level checksum recovery).
            assert_eq!(journal.size(1).await.unwrap(), 64);

            // Items 0 and 1 should still be readable
            let item0 = journal.get(1, 0).await.expect("failed to get item 0");
            assert_eq!(item0, test_digest(0));
            let item1 = journal.get(1, 1).await.expect("failed to get item 1");
            assert_eq!(item1, test_digest(1));

            // Item 2 should return ItemOutOfRange
            let err = journal.get(1, 2).await;
            assert!(
                matches!(err, Err(Error::ItemOutOfRange(2))),
                "expected ItemOutOfRange(2), got {:?}",
                err
            );

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_init_section_at_size() {
        // Test that init_section_at_size correctly initializes a section with zero-filled items.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Initialize section 1 with 5 zero-filled items
            journal
                .init_section_at_size(1, 5)
                .await
                .expect("failed to init section at size");

            // Verify section has correct length
            assert_eq!(journal.section_len(1).await.unwrap(), 5);

            // Verify size is correct (5 items * 32 bytes per Digest)
            assert_eq!(journal.size(1).await.unwrap(), 5 * 32);

            // Verify we can read the zero-filled items
            let zero_digest = Sha256::fill(0);
            for i in 0u64..5 {
                let item = journal.get(1, i).await.expect("failed to get");
                assert_eq!(item, zero_digest, "item {i} should be zero-filled");
            }

            // Verify position past the initialized range returns error
            let err = journal.get(1, 5).await;
            assert!(matches!(err, Err(Error::ItemOutOfRange(5))));

            // Verify we can append after the initialized items
            let pos = journal
                .append(1, test_digest(100))
                .await
                .expect("failed to append");
            assert_eq!(pos, 5, "append should return position 5");

            // Verify section now has 6 items
            assert_eq!(journal.section_len(1).await.unwrap(), 6);

            // Verify the appended item is readable
            let item = journal.get(1, 5).await.expect("failed to get");
            assert_eq!(item, test_digest(100));

            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Test persistence - reopen and verify
            let journal = Journal::<_, Digest>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            assert_eq!(journal.section_len(1).await.unwrap(), 6);

            // Verify zero-filled items persisted
            for i in 0u64..5 {
                let item = journal.get(1, i).await.expect("failed to get");
                assert_eq!(
                    item, zero_digest,
                    "item {i} should still be zero-filled after restart"
                );
            }

            // Verify appended item persisted
            let item = journal.get(1, 5).await.expect("failed to get");
            assert_eq!(item, test_digest(100));

            // Test replay includes zero-filled items
            {
                let stream = journal
                    .replay(1, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }

                assert_eq!(items.len(), 6);
                for (i, item) in items.iter().enumerate().take(5) {
                    assert_eq!(*item, (1, i as u64, zero_digest));
                }
                assert_eq!(items[5], (1, 5, test_digest(100)));
            }

            // Test replay with non-zero start offset skips zero-filled items
            {
                let stream = journal
                    .replay(1, 3, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }

                assert_eq!(items.len(), 3);
                assert_eq!(items[0], (1, 3, zero_digest));
                assert_eq!(items[1], (1, 4, zero_digest));
                assert_eq!(items[2], (1, 5, test_digest(100)));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_journal_clear() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "clear_test".into(),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal: Journal<_, Digest> =
                Journal::init(context.with_label("journal"), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

            // Append items across multiple sections
            for section in 0..5u64 {
                for i in 0..10u64 {
                    journal
                        .append(section, test_digest(section * 1000 + i))
                        .await
                        .expect("Failed to append");
                }
                journal.sync(section).await.expect("Failed to sync");
            }

            // Verify we have data
            assert_eq!(journal.get(0, 0).await.unwrap(), test_digest(0));
            assert_eq!(journal.get(4, 0).await.unwrap(), test_digest(4000));

            // Clear the journal
            journal.clear().await.expect("Failed to clear");

            // After clear, all reads should fail
            for section in 0..5u64 {
                assert!(matches!(
                    journal.get(section, 0).await,
                    Err(Error::SectionOutOfRange(s)) if s == section
                ));
            }

            // Append new data after clear
            for i in 0..5u64 {
                journal
                    .append(10, test_digest(i * 100))
                    .await
                    .expect("Failed to append after clear");
            }
            journal.sync(10).await.expect("Failed to sync after clear");

            // New data should be readable
            assert_eq!(journal.get(10, 0).await.unwrap(), test_digest(0));

            // Old sections should still be missing
            assert!(matches!(
                journal.get(0, 0).await,
                Err(Error::SectionOutOfRange(0))
            ));

            journal.destroy().await.unwrap();
        });
    }
}
