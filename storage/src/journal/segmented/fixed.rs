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
    Blob, Handle, Metrics, Storage,
    buffer::paged::{CacheRef, Replay as BlobReplay},
};
use commonware_utils::NZUsize;
use std::{collections::VecDeque, marker::PhantomData, num::NonZeroUsize};
use tracing::{trace, warn};

/// State for replaying a single section's blob.
struct SectionReplay<B: Blob> {
    section: u64,
    reader: BlobReplay<B>,
    position: u64,
}

/// Configuration for the fixed segmented journal.
#[derive(Clone)]
pub struct Config {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// The journal's state, boxed so the public [Journal] handle stays pointer-sized.
struct Inner<E: Storage + Metrics, A: CodecFixed> {
    manager: Manager<E, AppendFactory>,
    _array: PhantomData<A>,
}

impl<E: Storage + Metrics, A: CodecFixedShared> Inner<E, A> {
    /// Size of each entry.
    const CHUNK_SIZE: usize = A::SIZE;
    const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// See [Journal::init].
    async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: AppendFactory {
                write_buffer: cfg.write_buffer,
                page_cache_ref: cfg.page_cache,
            },
        };
        let mut manager = Manager::init(context, manager_cfg).await?;

        // Repair any blobs with trailing bytes (incomplete items from crash)
        let sections: Vec<_> = manager.sections().collect();
        for section in sections {
            let size = manager.size(section)?;
            if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
                let valid_size = size - (size % Self::CHUNK_SIZE_U64);
                warn!(
                    section,
                    invalid_size = size,
                    new_size = valid_size,
                    "trailing bytes detected: truncating"
                );
                manager.rewind_section(section, valid_size).await?;
                // Startup repair is exceptional; make it durable immediately so callers do not
                // need to track repaired sections separately.
                manager.sync(section).await?;
            }
        }

        Ok(Self {
            manager,
            _array: PhantomData,
        })
    }

    /// See [Journal::append].
    async fn append(&mut self, section: u64, item: &A) -> Result<u64, Error> {
        let blob = self.manager.get_or_create(section).await?;

        // Encode the item
        let buf = item.encode_mut();
        let offset = blob.append(&buf).await?;
        if !offset.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::InvalidBlobSize(section, offset));
        }
        let position = offset / Self::CHUNK_SIZE_U64;
        trace!(section, position, "appended item");

        Ok(position)
    }

    /// See [Journal::get].
    async fn get(&self, section: u64, position: u64) -> Result<A, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let offset = position
            .checked_mul(Self::CHUNK_SIZE_U64)
            .ok_or(Error::ItemOutOfRange(position))?;

        // The read validates bounds against the blob's logical size.
        let buf = blob
            .read_at(offset, Self::CHUNK_SIZE)
            .await
            .map_err(|err| match err {
                commonware_runtime::Error::BlobInsufficientLength
                | commonware_runtime::Error::OffsetOverflow => Error::ItemOutOfRange(position),
                err => Error::Runtime(err),
            })?;
        A::decode(buf.coalesce()).map_err(Error::Codec)
    }

    /// See [Journal::get_many].
    async fn get_many(
        &self,
        section: u64,
        positions: &[u64],
        buf: &mut [u8],
    ) -> Result<(Vec<A>, usize), Error> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        if positions.is_empty() {
            return Ok((Vec::new(), 0));
        }
        assert!(
            buf.len() >= positions.len() * Self::CHUNK_SIZE,
            "get_many requires buf.len() >= positions.len() * CHUNK_SIZE"
        );
        let buf = &mut buf[..positions.len() * Self::CHUNK_SIZE];
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let offsets: Vec<u64> = positions
            .iter()
            .map(|&p| {
                p.checked_mul(Self::CHUNK_SIZE_U64)
                    .ok_or(Error::ItemOutOfRange(p))
            })
            .collect::<Result<_, _>>()?;

        let hits = blob
            .read_many_into(buf, &offsets, NZUsize!(Self::CHUNK_SIZE))
            .await?;

        let mut items = Vec::with_capacity(positions.len());
        for i in 0..positions.len() {
            let slice = &buf[i * Self::CHUNK_SIZE..(i + 1) * Self::CHUNK_SIZE];
            items.push(A::decode(slice).map_err(Error::Codec)?);
        }
        Ok((items, hits))
    }

    /// See [Journal::try_get_sync].
    fn try_get_sync(&self, section: u64, position: u64) -> Option<A> {
        let blob = self.manager.get(section).ok()??;
        let offset = position.checked_mul(Self::CHUNK_SIZE_U64)?;
        let remaining = blob.size().checked_sub(offset)?;
        if remaining < Self::CHUNK_SIZE_U64 {
            return None;
        }
        let mut buf = vec![0u8; Self::CHUNK_SIZE];
        if !blob.try_read_sync_into(&mut buf, offset) {
            return None;
        }
        A::decode(&buf[..]).ok()
    }

    /// See [Journal::last].
    async fn last(&self, section: u64) -> Result<Option<A>, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let size = blob.size();
        if size < Self::CHUNK_SIZE_U64 {
            return Ok(None);
        }

        let last_position = (size / Self::CHUNK_SIZE_U64) - 1;
        let offset = last_position * Self::CHUNK_SIZE_U64;
        let buf = blob.read_at(offset, Self::CHUNK_SIZE).await?;
        A::decode(buf.coalesce()).map_err(Error::Codec).map(Some)
    }

    /// See [Journal::sync].
    async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        self.manager.sync(sections).await
    }

    /// See [Journal::start_sync].
    async fn start_sync(&mut self, sections: impl crate::Sections) -> Result<Handle<()>, Error> {
        self.manager.start_sync(sections).await
    }

    /// See [Journal::sync_all].
    async fn sync_all(&mut self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// See [Journal::prune].
    async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.manager.prune(min).await
    }

    /// See [Journal::pruned].
    const fn pruned(&self, section: u64) -> bool {
        self.manager.pruned(section)
    }

    /// See [Journal::oldest_section].
    fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// See [Journal::newest_section].
    fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// See [Journal::sections].
    fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.manager.sections()
    }

    /// See [Journal::section_len].
    fn section_len(&self, section: u64) -> Result<u64, Error> {
        let size = self.manager.size(section)?;
        Ok(size / Self::CHUNK_SIZE_U64)
    }

    /// See [Journal::size].
    fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section)
    }

    /// See [Journal::rewind].
    async fn rewind(&mut self, section: u64, offset: u64) -> Result<(), Error> {
        self.manager.rewind(section, offset).await
    }

    /// See [Journal::rewind_section].
    async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind_section(section, size).await
    }

    /// See [Journal::destroy].
    async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }

    /// See [Journal::clear].
    async fn clear(&mut self) -> Result<(), Error> {
        self.manager.clear().await
    }
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
///
/// Mutating functions consume the journal and return it only on success: an error (or a dropped
/// future) destroys the handle. [Journal::replay] consumes the journal into an owned [Replay]
/// reader, which returns it via [Replay::finish] once exhausted. Mutations on pruned sections
/// fail with [Error::AlreadyPrunedToSection] without mutating. Check [Journal::pruned] first to
/// keep the handle.
pub struct Journal<E: Storage + Metrics, A: CodecFixed>(Box<Inner<E, A>>);

impl<E: Storage + Metrics, A: CodecFixedShared> std::fmt::Debug for Journal<E, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("oldest_section", &self.oldest_section())
            .field("newest_section", &self.newest_section())
            .finish_non_exhaustive()
    }
}

impl<E: Storage + Metrics, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry.
    pub const CHUNK_SIZE: usize = Inner::<E, A>::CHUNK_SIZE;

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. Use `replay`
    /// to iterate over all items.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        Ok(Self(Box::new(Inner::init(context, cfg).await?)))
    }

    /// Append a new item to the journal in the given section.
    ///
    /// Returns the position of the item within the section (0-indexed).
    pub async fn append(mut self, section: u64, item: &A) -> Result<(Self, u64), Error> {
        let position = self.0.append(section, item).await?;
        Ok((self, position))
    }

    /// Read the item at the given section and position.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    /// - [Error::ItemOutOfRange] if the position is beyond the blob size.
    pub async fn get(&self, section: u64, position: u64) -> Result<A, Error> {
        self.0.get(section, position).await
    }

    /// Read multiple items from the same section into a caller buffer.
    ///
    /// `buf` must be at least `positions.len() * CHUNK_SIZE` bytes. All positions must be
    /// strictly increasing and within the section's bounds.
    ///
    /// Returns the decoded items and the number served without a blob read (page cache or tip
    /// buffer hits).
    pub async fn get_many(
        &self,
        section: u64,
        positions: &[u64],
        buf: &mut [u8],
    ) -> Result<(Vec<A>, usize), Error> {
        self.0.get_many(section, positions, buf).await
    }

    /// Get an item if it can be done synchronously (e.g. without I/O), returning `None` otherwise.
    pub fn try_get_sync(&self, section: u64, position: u64) -> Option<A> {
        self.0.try_get_sync(section, position)
    }

    /// Read the last item in a section, if any.
    ///
    /// Returns `Ok(None)` if the section is empty.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    pub async fn last(&self, section: u64) -> Result<Option<A>, Error> {
        self.0.last(section).await
    }

    /// Consumes the journal and returns an owned [Replay] reader over all items starting
    /// from `start_position` in `start_section`.
    ///
    /// Setup flushes buffered pages so the reader observes every accepted write. It
    /// validates replay setup but does not allocate `buffer` bytes per blob. Page buffers
    /// are allocated lazily as the reader advances.
    pub async fn replay(
        mut self,
        start_section: u64,
        start_position: u64,
        buffer: NonZeroUsize,
    ) -> Result<Replay<E, A>, Error> {
        let mut sections = VecDeque::new();
        for (&section, blob) in self.0.manager.sections_from(start_section) {
            let blob_size = blob.size();
            let mut reader = blob.replay(buffer).await?;
            // For the first section, seek to the start position
            let position = if section == start_section {
                let start = start_position
                    .checked_mul(Inner::<E, A>::CHUNK_SIZE_U64)
                    .ok_or(Error::ItemOutOfRange(start_position))?;
                if start > blob_size {
                    return Err(Error::ItemOutOfRange(start_position));
                }
                reader.seek_to(start)?;
                start_position
            } else {
                0
            };
            sections.push_back(SectionReplay {
                section,
                reader,
                position,
            });
        }
        let finished = sections.is_empty();
        Ok(Replay {
            journal: self,
            sections,
            finished,
            errored: false,
        })
    }

    /// Sync the given `sections` to storage.
    pub async fn sync(mut self, sections: impl crate::Sections) -> Result<Self, Error> {
        self.0.sync(sections).await?;
        Ok(self)
    }

    /// Start syncing the given `sections` to storage.
    ///
    /// An error reported by the returned [Handle] is fatal to the journal: the caller
    /// must stop using the returned journal.
    pub async fn start_sync(
        mut self,
        sections: impl crate::Sections,
    ) -> Result<(Self, Handle<()>), Error> {
        let handle = self.0.start_sync(sections).await?;
        Ok((self, handle))
    }

    /// Sync all sections to storage.
    pub async fn sync_all(mut self) -> Result<Self, Error> {
        self.0.sync_all().await?;
        Ok(self)
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(mut self, min: u64) -> Result<(Self, bool), Error> {
        let pruned = self.0.prune(min).await?;
        Ok((self, pruned))
    }

    /// Returns true when `section` is below the prune floor.
    ///
    /// The floor only tracks prunes from the current execution and resets at init, so a
    /// section pruned in a previous execution reports false.
    pub fn pruned(&self, section: u64) -> bool {
        self.0.pruned(section)
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.0.oldest_section()
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.0.newest_section()
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.sections()
    }

    /// Returns the number of items in the given section.
    pub fn section_len(&self, section: u64) -> Result<u64, Error> {
        self.0.section_len(section)
    }

    /// Returns the byte size of the given section.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.0.size(section)
    }

    /// Rewind the journal to a specific section and byte size.
    ///
    /// This truncates the section to the given size. All sections
    /// after `section` are removed.
    pub async fn rewind(mut self, section: u64, size: u64) -> Result<Self, Error> {
        self.0.rewind(section, size).await?;
        Ok(self)
    }

    /// Rewind only the given section to a specific byte offset.
    ///
    /// Unlike `rewind`, this does not affect other sections.
    pub async fn rewind_section(mut self, section: u64, size: u64) -> Result<Self, Error> {
        self.0.rewind_section(section, size).await?;
        Ok(self)
    }

    /// Remove all underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        self.0.destroy().await
    }

    /// Clear all data, resetting the journal to an empty state.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused.
    pub async fn clear(mut self) -> Result<Self, Error> {
        self.0.clear().await?;
        Ok(self)
    }
}

/// Owned replay reader over a [Journal]'s items.
///
/// Yields `(section, position, item)` in order. Dropping the reader before it is exhausted
/// destroys the journal: recovery is re-initialization. Call [Replay::finish] on an
/// exhausted reader to get the journal back.
pub struct Replay<E: Storage + Metrics, A: CodecFixed> {
    journal: Journal<E, A>,
    sections: VecDeque<SectionReplay<E::Blob>>,
    finished: bool,
    errored: bool,
}

impl<E: Storage + Metrics, A: CodecFixedShared> Replay<E, A> {
    /// Returns the next `(section, position, item)`, or `None` once every section is
    /// exhausted.
    ///
    /// An error ends the section that produced it, and iteration continues with the
    /// next section.
    pub async fn next(&mut self) -> Option<Result<(u64, u64, A), Error>> {
        while let Some(current) = self.sections.front_mut() {
            // Ensure we have enough data for one item
            match current.reader.ensure(Inner::<E, A>::CHUNK_SIZE).await {
                Ok(true) => {}
                Ok(false) => {
                    // Reader exhausted, move to the next section
                    self.sections.pop_front();
                    continue;
                }
                Err(err) => {
                    self.sections.pop_front();
                    return self.fail(Error::Runtime(err));
                }
            }

            // Decode the item at the current position
            match A::read(&mut current.reader) {
                Ok(item) => {
                    let yielded = (current.section, current.position, item);
                    current.position += 1;
                    return Some(Ok(yielded));
                }
                Err(err) => {
                    self.sections.pop_front();
                    return self.fail(Error::Codec(err));
                }
            }
        }
        self.finished = true;
        None
    }

    /// Records a yielded error, which is fatal to the journal.
    const fn fail(&mut self, err: Error) -> Option<Result<(u64, u64, A), Error>> {
        self.errored = true;
        Some(Err(err))
    }

    /// Returns the journal.
    ///
    /// Fails when the reader was not fully drained or yielded an error: the journal is
    /// destroyed and recovery is re-initialization.
    pub fn finish(self) -> Result<Journal<E, A>, Error> {
        if self.errored || !self.finished {
            return Err(Error::ReplayFailed);
        }
        Ok(self.journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        BufferPooler, Error as RError, Runner, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, fail_pending_syncs, release_pending_syncs},
    };
    use commonware_utils::{NZU16, NZUsize};
    use core::num::NonZeroU16;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&[&value.to_be_bytes()])
    }

    fn test_cfg(pooler: &impl BufferPooler) -> Config {
        Config {
            partition: "test-partition".into(),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    #[test_traced]
    fn test_segmented_fixed_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            let pos0;
            (journal, pos0) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos0, 0);

            let pos1;
            (journal, pos1) = journal
                .append(1, &test_digest(1))
                .await
                .expect("failed to append");
            assert_eq!(pos1, 1);

            let pos2;
            (journal, pos2) = journal
                .append(2, &test_digest(2))
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
    fn test_segmented_fixed_replay_empty_finishes_immediately() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let journal = Journal::<_, Digest>::init(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            // An empty journal's reader is exhausted from the start
            let replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("failed to replay");
            let journal = replay.finish().expect("failed to finish replay");
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay_finish_before_drain_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::<_, Digest>::init(context.child("storage"), cfg)
                .await
                .expect("failed to init");
            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            journal = journal.sync_all().await.expect("failed to sync");

            let replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("failed to replay");
            assert!(matches!(replay.finish(), Err(Error::ReplayFailed)));
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..10 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            for i in 10u64..20 {
                (journal, _) = journal
                    .append(2, &test_digest(i))
                    .await
                    .expect("failed to append");
            }

            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            let items = {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    match result {
                        Ok((section, pos, item)) => items.push((section, pos, item)),
                        Err(err) => panic!("replay error: {err}"),
                    }
                }
                journal = replay.finish().expect("failed to finish replay");
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
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append 10 items to section 1
            for i in 0u64..10 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            // Append 5 items to section 2
            for i in 10u64..15 {
                (journal, _) = journal
                    .append(2, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Replay from section 1, position 5 - should get items 5-9 from section 1 and all of section 2
            {
                let mut replay = journal
                    .replay(1, 5, NZUsize!(1024))
                    .await
                    .expect("failed to replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }
                journal = replay.finish().expect("failed to finish replay");

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
                let mut replay = journal
                    .replay(1, 9, NZUsize!(1024))
                    .await
                    .expect("failed to replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }
                journal = replay.finish().expect("failed to finish replay");

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
                let mut replay = journal
                    .replay(2, 3, NZUsize!(1024))
                    .await
                    .expect("failed to replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, pos, item) = result.expect("replay error");
                    items.push((section, pos, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 2, "Should have 2 items from section 2");
                assert_eq!(items[0], (2, 3, test_digest(13)));
                assert_eq!(items[1], (2, 4, test_digest(14)));
            }

            // Replay from position past the end should return ItemOutOfRange error.
            // A failed replay consumes the journal, so re-initialize between attempts.
            let result = journal.replay(1, 100, NZUsize!(1024)).await;
            assert!(matches!(result, Err(Error::ItemOutOfRange(100))));

            let journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
                .await
                .expect("failed to re-init");
            let result = journal.replay(1, u64::MAX, NZUsize!(1024)).await;
            assert!(matches!(result, Err(Error::ItemOutOfRange(u64::MAX))));

            let journal = Journal::<_, Digest>::init(context.child("fourth"), cfg.clone())
                .await
                .expect("failed to re-init");
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            for section in 1u64..=5 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            (journal, _) = journal.prune(3).await.expect("failed to prune");

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
    fn test_segmented_fixed_pruned_after_full_prune() {
        // `pruned` must keep reporting the floor after every blob is removed, when
        // `oldest_section` returns None (indistinguishable from a fresh journal).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            for section in 1u64..=3 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            (journal, _) = journal.prune(10).await.expect("failed to prune");
            assert_eq!(journal.oldest_section(), None);
            assert!(journal.pruned(3));
            assert!(journal.pruned(9));
            assert!(!journal.pruned(10));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1, 2, 3
            for section in 1u64..=3 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            // Verify all sections exist
            for section in 1u64..=3 {
                let size = journal.size(section).expect("failed to get size");
                assert!(size > 0, "section {section} should have data");
            }

            // Rewind to section 1 (should remove sections 2, 3)
            let size = journal.size(1).expect("failed to get size");
            journal = journal.rewind(1, size).await.expect("failed to rewind");

            // Verify section 1 still has data
            let size = journal.size(1).expect("failed to get size");
            assert!(size > 0, "section 1 should still have data");

            // Verify sections 2, 3 are removed
            for section in 2u64..=3 {
                let size = journal.size(section).expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data in section 1 is still readable
            let item = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item, test_digest(1));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind_max_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            // Append to the maximal section. `section + 1` has no representable successor.
            (journal, _) = journal
                .append(u64::MAX, &test_digest(0))
                .await
                .expect("failed to append");
            journal = journal.sync_all().await.expect("failed to sync");

            // Rewinding the maximal section removes no sections above it and must not panic.
            let size = journal.size(u64::MAX).expect("failed to get size");
            journal = journal
                .rewind(u64::MAX, size)
                .await
                .expect("failed to rewind");

            // The section is intact and readable.
            assert_eq!(journal.size(u64::MAX).expect("failed to get size"), size);
            assert_eq!(journal.get(u64::MAX, 0).await.unwrap(), test_digest(0));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind_many_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1-10
            for section in 1u64..=10 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            // Rewind to section 5 (should remove sections 6-10)
            let size = journal.size(5).expect("failed to get size");
            journal = journal.rewind(5, size).await.expect("failed to rewind");

            // Verify sections 1-5 still have data
            for section in 1u64..=5 {
                let size = journal.size(section).expect("failed to get size");
                assert!(size > 0, "section {section} should still have data");
            }

            // Verify sections 6-10 are removed
            for section in 6u64..=10 {
                let size = journal.size(section).expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data integrity via replay
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, item) = result.expect("failed to read");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");
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
            let cfg = test_cfg(&context);

            // Create sections 1-5
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");
            for section in 1u64..=5 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            // Rewind to section 2
            let size = journal.size(2).expect("failed to get size");
            journal = journal.rewind(2, size).await.expect("failed to rewind");
            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Re-init and verify only sections 1-2 exist
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Verify sections 1-2 have data
            for section in 1u64..=2 {
                let size = journal.size(section).expect("failed to get size");
                assert!(size > 0, "section {section} should have data after restart");
            }

            // Verify sections 3-5 are gone
            for section in 3u64..=5 {
                let size = journal.size(section).expect("failed to get size");
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
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("failed to open blob");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");

            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            let count = {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");

                let mut count = 0;
                while let Some(result) = replay.next().await {
                    result.expect("should be ok");
                    count += 1;
                }
                journal = replay.finish().expect("failed to finish replay");
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
            let cfg = test_cfg(&context);

            // Create and populate journal
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Reopen and verify data persisted
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg)
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
    fn test_segmented_fixed_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // One sub-page item per section stays buffered until synced.
            for section in 1u64..=3 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }

            // Sync sections 1 and 3; a nonexistent section (99) is skipped, not an error.
            journal
                .sync(&[1, 3, 99])
                .await
                .expect("failed to sync sections");

            // Only the synced sections survive the unclean drop.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg)
                .await
                .expect("failed to re-init");
            assert_eq!(
                journal.get(1, 0).await.expect("section 1 durable"),
                test_digest(1)
            );
            assert_eq!(
                journal.get(3, 0).await.expect("section 3 durable"),
                test_digest(3)
            );
            assert!(matches!(
                journal.get(2, 0).await,
                Err(Error::ItemOutOfRange(0)) | Err(Error::SectionOutOfRange(2))
            ));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_section_len() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            assert_eq!(journal.section_len(1).unwrap(), 0);

            for i in 0u64..5 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }

            assert_eq!(journal.section_len(1).unwrap(), 5);
            assert_eq!(journal.section_len(2).unwrap(), 0);

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_non_contiguous_sections() {
        // Test that sections with gaps in numbering work correctly.
        // Sections 1, 5, 10 should all be independent and accessible.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections with gaps: 1, 5, 10
            (journal, _) = journal
                .append(1, &test_digest(100))
                .await
                .expect("failed to append");
            (journal, _) = journal
                .append(5, &test_digest(500))
                .await
                .expect("failed to append");
            (journal, _) = journal
                .append(10, &test_digest(1000))
                .await
                .expect("failed to append");
            journal = journal.sync_all().await.expect("failed to sync");

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
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Replay and verify all items in order
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 3, "Should have 3 items");
                assert_eq!(items[0], (1, test_digest(100)));
                assert_eq!(items[1], (5, test_digest(500)));
                assert_eq!(items[2], (10, test_digest(1000)));
            }

            // Test replay starting from middle section (5)
            {
                let mut replay = journal
                    .replay(5, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay from section 5");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

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
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append to section 1
            (journal, _) = journal
                .append(1, &test_digest(100))
                .await
                .expect("failed to append");

            // Create section 2 but make it empty via rewind
            (journal, _) = journal
                .append(2, &test_digest(200))
                .await
                .expect("failed to append");
            journal = journal.sync(2).await.expect("failed to sync");
            journal = journal
                .rewind_section(2, 0)
                .await
                .expect("failed to rewind");

            // Append to section 3
            (journal, _) = journal
                .append(3, &test_digest(300))
                .await
                .expect("failed to append");

            journal = journal.sync_all().await.expect("failed to sync");

            // Verify section lengths
            assert_eq!(journal.section_len(1).unwrap(), 1);
            assert_eq!(journal.section_len(2).unwrap(), 0);
            assert_eq!(journal.section_len(3).unwrap(), 1);

            // Drop and reopen to test replay
            drop(journal);
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Replay all - should get items from sections 1 and 3, skipping empty section 2
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

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
                let mut replay = journal
                    .replay(2, 0, NZUsize!(1024))
                    .await
                    .expect("failed to replay from section 2");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, item) = result.expect("replay error");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

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
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append 3 items (just over 2 pages worth)
            for i in 0u64..3 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

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
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Verify section now has only 2 items
            assert_eq!(journal.section_len(1).unwrap(), 2);

            // Verify size is the expected multiple of ITEM_SIZE (this would fail if we didn't trim
            // items and just relied on page-level checksum recovery).
            assert_eq!(journal.size(1).unwrap(), 64);

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
    fn test_journal_clear() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "clear-test".into(),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal: Journal<_, Digest> =
                Journal::init(context.child("journal"), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

            // Append items across multiple sections
            for section in 0..5u64 {
                for i in 0..10u64 {
                    (journal, _) = journal
                        .append(section, &test_digest(section * 1000 + i))
                        .await
                        .expect("Failed to append");
                }
                journal = journal.sync(section).await.expect("Failed to sync");
            }

            // Verify we have data
            assert_eq!(journal.get(0, 0).await.unwrap(), test_digest(0));
            assert_eq!(journal.get(4, 0).await.unwrap(), test_digest(4000));

            // Clear the journal
            journal = journal.clear().await.expect("Failed to clear");

            // After clear, all reads should fail
            for section in 0..5u64 {
                assert!(matches!(
                    journal.get(section, 0).await,
                    Err(Error::SectionOutOfRange(s)) if s == section
                ));
            }

            // Append new data after clear
            for i in 0..5u64 {
                (journal, _) = journal
                    .append(10, &test_digest(i * 100))
                    .await
                    .expect("Failed to append after clear");
            }
            journal = journal.sync(10).await.expect("Failed to sync after clear");

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

    #[test_traced]
    fn test_last_missing_section_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let journal = Journal::<_, Digest>::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            assert!(matches!(
                journal.last(0).await,
                Err(Error::SectionOutOfRange(0))
            ));
            assert!(matches!(
                journal.last(99).await,
                Err(Error::SectionOutOfRange(99))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_last_after_rewind_to_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            (journal, _) = journal.append(0, &test_digest(0)).await.unwrap();
            (journal, _) = journal.append(0, &test_digest(1)).await.unwrap();
            journal = journal.sync(0).await.unwrap();

            assert!(journal.last(0).await.unwrap().is_some());

            journal = journal.rewind(0, 0).await.unwrap();
            assert_eq!(journal.last(0).await.unwrap(), None);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_last_pruned_section_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::<_, Digest>::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            (journal, _) = journal.append(0, &test_digest(0)).await.unwrap();
            (journal, _) = journal.append(1, &test_digest(1)).await.unwrap();
            journal = journal.sync_all().await.unwrap();

            (journal, _) = journal.prune(1).await.unwrap();

            assert!(matches!(
                journal.last(0).await,
                Err(Error::AlreadyPrunedToSection(1))
            ));
            assert!(journal.last(1).await.unwrap().is_some());

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg).await.unwrap();
            (journal, _) = journal.append(0, &test_digest(0)).await.unwrap();
            assert_eq!(journal.section_len(0).unwrap(), 1);

            let mut buf = [];
            let (items, hits) = journal.get_many(0, &[], &mut buf).await.unwrap();
            assert!(items.is_empty());
            assert_eq!(hits, 0);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_single_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg).await.unwrap();

            for i in 0..5 {
                (journal, _) = journal.append(0, &test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.section_len(0).unwrap(), 5);

            // Read all 5 items in one call. The reusable buffer is intentionally oversized:
            // get_many slices it to the exact length the batch needs.
            let chunk = Journal::<deterministic::Context, Digest>::CHUNK_SIZE;
            let mut buf = vec![0u8; 6 * chunk];
            let (items, _) = journal
                .get_many(0, &[0, 1, 2, 3, 4], &mut buf)
                .await
                .unwrap();

            for (i, item) in items.iter().enumerate() {
                assert_eq!(*item, test_digest(i as u64));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_subset() {
        // Read a sparse subset of positions.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg).await.unwrap();

            for i in 0..10 {
                (journal, _) = journal.append(0, &test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.section_len(0).unwrap(), 10);

            let chunk = Journal::<deterministic::Context, Digest>::CHUNK_SIZE;
            let positions = [1, 4, 7, 9];
            let mut buf = vec![0u8; positions.len() * chunk];
            let (items, _) = journal.get_many(0, &positions, &mut buf).await.unwrap();

            for (i, &pos) in positions.iter().enumerate() {
                assert_eq!(items[i], test_digest(pos));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_bad_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let journal = Journal::<_, Digest>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            let mut buf = vec![0u8; 64];
            let err = journal.get_many(99, &[0], &mut buf).await.unwrap_err();
            assert!(matches!(err, Error::SectionOutOfRange(99)));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_matches_get() {
        // Verify batch read matches individual reads.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg).await.unwrap();

            for i in 0..8 {
                (journal, _) = journal.append(0, &test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.section_len(0).unwrap(), 8);
            journal = journal.sync_all().await.unwrap();

            let chunk = Journal::<deterministic::Context, Digest>::CHUNK_SIZE;
            let positions: Vec<u64> = (0..8).collect();
            let mut buf = vec![0u8; positions.len() * chunk];
            let (batch, _) = journal.get_many(0, &positions, &mut buf).await.unwrap();

            for pos in &positions {
                let single = journal.get(0, *pos).await.unwrap();
                assert_eq!(batch[*pos as usize], single);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("prune").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                let (journal, pruned) = journal.prune(2).await.expect("failed to prune");
                assert!(pruned);
                completed_clone.fetch_add(1, Ordering::Relaxed);
                journal
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "prune must wait for in-flight syncs on pruned sections"
            );

            release_pending_syncs(&pending);
            handle
                .await
                .expect("sync handle should complete despite pruning");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let journal = waiter.await.expect("prune task failed");
            assert_eq!(journal.oldest_section(), None);
        });
    }

    #[test_traced]
    fn test_segmented_fixed_destroy_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("destroy").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                journal.destroy().await.expect("failed to destroy");
                completed_clone.fetch_add(1, Ordering::Relaxed);
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "destroy must wait for in-flight syncs"
            );

            release_pending_syncs(&pending);
            handle
                .await
                .expect("sync handle should complete despite destruction");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            waiter.await.expect("destroy task failed");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_clear_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("clear").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                journal = journal.clear().await.expect("failed to clear");
                completed_clone.fetch_add(1, Ordering::Relaxed);
                journal
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "clear must wait for in-flight syncs"
            );

            release_pending_syncs(&pending);
            handle
                .await
                .expect("sync handle should complete despite clearing");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let mut journal = waiter.await.expect("clear task failed");

            // The journal must remain usable after clear.
            assert_eq!(journal.oldest_section(), None);
            let position;
            (journal, position) = journal
                .append(1, &test_digest(1))
                .await
                .expect("failed to append after clear");
            assert_eq!(position, 0);
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            (journal, _) = journal
                .append(2, &test_digest(1))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(2).await.expect("failed to start sync");
            assert!(!pending.lock().is_empty());

            let size = journal.size(1).expect("failed to get size");
            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("rewind").spawn(move |_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                journal = journal.rewind(1, size).await.expect("failed to rewind");
                completed_clone.fetch_add(1, Ordering::Relaxed);
                journal
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "rewind must wait for in-flight syncs on removed sections"
            );

            release_pending_syncs(&pending);
            handle
                .await
                .expect("sync handle should complete despite rewind");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let journal = waiter.await.expect("rewind task failed");
            assert_eq!(journal.size(2).expect("failed to get size"), 0);
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune_surfaces_failed_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            fail_pending_syncs(&pending);

            let err = journal
                .prune(2)
                .await
                .expect_err("prune must surface a failed in-flight sync");
            assert!(matches!(err, Error::Runtime(RError::Io(_))));

            let err = handle.await.expect_err("sync handle should fail");
            assert!(matches!(err, RError::Io(_)));
        });
    }
}
