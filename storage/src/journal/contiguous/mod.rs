//! Contiguous journals with position-based access.
//!
//! This module provides position-based journal implementations where items are stored
//! contiguously and can be accessed by their position (0-indexed). Both [fixed]-size and
//! [variable]-size item journals are supported.
//!
//! Storage errors from mutable operations are considered fatal for the current handle and may
//! leave its in-memory state inconsistent with the underlying storage.

use super::Error;
use crate::journal::frame::FrameReader;
use commonware_runtime::{
    buffer::paged::{Replay as PagedReplay, Sealed, Writer},
    Blob as RBlob, Buf, Error as RError, IoBufMut, IoBufs,
};
use futures::{stream, Stream, StreamExt as _};
use std::{future::Future, num::NonZeroUsize, ops::Range};
use tracing::warn;

pub mod fixed;
mod metrics;
pub mod variable;

#[cfg(test)]
mod tests;

/// A decoded batch yielded by [ReplayBatchState::next_batch] paired with the advanced state, or
/// `None` once the state is exhausted.
type ReplayBatch<S> = Option<(Vec<Result<(u64, <S as ReplayBatchState>::Item), Error>>, S)>;

/// Replay state over a journal's blob that yields decoded item batches.
trait ReplayBatchState: Sized {
    /// The decoded item type.
    type Item;

    /// Decode the next batch from the blob.
    fn next_batch(self) -> impl Future<Output = ReplayBatch<Self>> + Send;
}

/// Build a stream over a replay state (`None` replays nothing): batches are yielded until the
/// state is exhausted, and the stream terminates after the first batch containing an error.
fn replay_stream<S>(state: Option<S>) -> impl Stream<Item = Result<(u64, S::Item), Error>> + Send
where
    S: ReplayBatchState + Send,
    S::Item: Send,
{
    stream::unfold(state, |state| async move {
        let (batch, state) = state?.next_batch().await?;
        let state = (!batch.iter().any(Result::is_err)).then_some(state);
        Some((batch, state))
    })
    .flat_map(stream::iter)
}

/// A read-only, position-based view of a contiguous journal.
///
/// Maintains a monotonically increasing position counter where each appended item receives a unique
/// position starting from 0.
pub trait Contiguous: Send + Sync {
    /// The type of items stored in the journal.
    type Item: Send;

    /// Returns [start, end) with a guaranteed stable pruning boundary.
    fn bounds(&self) -> Range<u64>;

    /// Read the item at the given position.
    ///
    /// Guaranteed not to return [Error::ItemPruned] for positions within `bounds()`.
    fn read(&self, position: u64) -> impl Future<Output = Result<Self::Item, Error>> + Send + Sync;

    /// Read multiple items at the given positions, which must be strictly increasing.
    ///
    /// Equivalent to serving every position [`try_read_many_sync`](Self::try_read_many_sync)
    /// declines with one batched read. Implementations may fuse the two passes.
    fn read_many(
        &self,
        positions: &[u64],
    ) -> impl Future<Output = Result<Vec<Self::Item>, Error>> + Send
    where
        Self::Item: Send;

    /// Read an item if it can be done synchronously (e.g. without I/O), returning `None`
    /// otherwise. Decode failures surface as `None` and the async read path reports the error.
    fn try_read_sync(&self, position: u64) -> Option<Self::Item>;

    /// Probe multiple strictly increasing positions, serving those that can be read
    /// synchronously (e.g. from a page cache) and returning one slot per position. Positions
    /// that require I/O, fail to decode, or fall outside `bounds()` decline to `None`. The
    /// async read paths are the sole error authority for declined positions.
    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<Self::Item>>;

    /// Return a stream of all items starting from `start_pos`, bounded by `bounds()`.
    ///
    /// `buffer` controls the replay byte budget for each chunk.
    fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> impl Future<
        Output = Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + Send, Error>,
    > + Send;
}

/// Items to append via [`Mutable::append_many`].
///
/// `Flat` wraps a single contiguous slice; `Nested` wraps multiple slices appended in order.
pub enum Many<'a, T> {
    /// A single contiguous slice of items.
    Flat(&'a [T]),
    /// Multiple slices of items, appended in order.
    Nested(&'a [&'a [T]]),
}

impl<T> Many<'_, T> {
    /// Returns the total number of items across all segments.
    pub fn len(&self) -> usize {
        match self {
            Self::Flat(items) => items.len(),
            Self::Nested(nested_items) => nested_items.iter().map(|items| items.len()).sum(),
        }
    }

    /// Returns `true` if there are no items across all segments.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Flat(items) => items.is_empty(),
            Self::Nested(nested_items) => nested_items.iter().all(|items| items.is_empty()),
        }
    }
}

/// A [Contiguous] journal that supports appending, rewinding, and pruning.
pub trait Mutable: Contiguous + Send + Sync {
    /// Append a new item to the journal, returning its position.
    ///
    /// Positions are consecutively increasing starting from 0. The position of each item
    /// is stable across pruning (i.e., if item X has position 5, it will always have
    /// position 5 even if earlier items are pruned).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails or if the item cannot
    /// be encoded.
    fn append(
        &mut self,
        item: &Self::Item,
    ) -> impl std::future::Future<Output = Result<u64, Error>> + Send;

    /// Append items to the journal, returning the position of the last item appended.
    ///
    /// Returns [Error::EmptyAppend] if items is empty.
    fn append_many<'a>(
        &'a mut self,
        items: Many<'a, Self::Item>,
    ) -> impl std::future::Future<Output = Result<u64, Error>> + Send + 'a
    where
        Self::Item: Sync;

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Behavior
    ///
    /// - If `min_position > bounds.end`, the prune is capped to `bounds.end` (no error is returned)
    /// - Pruning is exact: the new pruning boundary IS the requested position (after capping)
    /// - The prune commits atomically: a crash leaves the journal either in its prior state or
    ///   fully pruned. The boundary may also regress across a crash to the last synced boundary
    ///   (never advance), so callers re-prune after recovery
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    fn prune(
        &mut self,
        min_position: u64,
    ) -> impl std::future::Future<Output = Result<bool, Error>> + Send;

    /// Rewind the journal to the given size, discarding items from the end.
    ///
    /// After rewinding to size N, the journal will contain exactly N items (positions 0 to N-1),
    /// and the next append will receive position N.
    ///
    /// # Behavior
    ///
    /// - If `size > bounds.end`, returns [Error::InvalidRewind]
    /// - If `size == bounds.end`, this is a no-op
    /// - If `size < bounds.start`, returns [Error::ItemPruned] (can't rewind to pruned data)
    /// - This operation is not atomic, but implementations guarantee the journal is left in a
    ///   recoverable state if a crash occurs during rewinding
    ///
    /// # Warnings
    ///
    /// - This operation is not guaranteed to survive restarts until `sync` is called.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if `size` is beyond the current size, or [Error::ItemPruned]
    /// if it precedes the pruning boundary. Returns an error if the underlying storage operation
    /// fails.
    fn rewind(&mut self, size: u64) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Durably persist the journal, guaranteeing the current state will survive a crash.
    ///
    /// All pending state (item data and any boundary records) lands in one atomic commit.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Destroy the journal, removing all associated storage.
    ///
    /// This method consumes the journal and deletes all persisted data, leaving behind no storage
    /// artifacts. The removals commit atomically: a crash leaves the journal either in its prior
    /// state or fully destroyed.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send
    where
        Self: Sized;

    /// Rewinds the journal to the last item matching `predicate`. If no item matches, the journal
    /// is rewound to the pruning boundary, discarding all unpruned items.
    ///
    /// # Warnings
    ///
    /// - This operation is not guaranteed to survive restarts until `sync` is called.
    fn rewind_to<'a, P>(
        &'a mut self,
        mut predicate: P,
    ) -> impl std::future::Future<Output = Result<u64, Error>> + Send + 'a
    where
        P: FnMut(&Self::Item) -> bool + Send + 'a,
    {
        async move {
            let bounds = self.bounds();
            let mut rewind_size = bounds.end;
            while rewind_size > bounds.start {
                let item = self.read(rewind_size - 1).await?;
                if predicate(&item) {
                    break;
                }
                rewind_size -= 1;
            }

            if rewind_size != bounds.end {
                let rewound_items = bounds.end - rewind_size;
                warn!(
                    journal_size = bounds.end,
                    rewound_items, "rewinding journal items"
                );
                self.rewind(rewind_size).await?;
            }

            Ok(rewind_size)
        }
    }
}

/// A read handle for a journal's blob.
pub(super) enum Blob<'a, B: RBlob> {
    /// Writable blob, read through the writer's cache-aware logical view.
    Writer(&'a Writer<B>),
    /// Immutable snapshot of the blob.
    Sealed(Sealed<B>),
}

impl<B: RBlob> Clone for Blob<'_, B> {
    fn clone(&self) -> Self {
        match self {
            Self::Writer(writer) => Self::Writer(writer),
            Self::Sealed(sealed) => Self::Sealed(sealed.clone()),
        }
    }
}

impl<'a, B: RBlob> Blob<'a, B> {
    /// Return the blob's logical size.
    pub(super) fn size(&self) -> u64 {
        match self {
            Self::Writer(writer) => writer.size(),
            Self::Sealed(sealed) => sealed.size(),
        }
    }

    /// Read into `buf` if the data is already cached.
    pub(super) fn try_read_sync_into(&self, buf: &mut [u8], offset: u64) -> bool {
        match self {
            Self::Writer(writer) => writer.try_read_sync_into(buf, offset),
            Self::Sealed(sealed) => sealed.try_read_sync_into(buf, offset),
        }
    }

    /// Read exactly `len` bytes at `offset`.
    pub(super) async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        match self {
            Self::Writer(writer) => writer.read_at(offset, len).await.map_err(Error::Runtime),
            Self::Sealed(sealed) => sealed.read_at(offset, len).await.map_err(Error::Runtime),
        }
    }

    /// Read up to `len` bytes at `offset`.
    pub(super) async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        match self {
            Self::Writer(writer) => writer
                .read_up_to(offset, len, bufs)
                .await
                .map_err(Error::Runtime),
            Self::Sealed(sealed) => sealed
                .read_up_to(offset, len, bufs)
                .await
                .map_err(Error::Runtime),
        }
    }

    /// Return a sequential replay handle starting at `offset`.
    ///
    /// Constructing the handle is cheap: paged replay stores prefetch settings, and writer-view
    /// replay starts with an empty buffer. Read buffers are allocated later by `Replay::ensure`.
    ///
    /// Sealed blobs can use paged replay directly because their bytes are already fixed. A
    /// writable blob is replayed through a live view so replay observes logical bytes without
    /// mutating or flushing the writer.
    pub(super) fn replay_from(
        self,
        offset: u64,
        buffer_size: NonZeroUsize,
    ) -> Result<Replay<'a, B>, Error> {
        match self {
            Self::Writer(writer) => Replay::view(Self::Writer(writer), offset, buffer_size),
            Self::Sealed(sealed) => {
                let mut replay = sealed.replay(buffer_size).map_err(Error::Runtime)?;
                replay.seek_to(offset).map_err(Error::Runtime)?;
                Ok(Replay::paged(replay))
            }
        }
    }

    /// Read fixed-size items at sorted byte offsets into `buf`.
    pub(super) async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        match self {
            Self::Writer(writer) => writer
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
            Self::Sealed(sealed) => sealed
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
        }
    }

    /// Like [`Self::read_many_into`], but synchronous and cache-only. Returns the indices of
    /// items that require a blob read. Their slots in `buf` hold unspecified bytes.
    pub(super) fn try_read_many_sync_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Vec<usize> {
        match self {
            Self::Writer(writer) => writer.try_read_many_sync_into(buf, offsets, item_size),
            Self::Sealed(sealed) => sealed.try_read_many_sync_into(buf, offsets, item_size),
        }
    }

    /// Like [`Self::try_read_many_sync_into`], but for variable-length `(offset, len)` ranges.
    pub(super) fn try_read_ranges_sync_into(
        &self,
        buf: &mut [u8],
        ranges: &[(u64, usize)],
    ) -> Vec<usize> {
        match self {
            Self::Writer(writer) => writer.try_read_ranges_sync_into(buf, ranges),
            Self::Sealed(sealed) => sealed.try_read_ranges_sync_into(buf, ranges),
        }
    }
}

impl<B: RBlob> FrameReader for Blob<'_, B> {
    async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        Self::read_up_to(self, offset, len, bufs).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        Self::read_at(self, offset, len).await
    }
}

/// Sequential replay over either a sealed paged blob or a live writer view.
pub(super) struct Replay<'a, B: RBlob> {
    inner: ReplayInner<'a, B>,
}

/// Backing strategy for sequential blob replay.
enum ReplayInner<'a, B: RBlob> {
    /// Paged replay over sealed data. The runtime buffer serves raw logical
    /// bytes (integrity is verified by the storage backend).
    Paged(PagedReplay<B>),
    /// Logical replay over a live writer or any other blob view.
    View(ViewReplay<'a, B>),
}

impl<'a, B: RBlob> Replay<'a, B> {
    /// Wrap a paged replay handle.
    const fn paged(replay: PagedReplay<B>) -> Self {
        Self {
            inner: ReplayInner::Paged(replay),
        }
    }

    /// Build a replay handle over a logical blob view.
    fn view(blob: Blob<'a, B>, offset: u64, buffer_size: NonZeroUsize) -> Result<Self, Error> {
        Ok(Self {
            inner: ReplayInner::View(ViewReplay::new(blob, offset, buffer_size)?),
        })
    }

    /// Return whether the underlying blob has reached EOF.
    ///
    /// The replay buffer may still hold bytes after this becomes true.
    pub(super) const fn is_exhausted(&self) -> bool {
        match &self.inner {
            ReplayInner::Paged(replay) => replay.is_exhausted(),
            ReplayInner::View(replay) => replay.is_exhausted(),
        }
    }

    /// Ensure at least `n` logical bytes are buffered unless EOF is reached first.
    pub(super) async fn ensure(&mut self, n: usize) -> Result<bool, Error> {
        match &mut self.inner {
            ReplayInner::Paged(replay) => replay.ensure(n).await.map_err(Error::Runtime),
            ReplayInner::View(replay) => replay.ensure(n).await,
        }
    }
}

impl<B: RBlob> Buf for Replay<'_, B> {
    fn remaining(&self) -> usize {
        match &self.inner {
            ReplayInner::Paged(replay) => replay.remaining(),
            ReplayInner::View(replay) => replay.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match &self.inner {
            ReplayInner::Paged(replay) => replay.chunk(),
            ReplayInner::View(replay) => replay.chunk(),
        }
    }

    fn advance(&mut self, cnt: usize) {
        match &mut self.inner {
            ReplayInner::Paged(replay) => replay.advance(cnt),
            ReplayInner::View(replay) => replay.advance(cnt),
        }
    }
}

/// Sequential read buffer over a live journal blob view.
struct ViewReplay<'a, B: RBlob> {
    /// The source blob view.
    blob: Blob<'a, B>,
    /// Next logical offset to read from `blob`.
    offset: u64,
    /// Minimum read size when more bytes are needed.
    buffer_size: NonZeroUsize,
    /// Buffered logical bytes.
    buf: Vec<u8>,
    /// Offset of the next unread byte in `buf`.
    cursor: usize,
    /// Whether `offset` has reached the source blob's logical size.
    exhausted: bool,
}

impl<'a, B: RBlob> ViewReplay<'a, B> {
    /// Create a view replay positioned at `offset`.
    fn new(blob: Blob<'a, B>, offset: u64, buffer_size: NonZeroUsize) -> Result<Self, Error> {
        if offset > blob.size() {
            return Err(Error::Runtime(RError::BlobInsufficientLength));
        }

        Ok(Self {
            blob,
            offset,
            buffer_size,
            buf: Vec::new(),
            cursor: 0,
            exhausted: false,
        })
    }

    /// Return whether the source view has no more bytes to read.
    const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Ensure at least `n` bytes are available through the [`Buf`] implementation.
    async fn ensure(&mut self, n: usize) -> Result<bool, Error> {
        while self.remaining() < n && !self.exhausted {
            self.compact();

            let blob_size = self.blob.size();
            let remaining = blob_size.saturating_sub(self.offset);
            if remaining == 0 {
                self.exhausted = true;
                break;
            }

            // Read enough to satisfy the request, but keep ordinary prefetch bounded by the replay
            // budget and never ask past the current logical EOF.
            let needed = n.saturating_sub(self.remaining());
            let read_len = self
                .buffer_size
                .get()
                .max(needed)
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let (buf, read) = self
                .blob
                .read_up_to(self.offset, read_len, IoBufMut::with_capacity(read_len))
                .await?;
            self.offset = self
                .offset
                .checked_add(read as u64)
                .ok_or(Error::OffsetOverflow)?;
            self.buf.extend_from_slice(&buf.chunk()[..read]);
            if self.offset == blob_size {
                self.exhausted = true;
            }
        }

        Ok(self.remaining() >= n)
    }

    /// Discard bytes already consumed through [`Buf::advance`].
    fn compact(&mut self) {
        match self.cursor {
            0 => {}
            cursor if cursor == self.buf.len() => {
                self.buf.clear();
                self.cursor = 0;
            }
            cursor => {
                self.buf.drain(..cursor);
                self.cursor = 0;
            }
        }
    }
}

impl<B: RBlob> Buf for ViewReplay<'_, B> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.cursor
    }

    fn chunk(&self) -> &[u8] {
        &self.buf[self.cursor..]
    }

    fn advance(&mut self, cnt: usize) {
        self.cursor = self
            .cursor
            .checked_add(cnt)
            .expect("advance overflowed replay cursor");
        assert!(self.cursor <= self.buf.len(), "advanced past replay buffer");
    }
}

#[cfg(test)]
mod blob_tests {
    use super::*;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _, Storage as _};
    use commonware_utils::{NZUsize, NZU16};

    fn assert_insufficient_length(result: Result<(IoBufMut, usize), Error>) {
        assert!(matches!(
            result,
            Err(Error::Runtime(RError::BlobInsufficientLength))
        ));
    }

    #[test]
    fn test_read_up_to_eof_parity() {
        const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(64);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(3));
            let (blob, size) = context
                .open("read_up_to_eof_parity", b"blob")
                .await
                .unwrap();
            let mut writer = Writer::new(blob, size, 128, cache_ref).await.unwrap();
            writer.append(b"abc").await.unwrap();

            let size = writer.size();
            let tail = Blob::Writer(&writer);
            assert_insufficient_length(tail.read_up_to(size, 1, IoBufMut::with_capacity(1)).await);
            assert_eq!(
                tail.read_up_to(size, 0, IoBufMut::with_capacity(0))
                    .await
                    .unwrap()
                    .1,
                0
            );

            let snapshot = writer.snapshot().await.unwrap();
            let snapshot_blob = Blob::Sealed(snapshot);
            assert_insufficient_length(
                snapshot_blob
                    .read_up_to(size, 1, IoBufMut::with_capacity(1))
                    .await,
            );
            assert_eq!(
                snapshot_blob
                    .read_up_to(size, 0, IoBufMut::with_capacity(0))
                    .await
                    .unwrap()
                    .1,
                0
            );
        });
    }
}
