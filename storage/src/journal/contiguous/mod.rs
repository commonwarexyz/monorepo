//! Contiguous journals with position-based access.
//!
//! This module provides position-based journal implementations where items are stored
//! contiguously and can be accessed by their position (0-indexed). Both [fixed]-size and
//! [variable]-size item journals are supported.
//!
//! # Ownership
//!
//! Mutating methods take the journal by value and return it on success. If a mutating
//! method returns an error, or its future is dropped before it finishes, the journal is
//! gone: state that was not yet durable is discarded, but everything already on disk stays
//! recoverable.

use super::Error;
use commonware_runtime::{Handle, ReadOptions, Removal};
use futures::{Stream, stream};
use std::{future::Future, num::NonZeroUsize, ops::Range};

mod blobs;
mod checkpoint;
pub mod fixed;
mod metrics;
pub mod variable;

#[cfg(test)]
pub(crate) mod tests;

/// Return the number of items that can be written before crossing the current blob boundary.
///
/// `position` is the next logical item position and `remaining` is the number of items left in the
/// append batch. The result is always at least one when `remaining > 0`.
fn batch_count_to_blob_boundary(position: u64, remaining: usize, items_per_blob: u64) -> usize {
    let pos_in_blob = position % items_per_blob;
    let remaining_space = items_per_blob - pos_in_blob;

    // Keep the min in u64 so a 2^32-item blob space does not truncate to zero on 32-bit targets.
    remaining_space.min(remaining as u64) as usize
}

/// Return the blob containing `position`.
///
/// # Examples
///
/// ```ignore
/// // With 10 items per blob:
/// assert_eq!(position_to_blob(0, 10), 0);   // position 0 -> blob 0
/// assert_eq!(position_to_blob(9, 10), 0);   // position 9 -> blob 0
/// assert_eq!(position_to_blob(10, 10), 1);  // position 10 -> blob 1
/// assert_eq!(position_to_blob(25, 10), 2);  // position 25 -> blob 2
/// assert_eq!(position_to_blob(30, 10), 3);  // position 30 -> blob 3
/// ```
const fn position_to_blob(position: u64, items_per_blob: u64) -> u64 {
    position / items_per_blob
}

/// Return the first position stored in `blob`.
fn blob_first_position(blob: u64, items_per_blob: u64) -> Result<u64, Error> {
    blob.checked_mul(items_per_blob)
        .ok_or(Error::OffsetOverflow)
}

/// Return the exclusive logical end for `blob`, clamped to `end`.
const fn blob_end_position(blob: u64, items_per_blob: u64, end: u64) -> u64 {
    // No positions exist, so `end - 1` would underflow
    if end == 0 {
        return 0;
    }

    // This blob contains `end - 1`, so clamp to the journal end
    let end_blob = (end - 1) / items_per_blob;
    if blob >= end_blob {
        return end;
    }

    // Earlier blobs have a representable natural boundary
    (blob + 1) * items_per_blob
}

/// The batch decoded by one [BatchDecoder::next] call.
struct Decoded<T> {
    /// The items decoded, possibly none.
    batch: Batch<T>,
    /// The error that ended this blob's replay after `batch`, if any.
    error: Option<Error>,
}

impl<T> Decoded<T> {
    /// The `items` decoded before `error` ended the blob's replay.
    const fn failed(start: u64, items: Vec<T>, error: Error) -> Self {
        Self {
            batch: Batch { start, items },
            error: Some(error),
        }
    }
}

/// Per-blob replay state that yields decoded batches.
trait BatchDecoder: Sized {
    /// The decoded item type.
    type Item;

    /// Decode the next batch from this blob state, or return `None` once it is exhausted.
    ///
    /// An error ends the blob's replay after the items decoded before it, and the state is not
    /// polled again.
    fn next(self) -> impl Future<Output = Option<(Decoded<Self::Item>, Self)>> + Send;
}

/// Stream driver over per-blob replay states.
struct ReplayStreamState<S: BatchDecoder> {
    /// Remaining blob states, in ascending blob order.
    states: std::vec::IntoIter<S>,
    /// State currently being drained.
    current: Option<S>,
    /// Error to yield after the batch decoded before it.
    pending: Option<Error>,
}

impl<S: BatchDecoder + Send> ReplayStreamState<S>
where
    S::Item: Send,
{
    /// Yield the next decoded batch, or the error that ends the stream.
    async fn next(mut self) -> Option<(Result<Batch<S::Item>, Error>, Self)> {
        loop {
            if let Some(err) = self.pending.take() {
                return Some((Err(err), self));
            }

            let state = match self.current.take().or_else(|| self.states.next()) {
                Some(state) => state,
                None => return None,
            };

            match state.next().await {
                Some((decoded, state)) => {
                    // A failed blob is dropped, and its error ends the stream before any later
                    // blob is read.
                    match decoded.error {
                        Some(err) => {
                            self.pending = Some(err);
                            self.states = Vec::new().into_iter();
                        }
                        None => self.current = Some(state),
                    }
                    if !decoded.batch.items.is_empty() {
                        return Some((Ok(decoded.batch), self));
                    }
                }
                None => {
                    self.current = None;
                }
            }
        }
    }
}

/// Build a batch stream from per-blob replay states.
fn replay_stream_from_states<S>(
    states: Vec<S>,
) -> impl Stream<Item = Result<Batch<S::Item>, Error>> + Send
where
    S: BatchDecoder + Send,
    S::Item: Send,
{
    stream::unfold(
        ReplayStreamState {
            states: states.into_iter(),
            current: None,
            pending: None,
        },
        ReplayStreamState::next,
    )
}

/// A batch of consecutive items yielded by [`Contiguous::replay`]. `items[i]` is the item at
/// position `start + i`, so `start + items.len()` must not exceed `u64::MAX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch<T> {
    /// Position of the first item.
    pub start: u64,
    /// The items at `start..start + items.len()`.
    pub items: Vec<T>,
}

impl<T> IntoIterator for Batch<T> {
    type Item = (u64, T);
    type IntoIter = std::iter::Zip<Range<u64>, std::vec::IntoIter<T>>;

    /// Iterate the items paired with their positions.
    fn into_iter(self) -> Self::IntoIter {
        let end = self.start + self.items.len() as u64;
        (self.start..end).zip(self.items)
    }
}

/// A read-only, position-based view of a contiguous journal.
///
/// Maintains a monotonically increasing position counter where each appended item receives a unique
/// position starting from 0.
///
/// Returned items may retain shared backing allocations larger than their byte fields.
pub trait Contiguous: Send + Sync {
    /// The type of items stored in the journal.
    type Item: Send + Sync;

    /// Returns the readable positions [start, end). `start` is the pruning boundary.
    /// [Mutable::prune] raises it to the requested position, at most `end`, and a reopened journal
    /// may relax it to its oldest retained item until the next prune.
    fn bounds(&self) -> Range<u64>;

    /// Read the item at the given position.
    ///
    /// Guaranteed not to return [Error::ItemPruned] for positions within `bounds()`.
    fn read(&self, position: u64) -> impl Future<Output = Result<Self::Item, Error>> + Send;

    /// Read multiple items at the given positions, which must be strictly increasing.
    ///
    /// Equivalent to serving every position [`try_read_many_sync`](Self::try_read_many_sync)
    /// declines with one batched read. Implementations may fuse the two passes.
    fn read_many(
        &self,
        positions: &[u64],
    ) -> impl Future<Output = Result<Vec<Self::Item>, Error>> + Send;

    /// Read an item if it can be done synchronously (e.g. without I/O), returning `None`
    /// otherwise. Decode failures surface as `None` and the async read path reports the error.
    fn try_read_sync(&self, position: u64) -> Option<Self::Item>;

    /// Probe multiple strictly increasing positions, serving those that can be read
    /// synchronously (e.g. from a page cache) and returning one slot per position. Positions
    /// that require I/O, fail to decode, or fall outside `bounds()` decline to `None`. The
    /// async read paths are the sole error authority for declined positions.
    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<Self::Item>>;

    /// Return a stream of the items in `range` as [`Batch`]es of consecutive items, in position
    /// order. `range` must fall within `bounds()`. An empty range within `bounds()` yields an
    /// empty stream.
    ///
    /// Every batch holds at least one item, consecutive batches are contiguous, and no batch
    /// crosses a backing blob boundary. A batch's items exceed `buffer` bytes as stored, framing
    /// and compression included, by less than one item.
    ///
    /// Backing reads of item data carry `read_options`, except reads served through the page
    /// cache, which applies its own policy.
    ///
    /// # Errors
    ///
    /// Returns [Error::ItemPruned] if `range.start` precedes `bounds().start`, or
    /// [Error::ItemOutOfRange] if `range.end` exceeds `bounds().end` or the range is inverted
    /// (`start > end`).
    fn replay(
        &self,
        range: Range<u64>,
        buffer: NonZeroUsize,
        read_options: ReadOptions,
    ) -> impl Future<
        Output = Result<impl Stream<Item = Result<Batch<Self::Item>, Error>> + Send, Error>,
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

/// A [Contiguous] journal that supports appending and prefix pruning.
pub trait Mutable: Contiguous + Sized {
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
        self,
        item: &Self::Item,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send;

    /// Append items to the journal, returning the position of the last item appended.
    ///
    /// Returns [Error::EmptyAppend] if items is empty.
    fn append_many(
        self,
        items: Many<'_, Self::Item>,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send;

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any blobs were released, `false` otherwise.
    ///
    /// # Behavior
    ///
    /// - If `min_position > bounds.end`, the prune is capped to `bounds.end` (no error is returned)
    /// - Some items with positions less than `min_position` may be retained due to
    ///   section/blob alignment
    /// - Retained items below `min_position` read as pruned, though a reopened journal may expose
    ///   them until the next prune
    /// - This operation is not atomic, but implementations guarantee the journal is left in a
    ///   recoverable state if a crash occurs during pruning
    ///
    /// # Removal
    ///
    /// The prune's effect on reads through this journal is settled when it returns. The storage
    /// layer deletes the released storage in order, once every earlier prune's deletions have
    /// succeeded, and deletion may continue after the prune returns. The [Removal] from
    /// [Self::start_prune] completes when deletion finishes.
    ///
    /// A deletion failure is fatal. Deletions of later prunes of this journal do not run, and the
    /// failure surfaces from that [Removal] and from the next prune, sync, reset, and destroy. A
    /// crash before deletion finishes leaves a prefix of the released storage removed, and
    /// recovery may expose the rest again until the next prune releases it. Deletion still queued
    /// when the runtime shuts down may be abandoned the same way, so a process that needs it
    /// before it exits awaits [Self::removals].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    fn prune(
        self,
        min_position: u64,
    ) -> impl std::future::Future<Output = Result<(Self, bool), Error>> + Send {
        self.prune_after(min_position, None)
    }

    /// Like [Self::prune], with the released storage deleted only once `after` has also completed
    /// successfully, so a structure built from several journals can order all their deletions as
    /// one lineage. If this prune releases storage and `after` fails, the released storage is not
    /// deleted and the failure becomes this journal's deletion failure. A prune that releases
    /// nothing ignores `after`. A journal built from several journals releases nothing only when
    /// none of them releases storage.
    ///
    /// `after` may cover deletions submitted through another storage instance, such as another
    /// journal's [Self::removals], but they must not depend on this prune's deletions, which wait
    /// for `after` before they run.
    fn prune_after(
        self,
        min_position: u64,
        after: Option<Removal>,
    ) -> impl std::future::Future<Output = Result<(Self, bool), Error>> + Send;

    /// Like [Self::prune], also returning a [Removal] that completes once the released storage is
    /// deleted.
    fn start_prune(
        self,
        min_position: u64,
    ) -> impl std::future::Future<Output = Result<(Self, bool, Removal), Error>> + Send {
        async move {
            let (journal, pruned) = self.prune_after(min_position, None).await?;
            let removals = journal.removals();
            Ok((journal, pruned, removals))
        }
    }

    /// A [Removal] that completes once the storage released by every earlier prune is deleted.
    fn removals(&self) -> Removal;

    /// Begin durably persisting the current state of the journal.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit]
    /// for the state present when the call begins (later appends need their own sync). Also
    /// tries to advance the recovery watermark to the previous proven durable size, bounding
    /// startup recovery. Use [Self::sync] to guarantee no recovery is needed. Dropping the
    /// handle does not cancel the sync or lose its failure, which resurfaces at latest on the
    /// next [Self::sync].
    fn start_sync(
        self,
    ) -> impl std::future::Future<Output = Result<(Self, Handle<()>), Error>> + Send;

    /// Durably persist the journal, guaranteeing the current state will survive a crash.
    ///
    /// For a stronger guarantee that eliminates potential recovery, use [Self::sync] instead.
    fn commit(self) -> impl std::future::Future<Output = Result<Self, Error>> + Send;

    /// Durably persist the journal, guaranteeing the current state will survive a crash, and that
    /// no recovery will be needed on startup.
    ///
    /// This provides a stronger guarantee than [Self::commit] but may be slower.
    fn sync(self) -> impl std::future::Future<Output = Result<Self, Error>> + Send;

    /// Destroy the journal, removing all associated storage.
    ///
    /// This method consumes the journal and deletes all persisted data, leaving behind no storage
    /// artifacts. This can be used to clean up disk resources in tests.
    ///
    /// # Crash Safety
    ///
    /// This operation is intended for final teardown and is not crash-safe. If interrupted,
    /// reopening the same storage may observe partially removed state. Use a reset operation
    /// provided by the concrete type when the journal must remain recoverable.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;
}
