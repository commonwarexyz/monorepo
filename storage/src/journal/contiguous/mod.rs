//! Contiguous journals with position-based access.
//!
//! This module provides position-based journal implementations where items are stored
//! contiguously and can be accessed by their position (0-indexed). Both [fixed]-size and
//! [variable]-size item journals are supported.
//!
//! Storage errors from mutable operations are considered fatal for the current handle and may
//! leave its in-memory state inconsistent with the underlying storage.

use super::Error;
use futures::{stream, Stream};
use std::{collections::VecDeque, future::Future, num::NonZeroUsize, ops::Range};
use tracing::warn;

mod blobs;
mod checkpoint;
pub mod fixed;
mod metrics;
pub mod variable;

#[cfg(test)]
mod tests;

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

/// Per-blob replay state that yields decoded item batches.
trait ReplayBatchState: Sized {
    /// The decoded item type.
    type Item;

    /// Decode the next batch from this blob state.
    fn next_batch(
        self,
    ) -> impl Future<Output = Option<(Vec<Result<(u64, Self::Item), Error>>, Self)>> + Send;
}

/// Stream driver over per-blob replay states.
struct ReplayStreamState<S: ReplayBatchState> {
    /// Remaining blob states, in ascending blob order.
    states: std::vec::IntoIter<S>,
    /// State currently being drained.
    current: Option<S>,
    /// Items decoded from the current state but not yet yielded by the stream.
    pending: VecDeque<Result<(u64, S::Item), Error>>,
    /// Set after the first error so the stream terminates cleanly.
    done: bool,
}

impl<S: ReplayBatchState + Send> ReplayStreamState<S>
where
    S::Item: Send,
{
    /// Yield one item, filling `pending` from the current blob when needed.
    async fn next(mut self) -> Option<(Result<(u64, S::Item), Error>, Self)> {
        loop {
            if self.done {
                return None;
            }

            if let Some(item) = self.pending.pop_front() {
                if item.is_err() {
                    self.done = true;
                    self.pending.clear();
                    self.current = None;
                }
                return Some((item, self));
            }

            let state = match self.current.take().or_else(|| self.states.next()) {
                Some(state) => state,
                None => return None,
            };

            match state.next_batch().await {
                Some((batch, state)) => {
                    self.current = Some(state);
                    self.pending = VecDeque::from(batch);
                }
                None => {
                    self.current = None;
                }
            }
        }
    }
}

/// Build a stream from per-blob replay states.
fn replay_stream_from_states<S>(
    states: Vec<S>,
) -> impl Stream<Item = Result<(u64, S::Item), Error>> + Send
where
    S: ReplayBatchState + Send,
    S::Item: Send,
{
    stream::unfold(
        ReplayStreamState {
            states: states.into_iter(),
            current: None,
            pending: VecDeque::new(),
            done: false,
        },
        ReplayStreamState::next,
    )
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
    /// The default implementation calls [`read`](Self::read) in a loop. Concrete journal
    /// implementations override this to batch I/O.
    fn read_many(
        &self,
        positions: &[u64],
    ) -> impl Future<Output = Result<Vec<Self::Item>, Error>> + Send
    where
        Self::Item: Send,
    {
        async move {
            let mut items = Vec::with_capacity(positions.len());
            for &pos in positions {
                items.push(self.read(pos).await?);
            }
            Ok(items)
        }
    }

    /// Read an item if it can be done synchronously (e.g. without I/O), returning `None` otherwise.
    ///
    /// Default implementation always returns `None`.
    fn try_read_sync(&self, _position: u64) -> Option<Self::Item> {
        None
    }

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
    /// The default implementation calls [Self::append] in a loop. Concrete implementations
    /// may override this to encode and write all items in one batch.
    ///
    /// Returns [Error::EmptyAppend] if items is empty.
    fn append_many<'a>(
        &'a mut self,
        items: Many<'a, Self::Item>,
    ) -> impl std::future::Future<Output = Result<u64, Error>> + Send + 'a
    where
        Self::Item: Sync,
    {
        async move {
            if items.is_empty() {
                return Err(Error::EmptyAppend);
            }
            let mut last_pos = self.bounds().end;
            match items {
                Many::Flat(items) => {
                    for item in items {
                        last_pos = self.append(item).await?;
                    }
                }
                Many::Nested(nested_items) => {
                    for items in nested_items {
                        for item in *items {
                            last_pos = self.append(item).await?;
                        }
                    }
                }
            }
            Ok(last_pos)
        }
    }

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Behavior
    ///
    /// - If `min_position > bounds.end`, the prune is capped to `bounds.end` (no error is returned)
    /// - Some items with positions less than `min_position` may be retained due to
    ///   section/blob alignment
    /// - This operation is not atomic, but implementations guarantee the journal is left in a
    ///   recoverable state if a crash occurs during pruning
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
    /// - This operation is not guaranteed to survive restarts until `commit` or `sync` is called.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if `size` is beyond the current size, or [Error::ItemPruned]
    /// if it precedes the pruning boundary. Returns an error if the underlying storage operation
    /// fails.
    fn rewind(&mut self, size: u64) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Durably persist the journal, guaranteeing the current state will survive a crash.
    ///
    /// For a stronger guarantee that eliminates potential recovery, use [Self::sync] instead.
    fn commit(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send {
        self.sync()
    }

    /// Durably persist the journal, guaranteeing the current state will survive a crash, and that
    /// no recovery will be needed on startup.
    ///
    /// This provides a stronger guarantee than [Self::commit] but may be slower.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

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
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send
    where
        Self: Sized;

    /// Rewinds the journal to the last item matching `predicate`. If no item matches, the journal
    /// is rewound to the pruning boundary, discarding all unpruned items.
    ///
    /// # Warnings
    ///
    /// - This operation is not guaranteed to survive restarts until `commit` or `sync` is called.
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
