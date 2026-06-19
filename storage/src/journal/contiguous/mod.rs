//! Contiguous journals with position-based access.
//!
//! This module provides position-based journal implementations where items are stored
//! contiguously and can be accessed by their position (0-indexed). Both [fixed]-size and
//! [variable]-size item journals are supported.

use super::Error;
use futures::Stream;
use std::{future::Future, num::NonZeroUsize, ops::Range};

mod blobs;
mod checkpoint;
pub mod fixed;
mod metrics;
mod replay;
pub mod variable;

#[cfg(test)]
mod tests;

/// A consistent view of the journal.
///
/// Bounds are stable for the reader's lifetime, and every position within `bounds()` stays
/// readable through it, even if the journal prunes those items afterward. A reader never
/// observes appends made after it was created.
///
/// A rewind below `bounds().end` would mutate bytes a reader can still see, so the journal
/// refuses it while any reader is alive (the rewind returns an error); it never proceeds and
/// leaves a reader observing changed data.
pub trait Reader: Send + Sync {
    /// The type of items stored in the journal.
    type Item;

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

    /// Return a stream of all items starting from `start_pos`, bounded by the reader's `bounds()`.
    fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> impl Future<
        Output = Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + Send, Error>,
    > + Send;
}

/// Reader factories for contiguous journals.
///
/// Implementations produce stable [`Reader`] snapshots that can be used independently of the
/// writer.
pub trait Contiguous: Send + Sync {
    /// The type of items stored in the journal.
    type Item;

    /// Acquire a reader that holds a consistent view of the journal.
    ///
    /// Any position within `reader.bounds()` remains readable for the
    /// reader's lifetime (see [Reader]).
    fn reader(&self) -> impl Future<Output = impl Reader<Item = Self::Item> + '_> + Send;

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value. Equivalent to [`Reader::bounds`]`.end`.
    fn size(&self) -> impl Future<Output = u64> + Send;
}

/// Items to append via [`Mutable::append_many`].
///
/// `Flat` wraps a single contiguous slice; `Nested` wraps multiple slices that are
/// appended in order under a single lock acquisition.
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

/// Writer side of a contiguous journal.
///
/// Maintains a monotonically increasing position counter where each appended item receives a
/// unique position starting from 0.
pub trait Mutable: Send + Sync {
    /// The type of items stored in the journal.
    type Item;

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value.
    fn size(&self) -> impl Future<Output = u64> + Send;

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
            let mut last_pos = self.size().await;
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
}
