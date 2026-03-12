//! Contiguous journals with position-based access.
//!
//! This module provides position-based journal implementations where items are stored
//! contiguously and can be accessed by their position (0-indexed). Both [fixed]-size and
//! [variable]-size item journals are supported.

use super::Error;
use futures::Stream;
use std::{future::Future, num::NonZeroUsize, ops::Range};
use tracing::warn;

pub mod fixed;
mod metrics;
pub mod variable;

#[cfg(test)]
mod tests;

/// A reader guard that holds a consistent view of the journal.
///
/// While this guard exists, operations that may modify the bounds (such as `append`, `prune`, and
/// `rewind`) will block until the guard is dropped. This keeps bounds stable, so any position
/// within `bounds()` is guaranteed readable.
//
// TODO(<https://github.com/commonwarexyz/monorepo/issues/3084>): Relax locking to allow `append`
// since it doesn't invalidate reads within the cached bounds.
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
    /// implementations override this to amortize lock acquisition and batch I/O.
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

    /// Return a stream of all items starting from `start_pos`.
    ///
    /// Because the reader holds the lock, validation and stream setup happen
    /// atomically with respect to `prune()`.
    fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> impl Future<
        Output = Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + Send, Error>,
    > + Send;
}

/// Journals that support sequential append operations.
///
/// Maintains a monotonically increasing position counter where each appended item receives a unique
/// position starting from 0.
pub trait Contiguous: Send + Sync {
    /// The type of items stored in the journal.
    type Item;

    /// Acquire a reader guard that holds a consistent view of the journal.
    ///
    /// While the returned guard exists, operations that need the journal's
    /// internal write lock (such as `append`, `prune`, and `rewind`) may block
    /// until the guard is dropped. This ensures any position within
    /// `reader.bounds()` remains readable.
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
    /// may override this to acquire the write lock once for all items.
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
    /// Returns [Error::InvalidRewind] if size is invalid (too large or points to pruned data).
    /// Returns an error if the underlying storage operation fails.
    fn rewind(&mut self, size: u64) -> impl std::future::Future<Output = Result<(), Error>> + Send;

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
            let (bounds, rewind_size) = {
                let reader = self.reader().await;
                let bounds = reader.bounds();
                let mut rewind_size = bounds.end;

                while rewind_size > bounds.start {
                    let item = reader.read(rewind_size - 1).await?;
                    if predicate(&item) {
                        break;
                    }
                    rewind_size -= 1;
                }

                (bounds, rewind_size)
            };

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
