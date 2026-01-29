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
pub mod variable;

#[cfg(test)]
mod tests;

/// Core trait for contiguous journals supporting sequential append operations.
///
/// A contiguous journal maintains a consecutively increasing position counter where each
/// appended item receives a unique position starting from 0.
pub trait Contiguous: Send + Sync {
    /// The type of items stored in the journal.
    type Item;

    /// Returns [start, end) where `start` and `end - 1` are the indices of the oldest and newest
    /// retained operations respectively.
    fn bounds(&self) -> Range<u64>;

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value.
    ///
    /// Equivalent to `bounds().end`.
    fn size(&self) -> u64 {
        self.bounds().end
    }

    /// Return a stream of all items in the journal starting from `start_pos`.
    ///
    /// Each item is yielded as a tuple `(position, item)` where position is the item's
    /// stable position in the journal.
    ///
    /// # Errors
    ///
    /// Returns an error if `start_pos` exceeds the journal size or if any storage/decoding
    /// errors occur during replay.
    fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> impl std::future::Future<
        Output = Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + Send + '_, Error>,
    > + Send;

    /// Read the item at the given position.
    ///
    /// # Errors
    ///
    /// - Returns [Error::ItemPruned] if the item at `position` has been pruned.
    /// - Returns [Error::ItemOutOfRange] if the item at `position` does not exist.
    fn read(&self, position: u64) -> impl Future<Output = Result<Self::Item, Error>> + Send;
}

/// A [Contiguous] journal that supports appending, rewinding, and pruning.
pub trait MutableContiguous: Contiguous + Send + Sync {
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
        item: Self::Item,
    ) -> impl std::future::Future<Output = Result<u64, Error>> + Send;

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
