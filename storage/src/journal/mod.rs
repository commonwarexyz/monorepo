//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use futures::Stream;
use std::num::NonZeroUsize;
use thiserror::Error;

pub mod contiguous;
pub mod segmented;

#[cfg(test)]
mod tests;

/// Core trait for journals supporting sequential append operations.
///
/// A journal maintains a consecutively increasing position counter where each
/// appended item receives a unique position starting from 0.
pub trait Journal {
    /// The type of items stored in the journal.
    type Item;

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

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value.
    fn size(&self) -> impl std::future::Future<Output = Result<u64, Error>> + Send;

    /// Return the position of the oldest item still retained in the journal.
    ///
    /// Returns `None` if the journal is empty or if all items have been pruned.
    ///
    /// After pruning, this returns the position of the first item that remains.
    /// Note that due to section/blob alignment, this may be less than the `min_position`
    /// passed to `prune()`.
    fn oldest_retained_pos(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Error>> + Send;

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Behavior
    ///
    /// - If `min_position > size()`, the prune is capped to `size()` (no error is returned)
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
    /// After rewinding to size N, the journal will contain exactly N items
    /// (positions 0 to N-1), and the next append will receive position N.
    ///
    /// # Behavior
    ///
    /// - If `size > current_size()`, returns [Error::InvalidRewind]
    /// - If `size == current_size()`, this is a no-op
    /// - If `size < oldest_retained_pos()`, returns [Error::InvalidRewind] (can't rewind to pruned data)
    /// - This operation is not atomic, but implementations guarantee the journal is left in a
    ///   recoverable state if a crash occurs during rewinding
    ///
    /// # Warnings
    ///
    /// - This operation is not guaranteed to survive restarts until `sync()` is called
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if size is invalid (too large or points to pruned data).
    /// Returns an error if the underlying storage operation fails.
    fn rewind(&mut self, size: u64) -> impl std::future::Future<Output = Result<(), Error>> + Send;

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
        Output = Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + '_, Error>,
    > + Send;

    /// Read the item at the given position.
    ///
    /// # Errors
    ///
    /// - Returns [Error::ItemPruned] if the item at `position` has been pruned.
    /// - Returns [Error::ItemOutOfRange] if the item at `position` does not exist.
    fn read(
        &self,
        position: u64,
    ) -> impl std::future::Future<Output = Result<Self::Item, Error>> + Send;

    /// Sync all pending writes to storage.
    ///
    /// This ensures all previously appended items are durably persisted.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Close the journal, syncing all pending writes and releasing resources.
    fn close(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Destroy the journal, removing all associated storage.
    ///
    /// This method consumes the journal and deletes all persisted data including blobs,
    /// metadata, and any other storage artifacts. Use this for cleanup in tests or when
    /// permanently removing a journal.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;
}

impl<E, Op> crate::adb::sync::Journal for contiguous::fixed::Journal<E, Op>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    Op: commonware_codec::Codec<Cfg = ()> + commonware_codec::FixedSize + Send + 'static,
{
    type Op = Op;
    type Error = Error;

    async fn size(&self) -> Result<u64, Self::Error> {
        contiguous::fixed::Journal::size(self).await
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        contiguous::fixed::Journal::append(self, op)
            .await
            .map(|_| ())
    }
}

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("invalid blob size: index={0} size={1}")]
    InvalidBlobSize(u64, u64),
    #[error("checksum mismatch: expected={0} actual={1}")]
    ChecksumMismatch(u32, u32),
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
    #[error("already pruned to section: {0}")]
    AlreadyPrunedToSection(u64),
    #[error("section out of range: {0}")]
    SectionOutOfRange(u64),
    #[error("usize too small")]
    UsizeTooSmall,
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("unexpected size: expected={0} actual={1}")]
    UnexpectedSize(u32, u32),
    #[error("missing blob: {0}")]
    MissingBlob(u64),
    #[error("item out of range: {0}")]
    ItemOutOfRange(u64),
    #[error("item pruned: {0}")]
    ItemPruned(u64),
    #[error("invalid rewind: {0}")]
    InvalidRewind(u64),
    #[error("compression failed")]
    CompressionFailed,
    #[error("decompression failed")]
    DecompressionFailed,
    #[error("corruption detected: {0}")]
    Corruption(String),
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
}
