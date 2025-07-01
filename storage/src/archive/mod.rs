//! A write-once key-value store where each key is associated with a unique index.
//!
//! [Archive] is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`.

use commonware_codec::Codec;
use commonware_utils::Array;
use std::future::Future;
use thiserror::Error;

pub mod fast;

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, K: Array> {
    Index(u64),
    Key(&'a K),
}

/// Errors that can occur when interacting with the archive.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("already pruned to: {0}")]
    AlreadyPrunedTo(u64),
    #[error("record too large")]
    RecordTooLarge,
}

/// A write-once key-value store where each key is associated with a unique index.
pub trait Archive {
    /// The type of the key.
    type Key: Array;

    /// The type of the value.
    type Value: Codec;

    /// Store an item in [Archive]. Both indices and keys are assumed to both be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    fn put(
        &mut self,
        index: u64,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Error>>;

    /// Retrieve an item from [Archive].
    fn get(
        &self,
        identifier: Identifier<'_, Self::Key>,
    ) -> impl Future<Output = Result<Option<Self::Value>, Error>>;

    /// Check if an item exists in [Archive].
    fn has(
        &self,
        identifier: Identifier<'_, Self::Key>,
    ) -> impl Future<Output = Result<bool, Error>>;

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the archive.
    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>);

    /// Sync all pending writes.
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Prune the to the minimum index.
    fn prune(&mut self, min: u64) -> impl Future<Output = Result<(), Error>>;

    /// Close [Archive] (and underlying storage).
    ///
    /// Any pending writes are synced prior to closing.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Remove all persistent data created by this [Archive].
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}
