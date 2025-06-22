//! A write-once key-value store where each key is associated with a unique index.
//!
//! [Archive] is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`. This is useful for storing ordered data either
//! [for a limited time](crate::archive::prunable) or [indefinitely](crate::archive::immutable).

use crate::identifier::Identifier;
use commonware_codec::Codec;
use commonware_utils::Array;
use std::future::Future;

pub mod immutable;
pub mod prunable;

/// A write-once key-value store where each key is associated with a unique index.
pub trait Archive {
    /// The type of the index.
    type Index;

    /// The type of the key.
    type Key: Array;

    /// The type of the value.
    type Value: Codec;

    /// The type of the error.
    type Error: std::error::Error;

    /// Store an item in [Archive]. Both indices and keys are assumed to both be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    fn put(
        &mut self,
        index: Self::Index,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Retrieve an item from [Archive].
    fn get(
        &self,
        identifier: Identifier<'_, Self::Index, Self::Key>,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>>;

    /// Check if an item exists in [Archive].
    fn has(
        &self,
        identifier: Identifier<'_, Self::Index, Self::Key>,
    ) -> impl Future<Output = Result<bool, Self::Error>>;

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the archive.
    #[allow(clippy::type_complexity)]
    fn next_gap(
        &self,
        index: Self::Index,
    ) -> impl Future<Output = Result<(Option<Self::Index>, Option<Self::Index>), Self::Error>>;

    /// Sync all pending writes.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Close [Archive] (and underlying storage).
    ///
    /// Any pending writes are synced prior to closing.
    fn close(self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Remove all persistent data created by this [Archive].
    fn destroy(self) -> impl Future<Output = Result<(), Self::Error>>;
}
