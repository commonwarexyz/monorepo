//! Traits for interacting with a key/value store.

mod batch;
pub use batch::{Batch, Batchable};
use std::future::Future;

/// A readable key-value store.
pub trait Gettable {
    type Key: Send + Sync;
    type Value: Send + Sync;
    type Error;

    /// Get the value of a key.
    fn get<'a>(
        &'a self,
        key: &'a Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>> + Send + use<'a, Self>;
}

/// A mutable key-value store.
pub trait Updatable: Gettable {
    /// Update the value of a key.
    fn update<'a>(
        &'a mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + use<'a, Self>;

    /// Creates a new key-value pair in the db. Returns true if the key was created, false if it
    /// already existed. The key is not modified if it already existed.
    fn create<'a>(
        &'a mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + use<'a, Self>;
}

/// A mutable key-value store that supports deleting values.
pub trait Deletable: Updatable {
    /// Delete the value of a key.
    ///
    /// Returns `true` if the key existed and was deleted, `false` if it did not exist.
    fn delete<'a>(
        &'a mut self,
        key: Self::Key,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + use<'a, Self>;
}
