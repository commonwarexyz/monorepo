//! Traits for interacting with a storage system.

use std::future::Future;

/// A read-only key-value store.
pub trait Store {
    type Key;
    type Value;
    type Error;

    /// Get the value for a given key.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>>;
}

/// A mutable key-value store that supports setting values.
pub trait StoreMut: Store {
    /// Set the value for a given key.
    fn set(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

/// A mutable key-value store that supports deleting values.
pub trait StoreDelete: StoreMut {
    /// Delete the value for a given key.
    ///
    /// Returns `true` if the key existed and was deleted, `false` if it did not exist.
    fn delete(&mut self, key: Self::Key) -> impl Future<Output = Result<bool, Self::Error>>;
}
