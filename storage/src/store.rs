//! Traits for interacting with a storage system.

use std::future::Future;

/// A read-only key-value store.
pub trait Store {
    type Key;
    type Value;
    type Error;

    /// Get the value of a key.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>>;
}

/// A mutable key-value store.
pub trait StoreMut: Store {
    /// Update the value of a key.
    fn update(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

/// A mutable key-value store that supports deleting values.
pub trait StoreDeletable: StoreMut {
    /// Delete the value of a key.
    ///
    /// Returns `true` if the key existed and was deleted, `false` if it did not exist.
    fn delete(&mut self, key: Self::Key) -> impl Future<Output = Result<bool, Self::Error>>;
}

/// A mutable key-value store that can be persisted.
pub trait StorePersistable: StoreMut {
    /// Commit the store to disk, ensuring all changes are durably persisted.
    fn commit(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Destroy the store, removing all persisted data.
    fn destroy(self) -> impl Future<Output = Result<(), Self::Error>>;
}
