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
    ///
    /// Note: The returned future is not required to be Send due to Rust limitation #100013
    /// with borrowed parameters in async trait methods.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>>;
}

/// A mutable key-value store.
pub trait Updatable: Gettable {
    /// Update the value of a key.
    fn update(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Updates the value associated with the given key in the store, inserting a default value if
    /// the key does not already exist.
    ///
    /// Note: The returned future is not Send because it calls `get` internally.
    fn upsert(
        &mut self,
        key: Self::Key,
        update: impl FnOnce(&mut Self::Value),
    ) -> impl Future<Output = Result<(), Self::Error>>
    where
        Self::Value: Default,
    {
        async {
            let mut value = self.get(&key).await?.unwrap_or_default();
            update(&mut value);

            self.update(key, value).await
        }
    }

    /// Creates a new key-value pair in the db. Returns true if the key was created, false if it
    /// already existed. The key is not modified if it already existed.
    ///
    /// Note: The returned future is not Send because it calls `get` internally.
    fn create(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<bool, Self::Error>> {
        async {
            if self.get(&key).await?.is_some() {
                return Ok(false);
            }

            self.update(key, value).await?;
            Ok(true)
        }
    }
}

/// A mutable key-value store that supports deleting values.
pub trait Deletable: Updatable {
    /// Delete the value of a key.
    ///
    /// Returns `true` if the key existed and was deleted, `false` if it did not exist.
    ///
    /// Note: The returned future is not required to be Send because some implementations
    /// (like Batch) may need to call `get` internally.
    fn delete(&mut self, key: Self::Key) -> impl Future<Output = Result<bool, Self::Error>>;
}
