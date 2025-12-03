//! Traits for interacting with a storage system.

use crate::mmr::Location;
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

    /// Updates the value associated with the given key in the store, inserting a default value if
    /// the key does not already exist.
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

            self.set(key, value).await
        }
    }

    /// Creates a new key-value pair in the db.
    /// Returns true if the key was created, false if it already existed.
    fn create(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<bool, Self::Error>> {
        async {
            if self.get(&key).await?.is_some() {
                return Ok(false);
            }

            self.set(key, value).await?;
            Ok(true)
        }
    }
}

/// A mutable key-value store that supports deleting values.
pub trait StoreDeletable: StoreMut {
    /// Delete the value for a given key.
    ///
    /// Returns `true` if the key existed and was deleted, `false` if it did not exist.
    fn delete(&mut self, key: Self::Key) -> impl Future<Output = Result<bool, Self::Error>>;
}

pub trait StoreCommittable: StoreMut {
    /// Commit operations performed since the last commit.
    fn commit(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
}

pub trait StoreDestructible: StoreDeletable {
    /// Destroy the database, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Self::Error>>;
}

pub trait StorePrunable: StoreMut {
    /// Prune operations
    fn prune(&mut self, prune_loc: Location) -> impl Future<Output = Result<(), Self::Error>>;
}
