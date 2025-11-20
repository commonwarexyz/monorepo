//! Support for batching changes to an underlying database.

use crate::adb::{store::Db, Error};
use commonware_codec::Codec;
use commonware_utils::Array;
use core::future::Future;
use std::collections::HashMap;

/// A trait for getting values from a database.
pub trait Getter<K, V> {
    /// Get the value of `key` from the database.
    fn get(&self, key: &K) -> impl Future<Output = Result<Option<V>, Error>>;
}

/// All databases implement the [Getter] trait.
impl<K, V, D> Getter<K, V> for D
where
    K: Array,
    V: Codec + Clone,
    D: Db<K, V>,
{
    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }
}

/// A batch of changes which may be written to an underlying database.
pub struct Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Getter<K, V>,
{
    /// The underlying database.
    db: &'a D,
    /// The diff of changes to the database.
    ///
    /// If the value is Some, the key is being created or updated.
    /// If the value is None, the key is being deleted.
    diff: HashMap<K, Option<V>>,
}

impl<'a, K, V, D> Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Getter<K, V>,
{
    /// Returns a new batch of changes that may be written to the database.
    pub fn new(db: &'a D) -> Self {
        Self {
            db,
            diff: HashMap::new(),
        }
    }

    /// Returns the value of `key` in the batch, or the value in the database if it is not present
    /// in the batch.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        if let Some(value) = self.diff.get(key) {
            return Ok(value.clone());
        }

        self.db.get(key).await
    }

    /// Creates a new key-value pair in the batch if it isn't present in the batch or database.
    /// Returns true if the key was created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        if let Some(value_opt) = self.diff.get_mut(&key) {
            match value_opt {
                Some(_) => return Ok(false),
                None => {
                    *value_opt = Some(value);
                    return Ok(true);
                }
            }
        }

        if self.db.get(&key).await?.is_some() {
            return Ok(false);
        }

        self.diff.insert(key, Some(value));
        Ok(true)
    }

    /// Updates the value of `key` to `value` in the batch.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.diff.insert(key, Some(value));

        Ok(())
    }

    /// Deletes `key` from the batch.
    /// Returns true if the key was in the batch or database, false otherwise.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        if let Some(entry) = self.diff.get_mut(&key) {
            match entry {
                Some(_) => {
                    *entry = None;
                    return Ok(true);
                }
                None => return Ok(false),
            }
        }

        if self.db.get(&key).await?.is_some() {
            self.diff.insert(key, None);
            return Ok(true);
        }

        Ok(false)
    }

    /// Deletes `key` from the batch without checking if it is present in the batch or database.
    pub async fn delete_unchecked(&mut self, key: K) -> Result<(), Error> {
        self.diff.insert(key, None);

        Ok(())
    }
}

/// A database that supports making batched changes.
pub trait Batchable<K: Array, V: Codec + Clone>: Db<K, V> {
    /// Returns a new empty batch of changes.
    fn start_batch(&self) -> Batch<'_, K, V, Self>
    where
        Self: Sized,
    {
        Batch {
            db: self,
            diff: HashMap::new(),
        }
    }

    /// Writes a batch of changes to the database.
    fn write_batch(
        &mut self,
        batch: Batch<'_, K, V, Self>,
    ) -> impl Future<Output = Result<(), Error>>
    where
        Self: Sized,
    {
        async {
            for (key, value) in batch.diff {
                if let Some(value) = value {
                    self.update(key, value).await?;
                } else {
                    self.delete(key).await?;
                }
            }
            Ok(())
        }
    }
}

/// Default implementation of [Batchable] for all databases.
impl<K, V, D> Batchable<K, V> for D
where
    K: Array,
    V: Codec + Clone,
    D: Db<K, V>,
{
}
