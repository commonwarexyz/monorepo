//! Support for batching changes to an underlying k/v store.

use crate::{
    kv::{Store, StoreDeletable, StoreMut},
    qmdb::Error,
};
use commonware_codec::Codec;
use commonware_utils::Array;
use core::future::Future;
use std::collections::BTreeMap;

/// A batch of changes which may be written to an underlying store with [Batchable::write_batch].
/// Writes and deletes to a batch are not applied to the store until the batch is written but
/// will be reflected in reads from the batch.
pub struct Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Store<Key = K, Value = V, Error = Error>,
{
    /// The underlying database.
    db: &'a D,
    /// The diff of changes to the database.
    ///
    /// If the value is Some, the key is being created or updated.
    /// If the value is None, the key is being deleted.
    ///
    /// We use a BTreeMap instead of HashMap to allow for a deterministic iteration order.
    diff: BTreeMap<K, Option<V>>,
}

impl<'a, K, V, D> Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Store<Key = K, Value = V, Error = Error>,
{
    /// Returns a new batch of changes that may be written to the store.
    pub const fn new(db: &'a D) -> Self {
        Self {
            db,
            diff: BTreeMap::new(),
        }
    }

    /// Deletes `key` from the batch without checking if it is present in the batch or database.
    pub async fn delete_unchecked(&mut self, key: K) -> Result<(), Error> {
        self.diff.insert(key, None);

        Ok(())
    }
}

impl<'a, K, V, D> Store for Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Store<Key = K, Value = V, Error = Error>,
{
    type Key = K;
    type Value = V;
    type Error = Error;

    /// Returns the value of `key` in the batch, or the value in the database if it is not present
    /// in the batch.
    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        if let Some(value) = self.diff.get(key) {
            return Ok(value.clone());
        }

        self.db.get(key).await
    }
}

impl<'a, K, V, D> StoreMut for Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Store<Key = K, Value = V, Error = Error>,
{
    /// Updates the value of `key` to `value` in the batch.
    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.diff.insert(key, Some(value));

        Ok(())
    }

    /// Creates a new key-value pair in the batch if it isn't present in the batch or database.
    /// Returns true if the key was created, false if it already existed.
    async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
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
}

impl<'a, K, V, D> StoreDeletable for Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Store<Key = K, Value = V, Error = Error>,
{
    /// Deletes `key` from the batch.
    /// Returns true if the key was in the batch or database, false otherwise.
    async fn delete(&mut self, key: K) -> Result<bool, Error> {
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
}

impl<'a, K, V, D> IntoIterator for Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Store<Key = K, Value = V, Error = Error>,
{
    type Item = (K, Option<V>);
    type IntoIter = std::collections::btree_map::IntoIter<K, Option<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.diff.into_iter()
    }
}

/// A database that supports making batched changes.
pub trait Batchable: Store<Key: Array, Value: Codec + Clone, Error = Error> {
    /// Returns a new empty batch of changes.
    fn start_batch(&self) -> Batch<'_, Self::Key, Self::Value, Self>
    where
        Self: Sized,
    {
        Batch {
            db: self,
            diff: BTreeMap::new(),
        }
    }

    /// Writes a batch of changes to the database.
    fn write_batch(
        &mut self,
        iter: impl Iterator<Item = (Self::Key, Option<Self::Value>)>,
    ) -> impl Future<Output = Result<(), Error>>;
}
