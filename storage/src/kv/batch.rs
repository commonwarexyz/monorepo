//! Support for batching changes to an underlying key-value store.

use super::{Deletable, Gettable, Updatable};
use crate::qmdb::Error;
use commonware_codec::CodecShared;
use commonware_utils::Array;
use std::{collections::BTreeMap, future::Future};

/// A batch of changes which may be written to an underlying store with [Batchable::write_batch].
/// Writes and deletes to a batch are not applied to the store until the batch is written but
/// will be reflected in reads from the batch.
pub struct Batch<'a, K, V, D>
where
    K: Array,
    V: CodecShared + Clone,
    D: Gettable<Key = K, Value = V, Error = Error> + Sync,
{
    /// The underlying k/v store.
    db: &'a D,
    /// The diff of changes to the store.
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
    V: CodecShared + Clone,
    D: Gettable<Key = K, Value = V, Error = Error> + Sync,
{
    /// Returns a new batch of changes that may be written to the store.
    pub const fn new(db: &'a D) -> Self {
        Self {
            db,
            diff: BTreeMap::new(),
        }
    }

    /// Deletes `key` from the batch without checking if it is present in the batch or store.
    pub async fn delete_unchecked(&mut self, key: K) -> Result<(), Error> {
        self.diff.insert(key, None);

        Ok(())
    }
}

impl<'a, K, V, D> Gettable for Batch<'a, K, V, D>
where
    K: Array,
    V: CodecShared + Clone,
    D: Gettable<Key = K, Value = V, Error = Error> + Sync,
{
    type Key = K;
    type Value = V;
    type Error = Error;

    /// Returns the value of `key` in the batch, or the value in the store if it is not present
    /// in the batch.
    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        if let Some(value) = self.diff.get(key) {
            return Ok(value.clone());
        }

        self.db.get(key).await
    }
}

impl<'a, K, V, D> Updatable for Batch<'a, K, V, D>
where
    K: Array,
    V: CodecShared + Clone,
    D: Gettable<Key = K, Value = V, Error = Error> + Sync,
{
    /// Updates the value of `key` to `value` in the batch.
    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.diff.insert(key, Some(value));

        Ok(())
    }
}

impl<'a, K, V, D> Deletable for Batch<'a, K, V, D>
where
    K: Array,
    V: CodecShared + Clone,
    D: Gettable<Key = K, Value = V, Error = Error> + Sync,
{
    /// Deletes `key` from the batch.
    /// Returns true if the key was in the batch or store, false otherwise.
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
    V: CodecShared + Clone,
    D: Gettable<Key = K, Value = V, Error = Error> + Sync,
{
    type Item = (K, Option<V>);
    type IntoIter = std::collections::btree_map::IntoIter<K, Option<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.diff.into_iter()
    }
}

/// A k/v store that supports making batched changes.
pub trait Batchable:
    Gettable<Key: Array, Value: CodecShared + Clone, Error = Error> + Updatable + Deletable
{
    /// Returns a new empty batch of changes.
    fn start_batch(&self) -> Batch<'_, Self::Key, Self::Value, Self>
    where
        Self: Sized + Sync,
        Self::Value: Send + Sync,
    {
        Batch {
            db: self,
            diff: BTreeMap::new(),
        }
    }

    /// Writes a batch of changes to the store.
    fn write_batch<'a, Iter>(
        &'a mut self,
        iter: Iter,
    ) -> impl Future<Output = Result<(), Error>> + Send + use<'a, Self, Iter>
    where
        Self: Send,
        Iter: Iterator<Item = (Self::Key, Option<Self::Value>)> + Send + 'a,
    {
        async move {
            for (key, value) in iter {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kv::tests::{assert_deletable, assert_gettable, assert_send, assert_updatable},
        qmdb::store::db::Db,
        translator::TwoCap,
    };
    use commonware_cryptography::sha256::Digest;
    use commonware_runtime::deterministic::Context;

    type TestStore = Db<Context, Digest, Vec<u8>, TwoCap>;
    type TestBatch<'a> = Batch<'a, Digest, Vec<u8>, TestStore>;

    #[allow(dead_code)]
    fn assert_batch_futures_are_send(batch: &mut TestBatch<'_>, key: Digest) {
        assert_gettable(batch, &key);
        assert_updatable(batch, key, vec![]);
        assert_deletable(batch, key);
    }

    #[allow(dead_code)]
    fn assert_batch_delete_unchecked_is_send(batch: &mut TestBatch<'_>, key: Digest) {
        assert_send(batch.delete_unchecked(key));
    }
}
