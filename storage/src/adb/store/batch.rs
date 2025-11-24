//! Support for batching changes to an underlying database.

use crate::adb::{store::Db, Error};
use commonware_codec::Codec;
use commonware_utils::Array;
use core::future::Future;
use std::collections::HashMap;

/// A trait for getting values from a keyed database.
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

/// A batch of changes which may be written to an underlying database with [Batchable::write_batch].
/// Writes and deletes to a batch are not applied to the database until the batch is written but
/// will be reflected in reads from the batch.
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

impl<'a, K, V, D> IntoIterator for Batch<'a, K, V, D>
where
    K: Array,
    V: Codec + Clone,
    D: Getter<K, V>,
{
    type Item = (K, Option<V>);
    type IntoIter = std::collections::hash_map::IntoIter<K, Option<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.diff.into_iter()
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
        iter: impl Iterator<Item = (K, Option<V>)>,
    ) -> impl Future<Output = Result<(), Error>> {
        async {
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

/// Default implementation of [Batchable] for all databases.
impl<K, V, D> Batchable<K, V> for D
where
    K: Array,
    V: Codec + Clone,
    D: Db<K, V>,
{
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use commonware_cryptography::{blake3, sha256};
    use core::{fmt::Debug, future::Future};

    pub trait TestKey: Array {
        fn from_seed(seed: u8) -> Self;
    }

    pub trait TestValue: Codec + Clone + PartialEq + Debug {
        fn from_seed(seed: u8) -> Self;
    }

    /// Run the shared batch test suite against a database factory.
    pub async fn run_batch_tests<K, V, D, F, Fut>(mut new_db: F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable<K, V>,
        K: TestKey,
        V: TestValue,
    {
        test_overlay_reads(&mut new_db).await?;
        test_create(&mut new_db).await?;
        test_delete(&mut new_db).await?;
        test_delete_unchecked(&mut new_db).await?;
        test_write_batch(&mut new_db).await?;
        Ok(())
    }

    async fn test_overlay_reads<K, V, D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable<K, V>,
        K: TestKey,
        V: TestValue,
    {
        let mut db = new_db().await;
        let key = K::from_seed(1);
        db.update(key.clone(), V::from_seed(1)).await?;

        let mut batch = db.start_batch();
        assert_eq!(batch.get(&key).await?, Some(V::from_seed(1)));

        batch.update(key.clone(), V::from_seed(9)).await?;
        assert_eq!(batch.get(&key).await?, Some(V::from_seed(9)));

        db.destroy().await?;
        Ok(())
    }

    async fn test_create<K, V, D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable<K, V>,
        K: TestKey,
        V: TestValue,
    {
        let mut db = new_db().await;
        let mut batch = db.start_batch();
        let key = K::from_seed(2);
        assert!(batch.create(key.clone(), V::from_seed(1)).await?);
        assert!(!batch.create(key.clone(), V::from_seed(2)).await?);

        batch.delete_unchecked(key.clone()).await?;
        assert!(batch.create(key.clone(), V::from_seed(3)).await?);
        assert_eq!(batch.get(&key).await?, Some(V::from_seed(3)));

        let existing = K::from_seed(3);
        db.update(existing.clone(), V::from_seed(4)).await?;
        let mut batch = db.start_batch();
        assert!(!batch.create(existing.clone(), V::from_seed(5)).await?);

        db.destroy().await?;
        Ok(())
    }

    async fn test_delete<K, V, D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable<K, V>,
        K: TestKey,
        V: TestValue,
    {
        let mut db = new_db().await;
        let base_key = K::from_seed(4);
        db.update(base_key.clone(), V::from_seed(10)).await?;
        let mut batch = db.start_batch();
        assert!(batch.delete(base_key.clone()).await?);
        assert_eq!(batch.get(&base_key).await?, None);
        assert!(!batch.delete(base_key.clone()).await?);

        let mut batch = db.start_batch();
        let overlay_key = K::from_seed(5);
        batch.update(overlay_key.clone(), V::from_seed(11)).await?;
        assert!(batch.delete(overlay_key.clone()).await?);
        assert_eq!(batch.get(&overlay_key).await?, None);
        assert!(!batch.delete(overlay_key).await?);

        db.destroy().await?;
        Ok(())
    }

    async fn test_delete_unchecked<K, V, D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable<K, V>,
        K: TestKey,
        V: TestValue,
    {
        let mut db = new_db().await;
        let key = K::from_seed(6);

        let mut batch = db.start_batch();
        batch.update(key.clone(), V::from_seed(12)).await?;
        batch.delete_unchecked(key.clone()).await?;
        assert_eq!(batch.get(&key).await?, None);

        db.update(key.clone(), V::from_seed(13)).await?;
        let mut batch = db.start_batch();
        batch.delete_unchecked(key.clone()).await?;
        assert_eq!(batch.get(&key).await?, None);

        db.destroy().await?;
        Ok(())
    }

    async fn test_write_batch<K, V, D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable<K, V>,
        K: TestKey,
        V: TestValue,
    {
        let mut db = new_db().await;
        let existing = K::from_seed(7);
        db.update(existing.clone(), V::from_seed(0)).await?;

        let created = K::from_seed(8);
        let mut batch = db.start_batch();
        batch.update(existing.clone(), V::from_seed(8)).await?;
        batch.create(created.clone(), V::from_seed(9)).await?;
        db.write_batch(batch.into_iter()).await?;

        assert_eq!(db.get(&existing).await?, Some(V::from_seed(8)));
        assert_eq!(db.get(&created).await?, Some(V::from_seed(9)));

        let mut delete_batch = db.start_batch();
        delete_batch.delete(existing.clone()).await?;
        db.write_batch(delete_batch.into_iter()).await?;
        assert_eq!(db.get(&existing).await?, None);

        db.destroy().await?;
        Ok(())
    }

    fn seed_bytes(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes
    }

    impl TestKey for blake3::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }

    impl TestKey for sha256::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }

    impl TestValue for Vec<u8> {
        fn from_seed(seed: u8) -> Self {
            vec![seed]
        }
    }

    impl TestValue for blake3::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }

    impl TestValue for sha256::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }
}
