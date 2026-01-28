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
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + use<'a, Self>
    where
        Self: Send,
    {
        async {
            if self.get(&key).await?.is_some() {
                return Ok(false);
            }
            self.update(key, value).await?;
            Ok(true)
        }
    }

    /// Updates the value associated with the given key in the store, inserting a default value if
    /// the key does not already exist.
    fn upsert<'a, F>(
        &'a mut self,
        key: Self::Key,
        update: F,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + use<'a, Self, F>
    where
        Self: Send,
        Self::Value: Default,
        F: FnOnce(&mut Self::Value) + Send + 'a,
    {
        async move {
            let mut value = self.get(&key).await?.unwrap_or_default();
            update(&mut value);
            self.update(key, value).await
        }
    }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::{Batchable, Deletable, Gettable, Updatable};
    use commonware_codec::DecodeExt;
    use commonware_utils::sequence::FixedBytes;

    pub fn assert_send<T: Send>(_: T) {}

    /// Create a test key from a string.
    pub fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    #[allow(dead_code)]
    pub fn assert_gettable<T: Gettable + Send>(db: &T, key: &T::Key) {
        assert_send(db.get(key));
    }

    #[allow(dead_code)]
    pub fn assert_updatable<T: Updatable + Send>(db: &mut T, key: T::Key, value: T::Value)
    where
        T::Key: Clone,
        T::Value: Default + Clone,
    {
        assert_send(db.update(key.clone(), value.clone()));
        assert_send(db.create(key.clone(), value));
        assert_send(db.upsert(key, |_| {}));
    }

    #[allow(dead_code)]
    pub fn assert_deletable<T: Deletable + Send>(db: &mut T, key: T::Key) {
        assert_send(db.delete(key));
    }

    #[allow(dead_code)]
    pub fn assert_batchable<T: Batchable + Send>(db: &mut T, key: T::Key, value: T::Value) {
        assert_send(db.write_batch(vec![(key, Some(value))].into_iter()));
    }
}
