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
mod tests {
    use super::{Batchable as _, Updatable as _};
    use crate::{qmdb::store::db::Db, translator::TwoCap};
    use commonware_cryptography::{
        blake3::{Blake3, Digest},
        Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Metrics, Runner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    type TestStore = Db<deterministic::Context, Digest, Vec<u8>, TwoCap>;

    async fn create_test_store(context: deterministic::Context) -> TestStore {
        let cfg = crate::qmdb::store::db::Config {
            log_partition: "kv_test_journal".to_string(),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
            translator: TwoCap,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        };
        TestStore::init(context, cfg).await.unwrap()
    }

    fn assert_send<T: Send>(_: T) {}

    #[test_traced]
    fn test_kv_futures_are_send() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_store(context.with_label("store"))
                .await
                .into_dirty();
            let key = Blake3::hash(&[1, 2, 3]);

            assert_send(db.get(&key));
            assert_send(db.update(key, vec![]));
            assert_send(db.create(key, vec![]));
            assert_send(db.upsert(key, |_| {}));
            assert_send(db.delete(key));
            assert_send(db.write_batch(vec![(key, Some(vec![1u8]))].into_iter()));
        });
    }
}
