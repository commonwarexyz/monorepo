use bytes::Bytes;
use commonware_runtime::{Blob, Metrics, Storage};
use commonware_storage::{
    archive::{self, Archive, Identifier},
    index::Translator,
};
use commonware_utils::Array;
use futures::lock::Mutex;
use std::sync::Arc;

/// Archive wrapper that handles all locking.
#[derive(Clone)]
pub struct Wrapped<T, K, B, R>
where
    T: Translator,
    K: Array,
    B: Blob,
    R: Storage<Blob = B> + Metrics,
{
    inner: Arc<Mutex<Archive<T, K, R>>>,
}

impl<T, K, B, R> Wrapped<T, K, B, R>
where
    T: Translator,
    K: Array,
    B: Blob,
    R: Storage<Blob = B> + Metrics,
{
    /// Creates a new `Wrapped` from an existing `Archive`.
    pub fn new(archive: Archive<T, K, R>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(archive)),
        }
    }

    /// Retrieves a value from the archive by identifier.
    pub async fn get(
        &self,
        identifier: Identifier<'_, K>,
    ) -> Result<Option<Bytes>, archive::Error> {
        let archive = self.inner.lock().await;
        archive.get(identifier).await
    }

    /// Inserts a value into the archive with the given index and key.
    pub async fn put(&self, index: u64, key: K, data: Bytes) -> Result<(), archive::Error> {
        let mut archive = self.inner.lock().await;
        archive.put(index, key, data).await?;
        Ok(())
    }

    /// Prunes entries from the archive up to the specified minimum index.
    pub async fn prune(&self, min_index: u64) -> Result<(), archive::Error> {
        let mut archive = self.inner.lock().await;
        archive.prune(min_index).await?;
        Ok(())
    }

    /// Retrieves the next gap in the archive.
    pub async fn next_gap(&self, start: u64) -> (Option<u64>, Option<u64>) {
        let archive = self.inner.lock().await;
        archive.next_gap(start)
    }
}
