use crate::{Blob as BlobTrait, Error, Storage as StorageTrait};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prometheus_client::registry::Registry;
use std::sync::Arc;

use super::Metrics;

// /// Metrics for the metered storage
// pub struct Metrics {
//     pub open_blobs: Gauge,
//     pub storage_reads: Counter,
//     pub storage_read_bytes: Counter,
//     pub storage_writes: Counter,
//     pub storage_write_bytes: Counter,
// }

// impl Metrics {
//     /// Initialize metrics and register them in the provided registry
//     pub fn new(registry: &mut Registry) -> Self {
//         let metrics = Self {
//             open_blobs: Gauge::default(),
//             storage_reads: Counter::default(),
//             storage_read_bytes: Counter::default(),
//             storage_writes: Counter::default(),
//             storage_write_bytes: Counter::default(),
//         };

//         registry.register(
//             "open_blobs",
//             "Number of open blobs",
//             metrics.open_blobs.clone(),
//         );
//         registry.register(
//             "storage_reads",
//             "Total number of storage reads",
//             metrics.storage_reads.clone(),
//         );
//         registry.register(
//             "storage_read_bytes",
//             "Total bytes read from storage",
//             metrics.storage_read_bytes.clone(),
//         );
//         registry.register(
//             "storage_writes",
//             "Total number of storage writes",
//             metrics.storage_writes.clone(),
//         );
//         registry.register(
//             "storage_write_bytes",
//             "Total bytes written to storage",
//             metrics.storage_write_bytes.clone(),
//         );

//         metrics
//     }
// }

/// A wrapper around a `Storage` implementation that tracks metrics.
#[derive(Clone)]
pub struct MeteredStorage<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S> MeteredStorage<S> {
    pub fn new(inner: S, metrics: Arc<Metrics>) -> Self {
        Self { inner, metrics }
    }
}

impl<S: StorageTrait> StorageTrait for MeteredStorage<S> {
    type Blob = MeteredBlob<S::Blob>;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, Error> {
        self.metrics.open_blobs.inc();
        let inner_blob = self.inner.open(partition, name).await?;
        Ok(MeteredBlob {
            inner: inner_blob,
            metrics: self.metrics.clone(),
        })
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

/// A wrapper around a `Blob` implementation that tracks metrics
#[derive(Clone)]
pub struct MeteredBlob<B> {
    inner: B,
    metrics: Arc<Metrics>,
}

impl<B: BlobTrait> BlobTrait for MeteredBlob<B> {
    async fn len(&self) -> Result<u64, Error> {
        self.inner.len().await
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(buf.len() as u64);
        self.inner.read_at(buf, offset).await
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf.len() as u64);
        self.inner.write_at(buf, offset).await
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.inner.truncate(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }

    async fn close(self) -> Result<(), Error> {
        self.metrics.open_blobs.dec(); // Decrement the open blobs gauge
        self.inner.close().await
    }
}
