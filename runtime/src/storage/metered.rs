use crate::{Blob as BlobTrait, Error, Storage as StorageTrait};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prometheus_client::registry::Registry;
use std::sync::Arc;

pub struct Metrics {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,
}

impl Metrics {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    pub fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            open_blobs: Gauge::default(),
            storage_reads: Counter::default(),
            storage_read_bytes: Counter::default(),
            storage_writes: Counter::default(),
            storage_write_bytes: Counter::default(),
        };

        registry.register(
            "open_blobs",
            "Number of open blobs",
            metrics.open_blobs.clone(),
        );
        registry.register(
            "storage_reads",
            "Total number of disk reads",
            metrics.storage_reads.clone(),
        );
        registry.register(
            "storage_read_bytes",
            "Total amount of data read from disk",
            metrics.storage_read_bytes.clone(),
        );
        registry.register(
            "storage_writes",
            "Total number of disk writes",
            metrics.storage_writes.clone(),
        );
        registry.register(
            "storage_write_bytes",
            "Total amount of data written to disk",
            metrics.storage_write_bytes.clone(),
        );

        metrics
    }
}

/// A wrapper around a `Storage` implementation that tracks metrics.
#[derive(Clone)]
pub struct MeteredStorage<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S> MeteredStorage<S> {
    pub fn new(inner: S, registry: &mut Registry) -> Self {
        Self {
            inner,
            metrics: Metrics::new(registry).into(),
        }
    }
}

impl<S: StorageTrait> StorageTrait for MeteredStorage<S> {
    type Blob = MeteredBlob<S::Blob>;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, Error> {
        self.metrics.open_blobs.inc();
        let inner_blob = self.inner.open(partition, name).await?;
        Ok(MeteredBlob {
            inner: State::Open(inner_blob),
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

#[derive(Clone)]
enum State<B> {
    Open(B),
    Closed,
}

/// A wrapper around a `Blob` implementation that tracks metrics
#[derive(Clone)]
pub struct MeteredBlob<B> {
    inner: State<B>,
    metrics: Arc<Metrics>,
}

impl<B: BlobTrait> BlobTrait for MeteredBlob<B> {
    async fn len(&self) -> Result<u64, Error> {
        match &self.inner {
            State::Open(inner) => inner.len().await,
            State::Closed => Err(Error::Closed),
        }
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        match &self.inner {
            State::Open(inner) => {
                inner.read_at(buf, offset).await?;
                self.metrics.storage_reads.inc();
                self.metrics.storage_read_bytes.inc_by(buf.len() as u64);
                Ok(())
            }
            State::Closed => Err(Error::Closed),
        }
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        match &self.inner {
            State::Open(inner) => {
                inner.write_at(buf, offset).await?;
                self.metrics.storage_writes.inc();
                self.metrics.storage_write_bytes.inc_by(buf.len() as u64);
                Ok(())
            }
            State::Closed => Err(Error::Closed),
        }
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        match &self.inner {
            State::Open(inner) => inner.truncate(len).await,
            State::Closed => Err(Error::Closed),
        }
    }

    async fn sync(&self) -> Result<(), Error> {
        match &self.inner {
            State::Open(inner) => inner.sync().await,
            State::Closed => Err(Error::Closed),
        }
    }

    async fn close(mut self) -> Result<(), Error> {
        let inner = match std::mem::replace(&mut self.inner, State::Closed) {
            State::Open(inner) => inner,
            State::Closed => return Err(Error::Closed),
        };

        self.metrics.open_blobs.dec();

        inner.close().await
    }
}

impl<B> Drop for MeteredBlob<B> {
    fn drop(&mut self) {
        match &self.inner {
            State::Open(_) => {
                self.metrics.open_blobs.dec();
            }
            State::Closed => {}
        }
    }
}
