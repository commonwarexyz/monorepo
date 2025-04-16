use crate::{deterministic::Auditor, Blob as BlobTrait, Error, Storage as StorageTrait};
use std::sync::Arc;

#[derive(Clone)]
pub struct Storage<S: StorageTrait> {
    inner: S,
    auditor: Arc<Auditor>,
}

impl<S: StorageTrait> Storage<S> {
    pub fn new(inner: S, auditor: Arc<Auditor>) -> Self {
        Self { inner, auditor }
    }
}

impl<S: StorageTrait> StorageTrait for Storage<S> {
    type Blob = Blob<S::Blob>;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, Error> {
        self.auditor.open(partition, name);
        self.inner.open(partition, name).await.map(|blob| Blob {
            auditor: self.auditor.clone(),
            blob,
            partition: partition.into(),
            name: name.to_vec(),
        })
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.auditor.remove(partition, name);
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.auditor.scan(partition);
        self.inner.scan(partition).await
    }
}

#[derive(Clone)]
pub struct Blob<B: BlobTrait> {
    auditor: Arc<Auditor>,
    partition: String,
    name: Vec<u8>,
    blob: B,
}

impl<B: BlobTrait> crate::Blob for Blob<B> {
    async fn len(&self) -> Result<u64, Error> {
        self.auditor.len(&self.partition, &self.name);
        self.blob.len().await
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.auditor
            .read_at(&self.partition, &self.name, buf.len(), offset);
        self.blob.read_at(buf, offset).await
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        self.auditor
            .write_at(&self.partition, &self.name, buf, offset);
        self.blob.write_at(buf, offset).await
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.auditor.truncate(&self.partition, &self.name, len);
        self.blob.truncate(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.auditor.sync(&self.partition, &self.name);
        self.blob.sync().await
    }

    async fn close(self) -> Result<(), Error> {
        self.auditor.close(&self.partition, &self.name);
        self.blob.close().await
    }
}
