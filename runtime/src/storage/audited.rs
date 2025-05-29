use crate::{deterministic::Auditor, Error};
use commonware_utils::StableBuf;
use sha2::digest::Update;
use std::sync::Arc;

#[derive(Clone)]
pub struct Storage<S: crate::Storage> {
    inner: S,
    auditor: Arc<Auditor>,
}

impl<S: crate::Storage> Storage<S> {
    pub fn new(inner: S, auditor: Arc<Auditor>) -> Self {
        Self { inner, auditor }
    }
}

impl<S: crate::Storage> crate::Storage for Storage<S> {
    type Blob = Blob<S::Blob>;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Self::Blob, u64), Error> {
        self.auditor.event(b"open", |hasher| {
            hasher.update(partition.as_bytes());
            hasher.update(name);
        });
        self.inner.open(partition, name).await.map(|(blob, len)| {
            (
                Blob {
                    auditor: self.auditor.clone(),
                    inner: blob,
                    partition: partition.into(),
                    name: name.to_vec(),
                },
                len,
            )
        })
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.auditor.event(b"remove", |hasher| {
            hasher.update(partition.as_bytes());
            if let Some(name) = name {
                hasher.update(name);
            }
        });
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.auditor.event(b"scan", |hasher| {
            hasher.update(partition.as_bytes());
        });
        self.inner.scan(partition).await
    }
}

#[derive(Clone)]
pub struct Blob<B: crate::Blob> {
    auditor: Arc<Auditor>,
    partition: String,
    name: Vec<u8>,
    inner: B,
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn read_at(&self, buf: impl Into<StableBuf>, offset: u64) -> Result<StableBuf, Error> {
        let buf = buf.into();
        self.auditor.event(b"read_at", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(buf.as_ref());
            hasher.update(&offset.to_be_bytes());
        });
        self.inner.read_at(buf, offset).await
    }

    async fn write_at(&self, buf: impl Into<StableBuf>, offset: u64) -> Result<(), Error> {
        let buf = buf.into();
        self.auditor.event(b"write_at", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(buf.as_ref());
            hasher.update(&offset.to_be_bytes());
        });
        self.inner.write_at(buf, offset).await
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.auditor.event(b"truncate", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(&len.to_be_bytes());
        });
        self.inner.truncate(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.auditor.event(b"sync", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.sync().await
    }

    async fn close(self) -> Result<(), Error> {
        self.auditor.event(b"close", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        storage::{
            audited::Storage as AuditedStorage, memory::Storage as MemStorage,
            tests::run_storage_tests,
        },
        Blob as _, Storage as _,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_audited_storage() {
        let inner = MemStorage::default();
        let auditor = Arc::new(crate::deterministic::Auditor::default());
        let storage = AuditedStorage::new(inner, auditor.clone());

        run_storage_tests(storage).await;
    }

    #[tokio::test]
    async fn test_audited_storage_combined() {
        use crate::deterministic::Auditor;

        // Initialize the first storage and auditor
        let inner1 = MemStorage::default();
        let auditor1 = Arc::new(Auditor::default());
        let storage1 = AuditedStorage::new(inner1, auditor1.clone());

        // Initialize the second storage and auditor
        let inner2 = MemStorage::default();
        let auditor2 = Arc::new(Auditor::default());
        let storage2 = AuditedStorage::new(inner2, auditor2.clone());

        // Perform a sequence of operations on both storages simultaneously
        let (blob1, _) = storage1.open("partition", b"test_blob").await.unwrap();
        let (blob2, _) = storage2.open("partition", b"test_blob").await.unwrap();

        // Write data to the blobs
        blob1.write_at(b"hello world".to_vec(), 0).await.unwrap();
        blob2.write_at(b"hello world".to_vec(), 0).await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after write"
        );

        // Read data from the blobs
        let read = blob1.read_at(vec![0; 11], 0).await.unwrap();
        assert_eq!(
            read.as_ref(),
            b"hello world",
            "Blob1 content does not match"
        );
        let read = blob2.read_at(vec![0; 11], 0).await.unwrap();
        assert_eq!(
            read.as_ref(),
            b"hello world",
            "Blob2 content does not match"
        );
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after read"
        );

        // Truncate the blobs
        blob1.truncate(5).await.unwrap();
        blob2.truncate(5).await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after truncate"
        );

        // Sync the blobs
        blob1.sync().await.unwrap();
        blob2.sync().await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after sync"
        );

        // Close the blobs
        blob1.close().await.unwrap();
        blob2.close().await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after close"
        );

        // Remove the blobs
        storage1
            .remove("partition", Some(b"test_blob"))
            .await
            .unwrap();
        storage2
            .remove("partition", Some(b"test_blob"))
            .await
            .unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after remove"
        );

        // Scan the partitions
        let blobs1 = storage1.scan("partition").await.unwrap();
        let blobs2 = storage2.scan("partition").await.unwrap();
        assert!(
            blobs1.is_empty(),
            "Partition1 should be empty after blob removal"
        );
        assert!(
            blobs2.is_empty(),
            "Partition2 should be empty after blob removal"
        );
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after scan"
        );
    }
}
