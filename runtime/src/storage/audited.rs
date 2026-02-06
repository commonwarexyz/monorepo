use crate::{deterministic::Auditor, Error, IoBufs, IoBufsMut};
use sha2::digest::Update;
use std::sync::Arc;

#[derive(Clone)]
pub struct Storage<S: crate::Storage> {
    inner: S,
    auditor: Arc<Auditor>,
}

impl<S: crate::Storage> Storage<S> {
    pub const fn new(inner: S, auditor: Arc<Auditor>) -> Self {
        Self { inner, auditor }
    }

    /// Get a reference to the inner storage.
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: crate::Storage> crate::Storage for Storage<S> {
    type Blob = Blob<S::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        self.auditor.event(b"open", |hasher| {
            hasher.update(partition.as_bytes());
            hasher.update(name);
            hasher.update(&versions.start().to_be_bytes());
            hasher.update(&versions.end().to_be_bytes());
        });
        self.inner
            .open_versioned(partition, name, versions)
            .await
            .map(|(blob, len, blob_version)| {
                (
                    Blob {
                        auditor: self.auditor.clone(),
                        inner: blob,
                        partition: partition.into(),
                        name: name.to_vec(),
                    },
                    len,
                    blob_version,
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
    async fn read_at_buf(
        &self,
        offset: u64,
        buf: impl Into<IoBufsMut> + Send,
        len: usize,
    ) -> Result<IoBufsMut, Error> {
        let buf = buf.into();
        self.auditor.event(b"read_at", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(&offset.to_be_bytes());
            hasher.update(&(len as u64).to_be_bytes());
        });
        self.inner.read_at_buf(offset, buf, len).await
    }

    async fn write_at(&self, offset: u64, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let buf = buf.into().coalesce();
        self.auditor.event(b"write_at", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(&offset.to_be_bytes());
            hasher.update(buf.as_ref());
        });
        self.inner.write_at(offset, buf).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.auditor.event(b"resize", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(&len.to_be_bytes());
        });
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.auditor.event(b"sync", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.sync().await
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
        blob1.write_at(0, b"hello world").await.unwrap();
        blob2.write_at(0, b"hello world").await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after write"
        );

        // Read data from the blobs
        let read = blob1.read_at(0, 11).await.unwrap();
        assert_eq!(
            read.coalesce(),
            b"hello world",
            "Blob1 content does not match"
        );
        let read = blob2.read_at(0, 11).await.unwrap();
        assert_eq!(
            read.coalesce(),
            b"hello world",
            "Blob2 content does not match"
        );
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after read"
        );

        // Resize the blobs
        blob1.resize(5).await.unwrap();
        blob2.resize(5).await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after resize"
        );

        // Sync the blobs
        blob1.sync().await.unwrap();
        blob2.sync().await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after sync"
        );

        // Drop the blobs
        drop(blob1);
        drop(blob2);

        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after drop"
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
