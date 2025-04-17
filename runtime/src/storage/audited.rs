use crate::{deterministic::Auditor, Error};
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

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, Error> {
        self.auditor.open(partition, name);
        self.inner.open(partition, name).await.map(|blob| Blob {
            auditor: self.auditor.clone(),
            inner: blob,
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
pub struct Blob<B: crate::Blob> {
    auditor: Arc<Auditor>,
    partition: String,
    name: Vec<u8>,
    inner: B,
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn len(&self) -> Result<u64, Error> {
        self.auditor.len(&self.partition, &self.name);
        self.inner.len().await
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.auditor
            .read_at(&self.partition, &self.name, buf.len(), offset);
        self.inner.read_at(buf, offset).await
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        self.auditor
            .write_at(&self.partition, &self.name, buf, offset);
        self.inner.write_at(buf, offset).await
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.auditor.truncate(&self.partition, &self.name, len);
        self.inner.truncate(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.auditor.sync(&self.partition, &self.name);
        self.inner.sync().await
    }

    async fn close(self) -> Result<(), Error> {
        self.auditor.close(&self.partition, &self.name);
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
        let blob1 = storage1.open("partition", b"test_blob").await.unwrap();
        let blob2 = storage2.open("partition", b"test_blob").await.unwrap();

        // Write data to the blobs
        blob1.write_at(b"hello world", 0).await.unwrap();
        blob2.write_at(b"hello world", 0).await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after write"
        );

        // Read data from the blobs
        let mut buffer1 = vec![0; 11];
        let mut buffer2 = vec![0; 11];
        blob1.read_at(&mut buffer1, 0).await.unwrap();
        blob2.read_at(&mut buffer2, 0).await.unwrap();
        assert_eq!(buffer1, b"hello world", "Blob1 content does not match");
        assert_eq!(buffer2, b"hello world", "Blob2 content does not match");
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after read"
        );

        // Truncate the blobs
        blob1.truncate(5).await.unwrap();
        blob2.truncate(5).await.unwrap();
        let len1 = blob1.len().await.unwrap();
        let len2 = blob2.len().await.unwrap();
        assert_eq!(len1, 5, "Blob1 length after truncation is incorrect");
        assert_eq!(len2, 5, "Blob2 length after truncation is incorrect");
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
