use crate::{
    AtomicBlob, AtomicStorage, BatchOperation, BatchStorage, Error, Handle, IoBufs, IoBufsMut,
    RemoveTarget, WriteOptions, deterministic::Auditor,
};
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
            hasher.update(versions.start().to_be_bytes());
            hasher.update(versions.end().to_be_bytes());
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
            match name {
                Some(name) => {
                    hasher.update([1]);
                    hasher.update(name);
                }
                None => hasher.update([0]),
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

impl<S: AtomicStorage> AtomicStorage for Storage<S> {
    type AtomicBlob = Blob<S::AtomicBlob>;

    async fn migrate_atomic(&self, blob: Self::Blob) -> Result<(), Error> {
        self.auditor.event(b"migrate_atomic", |hasher| {
            hasher.update(blob.partition.as_bytes());
            hasher.update(&blob.name);
        });
        self.inner.migrate_atomic(blob.inner).await
    }

    async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::AtomicBlob, u64, u16), Error> {
        self.auditor.event(b"open_atomic", |hasher| {
            hasher.update(partition.as_bytes());
            hasher.update(name);
            hasher.update(versions.start().to_be_bytes());
            hasher.update(versions.end().to_be_bytes());
        });
        self.inner
            .open_atomic_versioned(partition, name, versions)
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
}

impl<S: BatchStorage> BatchStorage for Storage<S> {
    async fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> Result<Handle<()>, Error> {
        let descriptors = crate::storage::batch::canonicalize_descriptors(&operations, |blob| {
            (blob.partition.clone(), blob.name.clone())
        })?;
        self.auditor.event(b"apply_batch", |hasher| {
            hasher.update((descriptors.len() as u64).to_be_bytes());
            for descriptor in &descriptors {
                match descriptor {
                    crate::storage::batch::Operation::Remove(RemoveTarget::Partition(
                        partition,
                    )) => {
                        hasher.update(b"remove_partition");
                        hasher.update(partition.as_bytes());
                    }
                    crate::storage::batch::Operation::Remove(RemoveTarget::Blob {
                        partition,
                        name,
                    }) => {
                        hasher.update(b"remove_blob");
                        hasher.update(partition.as_bytes());
                        hasher.update(name);
                    }
                    crate::storage::batch::Operation::Publish {
                        partition, name, ..
                    } => {
                        hasher.update(b"publish");
                        hasher.update(partition.as_bytes());
                        hasher.update(name);
                    }
                    crate::storage::batch::Operation::Rewind {
                        partition,
                        name,
                        len,
                        ..
                    } => {
                        hasher.update(b"rewind");
                        hasher.update(partition.as_bytes());
                        hasher.update(name);
                        hasher.update(len.to_be_bytes());
                    }
                }
            }
        });
        let operations = crate::storage::batch::map_blobs(operations, |blob| blob.inner);
        self.inner.start_apply(operations).await
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
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.auditor.event(b"read_at", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(offset.to_be_bytes());
            hasher.update(len.to_be_bytes());
        });
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let bufs = bufs.into();
        self.auditor.event(b"read_at_buf", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(offset.to_be_bytes());
            hasher.update(len.to_be_bytes());
        });
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.write_at_with_options(offset, bufs, WriteOptions::default())
            .await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.write_at_with_options(offset, bufs, WriteOptions::SYNC)
            .await
    }

    async fn write_at_with_options(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        self.auditor.event(b"write_at", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(offset.to_be_bytes());
            hasher.update_bufs(&bufs);
        });
        self.inner
            .write_at_with_options(offset, bufs, options)
            .await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.auditor.event(b"resize", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(len.to_be_bytes());
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

    async fn start_sync(&self) -> Handle<()> {
        self.auditor.event(b"start_sync", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.start_sync().await
    }
}

impl<B: AtomicBlob> AtomicBlob for Blob<B> {
    async fn tag(&self) -> Result<[u8; crate::ATOMIC_BLOB_TAG_LEN], Error> {
        self.auditor.event(b"tag", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.tag().await
    }

    async fn integrity_scheme(&self) -> Result<crate::IntegrityScheme, Error> {
        self.auditor.event(b"integrity_scheme", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.integrity_scheme().await
    }

    async fn integrity_snapshot(&self) -> Result<crate::IntegritySnapshot, Error> {
        self.auditor.event(b"integrity_snapshot", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.integrity_snapshot().await
    }

    async fn compare_set_tag(
        &self,
        expected: crate::IntegrityToken,
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<crate::IntegrityToken, Error> {
        self.auditor.event(b"compare_set_tag", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(expected.0.to_be_bytes());
            hasher.update(tag);
        });
        self.inner.compare_set_tag(expected, tag).await
    }

    async fn set_tag(&self, tag: [u8; crate::ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        self.auditor.event(b"set_tag", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(tag);
        });
        self.inner.set_tag(tag).await
    }

    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        let data = data.into();
        self.auditor.event(b"append", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update_bufs(&data);
        });
        self.inner.append(data).await
    }

    async fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<u64, Error> {
        let data = data.into();
        self.auditor.event(b"append_tagged", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update_bufs(&data);
            hasher.update(tag);
        });
        self.inner.append_tagged(data, tag).await
    }

    async fn append_integrity(
        &self,
        expected: crate::IntegrityToken,
        data: impl Into<IoBufs> + Send,
        boundary: crate::IntegrityBoundary,
        tag: Option<[u8; crate::ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<crate::IntegrityAppend, Error> {
        let data = data.into();
        self.auditor.event(b"append_integrity", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(expected.0.to_be_bytes());
            hasher.update_bufs(&data);
            match boundary {
                crate::IntegrityBoundary::Continue => hasher.update([0]),
                crate::IntegrityBoundary::Complete => hasher.update([1]),
                crate::IntegrityBoundary::Chunked(size) => {
                    hasher.update([2]);
                    hasher.update(size.get().to_be_bytes());
                }
            };
            if let Some(tag) = tag {
                hasher.update(tag);
            }
        });
        self.inner
            .append_integrity(expected, data, boundary, tag)
            .await
    }

    async fn read_integrity_tail(&self) -> Result<Option<(crate::IntegrityUnit, IoBufs)>, Error> {
        self.auditor.event(b"read_integrity_tail", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
        });
        self.inner.read_integrity_tail().await
    }

    async fn read_integrity(&self, unit: crate::IntegrityUnit) -> Result<IoBufs, Error> {
        self.auditor.event(b"read_integrity", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(unit.offset.to_be_bytes());
            hasher.update(unit.len.to_be_bytes());
        });
        self.inner.read_integrity(unit).await
    }

    async fn rewind(&self, len: u64) -> Result<(), Error> {
        self.auditor.event(b"rewind", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(len.to_be_bytes());
        });
        self.inner.rewind(len).await
    }

    async fn rewind_tagged(
        &self,
        len: u64,
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<(), Error> {
        self.auditor.event(b"rewind_tagged", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(len.to_be_bytes());
            hasher.update(tag);
        });
        self.inner.rewind_tagged(len, tag).await
    }

    async fn rewind_integrity(
        &self,
        expected: crate::IntegrityToken,
        len: u64,
        unit: Option<crate::IntegrityUnit>,
        tag: Option<[u8; crate::ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<crate::IntegrityToken, Error> {
        self.auditor.event(b"rewind_integrity", |hasher| {
            hasher.update(self.partition.as_bytes());
            hasher.update(&self.name);
            hasher.update(expected.0.to_be_bytes());
            hasher.update(len.to_be_bytes());
            if let Some(unit) = unit {
                hasher.update(unit.offset.to_be_bytes());
                hasher.update(unit.len.to_be_bytes());
            }
            if let Some(tag) = tag {
                hasher.update(tag);
            }
        });
        self.inner.rewind_integrity(expected, len, unit, tag).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        AtomicBlob as _, AtomicStorage as _, BatchOperation, BatchStorage as _, Blob as _,
        BufferPool, BufferPoolConfig, Error, Handle, IoBuf, IoBufs, IoBufsMut, Storage as _,
        WriteOptions,
        deterministic::Auditor,
        storage::{
            audited::Storage as AuditedStorage,
            memory::Storage as MemStorage,
            tests::{
                run_atomic_storage_tests, run_batch_storage_tests, run_storage_foreign_handle_test,
                run_storage_tests,
            },
        },
        telemetry::metrics::Registry,
    };
    use commonware_utils::sync::Mutex;
    use std::sync::Arc;

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    #[tokio::test]
    async fn test_audited_storage() {
        let inner = MemStorage::new(test_pool());
        let auditor = Arc::new(crate::deterministic::Auditor::default());
        let storage = AuditedStorage::new(inner, auditor.clone());
        let tested = storage.clone();
        run_storage_tests(storage.clone()).await;
        run_atomic_storage_tests(storage.clone()).await;
        run_batch_storage_tests(storage).await;

        let foreign =
            AuditedStorage::new(MemStorage::new(test_pool()), Arc::new(Auditor::default()));
        run_storage_foreign_handle_test(&tested, &foreign).await;
    }

    #[tokio::test]
    async fn test_audited_storage_separates_partition_and_blob_names() {
        let auditor1 = Arc::new(Auditor::default());
        let storage1 = AuditedStorage::new(MemStorage::new(test_pool()), auditor1.clone());
        let auditor2 = Arc::new(Auditor::default());
        let storage2 = AuditedStorage::new(MemStorage::new(test_pool()), auditor2.clone());

        storage1.open("a", b"bc").await.unwrap();
        storage2.open("ab", b"c").await.unwrap();

        assert_ne!(auditor1.state(), auditor2.state());
    }

    #[tokio::test]
    async fn test_write_options_do_not_change_audit_event() {
        let auditor1 = Arc::new(Auditor::default());
        let storage1 = AuditedStorage::new(MemStorage::new(test_pool()), auditor1.clone());
        let auditor2 = Arc::new(Auditor::default());
        let storage2 = AuditedStorage::new(MemStorage::new(test_pool()), auditor2.clone());

        let (blob1, _) = storage1.open("partition", b"blob").await.unwrap();
        let (blob2, _) = storage2.open("partition", b"blob").await.unwrap();
        blob1.write_at(0, b"data").await.unwrap();
        blob2
            .write_at_with_options(0, b"data", WriteOptions::SYNC | WriteOptions::DONT_CACHE)
            .await
            .unwrap();

        assert_eq!(auditor1.state(), auditor2.state());
    }

    #[tokio::test]
    async fn test_audited_batch_hashes_canonical_operations() {
        let auditor1 = Arc::new(Auditor::default());
        let storage1 = AuditedStorage::new(MemStorage::new(test_pool()), auditor1.clone());
        let auditor2 = Arc::new(Auditor::default());
        let storage2 = AuditedStorage::new(MemStorage::new(test_pool()), auditor2.clone());
        let (rewind1, _) = storage1
            .open_atomic("rewind_partition", b"name")
            .await
            .unwrap();
        let (rewind2, _) = storage2
            .open_atomic("rewind_partition", b"name")
            .await
            .unwrap();
        let (publish1, _) = storage1
            .open_atomic("publish_partition", b"name")
            .await
            .unwrap();
        let (publish2, _) = storage2
            .open_atomic("publish_partition", b"name")
            .await
            .unwrap();
        let (remove1, _) = storage1
            .open_atomic("blob_partition", b"name")
            .await
            .unwrap();
        let (remove2, _) = storage2
            .open_atomic("blob_partition", b"name")
            .await
            .unwrap();
        rewind1.append(b"rewind").await.unwrap();
        rewind2.append(b"rewind").await.unwrap();
        publish1.append(b"pending").await.unwrap();
        publish2.append(b"pending").await.unwrap();

        storage1
            .apply(vec![
                BatchOperation::Rewind {
                    blob: rewind1.clone(),
                    len: 3,
                },
                BatchOperation::Remove(remove1.clone()),
                BatchOperation::Remove(remove1),
                BatchOperation::Rewind {
                    blob: rewind1,
                    len: 3,
                },
                BatchOperation::Publish(publish1),
            ])
            .await
            .unwrap();
        storage2
            .apply(vec![
                BatchOperation::Remove(remove2),
                BatchOperation::Rewind {
                    blob: rewind2,
                    len: 3,
                },
                BatchOperation::Publish(publish2),
            ])
            .await
            .unwrap();

        assert_eq!(auditor1.state(), auditor2.state());
    }

    #[tokio::test]
    async fn test_audited_atomic_mutations_hash_all_fields() {
        async fn append_state(data: &'static [u8]) -> String {
            let auditor = Arc::new(Auditor::default());
            let storage = AuditedStorage::new(MemStorage::new(test_pool()), auditor.clone());
            let (blob, _) = storage.open_atomic("partition", b"name").await.unwrap();
            blob.append(data).await.unwrap();
            auditor.state()
        }

        async fn rewind_state(len: u64) -> String {
            let auditor = Arc::new(Auditor::default());
            let storage = AuditedStorage::new(MemStorage::new(test_pool()), auditor.clone());
            let (blob, _) = storage.open_atomic("partition", b"name").await.unwrap();
            blob.append(b"abc").await.unwrap();
            blob.rewind(len).await.unwrap();
            auditor.state()
        }

        assert_ne!(append_state(b"a").await, append_state(b"b").await);
        assert_ne!(rewind_state(1).await, rewind_state(2).await);
    }

    #[tokio::test]
    async fn test_audited_batch_rejects_conflict_before_audit() {
        let auditor = Arc::new(Auditor::default());
        let storage = AuditedStorage::new(MemStorage::new(test_pool()), auditor.clone());
        let (blob, _) = storage.open_atomic("partition", b"name").await.unwrap();
        blob.append(b"abc").await.unwrap();
        let before = auditor.state();

        assert!(matches!(
            storage
                .apply(vec![
                    BatchOperation::Rewind {
                        blob: blob.clone(),
                        len: 1,
                    },
                    BatchOperation::Rewind { blob, len: 2 },
                ])
                .await,
            Err(Error::Io(_))
        ));
        assert_eq!(auditor.state(), before);
    }

    #[tokio::test]
    async fn test_audited_start_sync() {
        // Two independent storages run the same sequence of operations.
        let auditor1 = Arc::new(Auditor::default());
        let storage1 = AuditedStorage::new(MemStorage::new(test_pool()), auditor1.clone());
        let auditor2 = Arc::new(Auditor::default());
        let storage2 = AuditedStorage::new(MemStorage::new(test_pool()), auditor2.clone());

        let (blob1, _) = storage1.open("partition", b"test_blob").await.unwrap();
        let (blob2, _) = storage2.open("partition", b"test_blob").await.unwrap();
        blob1.write_at(0, b"hello world").await.unwrap();
        blob2.write_at(0, b"hello world").await.unwrap();

        // `start_sync` must record an auditor event, so the state advances.
        let before = auditor1.state();
        blob1.start_sync().await.await.unwrap();
        assert_ne!(
            auditor1.state(),
            before,
            "start_sync must record an auditor event"
        );

        // The recorded event must be deterministic across independent runs.
        blob2.start_sync().await.await.unwrap();
        assert_eq!(
            auditor1.state(),
            auditor2.state(),
            "Hashes do not match after start_sync"
        );
    }

    #[tokio::test]
    async fn test_audited_storage_combined() {
        // Initialize the first storage and auditor
        let inner1 = MemStorage::new(test_pool());
        let auditor1 = Arc::new(Auditor::default());
        let storage1 = AuditedStorage::new(inner1, auditor1.clone());

        // Initialize the second storage and auditor
        let inner2 = MemStorage::new(test_pool());
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

    #[derive(Clone)]
    struct RecordingBlob {
        writes: Arc<Mutex<Vec<(usize, WriteOptions)>>>,
        appends: Arc<Mutex<Vec<usize>>>,
        rewinds: Arc<Mutex<Vec<u64>>>,
    }

    impl crate::Blob for RecordingBlob {
        async fn read_at(&self, _offset: u64, _len: usize) -> Result<IoBufsMut, Error> {
            unreachable!("not used in test");
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            unreachable!("not used in test");
        }

        async fn write_at(
            &self,
            _offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            self.write_at_with_options(_offset, bufs, WriteOptions::default())
                .await
        }

        async fn write_at_sync(
            &self,
            _offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            self.write_at_with_options(_offset, bufs, WriteOptions::SYNC)
                .await
        }

        async fn write_at_with_options(
            &self,
            _offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            self.writes
                .lock()
                .push((bufs.into().chunk_count(), options));
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), Error> {
            Ok(())
        }

        async fn start_sync(&self) -> Handle<()> {
            Handle::ready(self.sync().await)
        }
    }

    impl crate::AtomicBlob for RecordingBlob {
        async fn tag(&self) -> Result<[u8; crate::ATOMIC_BLOB_TAG_LEN], Error> {
            Ok([0; crate::ATOMIC_BLOB_TAG_LEN])
        }

        async fn integrity_scheme(&self) -> Result<crate::IntegrityScheme, Error> {
            Ok(crate::IntegrityScheme::Unbound)
        }

        async fn integrity_snapshot(&self) -> Result<crate::IntegritySnapshot, Error> {
            Ok(crate::IntegritySnapshot {
                encoded_len: 0,
                scheme: crate::IntegrityScheme::Unbound,
                tag: [0; crate::ATOMIC_BLOB_TAG_LEN],
                tail: None,
                token: crate::IntegrityToken(0),
            })
        }

        async fn compare_set_tag(
            &self,
            expected: crate::IntegrityToken,
            _tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
        ) -> Result<crate::IntegrityToken, Error> {
            Ok(expected)
        }

        async fn set_tag(&self, _tag: [u8; crate::ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
            Ok(())
        }

        async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
            self.appends.lock().push(data.into().chunk_count());
            Ok(7)
        }

        async fn append_tagged(
            &self,
            data: impl Into<IoBufs> + Send,
            _tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
        ) -> Result<u64, Error> {
            self.appends.lock().push(data.into().chunk_count());
            Ok(7)
        }

        async fn append_integrity(
            &self,
            expected: crate::IntegrityToken,
            data: impl Into<IoBufs> + Send,
            _boundary: crate::IntegrityBoundary,
            _tag: Option<[u8; crate::ATOMIC_BLOB_TAG_LEN]>,
        ) -> Result<crate::IntegrityAppend, Error> {
            self.appends.lock().push(data.into().chunk_count());
            Ok(crate::IntegrityAppend {
                offset: 7,
                token: expected,
            })
        }

        async fn read_integrity_tail(
            &self,
        ) -> Result<Option<(crate::IntegrityUnit, IoBufs)>, Error> {
            Ok(None)
        }

        async fn read_integrity(&self, _unit: crate::IntegrityUnit) -> Result<IoBufs, Error> {
            Ok(IoBufs::default())
        }

        async fn rewind(&self, len: u64) -> Result<(), Error> {
            self.rewinds.lock().push(len);
            Ok(())
        }

        async fn rewind_tagged(
            &self,
            len: u64,
            _tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
        ) -> Result<(), Error> {
            self.rewinds.lock().push(len);
            Ok(())
        }

        async fn rewind_integrity(
            &self,
            expected: crate::IntegrityToken,
            len: u64,
            _unit: Option<crate::IntegrityUnit>,
            _tag: Option<[u8; crate::ATOMIC_BLOB_TAG_LEN]>,
        ) -> Result<crate::IntegrityToken, Error> {
            self.rewinds.lock().push(len);
            Ok(expected)
        }
    }

    #[tokio::test]
    async fn test_audited_blob_writes_and_atomic_mutations_preserve_arguments() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let appends = Arc::new(Mutex::new(Vec::new()));
        let rewinds = Arc::new(Mutex::new(Vec::new()));
        let blob = super::Blob {
            auditor: Arc::new(crate::deterministic::Auditor::default()),
            partition: "partition".into(),
            name: b"blob".to_vec(),
            inner: RecordingBlob {
                writes: writes.clone(),
                appends: appends.clone(),
                rewinds: rewinds.clone(),
            },
        };

        let chunked = || {
            IoBufs::from(vec![
                IoBuf::from(b"a".to_vec()),
                IoBuf::from(b"b".to_vec()),
                IoBuf::from(b"c".to_vec()),
                IoBuf::from(b"d".to_vec()),
            ])
        };
        blob.write_at(0, chunked()).await.unwrap();
        blob.write_at_sync(0, chunked()).await.unwrap();
        let options = WriteOptions::SYNC | WriteOptions::DONT_CACHE;
        blob.write_at_with_options(0, chunked(), options)
            .await
            .unwrap();
        assert_eq!(blob.append(chunked()).await.unwrap(), 7);
        blob.rewind(5).await.unwrap();

        assert_eq!(
            *writes.lock(),
            vec![
                (4, WriteOptions::default()),
                (4, WriteOptions::SYNC),
                (4, options),
            ]
        );
        assert_eq!(*appends.lock(), vec![4]);
        assert_eq!(*rewinds.lock(), vec![5]);
    }
}
