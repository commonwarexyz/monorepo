pub mod audited;
pub mod memory;
pub mod metered;
#[cfg(not(target_arch = "wasm32"))]
pub mod tokio_storage;

#[cfg(test)]
mod tests {
    use crate::storage::{
        audited::Storage as AuditedStorage, memory::Storage as MemoryStorage,
        metered::MeteredStorage, tokio_storage::Storage as TokioStorage,
    };
    use crate::{Blob, Storage};
    use prometheus_client::registry::Registry;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// Runs the full suite of tests on the provided storage implementation.
    async fn run_storage_tests<S>(storage: S)
    where
        S: Storage + Send + Sync + 'static,
        S::Blob: Send + Sync,
    {
        test_open_and_write(&storage).await;
        test_remove(&storage).await;
        test_scan(&storage).await;
        test_concurrent_access(&storage).await;
        test_large_data(&storage).await;
    }

    /// Test opening a blob, writing to it, and reading back the data.
    async fn test_open_and_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage.open("partition", b"test_blob").await.unwrap();

        blob.write_at(b"hello world", 0).await.unwrap();
        let mut buffer = vec![0; 11];
        blob.read_at(&mut buffer, 0).await.unwrap();

        assert_eq!(
            buffer, b"hello world",
            "Blob content does not match expected value"
        );
    }

    /// Test removing a blob from storage.
    async fn test_remove<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"test_blob").await.unwrap();
        storage
            .remove("partition", Some(b"test_blob"))
            .await
            .unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert!(blobs.is_empty(), "Blob was not removed as expected");
    }

    /// Test scanning a partition for blobs.
    async fn test_scan<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"blob1").await.unwrap();
        storage.open("partition", b"blob2").await.unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert_eq!(
            blobs.len(),
            2,
            "Scan did not return the expected number of blobs"
        );
        assert!(
            blobs.contains(&b"blob1".to_vec()),
            "Blob1 is missing from scan results"
        );
        assert!(
            blobs.contains(&b"blob2".to_vec()),
            "Blob2 is missing from scan results"
        );
    }

    /// Test concurrent access to the same blob.
    async fn test_concurrent_access<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage.open("partition", b"test_blob").await.unwrap();

        let write_task = tokio::spawn({
            let blob = blob.clone();
            async move {
                blob.write_at(b"concurrent write", 0).await.unwrap();
            }
        });

        let read_task = tokio::spawn({
            let blob = blob.clone();
            async move {
                let mut buffer = vec![0; 16];
                blob.read_at(&mut buffer, 0).await.unwrap();
                buffer
            }
        });

        write_task.await.unwrap();
        let buffer = read_task.await.unwrap();

        assert_eq!(buffer, b"concurrent write", "Concurrent access failed");
    }

    /// Test handling of large data sizes.
    async fn test_large_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage.open("partition", b"large_blob").await.unwrap();

        let large_data = vec![42u8; 10 * 1024 * 1024]; // 10 MB
        blob.write_at(&large_data, 0).await.unwrap();

        let mut buffer = vec![0u8; 10 * 1024 * 1024];
        blob.read_at(&mut buffer, 0).await.unwrap();

        assert_eq!(buffer, large_data, "Large data read/write failed");
    }

    /// Test metrics tracking for MeteredStorage.
    #[tokio::test]
    async fn test_metered_storage() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = MeteredStorage::new(inner, &mut registry);

        run_storage_tests(storage).await;
    }

    /// Test auditing behavior for AuditedStorage.
    #[tokio::test]
    async fn test_audited_storage() {
        let inner = MemoryStorage::default();
        let auditor = Arc::new(crate::deterministic::Auditor::default());
        let storage = AuditedStorage::new(inner, auditor);

        run_storage_tests(storage).await;
    }

    /// Test TokioStorage with a temporary directory.
    #[tokio::test]
    async fn test_tokio_storage() {
        let temp_dir = tempdir().unwrap();
        let config = crate::storage::tokio_storage::Config::new(temp_dir.path().to_path_buf());
        let storage = TokioStorage::new(config);

        run_storage_tests(storage).await;
    }

    /// Test MemoryStorage.
    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::default();
        run_storage_tests(storage).await;
    }
}

#[cfg(test)]
mod extended_tests {
    use crate::storage::{
        audited::Storage as AuditedStorage, memory::Storage as MemoryStorage,
        metered::MeteredStorage, tokio_storage::Storage as TokioStorage,
    };
    use crate::{Blob, Storage};
    use prometheus_client::registry::Registry;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// Test overwriting data in a blob.
    async fn test_overwrite_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage
            .open("test_overwrite_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(b"initial data", 0).await.unwrap();

        // Overwrite part of the data
        blob.write_at(b"overwrite", 8).await.unwrap();

        // Read back the data
        let mut buffer = vec![0; 17];
        blob.read_at(&mut buffer, 0).await.unwrap();

        assert_eq!(
            buffer, b"initial overwrite",
            "Data was not overwritten correctly"
        );
    }

    /// Test reading from an offset beyond the written data.
    async fn test_read_beyond_bound<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage
            .open("test_read_beyond_written_data", b"test_blob")
            .await
            .unwrap();

        // Write some data
        blob.write_at(b"hello", 0).await.unwrap();

        // Attempt to read beyond the written data
        let mut buffer = vec![0; 10];
        let result = blob.read_at(&mut buffer, 6).await;

        assert!(
            result.is_err(),
            "Reading beyond written data should return an error"
        );
    }

    /// Test writing data at a large offset.
    async fn test_write_at_large_offset<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage
            .open("test_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        // Write data at a large offset
        blob.write_at(b"offset data", 10_000).await.unwrap();

        // Read back the data
        let mut buffer = vec![0; 11];
        blob.read_at(&mut buffer, 10_000).await.unwrap();

        assert_eq!(buffer, b"offset data", "Data at large offset is incorrect");
    }

    /// Test appending data to a blob.
    async fn test_append_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage
            .open("test_append_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(b"first", 0).await.unwrap();

        // Append data
        blob.write_at(b"second", 5).await.unwrap();

        // Read back the data
        let mut buffer = vec![0; 11];
        blob.read_at(&mut buffer, 0).await.unwrap();

        assert_eq!(buffer, b"firstsecond", "Appended data is incorrect");
    }

    /// Test reading and writing with interleaved offsets.
    async fn test_sequential_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage.open("partition", b"test_blob").await.unwrap();

        // Write data at different offsets
        blob.write_at(b"first", 0).await.unwrap();
        blob.write_at(b"second", 10).await.unwrap();

        // Read back the data
        let mut buffer1 = vec![0; 5];
        blob.read_at(&mut buffer1, 0).await.unwrap();

        let mut buffer2 = vec![0; 6];
        blob.read_at(&mut buffer2, 10).await.unwrap();

        assert_eq!(buffer1, b"first", "Data at offset 0 is incorrect");
        assert_eq!(buffer2, b"second", "Data at offset 10 is incorrect");
    }

    /// Test writing and reading large data in chunks.
    async fn test_sequential_chunk_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage
            .open("test_large_data_in_chunks", b"large_blob")
            .await
            .unwrap();

        let chunk_size = 1024 * 1024; // 1 MB
        let num_chunks = 10;
        let data = vec![7u8; chunk_size];

        // Write data in chunks
        for i in 0..num_chunks {
            blob.write_at(&data, (i * chunk_size) as u64).await.unwrap();
        }

        // Read back the data in chunks
        for i in 0..num_chunks {
            let mut buffer = vec![0u8; chunk_size];
            blob.read_at(&mut buffer, (i * chunk_size) as u64)
                .await
                .unwrap();
            assert_eq!(buffer, data, "Chunk {} is incorrect", i);
        }
    }

    /// Test reading from an empty blob.
    async fn test_read_empty_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage
            .open("test_read_empty_blob", b"empty_blob")
            .await
            .unwrap();

        let mut buffer = vec![0; 1];
        let result = blob.read_at(&mut buffer, 0).await;

        assert!(
            result.is_err(),
            "Reading from an empty blob should return an error"
        );
    }

    /// Test writing and reading with overlapping writes.
    async fn test_overlapping_writes<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let blob = storage
            .open("test_overlapping_writes", b"test_blob")
            .await
            .unwrap();

        // Write overlapping data
        blob.write_at(b"overlap", 0).await.unwrap();
        blob.write_at(b"map", 4).await.unwrap();

        // Read back the data
        let mut buffer = vec![0; 7];
        blob.read_at(&mut buffer, 0).await.unwrap();

        assert_eq!(buffer, b"overmap", "Overlapping writes are incorrect");
    }

    /// Add the new tests to the test suite.
    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::default();
        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_append_data(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
    }

    #[tokio::test]
    async fn test_tokio_storage() {
        let temp_dir = tempdir().unwrap();
        let config = crate::storage::tokio_storage::Config::new(temp_dir.path().to_path_buf());
        let storage = TokioStorage::new(config);

        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_append_data(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
    }

    #[tokio::test]
    async fn test_audited_storage() {
        let inner = MemoryStorage::default();
        let auditor = Arc::new(crate::deterministic::Auditor::default());
        let storage = AuditedStorage::new(inner, auditor.clone());

        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_append_data(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
    }

    #[tokio::test]
    async fn test_metered_storage() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = MeteredStorage::new(inner, &mut registry);

        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_append_data(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
    }
}
