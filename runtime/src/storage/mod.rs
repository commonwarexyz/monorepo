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
        let inner = MemoryStorage::new();
        let storage = MeteredStorage::new(inner, &mut registry);

        run_storage_tests(storage).await;
    }

    /// Test auditing behavior for AuditedStorage.
    #[tokio::test]
    async fn test_audited_storage() {
        let inner = MemoryStorage::new();
        let auditor = Arc::new(crate::deterministic::Auditor::new());
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
        let storage = MemoryStorage::new();
        run_storage_tests(storage).await;
    }
}
