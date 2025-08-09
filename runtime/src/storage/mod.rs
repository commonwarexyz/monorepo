//! Implementations of the `Storage` trait that can be used by the runtime.
pub mod audited;
#[cfg(feature = "iouring-storage")]
pub mod iouring;
pub mod memory;
pub mod metered;
#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
pub mod tokio;

#[cfg(test)]
pub(crate) mod tests {
    use crate::{Blob, Storage};

    /// Runs the full suite of tests on the provided storage implementation.
    pub(crate) async fn run_storage_tests<S>(storage: S)
    where
        S: Storage + Send + Sync + 'static,
        S::Blob: Send + Sync,
    {
        test_open_and_write(&storage).await;
        test_remove(&storage).await;
        test_scan(&storage).await;
        test_concurrent_access(&storage).await;
        test_large_data(&storage).await;
        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_append_data(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
        test_resize_then_open(&storage).await;
    }

    /// Test opening a blob, writing to it, and reading back the data.
    async fn test_open_and_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(Vec::from("hello world"), 0).await.unwrap();
        let read = blob.read_at(vec![0; 11], 0).await.unwrap();

        assert_eq!(
            read.as_ref(),
            b"hello world",
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
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Initialize blob with data of sufficient length first
        blob.write_at(b"concurrent write".to_vec(), 0)
            .await
            .unwrap();

        // Read and write concurrently
        let write_task = tokio::spawn({
            let blob = blob.clone();
            async move {
                blob.write_at(b"concurrent write".to_vec(), 0)
                    .await
                    .unwrap();
            }
        });

        let read_task = tokio::spawn({
            let blob = blob.clone();
            async move { blob.read_at(vec![0; 16], 0).await.unwrap() }
        });

        write_task.await.unwrap();
        let buffer = read_task.await.unwrap();

        assert_eq!(
            buffer.as_ref(),
            b"concurrent write",
            "Concurrent access failed"
        );
    }

    /// Test handling of large data sizes.
    async fn test_large_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"large_blob").await.unwrap();

        let large_data = vec![42u8; 10 * 1024 * 1024]; // 10 MB
        blob.write_at(large_data.clone(), 0).await.unwrap();

        let read = blob.read_at(vec![0; 10 * 1024 * 1024], 0).await.unwrap();

        assert_eq!(read.as_ref(), large_data, "Large data read/write failed");
    }

    /// Test overwriting data in a blob.
    async fn test_overwrite_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_overwrite_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(b"initial data".to_vec(), 0).await.unwrap();

        // Overwrite part of the data
        blob.write_at(b"overwrite".to_vec(), 8).await.unwrap();

        // Read back the data
        let read = blob.read_at(vec![0; 17], 0).await.unwrap();

        assert_eq!(
            read.as_ref(),
            b"initial overwrite",
            "Data was not overwritten correctly"
        );
    }

    /// Test reading from an offset beyond the written data.
    async fn test_read_beyond_bound<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_beyond_written_data", b"test_blob")
            .await
            .unwrap();

        // Write some data
        blob.write_at(b"hello".to_vec(), 0).await.unwrap();

        // Attempt to read beyond the written data
        let result = blob.read_at(vec![0; 10], 6).await;

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
        let (blob, _) = storage
            .open("test_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        // Write data at a large offset
        blob.write_at(b"offset data".to_vec(), 10_000)
            .await
            .unwrap();

        // Read back the data
        let read = blob.read_at(vec![0; 11], 10_000).await.unwrap();
        assert_eq!(
            read.as_ref(),
            b"offset data",
            "Data at large offset is incorrect"
        );
    }

    /// Test appending data to a blob.
    async fn test_append_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_append_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(b"first".to_vec(), 0).await.unwrap();

        // Append data
        blob.write_at(b"second".to_vec(), 5).await.unwrap();

        // Read back the data
        let read = blob.read_at(vec![0; 11], 0).await.unwrap();
        assert_eq!(read.as_ref(), b"firstsecond", "Appended data is incorrect");
    }

    /// Test reading and writing with interleaved offsets.
    async fn test_sequential_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Write data at different offsets
        blob.write_at(b"first".to_vec(), 0).await.unwrap();
        blob.write_at(b"second".to_vec(), 10).await.unwrap();

        // Read back the data
        let read = blob.read_at(vec![0; 5], 0).await.unwrap();
        assert_eq!(read.as_ref(), b"first", "Data at offset 0 is incorrect");

        let read = blob.read_at(vec![0; 6], 10).await.unwrap();
        assert_eq!(read.as_ref(), b"second", "Data at offset 10 is incorrect");
    }

    /// Test writing and reading large data in chunks.
    async fn test_sequential_chunk_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_large_data_in_chunks", b"large_blob")
            .await
            .unwrap();

        let chunk_size = 1024 * 1024; // 1 MB
        let num_chunks = 10;
        let data = vec![7u8; chunk_size];

        // Write data in chunks
        for i in 0..num_chunks {
            blob.write_at(data.clone(), (i * chunk_size) as u64)
                .await
                .unwrap();
        }

        // Read back the data in chunks
        let mut read = vec![0u8; chunk_size].into();
        for i in 0..num_chunks {
            read = blob.read_at(read, (i * chunk_size) as u64).await.unwrap();
            assert_eq!(read.as_ref(), data, "Chunk {i} is incorrect");
        }
    }

    /// Test reading from an empty blob.
    async fn test_read_empty_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_empty_blob", b"empty_blob")
            .await
            .unwrap();

        let result = blob.read_at(vec![0; 1], 0).await;
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
        let (blob, _) = storage
            .open("test_overlapping_writes", b"test_blob")
            .await
            .unwrap();

        // Write overlapping data
        blob.write_at(b"overlap".to_vec(), 0).await.unwrap();
        blob.write_at(b"map".to_vec(), 4).await.unwrap();

        // Read back the data
        let read = blob.read_at(vec![0; 7], 0).await.unwrap();
        assert_eq!(
            read.as_ref(),
            b"overmap",
            "Overlapping writes are incorrect"
        );
    }

    async fn test_resize_then_open<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        {
            let (blob, _) = storage
                .open("test_resize_then_open", b"test_blob")
                .await
                .unwrap();

            // Write some data
            blob.write_at(b"hello world".to_vec(), 0).await.unwrap();

            // Resize the blob
            blob.resize(5).await.unwrap();

            // Sync the blob
            blob.sync().await.unwrap();
        }

        // Reopen the blob
        let (blob, len) = storage
            .open("test_resize_then_open", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 5, "Blob length after resize is incorrect");

        // Read back the data
        let read = blob.read_at(vec![0; 5], 0).await.unwrap();
        assert_eq!(read.as_ref(), b"hello", "Resized data is incorrect");
    }
}
