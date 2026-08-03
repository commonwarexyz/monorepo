//! Implementations of the `Storage` trait that can be used by the runtime.

use commonware_macros::stability_scope;

stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    /// Flush the whole filesystem containing `dir` at startup so that bytes a prior process wrote
    /// but did not `fsync` are crash-durable before any storage structure reads.
    ///
    /// Per-platform guarantee:
    /// - **Linux**: `syncfs(2)` makes all data on the storage filesystem crash-durable.
    /// - **macOS/BSD**: best-effort `sync(2)`; it does not flush the drive cache, so it is **not**
    ///   crash-durable.
    ///
    /// Assumes storage lives on a single filesystem; on Linux reliable error detection needs kernel
    /// >= 5.8. A missing `dir` is treated as success.
    pub(crate) fn sync(dir: &std::path::Path) -> std::io::Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                use std::os::fd::AsRawFd;
                let file = match std::fs::File::open(dir) {
                    Ok(file) => file,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(e) => return Err(e),
                };
                // SAFETY: `file` owns a valid fd that lives across the call; `syncfs` takes only
                // that fd, performs no memory access, and returns -1 on error.
                if unsafe { libc::syncfs(file.as_raw_fd()) } == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                tracing::debug!(
                    storage_directory = %dir.display(),
                    "made storage filesystem durable at startup (syncfs)"
                );
                Ok(())
            } else {
                // SAFETY: `sync` takes no arguments and cannot fail.
                unsafe { libc::sync() };
                tracing::debug!(
                    storage_directory = %dir.display(),
                    "best-effort storage flush at startup (sync(); not a crash-durability guarantee)"
                );
                Ok(())
            }
        }
    }
});

stability_scope!(ALPHA {
    pub mod audited;
    pub mod faulty;
    pub mod memory;
});
stability_scope!(ALPHA, cfg(feature = "iouring-storage") {
    pub mod iouring;
});
stability_scope!(BETA, cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage"))) {
    pub mod tokio;
});
stability_scope!(BETA {
    pub mod metered;

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) mod atomic;
    pub(crate) mod batch;
    #[cfg(not(target_arch = "wasm32"))]
    mod generation;
    mod header;
    #[cfg(not(target_arch = "wasm32"))]
    mod preflush;
    pub(crate) use header::{Header, Layout};

    /// Validate that a partition name contains only allowed characters.
    ///
    /// Partition names must only contain alphanumeric characters, dashes ('-'),
    /// or underscores ('_').
    pub fn validate_partition_name(partition: &str) -> Result<(), crate::Error> {
        if partition.is_empty()
            || partition
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || ['_', '-'].contains(&c)))
        {
            return Err(crate::Error::PartitionNameInvalid(partition.into()));
        }
        Ok(())
    }
});

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        ATOMIC_BLOB_TAG_LEN, AtomicBlob, AtomicStorage, BatchOperation, BatchStorage, Blob, Buf,
        IoBuf, IoBufMut, IoBufs, IoBufsMut, Storage, WriteOptions,
    };
    use futures::FutureExt;

    /// Runs the full suite of tests on the provided storage implementation.
    pub(crate) async fn run_storage_tests<S>(storage: S)
    where
        S: Storage + Send + Sync + 'static,
        S::Blob: Send + Sync,
    {
        test_open_and_write(&storage).await;
        test_remove(&storage).await;
        test_read_after_remove_blob(&storage).await;
        test_read_after_remove_partition(&storage).await;
        test_recreate_after_remove(&storage).await;
        test_read_after_remove_unsynced(&storage).await;
        test_read_after_remove_handle_clones(&storage).await;
        test_recreate_generations(&storage).await;
        test_read_after_remove_partition_multi(&storage).await;
        test_scan(&storage).await;
        test_concurrent_access(&storage).await;
        test_large_data(&storage).await;
        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_write_at_sync(&storage).await;
        test_start_sync(&storage).await;
        test_append_data(&storage).await;
        test_vectored_write_at(&storage).await;
        test_vectored_write_at_large_offset(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
        test_resize_then_open(&storage).await;
        test_partition_name_validation(&storage).await;
        test_blob_version_mismatch(&storage).await;
        test_aligned_layout(&storage).await;
        test_read_zero_length(&storage).await;
        test_read_at_buf_returns_same_buffer(&storage).await;
        test_read_at_buf_insufficient_capacity(&storage).await;
        test_read_at_buf_larger_capacity(&storage).await;
    }

    /// Runs the batch-specific suite on an opt-in storage implementation.
    pub(crate) async fn run_batch_storage_tests<S>(storage: S)
    where
        S: BatchStorage<AtomicBlob = <S as Storage>::Blob> + Send + Sync + 'static,
        <S as Storage>::Blob: AtomicBlob + Send + Sync,
    {
        test_start_apply_is_self_driving(&storage).await;
        test_apply_batch_deduplication(&storage).await;
        test_apply_batch_mixed_success(&storage).await;
        test_apply_batch_publishes_two_pending_blobs(&storage).await;
        test_apply_batch_publishes_tags(&storage).await;
        test_apply_batch_does_not_charge_clean_publishes_to_witness(&storage).await;
        test_apply_batch_carries_consecutive_publications(&storage).await;
        test_apply_batch_carries_disjoint_publications(&storage).await;
        test_direct_sync_transitions_to_and_from_a_group(&storage).await;
        test_apply_batch_rejects_non_atomic_handle(&storage).await;
        test_apply_batch_validates_atomically(&storage).await;
        test_apply_batch_validates_all_rewinds_before_mutating(&storage).await;
        test_apply_batch_conflicts_are_atomic(&storage).await;
        test_apply_batch_rejects_stale_handle(&storage).await;
    }

    /// Runs explicit ordinary-to-atomic migration semantics on an opt-in storage implementation.
    pub(crate) async fn run_atomic_storage_tests<S>(storage: S)
    where
        S: AtomicStorage + Send + Sync + 'static,
        S::Blob: Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        test_migrate_atomic_preserves_contents_and_version(&storage).await;
        test_migrate_atomic_rejects_stale_handle(&storage).await;
        test_atomic_tag_persistence(&storage).await;
    }

    /// Migration replaces one exact name generation while preserving logical bytes and version.
    async fn test_migrate_atomic_preserves_contents_and_version<S>(storage: &S)
    where
        S: AtomicStorage + Send + Sync,
        S::Blob: Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        const VERSION: u16 = 7;
        let expected = (0..160_003u64)
            .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
            .collect::<Vec<_>>();
        let (blob, len, version) = storage
            .open_versioned("migrate_atomic", b"blob", VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(len, 0);
        assert_eq!(version, VERSION);
        blob.write_at(0, expected.clone(), WriteOptions::default())
            .await
            .unwrap();
        let prior = blob.clone();

        storage.migrate_atomic(blob).await.unwrap();

        let (atomic, len, version) = storage
            .open_atomic_versioned("migrate_atomic", b"blob", VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(len, expected.len() as u64);
        assert_eq!(version, VERSION);
        assert_eq!(atomic.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(
            atomic.read_at(0, expected.len()).await.unwrap().coalesce(),
            expected.as_slice()
        );
        assert_eq!(
            prior.read_at(0, expected.len()).await.unwrap().coalesce(),
            expected.as_slice()
        );

        atomic.append(b"tail").await.unwrap();
        atomic.sync().await.unwrap();
        assert!(prior.read_at(expected.len() as u64, 1).await.is_err());
        assert!(storage.migrate_atomic(prior.clone()).await.is_err());
        drop(prior);

        // Migrating an ordinary handle to an existing V2 blob neither replaces nor invalidates it.
        let (ordinary, len, version) = storage
            .open_versioned("migrate_atomic", b"blob", VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(len, expected.len() as u64 + 4);
        assert_eq!(version, VERSION);
        storage.migrate_atomic(ordinary).await.unwrap();
        assert_eq!(
            atomic.append(b"!").await.unwrap(),
            expected.len() as u64 + 4
        );
        atomic.sync().await.unwrap();
        drop(atomic);
        let (atomic, len, version) = storage
            .open_atomic_versioned("migrate_atomic", b"blob", VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(len, expected.len() as u64 + 5);
        assert_eq!(version, VERSION);
        assert_eq!(
            atomic
                .read_at(expected.len() as u64, 5)
                .await
                .unwrap()
                .coalesce(),
            b"tail!"
        );
    }

    /// Tags share the synchronization boundary with an atomic blob's logical length.
    async fn test_atomic_tag_persistence<S>(storage: &S)
    where
        S: AtomicStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        const SYNC_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [1; ATOMIC_BLOB_TAG_LEN];
        const START_SYNC_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [2; ATOMIC_BLOB_TAG_LEN];
        const APPEND_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [3; ATOMIC_BLOB_TAG_LEN];
        const REWIND_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [4; ATOMIC_BLOB_TAG_LEN];

        let (blob, len) = storage.open_atomic("atomic_tags", b"blob").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);

        blob.set_tag(SYNC_TAG).await.unwrap();
        assert_eq!(blob.tag().await.unwrap(), SYNC_TAG);
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, len) = storage.open_atomic("atomic_tags", b"blob").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), SYNC_TAG);

        blob.set_tag(START_SYNC_TAG).await.unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);

        let (blob, len) = storage.open_atomic("atomic_tags", b"blob").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), START_SYNC_TAG);

        blob.append_tagged(b"abcdef", APPEND_TAG).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, len) = storage.open_atomic("atomic_tags", b"blob").await.unwrap();
        assert_eq!(len, 6);
        assert_eq!(blob.read_at(0, 6).await.unwrap().coalesce(), b"abcdef");
        assert_eq!(blob.tag().await.unwrap(), APPEND_TAG);

        blob.rewind_tagged(3, REWIND_TAG).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, len) = storage.open_atomic("atomic_tags", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        assert_eq!(blob.tag().await.unwrap(), REWIND_TAG);
    }

    /// A removed handle cannot replace a newer same-name blob generation during migration.
    async fn test_migrate_atomic_rejects_stale_handle<S>(storage: &S)
    where
        S: AtomicStorage + Send + Sync,
        S::Blob: Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (stale, _) = storage.open("migrate_atomic_stale", b"blob").await.unwrap();
        stale
            .write_at(0, b"stale", WriteOptions::SYNC)
            .await
            .unwrap();
        storage
            .remove("migrate_atomic_stale", Some(b"blob"))
            .await
            .unwrap();
        let (replacement, _) = storage.open("migrate_atomic_stale", b"blob").await.unwrap();
        replacement
            .write_at(0, b"replacement", WriteOptions::SYNC)
            .await
            .unwrap();

        assert!(storage.migrate_atomic(stale).await.is_err());
        assert_eq!(
            replacement.read_at(0, 11).await.unwrap().coalesce(),
            b"replacement"
        );
        assert!(
            storage
                .open_atomic("migrate_atomic_stale", b"blob")
                .await
                .is_err()
        );
    }

    /// Runs append, rewind, and synchronization-fence semantics on an atomic blob.
    pub(crate) async fn run_atomic_blob_tests<B>(blob: B)
    where
        B: AtomicBlob,
    {
        const APPEND_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [5; ATOMIC_BLOB_TAG_LEN];
        const REWIND_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [6; ATOMIC_BLOB_TAG_LEN];

        assert_eq!(blob.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
        blob.set_tag(APPEND_TAG).await.unwrap();
        assert_eq!(blob.tag().await.unwrap(), APPEND_TAG);
        assert_eq!(
            blob.append(vec![IoBuf::from(b"ab"), IoBuf::from(b"cdef")])
                .await
                .unwrap(),
            0
        );
        assert_eq!(blob.read_at(0, 6).await.unwrap().coalesce(), b"abcdef");

        assert!(
            blob.write_at(0, b"x", WriteOptions::default())
                .await
                .is_err()
        );
        assert_eq!(blob.read_at(0, 6).await.unwrap().coalesce(), b"abcdef");

        blob.set_tag(REWIND_TAG).await.unwrap();
        assert_eq!(blob.tag().await.unwrap(), REWIND_TAG);
        blob.rewind(4).await.unwrap();
        assert_eq!(blob.append(b"XY").await.unwrap(), 4);
        assert_eq!(blob.read_at(0, 6).await.unwrap().coalesce(), b"abcdXY");
        blob.sync().await.unwrap();
        assert_eq!(blob.tag().await.unwrap(), REWIND_TAG);

        blob.rewind(3).await.unwrap();
        assert!(blob.append(b"blocked").await.is_err());
        assert_eq!(blob.append(Vec::<u8>::new()).await.unwrap(), 3);
        assert!(blob.resize(4).await.is_err());
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        blob.sync().await.unwrap();
        assert_eq!(blob.append(b"Z").await.unwrap(), 3);
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"abcZ");
    }

    /// Verify that mutations cannot accept handles from another backend instance.
    pub(crate) async fn run_storage_foreign_handle_test<S>(storage: &S, foreign_storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::Blob: Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (local, _) = storage
            .open_atomic("batch_foreign_handle", b"shared_name")
            .await
            .unwrap();
        local.append(b"local").await.unwrap();
        local.sync().await.unwrap();
        let (foreign, _) = foreign_storage
            .open_atomic("batch_foreign_handle", b"shared_name")
            .await
            .unwrap();
        foreign.append(b"foreign").await.unwrap();
        foreign.sync().await.unwrap();

        let result = storage
            .apply(vec![
                BatchOperation::Remove(local.clone()),
                BatchOperation::Remove(foreign.clone()),
            ])
            .await;
        assert!(matches!(result, Err(crate::Error::BlobMissing(..))));

        assert_eq!(
            local.read_at(0, 5).await.unwrap().coalesce(),
            b"local",
            "a foreign duplicate must reject the batch before the local removal"
        );
        assert_eq!(
            foreign.read_at(0, 7).await.unwrap().coalesce(),
            b"foreign",
            "a rejected foreign removal must not mutate its source blob"
        );
        assert_eq!(
            storage.scan("batch_foreign_handle").await.unwrap(),
            vec![b"shared_name".to_vec()]
        );

        let (foreign_v1, _) = foreign_storage
            .open("migration_foreign_v1", b"blob")
            .await
            .unwrap();
        foreign_v1
            .write_at(0, b"foreign-v1", WriteOptions::SYNC)
            .await
            .unwrap();
        let readable_v1 = foreign_v1.clone();
        assert!(matches!(
            storage.migrate_atomic(foreign_v1).await,
            Err(crate::Error::BlobMissing(..))
        ));
        assert_eq!(
            readable_v1.read_at(0, 10).await.unwrap().coalesce(),
            b"foreign-v1"
        );
        assert!(
            foreign_storage
                .open_atomic("migration_foreign_v1", b"blob")
                .await
                .is_err()
        );

        let (foreign_atomic, _) = foreign_storage
            .open_atomic("migration_foreign_v2", b"blob")
            .await
            .unwrap();
        foreign_atomic.append(b"foreign-v2").await.unwrap();
        foreign_atomic.sync().await.unwrap();
        drop(foreign_atomic);
        let (foreign_v2, _) = foreign_storage
            .open("migration_foreign_v2", b"blob")
            .await
            .unwrap();
        let readable_v2 = foreign_v2.clone();
        assert!(matches!(
            storage.migrate_atomic(foreign_v2).await,
            Err(crate::Error::BlobMissing(..))
        ));
        assert_eq!(
            readable_v2.read_at(0, 10).await.unwrap().coalesce(),
            b"foreign-v2"
        );
    }

    /// Test opening a blob, writing to it, and reading back the data.
    async fn test_open_and_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();
        let read = blob.read_at(0, 11).await.unwrap();

        assert_eq!(
            read.coalesce(),
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

    /// Once intent is committed, aborting its observer does not cancel physical application.
    async fn test_start_apply_is_self_driving<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (removed, _) = storage
            .open_atomic("batch_start_removed", b"victim")
            .await
            .unwrap();
        removed.append(b"remove me").await.unwrap();
        removed.sync().await.unwrap();
        let (retained, _) = storage
            .open_atomic("batch_start_retained", b"blob")
            .await
            .unwrap();
        retained.append(b"old bytes").await.unwrap();
        retained.sync().await.unwrap();
        let completion = storage
            .start_apply(vec![
                BatchOperation::Remove(removed.clone()),
                BatchOperation::Rewind {
                    blob: retained.clone(),
                    len: 3,
                },
            ])
            .await
            .unwrap();
        completion.abort();
        drop(completion);

        assert!(
            storage
                .scan("batch_start_removed")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(removed.read_at(0, 1).await.unwrap().coalesce(), b"r");
        assert!(removed.sync().await.is_err());
        assert_eq!(retained.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert!(retained.read_at(3, 1).await.is_err());
    }

    /// Identical exact removals and rewinds are idempotent within one batch.
    async fn test_apply_batch_deduplication<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        storage.apply(Vec::new()).await.unwrap();
        let (one, _) = storage.open_atomic("batch_set_a", b"one").await.unwrap();
        one.append(b"one").await.unwrap();
        one.sync().await.unwrap();
        let (two, _) = storage.open_atomic("batch_set_a", b"two").await.unwrap();
        two.append(b"two").await.unwrap();
        two.sync().await.unwrap();
        storage.open_atomic("batch_set_a", b"keep").await.unwrap();
        let (victim, _) = storage.open_atomic("batch_set_b", b"victim").await.unwrap();
        victim.append(b"victim").await.unwrap();
        victim.sync().await.unwrap();
        let (resized, _) = storage
            .open_atomic("batch_set_resize", b"blob")
            .await
            .unwrap();
        resized.append(b"abcdef").await.unwrap();

        let operations = vec![
            BatchOperation::Rewind {
                blob: resized.clone(),
                len: 3,
            },
            BatchOperation::Remove(two.clone()),
            BatchOperation::Remove(victim.clone()),
            BatchOperation::Remove(one.clone()),
            BatchOperation::Remove(two.clone()),
            BatchOperation::Rewind {
                blob: resized.clone(),
                len: 3,
            },
        ];
        storage.apply(operations).await.unwrap();

        let mut blobs = storage.scan("batch_set_a").await.unwrap();
        blobs.sort();
        assert_eq!(blobs, vec![b"keep".to_vec()]);
        assert!(storage.scan("batch_set_b").await.unwrap().is_empty());
        assert_eq!(one.read_at(0, 3).await.unwrap().coalesce(), b"one");
        assert_eq!(two.read_at(0, 3).await.unwrap().coalesce(), b"two");
        assert_eq!(victim.read_at(0, 6).await.unwrap().coalesce(), b"victim");
        assert_eq!(resized.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        assert!(resized.read_at(3, 1).await.is_err());
    }

    /// Pending blob contents, retained mutations, and removals commit together.
    async fn test_apply_batch_mixed_success<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (published, _) = storage
            .open_atomic("batch_mixed_publish", b"published")
            .await
            .unwrap();
        published.append(b"published-value").await.unwrap();
        let (resized, _) = storage
            .open_atomic("batch_mixed_resize", b"resized")
            .await
            .unwrap();
        resized.append(b"pending bytes").await.unwrap();
        let (removed, _) = storage
            .open_atomic("batch_mixed_remove", b"victim")
            .await
            .unwrap();
        removed.append(b"removed").await.unwrap();
        removed.sync().await.unwrap();
        let (second_removed, _) = storage
            .open_atomic("batch_mixed_second_remove", b"victim")
            .await
            .unwrap();
        second_removed.append(b"also removed").await.unwrap();
        second_removed.sync().await.unwrap();
        storage.open("batch_mixed_keep", b"survivor").await.unwrap();

        storage
            .apply(vec![
                BatchOperation::Remove(removed.clone()),
                BatchOperation::Publish(published.clone()),
                BatchOperation::Rewind {
                    blob: resized.clone(),
                    len: 7,
                },
                BatchOperation::Remove(second_removed.clone()),
            ])
            .await
            .unwrap();

        drop(published);
        drop(resized);
        let (published, len) = storage
            .open_atomic("batch_mixed_publish", b"published")
            .await
            .unwrap();
        assert_eq!(len, 15);
        assert_eq!(
            published.read_at(0, 15).await.unwrap().coalesce(),
            b"published-value"
        );
        let (resized, len) = storage
            .open_atomic("batch_mixed_resize", b"resized")
            .await
            .unwrap();
        assert_eq!(len, 7);
        assert_eq!(resized.read_at(0, 7).await.unwrap().coalesce(), b"pending");
        assert!(storage.scan("batch_mixed_remove").await.unwrap().is_empty());
        assert!(
            storage
                .scan("batch_mixed_second_remove")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(removed.read_at(0, 7).await.unwrap().coalesce(), b"removed");
        assert_eq!(
            second_removed.read_at(0, 12).await.unwrap().coalesce(),
            b"also removed"
        );
        assert_eq!(
            storage.scan("batch_mixed_keep").await.unwrap(),
            vec![b"survivor".to_vec()],
        );
    }

    /// Two pending atomic blobs are published completely by one batch.
    async fn test_apply_batch_publishes_two_pending_blobs<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (first, _) = storage
            .open_atomic("batch_publish_two", b"first")
            .await
            .unwrap();
        first
            .append(vec![IoBuf::from(b"atomic-"), IoBuf::from(b"first")])
            .await
            .unwrap();
        let (second, _) = storage
            .open_atomic("batch_publish_two", b"second")
            .await
            .unwrap();
        second
            .append(vec![
                IoBuf::from(b"second"),
                IoBuf::from(b"-"),
                IoBuf::from(b"value"),
            ])
            .await
            .unwrap();

        storage
            .apply(vec![
                BatchOperation::Publish(first.clone()),
                BatchOperation::Publish(second.clone()),
            ])
            .await
            .unwrap();

        drop(first);
        drop(second);
        let (first, first_len) = storage
            .open_atomic("batch_publish_two", b"first")
            .await
            .unwrap();
        let (second, second_len) = storage
            .open_atomic("batch_publish_two", b"second")
            .await
            .unwrap();
        assert_eq!(first_len, 12);
        assert_eq!(second_len, 12);
        assert_eq!(
            first.read_at(0, 12).await.unwrap().coalesce(),
            b"atomic-first"
        );
        assert_eq!(
            second.read_at(0, 12).await.unwrap().coalesce(),
            b"second-value"
        );
    }

    /// A batch publishes data-bearing and metadata-only tags, which need not be unique.
    async fn test_apply_batch_publishes_tags<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        const FIRST_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [7; ATOMIC_BLOB_TAG_LEN];
        const SECOND_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [8; ATOMIC_BLOB_TAG_LEN];
        const SHARED_TAG: [u8; ATOMIC_BLOB_TAG_LEN] = [9; ATOMIC_BLOB_TAG_LEN];

        let (first, _) = storage
            .open_atomic("batch_publish_tags", b"first")
            .await
            .unwrap();
        first.append(b"payload").await.unwrap();
        first.set_tag(FIRST_TAG).await.unwrap();
        let (second, _) = storage
            .open_atomic("batch_publish_tags", b"second")
            .await
            .unwrap();
        second.set_tag(SECOND_TAG).await.unwrap();

        storage
            .apply(vec![
                BatchOperation::Publish(first.clone()),
                BatchOperation::Publish(second.clone()),
            ])
            .await
            .unwrap();

        drop(first);
        drop(second);
        let (first, first_len) = storage
            .open_atomic("batch_publish_tags", b"first")
            .await
            .unwrap();
        let (second, second_len) = storage
            .open_atomic("batch_publish_tags", b"second")
            .await
            .unwrap();
        assert_eq!(first_len, 7);
        assert_eq!(second_len, 0);
        assert_eq!(first.read_at(0, 7).await.unwrap().coalesce(), b"payload");
        assert_eq!(first.tag().await.unwrap(), FIRST_TAG);
        assert_eq!(second.tag().await.unwrap(), SECOND_TAG);

        first.set_tag(SHARED_TAG).await.unwrap();
        second.set_tag(SHARED_TAG).await.unwrap();
        storage
            .apply(vec![
                BatchOperation::Publish(first.clone()),
                BatchOperation::Publish(second.clone()),
            ])
            .await
            .unwrap();

        drop(first);
        drop(second);
        let (first, _) = storage
            .open_atomic("batch_publish_tags", b"first")
            .await
            .unwrap();
        let (second, _) = storage
            .open_atomic("batch_publish_tags", b"second")
            .await
            .unwrap();
        assert_eq!(first.tag().await.unwrap(), SHARED_TAG);
        assert_eq!(second.tag().await.unwrap(), SHARED_TAG);
    }

    /// Clean publications do not occupy the embedded descriptor carried by dirty participants.
    async fn test_apply_batch_does_not_charge_clean_publishes_to_witness<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let mut operations = Vec::new();
        for name in 0u8..28 {
            let (blob, _) = storage.open_atomic("p", &[name]).await.unwrap();
            operations.push(BatchOperation::Publish(blob));
        }
        let (dirty, _) = storage.open_atomic("p", b"dirty").await.unwrap();
        dirty.append(b"value").await.unwrap();
        operations.push(BatchOperation::Publish(dirty.clone()));

        storage.apply(operations).await.unwrap();
        assert_eq!(dirty.read_at(0, 5).await.unwrap().coalesce(), b"value");
    }

    /// A later batch can durably supersede a still-authoritative prior decision.
    async fn test_apply_batch_carries_consecutive_publications<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (first, _) = storage.open_atomic("batch_carry", b"first").await.unwrap();
        let (second, _) = storage.open_atomic("batch_carry", b"second").await.unwrap();

        for suffix in *b"12" {
            first.append(vec![b'f', suffix]).await.unwrap();
            second.append(vec![b's', suffix]).await.unwrap();
            storage
                .apply(vec![
                    BatchOperation::Publish(first.clone()),
                    BatchOperation::Publish(second.clone()),
                ])
                .await
                .unwrap();
        }

        drop(first);
        drop(second);
        let (first, first_len) = storage.open_atomic("batch_carry", b"first").await.unwrap();
        let (second, second_len) = storage.open_atomic("batch_carry", b"second").await.unwrap();
        assert_eq!(first_len, 4);
        assert_eq!(second_len, 4);
        assert_eq!(first.read_at(0, 4).await.unwrap().coalesce(), b"f1f2");
        assert_eq!(second.read_at(0, 4).await.unwrap().coalesce(), b"s1s2");
    }

    /// A retained handle can rejoin after a disjoint decision materializes its prior root.
    async fn test_apply_batch_carries_disjoint_publications<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (first, _) = storage
            .open_atomic("batch_carry_disjoint", b"first")
            .await
            .unwrap();
        let (second, _) = storage
            .open_atomic("batch_carry_disjoint", b"second")
            .await
            .unwrap();

        first.append(b"a1").await.unwrap();
        storage
            .apply(vec![BatchOperation::Publish(first.clone())])
            .await
            .unwrap();

        // Materializing the carried first decision must not truncate this newer pending tail.
        first.append(b"a2").await.unwrap();
        second.append(b"b1").await.unwrap();
        storage
            .apply(vec![BatchOperation::Publish(second.clone())])
            .await
            .unwrap();
        assert_eq!(first.read_at(0, 4).await.unwrap().coalesce(), b"a1a2");
        storage
            .apply(vec![BatchOperation::Publish(first.clone())])
            .await
            .unwrap();

        assert_eq!(first.read_at(0, 4).await.unwrap().coalesce(), b"a1a2");
        assert_eq!(second.read_at(0, 2).await.unwrap().coalesce(), b"b1");
    }

    /// Direct one-participant publication can replace and be replaced by a larger group.
    async fn test_direct_sync_transitions_to_and_from_a_group<S>(storage: &S)
    where
        S: BatchStorage<AtomicBlob = <S as Storage>::Blob> + Send + Sync,
        <S as Storage>::Blob: AtomicBlob + Send + Sync,
    {
        let (first, _) = storage
            .open_atomic("batch_direct_transition", b"first")
            .await
            .unwrap();
        let (second, _) = storage
            .open_atomic("batch_direct_transition", b"second")
            .await
            .unwrap();

        first.append(b"a0").await.unwrap();
        first.sync().await.unwrap();

        first.append(b"a1").await.unwrap();
        second.append(b"b1").await.unwrap();
        storage
            .apply(vec![
                BatchOperation::Publish(first.clone()),
                BatchOperation::Publish(second.clone()),
            ])
            .await
            .unwrap();

        first.append(b"a2").await.unwrap();
        first.sync().await.unwrap();
        drop((first, second));

        let (first, first_len) = storage
            .open_atomic("batch_direct_transition", b"first")
            .await
            .unwrap();
        let (second, second_len) = storage
            .open_atomic("batch_direct_transition", b"second")
            .await
            .unwrap();
        assert_eq!(first_len, 6);
        assert_eq!(second_len, 2);
        assert_eq!(first.read_at(0, 6).await.unwrap().coalesce(), b"a0a1a2");
        assert_eq!(second.read_at(0, 2).await.unwrap().coalesce(), b"b1");
    }

    /// An ordinary handle rejects the batch before a valid atomic publication is applied.
    async fn test_apply_batch_rejects_non_atomic_handle<S>(storage: &S)
    where
        S: BatchStorage<AtomicBlob = <S as Storage>::Blob> + Send + Sync,
        <S as Storage>::Blob: AtomicBlob + Send + Sync,
    {
        let (published, _) = storage
            .open_atomic("batch_non_atomic", b"published")
            .await
            .unwrap();
        published.append(b"pending").await.unwrap();
        let (ordinary, _) = storage.open("batch_non_atomic", b"ordinary").await.unwrap();
        ordinary
            .write_at(0, b"ordinary", WriteOptions::SYNC)
            .await
            .unwrap();

        let result = storage
            .apply(vec![
                BatchOperation::Publish(published.clone()),
                BatchOperation::Remove(ordinary.clone()),
            ])
            .await;
        assert!(matches!(result, Err(crate::Error::BlobOpenFailed(..))));
        assert_eq!(
            published.read_at(0, 7).await.unwrap().coalesce(),
            b"pending"
        );
        assert_eq!(
            ordinary.read_at(0, 8).await.unwrap().coalesce(),
            b"ordinary"
        );
        assert_eq!(
            storage.scan("batch_non_atomic").await.unwrap(),
            vec![b"ordinary".to_vec(), b"published".to_vec()]
        );

        drop(published);
        let (published, len) = storage
            .open_atomic("batch_non_atomic", b"published")
            .await
            .unwrap();
        assert_eq!(len, 0);
        assert!(published.read_at(0, 1).await.is_err());
    }

    /// A bad late operation rejects the entire batch before an exact removal is applied.
    async fn test_apply_batch_validates_atomically<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (survivor, _) = storage
            .open_atomic("batch_validation", b"first")
            .await
            .unwrap();
        survivor.append(b"keep").await.unwrap();
        survivor.sync().await.unwrap();
        let (invalid, _) = storage
            .open_atomic("batch_validation", b"second")
            .await
            .unwrap();
        invalid.append(b"abc").await.unwrap();
        invalid.sync().await.unwrap();
        let result = storage
            .apply(vec![
                BatchOperation::Remove(survivor.clone()),
                BatchOperation::Rewind {
                    blob: invalid.clone(),
                    len: 4,
                },
            ])
            .await
            .unwrap_err();
        assert!(
            matches!(result, crate::Error::Io(err) if err.kind() == std::io::ErrorKind::InvalidInput)
        );
        let mut blobs = storage.scan("batch_validation").await.unwrap();
        blobs.sort();
        assert_eq!(blobs, vec![b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(survivor.read_at(0, 4).await.unwrap().coalesce(), b"keep");
        assert_eq!(invalid.read_at(0, 3).await.unwrap().coalesce(), b"abc");
    }

    /// An invalid rewind rejects the batch before another participant is rewound.
    async fn test_apply_batch_validates_all_rewinds_before_mutating<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (first, _) = storage
            .open_atomic("batch_rewind_validation", b"first")
            .await
            .unwrap();
        let (second, _) = storage
            .open_atomic("batch_rewind_validation", b"second")
            .await
            .unwrap();
        first.append(b"abc").await.unwrap();
        second.append(b"xyz").await.unwrap();
        first.sync().await.unwrap();
        second.sync().await.unwrap();

        let result = storage
            .apply(vec![
                BatchOperation::Rewind {
                    blob: first.clone(),
                    len: 1,
                },
                BatchOperation::Rewind {
                    blob: second.clone(),
                    len: 4,
                },
            ])
            .await;
        assert!(
            matches!(result, Err(crate::Error::Io(err)) if err.kind() == std::io::ErrorKind::InvalidInput)
        );
        assert_eq!(first.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        assert_eq!(second.read_at(0, 3).await.unwrap().coalesce(), b"xyz");
    }

    /// Conflicting blob mutations reject the entire batch without changing blob state.
    async fn test_apply_batch_conflicts_are_atomic<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (resized, _) = storage
            .open_atomic("batch_conflict_resize", b"blob")
            .await
            .unwrap();
        resized.append(b"abcdef").await.unwrap();
        resized.sync().await.unwrap();
        let (victim, _) = storage
            .open_atomic("batch_conflict_victim", b"victim")
            .await
            .unwrap();
        victim.append(b"keep").await.unwrap();
        victim.sync().await.unwrap();

        let removal = BatchOperation::Remove(victim.clone());
        let cases = vec![
            vec![
                removal.clone(),
                BatchOperation::Rewind {
                    blob: resized.clone(),
                    len: 2,
                },
                BatchOperation::Remove(resized.clone()),
            ],
            vec![
                removal.clone(),
                BatchOperation::Remove(resized.clone()),
                BatchOperation::Rewind {
                    blob: resized.clone(),
                    len: 2,
                },
            ],
            vec![
                removal.clone(),
                BatchOperation::Rewind {
                    blob: resized.clone(),
                    len: 2,
                },
                BatchOperation::Rewind {
                    blob: resized.clone(),
                    len: 3,
                },
            ],
            vec![
                removal.clone(),
                BatchOperation::Rewind {
                    blob: resized.clone(),
                    len: 4,
                },
                BatchOperation::Publish(resized.clone()),
            ],
            vec![
                removal,
                BatchOperation::Publish(resized.clone()),
                BatchOperation::Rewind {
                    blob: resized.clone(),
                    len: 4,
                },
            ],
        ];
        for operations in cases {
            let result = storage.apply(operations).await;
            assert!(
                matches!(result, Err(crate::Error::Io(err)) if err.kind() == std::io::ErrorKind::InvalidInput)
            );
            assert_eq!(resized.read_at(0, 6).await.unwrap().coalesce(), b"abcdef");
            assert_eq!(victim.read_at(0, 4).await.unwrap().coalesce(), b"keep");
            assert_eq!(
                storage.scan("batch_conflict_victim").await.unwrap(),
                vec![b"victim".to_vec()]
            );
        }
    }

    /// An identical duplicate cannot hide a stale handle; rejection leaves the batch unchanged.
    async fn test_apply_batch_rejects_stale_handle<S>(storage: &S)
    where
        S: BatchStorage + Send + Sync,
        S::AtomicBlob: Send + Sync,
    {
        let (old, _) = storage
            .open_atomic("batch_stale", b"shared_name")
            .await
            .unwrap();
        old.append(b"old").await.unwrap();
        old.sync().await.unwrap();
        let old_clone = old.clone();
        storage
            .apply(vec![BatchOperation::Remove(old.clone())])
            .await
            .unwrap();

        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(old_clone.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert!(old.sync().await.is_err());

        let (new, size) = storage
            .open_atomic("batch_stale", b"shared_name")
            .await
            .unwrap();
        assert_eq!(size, 0);
        new.append(b"new").await.unwrap();
        new.sync().await.unwrap();

        let result = storage
            .apply(vec![
                BatchOperation::Remove(new.clone()),
                BatchOperation::Remove(old.clone()),
            ])
            .await;
        assert!(matches!(result, Err(crate::Error::BlobMissing(..))));

        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(new.read_at(0, 3).await.unwrap().coalesce(), b"new");
        assert_eq!(
            storage.scan("batch_stale").await.unwrap(),
            vec![b"shared_name".to_vec()]
        );
    }

    /// An already-open handle remains fully readable after the blob is removed by name.
    async fn test_read_after_remove_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("read_after_remove", b"by_name").await.unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        blob.write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        storage
            .remove("read_after_remove", Some(b"by_name"))
            .await
            .unwrap();

        // The name is gone but the open handle keeps reading the removed blob's bytes.
        let blobs = storage.scan("read_after_remove").await.unwrap();
        assert!(blobs.is_empty(), "Blob was not removed as expected");
        let read = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "open handle must remain readable after blob removal"
        );
    }

    /// An already-open handle remains fully readable after its entire partition is removed.
    async fn test_read_after_remove_partition<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("read_after_remove_partition", b"victim")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).rev().collect();
        blob.write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        storage
            .remove("read_after_remove_partition", None)
            .await
            .unwrap();

        let read = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "open handle must remain readable after partition removal"
        );
    }

    /// Re-opening a removed blob's name creates an independent blob; the pre-removal handle keeps
    /// observing the removed blob's contents.
    async fn test_recreate_after_remove<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (old, _) = storage
            .open("recreate_after_remove", b"name")
            .await
            .unwrap();
        old.write_at(0, b"old contents", WriteOptions::default())
            .await
            .unwrap();
        old.sync().await.unwrap();

        storage
            .remove("recreate_after_remove", Some(b"name"))
            .await
            .unwrap();

        // Re-creating the name yields a fresh, empty, independent blob.
        let (new, len) = storage
            .open("recreate_after_remove", b"name")
            .await
            .unwrap();
        assert_eq!(len, 0, "recreated blob must start empty");
        new.write_at(0, b"new contents", WriteOptions::default())
            .await
            .unwrap();
        new.sync().await.unwrap();

        let old_read = old.read_at(0, 12).await.unwrap();
        assert_eq!(
            old_read.coalesce().as_ref(),
            b"old contents",
            "pre-removal handle must keep observing the removed blob"
        );
        let new_read = new.read_at(0, 12).await.unwrap();
        assert_eq!(new_read.coalesce().as_ref(), b"new contents");
    }

    /// Bytes written but never synced remain readable through an open handle after removal.
    async fn test_read_after_remove_unsynced<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("read_after_remove_unsynced", b"name")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        blob.write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();

        // Read through the handle before removal so the removal crosses an actively-used handle.
        let read = blob.read_at(0, 16).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), &data[..16]);

        storage
            .remove("read_after_remove_unsynced", Some(b"name"))
            .await
            .unwrap();

        // Unsynced bytes are still served in full.
        let read = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "unsynced bytes must remain readable after removal"
        );
        let read = blob.read_at(data.len() as u64 - 1, 1).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), &data[data.len() - 1..]);
    }

    /// Removal liveness is per-blob, not per-handle: clones taken before or after removal keep
    /// reading regardless of other handles' lifetimes, and out-of-bounds reads still fail.
    async fn test_read_after_remove_handle_clones<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (first, _) = storage
            .open("read_after_remove_clones", b"name")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        first
            .write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        first.sync().await.unwrap();
        let second = first.clone();
        // Opened independently: a distinct handle to the same blob, not a clone.
        let (independent, _) = storage
            .open("read_after_remove_clones", b"name")
            .await
            .unwrap();

        storage
            .remove("read_after_remove_clones", Some(b"name"))
            .await
            .unwrap();

        // A clone taken after removal reads too, and outlives the handle it was cloned from.
        let third = first.clone();
        drop(first);

        for handle in [&second, &third, &independent] {
            let read = handle.read_at(0, data.len()).await.unwrap();
            assert_eq!(read.coalesce().as_ref(), data.as_slice());
            assert!(
                handle.read_at(data.len() as u64, 1).await.is_err(),
                "out-of-bounds read must still fail after removal"
            );
        }
    }

    /// Every removed generation of a name stays readable through its own handle while the name
    /// is recreated and removed repeatedly.
    async fn test_recreate_generations<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let partition = "recreate_generations";

        // Hold a handle on each of three generations of the same name, each removed while open.
        let mut handles = Vec::new();
        for generation in 0u8..3 {
            let (blob, len) = storage.open(partition, b"name").await.unwrap();
            assert_eq!(len, 0, "each recreation must start empty");
            let data = vec![generation; 32];
            blob.write_at(0, data.clone(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            storage.remove(partition, Some(b"name")).await.unwrap();
            handles.push((blob, data));
        }

        // Churn the name further with the removed generations still held.
        for _ in 0..5 {
            let (blob, _) = storage.open(partition, b"name").await.unwrap();
            blob.write_at(0, vec![0xFF; 8], WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            storage.remove(partition, Some(b"name")).await.unwrap();
        }

        for (blob, data) in &handles {
            let read = blob.read_at(0, data.len()).await.unwrap();
            assert_eq!(
                read.coalesce().as_ref(),
                data.as_slice(),
                "each handle must keep observing its own generation"
            );
        }
    }

    /// Every handle into a removed partition stays readable, including a large blob at interior
    /// offsets, and recreating the partition yields independent blobs.
    async fn test_read_after_remove_partition_multi<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let partition = "read_after_remove_partition_multi";
        let (small_a, _) = storage.open(partition, b"a").await.unwrap();
        small_a
            .write_at(0, b"alpha", WriteOptions::default())
            .await
            .unwrap();
        small_a.sync().await.unwrap();
        // Deliberately never synced: partition removal must not lose unsynced bytes either.
        let (small_b, _) = storage.open(partition, b"b").await.unwrap();
        small_b
            .write_at(0, b"bravo", WriteOptions::default())
            .await
            .unwrap();

        const LARGE_LEN: usize = 1 << 20;
        let (large, _) = storage.open(partition, b"large").await.unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(LARGE_LEN).collect();
        large
            .write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        large.sync().await.unwrap();

        storage.remove(partition, None).await.unwrap();

        let read = small_a.read_at(0, 5).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), b"alpha");
        let read = small_b.read_at(0, 5).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), b"bravo");

        // Start, unaligned interior, and final-byte reads of the large blob.
        for (offset, len) in [(0usize, 4096), (123_457, 8192), (LARGE_LEN - 1, 1)] {
            let read = large.read_at(offset as u64, len).await.unwrap();
            assert_eq!(
                read.coalesce().as_ref(),
                &data[offset..offset + len],
                "offset={offset} len={len}"
            );
        }

        // Recreating the partition and a same-named blob yields an independent blob.
        let (fresh, len) = storage.open(partition, b"a").await.unwrap();
        assert_eq!(len, 0, "recreated blob must start empty");
        fresh
            .write_at(0, b"fresh", WriteOptions::default())
            .await
            .unwrap();
        fresh.sync().await.unwrap();
        let read = small_a.read_at(0, 5).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            b"alpha",
            "pre-removal handle must keep observing the removed partition's blob"
        );
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
        blob.write_at(0, b"concurrent write", WriteOptions::default())
            .await
            .unwrap();

        // Read and write concurrently
        let write_task = tokio::spawn({
            let blob = blob.clone();
            async move {
                blob.write_at(0, IoBuf::from(b"concurrent write"), WriteOptions::default())
                    .await
                    .unwrap();
            }
        });

        let read_task = tokio::spawn({
            let blob = blob.clone();
            async move { blob.read_at(0, 16).await.unwrap() }
        });

        write_task.await.unwrap();
        let buffer = read_task.await.unwrap();

        assert_eq!(
            buffer.coalesce(),
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
        blob.write_at(0, large_data.clone(), WriteOptions::default())
            .await
            .unwrap();

        let read = blob.read_at(0, 10 * 1024 * 1024).await.unwrap().coalesce();

        assert_eq!(read, large_data.as_slice(), "Large data read/write failed");
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
        blob.write_at(0, b"initial data", WriteOptions::default())
            .await
            .unwrap();

        // Overwrite part of the data
        blob.write_at(8, b"overwrite", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob.read_at(0, 17).await.unwrap().coalesce();

        assert_eq!(
            read, b"initial overwrite",
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
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();

        // Attempt to read beyond the written data
        let result = blob.read_at(6, 10).await;
        assert!(
            result.is_err(),
            "Reading beyond written data should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(10);
        let result = blob.read_at_buf(6, 10, buf).await;
        assert!(
            result.is_err(),
            "read_at_buf beyond written data should return an error"
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
        blob.write_at(10_000, b"offset data", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob.read_at(10_000, 11).await.unwrap().coalesce();
        assert_eq!(read, b"offset data", "Data at large offset is incorrect");
    }

    /// Test writing and syncing data in one operation.
    async fn test_write_at_sync<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();

        // Empty writes should be accepted without extending the blob.
        blob.write_at(1024, Vec::<u8>::new(), WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);

        let (blob, len) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 0);

        // Non-empty writes must be visible after reopen without a separate sync call.
        blob.write_at(0, b"hello", WriteOptions::SYNC)
            .await
            .unwrap();
        blob.write_at(
            5,
            vec![IoBuf::from(b" "), IoBuf::from(b"world")],
            WriteOptions::SYNC,
        )
        .await
        .unwrap();
        drop(blob);

        // Reopening a blob in the same process may still observe dirty kernel
        // page-cache state, so this doesn't really prove write durability.
        let (blob, len) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 11);
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    /// Test that `start_sync` durably persists data, matching `sync`.
    async fn test_start_sync<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("test_start_sync", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);

        // The bytes must survive a reopen, just as they would after `sync`.
        let (blob, len) = storage.open("test_start_sync", b"test_blob").await.unwrap();
        assert_eq!(len, 11);
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
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
        blob.write_at(0, b"first", WriteOptions::default())
            .await
            .unwrap();

        // Append data
        blob.write_at(5, b"second", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read, b"firstsecond", "Appended data is incorrect");
    }

    /// Test vectored writes at offset 0.
    async fn test_vectored_write_at<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let test = |partition, bufs: Vec<IoBuf>, options, context| async move {
            // Coalesce the input to test later when reading
            let expected = IoBufs::from(bufs.clone()).coalesce();
            let (blob, _) = storage.open(partition, b"test_blob").await.unwrap();

            // Write data
            blob.write_at(0, bufs, options).await.unwrap();

            // Read back the data
            let read = blob.read_at(0, expected.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), expected.as_ref(), "{context}");
        };

        test(
            "test_vectored_write_basic",
            vec![
                IoBuf::from(b"hello"),
                IoBuf::from(b" "),
                IoBuf::from(b"world"),
            ],
            WriteOptions::default(),
            "Vectored write content is incorrect",
        )
        .await;

        test(
            "test_vectored_write_empty_chunks",
            vec![
                IoBuf::default(),
                IoBuf::from(b"abc"),
                IoBuf::default(),
                IoBuf::from(b"def"),
                IoBuf::default(),
            ],
            WriteOptions::default(),
            "Vectored write with empties is incorrect",
        )
        .await;

        // Both filesystem backends cap one submission at 1,024 iovecs.
        let chunk_count = 1_025;
        let mut bufs = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            bufs.push(IoBuf::from(vec![i as u8]));
        }

        test(
            "test_vectored_write_many_chunks",
            bufs.clone(),
            WriteOptions::default(),
            "Vectored write over batch size is incorrect",
        )
        .await;
        test(
            "test_vectored_sync_write_many_chunks",
            bufs,
            WriteOptions::SYNC,
            "Synchronized vectored write over batch size is incorrect",
        )
        .await;
    }

    /// Test vectored writes at large offset with many chunks.
    async fn test_vectored_write_at_large_offset<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_vectored_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        let chunk_count = 128;
        let mut bufs = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            bufs.push(IoBuf::from(vec![i as u8; i]));
        }
        let expected = IoBufs::from(bufs.clone()).coalesce();

        // Write vectored data at a large offset
        blob.write_at(5_000, bufs, WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob
            .read_at(5_000, expected.len())
            .await
            .unwrap()
            .coalesce();

        assert_eq!(
            read.as_ref(),
            expected.as_ref(),
            "Vectored write at offset content is incorrect"
        );

        // Prefix gap should be zero-filled.
        let prefix = blob.read_at(0, 5_000).await.unwrap().coalesce();
        assert_eq!(prefix.as_ref(), [0u8; 5_000]);
    }

    /// Test reading and writing with interleaved offsets.
    async fn test_sequential_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Write data at different offsets
        blob.write_at(0, b"first", WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(10, b"second", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read, b"first", "Data at offset 0 is incorrect");

        let read = blob.read_at(10, 6).await.unwrap().coalesce();
        assert_eq!(read, b"second", "Data at offset 10 is incorrect");
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
            blob.write_at(
                (i * chunk_size) as u64,
                data.clone(),
                WriteOptions::default(),
            )
            .await
            .unwrap();
        }

        // Read back the data in chunks
        for i in 0..num_chunks {
            let read = blob
                .read_at((i * chunk_size) as u64, chunk_size)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read, data.as_slice(), "Chunk {i} is incorrect");
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

        let result = blob.read_at(0, 1).await;
        assert!(
            result.is_err(),
            "Reading from an empty blob should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(1);
        let result = blob.read_at_buf(0, 1, buf).await;
        assert!(
            result.is_err(),
            "read_at_buf from an empty blob should return an error"
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
        blob.write_at(0, b"overlap", WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(4, b"map", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob.read_at(0, 7).await.unwrap().coalesce();
        assert_eq!(read, b"overmap", "Overlapping writes are incorrect");
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
            blob.write_at(0, b"hello world", WriteOptions::default())
                .await
                .unwrap();

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
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read, b"hello", "Resized data is incorrect");
    }

    /// Test that partition names are validated correctly.
    async fn test_partition_name_validation<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Valid partition names should not return PartitionNameInvalid
        for valid in [
            "partition",
            "my_partition",
            "my-partition",
            "partition123",
            "A1",
        ] {
            assert!(
                !matches!(
                    storage.open(valid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by open"
            );
            assert!(
                !matches!(
                    storage.remove(valid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by remove"
            );
            assert!(
                !matches!(
                    storage.scan(valid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by scan"
            );
        }

        // Invalid partition names should return PartitionNameInvalid
        for invalid in [
            "my/partition",
            "my.partition",
            "my partition",
            "../escape",
            "",
        ] {
            assert!(
                matches!(
                    storage.open(invalid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by open"
            );
            assert!(
                matches!(
                    storage.remove(invalid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by remove"
            );
            assert!(
                matches!(
                    storage.scan(invalid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by scan"
            );
        }
    }

    /// Test that opening a blob with an incompatible version range returns an error.
    async fn test_blob_version_mismatch<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create a blob with version 1
        let (blob, _, blob_version) = storage
            .open_versioned("test_version_mismatch", b"blob", 1..=1)
            .await
            .unwrap();
        assert_eq!(blob_version, 1);
        blob.sync().await.unwrap();
        drop(blob);

        // Reopen with a range that includes version 1
        let (_, _, blob_version) = storage
            .open_versioned("test_version_mismatch", b"blob", 0..=2)
            .await
            .unwrap();
        assert_eq!(blob_version, 1);

        // Try to open with version range that excludes version 1
        let result = storage
            .open_versioned("test_version_mismatch", b"blob", 2..=3)
            .await;
        assert!(
            matches!(
                result,
                Err(crate::Error::BlobVersionMismatch { expected, found })
                if expected == (2..=3) && found == 1
            ),
            "Expected BlobVersionMismatch error"
        );
    }

    /// Test aligned-layout blob creation, reopen, and resize through logical offsets.
    async fn test_aligned_layout<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create an aligned blob and write/read through logical offsets.
        let (blob, size, _) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, 0);
        blob.write_at(0, b"hello world".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
        drop(blob);

        // Reopen honors the recorded layout and logical size.
        let (blob, size, _) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, 11);
        let read = blob.read_at(6, 5).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"world");

        // Resize preserves logical semantics.
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let (blob, size, _) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, 5);
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello");
        drop(blob);
    }

    /// Test that read_at with zero length returns an empty buffer.
    async fn test_read_zero_length<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_zero_len", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();

        // read_at with len=0 should succeed and return empty
        let output = blob.read_at(0, 0).await.unwrap();
        assert_eq!(output.len(), 0);

        // read_at_buf with len=0 should also succeed
        let buf = IoBufMut::with_capacity(16);
        let output = blob.read_at_buf(0, 0, buf).await.unwrap();
        assert_eq!(output.len(), 0);
    }

    /// Test that read_at_buf returns the same buffer that was passed in (contract verification).
    async fn test_read_at_buf_returns_same_buffer<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_contract", b"blob")
            .await
            .unwrap();

        // Write test data
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Test with single buffer - verify same buffer is returned
        let input_buf = IoBufMut::zeroed(11);
        let input_ptr = input_buf.as_ref().as_ptr();
        let output = blob.read_at_buf(0, 11, input_buf).await.unwrap();
        assert!(
            output.is_single(),
            "Single input should return single output"
        );
        let output_ptr = output.chunk().as_ptr();
        assert_eq!(
            input_ptr, output_ptr,
            "read_at must return the same buffer that was passed in"
        );
        assert_eq!(output.chunk(), b"hello world");

        // Test with multi-chunk buffers - verify same buffers are returned with correct data
        let buf1 = IoBufMut::zeroed(5);
        let buf2 = IoBufMut::zeroed(6);
        let ptr1 = buf1.as_ref().as_ptr();
        let ptr2 = buf2.as_ref().as_ptr();
        let input_bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!input_bufs.is_single(), "Should be multi-chunk");

        let mut output = blob.read_at_buf(0, 11, input_bufs).await.unwrap();
        assert!(
            !output.is_single(),
            "Multi-chunk input should return multi-chunk output"
        );

        // Verify the buffers are the same and contain correct data.
        assert_eq!(
            output.chunk().as_ptr(),
            ptr1,
            "First chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b"hello");
        output.advance(5);
        assert_eq!(
            output.chunk().as_ptr(),
            ptr2,
            "Second chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b" world");
        output.advance(6);
        assert_eq!(output.remaining(), 0);

        // when requested len only fills the first chunk, read_at_buf
        // should still preserve caller-provided multi-chunk layout.
        let buf1 = IoBufMut::zeroed(2);
        let buf2 = IoBufMut::zeroed(2);
        let ptr1 = buf1.as_ref().as_ptr();
        let input_bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!input_bufs.is_single(), "Should be multi-chunk");

        let output = blob.read_at_buf(0, 2, input_bufs).await.unwrap();
        assert!(
            !output.is_single(),
            "Multi-chunk input should remain multi-chunk when len only uses first chunk"
        );
        assert_eq!(
            output.chunk().as_ptr(),
            ptr1,
            "First chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b"he");
    }

    /// Test that read_at_buf panics when buffer capacity < len.
    async fn test_read_at_buf_insufficient_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_capacity", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Single buffer with capacity 5, request 11 bytes
        let buf = IoBufMut::with_capacity(5);
        let result = std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, buf))
            .catch_unwind()
            .await;
        assert!(
            result.is_err(),
            "Expected panic for insufficient single buffer capacity"
        );

        // Chunked buffers with total capacity 8, request 11 bytes
        let bufs = IoBufsMut::from(vec![IoBufMut::with_capacity(4), IoBufMut::with_capacity(4)]);
        let result = std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, bufs))
            .catch_unwind()
            .await;
        assert!(
            result.is_err(),
            "Expected panic for insufficient multi-chunk buffer capacity"
        );
    }

    /// Test that read_at_buf works when buffer capacity exceeds len.
    async fn test_read_at_buf_larger_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_large_cap", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Buffer with capacity 64, request only 11 bytes
        let buf = IoBufMut::with_capacity(64);
        assert_eq!(buf.len(), 0, "with_capacity should start at len 0");
        let output = blob.read_at_buf(0, 11, buf).await.unwrap();
        assert_eq!(output.len(), 11);
        assert_eq!(output.coalesce(), b"hello world");

        // Buffer with capacity 64, request only 5 bytes (partial read)
        let buf = IoBufMut::with_capacity(64);
        let output = blob.read_at_buf(0, 5, buf).await.unwrap();
        assert_eq!(output.len(), 5);
        assert_eq!(output.coalesce(), b"hello");
    }
}
