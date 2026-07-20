use super::Header;
use crate::{BufferPool, DEFAULT_OPEN_CONCURRENCY, Error};
use commonware_codec::Encode;
use commonware_formatting::{from_hex, hex};
#[cfg(unix)]
use std::path::Path;
use std::{
    future::Future,
    hash::{Hash, Hasher},
    io::ErrorKind,
    num::NonZeroUsize,
    ops::RangeInclusive,
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

#[cfg(not(unix))]
mod fallback;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
type BackendBlob = fallback::Blob;
#[cfg(unix)]
type BackendBlob = unix::Blob;

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly
/// fsynced.
#[cfg(unix)]
async fn sync_dir(path: &Path) -> Result<(), Error> {
    let dir = fs::File::open(path).await.map_err(|e| {
        Error::BlobOpenFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })?;
    dir.sync_all().await.map_err(|e| {
        Error::BlobSyncFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })
}

#[derive(Clone)]
pub struct Config {
    pub storage_directory: PathBuf,
    pub maximum_buffer_size: usize,
    /// See [crate::Storage::open_concurrency].
    pub open_concurrency: NonZeroUsize,
}

impl Config {
    pub const fn new(storage_directory: PathBuf, maximum_buffer_size: usize) -> Self {
        Self {
            storage_directory,
            maximum_buffer_size,
            open_concurrency: DEFAULT_OPEN_CONCURRENCY,
        }
    }
}

/// Maps only an absent partition to [`Error::PartitionMissing`], preserving all other I/O
/// failures so callers never mistake a failed removal for a successful reset.
fn partition_remove_error(partition: &str, error: std::io::Error) -> Error {
    if error.kind() == ErrorKind::NotFound {
        Error::PartitionMissing(partition.into())
    } else {
        error.into()
    }
}

#[derive(Clone, Default)]
struct Cancellation(Arc<std::sync::atomic::AtomicBool>);

impl Cancellation {
    fn cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

struct CancelOnDrop(Cancellation);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Number of partition-lock stripes. Collisions only cost spurious serialization of unrelated
/// partitions, so a small fixed table suffices.
const PARTITION_LOCK_STRIPES: usize = 64;

#[derive(Clone)]
pub struct Storage {
    /// Striped per-partition locks. Each lock upholds two invariants (see #3869): after
    /// [crate::Storage::remove] returns, a [crate::Storage::scan] must not observe the removed
    /// name, and an open must not recreate a blob between removal's unlink and its directory
    /// fsync. Existing blobs reopen under a shared lock; creation, healing, scans, and removals
    /// hold it exclusively.
    partition_locks: Arc<[RwLock<()>; PARTITION_LOCK_STRIPES]>,
    cfg: Config,
    pool: BufferPool,
}

impl Storage {
    pub fn new(cfg: Config, pool: BufferPool) -> Self {
        Self {
            partition_locks: Arc::new(std::array::from_fn(|_| RwLock::new(()))),
            cfg,
            pool,
        }
    }

    /// Hashes a partition for lock selection, folding ASCII case so aliases on a
    /// case-insensitive filesystem select the same lock. Names are ASCII-only (see
    /// [super::validate_partition_name]), so case is the only aliasing a filesystem can
    /// introduce; on case-sensitive filesystems folding only risks serializing
    /// otherwise-independent operations.
    fn hash_partition(partition: &str, hasher: &mut impl Hasher) {
        partition.len().hash(hasher);
        for byte in partition.bytes() {
            byte.to_ascii_lowercase().hash(hasher);
        }
    }

    /// Returns the lock stripe for `partition`.
    fn partition_lock(&self, partition: &str) -> &RwLock<()> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        Self::hash_partition(partition, &mut hasher);
        &self.partition_locks[hasher.finish() as usize % PARTITION_LOCK_STRIPES]
    }

    /// Validate an existing blob's header and construct its backend handle.
    async fn finish_existing(
        &self,
        partition: &str,
        name: &[u8],
        mut file: fs::File,
        len: u64,
        versions: &RangeInclusive<u16>,
    ) -> Result<(BackendBlob, u64, u16), Error> {
        file.set_max_buf_size(self.cfg.maximum_buffer_size);
        let mut header_bytes = [0u8; Header::SIZE];
        file.read_exact(&mut header_bytes)
            .await
            .map_err(|_| Error::ReadFailed)?;
        let (blob_version, logical_size) =
            Header::from(header_bytes, len, versions).map_err(|e| e.into_error(partition, name))?;
        Ok(self
            .finish_blob(partition, name, file, logical_size, blob_version)
            .await)
    }

    /// Construct the platform-specific blob handle from an opened Tokio file.
    #[cfg_attr(not(unix), allow(clippy::unused_async))]
    async fn finish_blob(
        &self,
        partition: &str,
        name: &[u8],
        file: fs::File,
        logical_size: u64,
        blob_version: u16,
    ) -> (BackendBlob, u64, u16) {
        #[cfg(unix)]
        let file = file.into_std().await;
        (
            BackendBlob::new(partition.into(), name, file, self.pool.clone()),
            logical_size,
            blob_version,
        )
    }
}

/// Runs a filesystem operation to completion after it has crossed its cancellation boundary,
/// even if its caller is cancelled. Tokio filesystem futures delegate to blocking tasks that keep
/// running when dropped, so the task must also retain the operation's lock guards until those
/// tasks finish.
async fn complete_on_cancel<F, Fut, T>(operation: F) -> T
where
    F: FnOnce(Cancellation) -> Fut,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let cancellation = Cancellation::default();
    let _cancel_on_drop = CancelOnDrop(cancellation.clone());
    match tokio::spawn(operation(cancellation)).await {
        Ok(output) => output,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => panic!("storage operation task was cancelled: {error}"),
    }
}

impl crate::Storage for Storage {
    #[cfg(unix)]
    type Blob = unix::Blob;
    #[cfg(not(unix))]
    type Blob = fallback::Blob;

    fn open_concurrency(&self) -> NonZeroUsize {
        self.cfg.open_concurrency
    }

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;

        // The normal reopen path is read-only and runs concurrently with other opens. Creation
        // and healing fall back to the exclusive path below.
        let partition_guard = self.partition_lock(partition).read().await;
        let path = self.cfg.storage_directory.join(partition).join(hex(name));
        let existing = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await;
        match existing {
            Ok(file) => {
                let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();
                if !Header::missing(len) {
                    return self
                        .finish_existing(partition, name, file, len, &versions)
                        .await;
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::BlobOpenFailed(
                    partition.into(),
                    hex(name),
                    error.into(),
                ));
            }
        }
        drop(partition_guard);

        // Missing and sub-header blobs require mutation. Serialize that exceptional path at the
        // partition level, rechecking after taking the write lock in case another opener repaired
        // the blob first.
        let storage = self.clone();
        let partition = partition.to_owned();
        let name = name.to_vec();
        let operation = move |cancellation: Cancellation| async move {
            let partition = partition.as_str();
            let name = name.as_slice();

            let _partition_guard = storage.partition_lock(partition).write().await;
            if cancellation.cancelled() {
                return Err(Error::Aborted);
            }

            let path = storage
                .cfg
                .storage_directory
                .join(partition)
                .join(hex(name));
            let parent = match path.parent() {
                Some(parent) => parent,
                None => return Err(Error::PartitionCreationFailed(partition.into())),
            };
            fs::create_dir_all(parent)
                .await
                .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .await
                .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e.into()))?;

            let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();
            if !Header::missing(len) {
                return storage
                    .finish_existing(partition, name, file, len, &versions)
                    .await;
            }

            file.set_max_buf_size(storage.cfg.maximum_buffer_size);
            // Truncate to zero (not the header size) so a crash cannot splice residual bytes into
            // a valid-looking header, and make the empty file and both directory levels durable
            // BEFORE writing the header: the reopen path admits any header-valid blob without
            // syncing directories, so header validity must certify that its creating open
            // completed the namespace syncs. A failure or crash anywhere before the header write
            // leaves a sub-header file, which the next open routes back through this path.
            // Windows doesn't have a notion of syncing a directory entry; see #2026.
            file.set_len(0)
                .await
                .map_err(|e| Error::BlobResizeFailed(partition.into(), hex(name), e.into()))?;
            file.sync_all()
                .await
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e.into()))?;
            #[cfg(unix)]
            {
                sync_dir(parent).await?;
                sync_dir(&storage.cfg.storage_directory).await?;
            }

            let (header, blob_version) = Header::new(&versions);
            file.write_all(&header.encode())
                .await
                .map_err(|_| Error::WriteFailed)?;
            file.sync_all()
                .await
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e.into()))?;

            Ok(storage
                .finish_blob(partition, name, file, 0, blob_version)
                .await)
        };
        complete_on_cancel(operation).await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let storage = self.clone();
        let partition = partition.to_owned();
        let name = name.map(<[u8]>::to_vec);
        let operation = move |cancellation: Cancellation| async move {
            let partition = partition.as_str();
            let name = name.as_deref();

            // Take the partition lock's write half: no open may recreate a blob between the
            // unlink and the directory fsync, and no scan may observe a partial removal.
            let _guard = storage.partition_lock(partition).write().await;
            // Honor cancellation until removal linearizes under the write lock. Past this point,
            // run to completion so an unlink is always followed by its directory fsync.
            if cancellation.cancelled() {
                return Err(Error::Aborted);
            }

            // Remove all related files
            let path = storage.cfg.storage_directory.join(partition);
            if let Some(name) = name {
                let blob_path = path.join(hex(name));
                fs::remove_file(blob_path)
                    .await
                    .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;

                // Sync the partition directory to ensure the removal is durable.
                // Windows doesn't have a notion of syncing a directory entry to ensure that it's
                // durably persisted. See https://github.com/commonwarexyz/monorepo/issues/2026.
                #[cfg(unix)]
                sync_dir(&path).await?;
            } else {
                fs::remove_dir_all(&path)
                    .await
                    .map_err(|error| partition_remove_error(partition, error))?;

                // Sync the storage directory to ensure the removal is durable.
                // Windows doesn't have a notion of syncing a directory entry to ensure that it's
                // durably persisted. See https://github.com/commonwarexyz/monorepo/issues/2026.
                #[cfg(unix)]
                sync_dir(&storage.cfg.storage_directory).await?;
            }
            Ok(())
        };
        complete_on_cancel(operation).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Take the partition lock exclusively so scan cannot observe a blob midway through open.
        // This preserves the prior namespace snapshot while still allowing the opens performed
        // after the scan to run concurrently.
        let _guard = self.partition_lock(partition).write().await;

        // Scan the partition directory
        let path = self.cfg.storage_directory.join(partition);
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|_| Error::PartitionMissing(partition.into()))?;
        let mut blobs = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| Error::ReadFailed)? {
            let file_type = entry.file_type().await.map_err(|_| Error::ReadFailed)?;
            if !file_type.is_file() {
                return Err(Error::PartitionCorrupt(partition.into()));
            }
            if let Some(name) = entry.file_name().to_str() {
                // Reject anything that isn't canonical lowercase hex (no `0x`
                // prefix, no whitespace) since `from_hex` is lenient and
                // storage only ever writes the canonical form via `hex()`.
                let decoded = from_hex(name).ok_or(Error::PartitionCorrupt(partition.into()))?;
                if hex(&decoded) != name {
                    return Err(Error::PartitionCorrupt(partition.into()));
                }

                blobs.push(decoded);
            }
        }
        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        Blob, BufferPoolConfig, Storage as _, storage::tests::run_storage_tests,
        telemetry::metrics::Registry,
    };
    use commonware_utils::sys_rng;
    use rand::RngExt as _;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::{env, time::Duration};
    use tokio::sync::{Mutex, oneshot};

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    fn random_suffix() -> u64 {
        let mut rng = sys_rng();
        rng.random()
    }

    /// Cancelling a caller must not release a mutating operation's lock while its detached
    /// filesystem work is still running.
    #[tokio::test]
    async fn test_complete_on_cancel_retains_guards() {
        let lock = Arc::new(Mutex::new(()));
        let operation_lock = lock.clone();
        let (started_sender, started_receiver) = oneshot::channel();
        let (finish_sender, finish_receiver) = oneshot::channel();

        let caller = tokio::spawn(async move {
            complete_on_cancel(move |_| async move {
                let _guard = operation_lock.lock().await;
                started_sender.send(()).unwrap();
                finish_receiver.await.unwrap();
            })
            .await;
        });

        started_receiver.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(lock.try_lock().is_err());

        finish_sender.send(()).unwrap();
        let _guard = tokio::time::timeout(Duration::from_secs(1), lock.lock())
            .await
            .expect("detached operation did not release its guard");
    }

    #[test]
    fn test_partition_remove_error_preserves_non_missing_failures() {
        let missing =
            partition_remove_error("partition", std::io::Error::from(ErrorKind::NotFound));
        assert!(matches!(missing, Error::PartitionMissing(partition) if partition == "partition"));

        let denied = partition_remove_error(
            "partition",
            std::io::Error::from(ErrorKind::PermissionDenied),
        );
        assert!(matches!(denied, Error::Io(error) if error.kind() == ErrorKind::PermissionDenied));
    }

    /// A cancelled open that has not acquired the partition lock must not run after removal and
    /// recreate the partition.
    #[tokio::test]
    async fn test_cancelled_open_does_not_resurrect_partition() {
        let storage_directory =
            env::temp_dir().join(format!("test_cancelled_open_{}", random_suffix()));
        let partition_path = storage_directory.join("partition");
        fs::create_dir_all(&partition_path).await.unwrap();
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 1024 * 1024),
            test_pool(),
        );

        // Let the read-only probe observe the missing blob, then hold the fallback before its
        // exclusive cancellation boundary.
        let removal_guard = storage.partition_lock("partition").read().await;
        let open_storage = storage.clone();
        let caller = tokio::spawn(async move { open_storage.open("partition", b"stale").await });
        // The probe's filesystem open completes on the blocking pool, so wait on wall time (not
        // yields) for the repair to queue its exclusive acquisition.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut repair_queued = false;
        while tokio::time::Instant::now() < deadline {
            if storage.partition_lock("partition").try_read().is_err() {
                repair_queued = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            repair_queued,
            "detached repair did not reach the write lock"
        );
        caller.abort();
        let error = match caller.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled open caller completed"),
        };
        assert!(error.is_cancelled());

        // Model a completed partition removal, then let the queued detached operation run.
        fs::remove_dir_all(&partition_path).await.unwrap();
        drop(removal_guard);
        let barrier = storage.partition_lock("partition").write().await;
        drop(barrier);

        assert!(!partition_path.exists());
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A cancelled remove that has not acquired the partition lock must not later delete a
    /// partition the caller has resumed using.
    #[tokio::test]
    async fn test_cancelled_remove_does_not_delete_partition() {
        let storage_directory =
            env::temp_dir().join(format!("test_cancelled_remove_{}", random_suffix()));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 1024 * 1024),
            test_pool(),
        );
        let (blob, _) = storage.open("partition", b"retained").await.unwrap();
        drop(blob);
        let blob_path = storage_directory.join("partition").join(hex(b"retained"));

        // Keep the detached remove before its cancellation boundary until its caller is gone.
        let operation_guard = storage.partition_lock("partition").read().await;
        let remove_storage = storage.clone();
        let caller = tokio::spawn(async move { remove_storage.remove("partition", None).await });
        let mut remove_queued = false;
        for _ in 0..100 {
            // Tokio's writer-preferring lock stops admitting readers once the remove is queued.
            if storage.partition_lock("partition").try_read().is_err() {
                remove_queued = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            remove_queued,
            "detached remove did not reach the write lock"
        );
        caller.abort();
        let error = match caller.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled remove caller completed"),
        };
        assert!(error.is_cancelled());

        drop(operation_guard);
        let barrier = storage.partition_lock("partition").write().await;
        drop(barrier);

        assert!(blob_path.exists());
        storage.remove("partition", None).await.unwrap();
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A create attempt that fails before completing its directory syncs must leave a
    /// sub-header file so a retry replays the full durability sequence instead of admitting a
    /// blob whose namespace entry was never made durable through the reopen path.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_failed_create_leaves_sub_header_blob() {
        let storage_directory =
            env::temp_dir().join(format!("test_failed_create_{}", random_suffix()));
        let partition_path = storage_directory.join("partition");
        fs::create_dir_all(&partition_path).await.unwrap();
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 1024 * 1024),
            test_pool(),
        );

        // Deny read on the storage root so its directory fsync fails (syncing requires opening
        // the directory read-only) while traversal and creation inside it still work.
        let normal = std::fs::metadata(&storage_directory).unwrap().permissions();
        std::fs::set_permissions(&storage_directory, std::fs::Permissions::from_mode(0o311))
            .unwrap();
        // Permissions cannot deny access to privileged users (e.g. root in a CI container).
        if std::fs::File::open(&storage_directory).is_ok() {
            let _ = std::fs::remove_dir_all(&storage_directory);
            return;
        }

        assert!(
            storage.open("partition", b"blob").await.is_err(),
            "create must fail when the storage root cannot be synced"
        );
        let len = std::fs::metadata(partition_path.join(hex(b"blob")))
            .unwrap()
            .len();
        assert!(
            Header::missing(len),
            "failed create left a header-valid blob (len {len})"
        );

        // With the failure cleared, a retry replays the full creation sequence.
        std::fs::set_permissions(&storage_directory, normal).unwrap();
        let (_, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 0);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Existing blobs reopen concurrently, while creation, scans, and removals serialize at the
    /// partition boundary.
    #[tokio::test]
    async fn test_narrowed_locking_invariants() {
        let storage_directory =
            env::temp_dir().join(format!("test_narrowed_locking_{}", random_suffix()));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 1024 * 1024),
            test_pool(),
        );

        // Case aliases must select the same lock stripes. On a case-sensitive filesystem this
        // only introduces harmless false contention; on a case-insensitive filesystem it keeps
        // operations on the same physical path coordinated.
        assert!(std::ptr::eq(
            storage.partition_lock("Alias"),
            storage.partition_lock("alias")
        ));
        let alias_guard = storage.partition_lock("Alias").write().await;
        assert!(storage.partition_lock("alias").try_read().is_err());
        drop(alias_guard);

        let partition_guard = storage.partition_lock("shared").read().await;
        let concurrent_partition_guard = storage.partition_lock("shared").try_read().unwrap();
        drop((partition_guard, concurrent_partition_guard));

        // Create many distinct blobs, then reopen them concurrently across two partitions.
        for i in 0..32u64 {
            let partition = if i % 2 == 0 { "even" } else { "odd" };
            storage.open(partition, &i.to_be_bytes()).await.unwrap();
        }
        let mut handles = Vec::new();
        for i in 0..32u64 {
            let storage = storage.clone();
            handles.push(tokio::spawn(async move {
                let partition = if i % 2 == 0 { "even" } else { "odd" };
                storage.open(partition, &i.to_be_bytes()).await.unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        // Concurrent opens of the same fresh blob serialize through the partition write lock, so
        // both succeed and agree on the resulting empty blob.
        for round in 0..8u64 {
            let name = round.to_be_bytes();
            let (a, b) = tokio::join!(storage.open("races", &name), storage.open("races", &name));
            let (_, size_a) = a.unwrap();
            let (_, size_b) = b.unwrap();
            assert_eq!(size_a, 0);
            assert_eq!(size_b, 0);
        }

        // After remove returns, a scan must not observe the removed name.
        storage
            .remove("even", Some(&0u64.to_be_bytes()))
            .await
            .unwrap();
        let names = storage.scan("even").await.unwrap();
        assert!(!names.contains(&0u64.to_be_bytes().to_vec()));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_storage() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());
        run_storage_tests(storage).await;
    }

    /// Dropping the `start_sync` receiver must not break the blob: the handle stays
    /// usable and a later sync still persists data.
    #[tokio::test]
    async fn test_start_sync_dropped_receiver() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_start_sync_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.write_at(0, b"hello world").await.unwrap();

        // Drop the completion receiver immediately.
        drop(blob.start_sync().await);

        // The blob remains usable, and a subsequent sync persists the data.
        blob.start_sync().await.await.unwrap();
        drop(blob);

        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 11);
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_header_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // Test 1: New blob returns logical size 0 and correct app version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw file has 8 bytes (header only)
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64,
            "raw file should have 8-byte header"
        );

        // Test 2: Logical offset handling - write at offset 0 stores at raw offset 8
        let data = b"hello world";
        blob.write_at(0, data).await.unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), Header::SIZE_U64 + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Header::MAGIC);
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[Header::MAGIC_LENGTH..Header::MAGIC_LENGTH + Header::VERSION_LENGTH],
            &Header::RUNTIME_VERSION.to_be_bytes()
        );
        // Data should start at offset 8
        assert_eq!(&raw_content[Header::SIZE..], data);

        // Test 3: Read at logical offset 0 returns data from raw offset 8
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64 + 5,
            "resize(5) should result in 13 raw bytes"
        );

        // resize(0) should leave only header
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64,
            "resize(0) should leave only header"
        );

        // Test 5: Reopen existing blob preserves header and returns correct logical size
        blob.write_at(0, b"test data").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(0, 9).await.unwrap();
        assert_eq!(read_buf.coalesce(), b"test data");
        drop(blob2);

        // Test 6: Corrupted blob recovery (0 < raw_size < 8)
        // Manually create a corrupted file with only 4 bytes
        let corrupted_path = storage_directory.join("partition").join(hex(b"corrupted"));
        std::fs::write(&corrupted_path, vec![0u8; 4]).unwrap();

        // Opening should truncate and write fresh header
        let (blob3, size3) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");

        // Verify raw file now has proper 8-byte header
        let metadata = std::fs::metadata(&corrupted_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64,
            "corrupted blob should be reset to header-only"
        );

        // Cleanup
        drop(blob3);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage_directory =
            env::temp_dir().join(format!("test_magic_mismatch_{}", random_suffix()));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 1024 * 1024),
            test_pool(),
        );

        // Create the partition directory and a file with invalid magic bytes
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, vec![0u8; Header::SIZE]).unwrap();

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Any file shorter than a header must reset to a valid, empty blob on open
    /// rather than fail as corrupt.
    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        let storage_directory =
            env::temp_dir().join(format!("test_partial_header_reset_{}", random_suffix()));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 1024 * 1024),
            test_pool(),
        );
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        for prefix_len in 0..Header::SIZE {
            let name = format!("short_{prefix_len}");
            let path = partition_path.join(hex(name.as_bytes()));
            // Seed a file shorter than a full header.
            std::fs::write(&path, vec![0u8; prefix_len]).unwrap();

            let (blob, size) = storage
                .open("partition", name.as_bytes())
                .await
                .expect("interrupted create should recover, not fail");
            assert_eq!(size, 0, "recovered blob should be empty");
            drop(blob);

            // The recovered blob is a valid header-only file and reopens cleanly.
            let raw = std::fs::read(&path).unwrap();
            assert_eq!(
                raw.len(),
                Header::SIZE,
                "recovered blob should be header-only"
            );
            assert_eq!(&raw[..Header::MAGIC_LENGTH], &Header::MAGIC);
            storage
                .open("partition", name.as_bytes())
                .await
                .expect("reopen after recovery should succeed");
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_canonical_hex_file_names() {
        // `commonware_formatting::from_hex` is lenient (strips `0x`/`0X` prefixes
        // and ASCII whitespace), but storage only ever writes filenames in the
        // canonical lowercase hex form produced by `hex()`. Verify that scans
        // reject any filename that decodes successfully but doesn't round-trip
        // to its canonical form.
        for bad_name in ["0x626c6f62", "0X626C6F62", " 626c6f62", "626C6F62"] {
            let storage_directory = env::temp_dir().join(format!(
                "test_scan_non_canonical_{}_{}",
                bad_name.replace([' ', '0', 'x', 'X'], "_"),
                random_suffix()
            ));
            let storage = Storage::new(
                Config::new(storage_directory.clone(), 1024 * 1024),
                test_pool(),
            );

            let partition_path = storage_directory.join("partition");
            std::fs::create_dir_all(&partition_path).unwrap();
            std::fs::write(partition_path.join(bad_name), []).unwrap();

            let err = match storage.scan("partition").await {
                Ok(_) => panic!("scan should have failed for filename {bad_name:?}"),
                Err(err) => err,
            };
            assert_eq!(
                err.to_string(),
                "partition corrupt: partition",
                "filename {bad_name:?} should be rejected as corrupt",
            );

            let _ = std::fs::remove_dir_all(&storage_directory);
        }
    }
}
