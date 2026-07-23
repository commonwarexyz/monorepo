use super::Header;
use crate::{BufferPool, Error};
use commonware_formatting::{from_hex, hex};
use commonware_utils::channel::oneshot;
#[cfg(unix)]
use std::path::Path;
#[cfg(all(test, unix))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{future::Future, ops::RangeInclusive, panic, path::PathBuf, sync::Arc};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
    task,
};

#[cfg(not(unix))]
mod fallback;
#[cfg(unix)]
mod unix;

/// Wait for the in-flight task, if any, to finish, then clear it.
///
/// The handle is awaited in place and removed only after it completes: a caller dropped
/// mid-wait leaves the task in flight for whoever comes next, and a finished handle must
/// never be polled again (doing so panics).
///
/// An orphan's error result is discardable (the contract allows a dropped operation to
/// never execute), but a panic is not: it is resumed here rather than silently swallowed.
async fn drain(inflight: &mut Option<task::JoinHandle<()>>) {
    if let Some(handle) = inflight.as_mut() {
        let result = handle.await;
        *inflight = None;
        if let Err(err) = result
            && err.is_panic()
        {
            panic::resume_unwind(err.into_panic());
        }
    }
}

/// Reads a blob's leading bytes and resolves its header (see [super::header::resolve]).
async fn resolve_header(
    file: &mut fs::File,
    raw_len: u64,
    versions: &RangeInclusive<u16>,
    partition: &str,
    name: &[u8],
) -> Result<Option<(u64, u16, u64)>, Error> {
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    file.read_exact(&mut raw)
        .await
        .map_err(|_| Error::ReadFailed)?;
    super::header::resolve(&raw, raw_len, versions, partition, name)
}

/// The filesystem-mutating phase of [crate::Storage::open_versioned].
///
/// Runs to completion on [Storage::run_ordered]'s task, so a dropped open future can
/// never abandon creation half-done (a straggling truncate could clobber a successor's
/// blob) or leave a later open trusting a header whose syncs never ran.
async fn open_inner(
    cfg: Config,
    partition: String,
    name: Vec<u8>,
    versions: RangeInclusive<u16>,
) -> Result<(fs::File, u64, u16, u64), Error> {
    // Construct the full path
    let path = cfg.storage_directory.join(&partition).join(hex(&name));
    let parent = match path.parent() {
        Some(parent) => parent,
        None => return Err(Error::PartitionCreationFailed(partition)),
    };

    // Create the partition directory, if it does not exist
    fs::create_dir_all(parent)
        .await
        .map_err(|_| Error::PartitionCreationFailed(partition.clone()))?;

    // Open the file, creating it if it doesn't exist
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .await
        .map_err(|e| Error::BlobOpenFailed(partition.clone(), hex(&name), e.into()))?;

    let raw_len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();

    // Set the maximum buffer size
    file.set_max_buf_size(cfg.maximum_buffer_size);

    // Handle header: existing blobs have their header read; new blobs and blobs left torn
    // by an interrupted creation get a fresh header written.
    let existing = resolve_header(&mut file, raw_len, &versions, &partition, &name).await?;
    let (logical_size, blob_version, data_offset) = match existing {
        Some(resolved) => resolved,
        None => {
            // Sync the directories before writing the header so a parseable header
            // always implies durable directory entries (an open that parses a header
            // never re-runs these). The storage directory is synced unconditionally:
            // the partition directory existing in the namespace does not imply its
            // entry is durable. (Windows has no notion of syncing a directory entry;
            // see https://github.com/commonwarexyz/monorepo/issues/2026.)
            #[cfg(unix)]
            {
                sync_dir(parent).await?;
                sync_dir(&cfg.storage_directory).await?;
            }

            // Truncate to zero before writing, per the [Header::create] contract.
            let (region, blob_version) = Header::create(&versions);
            let data_offset = region.len() as u64;
            file.set_len(0)
                .await
                .map_err(|e| Error::BlobResizeFailed(partition.clone(), hex(&name), e.into()))?;
            file.rewind().await.map_err(|_| Error::WriteFailed)?;
            file.write_all(&region)
                .await
                .map_err(|_| Error::WriteFailed)?;
            file.sync_all()
                .await
                .map_err(|e| Error::BlobSyncFailed(partition, hex(&name), e.into()))?;
            (0, blob_version, data_offset)
        }
    };

    Ok((file, logical_size, blob_version, data_offset))
}

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
}

impl Config {
    pub const fn new(storage_directory: PathBuf, maximum_buffer_size: usize) -> Self {
        Self {
            storage_directory,
            maximum_buffer_size,
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    /// The in-flight filesystem-mutating task (an open's create phase or a removal), if any.
    ///
    /// Dropping a future does not stop its task: the unlink or create keeps running in the
    /// background. Keeping it here lets the next operation wait for it, so an orphaned
    /// unlink can never delete a recreated blob and an orphaned create can never resurrect
    /// a removed name (the ordering contract on [crate::Storage::remove]). The barrier is
    /// per-instance: independently constructed storages over the same directory are not
    /// coordinated (also per that contract).
    inflight: Arc<Mutex<Option<task::JoinHandle<()>>>>,
    cfg: Config,
    pool: BufferPool,
    /// Number of delete-path directory syncs.
    #[cfg(all(test, unix))]
    delete_dir_syncs: Arc<AtomicU64>,
}

impl Storage {
    pub fn new(cfg: Config, pool: BufferPool) -> Self {
        Self {
            inflight: Arc::new(Mutex::new(None)),
            cfg,
            pool,
            #[cfg(all(test, unix))]
            delete_dir_syncs: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run `op`, ordered after any in-flight task.
    ///
    /// The `inflight` guard is held for the whole operation, so the only way a later
    /// caller finds an in-flight handle is that the future which owned it was dropped.
    /// Dropping this future is safe at every await point: before the spawn, the operation
    /// never executes; after it, the handle stays in flight and the next operation waits
    /// for it.
    ///
    /// `task_failed` supplies the result reported when the task dies without delivering
    /// one (the runtime is shutting down); a panicking task resumes its panic here
    /// instead.
    async fn run_ordered<T: Send + 'static>(
        &self,
        op: impl Future<Output = T> + Send + 'static,
        task_failed: impl FnOnce() -> T,
    ) -> T {
        let mut inflight = self.inflight.lock().await;
        drain(&mut inflight).await;

        let (tx, rx) = oneshot::channel();
        *inflight = Some(task::spawn(async move {
            let _ = tx.send(op.await);
        }));
        let result = rx.await;

        // Reap the finished task and clear it before releasing the guard.
        drain(&mut inflight).await;
        result.unwrap_or_else(|_| task_failed())
    }
}

impl crate::Storage for Storage {
    #[cfg(unix)]
    type Blob = unix::Blob;
    #[cfg(not(unix))]
    type Blob = fallback::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;

        // A dropped open must stay ordered against later opens and removals of the
        // same name.
        let (file, logical_size, blob_version, data_offset) = self
            .run_ordered(
                open_inner(
                    self.cfg.clone(),
                    partition.to_string(),
                    name.to_vec(),
                    versions,
                ),
                || {
                    Err(Error::BlobOpenFailed(
                        partition.into(),
                        hex(name),
                        std::io::Error::other("open task failed").into(),
                    ))
                },
            )
            .await?;

        // Convert to a blocking std::fs::File
        #[cfg(unix)]
        let file = file.into_std().await;

        // Construct the blob
        let blob = Self::Blob::new(partition.into(), name, file, self.pool.clone(), data_offset);
        Ok((blob, logical_size, blob_version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let path = self.cfg.storage_directory.join(partition);
        let partition_owned = partition.to_string();
        let name_owned = name.map(<[u8]>::to_vec);
        #[cfg(unix)]
        let storage_dir = self.cfg.storage_directory.clone();
        #[cfg(all(test, unix))]
        let delete_dir_syncs = self.delete_dir_syncs.clone();

        // A dropped removal must stay ordered against later opens of the same name.
        self.run_ordered(
            async move {
                // Sync the directory below even when the target is already missing: an
                // earlier removal may have unlinked it and then been dropped before its
                // directory sync ran, so the unlink may not be crash-durable yet. Reporting
                // the target as missing promises it is durably gone, and this retry is the
                // only barrier left.
                if let Some(name) = name_owned {
                    let blob_path = path.join(hex(&name));
                    let missing = match fs::remove_file(blob_path).await {
                        Ok(()) => false,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
                        Err(err) => return Err(err.into()),
                    };

                    // Make the unlink durable before reporting the result. A deletion is
                    // durable only once the directory that held the entry is synced:
                    // - The partition directory exists: it held the blob's entry, sync it.
                    // - The partition directory is gone too: an earlier partition removal
                    //   may have deleted it without a durable sync. Its entry lived in the
                    //   storage directory, so sync that instead.
                    // - Neither exists: nothing was ever created, so there is nothing to
                    //   sync.
                    // Windows doesn't have a notion of syncing a directory entry to ensure
                    // that it's durably persisted. See
                    // https://github.com/commonwarexyz/monorepo/issues/2026.
                    #[cfg(unix)]
                    if !missing || fs::try_exists(&path).await? {
                        sync_dir(&path).await?;
                        #[cfg(test)]
                        delete_dir_syncs.fetch_add(1, Ordering::Relaxed);
                    } else if fs::try_exists(&storage_dir).await? {
                        sync_dir(&storage_dir).await?;
                        #[cfg(test)]
                        delete_dir_syncs.fetch_add(1, Ordering::Relaxed);
                    }

                    if missing {
                        return Err(Error::BlobMissing(partition_owned, hex(&name)));
                    }
                } else {
                    let missing = match fs::remove_dir_all(&path).await {
                        Ok(()) => false,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
                        Err(err) => return Err(err.into()),
                    };

                    // Sync the storage directory to ensure the removal is durable. When the
                    // partition was already missing, the storage directory itself may not
                    // exist yet; then there is no directory entry change to persist.
                    // Windows doesn't have a notion of syncing a directory entry to ensure that
                    // it's durably persisted. See
                    // https://github.com/commonwarexyz/monorepo/issues/2026.
                    #[cfg(unix)]
                    if !missing || fs::try_exists(&storage_dir).await? {
                        sync_dir(&storage_dir).await?;
                        #[cfg(test)]
                        delete_dir_syncs.fetch_add(1, Ordering::Relaxed);
                    }

                    if missing {
                        return Err(Error::PartitionMissing(partition_owned));
                    }
                }
                Ok(())
            },
            || {
                Err(Error::Io(
                    std::io::Error::other("remove task failed").into(),
                ))
            },
        )
        .await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Wait for any in-flight open or removal, holding the guard so no new one starts
        // mid-scan.
        let mut inflight = self.inflight.lock().await;
        drain(&mut inflight).await;

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
        Blob, BufferPoolConfig, Storage as _,
        storage::{Layout, tests::run_storage_tests},
        telemetry::metrics::Registry,
    };
    use commonware_utils::sys_rng;
    use futures::FutureExt as _;
    use rand::RngExt as _;
    use std::env;

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    fn random_suffix() -> u64 {
        let mut rng = sys_rng();
        rng.random()
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

        // Test 1: New blob (V1 by default) returns logical size 0 and correct app version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw file holds one header page
        let data_offset = Layout::V1.data_offset();
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "raw file should have a full header page"
        );

        // Test 2: Logical offset handling - write at offset 0 stores at the data offset
        let data = b"hello world";
        blob.write_at(0, data).await.unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), data_offset + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V1.magic());
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[4..6],
            &Layout::V1.runtime_version().to_be_bytes()
        );
        // Data should start at the data offset
        assert_eq!(&raw_content[data_offset as usize..], data);

        // Test 3: Read at logical offset 0 returns data from the data offset
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset + 5,
            "resize(5) should leave 5 raw bytes past the header page"
        );

        // resize(0) should leave only the header page
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "resize(0) should leave only the header page"
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

        // Verify raw file now has a proper header page
        let metadata = std::fs::metadata(&corrupted_path).unwrap();
        assert_eq!(
            metadata.len(),
            Layout::V1.data_offset(),
            "corrupted blob should be reset to header-only"
        );

        // Cleanup
        drop(blob3);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Verify the end-to-end storage-page alignment invariant: paged data written to a V1 blob
    /// with a 4096-byte physical page size occupies exactly one aligned 4096-byte disk page
    /// per physical page (header page included), so page reads never straddle a page boundary.
    #[tokio::test]
    async fn test_v1_paged_alignment() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_aligned_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // A logical page size whose physical page is exactly one 4096-byte storage page.
        const PHYSICAL_PAGE_SIZE: u64 = 4096;
        let logical = crate::buffer::paged::page_size(PHYSICAL_PAGE_SIZE as u32);
        let cache = crate::buffer::paged::CacheRef::new(
            test_pool(),
            logical,
            std::num::NonZeroUsize::new(16).unwrap(),
        );

        // Write several pages of patterned data through the paged writer (V1 blob via open()).
        let (blob, size) = storage.open("partition", b"aligned").await.unwrap();
        let mut writer = crate::buffer::paged::Writer::new(blob, size, 1024, cache)
            .await
            .unwrap();
        let item: Vec<u8> = (0..1000u32).flat_map(|i| i.to_be_bytes()).collect();
        for _ in 0..12 {
            writer.append(&item).await.unwrap();
        }
        let logical_size = writer.size();
        writer.sync().await.unwrap();

        // The raw file is a whole number of 4096-byte pages: one header page plus one page per
        // physical page of data (the partial tail page is zero-padded to a full physical page).
        let file_path = storage_directory.join("partition").join(hex(b"aligned"));
        let raw = std::fs::read(&file_path).unwrap();
        let pages = (logical_size as usize).div_ceil(logical.get() as usize);
        assert_eq!(raw.len() as u64 % PHYSICAL_PAGE_SIZE, 0);
        assert_eq!(
            raw.len() as u64,
            Layout::V1.data_offset() + pages as u64 * PHYSICAL_PAGE_SIZE
        );

        // Every physical page sits exactly within one aligned 4096-byte disk page, with a valid
        // CRC record in its final 12 bytes.
        for page in 0..pages {
            let start = Layout::V1.data_offset() as usize + page * PHYSICAL_PAGE_SIZE as usize;
            let physical = &raw[start..start + PHYSICAL_PAGE_SIZE as usize];
            assert!(
                crate::buffer::paged::validate_page_for_tests(physical),
                "page {page} failed CRC validation at aligned boundary"
            );
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let storage_directory =
            env::temp_dir().join(format!("test_torn_creation_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create a durable V1 blob to obtain the canonical header region bytes.
        let (blob, _) = storage.open("partition", b"torn").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let path = storage_directory.join("partition").join(hex(b"torn"));
        let region = std::fs::read(&path).unwrap();

        // Simulate torn creations (the full state enumeration lives in the
        // Layout::interrupted_creation unit tables): a file truncated mid-CRC and the same
        // prefix at a persisted full length.
        let mut torn_content = vec![0u8; region.len()];
        torn_content[..10].copy_from_slice(&region[..10]);
        let states = [region[..10].to_vec(), torn_content];
        for state in states {
            std::fs::write(&path, &state).unwrap();
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec()).await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen with its data intact.
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);
        }

        // Foreign bytes are corruption, not a torn creation: nonzero padding behind a
        // torn (unparseable) prefix proves the file was never a canonical prefix of a
        // header region.
        let mut corrupt = vec![0u8; region.len()];
        corrupt[..10].copy_from_slice(&region[..10]);
        corrupt[100] = 0xFF;
        std::fs::write(&path, &corrupt).unwrap();
        let result = storage.open("partition", b"torn").await;
        assert!(matches!(result, Err(crate::Error::BlobCorrupt(_, _, _))));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Dropping an open future at any await point must leave the blob openable: creation
    /// runs to completion on a task that owns the filesystem lock, so a retry serializes
    /// behind it and never observes (or clobbers) a half-created blob.
    #[tokio::test]
    async fn test_open_dropped_mid_creation() {
        use futures::FutureExt;
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Poll},
        };

        /// Polls the wrapped future normally, but drops it after a fixed number of polls.
        struct DropAfter<F: Future + Unpin> {
            inner: Option<F>,
            remaining: usize,
        }

        impl<F: Future + Unpin> Future for DropAfter<F> {
            type Output = Option<F::Output>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.remaining == 0 {
                    self.inner = None;
                    return Poll::Ready(None);
                }
                self.remaining -= 1;
                match self.inner.as_mut().unwrap().poll_unpin(cx) {
                    Poll::Ready(output) => Poll::Ready(Some(output)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        let storage_directory =
            env::temp_dir().join(format!("test_dropped_open_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        for depth in 0..64 {
            let name = format!("blob{depth}");
            let name = name.as_bytes();
            let dropped = DropAfter {
                inner: Some(Box::pin(storage.open("partition", name))),
                remaining: depth,
            }
            .await;
            let completed = dropped.is_some();
            drop(dropped);

            // Retry, write data, and confirm it survives reopen.
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec()).await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);

            // Once the first open completes within the poll budget, deeper drops add nothing.
            if completed {
                let _ = std::fs::remove_dir_all(&storage_directory);
                return;
            }
        }
        panic!("open never completed within the poll budget");
    }

    #[tokio::test]
    async fn test_blob_v1_rejects_nonzero_header_padding() {
        let storage_directory =
            env::temp_dir().join(format!("test_v1_header_padding_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let path = partition_dir.join(hex(b"dirty_padding"));
        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
        raw[Header::PARSE_LEN] = 0xFF;
        std::fs::write(&path, raw).unwrap();

        let result = storage.open("partition", b"dirty_padding").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("header padding"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v0_legacy_read() {
        let storage_directory =
            env::temp_dir().join(format!("test_v0_legacy_read_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Fabricate a legacy V0 blob on disk (creation is always V1): an 8-byte header
        // followed immediately by the payload.
        let payload = b"hello world";
        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let file_path = partition_dir.join(hex(b"v0"));
        std::fs::write(
            &file_path,
            crate::storage::header::tests::v0_blob_bytes(0, payload),
        )
        .unwrap();

        // The blob opens with its data intact and remains readable and writable in place.
        let (blob, size) = storage.open("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len()).await.unwrap().coalesce(),
            payload
        );
        blob.write_at(size, b"!".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // On disk the payload still sits immediately after the 8-byte V0 header.
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + payload.len() + 1);
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
        assert_eq!(&raw_content[Header::PRELUDE_SIZE..], b"hello world!");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage_directory =
            env::temp_dir().join(format!("test_magic_mismatch_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create the partition directory and a file whose magic bytes are foreign (not a
        // prefix of any canonical header, so not a torn creation)
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, b"XXXXXXXX").unwrap();

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Any file shorter than a header prelude must reset to a valid, empty blob on open
    /// rather than fail as corrupt.
    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        let storage_directory =
            env::temp_dir().join(format!("test_partial_header_reset_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        for prefix_len in 0..Header::PRELUDE_SIZE {
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
                Layout::V1.data_offset() as usize,
                "recovered blob should be header-only"
            );
            assert_eq!(&raw[..Header::MAGIC_LENGTH], &Layout::V1.magic());
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
                Config {
                    storage_directory: storage_directory.clone(),
                    maximum_buffer_size: 1024 * 1024,
                },
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

    fn test_storage_in(label: &str) -> (Storage, std::path::PathBuf) {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_{label}_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        (Storage::new(config, test_pool()), storage_directory)
    }

    // A write dropped mid-flight must execute before (never after) a later write to the
    // same offset. Without in-flight ordering this test fails flakily.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_dropped_write_ordered_before_replacement() {
        let (storage, storage_directory) = test_storage_in("dropped_write");
        let (blob, _) = storage.open("partition", b"ordering").await.unwrap();

        for i in 0..100u32 {
            let _ = blob.write_at(0, vec![0xAA; 64]).now_or_never();
            blob.write_at(0, vec![0xBB; 64]).await.unwrap();
            let read = blob.read_at(0, 64).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &[0xBB; 64][..], "iteration {i}");
        }

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    // A shrink dropped mid-flight must execute before a later, larger resize: the file
    // ends at the later size, with the shrunken range zero-filled if the shrink ran,
    // never at the stale shorter size.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_dropped_shrink_ordered_before_grow() {
        let (storage, storage_directory) = test_storage_in("dropped_shrink");
        let (blob, _) = storage.open("partition", b"resize").await.unwrap();

        for i in 0..100u32 {
            blob.write_at(0, vec![0xCC; 16]).await.unwrap();
            let _ = blob.resize(3).now_or_never();
            blob.resize(10).await.unwrap();

            // The dropped shrink either executed before the grow (suffix zero-filled) or
            // never executed (suffix intact); it must never execute after the grow.
            let read = blob.read_at(0, 10).await.unwrap().coalesce();
            let read = read.as_ref();
            assert_eq!(&read[..3], &[0xCC; 3][..], "iteration {i}");
            assert!(
                read[3..] == [0u8; 7] || read[3..] == [0xCC; 7],
                "iteration {i}: dropped shrink must land before the grow or never"
            );
            // The stale shrink must not land after the grow and truncate the file.
            assert!(
                blob.read_at(0, 16).await.is_err(),
                "iteration {i}: file must be exactly 10 bytes"
            );
        }

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    // A removal dropped mid-flight must execute before a later open: the orphaned unlink
    // can never delete the blob the open recreates.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_dropped_remove_ordered_before_reopen() {
        let (storage, storage_directory) = test_storage_in("dropped_remove");

        for i in 0..50u32 {
            let (blob, _) = storage.open("partition", b"victim").await.unwrap();
            blob.write_at(0, b"hello".to_vec()).await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            let _ = storage.remove("partition", Some(b"victim")).now_or_never();

            // The open waits for the orphaned removal, so it recreates the blob fresh.
            let (blob, size) = storage.open("partition", b"victim").await.unwrap();
            assert_eq!(size, 0, "iteration {i}: open must observe the removal");
            blob.write_at(0, b"world".to_vec()).await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            // The recreated blob survives: no orphaned unlink lands after the open.
            let (blob, size) = storage.open("partition", b"victim").await.unwrap();
            assert_eq!(size, 5, "iteration {i}: recreated blob must survive");
            let read = blob.read_at(0, 5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"world", "iteration {i}");
            drop(blob);

            storage.remove("partition", Some(b"victim")).await.unwrap();
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    // Reporting a removal target as missing promises it is durably gone, so `remove`
    // must sync the directory before returning `BlobMissing`/`PartitionMissing`. The
    // dangerous case: an earlier removal unlinked the blob but was dropped before its
    // directory sync ran, so the unlink may not survive a crash. The retry finds the
    // blob already missing and is the last chance to run the barrier.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_remove_missing_blob_still_syncs_directory() {
        let (storage, storage_directory) = test_storage_in("remove_missing");

        // Model the dangerous case directly: create the blob, then unlink it with
        // std::fs (no directory sync). The disk now looks exactly as if a removal was
        // dropped between its unlink and its sync.
        let (blob, _) = storage.open("partition", b"barrier").await.unwrap();
        drop(blob);
        let blob_path = storage_directory.join("partition").join(hex(b"barrier"));
        std::fs::remove_file(&blob_path).unwrap();

        // Retrying the removal reports the blob missing, but must sync the partition
        // directory first.
        let before = storage.delete_dir_syncs.load(Ordering::Relaxed);
        let err = storage
            .remove("partition", Some(b"barrier"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BlobMissing(..)));
        assert_eq!(
            storage.delete_dir_syncs.load(Ordering::Relaxed),
            before + 1,
            "the barrier must run even when the blob is already gone"
        );

        // Removing a blob whose partition directory is absent still syncs the storage
        // directory: the backend cannot distinguish a partition that never existed from
        // one whose removal was unlinked but never made durable, so it conservatively
        // runs the remaining barrier.
        let before = storage.delete_dir_syncs.load(Ordering::Relaxed);
        let err = storage
            .remove("elsewhere", Some(b"barrier"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BlobMissing(..)));
        assert_eq!(storage.delete_dir_syncs.load(Ordering::Relaxed), before + 1);

        // The dangerous variant of the case above: the whole partition was unlinked
        // without syncing the storage directory (a partition removal dropped between
        // its remove_dir_all and its sync). Retrying a blob removal inside it is the
        // last chance to run the storage-directory barrier before `BlobMissing`
        // promises the blob is durably gone.
        let partition_path = storage_directory.join("gone");
        std::fs::create_dir_all(&partition_path).unwrap();
        std::fs::write(partition_path.join(hex(b"barrier")), []).unwrap();
        std::fs::remove_dir_all(&partition_path).unwrap();

        let before = storage.delete_dir_syncs.load(Ordering::Relaxed);
        let err = storage.remove("gone", Some(b"barrier")).await.unwrap_err();
        assert!(matches!(err, Error::BlobMissing(..)));
        assert_eq!(
            storage.delete_dir_syncs.load(Ordering::Relaxed),
            before + 1,
            "the storage directory barrier must run when the partition itself is already gone"
        );

        // Removing an already-missing partition still syncs when the storage directory
        // exists: a dropped partition removal leaves the same durability gap.
        let before = storage.delete_dir_syncs.load(Ordering::Relaxed);
        let err = storage.remove("elsewhere", None).await.unwrap_err();
        assert!(matches!(err, Error::PartitionMissing(..)));
        assert_eq!(storage.delete_dir_syncs.load(Ordering::Relaxed), before + 1);

        // On a fresh storage whose directory does not exist yet, removals report the
        // target missing without attempting a sync: nothing exists to persist.
        let (fresh, fresh_directory) = test_storage_in("remove_missing_fresh");
        let err = fresh.remove("nope", None).await.unwrap_err();
        assert!(matches!(err, Error::PartitionMissing(..)));
        let err = fresh.remove("nope", Some(b"blob")).await.unwrap_err();
        assert!(matches!(err, Error::BlobMissing(..)));
        assert_eq!(fresh.delete_dir_syncs.load(Ordering::Relaxed), 0);

        let _ = std::fs::remove_dir_all(&storage_directory);
        let _ = std::fs::remove_dir_all(&fresh_directory);
    }
}
