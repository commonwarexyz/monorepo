//! This module provides an io_uring-based implementation of the [crate::Storage] trait,
//! offering fast, high-throughput file operations on Linux systems.
//!
//! ## Architecture
//!
//! I/O operations are submitted through an io_uring [Handle][crate::iouring::Handle] to a
//! dedicated event loop running in another thread.
//!
//! ## Memory Safety
//!
//! Buffers and file descriptors are owned by the active request state machine inside the io_uring
//! loop, ensuring that the memory location is valid for the duration of the operation.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring-storage` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.
//! It requires Linux kernel 6.1 or newer. See [crate::iouring] for details.

use super::{
    Generation, Header, Layout, Pending, Tracker, defer_sync, hold::Hold, resolve_header, sync_dir,
};
use crate::{
    BlobVersion, Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions,
    iouring::{self},
    telemetry::metrics::Register,
    utils,
};
use commonware_formatting::{from_hex, hex};
use commonware_utils::sync::Mutex;
use std::{
    fs::{self, File},
    io::{Error as IoError, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

/// Configuration for a [Storage].
#[derive(Clone, Debug)]
pub struct Config {
    /// Where to store blobs.
    pub storage_directory: PathBuf,
    /// Blob layouts accepted by storage.
    pub blob_layouts: RangeInclusive<Layout>,
    /// Configuration for the iouring instance. `single_issuer` is forced on and
    /// `shutdown_timeout` is forced to `None`: the ring must drain every
    /// in-flight operation before the directory hold releases.
    pub iouring_config: iouring::Config,
    /// Stack size for the dedicated io_uring worker thread.
    pub thread_stack_size: usize,
}

#[derive(Clone)]
pub struct Storage {
    lock: Arc<Mutex<()>>,
    storage_directory: PathBuf,
    blob_layouts: RangeInclusive<Layout>,
    io_handle: iouring::Handle,
    pool: BufferPool,
    pending: Arc<Pending>,
}

impl Storage {
    /// Returns a new `Storage` instance.
    pub(crate) fn start(cfg: Config, registry: &mut impl Register, pool: BufferPool) -> Self {
        let Config {
            storage_directory,
            blob_layouts,
            mut iouring_config,
            thread_stack_size,
        } = cfg;

        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        iouring_config.single_issuer = true;

        // The directory hold's guarantee requires the ring to drain in-flight
        // operations before it exits: a finite shutdown deadline would let the
        // loop abandon operations that then land after the hold releases.
        iouring_config.shutdown_timeout = None;

        let (io_handle, iouring_loop) = iouring::IoUringLoop::new(iouring_config, registry);

        let hold = Hold::acquire(&storage_directory).unwrap_or_else(|e| {
            panic!(
                "failed to acquire storage directory hold ({}): {e}",
                storage_directory.display()
            )
        });

        let storage = Self {
            lock: Arc::new(Mutex::new(())),
            storage_directory,
            blob_layouts,
            io_handle,
            pool,
            pending: Arc::new(Pending::default()),
        };

        utils::thread::spawn(thread_stack_size, move || {
            // Hold the storage directory until the ring has drained. The loop
            // exits only after every ring handle is dropped and in-flight work
            // completes, and the storage instance and every blob own a handle,
            // so the hold outlives them and every operation they issue.
            let _hold = hold;
            iouring_loop.run()
        });
        storage
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Blob, u64, BlobVersion), Error> {
        super::validate_partition_name(partition)?;

        let (blob, logical_len, blob_version, wait) = {
            // Acquire the filesystem lock
            let _guard = self.lock.lock();

            // Construct the full path
            let path = self.storage_directory.join(partition).join(hex(name));
            let parent = path
                .parent()
                .ok_or_else(|| Error::PartitionMissing(partition.into()))?;

            // Create the partition directory if it does not exist
            fs::create_dir_all(parent)
                .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

            // Open the file, creating it if it doesn't exist
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e.into()))?;

            let raw_len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

            // Handle the header. Existing blobs have their header read. New blobs and blobs left
            // torn by an interrupted creation get a fresh header written.
            let existing = resolve_header(
                &mut file,
                raw_len,
                &self.blob_layouts,
                &versions,
                partition,
                name,
            )?;

            if existing.is_none() {
                self.pending.forget(partition, Some(name));
            }
            let (generation, wait) = self.pending.attach(partition, name);

            let (logical_len, blob_version, data_offset) = match existing {
                Some(resolved) => resolved,
                None => (|| {
                    // Sync the directories before writing the header so a parseable header
                    // always implies durable directory entries (an open that parses a header
                    // never re-runs these). The storage directory is synced unconditionally:
                    // the partition directory existing in the namespace does not imply its
                    // entry is durable.
                    sync_dir(parent)?;
                    sync_dir(&self.storage_directory)?;

                    // Truncate to zero before writing, per the [Header::create] contract.
                    let (region, blob_version) = Header::create(&self.blob_layouts, &versions);
                    let data_offset = region.len() as u64;
                    file.set_len(0).map_err(|e| {
                        Error::BlobResizeFailed(partition.into(), hex(name), e.into())
                    })?;
                    file.seek(SeekFrom::Start(0))
                        .map_err(|_| Error::WriteFailed)?;
                    #[cfg(test)]
                    if let Some(len) = self.pending.fail_creation_after.lock().take() {
                        file.write_all(&region[..len.min(region.len())])
                            .map_err(|_| Error::WriteFailed)?;
                        return Err(Error::Closed);
                    }
                    file.write_all(&region).map_err(|_| Error::WriteFailed)?;
                    file.sync_all().map_err(|e| {
                        Error::BlobSyncFailed(partition.into(), hex(name), e.into())
                    })?;

                    Ok((0, blob_version, data_offset))
                })()
                .inspect_err(|error: &Error| {
                    // Retain creation failures until the namespace entry is removed or replaced.
                    let sender = self
                        .pending
                        .start(&generation)
                        .expect("creation owns its namespace entry");
                    self.pending.finish(&generation, sender, Err(error.clone()));
                })?,
            };

            let blob = Blob::new(
                file,
                self.io_handle.clone(),
                self.pool.clone(),
                data_offset,
                generation,
            );
            (blob, logical_len, blob_version, wait)
        };
        Pending::wait(wait).await?;
        Ok((blob, logical_len, blob_version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock();

        let path = self.storage_directory.join(partition);
        let sync_path = if let Some(name) = name {
            let blob_path = path.join(hex(name));
            fs::remove_file(blob_path)
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;

            &path
        } else {
            fs::remove_dir_all(&path).map_err(|_| Error::PartitionMissing(partition.into()))?;

            &self.storage_directory
        };

        self.pending.forget(partition, name);
        sync_dir(sync_path)
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock();

        let path = self.storage_directory.join(partition);

        let entries =
            std::fs::read_dir(&path).map_err(|_| Error::PartitionMissing(partition.into()))?;

        let mut blobs = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| Error::ReadFailed)?;
            let file_type = entry.file_type().map_err(|_| Error::ReadFailed)?;

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

#[derive(Clone)]
pub struct Blob {
    /// The underlying file and its write tracking, shared by every clone of this open
    shared: Arc<Shared>,
    /// Buffer pool for read allocations
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// Whether the kernel and filesystem may support `RWF_DONTCACHE`.
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted I/O operation.
    dont_cache_supported: Arc<AtomicBool>,
}

/// A blob's file with the writes no completed sync covers.
///
/// Dropping the last handle while dirty starts a deferred sync that later opens of the blob
/// wait for. The ring handle keeps the storage directory held through that sync.
struct Shared {
    file: Arc<File>,
    io_handle: iouring::Handle,
    tracker: Tracker,
    generation: Arc<Generation>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        if !self.tracker.is_dirty() {
            return;
        }
        let file = self.file.clone();
        let io_handle = self.io_handle.clone();
        let generation = self.generation.clone();
        defer_sync(generation.clone(), move || {
            let _io_handle = io_handle;
            file.sync_data().map_err(|e| {
                let (partition, name) = &generation.key;
                Error::BlobSyncFailed(partition.clone(), hex(name), e.into())
            })
        });
    }
}

impl Blob {
    /// Construct a blob handle around an already-open file and shared io_uring loop.
    fn new(
        file: File,
        io_handle: iouring::Handle,
        pool: BufferPool,
        data_offset: u64,
        generation: Arc<Generation>,
    ) -> Self {
        let shared = Shared {
            file: Arc::new(file),
            io_handle,
            tracker: Tracker::default(),
            generation,
        };
        Self {
            shared: Arc::new(shared),
            pool,
            data_offset,
            dont_cache_supported: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl crate::Blob for Blob {
    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, self.pool.alloc(len), options)
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        let mut input_bufs = bufs.into();
        // SAFETY: `len` bytes are filled via io_uring read loop below.
        unsafe { input_bufs.set_len(len) };

        // For single buffers, read directly into them (zero-copy).
        // For multi-chunk buffers, use a temporary and copy to preserve the input structure.
        let (io_buf, original_bufs) = if input_bufs.is_single() {
            (input_bufs.coalesce(), None)
        } else {
            // SAFETY: `len` bytes are filled via io_uring read loop below.
            let tmp = unsafe { self.pool.alloc_len(len) };
            (tmp, Some(input_bufs))
        };

        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        // Zero-length reads succeed trivially without submitting to the ring.
        if len == 0 {
            return Ok(original_bufs.unwrap_or_else(|| io_buf.into()));
        }

        let cache = if options.contains(ReadOptions::DONT_CACHE) {
            iouring::Cache::Disabled(self.dont_cache_supported.clone())
        } else {
            iouring::Cache::Enabled
        };
        let io_buf = self
            .shared
            .io_handle
            .read_at(self.shared.file.clone(), offset, len, io_buf, cache)
            .await
            .map_err(|(_, err)| err)?;

        match original_bufs {
            None => Ok(io_buf.into()),
            Some(mut bufs) => {
                bufs.copy_from_slice(io_buf.as_ref());
                Ok(bufs)
            }
        }
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        let cache = if options.contains(WriteOptions::DONT_CACHE) {
            iouring::Cache::Disabled(self.dont_cache_supported.clone())
        } else {
            iouring::Cache::Enabled
        };

        let sync = options.contains(WriteOptions::SYNC);
        let seen = if sync {
            self.shared.tracker.begin_sync()
        } else {
            0
        };
        if !sync {
            self.shared.tracker.write();
        }
        let result = self
            .shared
            .io_handle
            .write_at(self.shared.file.clone(), offset, bufs, options, cache)
            .await;
        if sync {
            match &result {
                Ok(true) => self.shared.tracker.end_sync(seen),
                Err(_) => self.shared.tracker.write(),
                Ok(false) => {}
            }
        } else if result.is_ok() {
            self.shared.tracker.complete();
        }
        result.map(|_| ())
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn resize(&self, len: u64) -> Result<(), Error> {
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        self.shared.tracker.write();
        self.shared.file.set_len(len).map_err(|e| {
            let (partition, name) = &self.shared.generation.key;
            Error::BlobResizeFailed(partition.clone(), hex(name), IoError::other(e).into())
        })?;
        self.shared.tracker.complete();
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if !self.shared.tracker.is_dirty() {
            #[cfg(test)]
            self.shared.tracker.skip_sync();
            return Ok(());
        }
        let seen = self.shared.tracker.begin_sync();
        self.shared
            .io_handle
            .sync(self.shared.file.clone())
            .await
            .map_err(|err| match err {
                Error::Io(e) => {
                    let (partition, name) = &self.shared.generation.key;
                    Error::BlobSyncFailed(partition.clone(), hex(name), e)
                }
                err => err,
            })?;
        self.shared.tracker.end_sync(seen);
        Ok(())
    }

    async fn start_sync(&self) -> Handle<()> {
        if !self.shared.tracker.is_dirty() {
            #[cfg(test)]
            self.shared.tracker.skip_sync();
            return Handle::ready(Ok(()));
        }
        let shared = self.shared.clone();
        let seen = shared.tracker.begin_sync();
        let receiver = self
            .shared
            .io_handle
            .start_sync(self.shared.file.clone())
            .await;
        Handle::from_future(async move {
            match receiver.await {
                Ok(Ok(())) => {
                    shared.tracker.end_sync(seen);
                    Ok(())
                }
                Ok(Err(Error::Io(e))) => {
                    let (partition, name) = &shared.generation.key;
                    Err(Error::BlobSyncFailed(partition.clone(), hex(name), e))
                }
                Ok(Err(err)) => Err(err),
                Err(_) => Err(Error::Closed),
            }
        })
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::{Header, *};
    use crate::{
        Blob as _, BufferPool, BufferPoolConfig, IoBuf, IoBufMut, Storage as _,
        storage::{Layout, tests::run_storage_tests},
        telemetry::metrics::Registry,
        utils::thread,
    };
    use std::{
        env,
        ffi::OsString,
        os::{
            fd::{FromRawFd, IntoRawFd},
            unix::{ffi::OsStringExt, net::UnixStream},
        },
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_STORAGE_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_storage(), scope)
    }

    /// Build a fresh storage instance rooted in a unique temporary directory.
    fn create_test_storage() -> (Storage, PathBuf) {
        let storage_directory = env::temp_dir().join(format!(
            "commonware_iouring_storage_{}_{}",
            std::process::id(),
            NEXT_STORAGE_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&storage_directory);

        let storage = start_test_storage(storage_directory.clone());
        (storage, storage_directory)
    }

    fn start_test_storage(storage_directory: PathBuf) -> Storage {
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        Storage::start(
            Config {
                storage_directory,
                blob_layouts: Layout::ALL,
                iouring_config: Default::default(),
                thread_stack_size: thread::system_thread_stack_size(),
            },
            &mut registry.sub_registry("storage"),
            pool,
        )
    }

    /// Build a fresh temporary directory without starting a storage loop.
    fn create_test_directory() -> PathBuf {
        let storage_directory = env::temp_dir().join(format!(
            "commonware_iouring_storage_{}_{}",
            std::process::id(),
            NEXT_STORAGE_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&storage_directory);
        std::fs::create_dir_all(&storage_directory).unwrap();
        storage_directory
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_recreate_reopen_waits_for_current_generation_sync() {
        let (storage, storage_directory) = create_test_storage();
        super::super::check_recreate_reopen(&storage, &storage.pending).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_failed_creation_does_not_publish_unsynced_header() {
        let (storage, storage_directory) = create_test_storage();
        super::super::check_failed_creation(&storage, &storage.pending).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_remove_live_dirty_owner_defers_nothing() {
        let (storage, storage_directory) = create_test_storage();
        super::super::check_remove_live_dirty_owner(&storage, &storage.pending, &storage.pool)
            .await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_durable_writes_need_no_reopen_sync() {
        let (storage, storage_directory) = create_test_storage();
        super::super::check_sync_writes(&storage, &storage.pending).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_multibatch_durable_write_covers_prior_mutations() {
        let (storage, storage_directory) = create_test_storage();
        for (case, (chunks, options, later_plain, expected)) in [
            (1025, WriteOptions::SYNC, false, 0),
            (
                1025,
                WriteOptions::SYNC | WriteOptions::DONT_CACHE,
                false,
                0,
            ),
            (1024, WriteOptions::SYNC, false, 1),
            (0, WriteOptions::SYNC, false, 1),
            (1025, WriteOptions::default(), false, 1),
            (1025, WriteOptions::SYNC, true, 1),
        ]
        .into_iter()
        .enumerate()
        {
            let before = storage.pending.finished();
            let (blob, _) = storage.open("large_durable", &[case as u8]).await.unwrap();
            blob.write_at(0, b"prefix", WriteOptions::default())
                .await
                .unwrap();
            let mut bufs = crate::IoBufs::default();
            for _ in 0..chunks {
                bufs.append(crate::IoBuf::from(vec![7u8]));
            }
            blob.write_at(6, bufs, options).await.unwrap();
            if later_plain {
                blob.write_at(0, b"suffix", WriteOptions::default())
                    .await
                    .unwrap();
            }
            drop(blob);
            let (blob, size) = storage.open("large_durable", &[case as u8]).await.unwrap();
            assert_eq!(size, 6 + chunks);
            let actual = blob
                .read_at(0, size as usize, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(
                &actual.as_ref()[..6],
                if later_plain { b"suffix" } else { b"prefix" }
            );
            assert!(actual.as_ref()[6..].iter().all(|byte| *byte == 7));
            drop(blob);
            assert_eq!(storage.pending.finished() - before, expected, "case={case}");
        }
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_hold_retained_by_open_blob() {
        let (storage, storage_directory) = create_test_storage();

        // An open blob keeps the ring alive (and with it the directory hold),
        // since a write or resize through it can still straggle. Dropping the
        // storage while the blob lives must not release the hold.
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        drop(storage);

        let dir = storage_directory.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let second = start_test_storage(dir);
            tx.send(()).unwrap();
            drop(second);
        });
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            other => panic!("second instance did not stay blocked on the hold: {other:?}"),
        }
        drop(blob);
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("second instance did not acquire the hold after the blob dropped");
        handle.join().unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[test]
    fn test_hold_retained_by_deferred_sync() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (storage, storage_directory) = create_test_storage();
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, vec![1], WriteOptions::default())
                .await
                .unwrap();

            // Occupy the blocking pool so the deferred sync stays queued throughout teardown.
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
            ready_rx.recv().unwrap();
            let pending = storage.pending.clone();
            drop(blob);
            drop(storage);

            let dir = storage_directory.clone();
            let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
            let successor = std::thread::spawn(move || {
                let storage = start_test_storage(dir);
                acquired_tx.send(()).unwrap();
                drop(storage);
            });
            let early = acquired_rx.recv_timeout(std::time::Duration::from_millis(200));

            // Release the pool before asserting so a failure cannot strand the blocking task.
            release_tx.send(()).unwrap();
            blocker.await.unwrap();
            Pending::wait(pending.attach("partition", b"blob").1)
                .await
                .unwrap();
            if early.is_err() {
                acquired_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .expect("successor did not acquire the directory after sync");
            }
            successor.join().unwrap();
            let _ = std::fs::remove_dir_all(storage_directory);
            assert!(
                matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
                "successor acquired the directory before the deferred sync: {early:?}"
            );
            assert_eq!(pending.finished(), 1);
        });
    }

    /// Verify the end-to-end storage-page alignment invariant on the io_uring backend: paged
    /// data written to a V1 blob with a 4096-byte physical page size occupies exactly one
    /// aligned 4096-byte disk page per physical page (header page included), so page reads
    /// never straddle a page boundary.
    #[tokio::test]
    async fn test_v1_paged_alignment() {
        let (storage, storage_directory) = create_test_storage();

        // A logical page size whose physical page is exactly one 4096-byte storage page.
        const PHYSICAL_PAGE_SIZE: u64 = 4096;
        let logical = crate::buffer::paged::page_size(PHYSICAL_PAGE_SIZE as u32);
        let mut registry = Registry::default();
        let cache = crate::buffer::paged::CacheRef::new(
            test_pool(&mut registry.sub_registry("pool")),
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
    async fn test_iouring_storage() {
        // Verify the io_uring storage backend satisfies the shared storage trait suite.
        let (storage, storage_directory) = create_test_storage();
        run_storage_tests(storage).await;
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        // Verify header creation, logical offsets, resize, reopen, and corruption recovery.
        let (storage, storage_directory) = create_test_storage();

        // Test 1: New blob (V1 by default) returns logical size 0 and correct application version
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
        blob.write_at(0, data.to_vec(), WriteOptions::default())
            .await
            .unwrap();
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
            &Layout::V1.layout_version().to_be_bytes()
        );
        // Data should start at the data offset
        assert_eq!(&raw_content[data_offset as usize..], data);

        // Test 3: Read at logical offset 0 returns data from the data offset
        let read_buf = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read_buf, data);

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
        blob.write_at(0, b"test data".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2
            .read_at(0, 9, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read_buf, b"test data");
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

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        // Verify opening a blob with an invalid runtime header fails as corrupt.
        let (storage, storage_directory) = create_test_storage();

        // Create the partition directory
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        // Manually create a file whose magic bytes are foreign (not a prefix of any
        // canonical header, so not a torn creation)
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, b"XXXXXXXX").unwrap();

        // Opening should fail with corrupt error
        let err = storage
            .open("partition", b"bad_magic")
            .await
            .err()
            .expect("bad magic should fail");
        assert!(
            err.to_string()
                .starts_with("blob corrupt: partition/6261645f6d61676963 reason: invalid magic")
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        // Any file shorter than a header prelude must reset to a valid, empty blob on open
        // rather than fail as corrupt.
        let (storage, storage_directory) = create_test_storage();
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
    async fn test_vectored_write_partial_progress() {
        // Verify multi-buffer writes survive partial progress and preserve byte order.
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"vectest").await.unwrap();
        blob.resize(200).await.unwrap();

        // Write multiple buffers in one vectored call.
        let mut bufs = crate::IoBufs::default();
        bufs.append(crate::IoBuf::from(vec![0xAAu8; 80]));
        bufs.append(crate::IoBuf::from(vec![0xBBu8; 80]));
        blob.write_at(0, bufs, WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // Read back and verify.
        let data = blob
            .read_at(0, 160, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(&data.as_ref()[..80], &[0xAAu8; 80]);
        assert_eq!(&data.as_ref()[80..], &[0xBBu8; 80]);

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_read_at_reports_eof_when_blob_is_too_short() {
        // Verify read-at returns `BlobInsufficientLength` when the kernel reports EOF mid-read.
        let (storage, storage_directory) = create_test_storage();

        // Persist fewer bytes than the upcoming read requests so the wrapper
        // encounters EOF after the header-adjusted offset has already started reading.
        let (blob, _) = storage.open("partition", b"short").await.unwrap();
        blob.write_at(0, b"abc".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // The wrapper should surface this as an insufficient-length error instead
        // of silently returning a short buffer.
        let err = blob
            .read_at(0, 5, ReadOptions::DONT_CACHE)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "blob insufficient length");

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_read_at_buf_preserves_multichunk_layout() {
        // Verify multi-chunk caller buffers keep their shape after the temporary-buffer fallback.
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"multichunk").await.unwrap();
        blob.write_at(0, b"hello world".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // Use a two-chunk destination so the read path must rebuild the original
        // chunk layout after reading through a temporary contiguous buffer.
        let bufs = IoBufsMut::from(vec![IoBufMut::with_capacity(5), IoBufMut::with_capacity(6)]);
        let read = blob
            .read_at_buf(0, 11, bufs, ReadOptions::DONT_CACHE)
            .await
            .unwrap();
        // The result should keep the split layout rather than collapsing to one buffer.
        assert!(!read.is_single());
        assert_eq!(read.coalesce(), b"hello world");

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_zero_length_read_and_write_short_circuit() {
        // Verify zero-length reads and writes complete without touching the ring.
        let (storage, storage_directory) = create_test_storage();

        let (blob, size) = storage.open("partition", b"empty").await.unwrap();
        assert_eq!(size, 0);

        // Zero-length operations should succeed immediately and preserve the empty blob.
        blob.write_at(0, IoBufs::default(), WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(0, IoBuf::default(), WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(0, Vec::<u8>::new(), WriteOptions::default())
            .await
            .unwrap();

        // A zero-length read beyond EOF retains io_uring's existing success behavior and must
        // still short-circuit before touching the disconnected backend or probing hint support.
        let empty = blob.read_at(1, 0, ReadOptions::DONT_CACHE).await.unwrap();
        assert!(empty.is_empty());
        let _ = blob
            .read_at_buf(
                0,
                0,
                IoBufsMut::from(IoBufMut::with_capacity(8)),
                ReadOptions::DONT_CACHE,
            )
            .await
            .unwrap();

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_file_entries() {
        // Verify partition scans reject unexpected directory contents as corruption.
        let (storage, storage_directory) = create_test_storage();

        // Inject a nested directory where `scan` expects only regular blob files.
        let partition = storage_directory.join("partition");
        std::fs::create_dir_all(partition.join("nested")).unwrap();

        // The wrapper should treat the partition as corrupt rather than silently skipping it.
        let err = storage.scan("partition").await.unwrap_err();
        assert_eq!(err.to_string(), "partition corrupt: partition");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_remove_reports_missing_targets() {
        // Verify wrapper-level remove errors distinguish missing partitions from missing blobs.
        let (storage, storage_directory) = create_test_storage();

        // Removing a missing partition should fail before any blob-specific path logic runs.
        let err = storage.remove("missing", None).await.unwrap_err();
        assert_eq!(err.to_string(), "partition missing: missing");

        // Once the partition exists, removing an absent blob should surface the
        // more specific `BlobMissing` error instead.
        std::fs::create_dir_all(storage_directory.join("partition")).unwrap();
        let err = storage
            .remove("partition", Some(b"missing"))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "blob missing: partition/6d697373696e67");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_ignores_non_utf8_file_names() {
        // Verify partition scans ignore entries whose names cannot be represented as UTF-8.
        let (storage, storage_directory) = create_test_storage();

        let partition = storage_directory.join("partition");
        std::fs::create_dir_all(&partition).unwrap();

        // Create a valid file entry with a non-UTF8 name so `scan` exercises
        // the branch that skips names it cannot decode.
        let invalid_name = OsString::from_vec(vec![0xff, 0xfe, 0xfd]);
        std::fs::write(partition.join(invalid_name), []).unwrap();

        let scanned = storage.scan("partition").await.unwrap();
        assert!(scanned.is_empty());

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_hex_file_names() {
        // Verify partition scans reject UTF-8 entries that are not valid blob names.
        let (storage, storage_directory) = create_test_storage();

        let partition = storage_directory.join("partition");
        std::fs::create_dir_all(&partition).unwrap();

        // Create a file whose name is valid UTF-8 but not valid hex.
        std::fs::write(partition.join("not-hex"), []).unwrap();

        let err = storage.scan("partition").await.unwrap_err();
        assert_eq!(err.to_string(), "partition corrupt: partition");

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
            let (storage, storage_directory) = create_test_storage();

            let partition = storage_directory.join("partition");
            std::fs::create_dir_all(&partition).unwrap();
            std::fs::write(partition.join(bad_name), []).unwrap();

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

    #[tokio::test]
    async fn test_open_reports_partition_creation_failure() {
        // Verify opening a blob reports partition-creation failures when the
        // partition path is occupied by a regular file. (An unusable storage
        // root fails Storage::start itself, when the directory hold is
        // acquired.)
        let storage_directory = create_test_directory();
        std::fs::write(storage_directory.join("partition"), b"not a directory").unwrap();

        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                blob_layouts: Layout::ALL,
                iouring_config: Default::default(),
                thread_stack_size: utils::thread::system_thread_stack_size(),
            },
            &mut registry.sub_registry("storage"),
            pool,
        );

        let err = storage
            .open("partition", b"blob")
            .await
            .err()
            .expect("occupied partition path should fail");
        assert_eq!(err.to_string(), "partition creation failed: partition");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_open_reports_blob_open_failure_for_directory_path() {
        // Verify opening a blob reports `BlobOpenFailed` when the blob path
        // already exists as a directory instead of a regular file.
        let storage_directory = create_test_directory();
        let partition = storage_directory.join("partition");
        let blob_name = hex(b"blob");

        // Pre-create the would-be blob path as a directory so `OpenOptions`
        // fails once the wrapper reaches the open call.
        std::fs::create_dir_all(partition.join(&blob_name)).unwrap();

        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                blob_layouts: Layout::ALL,
                iouring_config: Default::default(),
                thread_stack_size: utils::thread::system_thread_stack_size(),
            },
            &mut registry.sub_registry("storage"),
            pool,
        );

        let err = storage
            .open("partition", b"blob")
            .await
            .err()
            .expect("opening a directory as a blob should fail");
        assert!(
            err.to_string()
                .starts_with(&format!("blob open failed: partition/{blob_name} error:"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_offset_overflow_guards() {
        // Verify logical offsets are checked before any filesystem or io_uring work.
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage.open("partition", b"overflow").await.unwrap();

        // Each operation adds the runtime header size internally, so using the
        // maximum logical offset must fail before any request is submitted.
        assert_eq!(
            blob.read_at(u64::MAX, 1, ReadOptions::default())
                .await
                .unwrap_err()
                .to_string(),
            "offset overflow"
        );
        assert_eq!(
            blob.read_at(u64::MAX, 0, ReadOptions::DONT_CACHE)
                .await
                .unwrap_err()
                .to_string(),
            "offset overflow"
        );
        assert_eq!(
            blob.read_at(i64::MAX as u64, 1, ReadOptions::DONT_CACHE)
                .await
                .unwrap_err()
                .to_string(),
            "read failed"
        );
        assert_eq!(
            blob.write_at(u64::MAX, b"x".to_vec(), WriteOptions::default())
                .await
                .unwrap_err()
                .to_string(),
            "offset overflow"
        );
        assert_eq!(
            blob.resize(u64::MAX).await.unwrap_err().to_string(),
            "offset overflow"
        );

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_read_and_write_report_handle_disconnect() {
        // Verify read/write wrappers report channel disconnects before any work
        // reaches the io_uring loop.
        let storage_directory = create_test_directory();
        let path = storage_directory.join("disconnected");
        let file = File::create(&path).unwrap();

        // Drop the loop immediately so the handle behaves like a dead
        // backend while the blob handle still exists.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
            Arc::new(Pending::default()).attach("partition", b"blob").0,
        );

        let empty = blob.read_at(0, 0, ReadOptions::DONT_CACHE).await.unwrap();
        assert!(empty.is_empty());
        assert!(
            blob.dont_cache_supported
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        // Read and write should fail through their wrapper-specific error enums
        // when the submission channel has already been disconnected.
        assert_eq!(
            blob.read_at(0, 1, ReadOptions::default())
                .await
                .unwrap_err()
                .to_string(),
            "read failed"
        );
        assert_eq!(
            blob.write_at(0, b"x".to_vec(), WriteOptions::default())
                .await
                .unwrap_err()
                .to_string(),
            "write failed"
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_sync_dir_reports_missing_directory() {
        // Verify directory fsync reports missing paths through the open-failure wrapper.
        let storage_directory = create_test_directory();
        let missing = storage_directory.join("missing");

        let err = sync_dir(&missing).expect_err("missing directory should fail");
        assert!(err.to_string().starts_with(&format!(
            "blob open failed: {}/directory error:",
            missing.to_string_lossy()
        )));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_sync_reports_handle_disconnect() {
        // Verify the storage wrapper maps submission-channel disconnects to
        // `BlobSyncFailed(..., "failed to send work")`.
        let storage_directory = create_test_directory();
        let path = storage_directory.join("disconnected");
        let file = File::create(&path).unwrap();

        // Construct a blob handle whose handle has already lost its loop so
        // the wrapper must synthesize the disconnect error locally.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
            Arc::new(Pending::default()).attach("partition", b"blob").0,
        );
        // A clean open skips the sync, so record an uncovered mutation first. The sync should
        // then fail through the blob-specific wrapper before any kernel work is attempted.
        blob.shared.tracker.write();
        let err = blob
            .sync()
            .await
            .expect_err("sync should fail without a loop");
        assert_eq!(
            err.to_string(),
            format!(
                "blob sync failed: partition/{} error: failed to send work",
                hex(b"blob")
            )
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_start_sync_reports_handle_disconnect() {
        // Verify start_sync completion errors use the same blob-specific wrapper as sync.
        let storage_directory = create_test_directory();
        let path = storage_directory.join("disconnected_start_sync");
        let file = File::create(&path).unwrap();

        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
            Arc::new(Pending::default()).attach("partition", b"blob").0,
        );
        // A clean open skips the sync, so record an uncovered mutation first.
        blob.shared.tracker.write();
        let err = blob
            .start_sync()
            .await
            .await
            .expect_err("start_sync should fail without a loop");
        assert_eq!(
            err.to_string(),
            format!(
                "blob sync failed: partition/{} error: failed to send work",
                hex(b"blob")
            )
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_resize_reports_kernel_error() {
        // Verify resize preserves its storage-specific wrapper when the
        // underlying descriptor is a socket rather than a regular file.
        let storage_directory = create_test_directory();
        let (socket, _peer) = UnixStream::pair().unwrap();
        // SAFETY: `into_raw_fd` transfers ownership of the socket fd into `File`.
        let file = unsafe { File::from_raw_fd(socket.into_raw_fd()) };

        // `set_len` on a socket-backed file descriptor should fail in the
        // kernel, letting the wrapper expose `BlobResizeFailed`.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
            Arc::new(Pending::default()).attach("partition", b"blob").0,
        );
        let err = blob
            .resize(0)
            .await
            .expect_err("resize should fail on a socket fd");
        assert!(err.to_string().starts_with(&format!(
            "blob resize failed: partition/{} error:",
            hex(b"blob")
        )));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_sync_reports_kernel_error() {
        // Verify completed sync CQE failures round-trip through the storage wrapper.
        let storage_directory = create_test_directory();
        let (socket, _peer) = UnixStream::pair().unwrap();
        // SAFETY: `into_raw_fd` transfers ownership of the socket fd into `File`.
        let file = unsafe { File::from_raw_fd(socket.into_raw_fd()) };

        // Run a real loop so the request reaches the kernel and fails there
        // rather than through the wrapper's disconnected-submit path.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        let handle = std::thread::spawn(move || io_loop.run());

        let blob = Blob::new(
            file,
            submitter.clone(),
            pool,
            Layout::V0.data_offset(),
            Arc::new(Pending::default()).attach("partition", b"blob").0,
        );
        // A clean open skips the sync, so record an uncovered mutation first. The request
        // should then reach the kernel and come back as a wrapped sync failure.
        blob.shared.tracker.write();
        let err = blob
            .sync()
            .await
            .expect_err("sync should fail on a socket fd");
        let message = err.to_string();
        assert!(message.starts_with(&format!(
            "blob sync failed: partition/{} error:",
            hex(b"blob")
        )));
        assert_ne!(
            message,
            format!(
                "blob sync failed: partition/{} error: failed to send work",
                hex(b"blob")
            )
        );

        drop(blob);
        drop(submitter);
        // Joining the loop proves the live backend path shut down cleanly after the error.
        handle.join().unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let (storage, storage_directory) = create_test_storage();

        // Create a durable V1 blob to obtain the canonical header region bytes.
        let (blob, _) = storage.open("partition", b"torn").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let path = storage_directory.join("partition").join(hex(b"torn"));
        let region = std::fs::read(&path).unwrap();

        // Simulate a torn creation: a prefix of the canonical header region (the full
        // state enumeration lives in the Layout::interrupted_creation unit tables).
        let states = [region[..10].to_vec()];
        for state in states {
            std::fs::write(&path, &state).unwrap();
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen.
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            drop(blob);
        }

        // Foreign bytes are corruption, not a torn creation: nonzero padding behind a
        // torn (unparseable) prefix.
        let mut corrupt = vec![0u8; region.len()];
        corrupt[..10].copy_from_slice(&region[..10]);
        corrupt[100] = 0xFF;
        std::fs::write(&path, &corrupt).unwrap();
        let result = storage.open("partition", b"torn").await;
        assert!(matches!(result, Err(Error::BlobCorrupt(_, _, _))));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v1_rejects_nonzero_header_padding() {
        let (storage, storage_directory) = create_test_storage();

        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let path = partition_dir.join(hex(b"dirty_padding"));
        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
        raw[Header::PARSE_LEN] = 0xFF;
        std::fs::write(&path, raw).unwrap();

        let result = storage.open("partition", b"dirty_padding").await;
        assert!(
            matches!(result, Err(Error::BlobCorrupt(_, _, reason)) if reason.contains("header padding"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v0_legacy_read() {
        let (storage, storage_directory) = create_test_storage();

        // Fabricate a legacy V0 blob on disk (creation here produces V1): an 8-byte header
        // followed immediately by the payload.
        let payload = b"hello world";
        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let file_path = partition_dir.join(hex(b"v0"));
        std::fs::write(&file_path, crate::storage::tests::v0_blob_bytes(0, payload)).unwrap();

        // The blob opens with its data intact and remains readable and writable in place.
        let (blob, size) = storage.open("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            payload
        );
        blob.write_at(size, b"!".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // On disk the payload still sits immediately after the 8-byte V0 header.
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + payload.len() + 1);
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
        assert_eq!(&raw_content[Header::PRELUDE_SIZE..], b"hello world!");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Dropping the last handle with unsynced writes starts a sync that the next open waits for,
    /// and durable writes, synced handles and removed blobs defer nothing.
    #[tokio::test]
    async fn test_reopen_waits_for_deferred_sync() {
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(storage.pending.finished(), 0);
        drop(blob);

        let (blob, len) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(storage.pending.len(), 0);
        assert_eq!(storage.pending.finished(), 1);
        assert_eq!(len, 5);
        let read = blob
            .read_at(0, 5, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello");
        drop(blob);

        let (blob, _) = storage.open("partition", b"durable").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);
        while storage.pending.len() > 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(storage.pending.finished(), 1);

        let (blob, _) = storage.open("partition", b"synced").await.unwrap();
        blob.resize(16).await.unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);
        while storage.pending.len() > 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(storage.pending.finished(), 1);

        storage.remove("partition", None).await.unwrap();
        assert_eq!(storage.pending.len(), 0);

        drop(storage);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A sync on an open with no uncovered mutation returns without a device flush.
    #[tokio::test]
    async fn test_clean_sync_is_skipped() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage.open("partition", b"clean").await.unwrap();
        blob.sync().await.unwrap();
        blob.start_sync().await.await.unwrap();
        assert_eq!(blob.shared.tracker.skipped(), 2);
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        assert_eq!(blob.shared.tracker.skipped(), 2);
        blob.sync().await.unwrap();
        assert_eq!(blob.shared.tracker.skipped(), 3);
        drop(blob);
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }
}
