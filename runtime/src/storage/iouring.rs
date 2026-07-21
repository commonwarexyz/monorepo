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

use super::{FloorState, Header};
use crate::{
    iouring::{self},
    telemetry::metrics::Register,
    utils, Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut,
};
use commonware_codec::Encode;
use commonware_formatting::{from_hex, hex};
use commonware_utils::sync::{AsyncMutex, Mutex};
use std::{
    fs::{self, File},
    io::{Error as IoError, Read, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(test)]
static DIR_SYNC_FAILURE: std::sync::OnceLock<Mutex<Option<PathBuf>>> = std::sync::OnceLock::new();
#[cfg(test)]
static OPEN_FILE_SYNC_FAILURE: std::sync::OnceLock<Mutex<Option<PathBuf>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn dir_sync_failure() -> &'static Mutex<Option<PathBuf>> {
    DIR_SYNC_FAILURE.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn open_file_sync_failure() -> &'static Mutex<Option<PathBuf>> {
    OPEN_FILE_SYNC_FAILURE.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn inject_dir_sync_failure(path: PathBuf) {
    *dir_sync_failure().lock() = Some(path);
}

#[cfg(test)]
fn inject_open_file_sync_failure(path: PathBuf) {
    *open_file_sync_failure().lock() = Some(path);
}

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly fsynced.
fn sync_dir(path: &Path) -> Result<(), Error> {
    #[cfg(test)]
    {
        let mut failure = dir_sync_failure().lock();
        if failure.as_deref() == Some(path) {
            *failure = None;
            return Err(Error::BlobSyncFailed(
                path.to_string_lossy().to_string(),
                "directory".to_string(),
                std::io::Error::other("injected directory sync failure").into(),
            ));
        }
    }
    let dir = File::open(path).map_err(|e| {
        Error::BlobOpenFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })?;
    dir.sync_all().map_err(|e| {
        Error::BlobSyncFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })
}

/// Sync `directory` and every ancestor. A visible directory after process
/// restart is not proof that its parent entry survived a stable-media loss,
/// so successful opens repeat the whole chain instead of trusting existence.
fn sync_dir_hierarchy(directory: &Path) -> Result<(), Error> {
    for directory in directory.ancestors() {
        // Relative paths end in an empty ancestor, which denotes the current
        // directory whose entry anchors the relative hierarchy.
        let directory = if directory.as_os_str().is_empty() {
            Path::new(".")
        } else {
            directory
        };
        sync_dir(directory)?;
    }
    Ok(())
}

/// Configuration for a [Storage].
#[derive(Clone, Debug)]
pub struct Config {
    /// Where to store blobs.
    pub storage_directory: PathBuf,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
    /// Stack size for the dedicated io_uring worker thread.
    pub thread_stack_size: usize,
}

#[derive(Clone)]
pub struct Storage {
    lock: Arc<Mutex<()>>,
    storage_directory: PathBuf,
    io_handle: iouring::Handle,
    pool: BufferPool,
}

impl Storage {
    /// Returns a new `Storage` instance.
    pub(crate) fn start(cfg: Config, registry: &mut impl Register, pool: BufferPool) -> Self {
        let Config {
            storage_directory,
            mut iouring_config,
            thread_stack_size,
        } = cfg;

        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        iouring_config.single_issuer = true;

        let (io_handle, iouring_loop) = iouring::IoUringLoop::new(iouring_config, registry);

        let storage = Self {
            lock: Arc::new(Mutex::new(())),
            storage_directory,
            io_handle,
            pool,
        };

        utils::thread::spawn(thread_stack_size, move || iouring_loop.run());
        storage
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock();

        // Construct the full path
        let path = self.storage_directory.join(partition).join(hex(name));
        let parent = path
            .parent()
            .ok_or_else(|| Error::PartitionMissing(partition.into()))?;

        // Create the partition directory if it does not exist
        fs::create_dir_all(parent).map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file, creating it if it doesn't exist
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e.into()))?;

        let raw_len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

        // Handle header: new/corrupted blobs get a fresh header written,
        // existing blobs have their header read.
        let (blob_version, logical_len, floor) = if Header::missing(raw_len) {
            // New or partially-created blob: reset it and write a fresh header. The
            // file grows only as header bytes are written, so a create interrupted by
            // a process crash leaves some prefix of the header, which the next open
            // resets here instead of rejecting as corrupt below.
            let (header, blob_version) = Header::new(&versions);
            file.set_len(0)
                .map_err(|e| Error::BlobResizeFailed(partition.into(), hex(name), e.into()))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| Error::WriteFailed)?;
            file.write_all(&header.encode())
                .map_err(|_| Error::WriteFailed)?;
            (blob_version, 0, 0)
        } else {
            // Existing blob - read and validate header
            file.seek(SeekFrom::Start(0))
                .map_err(|_| Error::ReadFailed)?;
            let mut header_bytes = [0u8; Header::SIZE];
            file.read_exact(&mut header_bytes)
                .map_err(|_| Error::ReadFailed)?;
            Header::from(header_bytes, raw_len, &versions, Header::DATA_OFFSET_U64)
                .map_err(|e| e.into_error(partition, name))?
        };

        // Repeat the file barrier even when an existing header validates. A
        // prior process may have exposed a complete header in page cache and
        // died before making those bytes stable. A later RWF_SYNC data write
        // covers only that write, so it cannot substitute for this barrier.
        #[cfg(test)]
        {
            let mut failure = open_file_sync_failure().lock();
            if failure.as_deref() == Some(path.as_path()) {
                *failure = None;
                return Err(Error::BlobSyncFailed(
                    partition.into(),
                    hex(name),
                    std::io::Error::other("injected open file sync failure").into(),
                ));
            }
        }
        file.sync_all()
            .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e.into()))?;

        // Repeat directory barriers on every successful open. A previous
        // process may have crashed after syncing a complete header but before
        // syncing one of the directory entries that names it.
        sync_dir_hierarchy(parent)?;

        let blob = Blob::new(
            partition.into(),
            name,
            file,
            self.io_handle.clone(),
            self.pool.clone(),
            blob_version,
            floor,
        );
        Ok((blob, logical_len, blob_version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock();

        let path = self.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_path = path.join(hex(name));
            fs::remove_file(blob_path)
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;

            // Sync the partition directory to ensure the removal is durable.
            sync_dir(&path)?;
        } else {
            fs::remove_dir_all(&path).map_err(|_| Error::PartitionMissing(partition.into()))?;

            // Sync the storage directory to ensure the removal is durable.
            sync_dir(&self.storage_directory)?;
        }
        Ok(())
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

pub struct Blob {
    /// The partition this blob lives in
    partition: String,
    /// The name of the blob
    name: Vec<u8>,
    /// The underlying file
    file: Arc<File>,
    /// Where to send IO operations to be executed
    io_handle: iouring::Handle,
    /// Buffer pool for read allocations
    pool: BufferPool,
    /// Version recorded in the blob header, needed to rewrite it at sync.
    blob_version: u16,
    /// The pruned floor bookkeeping, seeded from the header at open and
    /// persisted back through [Self::prepare_sync] (see [FloorState]).
    floor: Arc<Mutex<FloorState>>,
    /// Serializes dirty-header rewrites across concurrent syncs (see
    /// [Self::prepare_sync]).
    header_lock: Arc<AsyncMutex<()>>,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            file: self.file.clone(),
            io_handle: self.io_handle.clone(),
            pool: self.pool.clone(),
            blob_version: self.blob_version,
            floor: self.floor.clone(),
            header_lock: self.header_lock.clone(),
        }
    }
}

impl Blob {
    /// Construct a blob handle around an already-open file and shared io_uring loop.
    fn new(
        partition: String,
        name: &[u8],
        file: File,
        io_handle: iouring::Handle,
        pool: BufferPool,
        blob_version: u16,
        floor: u64,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            file: Arc::new(file),
            io_handle,
            pool,
            blob_version,
            floor: Arc::new(Mutex::new(FloorState::new(floor))),
            header_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Persist a dirty floor into the header ahead of an fsync, returning
    /// the floor epoch the caller passes to [FloorState::mark_synced]
    /// once that fsync completes.
    ///
    /// The floor snapshot and the header write submission+completion
    /// happen under `header_lock` (the floor mutex cannot be held across
    /// ring awaits), so concurrent syncs land header images in snapshot
    /// order and a stale floor can never overwrite a fresher one (floors
    /// are monotone).
    async fn prepare_sync(&self) -> Result<u64, Error> {
        // Fast path: a clean floor needs no header write and no ordering
        // against other header writes.
        {
            let state = self.floor.lock();
            if !state.dirty() {
                return Ok(state.epoch());
            }
        }
        let _guard = self.header_lock.lock().await;
        let (dirty, header_floor, epoch) = {
            let state = self.floor.lock();
            (state.dirty(), state.floor(), state.epoch())
        };
        if dirty {
            let header = Header::with_floor(self.blob_version, header_floor);
            self.io_handle
                .write_at(self.file.clone(), 0, header.encode().into())
                .await?;
        }
        Ok(epoch)
    }
}

impl crate::Blob for Blob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, self.pool.alloc(len)).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
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

        let floor = self.floor.lock().floor();
        if offset < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        let offset = offset
            .checked_add(Header::DATA_OFFSET_U64)
            .ok_or(Error::OffsetOverflow)?;

        // Zero-length reads succeed trivially without submitting to the ring.
        if len == 0 {
            return Ok(original_bufs.unwrap_or_else(|| io_buf.into()));
        }

        let io_buf = self
            .io_handle
            .read_at(self.file.clone(), offset, len, io_buf)
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

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        let floor = self.floor.lock().floor();
        if offset < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        let offset = offset
            .checked_add(Header::DATA_OFFSET_U64)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        self.io_handle
            .write_at(self.file.clone(), offset, bufs)
            .await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let floor = self.floor.lock().floor();
        if offset < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        let offset = offset
            .checked_add(Header::DATA_OFFSET_U64)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        // A single-write flush cannot persist a dirty floor: with one
        // pending, the header must be rewritten and fsynced with this
        // write, so take the write-then-sync path instead.
        if self.floor.lock().dirty() {
            self.io_handle
                .write_at(self.file.clone(), offset, bufs)
                .await?;
            return self.sync().await;
        }

        self.io_handle
            .write_at_sync(self.file.clone(), offset, bufs)
            .await
    }

    async fn prune(&self, offset: u64) -> Result<(), Error> {
        let size = self
            .file
            .metadata()
            .map_err(|e| {
                Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e.into())
            })?
            .len()
            .saturating_sub(Header::DATA_OFFSET_U64);
        if offset > size {
            return Err(Error::BlobInsufficientLength);
        }
        // Best-effort deallocation of the newly pruned raw range while
        // keeping the file size. Errors are deliberately dropped: a
        // filesystem without hole punching degrades to unreclaimed space.
        // Bind the advance result so the floor lock guard drops before the
        // fallocate.
        let advanced = self.floor.lock().advance(offset);
        if let Some(old) = advanced {
            if let (Ok(start), Ok(len)) = (
                libc::off_t::try_from(Header::DATA_OFFSET_U64 + old),
                libc::off_t::try_from(offset - old),
            ) {
                // SAFETY: `self.file` owns a valid fd that lives across the
                // call; `fallocate` reads only its scalar arguments.
                unsafe {
                    libc::fallocate(
                        self.file.as_raw_fd(),
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        start,
                        len,
                    );
                }
            }
        }
        Ok(())
    }

    fn floor(&self) -> u64 {
        self.floor.lock().floor()
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn resize(&self, len: u64) -> Result<(), Error> {
        let floor = self.floor.lock().floor();
        if len < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        let len = len
            .checked_add(Header::DATA_OFFSET_U64)
            .ok_or(Error::OffsetOverflow)?;
        self.file.set_len(len).map_err(|e| {
            Error::BlobResizeFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::other(e).into(),
            )
        })
    }

    async fn sync(&self) -> Result<(), Error> {
        // A dirty floor is rewritten into the header by the same sync that
        // makes the pruned state durable (see [Self::prepare_sync]).
        let epoch = self.prepare_sync().await?;
        self.io_handle
            .sync(self.file.clone())
            .await
            .map_err(|err| match err {
                Error::Io(e) => Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), e),
                err => err,
            })?;
        // The floor written by [Self::prepare_sync] is durable, unless a
        // prune advanced it mid-sync (a failure leaves the mark set for a
        // retry).
        self.floor.lock().mark_synced(epoch);
        Ok(())
    }

    async fn start_sync(&self) -> Handle<()> {
        // As in [Self::sync], a dirty floor is rewritten into the header
        // before the fsync is registered and the mark clears only through
        // a successful completion.
        let epoch = match self.prepare_sync().await {
            Ok(epoch) => epoch,
            Err(err) => return Handle::ready(Err(err)),
        };
        let partition = self.partition.clone();
        let name = self.name.clone();
        let floor = self.floor.clone();
        let receiver = self.io_handle.start_sync(self.file.clone()).await;
        Handle::from_future(async move {
            match receiver.await {
                Ok(Ok(())) => {
                    floor.lock().mark_synced(epoch);
                    Ok(())
                }
                Ok(Err(Error::Io(e))) => Err(Error::BlobSyncFailed(partition, hex(&name), e)),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(Error::Closed),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        storage::tests::run_storage_tests, telemetry::metrics::Registry, utils::thread, Blob as _,
        BufferPool, BufferPoolConfig, IoBuf, IoBufMut, Storage as _,
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

        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                iouring_config: Default::default(),
                thread_stack_size: thread::system_thread_stack_size(),
            },
            &mut registry.sub_registry("storage"),
            pool,
        );
        (storage, storage_directory)
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

    #[tokio::test]
    async fn test_iouring_storage() {
        // Verify the io_uring storage backend satisfies the shared storage trait suite.
        let (storage, storage_directory) = create_test_storage();
        run_storage_tests(storage).await;
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    /// The production composition: a volume over the io_uring backend.
    #[tokio::test]
    async fn test_iouring_volume_storage() {
        let (storage, storage_directory) = create_test_storage();
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("volume_pool"));
        let storage = crate::storage::volume::Storage::new(
            storage,
            pool,
            Default::default(),
            crate::storage::volume::Driver::new(|fut| {
                tokio::spawn(fut);
            }),
        );
        run_storage_tests(storage).await;
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        // Verify header creation, logical offsets, resize, reopen, and corruption recovery.
        let (storage, storage_directory) = create_test_storage();

        // Test 1: New blob returns logical size 0 and correct application version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw file holds only the header
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64,
            "raw file should be header-only"
        );

        // Test 2: Logical offset handling - write at offset 0 stores at the data offset
        let data = b"hello world";
        blob.write_at(0, data.to_vec()).await.unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), Header::DATA_OFFSET_U64 + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Header::MAGIC);
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[Header::MAGIC_LENGTH..Header::MAGIC_LENGTH + Header::VERSION_LENGTH],
            &Header::RUNTIME_VERSION.to_be_bytes()
        );
        // Floor (bytes 8-15) starts at zero.
        assert_eq!(
            &raw_content[Header::MAGIC_LENGTH + 2 * Header::VERSION_LENGTH..Header::SIZE],
            &0u64.to_be_bytes()
        );
        // Data starts at the aligned data offset.
        assert_eq!(&raw_content[Header::DATA_OFFSET..], data);

        // Test 3: Read at logical offset 0 returns data from the data offset
        let read_buf = blob.read_at(0, data.len()).await.unwrap().coalesce();
        assert_eq!(read_buf, data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::DATA_OFFSET_U64 + 5,
            "resize(5) should keep 5 data bytes past the data offset"
        );

        // resize(0) should leave no data past the data offset
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::DATA_OFFSET_U64,
            "resize(0) should leave no data past the data offset"
        );

        // Test 5: Reopen existing blob preserves header and returns correct logical size
        blob.write_at(0, b"test data".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(0, 9).await.unwrap().coalesce();
        assert_eq!(read_buf, b"test data");
        drop(blob2);

        // Test 6: Corrupted blob recovery (0 < raw_size < Header::SIZE)
        // Manually create a corrupted file with only 4 bytes
        let corrupted_path = storage_directory.join("partition").join(hex(b"corrupted"));
        std::fs::write(&corrupted_path, vec![0u8; 4]).unwrap();

        // Opening should truncate and write fresh header
        let (blob3, size3) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");

        // Verify raw file now has a proper header
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

    /// A process can die after a complete header becomes visible but before
    /// the file or directory barriers. Fresh storage instances must repeat
    /// both even though the file and partition are visible.
    #[tokio::test]
    async fn test_open_retries_file_and_directory_sync_after_complete_header() {
        let storage_directory = create_test_directory().join("root");
        let partition = storage_directory.join("partition");
        let path = partition.join(hex(b"retry"));
        let start = || {
            let mut registry = Registry::default();
            let pool = test_pool(&mut registry.sub_registry("pool"));
            Storage::start(
                Config {
                    storage_directory: storage_directory.clone(),
                    iouring_config: Default::default(),
                    thread_stack_size: thread::system_thread_stack_size(),
                },
                &mut registry.sub_registry("storage"),
                pool,
            )
        };

        // Fail before the first file barrier. The next instance still sees a
        // complete header in page cache and must not trust that visibility.
        inject_open_file_sync_failure(path.clone());
        let storage = start();
        assert!(matches!(
            storage.open("partition", b"retry").await,
            Err(Error::BlobSyncFailed(..))
        ));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), Header::SIZE as u64);
        drop(storage);

        // Prove that the existing-header retry repeats the file barrier.
        inject_open_file_sync_failure(path.clone());
        let storage = start();
        assert!(matches!(
            storage.open("partition", b"retry").await,
            Err(Error::BlobSyncFailed(..))
        ));
        drop(storage);

        // The file barrier now succeeds, but the process can still die before
        // the first directory entry is stable.
        inject_dir_sync_failure(partition.clone());
        let storage = start();
        assert!(matches!(
            storage.open("partition", b"retry").await,
            Err(Error::BlobSyncFailed(..))
        ));
        drop(storage);

        // The retry must sync past the visible partition and reach its parent.
        inject_dir_sync_failure(storage_directory.clone());
        let storage = start();
        assert!(matches!(
            storage.open("partition", b"retry").await,
            Err(Error::BlobSyncFailed(..))
        ));
        drop(storage);

        // The configured storage root may itself have been created by the
        // interrupted open, so its parent entry also needs the retry barrier.
        let storage_parent = storage_directory
            .parent()
            .expect("test storage has a parent")
            .to_path_buf();
        inject_dir_sync_failure(storage_parent.clone());
        let storage = start();
        assert!(matches!(
            storage.open("partition", b"retry").await,
            Err(Error::BlobSyncFailed(..))
        ));

        let (blob, size) = storage.open("partition", b"retry").await.unwrap();
        assert_eq!(size, 0);
        drop(blob);
        let _ = std::fs::remove_dir_all(storage_parent);
    }

    /// A stored floor beyond the logical size is rejected at open: it
    /// means a crash persisted the header while losing an unsynced data
    /// extension, or the floor bytes were torn.
    #[tokio::test]
    async fn test_open_rejects_floor_beyond_size() {
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"floor").await.unwrap();
        blob.write_at(0, vec![7u8; 64]).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let file_path = storage_directory.join("partition").join(hex(b"floor"));
        let doctor = |floor: u64| {
            let mut raw = std::fs::read(&file_path).unwrap();
            raw[Header::MAGIC_LENGTH + 2 * Header::VERSION_LENGTH..Header::SIZE]
                .copy_from_slice(&floor.to_be_bytes());
            std::fs::write(&file_path, &raw).unwrap();
        };

        // One past the size must fail loud (recovery is restore-or-recreate).
        doctor(65);
        let result = storage.open("partition", b"floor").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("floor")),
            "a floor beyond the size must be rejected as corrupt"
        );

        // A floor at exactly the size is valid.
        doctor(64);
        let (blob, len) = storage.open("partition", b"floor").await.unwrap();
        assert_eq!(len, 64);
        assert_eq!(blob.floor(), 64);

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A floor whose prune happened-before a completed sync must survive
    /// racing syncs and prunes: no interleaving may clear the dirty mark
    /// while the on-disk header still carries a stale floor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_prune_sync_floor_persistence() {
        let (storage, storage_directory) = create_test_storage();

        for round in 0..128u64 {
            let name = format!("prune_race_{round}");
            let (blob, _) = storage.open("partition", name.as_bytes()).await.unwrap();
            blob.write_at(0, vec![7u8; 8192]).await.unwrap();
            blob.sync().await.unwrap();
            blob.prune(4096).await.unwrap();

            // Two syncs race a further prune: one may snapshot the old
            // floor, the other may complete with the new one.
            let sync_a = tokio::spawn({
                let blob = blob.clone();
                let yields = round % 4;
                async move {
                    for _ in 0..yields {
                        tokio::task::yield_now().await;
                    }
                    blob.sync().await.unwrap();
                }
            });
            let sync_b = tokio::spawn({
                let blob = blob.clone();
                async move {
                    blob.sync().await.unwrap();
                }
            });
            if round % 2 == 0 {
                tokio::task::yield_now().await;
            }
            blob.prune(8192).await.unwrap();
            sync_a.await.unwrap();
            sync_b.await.unwrap();

            // This sync completes strictly after the prune to 8192, so a
            // reopen must observe that floor.
            blob.sync().await.unwrap();
            drop(blob);

            // The on-disk header must parse and carry the synced floor.
            let file_path = storage_directory
                .join("partition")
                .join(hex(name.as_bytes()));
            let raw = std::fs::read(&file_path).unwrap();
            let mut header_bytes = [0u8; Header::SIZE];
            header_bytes.copy_from_slice(&raw[..Header::SIZE]);
            let (_, _, floor) = Header::from(
                header_bytes,
                raw.len() as u64,
                &(0..=0),
                Header::DATA_OFFSET_U64,
            )
            .expect("on-disk header must parse");
            assert_eq!(floor, 8192, "round {round}: synced floor lost");

            let (blob, _) = storage.open("partition", name.as_bytes()).await.unwrap();
            assert_eq!(
                blob.floor(),
                8192,
                "round {round}: reopened floor regressed"
            );
            drop(blob);
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_prune_floor_persistence() {
        // Verify the floor persists through the header at sync and regresses
        // to the synced floor when unsynced.
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"prune").await.unwrap();
        blob.write_at(0, vec![7u8; 8192]).await.unwrap();
        blob.sync().await.unwrap();

        // A synced floor is written into the on-disk header.
        blob.prune(4096).await.unwrap();
        blob.sync().await.unwrap();
        let file_path = storage_directory.join("partition").join(hex(b"prune"));
        let raw = std::fs::read(&file_path).unwrap();
        assert_eq!(
            &raw[Header::MAGIC_LENGTH + 2 * Header::VERSION_LENGTH..Header::SIZE],
            &4096u64.to_be_bytes()
        );

        // And survives reopen.
        drop(blob);
        let (blob, len) = storage.open("partition", b"prune").await.unwrap();
        assert_eq!(len, 8192);
        assert_eq!(blob.floor(), 4096);
        assert!(matches!(
            blob.read_at(0, 1).await,
            Err(crate::Error::OffsetPruned(_, _, 4096))
        ));
        let read = blob.read_at(4096, 4096).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), &[7u8; 4096]);

        // An unsynced floor advance regresses to the synced floor on reopen.
        blob.prune(5000).await.unwrap();
        assert_eq!(blob.floor(), 5000);
        drop(blob);
        let (blob, _) = storage.open("partition", b"prune").await.unwrap();
        assert_eq!(blob.floor(), 4096);

        // write_at_sync persists a dirty floor too.
        blob.prune(5000).await.unwrap();
        blob.write_at_sync(5000, b"x".to_vec()).await.unwrap();
        drop(blob);
        let (blob, _) = storage.open("partition", b"prune").await.unwrap();
        assert_eq!(blob.floor(), 5000);

        // As does start_sync.
        blob.prune(6000).await.unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);
        let (blob, _) = storage.open("partition", b"prune").await.unwrap();
        assert_eq!(blob.floor(), 6000);

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        // Verify opening a blob with an invalid runtime header fails as corrupt.
        let (storage, storage_directory) = create_test_storage();

        // Create the partition directory
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        // Manually create a file with invalid magic bytes
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, vec![0u8; Header::SIZE]).unwrap();

        // Opening should fail with corrupt error
        let err = storage
            .open("partition", b"bad_magic")
            .await
            .err()
            .expect("bad magic should fail");
        assert!(err
            .to_string()
            .starts_with("blob corrupt: partition/6261645f6d61676963 reason: invalid magic"));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        // Any file shorter than a header must reset to a valid, empty blob on open
        // rather than fail as corrupt.
        let (storage, storage_directory) = create_test_storage();
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
    async fn test_vectored_write_partial_progress() {
        // Verify multi-buffer writes survive partial progress and preserve byte order.
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"vectest").await.unwrap();
        blob.resize(200).await.unwrap();

        // Write multiple buffers in one vectored call.
        let mut bufs = crate::IoBufs::default();
        bufs.append(crate::IoBuf::from(vec![0xAAu8; 80]));
        bufs.append(crate::IoBuf::from(vec![0xBBu8; 80]));
        blob.write_at(0, bufs).await.unwrap();
        blob.sync().await.unwrap();

        // Read back and verify.
        let data = blob.read_at(0, 160).await.unwrap().coalesce();
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
        blob.write_at(0, b"abc".to_vec()).await.unwrap();
        blob.sync().await.unwrap();

        // The wrapper should surface this as an insufficient-length error instead
        // of silently returning a short buffer.
        let err = blob.read_at(0, 5).await.unwrap_err();
        assert_eq!(err.to_string(), "blob insufficient length");

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_read_at_buf_preserves_multichunk_layout() {
        // Verify multi-chunk caller buffers keep their shape after the temporary-buffer fallback.
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"multichunk").await.unwrap();
        blob.write_at(0, b"hello world".to_vec()).await.unwrap();
        blob.sync().await.unwrap();

        // Use a two-chunk destination so the read path must rebuild the original
        // chunk layout after reading through a temporary contiguous buffer.
        let bufs = IoBufsMut::from(vec![IoBufMut::with_capacity(5), IoBufMut::with_capacity(6)]);
        let read = blob.read_at_buf(0, 11, bufs).await.unwrap();
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
        blob.write_at(0, IoBufs::default()).await.unwrap();
        blob.write_at(0, IoBuf::default()).await.unwrap();
        blob.write_at(0, Vec::<u8>::new()).await.unwrap();
        let empty = blob.read_at(0, 0).await.unwrap();
        assert!(empty.is_empty());
        let _ = blob
            .read_at_buf(0, 0, IoBufsMut::from(IoBufMut::with_capacity(8)))
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
        // configured storage root is not a directory.
        let storage_directory = create_test_directory();
        let storage_root = storage_directory.join("root-file");
        std::fs::write(&storage_root, b"not a directory").unwrap();

        // Start storage against the invalid root so `open` reaches the
        // filesystem setup path under realistic wrapper code.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let storage = Storage::start(
            Config {
                storage_directory: storage_root.clone(),
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
            .expect("invalid storage root should fail");
        assert_eq!(err.to_string(), "partition creation failed: partition");

        let _ = std::fs::remove_file(&storage_root);
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
        assert!(err
            .to_string()
            .starts_with(&format!("blob open failed: partition/{blob_name} error:")));

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
            blob.read_at(u64::MAX, 1).await.unwrap_err().to_string(),
            "offset overflow"
        );
        assert_eq!(
            blob.write_at(u64::MAX, b"x".to_vec())
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

        let blob = Blob::new("partition".into(), b"blob", file, submitter, pool, 0, 0);

        // Read and write should fail through their wrapper-specific error enums
        // when the submission channel has already been disconnected.
        assert_eq!(
            blob.read_at(0, 1).await.unwrap_err().to_string(),
            "read failed"
        );
        assert_eq!(
            blob.write_at(0, b"x".to_vec())
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

        let blob = Blob::new("partition".into(), b"blob", file, submitter, pool, 0, 0);
        // Sync should fail through the blob-specific wrapper before any kernel work is attempted.
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

        let blob = Blob::new("partition".into(), b"blob", file, submitter, pool, 0, 0);
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

        let blob = Blob::new("partition".into(), b"blob", file, submitter, pool, 0, 0);
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
            "partition".into(),
            b"blob",
            file,
            submitter.clone(),
            pool,
            0,
            0,
        );
        // The request should reach the kernel and come back as a wrapped sync failure.
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
}
