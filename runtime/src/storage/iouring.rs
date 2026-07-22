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

use super::Header;
use crate::{
    Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut,
    iouring::{self},
    telemetry::metrics::Register,
    utils,
};
use commonware_formatting::{from_hex, hex};
use commonware_utils::sync::Mutex;
use std::{
    fs::{self, File},
    io::{Error as IoError, Read, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Reads a blob's leading bytes and resolves its header (see [super::header::resolve]).
fn resolve_header(
    file: &mut File,
    raw_len: u64,
    versions: &RangeInclusive<u16>,
    partition: &str,
    name: &[u8],
) -> Result<Option<(u64, u16, u64)>, Error> {
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::ReadFailed)?;
    file.read_exact(&mut raw).map_err(|_| Error::ReadFailed)?;
    super::header::resolve(&raw, raw_len, versions, partition, name)
}

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly fsynced.
fn sync_dir(path: &Path) -> Result<(), Error> {
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

        // Handle header: existing blobs have their header read; new blobs and blobs left torn
        // by an interrupted creation get a fresh header written.
        let existing = resolve_header(&mut file, raw_len, &versions, partition, name)?;
        let (logical_len, blob_version, data_offset) = match existing {
            Some(resolved) => resolved,
            None => {
                // Sync the directories before writing the header so a parseable header
                // always implies durable directory entries (an open that parses a header
                // never re-runs these). The storage directory is synced unconditionally:
                // the partition directory existing in the namespace does not imply its
                // entry is durable.
                sync_dir(parent)?;
                sync_dir(&self.storage_directory)?;

                // Truncate to zero before writing, per the [Header::create] contract.
                let (region, blob_version) = Header::create(&versions);
                let data_offset = region.len() as u64;
                file.set_len(0)
                    .map_err(|e| Error::BlobResizeFailed(partition.into(), hex(name), e.into()))?;
                file.seek(SeekFrom::Start(0))
                    .map_err(|_| Error::WriteFailed)?;
                file.write_all(&region).map_err(|_| Error::WriteFailed)?;
                file.sync_all()
                    .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e.into()))?;

                (0, blob_version, data_offset)
            }
        };

        let blob = Blob::new(
            partition.into(),
            name,
            file,
            self.io_handle.clone(),
            self.pool.clone(),
            data_offset,
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
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            file: self.file.clone(),
            io_handle: self.io_handle.clone(),
            pool: self.pool.clone(),
            data_offset: self.data_offset,
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
        data_offset: u64,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            file: Arc::new(file),
            io_handle,
            pool,
            data_offset,
        }
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

        let offset = offset
            .checked_add(self.data_offset)
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
        let offset = offset
            .checked_add(self.data_offset)
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
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        self.io_handle
            .write_at_sync(self.file.clone(), offset, bufs)
            .await
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn resize(&self, len: u64) -> Result<(), Error> {
        let len = len
            .checked_add(self.data_offset)
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
        self.io_handle
            .sync(self.file.clone())
            .await
            .map_err(|err| match err {
                Error::Io(e) => Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), e),
                err => err,
            })
    }

    async fn start_sync(&self) -> Handle<()> {
        let partition = self.partition.clone();
        let name = self.name.clone();
        let receiver = self.io_handle.start_sync(self.file.clone()).await;
        Handle::from_future(async move {
            match receiver.await {
                Ok(Ok(())) => Ok(()),
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
        blob.write_at(0, data.to_vec()).await.unwrap();
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
        let read_buf = blob.read_at(0, data.len()).await.unwrap().coalesce();
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
        blob.write_at(0, b"test data".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(0, 9).await.unwrap().coalesce();
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

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
        );

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

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
        );
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

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
        );
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
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
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
            "partition".into(),
            b"blob",
            file,
            submitter.clone(),
            pool,
            Layout::V0.data_offset(),
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
}
