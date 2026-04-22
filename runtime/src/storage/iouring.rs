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
    iouring::{self},
    utils::{self, MetricScope},
    Buf, BufferPool, Error, IoBufs, IoBufsMut,
};
use commonware_codec::Encode;
use commonware_utils::{from_hex, hex};
use std::{
    fs::{self, File},
    io::{Error as IoError, Read, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly fsynced.
fn sync_dir(path: &Path) -> Result<(), Error> {
    let dir = File::open(path).map_err(|e| {
        Error::BlobOpenFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e,
        )
    })?;
    dir.sync_all().map_err(|e| {
        Error::BlobSyncFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e,
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
    storage_directory: PathBuf,
    io_handle: iouring::Handle,
    pool: BufferPool,
}

impl Storage {
    /// Returns a new `Storage` instance.
    pub fn start(cfg: Config, registry: &mut MetricScope<'_>, pool: BufferPool) -> Self {
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

        // Construct the full path
        let path = self.storage_directory.join(partition).join(hex(name));
        let parent = path
            .parent()
            .ok_or_else(|| Error::PartitionMissing(partition.into()))?;

        // Check if partition exists before creating
        let parent_existed = parent.exists();

        // Create the partition directory if it does not exist
        fs::create_dir_all(parent).map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file, creating it if it doesn't exist
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e))?;

        // Assume empty files are newly created. Existing empty files will be synced too; that's OK.
        let raw_len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

        // Handle header: new/corrupted blobs get a fresh header written,
        // existing blobs have their header read.
        let (blob_version, logical_len) = if Header::missing(raw_len) {
            // New (or corrupted) blob - truncate and write header with latest version
            let (header, blob_version) = Header::new(&versions);
            file.set_len(Header::SIZE_U64)
                .map_err(|e| Error::BlobResizeFailed(partition.into(), hex(name), e))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| Error::WriteFailed)?;
            file.write_all(&header.encode())
                .map_err(|_| Error::WriteFailed)?;
            file.sync_all()
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e))?;

            // For new files, sync the parent directory to ensure the directory entry is durable.
            if raw_len == 0 {
                sync_dir(parent)?;
                if !parent_existed {
                    sync_dir(&self.storage_directory)?;
                }
            }

            (blob_version, 0)
        } else {
            // Existing blob - read and validate header
            file.seek(SeekFrom::Start(0))
                .map_err(|_| Error::ReadFailed)?;
            let mut header_bytes = [0u8; Header::SIZE];
            file.read_exact(&mut header_bytes)
                .map_err(|_| Error::ReadFailed)?;
            Header::from(header_bytes, raw_len, &versions)
                .map_err(|e| e.into_error(partition, name))?
        };

        let blob = Blob::new(
            partition.into(),
            name,
            file,
            self.io_handle.clone(),
            self.pool.clone(),
        );
        Ok((blob, logical_len, blob_version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

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
                let name = from_hex(name).ok_or(Error::PartitionCorrupt(partition.into()))?;
                blobs.push(name);
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
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            file: self.file.clone(),
            io_handle: self.io_handle.clone(),
            pool: self.pool.clone(),
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
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            file: Arc::new(file),
            io_handle,
            pool,
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
            .checked_add(Header::SIZE_U64)
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
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        self.io_handle
            .write_at(self.file.clone(), offset, bufs)
            .await
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn resize(&self, len: u64) -> Result<(), Error> {
        let len = len
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        self.file.set_len(len).map_err(|e| {
            Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), IoError::other(e))
        })
    }

    async fn sync(&self) -> Result<(), Error> {
        self.io_handle
            .sync(self.file.clone())
            .await
            .map_err(|e| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), e))
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        storage::tests::run_storage_tests, utils::thread, Blob as _, BufferPool, BufferPoolConfig,
        IoBuf, IoBufMut, Storage as _,
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

    /// Build a fresh storage instance rooted in a unique temporary directory.
    fn create_test_storage() -> (Storage, PathBuf) {
        let storage_directory = env::temp_dir().join(format!(
            "commonware_iouring_storage_{}_{}",
            std::process::id(),
            NEXT_STORAGE_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&storage_directory);

        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                iouring_config: Default::default(),
                thread_stack_size: thread::system_thread_stack_size(),
            },
            &mut Registry::default(),
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

    #[tokio::test]
    async fn test_blob_header_handling() {
        // Verify header creation, logical offsets, resize, reopen, and corruption recovery.
        let (storage, storage_directory) = create_test_storage();

        // Test 1: New blob returns logical size 0 and correct application version
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
        blob.write_at(0, data.to_vec()).await.unwrap();
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
        let read_buf = blob.read_at(0, data.len()).await.unwrap().coalesce();
        assert_eq!(read_buf, data);

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
    async fn test_open_reports_partition_creation_failure() {
        // Verify opening a blob reports partition-creation failures when the
        // configured storage root is not a directory.
        let storage_directory = create_test_directory();
        let storage_root = storage_directory.join("root-file");
        std::fs::write(&storage_root, b"not a directory").unwrap();

        // Start storage against the invalid root so `open` reaches the
        // filesystem setup path under realistic wrapper code.
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let storage = Storage::start(
            Config {
                storage_directory: storage_root.clone(),
                iouring_config: Default::default(),
                thread_stack_size: utils::thread::system_thread_stack_size(),
            },
            &mut Registry::default(),
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

        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                iouring_config: Default::default(),
                thread_stack_size: utils::thread::system_thread_stack_size(),
            },
            &mut Registry::default(),
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
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        drop(io_loop);

        let blob = Blob::new("partition".into(), b"blob", file, submitter, pool);

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
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        drop(io_loop);

        let blob = Blob::new("partition".into(), b"blob", file, submitter, pool);
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
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        drop(io_loop);

        let blob = Blob::new("partition".into(), b"blob", file, submitter, pool);
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
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        let handle = std::thread::spawn(move || io_loop.run());

        let blob = Blob::new("partition".into(), b"blob", file, submitter.clone(), pool);
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
