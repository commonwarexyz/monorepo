//! This module provides an io_uring-based implementation of the [crate::Storage] trait,
//! offering fast, high-throughput file operations on Linux systems.
//!
//! ## Architecture
//!
//! I/O operations are sent via a [commonware_utils::channel::mpsc] channel to a dedicated io_uring event loop
//! running in another thread. Operation results are returned via a [commonware_utils::channel::oneshot] channel.
//!
//! ## Memory Safety
//!
//! We pass to the kernel, via io_uring, a pointer to the buffer being read from/written into.
//! Therefore, we ensure that the memory location is valid for the duration of the operation.
//! That is, it doesn't move or go out of scope until the operation completes.
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
    iouring::{self, should_retry, OpBuffer, OpFd},
    BufferPool, Error, IoBufs, IoBufsMut,
};
use commonware_codec::Encode;
use commonware_utils::{channel::oneshot, from_hex, hex};
use io_uring::{opcode, types};
use prometheus_client::registry::Registry;
use std::{
    fs::{self, File},
    io::{Error as IoError, Read, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    os::fd::AsRawFd,
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

#[derive(Clone, Debug)]
/// Configuration for a [Storage].
pub struct Config {
    /// Where to store blobs.
    pub storage_directory: PathBuf,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
}

#[derive(Clone)]
pub struct Storage {
    storage_directory: PathBuf,
    io_submitter: iouring::Submitter,
    pool: BufferPool,
}

impl Storage {
    /// Returns a new `Storage` instance.
    pub fn start(mut cfg: Config, registry: &mut Registry, pool: BufferPool) -> Self {
        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        cfg.iouring_config.single_issuer = true;

        let (io_submitter, iouring_loop) = iouring::IoUringLoop::new(cfg.iouring_config, registry);

        let storage = Self {
            storage_directory: cfg.storage_directory,
            io_submitter,
            pool,
        };

        std::thread::spawn(move || iouring_loop.run());
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
            self.io_submitter.clone(),
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
    io_submitter: iouring::Submitter,
    /// Buffer pool for read allocations
    pool: BufferPool,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            file: self.file.clone(),
            io_submitter: self.io_submitter.clone(),
            pool: self.pool.clone(),
        }
    }
}

impl Blob {
    fn new(
        partition: String,
        name: &[u8],
        file: File,
        io_submitter: iouring::Submitter,
        pool: BufferPool,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            file: Arc::new(file),
            io_submitter,
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
        let (mut io_buf, original_bufs) = if input_bufs.is_single() {
            (input_bufs.coalesce(), None)
        } else {
            // SAFETY: `len` bytes are filled via io_uring read loop below.
            let tmp = unsafe { self.pool.alloc_len(len) };
            (tmp, Some(input_bufs))
        };

        let fd = types::Fd(self.file.as_raw_fd());
        let mut bytes_read = 0;
        let io_submitter = self.io_submitter.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        while bytes_read < len {
            // Figure out how much is left to read and where to read into.
            //
            // SAFETY: IoBufMut wraps BytesMut which has stable memory addresses.
            // `bytes_read` is always < `len` due to the loop condition, so
            // `add(bytes_read)` stays within bounds and `len - bytes_read`
            // correctly represents the remaining valid bytes.
            let ptr = unsafe { io_buf.as_mut_ptr().add(bytes_read) };
            let remaining_len = len - bytes_read;
            let offset = offset + bytes_read as u64;

            // Create an operation to do the read
            let op = opcode::Read::new(fd, ptr, remaining_len as _)
                .offset(offset as _)
                .build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            io_submitter
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: Some(OpBuffer::Read(io_buf)),
                    fd: Some(OpFd::File(self.file.clone())),
                })
                .await
                .map_err(|_| Error::ReadFailed)?;

            // Wait for the result
            let (result, got_buf) = receiver.await.map_err(|_| Error::ReadFailed)?;
            io_buf = match got_buf {
                Some(OpBuffer::Read(b)) => b,
                _ => return Err(Error::ReadFailed),
            };
            if should_retry(result) {
                continue;
            }

            // A non-positive return value indicates an error.
            let op_bytes_read: usize = result.try_into().map_err(|_| Error::ReadFailed)?;
            if op_bytes_read == 0 {
                // A return value of 0 indicates EOF, which shouldn't happen because we
                // aren't done reading into `buf`. See `man pread`.
                return Err(Error::BlobInsufficientLength);
            }
            bytes_read += op_bytes_read;
        }

        // Return the same buffer structure as input
        match original_bufs {
            None => Ok(io_buf.into()),
            Some(mut bufs) => {
                // Copy from temporary buffer to the original multi-chunk buffers.
                bufs.copy_from_slice(io_buf.as_ref());
                Ok(bufs)
            }
        }
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        // Convert to contiguous IoBuf for io_uring write
        // (zero-copy if single buffer, copies if multiple)
        let mut buf = bufs.into().coalesce_with_pool(&self.pool);
        let fd = types::Fd(self.file.as_raw_fd());
        let mut bytes_written = 0;
        let buf_len = buf.len();
        let io_submitter = self.io_submitter.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        while bytes_written < buf_len {
            // Figure out how much is left to write and where to write from.
            //
            // SAFETY: IoBuf wraps Bytes which has stable memory addresses.
            // `bytes_written` is always < `buf_len` due to the loop condition, so
            // `add(bytes_written)` stays within bounds and `buf_len - bytes_written`
            // correctly represents the remaining valid bytes.
            let ptr = unsafe { buf.as_ptr().add(bytes_written) };
            let remaining_len = buf_len - bytes_written;
            let offset = offset + bytes_written as u64;

            // Create an operation to do the write
            let op = opcode::Write::new(fd, ptr, remaining_len as _)
                .offset(offset as _)
                .build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            io_submitter
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: Some(OpBuffer::Write(buf)),
                    fd: Some(OpFd::File(self.file.clone())),
                })
                .await
                .map_err(|_| Error::WriteFailed)?;

            // Wait for the result
            let (return_value, got_buf) = receiver.await.map_err(|_| Error::WriteFailed)?;
            buf = match got_buf {
                Some(OpBuffer::Write(b)) => b,
                _ => return Err(Error::WriteFailed),
            };
            if should_retry(return_value) {
                continue;
            }

            // A negative return value indicates an error.
            let op_bytes_written: usize =
                return_value.try_into().map_err(|_| Error::WriteFailed)?;

            bytes_written += op_bytes_written;
        }
        Ok(())
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
        loop {
            // Create an operation to do the sync
            let op = opcode::Fsync::new(types::Fd(self.file.as_raw_fd())).build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            self.io_submitter
                .clone()
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: None,
                    fd: Some(OpFd::File(self.file.clone())),
                })
                .await
                .map_err(|_| {
                    Error::BlobSyncFailed(
                        self.partition.clone(),
                        hex(&self.name),
                        IoError::other("failed to send work"),
                    )
                })?;

            // Wait for the result
            let (return_value, _) = receiver.await.map_err(|_| {
                Error::BlobSyncFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    IoError::other("failed to read result"),
                )
            })?;
            if should_retry(return_value) {
                continue;
            }

            // If the return value is negative, it indicates an error.
            if return_value < 0 {
                return Err(Error::BlobSyncFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    IoError::other(format!("error code: {return_value}")),
                ));
            }

            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        storage::tests::run_storage_tests, Blob, BufferPool, BufferPoolConfig, Storage as _,
    };
    use rand::{Rng as _, SeedableRng as _};
    use std::env;

    // Helper for creating test storage
    fn create_test_storage() -> (Storage, PathBuf) {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("commonware_iouring_storage_{}", rng.gen::<u64>()));

        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut Registry::default());
        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                iouring_config: Default::default(),
            },
            &mut Registry::default(),
            pool,
        );
        (storage, storage_directory)
    }

    #[tokio::test]
    async fn test_iouring_storage() {
        let (storage, storage_directory) = create_test_storage();
        run_storage_tests(storage).await;
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
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
        let (storage, storage_directory) = create_test_storage();

        // Create the partition directory
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        // Manually create a file with invalid magic bytes
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, vec![0u8; Header::SIZE]).unwrap();

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }
}
