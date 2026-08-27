//! io_uring implementation of [crate::Storage]. See [crate::iouring] for
//! runtime requirements and worker-affinity rules.
//!
//! ## Blocking Metadata Operations
//!
//! `open`, `remove`, and `scan` execute synchronous filesystem calls (including
//! fsyncs) on the calling worker's thread, serialized across all workers by a
//! runtime-wide lock. A slow metadata operation therefore stalls the calling
//! worker's event loop, and other workers entering a metadata operation block on
//! the same lock until it completes. [crate::Blob::resize] (tracked by #831) is
//! likewise a synchronous `set_len` on the worker, though it touches only the open
//! file and takes no lock. Keep these off hot paths. Data-path reads, writes, and
//! syncs go through the ring and do not block.
//!

use super::Header;
use crate::{
    Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions, iouring,
};
use commonware_formatting::{from_hex, hex};
use commonware_utils::sync::Mutex;
use std::{
    fs::{self, File},
    io::{Error as IoError, Read, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
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

/// io_uring implementation of [crate::Storage].
///
/// Its `open_versioned` method is associated with the worker whose ring
/// services it, and blobs it opens must be used on that worker (see the
/// [worker affinity](crate::iouring#worker-affinity) rules). Metadata operations
/// (`open`, `remove`, `scan`) run synchronously on the calling worker under a
/// runtime-wide lock and therefore block its event loop (see the [module docs](self)
/// for the blocking rules and lifecycle).
#[derive(Clone)]
pub struct Storage {
    metadata_lock: Arc<Mutex<()>>,
    storage_directory: PathBuf,
    driver_handle: iouring::DriverHandle,
    pool: BufferPool,
}

impl Storage {
    /// Returns a new `Storage` instance that submits I/O through the driver.
    ///
    /// `metadata_lock` serializes filesystem-shape operations (open, remove, scan).
    /// Every instance sharing a storage directory must share the same lock,
    /// so the runtime passes one lock to all of its workers.
    pub(crate) const fn new(
        storage_directory: PathBuf,
        driver_handle: iouring::DriverHandle,
        pool: BufferPool,
        metadata_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            metadata_lock,
            storage_directory,
            driver_handle,
            pool,
        }
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
        self.driver_handle.assert_owner();
        super::validate_partition_name(partition)?;

        let _guard = self.metadata_lock.lock();

        let path = self.storage_directory.join(partition).join(hex(name));
        let parent = path
            .parent()
            .ok_or_else(|| Error::PartitionMissing(partition.into()))?;

        fs::create_dir_all(parent).map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e.into()))?;

        let raw_len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

        // Handle header: existing blobs have their header read, while new blobs and blobs left
        // torn by an interrupted creation get a fresh header written.
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
            self.driver_handle.clone(),
            self.pool.clone(),
            data_offset,
        );
        Ok((blob, logical_len, blob_version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let _guard = self.metadata_lock.lock();

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

        let _guard = self.metadata_lock.lock();

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

/// io_uring implementation of [crate::Blob].
///
/// Bound to the worker whose ring services it: using it from another worker
/// panics (see the [worker affinity](crate::iouring#worker-affinity) rules).
/// Non-empty reads, writes, and syncs go through the ring. Empty reads and
/// writes complete locally. [crate::Blob::resize] runs a synchronous `set_len`
/// that blocks the calling worker (see the [module docs](self) for the blocking
/// rules and lifecycle).
#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
    driver_handle: iouring::DriverHandle,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// Whether the kernel and filesystem may support `RWF_DONTCACHE`.
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted I/O operation.
    dont_cache_supported: Arc<AtomicBool>,
}

impl Blob {
    fn new(
        partition: String,
        name: &[u8],
        file: File,
        driver_handle: iouring::DriverHandle,
        pool: BufferPool,
        data_offset: u64,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            file: Arc::new(file),
            driver_handle,
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
        self.driver_handle.assert_owner();
        let mut input_bufs = bufs.into();
        // SAFETY: `len` bytes are filled via io_uring read loop below.
        unsafe { input_bufs.set_len(len) };

        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        if len == 0 {
            return Ok(input_bufs);
        }

        // For single buffers, read directly into them (zero-copy).
        // For multi-chunk buffers, use a temporary and copy to preserve the input structure.
        let (io_buf, original_bufs) = if input_bufs.is_single() {
            (input_bufs.coalesce(), None)
        } else {
            // SAFETY: `len` bytes are filled via io_uring read loop below.
            let tmp = unsafe { self.pool.alloc_len(len) };
            (tmp, Some(input_bufs))
        };

        let cache = if options.contains(ReadOptions::DONT_CACHE) {
            iouring::Cache::Disabled(self.dont_cache_supported.clone())
        } else {
            iouring::Cache::Enabled
        };
        let io_buf = self
            .driver_handle
            .read_at(self.file.clone(), offset, len, io_buf, cache)
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
        self.driver_handle.assert_owner();
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
        self.driver_handle
            .write_at(self.file.clone(), offset, bufs, options, cache)
            .await
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.driver_handle.assert_owner();
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
        self.driver_handle
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
        let ticket = self.driver_handle.start_sync(self.file.clone()).await;
        Handle::from_future(async move {
            match ticket.await {
                Ok(()) => Ok(()),
                Err(Error::Io(e)) => Err(Error::BlobSyncFailed(partition, hex(&name), e)),
                Err(err) => Err(err),
            }
        })
    }
}

#[cfg(test)]
#[path = "iouring_tests.rs"]
mod tests;
