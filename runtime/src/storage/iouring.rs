//! This module provides an io_uring-based implementation of the [crate::Storage] trait,
//! offering fast, high-throughput file operations on Linux systems.
//!
//! ## Architecture
//!
//! Reads, writes, and syncs register requests with the worker that first polls them.
//! Requests stay on that worker, with completion forwarded when their futures are
//! polled elsewhere. Storage and blob handles retain no ring identity and can move
//! between workers. Moving a future does not keep its original worker alive.
//! Empty reads and writes return without touching the ring. Metadata, resize, and
//! flushing a dirty predecessor during reopen run synchronously on the calling worker.
//!
//! Registered requests retain the open they were issued through, with its file,
//! directory hold, and durability debt. Dropping a caller never releases them
//! while the kernel can still access the file. Registered writes and syncs finish
//! their logical work after caller cancellation, including requests still queued
//! for staging capacity or another durability operation on the same open.
//!
//! Dropping the last handle of an open performs no I/O. It records what the open
//! left unflushed, and the next open of the blob establishes that durability
//! before it returns.
//!
//! ## Uncached Batched Reads
//!
//! [crate::Blob::read_many] and [crate::Blob::start_read_many] with
//! [crate::ReadOptions::DONT_CACHE] read with direct I/O, as the Linux tokio backend does. The
//! first such batch of an open opens a second, read-only `O_DIRECT` descriptor on its file
//! through `/proc/self/fd`, a blocking open on the worker that polls the batch. The open keeps
//! that descriptor until it is dropped, so an open that served such a batch holds two
//! descriptors. Each range is read as its superset aligned to 4096 bytes into an exact-size
//! aligned buffer, and only the requested bytes are handed out. Every read of a batch is
//! registered together, on the first poll of a [crate::Blob::read_many] stream or before
//! [crate::Blob::start_read_many] returns its handle.
//!
//! On filesystems that serve `O_DIRECT` natively, such as XFS and ext4, a direct read neither
//! uses nor evicts data the OS page cache holds, so cached data is read from the device again,
//! and the read first waits for dirty data in its superset to be written back. The kernel may
//! retry a direct read on an io-wq worker, for example while the range has dirty pages or a
//! buffered write to the file is in progress. Some filesystems accept `O_DIRECT` but serve
//! these reads from memory or through buffered I/O internally.
//!
//! A range whose superset is not representable, a direct read the kernel rejects or that ends
//! short of the range, every range of an open whose filesystem rejects `O_DIRECT`, and every
//! range of a batch whose direct descriptor failed to open for another reason are read as
//! [crate::Blob::read_at] reads them, buffered with `RWF_DONTCACHE`. The next batch tries such
//! an open again. Other reads, including [crate::Blob::read_at], stay buffered.
//!
//! ## Memory Safety
//!
//! Buffers and file descriptors are owned by the active request state machine inside the io_uring
//! loop, ensuring that the memory location is valid for the duration of the operation.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.
//! It requires Linux kernel 6.1 or newer. See [crate::iouring] for details.

use super::{
    Generation, Layout, Pending, Sender, Tracker, create_header,
    hold::{Held, Hold},
    resolve_header, sync_dir,
};
use crate::{
    BlobVersion, Buf, Error, Handle, IoBufMut, IoBufs, IoBufsMut, ReadOptions, WriteOptions,
    iouring::{
        operation::{self, Operation},
        request::{
            Cache, IOVEC_BATCH_SIZE, ReadAtRequest, Request, RequestOutput, SyncRequest,
            WriteAtRequest, WriteAtState,
        },
    },
};
use commonware_formatting::{from_hex, hex};
use commonware_utils::{
    Widen,
    sync::{AsyncMutex, Mutex},
};
use futures::{
    FutureExt as _, Stream, StreamExt as _,
    future::Either,
    stream::{self, FuturesUnordered},
};
use once_cell::sync::OnceCell;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::{
    alloc,
    fs::{self, File},
    future::Future,
    io::{Error as IoError, ErrorKind},
    ops::{Deref, RangeInclusive},
    os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock, atomic::AtomicBool},
    task::{Context, Poll},
};

/// Configuration for a [Storage].
#[derive(Clone, Debug)]
pub struct Config {
    /// Where to store blobs.
    pub storage_directory: PathBuf,
    /// Blob layouts accepted by storage.
    pub blob_layouts: RangeInclusive<Layout>,
}

/// Filesystem storage with one logical open per blob. Each request executes on the worker
/// that registers it.
///
/// Failed durability barriers during content sync remain errors on later opens through this
/// instance until the blob is removed or recreated. Creation failures are retained only when
/// the header is complete.
#[derive(Clone)]
pub struct Storage {
    /// Serialize metadata operations across cloned contexts and workers.
    lock: Arc<Mutex<()>>,
    /// Root directory containing blob partitions.
    storage_directory: PathBuf,
    /// Accepted on-disk layouts and creation policy.
    blob_layouts: RangeInclusive<Layout>,
    /// Directory exclusion also retained by opened files and registered requests.
    hold: Arc<Hold>,
    /// The live open of each blob and the debt its dropped handles left behind.
    pending: Arc<Pending>,
}

impl Storage {
    /// Create storage and acquire its directory hold.
    pub(crate) fn new(cfg: Config) -> Self {
        let Config {
            storage_directory,
            blob_layouts,
        } = cfg;
        let hold = Hold::acquire(&storage_directory).unwrap_or_else(|e| {
            panic!(
                "failed to acquire storage directory hold ({}): {e}",
                storage_directory.display()
            )
        });
        Self {
            lock: Arc::new(Mutex::new(())),
            storage_directory,
            blob_layouts,
            hold,
            pending: Arc::new(Pending::default()),
        }
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

        let (blob, mut logical_len, blob_version, wait, owed) = {
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

            // Claim the name for this open. A fresh header starts a new incarnation.
            let (generation, wait, owed) =
                self.pending.admit(partition, name, existing.is_some())?;

            // Existing headers retain their layout. New headers become visible only after
            // their namespace entries are durable.
            let (mut logical_len, blob_version, data_offset) = match existing {
                Some(resolved) => resolved,
                None => {
                    // Sync the directories before writing the header so a parseable header
                    // always implies durable directory entries (an open that parses a header
                    // never re-runs these). The storage directory is synced unconditionally:
                    // the partition directory existing in the namespace does not imply its
                    // entry is durable.
                    sync_dir(parent)?;
                    sync_dir(&self.storage_directory)?;

                    // Retain a creation failure until the blob is removed or recreated.
                    create_header(&mut file, &self.blob_layouts, &versions, &generation)
                        .inspect_err(|error| self.pending.fail(&generation, error.clone()))?
                }
            };

            // With no predecessor work or debt, the captured file's length is final. Otherwise,
            // it is read below once outstanding work settles and any debt is flushed.
            if !owed {
                logical_len = file.metadata().map_err(|_| Error::ReadFailed)?.len() - data_offset;
            }

            let blob = Blob::new(file, self.hold.clone(), data_offset, generation);
            (blob, logical_len, blob_version, wait, owed)
        };

        // Outside the namespace lock, wait for any outstanding work, then flush any debt and read
        // the final file length.
        if owed {
            Pending::wait(wait).await?;
            logical_len = blob.complete()?;
        }
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
            // Distinguish missing partitions from other filesystem failures.
            fs::remove_dir_all(&path).map_err(|error| match error.kind() {
                ErrorKind::NotFound => Error::PartitionMissing(partition.into()),
                _ => Error::Io(error.into()),
            })?;

            &self.storage_directory
        };

        // Retire the removed names before the directory sync makes the removal durable.
        self.pending.forget(partition, name);
        sync_dir(sync_path)
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock();

        let path = self.storage_directory.join(partition);

        // Distinguish missing partitions from other filesystem failures.
        let entries = fs::read_dir(&path).map_err(|error| match error.kind() {
            ErrorKind::NotFound => Error::PartitionMissing(partition.into()),
            _ => Error::ReadFailed,
        })?;

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

/// An open blob whose file retains the storage directory hold.
pub struct Blob {
    /// File state retained by issued requests.
    shared: Arc<Shared>,
    /// The logical open's namespace identity.
    generation: Arc<Generation>,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
}

/// A blob's file with the writes no completed sync covers.
///
/// Every request issued through the open retains it, so it carries the directory hold into the
/// ring and keeps the open's settlement pending until the kernel has finished with the file.
/// Dropping the last reference performs no I/O: it records what the open left unflushed for the
/// next open of the blob to establish before that open returns.
pub(crate) struct Shared {
    /// Descriptor for direct reads of the same inode, opened by the first uncached batch with a
    /// nonempty range. Holds `None` once the filesystem rejected direct I/O for this open.
    /// Declared before `file` so both descriptors close before the directory hold is released.
    direct: OnceCell<Option<File>>,
    file: Held,
    pub(crate) tracker: Tracker,
    /// Serializes kernel durability operations through terminal accounting.
    /// Only driver-owned futures may wait on this mutex. Permits are released while
    /// the worker is borrowed, so their wakers must not borrow the worker again.
    pub(crate) durability: Arc<AsyncMutex<()>>,
    pending: Arc<Pending>,
    key: (String, Vec<u8>),
    /// Settles the open once its last handle dropped and every request finished.
    promise: OnceLock<Sender>,
    /// Whether the kernel and filesystem may support `RWF_DONTCACHE`.
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted I/O operation.
    pub(crate) dont_cache_supported: AtomicBool,
    /// Direct reads of this open that switched to a buffered read.
    #[cfg(test)]
    pub(crate) direct_fallbacks: AtomicUsize,
}

impl Drop for Shared {
    fn drop(&mut self) {
        let Some(sender) = self.promise.take() else {
            return;
        };
        self.pending.settle(
            &self.key,
            sender,
            self.tracker.is_dirty(),
            self.tracker.failure(),
        );
    }
}

impl Shared {
    /// Check whether this open needs a full-file barrier, rejecting retained failures.
    pub(crate) fn needs_sync(&self) -> Result<bool, Error> {
        if let Some(error) = self.tracker.failure() {
            return Err(error);
        }
        if !self.tracker.is_dirty() {
            #[cfg(test)]
            self.tracker.skip_sync();
            return Ok(false);
        }
        #[cfg(test)]
        if let Some(error) = self.pending.take_flush_failure() {
            self.tracker.poison(&error);
            return Err(error);
        }
        Ok(true)
    }

    /// Settle a write's mutation debt from the outcome the ring observed.
    ///
    /// The ring sees every completion, including those the caller stopped waiting for. A plain
    /// write recorded its mutation before submission and completes it here. A durable write
    /// covers itself, so a failure records a mutation. A failed barrier poisons the open:
    /// it may have consumed the kernel's writeback error. Durable completions reject any
    /// previously retained failure before acknowledging success.
    pub(crate) fn wrote(
        &self,
        durable: bool,
        synced: bool,
        result: Result<(), Error>,
    ) -> Result<(), Error> {
        match (durable, &result) {
            (false, Ok(())) => self.tracker.complete(),
            (true, Err(error)) => {
                self.tracker.write();

                // Only a failed fused write or trailing sync may have consumed the kernel's
                // writeback error.
                if synced {
                    self.sync_failed(error);
                }
            }
            _ => {}
        }
        if durable
            && result.is_ok()
            && let Some(error) = self.tracker.failure()
        {
            return Err(error);
        }
        result
    }

    /// Retain a failed barrier under the name the caller sees.
    pub(crate) fn sync_failed(&self, error: &Error) {
        let (partition, name) = &self.key;
        let error = match error {
            Error::Io(error) => Error::BlobSyncFailed(partition.clone(), hex(name), error.clone()),
            error => error.clone(),
        };
        self.tracker.poison(&error);
    }

    /// Establish a settled predecessor's debt through this open's file.
    ///
    /// This runs on the calling worker: the predecessor already finished, so no ring request
    /// can be lost to a dropped open or rejected by a closing worker.
    fn complete(&self) -> Result<(), Error> {
        #[cfg(test)]
        self.pending.before_complete();
        let (partition, name) = &self.key;
        let result = self
            .file
            .sync_data()
            .map_err(|e| Error::BlobSyncFailed(partition.clone(), hex(name), e.into()));
        #[cfg(test)]
        let result = self.pending.take_flush_failure().map_or(result, Err);

        // Poison this open so its settlement carries the flush failure to later opens.
        if let Err(error) = &result {
            self.tracker.poison(error);
        }
        #[cfg(test)]
        if result.is_ok() {
            self.pending.completed();
        }
        result
    }

    /// Return the direct descriptor, opening it on first use.
    ///
    /// The descriptor reopens this open's file through `/proc/self/fd` read only with
    /// `O_DIRECT`, so it reaches the same inode after the name is removed or reused. `None` when
    /// the filesystem rejected direct I/O for this open, which is remembered, or when the open
    /// failed for any other reason (such as a descriptor limit or a permission change), which
    /// leaves the next call to try again. The open blocks the calling worker.
    fn open_direct(&self) -> Option<&File> {
        self.direct
            .get_or_try_init(|| {
                match fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECT)
                    .open(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
                {
                    Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(None),
                    result => result.map(Some),
                }
            })
            .ok()?
            .as_ref()
    }
}

impl Deref for Shared {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
}

#[cfg(test)]
impl Shared {
    /// Retain a file and directory hold for requests issued outside any open.
    pub(crate) fn detached(file: File, hold: Arc<Hold>) -> Arc<Self> {
        Arc::new(Self {
            direct: OnceCell::new(),
            file: Held::new(file, hold),
            tracker: Tracker::default(),
            durability: Arc::new(AsyncMutex::new(())),
            pending: Arc::new(Pending::default()),
            key: (String::new(), Vec::new()),
            promise: OnceLock::new(),
            dont_cache_supported: AtomicBool::new(true),
            direct_fallbacks: AtomicUsize::new(0),
        })
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        // Register settlement before releasing the file and namespace identity.
        if let Some(sender) = self.generation.release() {
            let _ = self.shared.promise.set(sender);
        }
    }
}

impl Blob {
    /// Construct a blob handle that retains its file and storage directory hold.
    fn new(file: File, hold: Arc<Hold>, data_offset: u64, generation: Arc<Generation>) -> Self {
        let shared = Arc::new(Shared {
            direct: OnceCell::new(),
            file: Held::new(file, hold),
            tracker: Tracker::default(),
            durability: Arc::new(AsyncMutex::new(())),
            pending: generation.pending.clone(),
            key: generation.key.clone(),
            promise: OnceLock::new(),
            dont_cache_supported: AtomicBool::new(true),
            #[cfg(test)]
            direct_fallbacks: AtomicUsize::new(0),
        });
        Self {
            shared,
            generation,
            data_offset,
        }
    }

    /// Establish what the settled predecessor left unflushed, then read the captured file's
    /// length. A failed flush is retained until the name is removed or recreated.
    fn complete(&self) -> Result<u64, Error> {
        let shared = &self.shared;
        let identity = Arc::downgrade(&self.generation);
        if shared.pending.debt(&shared.key, &identity)? {
            let result = shared.complete();
            shared.pending.clear(&shared.key, &identity, &result);
            result?;
        }
        shared
            .metadata()
            .map(|metadata| metadata.len() - self.data_offset)
            .map_err(|_| Error::ReadFailed)
    }

    /// Build the ring barrier that covers this open's mutations, returning `None` when clean.
    /// An open with a retained failure rejects every later durability claim.
    fn barrier(&self) -> Result<Option<SyncRequest>, Error> {
        if !self.shared.needs_sync()? {
            return Ok(None);
        }

        Ok(Some(SyncRequest::new(self.shared.clone())))
    }

    /// Prepare a contiguous read destination, retaining chunked input for copy-back.
    ///
    /// Keep preparation synchronous so its moved-from buffer collection does not
    /// occupy space in the suspended read future. The caller must fill `len`
    /// bytes before exposing the destination's contents.
    fn read_buffers(mut bufs: IoBufsMut, len: usize) -> (IoBufMut, Option<IoBufsMut>) {
        // SAFETY: The read loop fills `len` bytes before returning the buffers.
        unsafe { bufs.set_len(len) };

        if bufs.is_single() {
            (bufs.coalesce(), None)
        } else {
            // Preserve the caller's chunk layout by reading into a temporary.
            let mut buf = IoBufMut::with_capacity(len);
            // SAFETY: The read loop fills `len` bytes before copying them back.
            unsafe { buf.set_len(len) };
            (buf, Some(bufs))
        }
    }

    /// Map the logical `ranges` of a batch to physical ranges.
    ///
    /// A range whose physical offset or end overflows, or whose buffer has no allocation layout,
    /// fails the whole batch with [Error::OffsetOverflow], before any read is registered.
    fn physical_ranges(&self, ranges: &[(u64, usize)]) -> Result<Vec<(u64, usize)>, Error> {
        ranges
            .iter()
            .map(|&(offset, len)| {
                let offset = offset
                    .checked_add(self.data_offset)
                    .ok_or(Error::OffsetOverflow)?;
                offset
                    .checked_add(Widen::widen(len))
                    .ok_or(Error::OffsetOverflow)?;
                alloc::Layout::array::<u8>(len).map_err(|_| Error::OffsetOverflow)?;
                Ok((offset, len))
            })
            .collect()
    }

    /// Register a read of every physical range of a batch on the current worker, returning
    /// their handles in range order.
    ///
    /// Registering every read of a batch at once puts them all in flight together, without
    /// waiting for any handle to be polled. [crate::Blob::start_read_many] needs that before it
    /// returns its handle, because paged replay queues handles without polling them.
    /// [crate::Blob::read_many] registers on the first poll of its stream, so constructing the
    /// stream needs no worker.
    fn register_all(&self, ranges: &[(u64, usize)], options: ReadOptions) -> Vec<ReadHandle> {
        // An uncached batch opens the direct descriptor at most once, and only when it has a
        // range to read. A rejected or failed open leaves every range of the batch buffered.
        let dont_cache = options.contains(ReadOptions::DONT_CACHE);
        let fd = (dont_cache && ranges.iter().any(|&(_, len)| len > 0))
            .then(|| self.shared.open_direct())
            .flatten()
            .map(|direct| direct.as_raw_fd());
        ranges
            .iter()
            .map(|&(offset, len)| {
                // A read of no bytes would complete with 0, which reads report as the end of the
                // blob, so an empty range succeeds without a request, as it does for read_at.
                if len == 0 {
                    return ReadHandle::Ready(Some(Ok(IoBufsMut::default())));
                }

                // A range is read buffered, as read_at reads it, when the batch has no direct
                // descriptor or the range's aligned superset is not representable. In an uncached
                // batch it carries the RWF_DONTCACHE hint while the open supports it.
                let request = fd
                    .and_then(|fd| ReadAtRequest::direct(self.shared.clone(), fd, offset, len))
                    .unwrap_or_else(|| {
                        let (buf, _) = Self::read_buffers(IoBufMut::with_capacity(len).into(), len);
                        let cache = if dont_cache {
                            Cache::Disabled
                        } else {
                            Cache::Enabled
                        };
                        ReadAtRequest::new(self.shared.clone(), offset, buf, cache)
                    });
                ReadHandle::Pending(Operation::register(Request::ReadAt(request)))
            })
            .collect()
    }
}

/// Extract a positioned read's buffer from its operation's output.
fn read_output(output: Result<RequestOutput, Error>) -> Result<IoBufMut, Error> {
    let output = output.map_err(|_| Error::ReadFailed)?;
    let RequestOutput::ReadAt(result) = output else {
        unreachable!("read request returned another output kind");
    };
    result.map_err(|(_, error)| error)
}

/// One range of a batch: a registered read, or a result that needed none.
enum ReadHandle {
    /// A result known at registration, taken by the first poll.
    Ready(Option<Result<IoBufsMut, Error>>),
    /// A registered read.
    Pending(Operation),
}

impl Future for ReadHandle {
    type Output = Result<IoBufsMut, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Ready(result) => {
                Poll::Ready(result.take().expect("read polled after completion"))
            }
            Self::Pending(operation) => operation
                .poll_unpin(cx)
                .map(|output| read_output(output).map(Into::into)),
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
        self.read_at_buf(offset, len, IoBufMut::with_capacity(len), options)
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        let (io_buf, original_bufs) = Self::read_buffers(bufs.into(), len);

        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        // Zero-length reads succeed trivially without submitting to the ring.
        if len == 0 {
            return Ok(original_bufs.unwrap_or_else(|| io_buf.into()));
        }

        // Exclude the current-position sentinel and keep every partial read's
        // physical offset within the validated range.
        offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;

        let cache = if options.contains(ReadOptions::DONT_CACHE) {
            Cache::Disabled
        } else {
            Cache::Enabled
        };
        let io_buf = read_output(
            Operation::register(Request::ReadAt(ReadAtRequest::new(
                self.shared.clone(),
                offset,
                io_buf,
                cache,
            )))
            .await,
        )?;

        match original_bufs {
            None => Ok(io_buf.into()),
            Some(mut bufs) => {
                bufs.copy_from_slice(io_buf.as_ref());
                Ok(bufs)
            }
        }
    }

    fn read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> impl Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
        // Reads the page cache should retain go through it one range at a time, as read_at does.
        if !options.contains(ReadOptions::DONT_CACHE) {
            return Either::Left(crate::read_each(self, ranges, options));
        }

        // Every range is checked before any read is registered, so a bad range leaves none
        // behind and fails the stream alone.
        let ranges = self.physical_ranges(ranges);

        // Constructing the stream needs no worker. Its first poll registers every read on the
        // polling worker, which submits them together.
        Either::Right(
            stream::once(async move {
                match ranges {
                    Ok(ranges) => self.register_all(&ranges, options),
                    Err(error) => vec![ReadHandle::Ready(Some(Err(error)))],
                }
                .into_iter()
                .enumerate()
                .map(|(index, read)| read.map(move |result| result.map(|bufs| (index, bufs))))
                .collect::<FuturesUnordered<_>>()
            })
            .flatten(),
        )
    }

    async fn start_read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> Handle<Vec<IoBufsMut>> {
        // Every range is checked before any read is registered, so a bad range leaves none
        // behind.
        let ranges = match self.physical_ranges(ranges) {
            Ok(ranges) => ranges,
            Err(error) => return Handle::ready(Err(error)),
        };

        // Every read is registered before the handle is returned.
        crate::join_reads(self.register_all(&ranges, options))
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

        // Validate the signed file extent before mutation accounting or ring registration.
        // Each submission after partial progress then avoids the current-position sentinel.
        offset
            .checked_add(Widen::widen(bufs.len()))
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or(Error::OffsetOverflow)?;

        let cache = if options.contains(WriteOptions::DONT_CACHE) {
            Cache::Disabled
        } else {
            Cache::Enabled
        };

        // Sync writes that fit one vectored batch use per-write durability, which covers only
        // their own range. Larger ones finish all batches before a trailing sync.
        let sync = options.contains(WriteOptions::SYNC);
        if sync && let Some(error) = self.shared.tracker.failure() {
            return Err(error);
        }
        let state = if !sync {
            WriteAtState::Writing
        } else if bufs.chunk_count() > IOVEC_BATCH_SIZE {
            WriteAtState::WritingBeforeSync
        } else {
            WriteAtState::WritingSync
        };

        // A plain write records its mutation before submission. The ring settles the debt at
        // completion, and credits a trailing sync while the request holds the open's durability
        // permit, so a caller that stops waiting changes nothing.
        if !sync {
            self.shared.tracker.write();
        }
        let trailing = state == WriteAtState::WritingBeforeSync;
        let result = match Operation::register(Request::WriteAt(WriteAtRequest::new(
            self.shared.clone(),
            offset,
            bufs.into(),
            state,
            cache,
        )))
        .await
        {
            Ok(RequestOutput::WriteAt(result)) => result,
            Ok(_) => unreachable!("write request returned another output kind"),
            Err(_) => Err(Error::WriteFailed),
        };

        // In a multi-batch write, only the trailing sync reports `Error::Io`. Name it like `sync`.
        match result {
            Err(Error::Io(error)) if trailing => {
                let (partition, name) = &self.shared.key;
                Err(Error::BlobSyncFailed(partition.clone(), hex(name), error))
            }
            result => result,
        }
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn resize(&self, len: u64) -> Result<(), Error> {
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        self.shared.tracker.write();
        self.shared.file.set_len(len).map_err(|e| {
            let (partition, name) = &self.shared.key;
            Error::BlobResizeFailed(partition.clone(), hex(name), IoError::other(e).into())
        })?;
        self.shared.tracker.complete();
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let Some(request) = self.barrier()? else {
            return Ok(());
        };
        let (partition, name) = &self.shared.key;
        let output = Operation::register(Request::Sync(request))
            .await
            .map_err(|error| {
                Error::BlobSyncFailed(partition.clone(), hex(name), IoError::other(error).into())
            })?;
        let RequestOutput::Sync(result) = output else {
            unreachable!("sync request returned another output kind");
        };
        result.map_err(|error| match error {
            Error::Io(error) => Error::BlobSyncFailed(partition.clone(), hex(name), error),
            error => error,
        })
    }

    async fn start_sync(&self) -> Handle<()> {
        let request = match self.barrier() {
            Ok(Some(request)) => request,
            Ok(None) => return Handle::ready(Ok(())),
            Err(error) => return Handle::ready(Err(error)),
        };
        let (partition, name) = self.shared.key.clone();
        let receiver = operation::start_sync(request);
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
#[allow(deprecated)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        BLOB_PAGE_SIZE, Blob as _, Clock as _, IoBuf, IoBufMut, Runner as _, Spawner as _,
        Storage as _, Supervisor as _,
        buffer::paged::{CHECKSUM_SIZE, CacheRef, Writer},
        iouring::{self, operation::tests::admitted},
        storage::{Header, Layout, shared, tests::run_storage_tests},
    };
    use commonware_utils::{NZU16, NZUsize, channel::oneshot};
    use futures::TryStreamExt as _;
    use std::{
        collections::VecDeque,
        env,
        ffi::OsString,
        io::IoSlice,
        os::{
            fd::{OwnedFd, RawFd},
            unix::{ffi::OsStringExt, fs::FileExt as _, net::UnixStream},
        },
        pin::pin,
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::Duration,
    };

    impl Shared {
        /// Use `file` as the direct descriptor, returning its raw descriptor.
        pub(crate) fn set_direct(&self, file: File) -> RawFd {
            let fd = file.as_raw_fd();
            assert!(
                self.direct.set(Some(file)).is_ok(),
                "direct descriptor already set"
            );
            fd
        }

        /// Return the direct descriptor if it is open, without opening it.
        pub(crate) fn direct_file(&self) -> Option<&File> {
            self.direct.get().and_then(Option::as_ref)
        }
    }

    /// Distinguish temporary directories created within one test process.
    static NEXT_STORAGE_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    /// Build a fresh storage instance rooted in a unique temporary directory.
    fn create_test_storage() -> (Storage, PathBuf) {
        let storage_directory = create_test_directory();

        let storage = Storage::new(Config {
            storage_directory: storage_directory.clone(),
            blob_layouts: Layout::ALL,
        });
        (storage, storage_directory)
    }

    /// Build a fresh temporary directory without constructing storage.
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

    /// Count this process's descriptors on `path`, which was removed.
    fn removed_descriptors(path: &std::path::Path) -> usize {
        let removed = format!("{} (deleted)", path.display());
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
            .filter(|target| target.to_string_lossy() == removed)
            .count()
    }

    /// Direct reads of `blob`'s open that switched to a buffered read.
    fn fallbacks(blob: &Blob) -> usize {
        blob.shared.direct_fallbacks.load(Ordering::Relaxed)
    }

    /// Assert that `blob`'s open has its direct descriptor and no direct read of it fell back.
    fn assert_direct(blob: &Blob) {
        assert!(blob.shared.direct_file().is_some());
        assert_eq!(fallbacks(blob), 0);
    }

    /// The bytes of each range of `data`.
    fn expected(data: &[u8], ranges: &[(u64, usize)]) -> Vec<Vec<u8>> {
        ranges
            .iter()
            .map(|&(offset, len)| {
                let offset = usize::try_from(offset).unwrap();
                data[offset..offset + len].to_vec()
            })
            .collect()
    }

    /// Read `ranges` through [crate::Blob::read_many], checking that every index is yielded once,
    /// and return the bytes in range order.
    async fn collect_many(
        blob: &impl crate::Blob,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut bufs: Vec<(usize, IoBufsMut)> =
            blob.read_many(ranges, options).try_collect().await?;
        bufs.sort_by_key(|(index, _)| *index);
        assert!(bufs.iter().map(|(index, _)| *index).eq(0..ranges.len()));
        Ok(bufs
            .into_iter()
            .map(|(_, bufs)| bufs.coalesce().as_ref().to_vec())
            .collect())
    }

    /// Read `ranges` through [crate::Blob::start_read_many] and return the bytes in range order.
    async fn collect_started(
        blob: &impl crate::Blob,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let bufs = blob.start_read_many(ranges, options).await.await?;
        assert_eq!(bufs.len(), ranges.len());
        Ok(bufs
            .into_iter()
            .map(|bufs| bufs.coalesce().as_ref().to_vec())
            .collect())
    }

    /// Check that `bufs` hold `ranges` of `data`, in range order.
    fn check(data: &[u8], ranges: &[(u64, usize)], bufs: Vec<IoBufsMut>) {
        let bufs: Vec<Vec<u8>> = bufs
            .into_iter()
            .map(|bufs| bufs.coalesce().as_ref().to_vec())
            .collect();
        assert_eq!(bufs, expected(data, ranges));
    }

    /// Check that a read_many stream yields `ranges` of `data`, each once.
    fn check_indexed(data: &[u8], ranges: &[(u64, usize)], mut bufs: Vec<(usize, IoBufsMut)>) {
        bufs.sort_by_key(|(index, _)| *index);
        assert!(bufs.iter().map(|(index, _)| *index).eq(0..ranges.len()));
        check(
            data,
            ranges,
            bufs.into_iter().map(|(_, bufs)| bufs).collect(),
        );
    }

    /// Ranges of the lifecycle tests, over a blob of three blocks.
    static LIFECYCLE_RANGES: [(u64, usize); 4] = [(0, 4096), (100, 5000), (4096, 0), (8000, 4288)];

    /// Open `name` holding three blocks of patterned bytes, returning the blob and its bytes.
    async fn lifecycle_blob(storage: &Storage, name: &[u8]) -> (Blob, Vec<u8>) {
        let (blob, _) = storage.open("partition", name).await.unwrap();
        let data: Vec<u8> = (0..3 * 4096).map(|i| (i % 251) as u8).collect();
        blob.write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        (blob, data)
    }

    /// Holds back the results of its first batch read until a gate opens, after that read's first
    /// poll registered its reads. Later batch reads pass through. Records each batch read's
    /// range count.
    struct GatedBatchBlob {
        inner: Blob,
        gate: Mutex<Option<oneshot::Receiver<()>>>,
        batches: Mutex<Vec<usize>>,
    }

    impl crate::Blob for GatedBatchBlob {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len, options).await
        }

        fn read_many(
            &self,
            ranges: &[(u64, usize)],
            options: ReadOptions,
        ) -> impl Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
            self.batches.lock().push(ranges.len());
            let mut reads = Box::pin(self.inner.read_many(ranges, options));
            let mut gate = self.gate.lock().take();
            let mut held = VecDeque::new();
            let mut started = false;
            stream::poll_fn(move |cx| {
                if !started {
                    started = true;
                    while let Poll::Ready(Some(read)) = reads.as_mut().poll_next(cx) {
                        held.push_back(read);
                    }
                }
                if let Some(open) = gate.as_mut() {
                    let _ = std::task::ready!(open.poll_unpin(cx));
                    gate = None;
                }
                held.pop_front().map_or_else(
                    || reads.as_mut().poll_next(cx),
                    |read| Poll::Ready(Some(read)),
                )
            })
        }

        async fn start_read_many(
            &self,
            ranges: &[(u64, usize)],
            options: ReadOptions,
        ) -> Handle<Vec<IoBufsMut>> {
            self.inner.start_read_many(ranges, options).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            self.inner.write_at(offset, bufs, options).await
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            self.inner.start_sync().await
        }
    }

    #[test]
    fn test_large_contiguous_write_returns_kernel_error() {
        let directory = create_test_directory();
        let hold = Hold::acquire(&directory).unwrap();
        let blob = Blob::new(
            File::options().write(true).open("/dev/full").unwrap(),
            hold,
            0,
            Arc::new(Pending::default())
                .admit("partition", b"large", false)
                .unwrap()
                .0,
        );

        // Zeroed allocation stays demand-paged on Linux. The erroring device
        // exercises real submission without copying or storing gigabytes.
        let buf = IoBuf::from(vec![0; u32::MAX as usize + 1]);

        iouring::Runner::default().start(|_| async move {
            assert!(matches!(
                blob.write_at(0, buf, WriteOptions::default()).await,
                Err(Error::WriteFailed)
            ));
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_dropped_durable_write_retains_hold_through_shutdown() {
        let (storage, directory) = create_test_storage();
        let (blob, _) =
            futures::executor::block_on(storage.open("partition", b"retained")).unwrap();
        let data_offset = blob.data_offset as usize;
        drop(storage);
        let contender = File::options()
            .write(true)
            .open(directory.join(".hold"))
            .unwrap();

        // The blob belongs to another storage instance. Its request must carry
        // that instance's directory hold into this worker and through shutdown.
        iouring::Runner::default().start(|_| async {
            let write = blob.write_at(0, b"durable", WriteOptions::SYNC);
            assert!(futures::FutureExt::now_or_never(write).is_none());
            drop(blob);
            assert!(matches!(
                contender.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
        });

        // Returning from the runner proves that the orphaned write and its
        // durability sequence retired before the original directory unlocked.
        contender
            .try_lock()
            .expect("retired request must release its hold");
        let bytes = fs::read(directory.join("partition").join(hex(b"retained"))).unwrap();
        assert_eq!(&bytes[data_offset..], b"durable");
        drop(contender);
        let _ = fs::remove_dir_all(directory);
    }

    /// Dropping the last handle with unsynced writes performs no I/O and leaves debt the next
    /// open establishes with a single flush. Settled opens release the directory hold.
    #[test]
    fn test_dirty_drop_leaves_its_flush_to_the_next_open() {
        let (storage, directory) = create_test_storage();
        let pending = storage.pending.clone();
        let contender = File::options()
            .write(true)
            .open(directory.join(".hold"))
            .unwrap();

        iouring::Runner::default().start(|_| async {
            let (blob, _) = storage.open("partition", b"retained").await.unwrap();
            blob.write_at(0, b"retained", WriteOptions::default())
                .await
                .unwrap();
            drop(blob);
            settle(&pending).await;
            assert!(pending.owes("partition", b"retained"));
            assert_eq!(pending.completions(), 0);

            let (blob, len) = storage.open("partition", b"retained").await.unwrap();
            assert_eq!(len, 8);
            assert_eq!(pending.completions(), 1);
            assert!(!pending.owes("partition", b"retained"));
            assert_eq!(
                blob.read_at(0, 8, ReadOptions::default())
                    .await
                    .unwrap()
                    .coalesce()
                    .as_ref(),
                b"retained"
            );
            drop(blob);
            drop(storage);
        });

        contender
            .try_lock()
            .expect("a settled open must release its directory hold");
        drop(contender);
        fs::remove_dir_all(directory).unwrap();
    }

    /// The direct descriptor reaches the held inode after its name is removed and recreated, and
    /// closes with the open.
    #[test]
    fn test_direct_descriptor_reads_the_held_inode() {
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|_| async {
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            let data = vec![0x5A; BLOB_PAGE_SIZE as usize];
            blob.write_at(0, data.clone(), WriteOptions::default())
                .await
                .unwrap();
            storage.remove("partition", Some(b"blob")).await.unwrap();
            let (successor, _) = storage.open("partition", b"blob").await.unwrap();
            successor
                .write_at(
                    0,
                    vec![0xA5; BLOB_PAGE_SIZE as usize],
                    WriteOptions::default(),
                )
                .await
                .unwrap();

            let direct = blob
                .shared
                .open_direct()
                .expect("temporary directory must support O_DIRECT");
            let fd = direct.as_raw_fd();
            let mut buf = IoBufMut::zeroed_with_alignment(
                BLOB_PAGE_SIZE as usize,
                std::num::NonZeroUsize::new(BLOB_PAGE_SIZE as usize).unwrap(),
            );
            direct
                .read_exact_at(buf.as_mut(), blob.data_offset)
                .unwrap();
            assert_eq!(buf.as_ref(), data.as_slice());

            // Dropping the open closes its direct descriptor.
            let link = format!("/proc/self/fd/{fd}");
            let removed = format!(
                "{} (deleted)",
                directory.join("partition").join(hex(b"blob")).display()
            );
            assert_eq!(fs::read_link(&link).unwrap().to_string_lossy(), removed);
            drop(blob);
            assert!(
                fs::read_link(&link).map_or(true, |target| target.to_string_lossy() != removed)
            );
            drop(successor);
        });
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_hold_retained_by_open_blob() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();

            // The blob alone retains directory exclusion after its storage is gone.
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            drop(storage);
            let contender = std::fs::File::options()
                .write(true)
                .open(storage_directory.join(".hold"))
                .unwrap();
            assert!(matches!(
                contender.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            drop(blob);
            contender
                .try_lock()
                .expect("blob drop must release the directory hold");
            drop(contender);

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    #[allow(clippy::async_yields_async)]
    fn test_unpolled_sync_completion_releases_hold() {
        let (storage, directory) = create_test_storage();
        let pending = storage.pending.clone();
        let completion = iouring::Runner::default().start(|_| async move {
            let (blob, _) = storage.open("partition", b"retained").await.unwrap();
            blob.write_at(0, b"durable", WriteOptions::default())
                .await
                .unwrap();
            let completion = blob.start_sync().await;
            drop(blob);
            drop(storage);
            completion
        });

        // Runner shutdown retires the request even while its completion is unobserved.
        let contender = File::options()
            .write(true)
            .open(directory.join(".hold"))
            .unwrap();
        let released = contender.try_lock().is_ok();
        if released {
            contender.unlock().unwrap();
        }
        futures::executor::block_on(completion).unwrap();
        contender
            .try_lock()
            .expect("observed completion must release its hold");
        assert!(
            !pending.owes("partition", b"retained"),
            "completed explicit sync must cover the mutation"
        );
        drop(contender);
        fs::remove_dir_all(directory).unwrap();
        assert!(released, "unpolled completion retained the directory hold");
    }

    /// Verify the end-to-end blob-page alignment invariant on the io_uring backend: paged data
    /// written to a V1 blob with a 4096-byte physical page size occupies exactly one aligned
    /// 4096-byte disk page per physical page (header page included), so page reads never straddle a
    /// page boundary.
    #[test]
    fn test_v1_paged_alignment() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();

            // A logical page size whose physical page is exactly one blob page.
            let logical = crate::buffer::paged::page_size(BLOB_PAGE_SIZE);
            let cache = crate::buffer::paged::CacheRef::new(
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
                (writer, _) = writer.append(&item).await.unwrap();
            }
            let logical_size = writer.size();
            writer.sync().await.unwrap();

            // The raw file is a whole number of 4096-byte pages: one header page plus one page per
            // physical page of data (the partial tail page is zero-padded to a full physical page).
            let file_path = storage_directory.join("partition").join(hex(b"aligned"));
            let raw = std::fs::read(&file_path).unwrap();
            let raw_len: u64 = Widen::widen(raw.len());
            let pages = logical_size.div_ceil(logical.widen());
            assert_eq!(raw_len % u64::from(BLOB_PAGE_SIZE), 0);
            assert_eq!(
                raw_len,
                Layout::V1.data_offset() + pages * u64::from(BLOB_PAGE_SIZE)
            );

            // Every physical page sits exactly within one aligned 4096-byte disk page, with a valid
            // CRC record in its final 12 bytes.
            let data = &raw[usize::try_from(Layout::V1.data_offset()).unwrap()..];
            for (page, physical) in data.chunks_exact(Widen::widen(BLOB_PAGE_SIZE)).enumerate() {
                assert!(
                    crate::buffer::paged::validate_page_for_tests(physical),
                    "page {page} failed CRC validation at aligned boundary"
                );
            }

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_iouring_storage() {
        iouring::Runner::default().start(|context| async move {
            // Verify the io_uring storage backend satisfies the shared storage trait suite.
            let (storage, storage_directory) = create_test_storage();
            run_storage_tests(context, storage).await;
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    #[test]
    fn test_blob_header_handling() {
        iouring::Runner::default().start(|_| async {
            // Verify header creation, logical offsets, resize, and reopen.
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

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_blob_magic_mismatch() {
        iouring::Runner::default().start(|_| async {
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
                err.to_string().starts_with(
                    "blob corrupt: partition/6261645f6d61676963 reason: invalid magic"
                )
            );

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_blob_partial_header_reset() {
        iouring::Runner::default().start(|_| async {
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
        });
    }

    #[test]
    fn test_vectored_write_preserves_byte_order() {
        iouring::Runner::default().start(|_| async {
            // Verify the vectored submission preserves byte order across buffers.
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
        });
    }

    #[test]
    fn test_read_at_reports_eof_when_blob_is_too_short() {
        iouring::Runner::default().start(|_| async {
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
        });
    }

    #[test]
    fn test_read_at_buf_preserves_multichunk_layout() {
        iouring::Runner::default().start(|_| async {
            // Verify multi-chunk caller buffers keep their shape after the temporary-buffer fallback.
            let (storage, storage_directory) = create_test_storage();

            let (blob, _) = storage.open("partition", b"multichunk").await.unwrap();
            blob.write_at(0, b"hello world".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Use a two-chunk destination so the read path must rebuild the original
            // chunk layout after reading through a temporary contiguous buffer.
            let bufs =
                IoBufsMut::from(vec![IoBufMut::with_capacity(5), IoBufMut::with_capacity(6)]);
            let read = blob
                .read_at_buf(0, 11, bufs, ReadOptions::DONT_CACHE)
                .await
                .unwrap();

            // Check the original chunk boundaries as well as the returned bytes.
            let mut chunks = [IoSlice::new(&[]); 2];
            assert_eq!(read.chunks_vectored(&mut chunks), 2);
            assert_eq!(&*chunks[0], b"hello");
            assert_eq!(&*chunks[1], b" world");

            drop(blob);
            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_zero_length_read_and_write_short_circuit() {
        futures::executor::block_on(async {
            // No io_uring worker is installed, so any attempted registration would panic.
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

            // Empty reads also succeed beyond EOF without probing cache-hint support.
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
        });
    }

    #[test]
    fn test_scan_rejects_non_file_entries() {
        iouring::Runner::default().start(|_| async {
            // Verify partition scans reject unexpected directory contents as corruption.
            let (storage, storage_directory) = create_test_storage();

            // Inject a nested directory where `scan` expects only regular blob files.
            let partition = storage_directory.join("partition");
            std::fs::create_dir_all(partition.join("nested")).unwrap();

            // The wrapper should treat the partition as corrupt rather than silently skipping it.
            let err = storage.scan("partition").await.unwrap_err();
            assert_eq!(err.to_string(), "partition corrupt: partition");

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_remove_reports_missing_targets() {
        iouring::Runner::default().start(|_| async {
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
        });
    }

    #[test]
    fn test_scan_ignores_non_utf8_file_names() {
        iouring::Runner::default().start(|_| async {
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
        });
    }

    #[test]
    fn test_scan_rejects_non_hex_file_names() {
        iouring::Runner::default().start(|_| async {
            // Verify partition scans reject UTF-8 entries that are not valid blob names.
            let (storage, storage_directory) = create_test_storage();

            let partition = storage_directory.join("partition");
            std::fs::create_dir_all(&partition).unwrap();

            // Create a file whose name is valid UTF-8 but not valid hex.
            std::fs::write(partition.join("not-hex"), []).unwrap();

            let err = storage.scan("partition").await.unwrap_err();
            assert_eq!(err.to_string(), "partition corrupt: partition");

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_scan_rejects_non_canonical_hex_file_names() {
        iouring::Runner::default().start(|_| async {
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
        });
    }

    #[test]
    fn test_open_reports_partition_creation_failure() {
        iouring::Runner::default().start(|_| async {
            // Verify opening a blob reports partition-creation failures when the
            // partition path is occupied by a regular file. (An unusable storage
            // root fails Storage::new itself, when the directory hold is
            // acquired.)
            let storage_directory = create_test_directory();
            std::fs::write(storage_directory.join("partition"), b"not a directory").unwrap();

            let storage = Storage::new(Config {
                storage_directory: storage_directory.clone(),
                blob_layouts: Layout::ALL,
            });

            let err = storage
                .open("partition", b"blob")
                .await
                .err()
                .expect("occupied partition path should fail");
            assert_eq!(err.to_string(), "partition creation failed: partition");

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_open_reports_blob_open_failure_for_directory_path() {
        iouring::Runner::default().start(|_| async {
            // Verify opening a blob reports `BlobOpenFailed` when the blob path
            // already exists as a directory instead of a regular file.
            let storage_directory = create_test_directory();
            let partition = storage_directory.join("partition");
            let blob_name = hex(b"blob");

            // Pre-create the would-be blob path as a directory so `OpenOptions`
            // fails once the wrapper reaches the open call.
            std::fs::create_dir_all(partition.join(&blob_name)).unwrap();

            let storage = Storage::new(Config {
                storage_directory: storage_directory.clone(),
                blob_layouts: Layout::ALL,
            });

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
        });
    }

    #[test]
    fn test_write_range_overflow_before_registration() {
        for options in [WriteOptions::default(), WriteOptions::SYNC] {
            for chunks in [IOVEC_BATCH_SIZE + 1, 1, 2] {
                iouring::Runner::default().start(|_| async {
                    let (storage, directory) = create_test_storage();
                    let (blob, _) = storage.open("partition", b"range").await.unwrap();
                    let completed = storage.pending.completions();

                    // The physical offset must never become io_uring's current
                    // file-position sentinel, including writes needing restaging.
                    let offset = u64::MAX - blob.data_offset;
                    blob.write_at(offset, IoBufs::default(), options)
                        .await
                        .unwrap();
                    let bufs = (0..chunks).map(|_| IoBuf::from(b"x")).collect::<IoBufs>();
                    assert!(matches!(
                        blob.write_at(offset, bufs, options).await,
                        Err(Error::OffsetOverflow)
                    ));

                    // The signed file extent must also fit, including writes
                    // that would cross it during a later partial submission.
                    let last = i64::MAX as u64;
                    for physical in [last - (Widen::widen(chunks) - 1), last + 1] {
                        let bufs = (0..chunks).map(|_| IoBuf::from(b"x")).collect::<IoBufs>();
                        assert!(
                            matches!(
                                blob.write_at(physical - blob.data_offset, bufs, options)
                                    .await,
                                Err(Error::OffsetOverflow)
                            ),
                            "physical={physical} chunks={chunks} options={options:?}"
                        );
                        assert!(!blob.shared.tracker.is_dirty());
                        assert!(blob.shared.tracker.failure().is_none());
                    }

                    drop(blob);
                    let (blob, size) = storage.open("partition", b"range").await.unwrap();
                    assert_eq!(size, 0);
                    assert_eq!(storage.pending.completions(), completed);
                    blob.write_at(0, b"ok", WriteOptions::SYNC).await.unwrap();
                    drop(blob);
                    drop(storage);
                    std::fs::remove_dir_all(directory).unwrap();
                });
            }
        }
    }

    #[test]
    fn test_read_range_overflow_before_registration() {
        iouring::Runner::default().start(|_| async {
            let (storage, directory) = create_test_storage();
            let (blob, _) = storage.open("partition", b"read_range").await.unwrap();
            let sentinel = u64::MAX - blob.data_offset;

            for options in [ReadOptions::default(), ReadOptions::DONT_CACHE] {
                // Empty reads need no physical offset, including the sentinel.
                assert!(blob.read_at(sentinel, 0, options).await.unwrap().is_empty());
                for (offset, len) in [(sentinel, 1), (sentinel - 1, 2)] {
                    assert!(matches!(
                        blob.read_at(offset, len, options).await,
                        Err(Error::OffsetOverflow)
                    ));
                }
            }

            drop(blob);
            drop(storage);
            std::fs::remove_dir_all(directory).unwrap();
        });
    }

    #[test]
    fn test_blob_offset_overflow_guards() {
        iouring::Runner::default().start(|_| async {
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
        });
    }

    #[test]
    fn test_sync_dir_reports_missing_directory() {
        iouring::Runner::default().start(|_| async {
            // Verify directory fsync reports missing paths through the open-failure wrapper.
            let storage_directory = create_test_directory();
            let missing = storage_directory.join("missing");

            let err = sync_dir(&missing).expect_err("missing directory should fail");
            assert!(err.to_string().starts_with(&format!(
                "blob open failed: {}/directory error:",
                missing.to_string_lossy()
            )));

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_resize_reports_kernel_error() {
        iouring::Runner::default().start(|_| async {
            // Verify resize preserves its storage-specific wrapper when the
            // underlying descriptor is a socket rather than a regular file.
            let storage_directory = create_test_directory();
            let (socket, _peer) = UnixStream::pair().unwrap();
            let file = File::from(OwnedFd::from(socket));

            // `set_len` on a socket-backed file descriptor should fail in the
            // kernel, letting the wrapper expose `BlobResizeFailed`.

            let blob = Blob::new(
                file,
                Hold::acquire(&storage_directory).unwrap(),
                Layout::V0.data_offset(),
                Arc::new(Pending::default())
                    .admit("partition", b"blob", false)
                    .unwrap()
                    .0,
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
        });
    }

    #[test]
    fn test_pending_blob_operations_observe_worker_closure() {
        let (read, write, sync, directory) = iouring::Runner::default().start(|_| async {
            let (storage, directory) = create_test_storage();
            let (blob, _) = storage.open("partition", b"closed").await.unwrap();
            let blob = Arc::new(blob);
            let reader = Arc::clone(&blob);
            let writer = Arc::clone(&blob);
            let mut read =
                Box::pin(async move { reader.read_at(0, 1, ReadOptions::default()).await });
            let mut write =
                Box::pin(async move { writer.write_at(0, b"x", WriteOptions::default()).await });

            // Record an uncovered mutation so the sync reaches the ring.
            blob.shared.tracker.write();
            let mut sync = Box::pin(async move { blob.sync().await });

            // Register each operation before allowing worker shutdown. Keeping
            // these futures tests closure of their original worker identity.
            assert!(futures::poll!(read.as_mut()).is_pending());
            assert!(futures::poll!(write.as_mut()).is_pending());
            assert!(futures::poll!(sync.as_mut()).is_pending());

            (read, write, sync, directory)
        });

        assert!(matches!(
            futures::executor::block_on(read),
            Err(Error::ReadFailed)
        ));
        assert!(matches!(
            futures::executor::block_on(write),
            Err(Error::WriteFailed)
        ));
        assert!(matches!(
            futures::executor::block_on(sync),
            Err(Error::BlobSyncFailed(..))
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_queued_write_and_start_sync_finish_through_shutdown() {
        let (blob, handle, directory) = iouring::Runner::new(
            iouring::Config::default().with_ring_config(iouring::RingConfig {
                size: 1,
                ..Default::default()
            }),
        )
        .start(|_| async {
            let (storage, directory) = create_test_storage();
            let (blob, _) = storage.open("partition", b"queued_sync").await.unwrap();
            let mut read = Box::pin(blob.read_at(0, 1, ReadOptions::default()));
            assert!(futures::poll!(read.as_mut()).is_pending());

            // The write is registered beyond the ring's size and dropped before
            // any driver service. Worker ownership must survive that drop.
            let mut write = Box::pin(blob.write_at(0, b"x", WriteOptions::default()));
            assert!(futures::poll!(write.as_mut()).is_pending());
            drop(write);

            // Registration returns before driver service. The escaped handle
            // must still receive the detached sync result after shutdown.
            let handle = blob.start_sync().await;
            drop(read);
            (blob, handle, directory)
        });

        futures::executor::block_on(handle).unwrap();
        iouring::Runner::default().start(|_| async move {
            let data = blob.read_at(0, 1, ReadOptions::default()).await.unwrap();
            assert_eq!(data.coalesce().as_ref(), b"x");
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_blob_sync_reports_kernel_error() {
        iouring::Runner::default().start(|_| async {
            // Both observation paths must preserve the blob identity in errors.
            for detached in [false, true] {
                let storage_directory = create_test_directory();
                let (socket, _peer) = UnixStream::pair().unwrap();
                let file = File::from(OwnedFd::from(socket));
                let blob = Blob::new(
                    file,
                    Hold::acquire(&storage_directory).unwrap(),
                    Layout::V0.data_offset(),
                    Arc::new(Pending::default())
                        .admit("partition", b"blob", false)
                        .unwrap()
                        .0,
                );

                // A clean open skips the sync, so record an uncovered mutation first. Syncing
                // a socket then reaches the kernel and fails through the adapter.
                blob.shared.tracker.write();
                let result = if detached {
                    blob.start_sync().await.await
                } else {
                    blob.sync().await
                };
                let err = result.expect_err("sync should fail on a socket fd");
                assert!(err.to_string().starts_with(&format!(
                    "blob sync failed: partition/{} error:",
                    hex(b"blob")
                )));

                drop(blob);
                let _ = std::fs::remove_dir_all(&storage_directory);
            }
        });
    }

    #[test]
    fn test_blob_torn_creation_recovers() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();

            // Create a durable V1 blob to obtain the canonical header region bytes.
            let (blob, _) = storage.open("partition", b"torn").await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            let path = storage_directory.join("partition").join(hex(b"torn"));
            let region = std::fs::read(&path).unwrap();

            // Simulate a torn creation: a prefix of the canonical header region (the full
            // state enumeration lives in the Layout::interrupted_creation unit tables).
            std::fs::write(&path, &region[..10]).unwrap();
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen.
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            drop(blob);

            // Foreign bytes are corruption, not a torn creation: nonzero padding behind a
            // torn (unparseable) prefix.
            let mut corrupt = vec![0u8; region.len()];
            corrupt[..10].copy_from_slice(&region[..10]);
            corrupt[100] = 0xFF;
            std::fs::write(&path, &corrupt).unwrap();
            let result = storage.open("partition", b"torn").await;
            assert!(matches!(result, Err(Error::BlobCorrupt(_, _, _))));

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_blob_v1_rejects_nonzero_header_padding() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();

            let partition_dir = storage_directory.join("partition");
            std::fs::create_dir_all(&partition_dir).unwrap();
            let path = partition_dir.join(hex(b"dirty_padding"));
            let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
            raw[Header::PARSE_LEN] = 0xFF;
            std::fs::write(&path, raw).unwrap();

            let Err(Error::BlobCorrupt(_, _, reason)) =
                storage.open("partition", b"dirty_padding").await
            else {
                panic!("nonzero header padding should be rejected");
            };
            assert!(reason.contains("header padding"));

            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    #[test]
    fn test_blob_v0_legacy_read() {
        iouring::Runner::default().start(|_| async {
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
        });
    }

    /// Scan and removal distinguish missing partitions from existing non-directory paths.
    #[test]
    fn test_partition_failures_are_not_absence() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            let partition = storage_directory.join("partition");
            fs::write(&partition, b"not a directory").unwrap();

            assert!(matches!(
                storage.scan("partition").await,
                Err(Error::ReadFailed)
            ));
            assert!(matches!(
                storage.scan("missing").await,
                Err(Error::PartitionMissing(_))
            ));

            assert!(matches!(
                storage.remove("partition", None).await,
                Err(Error::Io(_))
            ));
            assert!(partition.exists());
            assert!(matches!(
                storage.remove("missing", None).await,
                Err(Error::PartitionMissing(_))
            ));

            drop(storage);
            fs::remove_dir_all(storage_directory).unwrap();
        });
    }

    /// Wait until every settling open has published its outcome.
    async fn settle(pending: &Pending) {
        while pending.outstanding() > 0 {
            crate::utils::reschedule().await;
        }
    }

    #[test]
    fn test_failed_creation_does_not_publish_unsynced_header() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            shared::check_failed_creation(&storage, &storage.pending).await;
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    #[test]
    fn test_durable_writes_need_no_reopen_sync() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            shared::check_sync_writes(&storage, &storage.pending).await;
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// A durable write that fails after its caller stopped waiting dirties the open. A fused
    /// write also poisons it, since its failure may have consumed the kernel's writeback error,
    /// so its name retains the failure until removed or recreated. A batched write that fails
    /// before its trailing sync only leaves the open dirty.
    #[test]
    fn test_orphaned_failed_durable_write_poisons_the_open() {
        // One batch fuses the sync into the write. More batches end in a trailing sync.
        for chunks in [1, IOVEC_BATCH_SIZE + 1] {
            let directory = create_test_directory();
            let path = directory.join("readonly");
            fs::write(&path, b"").unwrap();
            let hold = Hold::acquire(&directory).unwrap();
            let pending = Arc::new(Pending::default());
            let blob = Blob::new(
                File::options().read(true).open(&path).unwrap(),
                hold,
                0,
                pending.admit("partition", b"readonly", false).unwrap().0,
            );

            iouring::Runner::default().start(|_| async move {
                let bufs = IoBufs::from((0..chunks).map(|_| IoBuf::from(b"x")).collect::<Vec<_>>());
                let mut write = Box::pin(blob.write_at(0, bufs, WriteOptions::SYNC));
                assert!(futures::poll!(write.as_mut()).is_pending());
                drop(write);
                drop(blob);
            });

            // The write failed against the read-only descriptor after its caller left, so the
            // retired request left the name dirty, and poisoned when the sync was fused.
            assert!(pending.owes("partition", b"readonly"), "chunks={chunks}");
            let admitted = pending.admit("partition", b"readonly", true);
            if chunks == 1 {
                assert!(
                    matches!(admitted, Err(Error::BlobSyncFailed(_, _, error))
                        if error.raw_os_error() == Some(libc::EBADF)),
                    "chunks={chunks}"
                );
            } else {
                let (_, wait, owed) = admitted.unwrap();
                assert!(wait.is_none() && owed, "chunks={chunks}");
            }
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn test_orphaned_write_lands_before_reopen() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            shared::check_orphaned_write(&storage).await;
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// Unlinking a blob forgets its debt, whether the last dirty handle drops before or after
    /// the unlink, so no later open flushes a file that no longer exists.
    #[test]
    fn test_remove_live_dirty_owner_leaves_no_debt() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            shared::check_remove_live_dirty_owner(&storage, &storage.pending).await;
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// A handle to a removed blob records no debt against the recreated name, while the
    /// recreated blob's own dirty drop is flushed by the next open.
    #[test]
    fn test_recreate_reopen_ignores_removed_handle() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            for remove_name in [true, false] {
                let partition = "recreate_pending";
                let name = b"blob";
                let (old, _) = storage.open(partition, name).await.unwrap();
                old.write_at(0, b"old", WriteOptions::default())
                    .await
                    .unwrap();
                storage
                    .remove(partition, remove_name.then_some(name.as_slice()))
                    .await
                    .unwrap();

                let (current, len) = storage.open(partition, name).await.unwrap();
                assert_eq!(len, 0);
                let current = Arc::new(current);
                let reader = Arc::clone(&current);
                current
                    .write_at(0, b"new", WriteOptions::default())
                    .await
                    .unwrap();
                let completions = storage.pending.completions();
                drop(current);
                drop(old);
                drop(reader);
                settle(&storage.pending).await;
                assert!(storage.pending.owes(partition, name));

                let (reopened, len) = storage.open(partition, name).await.unwrap();
                assert_eq!(storage.pending.completions() - completions, 1);
                assert_eq!(len, 3);
                let bytes = reopened
                    .read_at(0, 3, ReadOptions::default())
                    .await
                    .unwrap()
                    .coalesce();
                assert_eq!(bytes.as_ref(), b"new");
                drop(reopened);
                storage.remove(partition, None).await.unwrap();
            }
            shared::check_recreate_clean(&storage, &storage.pending).await;
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// Only a multi-batch durable write covers the plain writes before it.
    #[test]
    fn test_multibatch_durable_write_covers_prior_mutations() {
        iouring::Runner::default().start(|_| async {
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
                let completions = storage.pending.completions();
                let (blob, _) = storage.open("large_durable", &[case as u8]).await.unwrap();
                blob.write_at(0, b"prefix", WriteOptions::default())
                    .await
                    .unwrap();
                let mut bufs = IoBufs::default();
                for _ in 0..chunks {
                    bufs.append(IoBuf::from(vec![7u8]));
                }
                blob.write_at(6, bufs, options).await.unwrap();
                if later_plain {
                    blob.write_at(0, b"suffix", WriteOptions::default())
                        .await
                        .unwrap();
                }
                drop(blob);
                let (blob, size) = storage.open("large_durable", &[case as u8]).await.unwrap();
                assert_eq!(
                    storage.pending.completions() - completions,
                    expected,
                    "case={case}"
                );
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
            }
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// A multi-batch durable write credits the plain writes before it when its trailing sync
    /// completes, not when its caller resumes. A dropped caller leaves no debt, and a failure
    /// retained after completion does not fail the finished write.
    #[test]
    fn test_trailing_sync_credits_at_completion() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            for orphan in [true, false] {
                let name = [u8::from(orphan)];
                let (blob, _) = storage.open("trailing_credit", &name).await.unwrap();
                blob.write_at(0, b"prefix", WriteOptions::default())
                    .await
                    .unwrap();

                // Submit a write spanning more than one iovec batch, then wait for the request
                // to retire its file reference without polling the caller again.
                let bufs = (0..IOVEC_BATCH_SIZE + 1)
                    .map(|_| IoBuf::from(b"x"))
                    .collect::<IoBufs>();
                let mut write = Box::pin(blob.write_at(6, bufs, WriteOptions::SYNC));
                assert!(futures::poll!(write.as_mut()).is_pending());
                while Arc::strong_count(&blob.shared) > 1 {
                    crate::utils::reschedule().await;
                }
                assert!(!blob.shared.tracker.is_dirty());

                if orphan {
                    // The dropped caller leaves nothing for the next open to flush.
                    drop(write);
                    drop(blob);
                    settle(&storage.pending).await;
                    assert!(!storage.pending.owes("trailing_credit", &name));
                    let completions = storage.pending.completions();
                    drop(storage.open("trailing_credit", &name).await.unwrap());
                    assert_eq!(storage.pending.completions(), completions);
                } else {
                    // A later barrier's failure does not fail the finished write. Later
                    // durability claims still observe it.
                    blob.shared.tracker.poison(&Error::Closed);
                    write.await.unwrap();
                    assert!(matches!(blob.sync().await, Err(Error::Closed)));
                    drop(blob);
                }
            }
            storage.remove("trailing_credit", None).await.unwrap();
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// Handles whose mutations are all durable leave no debt, and removal forgets whatever a
    /// dirty handle left behind.
    #[test]
    fn test_synced_drop_leaves_no_debt() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();

            // Each durability entry point (sync, start_sync, and a SYNC write) must cover its
            // mutations before the open settles.
            let (blob, _) = storage.open("partition", b"sync").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            let (blob, _) = storage.open("partition", b"start_sync").await.unwrap();
            blob.resize(16).await.unwrap();
            blob.start_sync().await.await.unwrap();
            drop(blob);

            let (blob, _) = storage.open("partition", b"sync_write").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::SYNC)
                .await
                .unwrap();
            drop(blob);

            // Clean settlement permits reopening without an additional completion flush.
            settle(&storage.pending).await;
            for name in [b"sync".as_slice(), b"start_sync", b"sync_write"] {
                assert!(!storage.pending.owes("partition", name));
                drop(storage.open("partition", name).await.unwrap());
            }
            assert_eq!(storage.pending.completions(), 0);

            // A dirty handle leaves debt that removal forgets.
            let (blob, _) = storage.open("partition", b"dirty").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::default())
                .await
                .unwrap();
            drop(blob);
            settle(&storage.pending).await;
            assert!(storage.pending.owes("partition", b"dirty"));
            storage.remove("partition", None).await.unwrap();
            assert!(!storage.pending.owes("partition", b"dirty"));
            assert_eq!(storage.pending.completions(), 0);

            drop(storage);
            let _ = std::fs::remove_dir_all(&storage_directory);
        });
    }

    /// A dropped write keeps its open alive, so the next open waits for it to retire before it
    /// flushes the debt and reports the blob's length.
    #[test]
    fn test_orphaned_write_delays_settlement() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            let (blob, _) = storage.open("partition", b"orphaned").await.unwrap();
            let mut write = Box::pin(blob.write_at(0, b"orphaned", WriteOptions::default()));
            assert!(futures::poll!(write.as_mut()).is_pending());
            drop(write);
            drop(blob);

            // The registered write still owns the open, so its settlement stays unpublished.
            assert_eq!(storage.pending.outstanding(), 1);
            assert_eq!(storage.pending.completions(), 0);

            let (blob, len) = storage.open("partition", b"orphaned").await.unwrap();
            assert_eq!(len, 8);
            assert_eq!(storage.pending.outstanding(), 0);
            assert_eq!(storage.pending.completions(), 1);
            let read = blob
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), b"orphaned");
            drop(blob);
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// An open waiting on a settling predecessor may be cancelled or have its blob removed. A
    /// cancelled open leaves the debt to a retry. A removed open binds to the old file and
    /// leaves the replacement alone.
    #[test]
    fn test_waiting_open_cancelled_or_removed() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            for remove in [false, true] {
                // Keep the predecessor settling behind a registered orphaned write.
                let name = [u8::from(remove)];
                let (blob, _) = storage.open("partition", &name).await.unwrap();
                let mut write = Box::pin(blob.write_at(0, b"orphaned", WriteOptions::default()));
                assert!(futures::poll!(write.as_mut()).is_pending());
                drop(write);
                drop(blob);
                let mut open = Box::pin(storage.open("partition", &name));
                assert!(futures::poll!(open.as_mut()).is_pending());
                let completions = storage.pending.completions();

                if remove {
                    // Removal detaches the settling predecessor. The replacement then opens
                    // while the removed open still waits.
                    assert_eq!(storage.pending.outstanding(), 1);
                    storage.remove("partition", Some(&name)).await.unwrap();
                    assert_eq!(storage.pending.outstanding(), 0);
                    let (current, len) = storage.open("partition", &name).await.unwrap();
                    assert_eq!(len, 0);
                    let (removed, len) = open.await.unwrap();
                    assert_eq!(len, 8);
                    let read = removed
                        .read_at(0, 8, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce();
                    assert_eq!(read.as_ref(), b"orphaned");
                    drop(removed);
                    drop(current);
                    settle(&storage.pending).await;
                    assert!(!storage.pending.owes("partition", &name));
                    let (_, len) = storage.open("partition", &name).await.unwrap();
                    assert_eq!(len, 0);
                    assert_eq!(storage.pending.completions(), completions);
                } else {
                    // The retry waits for the same predecessor and flushes its debt once.
                    drop(open);
                    let (retry, len) = storage.open("partition", &name).await.unwrap();
                    assert_eq!(len, 8);
                    assert_eq!(storage.pending.completions(), completions + 1);
                    let read = retry
                        .read_at(0, 8, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce();
                    assert_eq!(read.as_ref(), b"orphaned");
                }
            }
            storage.remove("partition", None).await.unwrap();
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    #[test]
    fn test_untouched_creation_needs_no_reopen_flush() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            shared::check_untouched_creation_leaves_no_debt(&storage, &storage.pending).await;
            drop(storage);
            std::fs::remove_dir_all(storage_directory).unwrap();
        });
    }

    /// A sync on an open with no uncovered mutation returns without a device flush, so callers
    /// may sync freely, including immediately after a successful open.
    #[test]
    fn test_clean_sync_is_skipped() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            let (blob, _) = storage.open("partition", b"clean").await.unwrap();
            blob.sync().await.unwrap();
            blob.start_sync().await.await.unwrap();
            assert_eq!(blob.shared.tracker.skipped(), 2);

            // A mutation makes the next sync real, and only the next one.
            blob.write_at(0, b"hello", WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            assert_eq!(blob.shared.tracker.skipped(), 2);
            blob.sync().await.unwrap();
            blob.resize(3).await.unwrap();
            blob.start_sync().await.await.unwrap();
            blob.start_sync().await.await.unwrap();
            assert_eq!(blob.shared.tracker.skipped(), 4);
            drop(blob);
            settle(&storage.pending).await;
            assert!(!storage.pending.owes("partition", b"clean"));
            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    #[test]
    fn test_dirty_sync_waits_without_blocking_other_io() {
        iouring::Runner::default().start(|_| async {
            let (storage, directory) = create_test_storage();
            let (blob, _) = storage.open("gate", b"first").await.unwrap();
            let (unrelated, _) = storage.open("gate", b"second").await.unwrap();
            let permit = blob.shared.durability.try_lock().unwrap();

            // A fused write leaves the tracker clean until its terminal result.
            let mut durable = Box::pin(blob.write_at(0, b"durable", WriteOptions::SYNC));
            assert!(futures::poll!(durable.as_mut()).is_pending());
            assert!(!blob.shared.tracker.is_dirty());

            // Clean syncs owe no barrier for the unfinished fused write.
            let mut clean = Box::pin(async {
                blob.sync().await?;
                blob.start_sync().await.await
            });
            assert!(matches!(
                futures::poll!(clean.as_mut()),
                std::task::Poll::Ready(Ok(()))
            ));
            drop(clean);

            // A completed plain write requires the sync to wait for the permit.
            blob.write_at(7, b"plain", WriteOptions::default())
                .await
                .unwrap();
            assert!(blob.shared.tracker.is_dirty());

            // start_sync must transfer ownership on its first poll, even while
            // another durability decision for this open owns the permit.
            let mut start = Box::pin(blob.start_sync());
            let std::task::Poll::Ready(handle) = futures::poll!(start.as_mut()) else {
                panic!("start_sync must return its handle on the first poll");
            };
            drop(start);
            let mut handle = Box::pin(handle);
            assert!(futures::poll!(handle.as_mut()).is_pending());

            unrelated
                .write_at(0, b"other", WriteOptions::SYNC)
                .await
                .unwrap();
            assert!(futures::poll!(durable.as_mut()).is_pending());

            drop(permit);
            durable.await.unwrap();
            handle.await.unwrap();
            blob.sync().await.unwrap();
            let bytes = blob.read_at(0, 12, ReadOptions::default()).await.unwrap();
            assert_eq!(bytes.coalesce().as_ref(), b"durableplain");
            drop(blob);
            drop(unrelated);
            storage.remove("gate", None).await.unwrap();
            drop(storage);
            fs::remove_dir_all(directory).unwrap();
        });
    }

    #[test]
    fn test_recreated_blob_does_not_wait_for_removed_opens_gate() {
        iouring::Runner::default().start(|_| async {
            let (storage, directory) = create_test_storage();
            for remove_name in [true, false] {
                let (old, _) = storage.open("recreated_gate", b"blob").await.unwrap();
                let permit = old.shared.durability.try_lock().unwrap();
                storage
                    .remove("recreated_gate", remove_name.then_some(b"blob".as_slice()))
                    .await
                    .unwrap();
                let (current, len) = storage.open("recreated_gate", b"blob").await.unwrap();
                assert_eq!(len, 0);
                assert!(!Arc::ptr_eq(
                    &old.shared.durability,
                    &current.shared.durability
                ));
                current
                    .write_at(0, b"new", WriteOptions::SYNC)
                    .await
                    .unwrap();
                drop(permit);
                drop(current);
                drop(old);
                storage.remove("recreated_gate", None).await.unwrap();
            }
            drop(storage);
            fs::remove_dir_all(directory).unwrap();
        });
    }

    /// A failed flush is retained: the handle reports it on every later sync, and once it drops
    /// every open of the name fails until the blob is removed.
    #[test]
    fn test_flush_failure_is_retained() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();

            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::default())
                .await
                .unwrap();
            *storage.pending.test.fail_flush.lock() = Some(Error::Closed);
            assert!(matches!(blob.sync().await, Err(Error::Closed)));
            assert!(matches!(blob.sync().await, Err(Error::Closed)));
            assert!(matches!(blob.start_sync().await.await, Err(Error::Closed)));
            drop(blob);
            settle(&storage.pending).await;
            for _ in 0..2 {
                assert!(matches!(
                    storage.open("partition", b"blob").await,
                    Err(Error::Closed)
                ));
            }
            storage.remove("partition", Some(b"blob")).await.unwrap();
            let (blob, size) = storage.open("partition", b"blob").await.unwrap();
            assert_eq!(size, 0);
            drop(blob);

            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    /// Completion failures poison the open before publishing the error to the namespace.
    #[test]
    fn test_completion_failure_poisons_open() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::default())
                .await
                .unwrap();

            *storage.pending.test.fail_flush.lock() = Some(Error::WriteFailed);
            assert!(matches!(blob.shared.complete(), Err(Error::WriteFailed)));
            assert!(matches!(
                blob.shared.tracker.failure(),
                Some(Error::WriteFailed)
            ));
            assert!(matches!(blob.sync().await, Err(Error::WriteFailed)));

            drop(blob);
            drop(storage);
            std::fs::remove_dir_all(storage_directory).unwrap();
        });
    }

    /// A completion that fails at open is retained for later opens instead of being retried, so
    /// a fresh descriptor cannot certify bytes the kernel already reported lost.
    #[test]
    fn test_completion_failure_is_retained() {
        iouring::Runner::default().start(|_| async {
            let (storage, storage_directory) = create_test_storage();

            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::default())
                .await
                .unwrap();
            drop(blob);
            settle(&storage.pending).await;
            *storage.pending.test.fail_flush.lock() = Some(Error::WriteFailed);
            for _ in 0..2 {
                assert!(matches!(
                    storage.open("partition", b"blob").await,
                    Err(Error::WriteFailed)
                ));
            }
            assert_eq!(storage.pending.completions(), 0);
            storage.remove("partition", None).await.unwrap();
            let (blob, size) = storage.open("partition", b"blob").await.unwrap();
            assert_eq!(size, 0);
            drop(blob);

            drop(storage);
            let _ = std::fs::remove_dir_all(storage_directory);
        });
    }

    #[test]
    fn test_read_many_indexes_every_range() {
        const BLOCK: usize = 4096;
        const BLOCKS: u64 = 64;
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|_| async {
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();

            // 64 blocks of 4096 bytes, each filled with its index.
            let data: Vec<u8> = (0..BLOCKS)
                .flat_map(|i| std::iter::repeat_n(i as u8, BLOCK))
                .collect();
            blob.write_at(0, data.clone(), WriteOptions::default())
                .await
                .unwrap();

            // Whole aligned blocks, small unaligned ranges inside and across blocks, empty,
            // duplicate and overlapping ranges, all out of offset order.
            let mut ranges: Vec<(u64, usize)> = Vec::new();
            for i in (0..BLOCKS).rev() {
                let start = i * BLOCK as u64;
                ranges.push((start, BLOCK));
                ranges.push((start + 7, 10));
                ranges.push((start + 7, 10));
                if i > 0 {
                    ranges.push((start - 3, 6));
                }
                ranges.push((start, 0));
                if i + 2 <= BLOCKS {
                    ranges.push((start + 100, 2 * BLOCK - 200));
                }
            }
            let expected = expected(&data, &ranges);
            for options in [ReadOptions::default(), ReadOptions::DONT_CACHE] {
                // Only uncached batches open the direct descriptor.
                let direct = options == ReadOptions::DONT_CACHE;
                assert_eq!(
                    collect_many(&blob, &ranges, options).await.unwrap(),
                    expected
                );
                assert_eq!(blob.shared.direct_file().is_some(), direct);
                assert_eq!(fallbacks(&blob), 0);
                assert_eq!(
                    collect_started(&blob, &ranges, options).await.unwrap(),
                    expected
                );
                assert_eq!(blob.shared.direct_file().is_some(), direct);
                assert_eq!(fallbacks(&blob), 0);

                // A range past the end fails the call as read_at does.
                let short = [(0, BLOCK), (BLOCKS * BLOCK as u64 - 1, 2)];
                assert!(matches!(
                    collect_many(&blob, &short, options).await,
                    Err(Error::BlobInsufficientLength)
                ));
                assert!(matches!(
                    collect_started(&blob, &short, options).await,
                    Err(Error::BlobInsufficientLength)
                ));

                // An offset beyond the file's address space fails the call.
                for invalid in [(u64::MAX, 1), (u64::MAX - BLOCK as u64, 2 * BLOCK)] {
                    let ranges = [(0, BLOCK), invalid];
                    assert!(matches!(
                        collect_many(&blob, &ranges, options).await,
                        Err(Error::OffsetOverflow)
                    ));
                    assert!(matches!(
                        collect_started(&blob, &ranges, options).await,
                        Err(Error::OffsetOverflow)
                    ));
                }
            }
            drop(blob);
        });
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// Ranges that are not block-aligned, under a layout whose data offset is not block-aligned
    /// either, are served by direct reads of their aligned superset, including a superset that
    /// ends past the unaligned end of the blob. A range past the end fails as read_at does.
    #[test]
    fn test_read_many_serves_unaligned_ranges_directly() {
        const BLOCK: usize = 4096;
        const LEN: usize = BLOCK + 1000;
        let data: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        for layout in [Layout::V0, Layout::V1] {
            let directory = create_test_directory();
            let storage = Storage::new(Config {
                storage_directory: directory.clone(),
                blob_layouts: layout..=layout,
            });
            iouring::Runner::default().start(|_| async {
                let (blob, _) = storage.open("partition", b"blob").await.unwrap();
                blob.write_at(0, data.clone(), WriteOptions::default())
                    .await
                    .unwrap();

                // Within a block, across a block boundary, up to the end, and the whole blob.
                let ranges = [
                    (100u64, 50usize),
                    (BLOCK as u64 - 3, 6),
                    (BLOCK as u64 + 500, 500),
                    (LEN as u64 - 1, 1),
                    (0, LEN),
                ];
                let expected = expected(&data, &ranges);
                assert_eq!(
                    collect_many(&blob, &ranges, ReadOptions::DONT_CACHE)
                        .await
                        .unwrap(),
                    expected
                );
                assert_eq!(
                    collect_started(&blob, &ranges, ReadOptions::DONT_CACHE)
                        .await
                        .unwrap(),
                    expected
                );
                assert_direct(&blob);

                // A range ending one byte past the end falls back once and fails as read_at does.
                let past = [(LEN as u64 - 100, 101)];
                assert!(matches!(
                    collect_started(&blob, &past, ReadOptions::DONT_CACHE).await,
                    Err(Error::BlobInsufficientLength)
                ));
                assert_eq!(fallbacks(&blob), 1);
            });
            drop(storage);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    /// A batched direct read goes through its own open file description, and the kernel writes
    /// the range's dirty pages back before a direct read, so the batch sees every buffered write
    /// that completed before it, synced or not.
    #[test]
    fn test_read_many_sees_unsynced_buffered_writes() {
        const BLOCK: usize = 4096;
        const RANGES: [(u64, usize); 3] =
            [(0, BLOCK), (BLOCK as u64, BLOCK), (BLOCK as u64 + 100, 300)];
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|_| async {
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            let read_all = || async {
                let bufs = collect_many(&blob, &RANGES, ReadOptions::DONT_CACHE)
                    .await
                    .unwrap();
                assert_direct(&blob);
                bufs
            };

            // Two buffered, unsynced generations of the same blocks. Each batch sees the latest.
            for generation in [0x11u8, 0x22] {
                let data = vec![generation; 2 * BLOCK];
                blob.write_at(0, data.clone(), WriteOptions::default())
                    .await
                    .unwrap();
                assert_eq!(read_all().await, expected(&data, &RANGES));
            }

            // A partial buffered overwrite inside the second block is seen too.
            blob.write_at(BLOCK as u64 + 150, vec![0x33; 100], WriteOptions::default())
                .await
                .unwrap();
            let bufs = read_all().await;
            assert_eq!(&bufs[2][..50], &[0x22; 50]);
            assert_eq!(&bufs[2][50..150], &[0x33; 100]);
            assert_eq!(&bufs[2][150..], &[0x22; 150]);
        });
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// A batch maps its ranges to physical ones, and a range whose physical offset or end
    /// overflows, or that no buffer can hold, fails it before any read is registered.
    #[test]
    fn test_read_many_reports_unservable_range() {
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|_| async {
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, vec![0u8; 4096], WriteOptions::default())
                .await
                .unwrap();

            // Every range up to the largest representable end is valid, empty or not.
            let data_offset = blob.data_offset;
            assert!(data_offset > 0);
            assert_eq!(
                blob.physical_ranges(&[(0, 4096), (7, 0), (u64::MAX - data_offset - 1, 1)])
                    .unwrap(),
                [(data_offset, 4096), (data_offset + 7, 0), (u64::MAX - 1, 1)]
            );
            for ranges in [
                vec![(0, 1), (u64::MAX, 1)],
                vec![(0, 1), (u64::MAX - data_offset - 100, 101)],
                vec![(0, isize::MAX as usize + 1)],
                vec![(0, 0), (1 << 40, usize::MAX)],
            ] {
                assert!(
                    matches!(blob.physical_ranges(&ranges), Err(Error::OffsetOverflow)),
                    "{ranges:?}"
                );
            }

            // The first range overflows the physical end, the second is larger than any
            // allocation layout, and the third is preceded by a valid range.
            for options in [ReadOptions::default(), ReadOptions::DONT_CACHE] {
                for ranges in [
                    vec![(0, usize::MAX - 10)],
                    vec![(0, 1usize << (usize::BITS - 1))],
                    vec![(0, 4096), (0, usize::MAX - 8191)],
                ] {
                    let handle = blob.start_read_many(&ranges, options).await;
                    assert_eq!(Arc::strong_count(&blob.shared), 1);
                    assert!(matches!(handle.await, Err(Error::OffsetOverflow)));
                    if options == ReadOptions::DONT_CACHE {
                        let mut reads = pin!(blob.read_many(&ranges, options));
                        assert!(matches!(
                            reads.next().await,
                            Some(Err(Error::OffsetOverflow))
                        ));
                        assert_eq!(Arc::strong_count(&blob.shared), 1);
                        assert!(reads.next().await.is_none());
                    }
                }
            }
            assert!(blob.shared.direct_file().is_none());
        });
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// Every nonempty range of a batch is admitted to the worker on the first poll of a
    /// read_many stream, before any range is yielded, and before start_read_many returns its
    /// handle.
    #[test]
    fn test_batches_register_every_read_together() {
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|_| async {
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            let data: Vec<u8> = (0..3 * 4096).map(|i| (i % 251) as u8).collect();
            blob.write_at(0, data.clone(), WriteOptions::default())
                .await
                .unwrap();
            let idle = admitted();

            // An empty range first is yielded by the first poll, after every read was admitted.
            let ranges = [(5, 0), (0, 4096), (100, 5000), (8192, 4096)];
            let mut reads = pin!(blob.read_many(&ranges, ReadOptions::DONT_CACHE));
            assert_eq!(admitted(), idle);
            let Poll::Ready(Some(Ok((0, empty)))) = futures::poll!(reads.next()) else {
                panic!("the empty range must be ready");
            };
            assert_eq!(empty.len(), 0);
            assert_eq!(admitted(), idle + 3);
            assert_eq!(Arc::strong_count(&blob.shared), 4);
            let mut bufs: Vec<(usize, IoBufsMut)> = reads.try_collect().await.unwrap();
            bufs.push((0, empty));
            check_indexed(&data, &ranges, bufs);

            // A first range failing at run time does not delay the others' admission.
            let ranges = [(3 * 4096 - 10, 20), (0, 4096), (8192, 4096)];
            let mut reads = pin!(blob.read_many(&ranges, ReadOptions::DONT_CACHE));
            assert!(futures::poll!(reads.next()).is_pending());
            assert_eq!(admitted(), idle + 3);
            assert_eq!(Arc::strong_count(&blob.shared), 4);
            let results: Vec<_> = reads.collect().await;
            assert!(
                results
                    .iter()
                    .any(|result| matches!(result, Err(Error::BlobInsufficientLength)))
            );

            // start_read_many admits every read before returning its handle, for both cache
            // policies.
            let ranges = [(0, 4096), (5, 0), (100, 5000), (8192, 4096)];
            for options in [ReadOptions::default(), ReadOptions::DONT_CACHE] {
                let handle = blob.start_read_many(&ranges, options).await;
                assert_eq!(admitted(), idle + 3);
                assert_eq!(Arc::strong_count(&blob.shared), 4);
                check(&data, &ranges, handle.await.unwrap());
            }
            settle(&storage.pending).await;
        });
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// An open whose filesystem rejected direct I/O reads every range of later batches buffered.
    /// Eligibility is decided when a batch registers its reads, not when its stream is
    /// constructed.
    #[test]
    fn test_rejected_direct_open_reads_buffered() {
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|_| async {
            let data: Vec<u8> = (0..2 * 4096).map(|i| (i % 251) as u8).collect();
            let ranges = [(0, 4096), (10, 100), (4000, 4192)];
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, data.clone(), WriteOptions::default())
                .await
                .unwrap();

            // A stream constructed before the rejection reads buffered too.
            let early = blob.read_many(&ranges, ReadOptions::DONT_CACHE);
            assert!(blob.shared.direct.set(None).is_ok());
            check_indexed(&data, &ranges, early.try_collect().await.unwrap());

            // Later batches read buffered too.
            let expected = expected(&data, &ranges);
            assert_eq!(
                collect_many(&blob, &ranges, ReadOptions::DONT_CACHE)
                    .await
                    .unwrap(),
                expected
            );
            assert_eq!(
                collect_started(&blob, &ranges, ReadOptions::DONT_CACHE)
                    .await
                    .unwrap(),
                expected
            );
            assert!(blob.shared.direct_file().is_none());
            assert_eq!(fallbacks(&blob), 0);
        });
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// Batches larger than the ring are admitted together and yield every range once.
    #[rstest::rstest]
    fn test_read_many_serves_more_ranges_than_the_ring_holds(#[values(1, 2, 128)] size: u32) {
        let config = iouring::Config::default().with_ring_config(iouring::RingConfig {
            size,
            ..Default::default()
        });
        iouring::Runner::new(config).start(|context| async move {
            let data: Vec<u8> = (0..16 * 2048).map(|i| (i % 251) as u8).collect();
            let (blob, _) = context.open("partition", b"blob").await.unwrap();
            blob.write_at(0, data.clone(), WriteOptions::default())
                .await
                .unwrap();
            let ranges: Vec<(u64, usize)> =
                (0..257).map(|i| (((i % 16) * 2048) as u64, 2048)).collect();
            let expected = expected(&data, &ranges);
            assert_eq!(
                collect_many(&blob, &ranges, ReadOptions::DONT_CACHE)
                    .await
                    .unwrap(),
                expected
            );
            assert_eq!(
                collect_started(&blob, &ranges, ReadOptions::DONT_CACHE)
                    .await
                    .unwrap(),
                expected
            );
            drop(blob);
            context.remove("partition", None).await.unwrap();
        });
    }

    /// Constructing a read_many stream registers nothing: it needs no worker, and the worker
    /// that first polls it registers its reads, even after the constructing worker exited.
    #[test]
    fn test_read_many_registers_on_its_first_polling_worker() {
        let (storage, directory) = create_test_storage();
        let (blob, data) = iouring::Runner::default().start(|_| lifecycle_blob(&storage, b"blob"));

        // Constructed without a worker.
        let reads = blob.read_many(&LIFECYCLE_RANGES, ReadOptions::DONT_CACHE);
        let bufs =
            iouring::Runner::default().start(|_| async { reads.try_collect().await.unwrap() });
        check_indexed(&data, &LIFECYCLE_RANGES, bufs);
        assert_direct(&blob);

        // Constructed on a dedicated worker whose task ends before the stream is polled. The
        // stream borrows the blob, so the blob outlives the test.
        let blob: &'static Blob = Box::leak(Box::new(blob));
        let bufs = iouring::Runner::default().start(|context| async move {
            let reads = context
                .child("constructor")
                .dedicated()
                .spawn(move |_| async move {
                    blob.read_many(&LIFECYCLE_RANGES, ReadOptions::DONT_CACHE)
                })
                .await
                .unwrap();
            reads.try_collect().await.unwrap()
        });
        check_indexed(&data, &LIFECYCLE_RANGES, bufs);
        assert_direct(blob);
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// A batch first observed on a plain thread after registration completes there, including
    /// one whose direct read falls back to a buffered read.
    #[test]
    fn test_plain_thread_observes_direct_reads_and_fallbacks() {
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|context| async move {
            let (blob, data) = lifecycle_blob(&storage, b"blob").await;
            let past = [(data.len() as u64 - 10, 20)];
            for ranges in [&LIFECYCLE_RANGES[..], &past[..]] {
                let handle = blob.start_read_many(ranges, ReadOptions::DONT_CACHE).await;
                let observer = thread::spawn(move || futures::executor::block_on(handle));
                while !observer.is_finished() {
                    context.sleep(Duration::from_millis(1)).await;
                }
                let result = observer.join().unwrap();
                if ranges.len() == past.len() {
                    assert!(matches!(result, Err(Error::BlobInsufficientLength)));
                    assert_eq!(fallbacks(&blob), 1);
                } else {
                    check(&data, ranges, result.unwrap());
                    assert_direct(&blob);
                }
            }
        });
        fs::remove_dir_all(directory).unwrap();
    }

    /// Workers share one direct descriptor per open, which reads the open's inode after its
    /// name is removed. Once the open closes, no descriptor remains on the removed inode and the
    /// directory hold is free.
    #[test]
    fn test_direct_descriptor_is_shared_across_workers() {
        let (storage, directory) = create_test_storage();
        let path = directory.join("partition").join(hex(b"blob"));
        let contender = File::options()
            .write(true)
            .open(directory.join(".hold"))
            .unwrap();
        let removed = path.clone();
        iouring::Runner::default().start(|context| async move {
            let (blob, data) = lifecycle_blob(&storage, b"blob").await;
            storage.remove("partition", Some(b"blob")).await.unwrap();
            let blob = Arc::new(blob);
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    let blob = blob.clone();
                    context
                        .child("reader")
                        .dedicated()
                        .spawn(move |_| async move {
                            collect_many(&*blob, &LIFECYCLE_RANGES, ReadOptions::DONT_CACHE).await
                        })
                })
                .collect();
            let here = collect_many(&*blob, &LIFECYCLE_RANGES, ReadOptions::DONT_CACHE)
                .await
                .unwrap();
            assert_eq!(here, expected(&data, &LIFECYCLE_RANGES));
            for reader in readers {
                assert_eq!(
                    reader.await.unwrap().unwrap(),
                    expected(&data, &LIFECYCLE_RANGES)
                );
            }
            assert_direct(&blob);
            assert_eq!(removed_descriptors(&removed), 2);
        });
        assert_eq!(removed_descriptors(&path), 0);
        contender
            .try_lock()
            .expect("closed open must release the directory hold");
        drop(contender);
        fs::remove_dir_all(directory).unwrap();
    }

    /// A paged cache batch started on one worker and joined from others is abandoned by
    /// dropping its starter and then every joiner while its reads are registered and its
    /// results held back. Later reads of its pages start a new batch.
    #[test]
    fn test_paged_batch_abandoned_by_starter_and_joiners() {
        const PAGE: u16 = 64;
        const PAGES: u64 = 8;
        let (storage, directory) = create_test_storage();
        iouring::Runner::default().start(|context| async move {
            let cache = CacheRef::new(NZU16!(PAGE), NZUsize!(2));
            let (blob, size) = storage.open("partition", b"paged").await.unwrap();
            let (open_gate, gate) = oneshot::channel::<()>();
            let blob = Arc::new(GatedBatchBlob {
                inner: blob,
                gate: Mutex::new(Some(gate)),
                batches: Mutex::new(Vec::new()),
            });
            let physical = PAGE as usize + CHECKSUM_SIZE as usize;
            let data: Vec<u8> = (0..PAGES as usize * PAGE as usize)
                .map(|i| (i % 251) as u8)
                .collect();
            let writer = Writer::new(blob.clone(), size, 2 * physical, cache)
                .await
                .unwrap();
            let (writer, _) = writer.append(&data).await.unwrap();
            let (sealed, sync) = writer.seal().await.unwrap();
            sync.await.unwrap();
            assert!(blob.batches.lock().is_empty());

            // The first four pages are no longer cached, so reading them starts a batch.
            let offsets: Vec<u64> = (0..4).map(|page| page * u64::from(PAGE)).collect();
            let item = NZUsize!(PAGE as usize);
            let read = |name: &'static str| {
                let (polled, polled_rx) = oneshot::channel();
                let (release, released) = oneshot::channel::<()>();
                let (sealed, offsets) = (sealed.clone(), offsets.clone());
                let handle = context.child(name).dedicated().spawn(move |_| async move {
                    let mut buf = vec![0u8; offsets.len() * item.get()];
                    let mut read = pin!(sealed.read_many_into(&mut buf, &offsets, item));
                    assert!(futures::poll!(read.as_mut()).is_pending());
                    polled.send(()).unwrap();
                    let _ = released.await;
                });
                (polled_rx, release, handle)
            };
            let (polled, release_starter, starter) = read("starter");
            polled.await.unwrap();
            let mut releases = Vec::new();
            let mut joiners = Vec::new();
            for _ in 0..2 {
                let (polled, release, joiner) = read("joiner");
                polled.await.unwrap();
                releases.push(release);
                joiners.push(joiner);
            }
            assert_eq!(blob.batches.lock().len(), 1);

            // Drop the starter, then every joiner, before any result is delivered.
            drop(release_starter);
            starter.await.unwrap();
            drop(releases);
            for joiner in joiners {
                joiner.await.unwrap();
            }

            let mut buf = vec![0u8; offsets.len() * item.get()];
            sealed
                .read_many_into(&mut buf, &offsets, item)
                .await
                .unwrap();
            assert_eq!(buf, data[..buf.len()]);
            let batches = blob.batches.lock().clone();
            assert_eq!(batches.len(), 2);
            assert_direct(&blob.inner);
            drop(open_gate);
        });
        fs::remove_dir_all(directory).unwrap();
    }
}
