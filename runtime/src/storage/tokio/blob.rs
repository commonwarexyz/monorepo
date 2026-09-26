use crate::{
    Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions,
    storage::{
        Generation, Pending, Sender, Tracker,
        hold::{Held, Hold},
    },
};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::{
    Widen,
    channel::oneshot,
    sync::{Mutex, MutexGuard},
};
#[cfg(test)]
use std::sync::mpsc;
use std::{
    fs::File,
    io::IoSlice,
    ops::Deref,
    os::{fd::AsRawFd, unix::fs::FileExt},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::task;

// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum so storage writes
// span as few submissions as possible.
const IOVEC_BATCH_SIZE: usize = 1024;

/// Page-cache policy for one positioned I/O request.
enum Cache {
    /// Use the operating system's normal page-cache behavior.
    Enabled,
    /// Best-effort bypass of the page cache while the backend supports it.
    Disabled,
}

impl Cache {
    /// Return whether the next Linux submission should request cache bypass.
    fn is_disabled(&self, supported: &AtomicBool) -> bool {
        cfg!(target_os = "linux")
            && matches!(self, Self::Disabled)
            && supported.load(Ordering::Relaxed)
    }

    /// Return whether an unsupported cache-bypass attempt should be retried with normal caching.
    fn retry_cached(
        &mut self,
        supported: &AtomicBool,
        err: &std::io::Error,
        attempted_dont_cache: bool,
    ) -> bool {
        if err.raw_os_error() != Some(libc::EOPNOTSUPP) || !attempted_dont_cache {
            return false;
        }
        let Self::Disabled = std::mem::replace(self, Self::Enabled) else {
            return false;
        };
        supported.store(false, Ordering::Relaxed);
        true
    }
}

/// A blob's file with the writes no completed sync covers.
///
/// Every operation retains the file, carrying the directory hold into the blocking pool and
/// keeping the open's settlement pending until the operation finishes. Dropping the last
/// reference performs no I/O: it records what the open left unflushed for the next open of the
/// blob to establish before that open returns.
struct Shared {
    file: Held,
    tracker: Tracker,
    durability: Mutex<()>,
    pending: Arc<Pending>,
    key: (String, Vec<u8>),
    /// Settles the open once its last handle dropped and every operation finished.
    promise: OnceLock<Sender>,
    /// Whether the kernel and filesystem may support `RWF_DONTCACHE`.
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted I/O operation.
    dont_cache_supported: AtomicBool,
    #[cfg(test)]
    test: Hooks,
}

/// Hooks for controlling blocking storage operations in lifecycle tests.
#[cfg(test)]
#[derive(Default)]
struct Hooks {
    /// Pause the next cached single-buffer plain write or resize after it enters the blocking
    /// pool.
    before_mutation: Mutex<Option<(oneshot::Sender<()>, mpsc::Receiver<()>)>>,
    /// Pause the next sync after the filesystem operation completes.
    after_sync: Mutex<Option<(oneshot::Sender<()>, mpsc::Receiver<()>)>>,
    /// Pause the next start_sync worker after publishing its completion.
    after_start_sync: Mutex<Option<(oneshot::Sender<()>, mpsc::Receiver<()>)>>,
}

#[cfg(test)]
impl Shared {
    fn wait_before_mutation(&self) {
        let hook = self.test.before_mutation.lock().take();
        if let Some((entered, release)) = hook {
            let _ = entered.send(());
            let _ = release.recv();
        }
    }

    fn wait_after_sync(&self) {
        let hook = self.test.after_sync.lock().take();
        if let Some((entered, release)) = hook {
            let _ = entered.send(());
            let _ = release.recv();
        }
    }
}

impl Deref for Shared {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
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
    /// Serialize a blocking barrier with its terminal accounting.
    fn durability(&self) -> Result<MutexGuard<'_, ()>, Error> {
        let guard = self.durability.lock();
        if let Some(error) = self.tracker.failure() {
            return Err(error);
        }
        Ok(guard)
    }

    fn barrier(&self) -> Result<(), Error> {
        // Data durability is the contract. `sync_data` covers the bytes and metadata required to
        // retrieve them, including file size, while avoiding timestamp-only journal commits.
        // Other platforms retain `sync_all` for their platform-specific guarantees.
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let result = self.file.sync_data();
            } else {
                let result = self.file.sync_all();
            }
        }
        let (partition, name) = &self.key;
        let result =
            result.map_err(|e| Error::BlobSyncFailed(partition.clone(), hex(name), e.into()));
        #[cfg(test)]
        let result = {
            let result = self.pending.take_flush_failure().map_or(result, Err);
            self.wait_after_sync();
            result
        };
        result
    }

    /// Flush this open's mutations, crediting the tracker on success and poisoning it on failure.
    /// A poisoned open rejects every later durability claim.
    fn flush(&self, seen: u64) -> Result<(), Error> {
        let _durability = self.durability()?;
        match self.barrier() {
            Ok(()) => self.tracker.end_sync(seen),
            Err(error) => {
                self.tracker.poison(&error);
                Err(error)
            }
        }
    }

    /// Establish a settled predecessor's debt through this open's file.
    ///
    /// A failure also poisons this open, so its settlement retains the error even when a
    /// successor was admitted during the flush. Removing or recreating the name clears the error.
    fn complete(&self) -> Result<(), Error> {
        #[cfg(test)]
        self.pending.before_complete();
        let result = self.barrier();
        if let Err(error) = &result {
            self.tracker.poison(error);
        }
        #[cfg(test)]
        if result.is_ok() {
            self.pending.completed();
        }
        result
    }
}

pub struct Blob {
    /// File state retained by issued operations.
    shared: Arc<Shared>,
    /// The logical open's namespace identity.
    generation: Arc<Generation>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
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
    /// Establish what the settled predecessor left unflushed, then read the captured file's
    /// length. A failed flush is retained until the name is removed or recreated.
    pub(super) async fn complete(&self) -> Result<u64, Error> {
        let shared = self.shared.clone();
        let identity = Arc::downgrade(&self.generation);
        let offset = self.data_offset;
        task::spawn_blocking(move || {
            #[cfg(test)]
            {
                let hook = shared.pending.test.before_metadata.lock().take();
                if let Some((entered, release)) = hook {
                    let _ = entered.send(());
                    let _ = release.recv();
                }
            }
            if shared.pending.debt(&shared.key, &identity)? {
                let result = shared.complete();
                shared.pending.clear(&shared.key, &identity, &result);
                result?;
            }
            shared
                .metadata()
                .map(|metadata| metadata.len() - offset)
                .map_err(|_| Error::ReadFailed)
        })
        .await
        .map_err(|_| Error::ReadFailed)?
    }

    pub(crate) fn new(
        file: File,
        pool: BufferPool,
        data_offset: u64,
        hold: Arc<Hold>,
        generation: Arc<Generation>,
    ) -> Self {
        let shared = Arc::new(Shared {
            file: Held::new(file, hold),
            tracker: Tracker::default(),
            durability: Mutex::new(()),
            pending: generation.pending.clone(),
            key: generation.key.clone(),
            promise: OnceLock::new(),
            dont_cache_supported: AtomicBool::new(true),
            #[cfg(test)]
            test: Hooks::default(),
        });
        Self {
            shared,
            generation,
            pool,
            data_offset,
        }
    }

    /// Number of syncs this open skipped because it had nothing to persist.
    #[cfg(test)]
    pub(super) fn skipped_syncs(&self) -> u64 {
        self.shared.tracker.skipped()
    }

    #[cfg(target_os = "linux")]
    fn read_exact_at(
        mut cache: Cache,
        file: &Shared,
        mut buf: &mut [u8],
        mut offset: u64,
    ) -> Result<(), Error> {
        if !cache.is_disabled(&file.dont_cache_supported) {
            file.read_exact_at(buf, offset)?;
            return Ok(());
        }

        while !buf.is_empty() {
            let iovec = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            // SAFETY: `file` owns a valid fd for this call. `iovec` describes the exclusive
            // writable slice borrowed for the duration of the syscall.
            let ret = unsafe {
                libc::preadv2(
                    file.as_raw_fd(),
                    &iovec,
                    1,
                    offset.try_into().map_err(|_| Error::OffsetOverflow)?,
                    libc::RWF_DONTCACHE,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if cache.retry_cached(&file.dont_cache_supported, &err, true) {
                    file.read_exact_at(buf, offset)?;
                    return Ok(());
                }
                return Err(err.into());
            }

            let bytes_read = ret as usize;
            if bytes_read == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            let (_, unread) = buf.split_at_mut(bytes_read);
            buf = unread;
            offset = offset
                .checked_add(bytes_read as u64)
                .ok_or(Error::OffsetOverflow)?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn read_exact_at(_: Cache, file: &Shared, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        file.read_exact_at(buf, offset)?;
        Ok(())
    }

    fn write_single_at(file: &File, offset: u64, buf: &[u8]) -> Result<(), Error> {
        file.write_all_at(buf, offset)?;
        Ok(())
    }

    /// Write `bufs` at `offset`, batching up to [IOVEC_BATCH_SIZE] iovecs per submission.
    ///
    /// `flags` apply to every submission, so callers must only pass durability flags when the
    /// write fits one submission. Hinted submissions carry `RWF_DONTCACHE` on Linux while the
    /// backend may support it. An EOPNOTSUPP disables the hint and retries normally.
    fn write_vectored_at(
        mut cache: Cache,
        file: &Shared,
        mut offset: u64,
        bufs: &mut IoBufs,
        flags: Option<libc::c_int>,
    ) -> Result<(), Error> {
        assert!(
            flags.is_none() || bufs.chunk_count() <= IOVEC_BATCH_SIZE,
            "durability flags on a multi-submission write serialize its batches"
        );

        while bufs.has_remaining() {
            // Scratch sized to the write, so small vectored writes never initialize a
            // full IOVEC_BATCH_SIZE array.
            let mut io_slices = vec![IoSlice::new(&[]); bufs.chunk_count().min(IOVEC_BATCH_SIZE)];
            let io_slices_len = bufs.chunks_vectored(&mut io_slices);
            assert!(
                io_slices_len > 0,
                "chunks_vectored should produce at least one slice when bufs has remaining"
            );

            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    let attempted_dont_cache = cache.is_disabled(&file.dont_cache_supported);
                    // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                    // `io_slices` points to valid readable buffers held alive for this syscall.
                    let ret = unsafe {
                        libc::pwritev2(
                            file.as_raw_fd(),
                            io_slices.as_ptr().cast::<libc::iovec>(),
                            io_slices_len as i32,
                            offset.try_into().map_err(|_| Error::OffsetOverflow)?,
                            flags.unwrap_or(0)
                                | if attempted_dont_cache { libc::RWF_DONTCACHE } else { 0 },
                        )
                    };
                } else {
                    let _ = &cache;
                    let attempted_dont_cache = false;
                    assert!(flags.is_none(), "flags are only supported on Linux");

                    // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                    // `io_slices` points to valid readable buffers held alive for this syscall.
                    let ret = unsafe {
                        libc::pwritev(
                            file.as_raw_fd(),
                            io_slices.as_ptr().cast::<libc::iovec>(),
                            io_slices_len as i32,
                            offset.try_into().map_err(|_| Error::OffsetOverflow)?,
                        )
                    };
                }
            }

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }

                // Retry normally and stop requesting an unsupported cache-bypass hint.
                if cache.retry_cached(&file.dont_cache_supported, &err, attempted_dont_cache) {
                    continue;
                }
                return Err(err.into());
            }

            let bytes_written = ret as usize;
            if bytes_written == 0 {
                return Err(Error::WriteFailed);
            }
            bufs.advance(bytes_written);
            offset = offset
                .checked_add(bytes_written as u64)
                .ok_or(Error::OffsetOverflow)?;
        }

        Ok(())
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
        let mut bufs = bufs.into();
        // SAFETY: `len` bytes are filled via read_exact below.
        unsafe { bufs.set_len(len) };
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        if len == 0 {
            return Ok(bufs);
        }
        let file = self.shared.clone();
        let pool = self.pool.clone();
        let cache = if options.contains(ReadOptions::DONT_CACHE) {
            Cache::Disabled
        } else {
            Cache::Enabled
        };
        let read = move || {
            if let Some(buf) = bufs.as_single_mut() {
                // Read directly into the single buffer (zero-copy).
                Self::read_exact_at(cache, &file, buf.as_mut(), offset)?;
            } else {
                // Read into a temporary contiguous buffer and copy back to preserve structure.
                // SAFETY: `len` bytes are filled via read_exact_at below.
                let mut temp = unsafe { pool.alloc_len(len) };
                Self::read_exact_at(cache, &file, temp.as_mut(), offset)?;
                bufs.copy_from_slice(temp.as_ref());
            }
            Ok(bufs)
        };

        // A dedicated task that opted in owns its thread, so the read runs on it directly and
        // skips the blocking-pool handoff (a pool wake plus a park of this thread per read).
        if crate::utils::thread::INLINE_IO.with(|inline| inline.get()) {
            return read();
        }
        task::spawn_blocking(read)
            .await
            .map_err(|_| Error::ReadFailed)?
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

        // Validate the signed file extent before recording debt or entering the blocking pool.
        // Each submission after partial progress then has a representable offset.
        offset
            .checked_add(Widen::widen(bufs.len()))
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Derive per-write policy from the requested options. The blocking worker checks
        // backend support before each hinted submission.
        let file = self.shared.clone();
        let sync = options.contains(WriteOptions::SYNC);
        if sync && let Some(error) = self.shared.tracker.failure() {
            return Err(error);
        }
        let cache = if options.contains(WriteOptions::DONT_CACHE) {
            Cache::Disabled
        } else {
            Cache::Enabled
        };

        // Plain syscall paths own mutation debt before submission, including worker unwind.
        // On Linux, a SYNC write fitting one submission fuses the barrier into that write.
        // Other SYNC writes finish with a full-file flush.
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let flags = (sync && bufs.chunk_count() <= IOVEC_BATCH_SIZE)
                    .then_some(libc::RWF_DSYNC);
            } else {
                let flags = None;
            }
        }
        let fused = flags.is_some();
        if !fused {
            self.shared.tracker.write();
        }
        task::spawn_blocking(move || {
            // Preserve the single-buffer fast path when no option requires per-write flags.
            let mut bufs = if !sync && !cache.is_disabled(&file.dont_cache_supported) {
                match bufs.try_into_single() {
                    Ok(buf) => {
                        #[cfg(test)]
                        file.wait_before_mutation();
                        Self::write_single_at(&file, offset, buf.as_ref())?;
                        file.tracker.complete();
                        return Ok(());
                    }
                    Err(bufs) => bufs,
                }
            } else {
                bufs
            };

            let _durability = if fused {
                Some(file.durability()?)
            } else {
                None
            };
            let result = Self::write_vectored_at(cache, &file, offset, &mut bufs, flags);
            #[cfg(test)]
            if fused {
                file.wait_after_sync();
            }
            if fused && let Err(error) = &result {
                // A failed fused write may have consumed the kernel's writeback error.
                file.tracker.write();
                let (partition, name) = &file.key;
                let error = match error {
                    Error::Io(error) => {
                        Error::BlobSyncFailed(partition.clone(), hex(name), error.clone())
                    }
                    error => error.clone(),
                };
                file.tracker.poison(&error);
            }
            result?;
            if !fused {
                file.tracker.complete();
            }
            if sync && !fused {
                let seen = file.tracker.begin_sync();
                file.flush(seen)?;
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::WriteFailed)?
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.shared.clone();
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        self.shared.tracker.write();
        task::spawn_blocking(move || {
            #[cfg(test)]
            file.wait_before_mutation();
            file.set_len(len)?;
            file.tracker.complete();
            Ok(())
        })
        .await
        .map_err(|e| e.into())
        .and_then(|r: std::io::Result<()>| r)
        .map_err(|e| {
            let (partition, name) = &self.shared.key;
            Error::BlobResizeFailed(partition.clone(), hex(name), e.into())
        })?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if let Some(error) = self.shared.tracker.failure() {
            return Err(error);
        }
        if !self.shared.tracker.is_dirty() {
            #[cfg(test)]
            self.shared.tracker.skip_sync();
            return Ok(());
        }
        let file = self.shared.clone();
        let seen = self.shared.tracker.begin_sync();
        task::spawn_blocking(move || file.flush(seen))
            .await
            .map_err(|e| {
                let err: std::io::Error = e.into();
                let (partition, name) = &self.shared.key;
                Error::BlobSyncFailed(partition.clone(), hex(name), err.into())
            })?
    }

    async fn start_sync(&self) -> Handle<()> {
        if let Some(error) = self.shared.tracker.failure() {
            return Handle::ready(Err(error));
        }
        if !self.shared.tracker.is_dirty() {
            #[cfg(test)]
            self.shared.tracker.skip_sync();
            return Handle::ready(Ok(()));
        }
        let (tx, rx) = oneshot::channel();
        let file = self.shared.clone();
        let seen = self.shared.tracker.begin_sync();
        #[cfg(test)]
        let after_start_sync = file.test.after_start_sync.lock().take();
        task::spawn_blocking(move || {
            // Release this operation's blob ownership before publishing its completion.
            let result = file.flush(seen);
            drop(file);
            let _ = tx.send(result);
            #[cfg(test)]
            if let Some((entered, release)) = after_start_sync {
                let _ = entered.send(());
                let _ = release.recv();
            }
        });
        Handle::from_receiver(rx)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, BlobVersion, BufferPoolConfig, Storage as _,
        storage::{
            Layout,
            tokio::{Config, Storage},
        },
        telemetry::metrics::Registry,
    };
    use futures::FutureExt as _;
    use std::{env, ops::RangeInclusive, path::PathBuf, process, sync::mpsc};

    fn storage_for_reopen_test(label: &str, layouts: RangeInclusive<Layout>) -> (Storage, PathBuf) {
        let directory = env::temp_dir().join(format!("storage_tokio_{label}_{}", process::id()));
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        (
            Storage::new(Config::new(directory.clone(), layouts), pool),
            directory,
        )
    }

    #[tokio::test]
    async fn test_overlapping_durability_failure() {
        #[derive(Clone, Copy, Debug)]
        enum Operation {
            Sync,
            StartSync,
            Write(usize),
        }

        async fn run(blob: &Blob, operation: Operation) -> Result<(), Error> {
            match operation {
                Operation::Sync => blob.sync().await,
                Operation::StartSync => blob.start_sync().await.await,
                Operation::Write(chunks) => {
                    let bufs = IoBufs::from(
                        (0..chunks)
                            .map(|_| crate::IoBuf::from(b"x"))
                            .collect::<Vec<_>>(),
                    );
                    blob.write_at(6, bufs, WriteOptions::SYNC).await
                }
            }
        }

        // Exercise both result orders and caller cancellation for every durability path. On
        // Linux, `Write(1)` fuses the barrier into its single submission. The larger write spans
        // more than one submission, so it writes and then runs a separate barrier.
        for operation in [
            Operation::Sync,
            Operation::StartSync,
            Operation::Write(1),
            Operation::Write(IOVEC_BATCH_SIZE + 1),
        ] {
            for failure_first in [false, true] {
                for cancel in [false, true] {
                    // Open a blob with unsynced data so `sync` and `start_sync` issue a barrier.
                    let (storage, directory) = storage_for_reopen_test(
                        &format!("overlapping_failure_{operation:?}_{failure_first}_{cancel}"),
                        Layout::ALL,
                    );
                    let (blob, _) = storage.open("partition", b"blob").await.unwrap();
                    blob.write_at(0, b"prefix", WriteOptions::default())
                        .await
                        .unwrap();

                    // With `failure_first`, the first barrier is a `Sync` that takes the injected
                    // flush failure. Otherwise it runs `operation` and succeeds. Pause it before
                    // its result reaches the tracker.
                    let (entered, entering) = oneshot::channel();
                    let (release, gate) = mpsc::channel();
                    *blob.shared.test.after_sync.lock() = Some((entered, gate));
                    if failure_first {
                        *storage.pending.test.fail_flush.lock() = Some(Error::Closed);
                    }
                    let mut first = Box::pin(run(
                        &blob,
                        if failure_first {
                            Operation::Sync
                        } else {
                            operation
                        },
                    ));
                    assert!((&mut first).now_or_never().is_none());
                    entering.await.unwrap();
                    assert!(
                        blob.shared.durability.try_lock().is_none(),
                        "barrier released admission before accounting"
                    );

                    // Canceling drops only the first caller's future. The blocking barrier keeps
                    // running and holds `durability` until its accounting finishes.
                    let first = if cancel {
                        drop(first);
                        None
                    } else {
                        Some(first)
                    };

                    // Without `failure_first`, inject the failure while the first barrier is
                    // paused, so only the competing `Sync` takes it.
                    if !failure_first {
                        *storage.pending.test.fail_flush.lock() = Some(Error::Closed);
                    }

                    // The competing barrier cannot finish while the paused barrier holds
                    // `durability`, in either result order.
                    let mut second = Box::pin(run(
                        &blob,
                        if failure_first {
                            operation
                        } else {
                            Operation::Sync
                        },
                    ));
                    assert!((&mut second).now_or_never().is_none());
                    let early = (&mut second).now_or_never();
                    release.send(()).unwrap();
                    assert!(
                        early.is_none(),
                        "barrier completed before predecessor accounting"
                    );

                    // Once accounting completes, every later durability claim sees the failure.
                    // When the first barrier fails, neither barrier credits a sync, so the open
                    // stays dirty.
                    let first = futures::future::OptionFuture::from(first).await;
                    let second = second.await;
                    if failure_first {
                        assert!(matches!(first, None | Some(Err(Error::Closed))));
                        assert!(matches!(second, Err(Error::Closed)));
                        assert!(blob.shared.tracker.is_dirty());
                    } else {
                        if let Some(first) = first {
                            first.unwrap();
                        }
                        assert!(matches!(second, Err(Error::Closed)));
                    }
                    assert!(matches!(blob.shared.tracker.failure(), Some(Error::Closed)));

                    // Settlement carries the failure into a later open of the same name.
                    drop(blob);
                    assert!(matches!(
                        storage.open("partition", b"blob").await,
                        Err(Error::Closed)
                    ));
                    storage.remove("partition", None).await.unwrap();
                    drop(storage);
                    std::fs::remove_dir_all(directory).unwrap();
                }
            }
        }
    }

    /// A reopen of the same incarnation waits for the canceled write or resize, with retirement
    /// on either side of its admission. Replacement leaves an earlier reopen bound to the
    /// removed file. Both paths report the captured file's settled contents. The wait itself is
    /// pinned deterministically by `test_cancelled_completion_failure_is_retained`.
    async fn check_reopen_after_gated_mutation(
        replace: bool,
        shrink: bool,
        retire_before_admit: bool,
    ) {
        // Use V0 to cover opens whose header prefix includes payload bytes.
        let (storage, directory) = storage_for_reopen_test(
            &format!("gated_reopen_{replace}_{shrink}_{retire_before_admit}"),
            Layout::V0..=Layout::V0,
        );
        let mut reopening = None;
        let mut paused = None;
        if replace {
            // The removed incarnation's reopen stays in flight while the name is recreated
            // underneath it. It pauses before its debt read, after its namespace dispatch
            // captured the old file, so it reads no debt and publishes nothing into the
            // recreated name.
            let (old, _) = storage.open("partition", b"blob").await.unwrap();
            old.write_at(0, b"old", WriteOptions::default())
                .await
                .unwrap();
            drop(old);
            let (entered, entering) = oneshot::channel();
            let (release, gate) = mpsc::channel();
            *storage.pending.test.before_metadata.lock() = Some((entered, gate));
            let mut open = Box::pin(storage.open("partition", b"blob"));
            commonware_macros::select! {
                entered = entering => entered.unwrap(),
                _ = &mut open => panic!("reopen completed before its debt read"),
            }
            reopening = Some(open);
            paused = Some(release);
            storage.remove("partition", Some(b"blob")).await.unwrap();
        }

        // Hold a mutation in the blocking pool after its caller and public blob are dropped.
        // The outstanding request must retain the file and its eventual durability debt.
        // `wait` fires once the request finishes and the dropped open settles.
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        if shrink {
            blob.write_at(0, b"orphaned", WriteOptions::SYNC)
                .await
                .unwrap();
        }
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        *blob.shared.test.before_mutation.lock() = Some((entered, gate));
        let mut mutation = Box::pin(async {
            if shrink {
                blob.resize(0).await
            } else {
                blob.write_at(0, b"orphaned", WriteOptions::default()).await
            }
        });
        assert!((&mut mutation).now_or_never().is_none());
        entering.await.unwrap();
        drop(mutation);
        drop(blob);
        let wait = storage
            .pending
            .entries
            .lock()
            .get(&("partition".into(), b"blob".to_vec()))
            .unwrap()
            .settle
            .clone();

        // Select whether retirement happens before or after the successor claims the name.
        let admission = if retire_before_admit {
            let (entered, entering) = oneshot::channel();
            let (release, gate) = mpsc::channel();
            *storage.pending.test.before_admit.lock() = Some((entered, gate));
            Some((entering, release))
        } else {
            None
        };
        let mut reopening =
            reopening.unwrap_or_else(|| Box::pin(storage.open("partition", b"blob")));
        let early = (&mut reopening).now_or_never();
        if let Some((entering, release_admit)) = admission {
            // The reopen captures the file and its pre-mutation length, then pauses before
            // admission while the mutation finishes and its open settles. It is admitted with
            // no settlement outstanding, so only the recorded debt defers its length read.
            entering.await.unwrap();
            release.send(()).unwrap();
            Pending::wait(wait.clone()).await.unwrap();
            assert_eq!(storage.pending.outstanding(), 0);
            release_admit.send(()).unwrap();
        } else {
            // Namespace dispatch completes before this barrier. Without replacement, the
            // mutation still owns the captured file, so its size is not yet authoritative.
            storage.scan("partition").await.unwrap();
            release.send(()).unwrap();
        }

        // With replacement, release the earlier reopen, which captured the old incarnation.
        // Every returned length and byte sequence must describe its captured file after
        // mutations finish.
        drop(paused);
        let (reopened, size) = match early {
            Some(result) => result,
            None => reopening.as_mut().await,
        }
        .unwrap();
        drop(reopening);
        Pending::wait(wait).await.unwrap();
        if replace {
            assert_eq!(size, 3);
            assert_eq!(
                reopened
                    .read_at(0, 3, ReadOptions::default())
                    .await
                    .unwrap()
                    .coalesce()
                    .as_ref(),
                b"old"
            );
        } else {
            let expected = if shrink { 0 } else { 8 };
            let bytes = reopened
                .read_at(0, expected, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(
                bytes.as_ref(),
                if shrink {
                    b"".as_slice()
                } else {
                    b"orphaned".as_slice()
                }
            );
            assert_eq!(
                size, expected as u64,
                "returned length must describe the settled captured file"
            );
        }
        drop(reopened);
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn test_reopen_replacement_after_gated_mutation() {
        for shrink in [false, true] {
            check_reopen_after_gated_mutation(true, shrink, false).await;
        }
    }

    #[tokio::test]
    async fn test_reopen_after_gated_mutation() {
        for shrink in [false, true] {
            check_reopen_after_gated_mutation(false, shrink, false).await;
        }
    }

    #[tokio::test]
    async fn test_reopen_after_retirement_before_admission() {
        for shrink in [false, true] {
            check_reopen_after_gated_mutation(false, shrink, true).await;
        }
    }

    #[tokio::test]
    async fn test_reopen_canceled_during_final_metadata() {
        // Leave a dirty predecessor and pause its successor before reading the debt and
        // the captured file's length.
        let (storage, directory) = storage_for_reopen_test("canceled_metadata", Layout::ALL);
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"old", WriteOptions::default())
            .await
            .unwrap();
        drop(blob);
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        *storage.pending.test.before_metadata.lock() = Some((entered, gate));
        let mut opening = Box::pin(storage.open("partition", b"blob"));
        assert!((&mut opening).now_or_never().is_none());
        storage.scan("partition").await.unwrap();
        commonware_macros::select! {
            entered = entering => entered.unwrap(),
            _ = &mut opening => panic!("open must wait for metadata"),
        }
        assert_eq!(storage.pending.completions(), 0);

        // Canceling the awaiter must leave completion owned by the blocking operation.
        drop(opening);

        // Admit the retry before releasing the stale completion.
        // Only the retry may flush the debt.
        let mut retry = Box::pin(storage.open("partition", b"blob"));
        assert!((&mut retry).now_or_never().is_none());
        storage.scan("partition").await.unwrap();
        release.send(()).unwrap();
        let (blob, size) = retry.await.unwrap();
        assert_eq!(size, 3);
        assert_eq!(storage.pending.completions(), 1);
        assert!(!storage.pending.owes("partition", b"blob"));
        assert_eq!(
            blob.read_at(0, 3, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"old"
        );
        drop(blob);
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// An open canceled while its predecessor is still settling neither replaces that
    /// settlement nor keeps the name, and the predecessor's debt survives for the next open.
    #[tokio::test]
    async fn test_reopen_canceled_during_wait_keeps_debt() {
        let (storage, directory) = storage_for_reopen_test("canceled_wait", Layout::ALL);
        let key = ("partition".to_string(), b"blob".to_vec());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();

        // Gate a plain write inside the blocking pool so the open settles only on release.
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        *blob.shared.test.before_mutation.lock() = Some((entered, gate));
        let mut mutation = Box::pin(blob.write_at(0, b"orphaned", WriteOptions::default()));
        assert!((&mut mutation).now_or_never().is_none());
        entering.await.unwrap();
        drop(mutation);
        drop(blob);
        let wait = storage
            .pending
            .entries
            .lock()
            .get(&key)
            .unwrap()
            .settle
            .clone();
        assert!(wait.is_some());
        assert_eq!(storage.pending.outstanding(), 1);

        // The reopen is admitted behind the settling predecessor and waits for it. The scan
        // proves its namespace dispatch, and with it the admission, completed.
        let mut opening = Box::pin(storage.open("partition", b"blob"));
        assert!((&mut opening).now_or_never().is_none());
        storage.scan("partition").await.unwrap();
        assert!((&mut opening).now_or_never().is_none());
        {
            let entries = storage.pending.entries.lock();
            let entry = entries.get(&key).unwrap();
            assert_eq!(entry.identity.strong_count(), 1);
            assert!(entry.settle.is_some());
            assert!(!entry.dirty);
        }

        // Canceling the waiting reopen releases the name without settling anything, so the
        // entry keeps the predecessor's settlement.
        drop(opening);
        {
            let entries = storage.pending.entries.lock();
            let entry = entries.get(&key).unwrap();
            assert_eq!(entry.identity.strong_count(), 0);
            assert!(entry.settle.is_some());
            assert!(!entry.dirty);
            assert!(entry.failed.is_none());
        }
        assert_eq!(storage.pending.outstanding(), 1);
        assert_eq!(storage.pending.completions(), 0);

        // The write lands and its settlement records the debt on the retained entry.
        release.send(()).unwrap();
        Pending::wait(wait).await.unwrap();
        assert_eq!(storage.pending.outstanding(), 0);
        assert!(storage.pending.owes("partition", b"blob"));

        // The next open establishes the debt before returning.
        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 8);
        assert_eq!(storage.pending.completions(), 1);
        assert!(!storage.pending.owes("partition", b"blob"));
        assert_eq!(
            blob.read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"orphaned"
        );
        drop(blob);
        assert!(storage.pending.entries.lock().is_empty());
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn test_header_read_after_payload_shrink() {
        // V0 header reads overlap the payload, so a shrink can shorten the captured prefix
        // without invalidating the header itself.
        let (storage, directory) =
            storage_for_reopen_test("header_shrink", Layout::V0..=Layout::V0);
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let mut file = File::open(directory.join("partition").join(hex(b"blob"))).unwrap();

        // Capture the raw length before shrinking, then resolve the header with that stale
        // length. The original sizes put the stale length below and above the header read
        // limit, and the retained sizes leave an empty or partial payload.
        for original in [8, 5000] {
            for retained in [0, 3] {
                blob.resize(original).await.unwrap();
                let raw_len = file.metadata().unwrap().len();
                blob.resize(retained).await.unwrap();
                let (size, _, offset) = crate::storage::resolve_header(
                    &mut file,
                    raw_len,
                    &Layout::ALL,
                    &(BlobVersion::new(0)..=BlobVersion::new(0)),
                    "partition",
                    b"blob",
                )
                .unwrap()
                .unwrap();

                // The shrunken file is shorter than the requested prefix, so the size comes from
                // the bytes read rather than the stale length.
                assert_eq!(offset, Layout::V0.data_offset());
                assert_eq!(size, retained);
            }
        }
        drop(file);
        drop(blob);
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn test_oversized_missing_header_is_not_recreated() {
        let (storage, directory) = storage_for_reopen_test("oversized_header", Layout::ALL);
        let parent = directory.join("partition");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join(hex(b"blob"));
        let raw = vec![0; 4097];
        std::fs::write(&path, &raw).unwrap();
        assert!(matches!(
            storage.open("partition", b"blob").await,
            Err(Error::BlobCorrupt(_, _, _))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_fused_write_error_is_recorded_before_buffer_drop() {
        struct WriteErrorObserver {
            shared: std::sync::Weak<Shared>,
            accounted: Arc<AtomicBool>,
        }

        impl AsRef<[u8]> for WriteErrorObserver {
            fn as_ref(&self) -> &[u8] {
                b"x"
            }
        }

        impl Drop for WriteErrorObserver {
            fn drop(&mut self) {
                self.accounted.store(
                    self.shared.upgrade().unwrap().tracker.is_dirty(),
                    Ordering::Release,
                );
            }
        }

        let (storage, directory) = storage_for_reopen_test("write_error_order", Layout::ALL);
        let path = directory.join("readonly");
        std::fs::write(&path, b"").unwrap();
        let blob = Blob::new(
            File::options().read(true).open(&path).unwrap(),
            storage.pool.clone(),
            0,
            storage.hold.clone(),
            storage
                .pending
                .admit("partition", b"readonly", false)
                .unwrap()
                .0,
        );

        let accounted = Arc::new(AtomicBool::new(false));
        let bufs = bytes::Bytes::from_owner(WriteErrorObserver {
            shared: Arc::downgrade(&blob.shared),
            accounted: accounted.clone(),
        });

        // The read-only descriptor makes the fused syscall fail after submission.
        // Its terminal accounting must precede retirement of the supplied buffer.
        let result = blob.write_at(0, bufs, WriteOptions::SYNC).await;
        let poisoned = blob.shared.tracker.failure().is_some();
        drop(blob);
        let retained = storage.pending.admit("partition", b"readonly", true);
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            matches!(result, Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EBADF))
        );
        assert!(accounted.load(Ordering::Acquire));
        assert!(poisoned, "a failed fused write must poison the open");
        assert!(
            matches!(retained, Err(Error::BlobSyncFailed(partition, name, error))
            if partition == "partition" && name == hex(b"readonly")
                && error.raw_os_error() == Some(libc::EBADF))
        );
    }

    #[tokio::test]
    async fn test_invalid_write_range_leaves_open_clean() {
        // Validate physical extents with both header layouts before any mutation is recorded.
        for (case, layouts) in [Layout::V0..=Layout::V0, Layout::ALL]
            .into_iter()
            .enumerate()
        {
            let (storage, directory) =
                storage_for_reopen_test(&format!("invalid_write_range_{case}"), layouts);
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            let header = blob.data_offset;
            let last = i64::MAX as u64;
            let completed = storage.pending.completions();

            for options in [WriteOptions::default(), WriteOptions::SYNC] {
                // Empty writes skip I/O but still reject overflow when adding the header offset.
                blob.write_at(u64::MAX - header, IoBufs::default(), options)
                    .await
                    .unwrap();
                assert!(matches!(
                    blob.write_at(u64::MAX, IoBufs::default(), options).await,
                    Err(Error::OffsetOverflow)
                ));

                // Each nonempty write exceeds the signed file extent by one byte. Chunk counts
                // cover one buffer, several buffers in one iovec batch, and more than one batch.
                for chunks in [1, 2, IOVEC_BATCH_SIZE + 1] {
                    let physical = last - (Widen::widen(chunks) - 1);
                    let bufs = (0..chunks)
                        .map(|_| crate::IoBuf::from(b"x"))
                        .collect::<IoBufs>();
                    assert!(
                        matches!(
                            blob.write_at(physical - header, bufs, options).await,
                            Err(Error::OffsetOverflow)
                        ),
                        "chunks={chunks} options={options:?}"
                    );
                    assert!(!blob.shared.tracker.is_dirty());
                    assert!(blob.shared.tracker.failure().is_none());
                }
            }

            // Rejected extents must leave neither flush debt nor a failure for the next open.
            drop(blob);
            let (blob, size) = storage.open("partition", b"blob").await.unwrap();
            assert_eq!(size, 0);
            assert_eq!(storage.pending.completions(), completed);
            blob.write_at(0, b"ok", WriteOptions::SYNC).await.unwrap();
            drop(blob);
            storage.remove("partition", None).await.unwrap();
            drop(storage);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    /// Pauses before panicking as the write releases its first buffer.
    struct PanickingOwner {
        entered: Option<oneshot::Sender<()>>,
        release: mpsc::Receiver<()>,
    }

    impl AsRef<[u8]> for PanickingOwner {
        fn as_ref(&self) -> &[u8] {
            b"x"
        }
    }

    impl Drop for PanickingOwner {
        fn drop(&mut self) {
            let _ = self.entered.take().unwrap().send(());
            let _ = self.release.recv();
            panic!("buffer owner dropped");
        }
    }

    #[tokio::test]
    async fn test_reopen_syncs_fallback_write_after_owner_panic() {
        // Exceed the Linux fused-write batch so payload destruction can interrupt the
        // fallback path after bytes reach the file but before its full-file flush.
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_owner_panic_{}", process::id()));
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL), pool);
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let (entered, entering) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let mut chunks = vec![crate::IoBuf::from(bytes::Bytes::from_owner(
            PanickingOwner {
                entered: Some(entered),
                release: released,
            },
        ))];
        for _ in 0..IOVEC_BATCH_SIZE {
            chunks.push(crate::IoBuf::from(vec![b'x']));
        }
        let blob = Arc::new(blob);
        let writing_blob = Arc::clone(&blob);
        let writing =
            ::tokio::spawn(
                async move { writing_blob.write_at(0, chunks, WriteOptions::SYNC).await },
            );

        // Observe written bytes before releasing the destructor to unwind the worker.
        entering.await.unwrap();
        let bytes = blob.read_at(0, 1, ReadOptions::default()).await;
        release.send(()).unwrap();
        let result = writing.await.unwrap();
        assert_eq!(bytes.unwrap().coalesce().as_ref(), b"x");
        assert!(matches!(result, Err(Error::WriteFailed)));

        // The failed mutation leaves debt. A reopen must wait for its flush before returning
        // the bytes that survived the worker panic.
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        *storage.pending.test.before_complete.lock() = Some((entered, gate));
        drop(blob);
        let mut reopen = Box::pin(storage.open("partition", b"blob"));
        commonware_macros::select! {
            entered = entering => entered.unwrap(),
            _ = &mut reopen => panic!("reopen returned before the failed write was made durable"),
        }
        assert!(
            (&mut reopen).now_or_never().is_none(),
            "reopen returned before the failed write was made durable"
        );
        release.send(()).unwrap();
        let (blob, size) = reopen.await.unwrap();
        assert!(size >= 1);
        assert_eq!(
            blob.read_at(0, 1, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"x"
        );
        drop(blob);
        let flushes = storage.pending.completions();
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
        assert_eq!(flushes, 1);
    }

    #[tokio::test]
    async fn test_reopen_after_start_sync_completion() {
        let (storage, storage_directory) = storage_for_reopen_test("sync_completion", Layout::ALL);
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let (entered, entering) = oneshot::channel();
        let (release, released) = mpsc::channel();
        *blob.shared.test.after_start_sync.lock() = Some((entered, released));

        // Keep the completed sync worker alive while the caller writes and closes the blob.
        blob.write_at(0, b"before", WriteOptions::default())
            .await
            .unwrap();
        let observed = async {
            blob.start_sync().await.await?;
            entering.await.expect("sync worker did not pause");
            blob.write_at(0, b"after sync", WriteOptions::default())
                .await?;
            drop(blob);
            let (reopened, len) = storage.open("partition", b"blob").await?;
            let bytes = reopened
                .read_at(0, len as usize, ReadOptions::default())
                .await?;
            Ok::<_, Error>((len, bytes.coalesce(), storage.pending.completions()))
        }
        .await;

        // Release the worker before checking results so a failure cannot strand it.
        let _ = release.send(());
        let (len, bytes, syncs) = observed.unwrap();
        let _ = std::fs::remove_dir_all(storage_directory);
        assert_eq!(len, 10);
        assert_eq!(bytes.as_ref(), b"after sync");
        assert_eq!(syncs, 1, "reopen did not flush the later write");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cache_bypass_is_ignored_off_linux() {
        let supported = AtomicBool::new(true);
        let cache = Cache::Disabled;
        assert!(!cache.is_disabled(&supported));
    }

    #[test]
    fn test_cache_bypass_retry_decision() {
        let supported = AtomicBool::new(true);
        let mut cache = Cache::Disabled;
        let mut sibling = Cache::Disabled;
        let unsupported = std::io::Error::from_raw_os_error(libc::EOPNOTSUPP);
        let invalid = std::io::Error::from_raw_os_error(libc::EINVAL);

        assert!(!cache.retry_cached(&supported, &invalid, true));
        assert!(supported.load(Ordering::Relaxed));
        assert!(!cache.retry_cached(&supported, &unsupported, false));
        assert!(supported.load(Ordering::Relaxed));
        assert!(cache.retry_cached(&supported, &unsupported, true));
        assert!(!supported.load(Ordering::Relaxed));
        assert!(!sibling.is_disabled(&supported));
        assert!(sibling.retry_cached(&supported, &unsupported, true));
        assert!(!cache.retry_cached(&supported, &unsupported, true));
    }
}
