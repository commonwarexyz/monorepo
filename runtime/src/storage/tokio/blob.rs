use crate::{
    Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions,
    storage::{
        Generation, Pending, Sender, Tracker, defer_sync,
        hold::{Held, Hold},
    },
};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{
    fs::File,
    io::IoSlice,
    ops::Deref,
    os::{fd::AsRawFd, unix::fs::FileExt},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::task;

cfg_if! {
    if #[cfg(test)] {
        use std::sync::{Barrier, mpsc};
        use tokio::sync::oneshot::Sender as OneshotSender;
    }
}

// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum so storage writes
// span as few submissions as possible.
const IOVEC_BATCH_SIZE: usize = 1024;

/// Page-cache policy for one positioned I/O request.
enum Cache {
    /// Use the operating system's normal page-cache behavior.
    Enabled,
    /// Best-effort bypass of the page cache while the backend supports it.
    Disabled(Arc<AtomicBool>),
}

impl Cache {
    /// Return whether the next Linux submission should request cache bypass.
    fn is_disabled(&self) -> bool {
        cfg!(target_os = "linux")
            && matches!(self, Self::Disabled(supported) if supported.load(Ordering::Relaxed))
    }

    /// Return whether an unsupported cache-bypass attempt should be retried with normal caching.
    fn retry_cached(&mut self, err: &std::io::Error, attempted_dont_cache: bool) -> bool {
        if err.raw_os_error() != Some(libc::EOPNOTSUPP) || !attempted_dont_cache {
            return false;
        }
        let Self::Disabled(supported) = std::mem::replace(self, Self::Enabled) else {
            return false;
        };
        supported.store(false, Ordering::Relaxed);
        true
    }
}

/// A blob's file with the writes no completed sync covers.
///
/// Every operation retains the file, carrying the directory hold into the blocking pool and
/// keeping the open's obligation pending until the operation finishes. Dropping the last
/// reference resolves that obligation immediately when a completed sync covers every mutation.
/// Otherwise, the next open waits for a deferred sync.
struct Shared {
    file: Arc<Held>,
    tracker: Tracker,
    pending: Arc<Pending>,
    key: (String, Vec<u8>),
    /// Resolves the obligation the open registered when its last handle dropped.
    promise: Mutex<Option<Sender>>,
    #[cfg(test)]
    before_mutation: Mutex<Option<(OneshotSender<()>, mpsc::Receiver<()>)>>,
}

#[cfg(test)]
impl Shared {
    fn wait_before_mutation(&self) {
        let hook = self.before_mutation.lock().take();
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
        let Some(sender) = self.promise.lock().take() else {
            return;
        };
        if !self.tracker.is_dirty() {
            self.pending.resolve(&self.key, sender, Ok(()));
            return;
        }
        let file = self.file.clone();
        let key = self.key.clone();
        defer_sync(self.pending.clone(), self.key.clone(), sender, move || {
            Blob::sync_inner(&file, &key.0, &key.1)
        });
    }
}

/// One open of a blob, shared by its clones.
///
/// Dropping the last clone releases the name and registers the obligation a
/// later open waits for, which [Shared] resolves once every operation issued
/// through this open has finished.
struct Open {
    shared: Arc<Shared>,
    generation: Arc<Generation>,
}

impl Deref for Open {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.shared
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        if let Some(sender) = self.generation.release() {
            *self.shared.promise.lock() = Some(sender);
        }
    }
}

#[derive(Clone)]
pub struct Blob {
    open: Arc<Open>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// Whether the kernel and filesystem may support `RWF_DONTCACHE`.
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted I/O operation.
    dont_cache_supported: Arc<AtomicBool>,
    #[cfg(test)]
    after_start_sync: Option<Arc<Barrier>>,
}

impl Blob {
    /// Read the captured file's length after its predecessor's operations have settled.
    pub(super) async fn size(&self) -> Result<u64, Error> {
        let file = self.open.shared.clone();
        let offset = self.data_offset;
        task::spawn_blocking(move || {
            #[cfg(test)]
            {
                let hook = file.pending.test.before_metadata.lock().take();
                if let Some((entered, release)) = hook {
                    let _ = entered.send(());
                    let _ = release.recv();
                }
            }
            file.metadata()
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
            pending: generation.pending.clone(),
            key: generation.key.clone(),
            promise: Mutex::new(None),
            #[cfg(test)]
            before_mutation: Mutex::new(None),
        });
        Self {
            open: Arc::new(Open { shared, generation }),
            pool,
            data_offset,
            dont_cache_supported: Arc::new(AtomicBool::new(true)),
            #[cfg(test)]
            after_start_sync: None,
        }
    }

    /// Number of syncs this open skipped because it had nothing to persist.
    #[cfg(test)]
    pub(super) fn skipped_syncs(&self) -> u64 {
        self.open.tracker.skipped()
    }

    pub(super) fn sync_inner(file: &File, partition: &str, name: &[u8]) -> Result<(), Error> {
        // Data durability is the contract. `sync_data` covers the bytes and metadata required to
        // retrieve them, including file size, while avoiding timestamp-only journal commits.
        // Other platforms retain `sync_all` for their platform-specific guarantees.
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let result = file.sync_data();
            } else {
                let result = file.sync_all();
            }
        }
        result.map_err(|e| Error::BlobSyncFailed(partition.to_string(), hex(name), e.into()))
    }

    #[cfg(target_os = "linux")]
    fn read_exact_at(
        mut cache: Cache,
        file: &File,
        mut buf: &mut [u8],
        mut offset: u64,
    ) -> Result<(), Error> {
        if !cache.is_disabled() {
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
                if cache.retry_cached(&err, true) {
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
    fn read_exact_at(_: Cache, file: &File, buf: &mut [u8], offset: u64) -> Result<(), Error> {
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
        file: &File,
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
                    let attempted_dont_cache = cache.is_disabled();
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
                if cache.retry_cached(&err, attempted_dont_cache) {
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
        let file = self.open.shared.clone();
        let pool = self.pool.clone();
        let cache = if options.contains(ReadOptions::DONT_CACHE) {
            Cache::Disabled(self.dont_cache_supported.clone())
        } else {
            Cache::Enabled
        };
        task::spawn_blocking(move || {
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
        })
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
        let file = self.open.shared.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        if !bufs.has_remaining() {
            return Ok(());
        }

        // Derive per-write policy from the requested options and cached backend support.
        let sync = options.contains(WriteOptions::SYNC);
        let cache = if options.contains(WriteOptions::DONT_CACHE) {
            Cache::Disabled(self.dont_cache_supported.clone())
        } else {
            Cache::Enabled
        };

        // Plain syscall paths own mutation debt before submission, including worker unwind.
        // Durability is fused for one submission. Larger writes finish with one full-file sync.
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let flags = (sync && bufs.chunk_count() <= IOVEC_BATCH_SIZE).then_some(libc::RWF_DSYNC);
            } else {
                let flags = None;
            }
        }
        let fused = flags.is_some();
        if !fused {
            self.open.tracker.write();
        }
        task::spawn_blocking(move || {
            // Preserve the single-buffer fast path when no option requires per-write flags.
            let mut bufs = if !sync && !cache.is_disabled() {
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

            // Remaining buffers stay owned here until terminal error accounting completes.
            // Their owners may unwind when dropped.
            let result = Self::write_vectored_at(cache, &file, offset, &mut bufs, flags);
            if fused && result.is_err() {
                file.tracker.write();
            }
            result?;
            if !fused {
                file.tracker.complete();
            }
            if sync && !fused {
                let seen = file.tracker.begin_sync();
                let (partition, name) = &file.key;
                Self::sync_inner(&file, partition, name)?;
                file.tracker.end_sync(seen);
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::WriteFailed)?
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.open.shared.clone();
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        self.open.tracker.write();
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
            let (partition, name) = &self.open.key;
            Error::BlobResizeFailed(partition.clone(), hex(name), e.into())
        })?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if !self.open.tracker.is_dirty() {
            #[cfg(test)]
            self.open.tracker.skip_sync();
            return Ok(());
        }
        let file = self.open.shared.clone();
        let seen = self.open.tracker.begin_sync();
        task::spawn_blocking(move || {
            let (partition, name) = &file.key;
            Self::sync_inner(&file, partition, name)?;
            file.tracker.end_sync(seen);
            Ok(())
        })
        .await
        .map_err(|e| {
            let err: std::io::Error = e.into();
            let (partition, name) = &self.open.key;
            Error::BlobSyncFailed(partition.clone(), hex(name), err.into())
        })?
    }

    async fn start_sync(&self) -> Handle<()> {
        if !self.open.tracker.is_dirty() {
            #[cfg(test)]
            self.open.tracker.skip_sync();
            return Handle::ready(Ok(()));
        }
        let (tx, rx) = oneshot::channel();
        let file = self.open.shared.clone();
        let seen = self.open.tracker.begin_sync();
        #[cfg(test)]
        let after_start_sync = self.after_start_sync.clone();
        task::spawn_blocking(move || {
            // Release this operation's blob ownership before publishing its completion.
            let (partition, name) = &file.key;
            let result = Self::sync_inner(&file, partition, name);
            if result.is_ok() {
                file.tracker.end_sync(seen);
            }
            drop(file);
            let _ = tx.send(result);
            #[cfg(test)]
            if let Some(gate) = after_start_sync {
                gate.wait();
                gate.wait();
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
    #[cfg(target_os = "linux")]
    use std::sync::Weak;
    use std::{
        env,
        ops::RangeInclusive,
        path::PathBuf,
        process,
        sync::{Barrier, mpsc},
        time::Duration,
    };
    use tokio::time::timeout;

    fn storage_for_reopen_test(label: &str, layouts: RangeInclusive<Layout>) -> (Storage, PathBuf) {
        let directory = env::temp_dir().join(format!("storage_tokio_{label}_{}", process::id()));
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        (
            Storage::new(Config::new(directory.clone(), layouts), pool),
            directory,
        )
    }

    async fn check_reopen_after_gated_mutation(
        replace: bool,
        shrink: bool,
        retire_before_attach: bool,
    ) {
        let (storage, directory) = storage_for_reopen_test(
            &format!("gated_reopen_{replace}_{shrink}_{retire_before_attach}"),
            Layout::V0..=Layout::V0,
        );
        let mut reopening = None;
        let mut old_sync = None;
        if replace {
            let (old, _) = storage.open("partition", b"blob").await.unwrap();
            old.write_at(0, b"old", WriteOptions::default())
                .await
                .unwrap();
            let (release, gate) = mpsc::channel();
            *storage.pending.test.before_sync.lock() = Some(gate);
            drop(old);
            let wait = storage
                .pending
                .syncs
                .lock()
                .get(&("partition".into(), b"blob".to_vec()))
                .unwrap()
                .sync
                .clone();
            old_sync = Some((release, wait));
            let mut open = Box::pin(storage.open("partition", b"blob"));
            assert!((&mut open).now_or_never().is_none());
            storage.scan("partition").await.unwrap();
            reopening = Some(open);
            storage.remove("partition", Some(b"blob")).await.unwrap();
        }

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        if shrink {
            blob.write_at(0, b"orphaned", WriteOptions::SYNC)
                .await
                .unwrap();
        }
        let (entered, entering) = ::tokio::sync::oneshot::channel();
        let (release, gate) = mpsc::channel();
        *blob.open.shared.before_mutation.lock() = Some((entered, gate));
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
            .syncs
            .lock()
            .get(&("partition".into(), b"blob".to_vec()))
            .unwrap()
            .sync
            .clone();
        if let Some((release, wait)) = old_sync {
            release.send(()).unwrap();
            Pending::wait(wait).await.unwrap();
        }

        let attachment = if retire_before_attach {
            let (entered, entering) = ::tokio::sync::oneshot::channel();
            let (release, gate) = mpsc::channel();
            *storage.pending.test.before_attach.lock() = Some((entered, gate));
            Some((entering, release))
        } else {
            None
        };
        let mut reopening =
            reopening.unwrap_or_else(|| Box::pin(storage.open("partition", b"blob")));
        let early = (&mut reopening).now_or_never();
        if let Some((entering, release_attach)) = attachment {
            entering.await.unwrap();
            release.send(()).unwrap();
            Pending::wait(wait.clone()).await.unwrap();
            assert!(storage.pending.syncs.lock().is_empty());
            release_attach.send(()).unwrap();
        } else {
            // Namespace dispatch completes before this barrier. The mutation still owns
            // the file, so the captured descriptor's size is not yet authoritative.
            storage.scan("partition").await.unwrap();
            release.send(()).unwrap();
        }
        let (reopened, size) = match early {
            Some(result) => result,
            None => reopening.as_mut().await,
        }
        .unwrap();
        drop(reopening);
        Pending::wait(wait).await.unwrap();
        if replace && size == 3 {
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
        timeout(Duration::from_secs(10), async {
            for shrink in [false, true] {
                check_reopen_after_gated_mutation(true, shrink, false).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_reopen_after_gated_mutation() {
        timeout(Duration::from_secs(10), async {
            for shrink in [false, true] {
                check_reopen_after_gated_mutation(false, shrink, false).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_reopen_after_retirement_before_attachment() {
        timeout(Duration::from_secs(10), async {
            for shrink in [false, true] {
                check_reopen_after_gated_mutation(false, shrink, true).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_reopen_canceled_during_final_metadata() {
        timeout(Duration::from_secs(10), async {
            let (storage, directory) = storage_for_reopen_test("canceled_metadata", Layout::ALL);
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, b"old", WriteOptions::default())
                .await
                .unwrap();
            let (sync_release, sync_gate) = mpsc::channel();
            *storage.pending.test.before_sync.lock() = Some(sync_gate);
            drop(blob);
            let (entered, entering) = ::tokio::sync::oneshot::channel();
            let (release, gate) = mpsc::channel();
            *storage.pending.test.before_metadata.lock() = Some((entered, gate));
            let mut opening = Box::pin(storage.open("partition", b"blob"));
            assert!((&mut opening).now_or_never().is_none());
            storage.scan("partition").await.unwrap();
            sync_release.send(()).unwrap();
            commonware_macros::select! {
                entered = entering => entered.unwrap(),
                _ = &mut opening => panic!("open must wait for metadata"),
            }
            drop(opening);

            let mut retry = Box::pin(storage.open("partition", b"blob"));
            assert!((&mut retry).now_or_never().is_none());
            storage.scan("partition").await.unwrap();
            release.send(()).unwrap();
            let (blob, size) = retry.await.unwrap();
            assert_eq!(size, 3);
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
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_header_read_after_payload_shrink() {
        let (storage, directory) =
            storage_for_reopen_test("header_shrink", Layout::V0..=Layout::V0);
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let mut file = File::open(directory.join("partition").join(hex(b"blob"))).unwrap();
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
    struct WriteErrorObserver {
        shared: Weak<Shared>,
        accounted: Arc<AtomicBool>,
    }

    #[cfg(target_os = "linux")]
    impl AsRef<[u8]> for WriteErrorObserver {
        fn as_ref(&self) -> &[u8] {
            b"x"
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for WriteErrorObserver {
        fn drop(&mut self) {
            self.accounted.store(
                self.shared.upgrade().unwrap().tracker.is_dirty(),
                Ordering::Release,
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_fused_write_error_is_recorded_before_buffer_drop() {
        let (storage, directory) = storage_for_reopen_test("write_error_order", Layout::ALL);
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let accounted = Arc::new(AtomicBool::new(false));
        let bufs = bytes::Bytes::from_owner(WriteErrorObserver {
            shared: Arc::downgrade(&blob.open.shared),
            accounted: accounted.clone(),
        });

        // The syscall offset is rejected before submission. Terminal error accounting
        // must precede retirement of the supplied buffers.
        let offset = i64::MAX as u64 + 1 - blob.data_offset;
        let result = blob.write_at(offset, bufs, WriteOptions::SYNC).await;
        drop(blob);
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
        assert!(matches!(result, Err(Error::OffsetOverflow)));
        assert!(accounted.load(Ordering::Acquire));
    }

    struct PanickingOwner {
        entered: Option<::tokio::sync::oneshot::Sender<()>>,
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
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_owner_panic_{}", process::id()));
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL), pool);
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let (entered, entering) = ::tokio::sync::oneshot::channel();
        let (release, released) = mpsc::channel();
        let mut chunks = vec![crate::IoBuf::from(bytes::Bytes::from_owner(
            PanickingOwner {
                entered: Some(entered),
                release: released,
            },
        ))];
        let count = if cfg!(target_os = "linux") { 1025 } else { 4 };
        for _ in 1..count {
            chunks.push(crate::IoBuf::from(vec![b'x']));
        }
        let writing_blob = blob.clone();
        let writing =
            ::tokio::spawn(
                async move { writing_blob.write_at(0, chunks, WriteOptions::SYNC).await },
            );
        let entered = ::tokio::time::timeout(std::time::Duration::from_secs(10), entering).await;
        let bytes = blob.read_at(0, 1, ReadOptions::default()).await;
        release.send(()).unwrap();
        let result = writing.await.unwrap();
        entered.unwrap().unwrap();
        assert_eq!(bytes.unwrap().coalesce().as_ref(), b"x");
        assert!(matches!(result, Err(Error::WriteFailed)));

        let (release, gate) = mpsc::channel();
        *storage.pending.test.before_sync.lock() = Some(gate);
        drop(blob);
        let mut reopen = Box::pin(storage.open("partition", b"blob"));
        let early = ::tokio::time::timeout(std::time::Duration::from_millis(20), &mut reopen).await;
        release.send(()).ok();
        let waited = early.is_err();
        let (blob, size) = match early {
            Ok(result) => result.unwrap(),
            Err(_) => reopen.as_mut().await.unwrap(),
        };
        drop(reopen);
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
        let syncs = storage.pending.finished();
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
        assert!(
            waited,
            "reopen returned before the failed write was made durable"
        );
        assert_eq!(syncs, 1);
    }

    #[tokio::test]
    async fn test_reopen_after_start_sync_completion() {
        let storage_directory = std::env::temp_dir().join(format!(
            "storage_tokio_sync_completion_{}",
            std::process::id()
        ));
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL), pool);
        let (mut blob, _) = storage.open("partition", b"blob").await.unwrap();
        let gate = Arc::new(Barrier::new(2));
        blob.after_start_sync = Some(gate.clone());

        // Keep the completed sync worker alive while the caller writes and closes the blob.
        blob.write_at(0, b"before", WriteOptions::default())
            .await
            .unwrap();
        blob.start_sync().await.await.unwrap();
        gate.wait();
        let observed: Result<_, Error> = async {
            blob.write_at(0, b"after sync", WriteOptions::default())
                .await?;
            drop(blob);
            let (reopened, len) = storage.open("partition", b"blob").await?;
            let bytes = reopened
                .read_at(0, len as usize, ReadOptions::default())
                .await?;
            Ok((len, bytes.coalesce(), storage.pending.finished()))
        }
        .await;

        // Release the worker before checking results so a failure cannot strand it.
        gate.wait();
        let (len, bytes, syncs) = observed.unwrap();
        let _ = std::fs::remove_dir_all(storage_directory);
        assert_eq!(len, 10);
        assert_eq!(bytes.as_ref(), b"after sync");
        assert_eq!(syncs, 1, "reopen did not wait for the later write's sync");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cache_bypass_is_ignored_off_linux() {
        let cache = Cache::Disabled(Arc::new(AtomicBool::new(true)));
        assert!(!cache.is_disabled());
    }

    #[test]
    fn test_cache_bypass_retry_decision() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut cache = Cache::Disabled(supported.clone());
        let sibling = Cache::Disabled(supported.clone());
        let unsupported = std::io::Error::from_raw_os_error(libc::EOPNOTSUPP);
        let invalid = std::io::Error::from_raw_os_error(libc::EINVAL);

        assert!(!cache.retry_cached(&invalid, true));
        assert!(supported.load(Ordering::Relaxed));
        assert!(!cache.retry_cached(&unsupported, false));
        assert!(supported.load(Ordering::Relaxed));
        assert!(cache.retry_cached(&unsupported, true));
        assert!(!supported.load(Ordering::Relaxed));
        assert!(!sibling.is_disabled());
        assert!(!cache.retry_cached(&unsupported, true));
    }
}
