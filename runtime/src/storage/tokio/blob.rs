use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
use std::{
    fs::File,
    io::IoSlice,
    os::{fd::AsRawFd, unix::fs::FileExt},
    sync::{
        Arc,
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
    Disabled(Arc<AtomicBool>),
}

impl Cache {
    /// Return whether the next Linux submission should request cache bypass.
    fn is_disabled(&self) -> bool {
        cfg!(target_os = "linux")
            && matches!(self, Self::Disabled(supported) if supported.load(Ordering::Relaxed))
    }

    /// Disable cache bypass for this request and its sibling handles.
    ///
    /// Returns whether this call performed the shared capability transition.
    fn fallback(&mut self) -> Option<bool> {
        match std::mem::replace(self, Self::Enabled) {
            Self::Disabled(supported) => Some(supported.swap(false, Ordering::Relaxed)),
            Self::Enabled => None,
        }
    }

    /// Return whether an unsupported cache-bypass attempt should be retried with normal caching.
    fn retry_cached(&mut self, err: &std::io::Error, attempted_dont_cache: bool) -> bool {
        if err.raw_os_error() != Some(libc::EOPNOTSUPP) || !attempted_dont_cache {
            return false;
        }
        let Some(transitioned) = self.fallback() else {
            return false;
        };
        if transitioned {
            tracing::debug!("RWF_DONTCACHE unsupported, using normal page caching");
        }
        true
    }
}

#[derive(Clone, Copy)]
struct Capabilities<'a> {
    dont_cache_supported: &'a AtomicBool,
    v2_supported: &'a AtomicBool,
}

#[derive(Clone, Copy)]
struct SyscallFlags {
    operation: Option<libc::c_int>,
    dont_cache: libc::c_int,
}

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// Whether the kernel and filesystem may support `RWF_DONTCACHE`.
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted I/O operation.
    dont_cache_supported: Arc<AtomicBool>,
    /// Whether this handle can use the `preadv2` and `pwritev2` syscall family.
    /// Cleared when the syscalls or required operation flags are unavailable so clones use
    /// legacy positioned I/O directly.
    v2_supported: Arc<AtomicBool>,
}

impl Blob {
    pub fn new(
        partition: String,
        name: &[u8],
        file: File,
        pool: BufferPool,
        data_offset: u64,
    ) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
            pool,
            data_offset,
            dont_cache_supported: Arc::new(AtomicBool::new(true)),
            v2_supported: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Stop using the v2 syscall family and cache hints for every clone of this handle.
    ///
    /// Returns whether this call performed the shared v2 capability transition.
    fn disable_v2(capabilities: Capabilities<'_>) -> bool {
        // Clear the hint first so a concurrent EOPNOTSUPP result does not emit a second event for
        // the capability loss already implied by ENOSYS.
        capabilities
            .dont_cache_supported
            .store(false, Ordering::Relaxed);
        let transitioned = capabilities.v2_supported.swap(false, Ordering::Relaxed);
        if transitioned {
            tracing::debug!("preadv2 and pwritev2 flags unavailable, using legacy positioned I/O");
        }
        transitioned
    }

    fn syscall_result(ret: libc::ssize_t) -> std::io::Result<usize> {
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn sync_inner(file: &File, partition: &str, name: &[u8]) -> Result<(), Error> {
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

    fn write_single_at(file: &File, offset: u64, buf: &[u8]) -> Result<(), Error> {
        file.write_all_at(buf, offset)?;
        Ok(())
    }

    /// Write `bufs` at `offset`, batching up to [IOVEC_BATCH_SIZE] iovecs per submission.
    ///
    /// `flags` apply to every submission, so callers must only pass durability flags when the
    /// write fits one submission. Hinted submissions carry `RWF_DONTCACHE` on Linux while the
    /// backend may support it. An EOPNOTSUPP disables the hint and retries normally.
    fn write_vectored_at_with<V2, Legacy>(
        mut cache: Cache,
        capabilities: Capabilities<'_>,
        mut offset: u64,
        mut bufs: IoBufs,
        flags: SyscallFlags,
        mut write_v2: V2,
        mut write_legacy: Legacy,
    ) -> Result<bool, Error>
    where
        V2: FnMut(
            *const libc::iovec,
            libc::c_int,
            libc::off_t,
            libc::c_int,
        ) -> std::io::Result<usize>,
        Legacy: FnMut(*const libc::iovec, libc::c_int, libc::off_t) -> std::io::Result<usize>,
    {
        assert!(
            flags.operation.is_none() || bufs.chunk_count() <= IOVEC_BATCH_SIZE,
            "durability flags on a multi-submission write serialize its batches"
        );
        let mut v2_flags_applied = true;

        while bufs.has_remaining() {
            // Scratch sized to the write, so small vectored writes never initialize a
            // full IOVEC_BATCH_SIZE array.
            let mut io_slices = vec![IoSlice::new(&[]); bufs.chunk_count().min(IOVEC_BATCH_SIZE)];
            let io_slices_len = bufs.chunks_vectored(&mut io_slices);
            assert!(
                io_slices_len > 0,
                "chunks_vectored should produce at least one slice when bufs has remaining"
            );

            let syscall_offset = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
            let iovecs = io_slices.as_ptr().cast::<libc::iovec>();
            let iovec_count = io_slices_len as libc::c_int;
            let attempted_v2 =
                cfg!(target_os = "linux") && capabilities.v2_supported.load(Ordering::Relaxed);
            let attempted_dont_cache = attempted_v2 && cache.is_disabled();
            let result = if attempted_v2 {
                write_v2(
                    iovecs,
                    iovec_count,
                    syscall_offset,
                    flags.operation.unwrap_or(0)
                        | if attempted_dont_cache {
                            flags.dont_cache
                        } else {
                            0
                        },
                )
            } else {
                if flags.operation.is_some() {
                    v2_flags_applied = false;
                }
                write_legacy(iovecs, iovec_count, syscall_offset)
            };

            let bytes_written = match result {
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }

                    if attempted_v2 && err.raw_os_error() == Some(libc::ENOSYS) {
                        Self::disable_v2(capabilities);
                        if flags.operation.is_some() {
                            v2_flags_applied = false;
                        }
                        continue;
                    }

                    // Retry normally and stop requesting an unsupported cache-bypass hint.
                    if cache.retry_cached(&err, attempted_dont_cache) {
                        continue;
                    }

                    // glibc maps an unavailable v2 syscall with nonzero flags from ENOSYS to
                    // EOPNOTSUPP. Once no cache hint was attempted, that error belongs to the
                    // operation flag or the syscall family itself. Legacy I/O plus the caller's
                    // trailing sync preserves the requested durability in either case.
                    if attempted_v2
                        && flags.operation.is_some()
                        && err.raw_os_error() == Some(libc::EOPNOTSUPP)
                    {
                        Self::disable_v2(capabilities);
                        v2_flags_applied = false;
                        continue;
                    }
                    return Err(err.into());
                }
                Ok(bytes_written) => bytes_written,
            };
            if bytes_written == 0 {
                return Err(Error::WriteFailed);
            }
            bufs.advance(bytes_written);
            offset = offset
                .checked_add(bytes_written as u64)
                .ok_or(Error::OffsetOverflow)?;
        }

        Ok(v2_flags_applied)
    }

    fn write_vectored_at(
        cache: Cache,
        capabilities: Capabilities<'_>,
        file: &File,
        offset: u64,
        bufs: IoBufs,
        flags: Option<libc::c_int>,
    ) -> Result<bool, Error> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let fd = file.as_raw_fd();
                let result = Self::write_vectored_at_with(
                    cache,
                    capabilities,
                    offset,
                    bufs,
                    SyscallFlags {
                        operation: flags,
                        dont_cache: libc::RWF_DONTCACHE,
                    },
                    |iovecs, iovec_count, offset, flags| {
                        // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                        // `write_vectored_at_with` passes an initialized, non-empty prefix bounded
                        // by IOVEC_BATCH_SIZE. The borrowed file keeps `fd` valid, and its IoSlice
                        // array and every referenced readable buffer remain alive for the call.
                        let ret = unsafe {
                            libc::pwritev2(fd, iovecs, iovec_count, offset, flags)
                        };
                        Self::syscall_result(ret)
                    },
                    |iovecs, iovec_count, offset| {
                        // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                        // `write_vectored_at_with` passes an initialized, non-empty prefix bounded
                        // by IOVEC_BATCH_SIZE. The borrowed file keeps `fd` valid, and its IoSlice
                        // array and every referenced readable buffer remain alive for the call.
                        let ret = unsafe { libc::pwritev(fd, iovecs, iovec_count, offset) };
                        Self::syscall_result(ret)
                    },
                );
            } else {
                let fd = file.as_raw_fd();
                let result = Self::write_vectored_at_with(
                    cache,
                    capabilities,
                    offset,
                    bufs,
                    SyscallFlags {
                        operation: flags,
                        dont_cache: 0,
                    },
                    |_, _, _, _| unreachable!("v2 writes are Linux-only"),
                    |iovecs, iovec_count, offset| {
                        // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                        // `write_vectored_at_with` passes an initialized, non-empty prefix bounded
                        // by IOVEC_BATCH_SIZE. The borrowed file keeps `fd` valid, and its IoSlice
                        // array and every referenced readable buffer remain alive for the call.
                        let ret = unsafe { libc::pwritev(fd, iovecs, iovec_count, offset) };
                        Self::syscall_result(ret)
                    },
                );
            }
        }
        result
    }

    #[cfg(target_os = "linux")]
    fn read_exact_at_hinted_with<Read, Fallback>(
        mut cache: Cache,
        capabilities: Capabilities<'_>,
        mut buf: &mut [u8],
        mut offset: u64,
        mut read: Read,
        mut fallback: Fallback,
    ) -> Result<(), Error>
    where
        Read: FnMut(&mut [u8], libc::off_t) -> std::io::Result<usize>,
        Fallback: FnMut(&mut [u8], u64) -> std::io::Result<()>,
    {
        while !buf.is_empty() {
            if !cache.is_disabled() || !capabilities.v2_supported.load(Ordering::Relaxed) {
                return fallback(buf, offset).map_err(Into::into);
            }
            let Ok(syscall_offset) = offset.try_into() else {
                return fallback(buf, offset).map_err(Into::into);
            };

            let bytes_read = match read(buf, syscall_offset) {
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => {
                    Self::disable_v2(capabilities);
                    return fallback(buf, offset).map_err(Into::into);
                }
                Err(err) if cache.retry_cached(&err, true) => {
                    return fallback(buf, offset).map_err(Into::into);
                }
                Err(err) => return Err(err.into()),
                Ok(0) => return Err(std::io::Error::from(ErrorKind::UnexpectedEof).into()),
                Ok(bytes_read) => bytes_read,
            };
            if bytes_read > buf.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "preadv2 returned more bytes than requested",
                )
                .into());
            }
            let (_, unread) = buf.split_at_mut(bytes_read);
            buf = unread;
            offset = offset
                .checked_add(bytes_read as u64)
                .ok_or(Error::OffsetOverflow)?;
        }
        Ok(())
    }

    fn read_exact_at(
        cache: Cache,
        capabilities: Option<Capabilities<'_>>,
        file: &File,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<(), Error> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                if !cache.is_disabled() {
                    file.read_exact_at(buf, offset)?;
                    return Ok(());
                }
                let capabilities = capabilities.expect("cache bypass requires capabilities");
                if !capabilities.v2_supported.load(Ordering::Relaxed) {
                    file.read_exact_at(buf, offset)?;
                    return Ok(());
                }
                let fd = file.as_raw_fd();
                Self::read_exact_at_hinted_with(
                    cache,
                    capabilities,
                    buf,
                    offset,
                    |buf, offset| {
                        let iovec = libc::iovec {
                            iov_base: buf.as_mut_ptr().cast(),
                            iov_len: buf.len(),
                        };
                        // SAFETY: `fd` is valid for this call. `iovec` describes the exclusive
                        // writable slice borrowed for the duration of the syscall.
                        let ret = unsafe {
                            libc::preadv2(fd, &iovec, 1, offset, libc::RWF_DONTCACHE)
                        };
                        Self::syscall_result(ret)
                    },
                    |buf, offset| file.read_exact_at(buf, offset),
                )
            } else {
                let _ = (cache, capabilities);
                file.read_exact_at(buf, offset)?;
                Ok(())
            }
        }
    }

    const fn needs_trailing_sync(sync: bool, fused: bool, v2_flags_applied: bool) -> bool {
        sync && (!fused || !v2_flags_applied)
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
        let file = self.file.clone();
        let pool = self.pool.clone();
        let capability_state = options
            .contains(ReadOptions::DONT_CACHE)
            .then(|| (self.dont_cache_supported.clone(), self.v2_supported.clone()));
        let cache = match &capability_state {
            Some((dont_cache_supported, _)) => Cache::Disabled(dont_cache_supported.clone()),
            None => Cache::Enabled,
        };
        task::spawn_blocking(move || {
            let capabilities =
                capability_state
                    .as_ref()
                    .map(|(dont_cache_supported, v2_supported)| Capabilities {
                        dont_cache_supported,
                        v2_supported,
                    });
            if let Some(buf) = bufs.as_single_mut() {
                // Read directly into the single buffer (zero-copy).
                Self::read_exact_at(cache, capabilities, &file, buf.as_mut(), offset)?;
            } else {
                // Read into a temporary contiguous buffer and copy back to preserve structure.
                // SAFETY: `len` bytes are filled via read_exact_at below.
                let mut temp = unsafe { pool.alloc_len(len) };
                Self::read_exact_at(cache, capabilities, &file, temp.as_mut(), offset)?;
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
        let file = self.file.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        if !bufs.has_remaining() {
            return Ok(());
        }

        // Derive per-write policy from the requested options and cached backend support.
        let sync = options.contains(WriteOptions::SYNC);
        let dont_cache = options.contains(WriteOptions::DONT_CACHE);
        // Preserve the ordinary single-buffer path without touching shared capability state.
        let bufs = if !sync && !dont_cache {
            match bufs.try_into_single() {
                Ok(buf) => {
                    return task::spawn_blocking(move || {
                        Self::write_single_at(&file, offset, buf.as_ref())
                    })
                    .await
                    .map_err(|_| Error::WriteFailed)?;
                }
                Err(bufs) => bufs,
            }
        } else {
            bufs
        };
        let cache = if dont_cache {
            Cache::Disabled(self.dont_cache_supported.clone())
        } else {
            Cache::Enabled
        };
        let dont_cache_supported = self.dont_cache_supported.clone();
        let v2_supported = self.v2_supported.clone();
        let partition = sync.then(|| self.partition.clone());
        let name = sync.then(|| self.name.clone());
        task::spawn_blocking(move || {
            let capabilities = Capabilities {
                dont_cache_supported: &dont_cache_supported,
                v2_supported: &v2_supported,
            };
            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    // Fuse durability only when the write fits one submission. Fusing every batch
                    // would serialize the batches behind per-call durability waits. Plain batches
                    // stay pipelined and finish with one data sync.
                    let fused = sync && bufs.chunk_count() <= IOVEC_BATCH_SIZE;
                    let v2_flags_applied = Self::write_vectored_at(
                        cache,
                        capabilities,
                        &file,
                        offset,
                        bufs,
                        fused.then_some(libc::RWF_DSYNC),
                    )?;
                    if Self::needs_trailing_sync(sync, fused, v2_flags_applied) {
                        file.sync_data().map_err(|e| {
                            Error::BlobSyncFailed(
                                partition.expect("sync write has a partition"),
                                hex(name.as_deref().expect("sync write has a name")),
                                e.into(),
                            )
                        })?;
                    }
                } else {
                    Self::write_vectored_at(
                        cache,
                        capabilities,
                        &file,
                        offset,
                        bufs,
                        None,
                    )?;
                    if sync {
                        Self::sync_inner(
                            &file,
                            partition.as_deref().expect("sync write has a partition"),
                            name.as_deref().expect("sync write has a name"),
                        )?;
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::WriteFailed)?
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.file.clone();
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || file.set_len(len))
            .await
            .map_err(|e| e.into())
            .and_then(|r| r)
            .map_err(|e| {
                Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e.into())
            })?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || Self::sync_inner(&file, &partition, &name))
            .await
            .map_err(|e| {
                let err: std::io::Error = e.into();
                Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), err.into())
            })?
    }

    async fn start_sync(&self) -> Handle<()> {
        let (tx, rx) = oneshot::channel();
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || {
            let result = Self::sync_inner(&file, &partition, &name);
            let _ = tx.send(result);
        });
        Handle::from_receiver(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::traces::collector::TraceStorage;
    use commonware_macros::test_collect_traces;
    use std::sync::Barrier;

    fn capabilities<'a>(
        dont_cache_supported: &'a AtomicBool,
        v2_supported: &'a AtomicBool,
    ) -> Capabilities<'a> {
        Capabilities {
            dont_cache_supported,
            v2_supported,
        }
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

    #[test]
    fn test_cache_bypass_transition_is_shared_once() {
        const THREADS: usize = 8;
        let supported = Arc::new(AtomicBool::new(true));
        let barrier = Arc::new(Barrier::new(THREADS));
        let transitions = std::thread::scope(|scope| {
            let handles = (0..THREADS)
                .map(|_| {
                    let supported = supported.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let mut cache = Cache::Disabled(supported);
                        barrier.wait();
                        cache.fallback().expect("disabled cache can fall back")
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(
            transitions
                .into_iter()
                .filter(|transition| *transition)
                .count(),
            1
        );
        assert!(!supported.load(Ordering::Relaxed));
    }

    #[test]
    fn test_v2_transition_is_shared_once() {
        const THREADS: usize = 8;
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let barrier = Arc::new(Barrier::new(THREADS));
        let transitions = std::thread::scope(|scope| {
            let handles = (0..THREADS)
                .map(|_| {
                    let dont_cache_supported = dont_cache_supported.clone();
                    let v2_supported = v2_supported.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        Blob::disable_v2(capabilities(&dont_cache_supported, &v2_supported))
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(
            transitions
                .into_iter()
                .filter(|transition| *transition)
                .count(),
            1
        );
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        assert!(!v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test_collect_traces]
    fn test_concurrent_hinted_read_failures_log_each_transition_once(traces: TraceStorage) {
        const THREADS: usize = 8;

        let run = |error: i32| {
            let dont_cache_supported = Arc::new(AtomicBool::new(true));
            let v2_supported = Arc::new(AtomicBool::new(true));
            let barrier = Arc::new(Barrier::new(THREADS));
            let dispatch = tracing::dispatcher::get_default(Clone::clone);

            std::thread::scope(|scope| {
                let handles = (0..THREADS)
                    .map(|_| {
                        let dont_cache_supported = dont_cache_supported.clone();
                        let v2_supported = v2_supported.clone();
                        let barrier = barrier.clone();
                        let dispatch = dispatch.clone();
                        scope.spawn(move || {
                            tracing::dispatcher::with_default(&dispatch, || {
                                let mut output = [0u8; 1];
                                Blob::read_exact_at_hinted_with(
                                    Cache::Disabled(dont_cache_supported.clone()),
                                    capabilities(&dont_cache_supported, &v2_supported),
                                    &mut output,
                                    0,
                                    |_, _| {
                                        barrier.wait();
                                        Err(std::io::Error::from_raw_os_error(error))
                                    },
                                    |buf, _| {
                                        buf.copy_from_slice(b"x");
                                        Ok(())
                                    },
                                )
                                .unwrap();
                                assert_eq!(&output, b"x");
                            });
                        })
                    })
                    .collect::<Vec<_>>();
                for handle in handles {
                    handle.join().unwrap();
                }
            });

            assert!(!dont_cache_supported.load(Ordering::Relaxed));
            if error == libc::ENOSYS {
                assert!(!v2_supported.load(Ordering::Relaxed));
            } else {
                assert!(v2_supported.load(Ordering::Relaxed));
            }
        };

        run(libc::EOPNOTSUPP);
        run(libc::ENOSYS);

        let events = traces.get_all();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.metadata.content.contains("RWF_DONTCACHE unsupported"))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event
                    .metadata
                    .content
                    .contains("preadv2 and pwritev2 flags unavailable"))
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_hinted_read_retries_eintr_and_advances_partial_reads() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut output = [0u8; 5];
        let mut calls = 0;
        let mut attempts = Vec::new();

        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut output,
            7,
            |buf, offset| {
                calls += 1;
                attempts.push((offset, buf.len()));
                match calls {
                    1 => Err(std::io::Error::from_raw_os_error(libc::EINTR)),
                    2 => {
                        buf[..2].copy_from_slice(b"he");
                        Ok(2)
                    }
                    3 => {
                        buf.copy_from_slice(b"llo");
                        Ok(3)
                    }
                    _ => unreachable!("exact read completed in three attempts"),
                }
            },
            |_, _| panic!("supported hinted read must not fall back"),
        )
        .unwrap();

        assert_eq!(attempts, [(7, 5), (7, 5), (9, 3)]);
        assert_eq!(&output, b"hello");
        assert!(dont_cache_supported.load(Ordering::Relaxed));
        assert!(v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_hinted_read_eopnotsupp_falls_back_unread_suffix() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut output = [0u8; 5];
        let mut calls = 0;
        let mut fallback = None;

        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut output,
            11,
            |buf, _| {
                calls += 1;
                if calls == 1 {
                    buf[..2].copy_from_slice(b"he");
                    Ok(2)
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP))
                }
            },
            |buf, offset| {
                fallback = Some((offset, buf.len()));
                buf.copy_from_slice(b"llo");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(calls, 2);
        assert_eq!(fallback, Some((13, 3)));
        assert_eq!(&output, b"hello");
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        assert!(v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_hinted_read_enosys_falls_back_unread_suffix_and_disables_v2() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut output = [0u8; 5];
        let mut calls = 0;
        let mut fallback = None;

        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut output,
            17,
            |buf, _| {
                calls += 1;
                if calls == 1 {
                    buf[..2].copy_from_slice(b"he");
                    Ok(2)
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
                }
            },
            |buf, offset| {
                fallback = Some((offset, buf.len()));
                buf.copy_from_slice(b"llo");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(calls, 2);
        assert_eq!(fallback, Some((19, 3)));
        assert_eq!(&output, b"hello");
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        assert!(!v2_supported.load(Ordering::Relaxed));

        let mut sibling = [0u8; 1];
        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut sibling,
            0,
            |_, _| panic!("sibling must not probe an absent syscall"),
            |buf, _| {
                buf.copy_from_slice(b"x");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(&sibling, b"x");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_hinted_read_zero_is_unexpected_eof() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut output = [0u8; 1];

        let err = Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut output,
            0,
            |_, _| Ok(0),
            |_, _| panic!("EOF is not a capability fallback"),
        )
        .unwrap_err();

        assert!(matches!(err, Error::Io(err) if err.kind() == ErrorKind::UnexpectedEof));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_hinted_read_unrepresentable_offset_uses_fileext_fallback() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut output = [0u8; 1];
        let offset = i64::MAX as u64 + 1;
        let mut fallback = None;

        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut output,
            offset,
            |_, _| panic!("unrepresentable offset must not reach preadv2"),
            |buf, fallback_offset| {
                fallback = Some((fallback_offset, buf.len()));
                buf.copy_from_slice(b"x");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(fallback, Some((offset, 1)));
        assert_eq!(&output, b"x");
        assert!(dont_cache_supported.load(Ordering::Relaxed));
        assert!(v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_hinted_read_continuation_offset_uses_fileext_fallback() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut output = [0u8; 2];
        let mut fallback = None;
        let max_offset = libc::off_t::MAX as u64;

        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut output,
            max_offset,
            |buf, offset| {
                assert_eq!(offset, libc::off_t::MAX);
                buf[0] = b'x';
                Ok(1)
            },
            |buf, offset| {
                fallback = Some((offset, buf.len()));
                buf.copy_from_slice(b"y");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(fallback, Some((max_offset + 1, 1)));
        assert_eq!(&output, b"xy");
        assert!(dont_cache_supported.load(Ordering::Relaxed));
        assert!(v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_zero_length_hinted_read_performs_no_work() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut output = [];

        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut output,
            u64::MAX,
            |_, _| panic!("zero-length read must not issue I/O"),
            |_, _| panic!("zero-length read must not fall back"),
        )
        .unwrap();
        assert!(dont_cache_supported.load(Ordering::Relaxed));
        assert!(v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_write_enosys_uses_legacy_and_requires_trailing_sync() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut v2_calls = 0;
        let mut legacy_calls = 0;

        let v2_flags_applied = Blob::write_vectored_at_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            0,
            IoBufs::from(crate::IoBuf::from(b"hello")),
            SyscallFlags {
                operation: Some(libc::RWF_DSYNC),
                dont_cache: libc::RWF_DONTCACHE,
            },
            |_, _, offset, flags| {
                v2_calls += 1;
                assert_eq!(offset, 0);
                assert_eq!(flags, libc::RWF_DSYNC | libc::RWF_DONTCACHE);
                Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
            },
            |_, _, offset| {
                legacy_calls += 1;
                assert_eq!(offset, 0);
                Ok(5)
            },
        )
        .unwrap();

        assert_eq!(v2_calls, 1);
        assert_eq!(legacy_calls, 1);
        assert!(!v2_flags_applied);
        assert!(Blob::needs_trailing_sync(true, true, v2_flags_applied));
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        assert!(!v2_supported.load(Ordering::Relaxed));

        let later_v2_flags_applied = Blob::write_vectored_at_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            5,
            IoBufs::from(crate::IoBuf::from(b"world")),
            SyscallFlags {
                operation: Some(libc::RWF_DSYNC),
                dont_cache: libc::RWF_DONTCACHE,
            },
            |_, _, _, _| panic!("later write must not probe an absent syscall"),
            |_, _, offset| {
                legacy_calls += 1;
                assert_eq!(offset, 5);
                Ok(5)
            },
        )
        .unwrap();
        assert_eq!(legacy_calls, 2);
        assert!(!later_v2_flags_applied);
        assert!(Blob::needs_trailing_sync(
            true,
            true,
            later_v2_flags_applied
        ));

        let mut sibling = [0u8; 1];
        Blob::read_exact_at_hinted_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            &mut sibling,
            0,
            |_, _| panic!("sibling read must not probe an absent syscall"),
            |buf, _| {
                buf.copy_from_slice(b"x");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(&sibling, b"x");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_write_eopnotsupp_retries_v2_with_dsync() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut flags = Vec::new();

        let v2_flags_applied = Blob::write_vectored_at_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            0,
            IoBufs::from(crate::IoBuf::from(b"hello")),
            SyscallFlags {
                operation: Some(libc::RWF_DSYNC),
                dont_cache: libc::RWF_DONTCACHE,
            },
            |_, _, _, submitted_flags| {
                flags.push(submitted_flags);
                if flags.len() == 1 {
                    Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP))
                } else {
                    Ok(5)
                }
            },
            |_, _, _| panic!("EOPNOTSUPP must retain the v2 syscall"),
        )
        .unwrap();

        assert_eq!(
            flags,
            [libc::RWF_DSYNC | libc::RWF_DONTCACHE, libc::RWF_DSYNC]
        );
        assert!(v2_flags_applied);
        assert!(!Blob::needs_trailing_sync(true, true, v2_flags_applied));
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        assert!(v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_write_operation_eopnotsupp_uses_legacy_and_requires_trailing_sync() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut flags = Vec::new();
        let mut legacy_calls = 0;

        let v2_flags_applied = Blob::write_vectored_at_with(
            Cache::Disabled(dont_cache_supported.clone()),
            capabilities(&dont_cache_supported, &v2_supported),
            0,
            IoBufs::from(crate::IoBuf::from(b"hello")),
            SyscallFlags {
                operation: Some(libc::RWF_DSYNC),
                dont_cache: libc::RWF_DONTCACHE,
            },
            |_, _, _, submitted_flags| {
                flags.push(submitted_flags);
                Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            },
            |_, _, offset| {
                legacy_calls += 1;
                assert_eq!(offset, 0);
                Ok(5)
            },
        )
        .unwrap();

        assert_eq!(
            flags,
            [libc::RWF_DSYNC | libc::RWF_DONTCACHE, libc::RWF_DSYNC]
        );
        assert_eq!(legacy_calls, 1);
        assert!(!v2_flags_applied);
        assert!(Blob::needs_trailing_sync(true, true, v2_flags_applied));
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        assert!(!v2_supported.load(Ordering::Relaxed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_sync_only_eopnotsupp_uses_legacy_and_requires_trailing_sync() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));
        let v2_supported = Arc::new(AtomicBool::new(true));
        let mut flags = Vec::new();
        let mut legacy_calls = 0;

        let v2_flags_applied = Blob::write_vectored_at_with(
            Cache::Enabled,
            capabilities(&dont_cache_supported, &v2_supported),
            0,
            IoBufs::from(crate::IoBuf::from(b"hello")),
            SyscallFlags {
                operation: Some(libc::RWF_DSYNC),
                dont_cache: libc::RWF_DONTCACHE,
            },
            |_, _, _, submitted_flags| {
                flags.push(submitted_flags);
                Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            },
            |_, _, offset| {
                legacy_calls += 1;
                assert_eq!(offset, 0);
                Ok(5)
            },
        )
        .unwrap();

        assert_eq!(flags, [libc::RWF_DSYNC]);
        assert_eq!(legacy_calls, 1);
        assert!(!v2_flags_applied);
        assert!(Blob::needs_trailing_sync(true, true, v2_flags_applied));
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        assert!(!v2_supported.load(Ordering::Relaxed));
    }
}
