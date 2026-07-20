use super::Header;
use crate::{storage::FloorState, Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut};
use cfg_if::cfg_if;
use commonware_codec::Encode;
use commonware_formatting::hex;
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{
    fs::File,
    io::IoSlice,
    os::{fd::AsRawFd, unix::fs::FileExt},
    sync::Arc,
};
use tokio::task;

// Cap iovec batch size: larger iovecs reduce syscall count but increase
// per-write kernel setup overhead.
const IOVEC_BATCH_SIZE: usize = 32;

/// Reads at or below this size attempt a non-blocking page-cache read on
/// the caller thread before falling back to the blocking pool. Dispatching
/// through `spawn_blocking` costs ~7us while a warm 4KiB `pread` costs
/// under 1us (a ~14x throughput cliff on cached small reads), and the
/// inline-vs-dispatch crossover sits well above 64KiB. Uncached reads must
/// NOT run inline — a device read would block the executor thread and
/// serialize I/O parallelism onto the worker count — which is what the
/// `RWF_NOWAIT` gate guarantees.
#[cfg(target_os = "linux")]
const INLINE_READ_MAX: usize = 64 * 1024;

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
    pool: BufferPool,
    /// Version recorded in the blob header, needed to rewrite it at sync.
    blob_version: u16,
    /// The pruned floor bookkeeping, seeded from the header at open and
    /// persisted back through [Self::sync_inner] (see [FloorState]).
    floor: Arc<Mutex<FloorState>>,
}

impl Blob {
    pub fn new(
        partition: String,
        name: &[u8],
        file: File,
        pool: BufferPool,
        blob_version: u16,
        floor: u64,
    ) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
            pool,
            blob_version,
            floor: Arc::new(Mutex::new(FloorState::new(floor))),
        }
    }

    fn sync_inner(
        file: &File,
        partition: &str,
        name: &[u8],
        blob_version: u16,
        floor: &Mutex<FloorState>,
    ) -> Result<(), Error> {
        // A dirty floor is rewritten into the header by the same sync that
        // makes the pruned state durable. The 16-byte write happens while
        // the lock is held, so concurrent syncs land header images in
        // snapshot order and a stale floor can never overwrite a fresher
        // one (floors are monotone).
        let epoch = {
            let state = floor.lock();
            if state.dirty() {
                let header = Header::with_floor(blob_version, state.floor());
                Self::write_single_at(file, 0, &header.encode())?;
            }
            state.epoch()
        };
        file.sync_all()
            .map_err(|e| Error::BlobSyncFailed(partition.to_string(), hex(name), e.into()))?;
        // The floor written above is durable, unless a prune advanced it
        // mid-sync (a failure leaves the mark set for a retry).
        floor.lock().mark_synced(epoch);
        Ok(())
    }

    fn write_single_at(file: &File, offset: u64, buf: &[u8]) -> Result<(), Error> {
        file.write_all_at(buf, offset)?;
        Ok(())
    }

    /// Fill every chunk of `bufs` (lengths already set) from `offset` with
    /// vectored positioned reads (`preadv`), `read_exact` semantics: a
    /// short file is an error.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn read_vectored_at(file: &File, mut offset: u64, bufs: &mut IoBufsMut) -> Result<(), Error> {
        let mut iovecs: Vec<libc::iovec> = Vec::new();
        bufs.for_each_chunk_mut(|buf| {
            if !buf.is_empty() {
                iovecs.push(libc::iovec {
                    iov_base: buf.as_mut().as_mut_ptr().cast(),
                    iov_len: buf.len(),
                });
            }
        });

        let mut idx = 0;
        while idx < iovecs.len() {
            let batch = (iovecs.len() - idx).min(IOVEC_BATCH_SIZE);
            // SAFETY: each iovec references a distinct live chunk of `bufs`,
            // owned by this frame and untouched for the syscall's duration.
            let ret = unsafe {
                libc::preadv(
                    file.as_raw_fd(),
                    iovecs[idx..].as_ptr(),
                    batch as libc::c_int,
                    offset.try_into().map_err(|_| Error::OffsetOverflow)?,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            if ret == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            let mut advanced = ret as usize;
            offset = offset
                .checked_add(ret as u64)
                .ok_or(Error::OffsetOverflow)?;
            // Advance past filled iovecs; trim a partially filled head.
            while advanced > 0 {
                let head = &mut iovecs[idx];
                if advanced >= head.iov_len {
                    advanced -= head.iov_len;
                    idx += 1;
                } else {
                    // SAFETY: `advanced < iov_len`, so the shifted base
                    // stays inside the chunk it was created from.
                    head.iov_base = unsafe { head.iov_base.cast::<u8>().add(advanced).cast() };
                    head.iov_len -= advanced;
                    advanced = 0;
                }
            }
        }
        Ok(())
    }

    /// Attempt to fill `buf` from `offset` entirely from the page cache
    /// with `preadv2(RWF_NOWAIT)` on the caller thread. Returns `false`
    /// when the read cannot complete without blocking (uncached pages,
    /// unsupported kernel/filesystem — memoized — or any error): the
    /// caller falls back to the blocking pool, which re-reads the whole
    /// range and surfaces real errors.
    #[cfg(target_os = "linux")]
    fn read_cached_at(file: &File, offset: u64, buf: &mut [u8]) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        // RWF_NOWAIT unsupported (kernel < 4.14 or filesystem): probe once
        // per process instead of per read.
        static UNSUPPORTED: AtomicBool = AtomicBool::new(false);
        if UNSUPPORTED.load(Ordering::Relaxed) {
            return false;
        }
        let mut filled = 0usize;
        while filled < buf.len() {
            let iov = libc::iovec {
                iov_base: buf[filled..].as_mut_ptr().cast(),
                iov_len: buf.len() - filled,
            };
            let Ok(at) = libc::off_t::try_from(offset + filled as u64) else {
                return false;
            };
            // SAFETY: `iov` references a live chunk of `buf`, owned by this
            // frame and untouched for the syscall's duration.
            let ret = unsafe { libc::preadv2(file.as_raw_fd(), &iov, 1, at, libc::RWF_NOWAIT) };
            if ret < 0 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) => {
                        UNSUPPORTED.store(true, Ordering::Relaxed);
                        return false;
                    }
                    // EAGAIN (pages not cached) and everything else: fall
                    // back to the blocking pool.
                    _ => return false,
                }
            }
            if ret == 0 {
                // Short file: let the blocking path produce the exact error.
                return false;
            }
            filled += ret as usize;
        }
        true
    }

    fn write_vectored_at(
        file: &File,
        mut offset: u64,
        mut bufs: IoBufs,
        flags: Option<libc::c_int>,
    ) -> Result<(), Error> {
        while bufs.has_remaining() {
            let mut io_slices = [IoSlice::new(&[]); IOVEC_BATCH_SIZE];
            let io_slices_len = bufs.chunks_vectored(&mut io_slices);
            assert!(
                io_slices_len > 0,
                "chunks_vectored should produce at least one slice when bufs has remaining"
            );

            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                    // `io_slices` points to valid readable buffers held alive for this syscall.
                    let ret = unsafe {
                        libc::pwritev2(
                            file.as_raw_fd(),
                            io_slices.as_ptr().cast::<libc::iovec>(),
                            io_slices_len as i32,
                            offset.try_into().map_err(|_| Error::OffsetOverflow)?,
                            flags.unwrap_or(0),
                        )
                    };
                } else {
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

    /// Best-effort deallocation of the raw byte range `[start, start + len)`
    /// while keeping the file size. Errors are deliberately dropped: a
    /// filesystem without hole punching degrades to unreclaimed space.
    fn punch_hole(file: &File, start: u64, len: u64) {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let (Ok(start), Ok(len)) = (
                    libc::off_t::try_from(start),
                    libc::off_t::try_from(len),
                ) else {
                    return;
                };
                // SAFETY: `file` owns a valid fd that lives across the call;
                // `fallocate` reads only its scalar arguments.
                unsafe {
                    libc::fallocate(
                        file.as_raw_fd(),
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        start,
                        len,
                    );
                }
            } else if #[cfg(target_os = "macos")] {
                let (Ok(fp_offset), Ok(fp_length)) = (
                    libc::off_t::try_from(start),
                    libc::off_t::try_from(len),
                ) else {
                    return;
                };
                let args = libc::fpunchhole_t {
                    fp_flags: 0,
                    reserved: 0,
                    fp_offset,
                    fp_length,
                };
                // SAFETY: `file` owns a valid fd that lives across the call;
                // `args` is a properly initialized `fpunchhole_t` that the
                // kernel only reads for the duration of the call.
                unsafe {
                    libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &args);
                }
            } else {
                // No hole-punching API on this platform: pruned bytes keep
                // their space until the blob is removed.
                let _ = (file, start, len);
            }
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
        let mut bufs = bufs.into();
        // SAFETY: `len` bytes are filled via read_exact below.
        unsafe { bufs.set_len(len) };
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
        // Small single-buffer reads: serve page-cache hits inline instead
        // of paying the blocking-pool dispatch (see [`INLINE_READ_MAX`]).
        // macOS has no `RWF_NOWAIT` equivalent, so it keeps the dispatch:
        // an inline miss there would block the executor on a device read.
        #[cfg(target_os = "linux")]
        if len <= INLINE_READ_MAX {
            if let Some(buf) = bufs.as_single_mut() {
                if Self::read_cached_at(&self.file, offset, buf.as_mut()) {
                    // The spawn_blocking round-trip used to be the yield
                    // point: stay cooperative under tight read loops.
                    tokio::task::consume_budget().await;
                    return Ok(bufs);
                }
            }
        }
        let file = self.file.clone();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let pool = self.pool.clone();
        task::spawn_blocking(move || {
            if let Some(buf) = bufs.as_single_mut() {
                // Read directly into the single buffer (zero-copy).
                file.read_exact_at(buf.as_mut(), offset)?;
            } else {
                cfg_if! {
                    if #[cfg(any(target_os = "linux", target_os = "macos"))] {
                        // Scatter directly into the buffers (zero-copy).
                        Self::read_vectored_at(&file, offset, &mut bufs)?;
                    } else {
                        // Read into a temporary contiguous buffer and copy back to preserve structure.
                        // SAFETY: `len` bytes are filled via read_exact_at below.
                        let mut temp = unsafe { pool.alloc_len(len) };
                        file.read_exact_at(temp.as_mut(), offset)?;
                        bufs.copy_from_slice(temp.as_ref());
                    }
                }
            }
            Ok(bufs)
        })
        .await
        .map_err(|_| Error::ReadFailed)?
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
        let file = self.file.clone();
        task::spawn_blocking(move || match bufs.try_into_single() {
            Ok(buf) => Self::write_single_at(&file, offset, buf.as_ref()),
            Err(bufs) => Self::write_vectored_at(&file, offset, bufs, None),
        })
        .await
        .map_err(|_| Error::WriteFailed)?
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

        cfg_if! {
            if #[cfg(target_os = "linux")] {
                // `RWF_SYNC` only persists this write's bytes: with a dirty
                // floor the header must be rewritten and fsynced too, so
                // take the write-then-sync path below instead.
                if !self.floor.lock().dirty() {
                    let file = self.file.clone();
                    return task::spawn_blocking(move || {
                        Self::write_vectored_at(&file, offset, bufs, Some(libc::RWF_SYNC))
                    })
                    .await
                    .map_err(|_| Error::WriteFailed)?;
                }
            }
        }

        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        let blob_version = self.blob_version;
        let floor = self.floor.clone();
        task::spawn_blocking(move || {
            Self::write_vectored_at(&file, offset, bufs, None)?;
            Self::sync_inner(&file, &partition, &name, blob_version, &floor)
        })
        .await
        .map_err(|_| Error::WriteFailed)?
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
        if let Some(old) = self.floor.lock().advance(offset) {
            Self::punch_hole(&self.file, Header::DATA_OFFSET_U64 + old, offset - old);
        }
        Ok(())
    }

    fn floor(&self) -> u64 {
        self.floor.lock().floor()
    }

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
        let file = self.file.clone();
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
        let blob_version = self.blob_version;
        let floor = self.floor.clone();
        task::spawn_blocking(move || {
            Self::sync_inner(&file, &partition, &name, blob_version, &floor)
        })
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
        let blob_version = self.blob_version;
        let floor = self.floor.clone();
        task::spawn_blocking(move || {
            let result = Self::sync_inner(&file, &partition, &name, blob_version, &floor);
            let _ = tx.send(result);
        });
        Handle::from_receiver(rx)
    }
}
