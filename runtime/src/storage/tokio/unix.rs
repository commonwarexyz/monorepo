use super::Header;
use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
use std::{
    fs::File,
    io::IoSlice,
    os::{fd::AsRawFd, unix::fs::FileExt},
    panic,
    sync::Arc,
};
use tokio::{sync::Mutex, task};

// Cap iovec batch size: larger iovecs reduce syscall count but increase
// per-write kernel setup overhead.
const IOVEC_BATCH_SIZE: usize = 32;

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
    pool: BufferPool,
    /// The in-flight content mutation, if any.
    ///
    /// Dropping a future does not stop its operation: the spawned pwrite or set_len keeps
    /// running in the background. Keeping it here lets whoever touches the blob next wait
    /// for it, so a dropped mutation can never land on disk after later operations. This
    /// is what upholds the ordering contract on [crate::Blob].
    inflight: Arc<Mutex<Option<task::JoinHandle<()>>>>,
}

impl Blob {
    pub fn new(partition: String, name: &[u8], file: File, pool: BufferPool) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
            pool,
            inflight: Arc::new(Mutex::new(None)),
        }
    }

    /// Wait for the in-flight mutation, if any, to finish, then clear it.
    ///
    /// The handle is awaited in place and removed only after it completes: a caller
    /// dropped mid-wait leaves the mutation in flight for whoever comes next, and a
    /// finished handle must never be polled again (doing so panics).
    ///
    /// An orphan's error result is discardable (the contract allows a dropped operation
    /// to never execute), but a panic is not: it is resumed here rather than silently
    /// swallowed.
    async fn drain(inflight: &mut Option<task::JoinHandle<()>>) {
        if let Some(handle) = inflight.as_mut() {
            let result = handle.await;
            *inflight = None;
            if let Err(err) = result {
                if err.is_panic() {
                    panic::resume_unwind(err.into_panic());
                }
            }
        }
    }

    /// Wait for any in-flight mutation to finish.
    async fn wait_for_inflight(&self) {
        let mut inflight = self.inflight.lock().await;
        Self::drain(&mut inflight).await;
    }

    /// Run `op`, ordered after any in-flight mutation.
    ///
    /// Submission order is lock-acquisition order (the tokio mutex is FIFO-fair). The
    /// `inflight` guard is held for the whole operation, so the only way a later caller
    /// finds an in-flight handle is that the future which owned it was dropped. Dropping
    /// this future at any await point is safe: before the spawn, the operation never
    /// executes; after it, the handle stays in flight and the next operation waits for it
    /// before starting.
    ///
    /// `task_failed` supplies the error reported when the blocking task dies without
    /// delivering a result (the runtime is shutting down); a panicking task resumes its
    /// panic here instead.
    async fn run_ordered(
        &self,
        op: impl FnOnce() -> Result<(), Error> + Send + 'static,
        task_failed: impl FnOnce() -> Error,
    ) -> Result<(), Error> {
        let mut inflight = self.inflight.lock().await;
        Self::drain(&mut inflight).await;

        let (tx, rx) = oneshot::channel();
        *inflight = Some(task::spawn_blocking(move || {
            let _ = tx.send(op());
        }));
        let result = rx.await;

        // Reap the finished task and clear it before releasing the guard.
        Self::drain(&mut inflight).await;
        result.unwrap_or_else(|_| Err(task_failed()))
    }

    fn sync_inner(file: &File, partition: &str, name: &[u8]) -> Result<(), Error> {
        file.sync_all()
            .map_err(|e| Error::BlobSyncFailed(partition.to_string(), hex(name), e.into()))
    }

    fn write_single_at(file: &File, offset: u64, buf: &[u8]) -> Result<(), Error> {
        file.write_all_at(buf, offset)?;
        Ok(())
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
        let file = self.file.clone();
        let pool = self.pool.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        // Wait for any in-flight mutation so this read sees it.
        self.wait_for_inflight().await;
        task::spawn_blocking(move || {
            if let Some(buf) = bufs.as_single_mut() {
                // Read directly into the single buffer (zero-copy).
                file.read_exact_at(buf.as_mut(), offset)?;
            } else {
                // Read into a temporary contiguous buffer and copy back to preserve structure.
                // SAFETY: `len` bytes are filled via read_exact_at below.
                let mut temp = unsafe { pool.alloc_len(len) };
                file.read_exact_at(temp.as_mut(), offset)?;
                bufs.copy_from_slice(temp.as_ref());
            }
            Ok(bufs)
        })
        .await
        .map_err(|_| Error::ReadFailed)?
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        let file = self.file.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        self.run_ordered(
            move || match bufs.try_into_single() {
                Ok(buf) => Self::write_single_at(&file, offset, buf.as_ref()),
                Err(bufs) => Self::write_vectored_at(&file, offset, bufs, None),
            },
            || Error::WriteFailed,
        )
        .await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let file = self.file.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let op = move || Self::write_vectored_at(&file, offset, bufs, Some(libc::RWF_SYNC));
            } else {
                let partition = self.partition.clone();
                let name = self.name.clone();
                let op = move || {
                    Self::write_vectored_at(&file, offset, bufs, None)?;
                    Self::sync_inner(&file, &partition, &name)
                };
            }
        }
        self.run_ordered(op, || Error::WriteFailed).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.file.clone();
        let len = len
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        let partition = self.partition.clone();
        let name = self.name.clone();
        self.run_ordered(
            move || {
                file.set_len(len)
                    .map_err(|e| Error::BlobResizeFailed(partition, hex(&name), e.into()))
            },
            || {
                Error::BlobResizeFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    std::io::Error::other("resize task failed").into(),
                )
            },
        )
        .await
    }

    async fn sync(&self) -> Result<(), Error> {
        // Wait for any in-flight mutation so this sync covers it. The sync changes no
        // bytes, so even a dropped sync that finishes late cannot undo anything that
        // comes after it.
        self.wait_for_inflight().await;
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
        self.wait_for_inflight().await;
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
