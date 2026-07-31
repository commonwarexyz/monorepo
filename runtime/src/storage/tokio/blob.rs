use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, WriteOptions};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
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

// Cap iovec batches at the kernel's IOV_MAX (1024): larger submissions fail with
// EINVAL. Larger batches reduce syscall count with no measurable per-iovec penalty.
const IOVEC_BATCH_SIZE: usize = 1024;

/// Page-cache policy for one write request.
enum Cache {
    /// Use the operating system's normal page-cache behavior.
    Enabled,
    /// Best-effort bypass of the page cache while the backend supports it.
    Disabled(Arc<AtomicBool>),
}

impl Cache {
    /// Return whether the next submission should request cache bypass.
    fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled(supported) if supported.load(Ordering::Relaxed))
    }

    /// Record that cache bypass is unsupported and use normal caching when retried.
    fn fallback(&mut self) -> bool {
        let Self::Disabled(supported) = std::mem::replace(self, Self::Enabled) else {
            return false;
        };
        supported.store(false, Ordering::Relaxed);
        true
    }
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
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted write.
    dont_cache_supported: Arc<AtomicBool>,
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
        }
    }

    fn sync_inner(file: &File, partition: &str, name: &[u8]) -> Result<(), Error> {
        // Data durability is the contract (see [crate::Blob::sync]): fdatasync covers the
        // data and the metadata needed to retrieve it (including size), skipping
        // timestamp-only journal commits. Non-Linux platforms keep the stronger sync_all
        // for its platform-specific durability semantics.
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
    /// `flags` apply to every submission, so callers must only pass durability flags for
    /// writes that fit a single submission (see [WriteOptions::SYNC]). Hinted submissions
    /// carry `RWF_DONTCACHE` on Linux while the backend may support it. An EOPNOTSUPP clears
    /// that capability and retries the submission without the hint.
    fn write_vectored_at(
        file: &File,
        mut offset: u64,
        mut bufs: IoBufs,
        flags: Option<libc::c_int>,
        mut cache: Cache,
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
                if err.raw_os_error() == Some(libc::EOPNOTSUPP) && attempted_dont_cache {
                    // The kernel or filesystem does not support RWF_DONTCACHE: fall back
                    // to cached writes for this and future hinted writes.
                    if cache.fallback() {
                        continue;
                    }
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

    async fn write_at_inner(
        &self,
        offset: u64,
        bufs: IoBufs,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let file = self.file.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        if !bufs.has_remaining() {
            return Ok(());
        }

        let sync = options.contains(WriteOptions::SYNC);
        let cache = if options.contains(WriteOptions::DONT_CACHE) {
            Cache::Disabled(self.dont_cache_supported.clone())
        } else {
            Cache::Enabled
        };
        let partition = sync.then(|| self.partition.clone());
        let name = sync.then(|| self.name.clone());
        task::spawn_blocking(move || {
            let bufs = if !sync && !cache.is_disabled() {
                match bufs.try_into_single() {
                    Ok(buf) => return Self::write_single_at(&file, offset, buf.as_ref()),
                    Err(bufs) => bufs,
                }
            } else {
                bufs
            };

            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    // Fuse durability into the write only when it fits one submission:
                    // fusing every batch would serialize the batches behind per-call
                    // durability waits, while plain batches keep the device pipelined
                    // and pay a single fdatasync at the end.
                    let fused = sync && bufs.chunk_count() <= IOVEC_BATCH_SIZE;
                    Self::write_vectored_at(
                        &file,
                        offset,
                        bufs,
                        fused.then_some(libc::RWF_DSYNC),
                        cache,
                    )?;
                    if sync && !fused {
                        file.sync_data().map_err(|e| {
                            Error::BlobSyncFailed(
                                partition.expect("sync write has a partition"),
                                hex(name.as_deref().expect("sync write has a name")),
                                e.into(),
                            )
                        })?;
                    }
                } else {
                    Self::write_vectored_at(&file, offset, bufs, None, cache)?;
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
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
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

    async fn write_at_with(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        self.write_at_inner(offset, bufs.into(), options).await
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
