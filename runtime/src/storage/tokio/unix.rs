use super::super::PendingHeader;
use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
use std::{
    fs::File,
    io::IoSlice,
    os::{fd::AsRawFd, unix::fs::FileExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{sync::Mutex, task};

// Cap iovec batch size: larger iovecs reduce syscall count but increase
// per-write kernel setup overhead.
const IOVEC_BATCH_SIZE: usize = 32;

/// A new blob's uncommitted creation: everything the first durability request needs to run the
/// deferred two-phase commit (the withheld header bytes and the directories whose entries it
/// must make durable). Held by the blob until that commit completes; while present, every
/// durability request routes through the commit path.
struct PendingCommit {
    header: PendingHeader,
    partition_directory: PathBuf,
    storage_directory: PathBuf,
}

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// First-durability header commit, shared by cloned handles.
    pending_commit: Arc<Mutex<Option<Arc<PendingCommit>>>>,
}

impl Blob {
    pub(super) fn new(
        partition: String,
        name: &[u8],
        file: File,
        pool: BufferPool,
        data_offset: u64,
        pending: Option<(PendingHeader, PathBuf, PathBuf)>,
    ) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
            pool,
            data_offset,
            pending_commit: Arc::new(Mutex::new(pending.map(
                |(header, partition_directory, storage_directory)| {
                    Arc::new(PendingCommit {
                        header,
                        partition_directory,
                        storage_directory,
                    })
                },
            ))),
        }
    }

    fn sync_dir(path: &Path) -> Result<(), Error> {
        let dir = File::open(path).map_err(|e| {
            Error::BlobOpenFailed(
                path.to_string_lossy().into_owned(),
                "directory".into(),
                e.into(),
            )
        })?;
        dir.sync_all().map_err(|e| {
            Error::BlobSyncFailed(
                path.to_string_lossy().into_owned(),
                "directory".into(),
                e.into(),
            )
        })
    }

    /// Runs a pending first commit's two-phase I/O: publishes the prelude and makes it, all
    /// prior user writes, the file length, and both directory entries durable, then issues the
    /// CRC commit record and makes it durable in turn. Must run under the creation gate.
    fn commit_inner(
        file: &File,
        partition: &str,
        name: &[u8],
        pending: &PendingCommit,
    ) -> Result<(), Error> {
        // Phase 1: publish the prelude and make it, all prior user writes, and both directory
        // entries durable before the CRC can be issued.
        Self::write_single_at(file, 0, pending.header.prelude())?;
        Self::sync_inner(file, partition, name)?;
        Self::sync_dir(&pending.partition_directory)?;
        Self::sync_dir(&pending.storage_directory)?;

        // Phase 2: the CRC is the commit record. Once it is durable, the preceding barriers are
        // known to have completed.
        Self::write_single_at(
            file,
            PendingHeader::CHECKSUM_OFFSET,
            pending.header.checksum(),
        )?;
        Self::sync_inner(file, partition, name)
    }

    /// Completes this blob's pending first commit, if any, returning whether one was performed.
    /// The commit runs on a detached task so a dropped caller cannot split its two-phase I/O;
    /// concurrent clones serialize on the pending lock, and the loser sees no pending commit.
    async fn commit_pending(&self) -> Result<bool, Error> {
        let blob = self.clone();
        task::spawn(async move { blob.commit_pending_inner().await })
            .await
            .map_err(|_| Error::WriteFailed)?
    }

    async fn commit_pending_inner(&self) -> Result<bool, Error> {
        let mut pending = self.pending_commit.lock().await;
        let Some(commit) = pending.as_ref().cloned() else {
            return Ok(false);
        };

        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || Self::commit_inner(&file, &partition, &name, &commit))
            .await
            .map_err(|_| Error::WriteFailed)??;
        *pending = None;
        Ok(true)
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

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        let file = self.file.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
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
        // While a first commit is pending, a non-empty write_at_sync serves as that commit:
        // route through write_at + sync so the two-phase commit runs (the RWF_SYNC fast path
        // syncs only the file, not the header commit or directory entries).
        if self.pending_commit.lock().await.is_some() {
            if !bufs.has_remaining() {
                return Ok(());
            }
            crate::Blob::write_at(self, offset, bufs).await?;
            return crate::Blob::sync(self).await;
        }
        let file = self.file.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        cfg_if! {
            if #[cfg(target_os = "linux")] {
                task::spawn_blocking(move || {
                    Self::write_vectored_at(&file, offset, bufs, Some(libc::RWF_SYNC))
                })
                .await
                .map_err(|_| Error::WriteFailed)?
            } else {
                let partition = self.partition.clone();
                let name = self.name.clone();
                task::spawn_blocking(move || {
                    Self::write_vectored_at(&file, offset, bufs, None)?;
                    Self::sync_inner(&file, &partition, &name)
                })
                .await
                .map_err(|_| Error::WriteFailed)?
            }
        }
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
        if self.commit_pending().await? {
            return Ok(());
        }
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
        let blob = self.clone();
        tokio::spawn(async move {
            let result = crate::Blob::sync(&blob).await;
            let _ = tx.send(result);
        });
        Handle::from_receiver(rx)
    }
}
