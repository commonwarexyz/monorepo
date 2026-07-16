use super::Header;
use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
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

/// Direct I/O (`O_DIRECT`) alignment contract: file offsets, lengths, and
/// buffer addresses must be multiples of this. Matches the volume's block
/// size and covers common logical-block sizes.
pub(super) const DIRECT_ALIGNMENT: u64 = 4096;

/// Physical offset of logical byte 0 in a direct blob: the header's block,
/// padded so block-aligned logical offsets stay block-aligned on disk.
pub(super) const DIRECT_DATA_OFFSET: u64 = DIRECT_ALIGNMENT;

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
    pool: BufferPool,
    /// Physical offset of logical byte 0 (the header shift).
    data_offset: u64,
    /// Whether the `O_DIRECT` alignment contract is enforced. Linux-only:
    /// macOS direct blobs use `F_NOCACHE`, which has no alignment
    /// requirement (see [`super::Config::direct_io`]).
    direct: bool,
}

impl Blob {
    pub fn new(partition: String, name: &[u8], file: File, pool: BufferPool, direct: bool) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
            pool,
            data_offset: if direct {
                DIRECT_DATA_OFFSET
            } else {
                Header::SIZE_U64
            },
            direct: direct && cfg!(target_os = "linux"),
        }
    }

    /// Assert the `O_DIRECT` contract for one I/O buffer. Unaligned I/O
    /// through a direct blob is API misuse: `O_DIRECT` would fail it with
    /// `EINVAL`, so fail loudly at the source instead.
    fn assert_direct_buf(buf: &[u8]) {
        assert!(
            (buf.as_ptr() as usize).is_multiple_of(DIRECT_ALIGNMENT as usize)
                && buf.len().is_multiple_of(DIRECT_ALIGNMENT as usize),
            "unaligned direct I/O buffer (addr {:p}, len {})",
            buf.as_ptr(),
            buf.len()
        );
    }

    /// Assert the `O_DIRECT` contract for a physical file offset.
    fn assert_direct_offset(offset: u64) {
        assert!(
            offset.is_multiple_of(DIRECT_ALIGNMENT),
            "unaligned direct I/O offset {offset}"
        );
    }

    fn sync_inner(file: &File, partition: &str, name: &[u8]) -> Result<(), Error> {
        file.sync_all()
            .map_err(|e| Error::BlobSyncFailed(partition.to_string(), hex(name), e.into()))
    }

    fn write_single_at(file: &File, offset: u64, buf: &[u8], direct: bool) -> Result<(), Error> {
        if direct {
            Self::assert_direct_offset(offset);
            Self::assert_direct_buf(buf);
        }
        file.write_all_at(buf, offset)?;
        Ok(())
    }

    fn write_vectored_at(
        file: &File,
        mut offset: u64,
        mut bufs: IoBufs,
        flags: Option<libc::c_int>,
        direct: bool,
    ) -> Result<(), Error> {
        if direct {
            Self::assert_direct_offset(offset);
        }
        while bufs.has_remaining() {
            let mut io_slices = [IoSlice::new(&[]); IOVEC_BATCH_SIZE];
            let io_slices_len = bufs.chunks_vectored(&mut io_slices);
            assert!(
                io_slices_len > 0,
                "chunks_vectored should produce at least one slice when bufs has remaining"
            );
            if direct {
                // O_DIRECT applies the alignment contract to every iovec.
                for io_slice in &io_slices[..io_slices_len] {
                    Self::assert_direct_buf(io_slice);
                }
            }

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
        if self.direct {
            Self::assert_direct_offset(offset);
            assert!(
                len.is_multiple_of(DIRECT_ALIGNMENT as usize),
                "unaligned direct I/O read length {len}"
            );
        }
        let direct = self.direct;
        task::spawn_blocking(move || {
            if let Some(buf) = bufs.as_single_mut() {
                // Read directly into the single buffer (zero-copy).
                if direct {
                    Self::assert_direct_buf(buf.as_ref());
                }
                file.read_exact_at(buf.as_mut(), offset)?;
            } else {
                // Read into a temporary contiguous buffer and copy back to preserve structure.
                // SAFETY: `len` bytes are filled via read_exact_at below.
                let mut temp = unsafe { pool.alloc_len(len) };
                if direct {
                    Self::assert_direct_buf(temp.as_ref());
                }
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
        let direct = self.direct;
        task::spawn_blocking(move || match bufs.try_into_single() {
            Ok(buf) => Self::write_single_at(&file, offset, buf.as_ref(), direct),
            Err(bufs) => Self::write_vectored_at(&file, offset, bufs, None, direct),
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
        let file = self.file.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        if !bufs.has_remaining() {
            return Ok(());
        }

        let direct = self.direct;
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                task::spawn_blocking(move || {
                    Self::write_vectored_at(&file, offset, bufs, Some(libc::RWF_SYNC), direct)
                })
                .await
                .map_err(|_| Error::WriteFailed)?
            } else {
                let partition = self.partition.clone();
                let name = self.name.clone();
                task::spawn_blocking(move || {
                    Self::write_vectored_at(&file, offset, bufs, None, direct)?;
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
