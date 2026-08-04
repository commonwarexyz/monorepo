//! The ordinary blob handle: file-as-truth, matching the per-file backends.
//!
//! Blob files carry the standard header layouts (V1 for created blobs; adopted legacy
//! files keep whatever layout they have), so every file remains readable by the
//! per-file backends and adoption never copies payload. Logical offsets translate by
//! the header's data offset.
//!
//! Content operations never touch the committer: writes go to the blob's own file,
//! `resize` is an immediate truncate, and `sync` is a barrier on the blob's own
//! descriptor. The one addition is the dentry wave: a blob's first successful
//! durability event also syncs its directory and the root (rule M: acknowledged bytes
//! must never be reachable only through an unsynced dentry). Later syncs skip it.

use super::medium::{File, Medium};
use crate::{Error, Handle, IoBufMut, IoBufs, IoBufsMut, WriteOptions};
use bytes::Buf as _;
use commonware_formatting::hex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A handle to one ordinary blob. Clones share the same file.
pub struct Blob<M: Medium> {
    medium: M,
    file: M::File,
    partition: String,
    /// The file's name in the partition directory (hex of the blob name).
    filename: String,
    /// Where blob offset 0 sits in the file (the header layout's data offset).
    data_offset: u64,
    /// Whether some handle already completed the dentry wave; shared across clones so
    /// steady-state syncs are exactly one barrier.
    dentry_synced: Arc<AtomicBool>,
}

impl<M: Medium> Clone for Blob<M> {
    fn clone(&self) -> Self {
        Self {
            medium: self.medium.clone(),
            file: self.file.clone(),
            partition: self.partition.clone(),
            filename: self.filename.clone(),
            data_offset: self.data_offset,
            dentry_synced: self.dentry_synced.clone(),
        }
    }
}

impl<M: Medium> Blob<M> {
    pub(super) fn new(
        medium: M,
        file: M::File,
        partition: &str,
        name: &[u8],
        data_offset: u64,
    ) -> Self {
        Self {
            medium,
            file,
            partition: partition.to_string(),
            filename: hex(name),
            data_offset,
            dentry_synced: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Translates a blob offset into its file offset.
    fn physical(&self, offset: u64) -> Result<u64, Error> {
        offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)
    }

    /// One durability event: barrier the file, and on the first ever completion make
    /// the dentry chain durable too (directory, then root). Ordering within the wave
    /// is irrelevant; everything completes before Ok, which is when the bytes become
    /// load-bearing.
    async fn barrier(&self) -> Result<(), Error> {
        self.file.sync().await?;
        if !self.dentry_synced.load(Ordering::Acquire) {
            self.medium.sync_dir(&self.partition).await?;
            self.medium.sync_root().await?;
            self.dentry_synced.store(true, Ordering::Release);
        }
        Ok(())
    }
}

impl<M: Medium> crate::Blob for Blob<M> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, IoBufMut::with_capacity(len))
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let mut bufs = bufs.into();
        let bytes = self.file.read_at(self.physical(offset)?, len).await?;
        // SAFETY: `copy_from_slice` fills exactly `len` bytes below.
        unsafe { bufs.set_len(len) };
        bufs.copy_from_slice(&bytes);
        Ok(bufs)
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }
        self.file.write_at(self.physical(offset)?, bufs).await?;
        if options.contains(WriteOptions::SYNC) {
            self.barrier().await?;
        }
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.file.set_len(self.physical(len)?).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.barrier().await
    }

    async fn start_sync(&self) -> Handle<()> {
        // Ordinary syncs are the blob's own barrier; there is no committer queue to
        // ride, so the sync simply runs here.
        Handle::ready(self.barrier().await)
    }
}
