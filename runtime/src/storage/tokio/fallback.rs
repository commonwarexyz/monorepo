use super::super::PendingHeader;
use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut};
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
use std::{io::SeekFrom, sync::Arc};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
};

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    // Files must be seeked prior to any read or write operation and are thus
    // not safe to concurrently interact with. If we switched to mapping files
    // we could remove this lock.
    file: Arc<Mutex<fs::File>>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// First-durability header commit, shared by cloned handles.
    pending_commit: Arc<Mutex<Option<Arc<PendingCommit>>>>,
}

/// A new blob's uncommitted creation: the withheld header bytes the first durability request
/// must publish. Windows has no directory-sync notion, so name durability is best-effort.
struct PendingCommit {
    header: PendingHeader,
}

impl Blob {
    pub fn new(
        partition: String,
        name: &[u8],
        file: fs::File,
        pool: BufferPool,
        data_offset: u64,
        pending: Option<PendingHeader>,
    ) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(Mutex::new(file)),
            pool,
            data_offset,
            pending_commit: Arc::new(Mutex::new(
                pending.map(|header| Arc::new(PendingCommit { header })),
            )),
        }
    }

    /// Publishes a pending first commit's two-phase I/O: write the prelude and make it (and all
    /// prior user writes) durable, then issue the CRC commit record and make it durable in turn.
    async fn commit_inner(
        file: &mut fs::File,
        partition: &str,
        name: &[u8],
        pending: &PendingCommit,
    ) -> Result<(), Error> {
        // Phase 1: publish the prelude and make it, and all prior user writes, durable before
        // the CRC can be issued.
        Self::write_physical_at(file, 0, pending.header.prelude()).await?;
        Self::sync_inner(file, partition, name).await?;

        // Phase 2: the CRC is the commit record. Once it is durable, the preceding barrier is
        // known to have completed.
        Self::write_physical_at(
            file,
            PendingHeader::CHECKSUM_OFFSET,
            pending.header.checksum(),
        )
        .await?;
        Self::sync_inner(file, partition, name).await
    }

    /// Completes this blob's pending first commit, if any, returning whether one was performed.
    /// The commit runs on a detached task so a dropped caller cannot split its two-phase I/O;
    /// concurrent clones serialize on the pending lock, and the loser sees no pending commit.
    async fn commit_pending(&self) -> Result<bool, Error> {
        let blob = self.clone();
        tokio::spawn(async move { blob.commit_pending_inner().await })
            .await
            .map_err(|_| Error::WriteFailed)?
    }

    async fn commit_pending_inner(&self) -> Result<bool, Error> {
        let mut pending = self.pending_commit.lock().await;
        let Some(commit) = pending.as_ref().cloned() else {
            return Ok(false);
        };

        {
            let mut file = self.file.lock().await;
            Self::commit_inner(&mut file, &self.partition, &self.name, &commit).await?;
        }
        *pending = None;
        Ok(true)
    }

    async fn write_physical_at(file: &mut fs::File, offset: u64, buf: &[u8]) -> Result<(), Error> {
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;
        file.write_all(buf).await.map_err(|_| Error::WriteFailed)
    }

    async fn write_at_inner(
        file: &mut fs::File,
        offset: u64,
        bufs: &mut IoBufs,
        data_offset: u64,
    ) -> Result<(), Error> {
        let offset = offset
            .checked_add(data_offset)
            .ok_or(Error::OffsetOverflow)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;

        if let Some(buf) = bufs.as_single() {
            file.write_all(buf.as_ref())
                .await
                .map_err(|_| Error::WriteFailed)
        } else {
            file.write_all_buf(bufs)
                .await
                .map_err(|_| Error::WriteFailed)
        }
    }

    async fn sync_inner(file: &fs::File, partition: &str, name: &[u8]) -> Result<(), Error> {
        file.sync_all()
            .await
            .map_err(|e| Error::BlobSyncFailed(partition.to_string(), hex(name), e.into()))
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
        let mut file = self.file.lock().await;
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::ReadFailed)?;

        if let Some(buf) = bufs.as_single_mut() {
            // Read directly into the single buffer.
            file.read_exact(buf.as_mut())
                .await
                .map_err(|_| Error::ReadFailed)?;
            Ok(bufs)
        } else {
            // Read into a temporary contiguous buffer and copy back to preserve structure.
            // SAFETY: `len` bytes are filled via read_exact below.
            let mut temp = unsafe { self.pool.alloc_len(len) };
            file.read_exact(temp.as_mut())
                .await
                .map_err(|_| Error::ReadFailed)?;
            bufs.copy_from_slice(temp.as_ref());
            Ok(bufs)
        }
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let mut bufs = bufs.into();
        let mut file = self.file.lock().await;
        Self::write_at_inner(&mut file, offset, &mut bufs, self.data_offset).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let mut bufs = bufs.into();
        // While a first commit is pending, a non-empty write_at_sync serves as that commit:
        // route through write_at + sync so the two-phase commit runs.
        if self.pending_commit.lock().await.is_some() {
            if !bufs.has_remaining() {
                return Ok(());
            }
            crate::Blob::write_at(self, offset, bufs).await?;
            return crate::Blob::sync(self).await;
        }
        if !bufs.has_remaining() {
            return Ok(());
        }

        let mut file = self.file.lock().await;
        Self::write_at_inner(&mut file, offset, &mut bufs, self.data_offset).await?;
        Self::sync_inner(&file, &self.partition, &self.name).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.file.lock().await;
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        file.set_len(len).await.map_err(|e| {
            Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e.into())
        })?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if self.commit_pending().await? {
            return Ok(());
        }
        let file = self.file.lock().await;
        Self::sync_inner(&file, &self.partition, &self.name).await
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
