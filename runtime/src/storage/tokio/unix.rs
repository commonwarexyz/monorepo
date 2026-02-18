use super::Header;
use crate::{BufferPool, Error, IoBufs, IoBufsMut};
use commonware_utils::hex;
use std::{fs::File, os::unix::fs::FileExt, sync::Arc};
use tokio::task;

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
    pool: BufferPool,
}

impl Blob {
    pub fn new(partition: String, name: &[u8], file: File, pool: BufferPool) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
            pool,
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
        let file = self.file.clone();
        let pool = self.pool.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
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
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            file.write_all_at(bufs.coalesce().as_ref(), offset)?;
            Ok(())
        })
        .await
        .map_err(|_| Error::WriteFailed)?
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.file.clone();
        let len = len
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || file.set_len(len))
            .await
            .map_err(|e| e.into())
            .and_then(|r| r)
            .map_err(|e| Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e))?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.clone();
        task::spawn_blocking(move || file.sync_all())
            .await
            .map_err(|e| e.into())
            .and_then(|r| r)
            .map_err(|e| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), e))?;
        Ok(())
    }
}
