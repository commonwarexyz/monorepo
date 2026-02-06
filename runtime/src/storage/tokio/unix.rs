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
        buf: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let mut buf = buf.into();
        // SAFETY: unix.rs fills all `len` bytes via read_exact_at below.
        unsafe { buf.prepare_read(len)? };
        let file = self.file.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || match buf {
            IoBufsMut::Single(mut single) => {
                file.read_exact_at(single.as_mut(), offset)?;
                Ok(IoBufsMut::Single(single))
            }
            IoBufsMut::Chunked(mut chunks) => {
                let mut temp = vec![0u8; len];
                file.read_exact_at(&mut temp, offset)?;
                let mut off = 0;
                for chunk in chunks.iter_mut() {
                    let chunk_len = chunk.len();
                    chunk.as_mut().copy_from_slice(&temp[off..off + chunk_len]);
                    off += chunk_len;
                }
                Ok(IoBufsMut::Chunked(chunks))
            }
        })
        .await
        .map_err(|_| Error::ReadFailed)?
    }

    async fn write_at(&self, offset: u64, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let buf = buf.into();
        let file = self.file.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            file.write_all_at(buf.coalesce().as_ref(), offset)?;
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
