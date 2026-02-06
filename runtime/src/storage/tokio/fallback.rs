use super::Header;
use crate::{BufferPool, Error, IoBufs, IoBufsMut};
use commonware_utils::hex;
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
}

impl Blob {
    pub fn new(partition: String, name: &[u8], file: fs::File, pool: BufferPool) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(Mutex::new(file)),
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
        // SAFETY: `len` bytes are filled via read_exact below.
        unsafe { buf.prepare_read(len)? };
        let mut file = self.file.lock().await;
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::ReadFailed)?;

        match buf {
            IoBufsMut::Single(mut single) => {
                // Read directly into the single buffer
                file.read_exact(single.as_mut())
                    .await
                    .map_err(|_| Error::ReadFailed)?;
                Ok(IoBufsMut::Single(single))
            }
            IoBufsMut::Chunked(chunks) => {
                // Read into a temporary buffer and copy to preserve the chunked structure
                let mut temp = self.pool.alloc(len);
                // SAFETY: `len` bytes are filled via read_exact below.
                unsafe { temp.prepare_read(len)? };
                file.read_exact(temp.as_mut())
                    .await
                    .map_err(|_| Error::ReadFailed)?;
                let mut bufs = IoBufsMut::Chunked(chunks);
                bufs.copy_from_slice(temp.as_ref());
                Ok(bufs)
            }
        }
    }

    async fn write_at(&self, offset: u64, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;
        file.write_all_buf(&mut buf.into())
            .await
            .map_err(|_| Error::WriteFailed)?;
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.file.lock().await;
        let len = len
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        file.set_len(len)
            .await
            .map_err(|e| Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e))?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.lock().await;
        file.sync_all()
            .await
            .map_err(|e| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), e))
    }
}
