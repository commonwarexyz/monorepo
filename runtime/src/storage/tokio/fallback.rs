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

    async fn write_single_at(file: &mut fs::File, buf: &[u8]) -> Result<(), Error> {
        file.write_all(buf).await.map_err(|_| Error::WriteFailed)
    }

    async fn write_vectored_at(file: &mut fs::File, bufs: &mut IoBufs) -> Result<(), Error> {
        file.write_all_buf(bufs)
            .await
            .map_err(|_| Error::WriteFailed)
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
            .checked_add(Header::SIZE_U64)
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
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;

        if let Some(buf) = bufs.as_single() {
            Self::write_single_at(&mut file, buf.as_ref()).await
        } else {
            Self::write_vectored_at(&mut file, &mut bufs).await
        }
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
