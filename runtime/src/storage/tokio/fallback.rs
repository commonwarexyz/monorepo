use super::Header;
use crate::{Error, IoBufs, IoBufsMut};
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
}

impl Blob {
    pub fn new(partition: String, name: &[u8], file: fs::File) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(Mutex::new(file)),
        }
    }
}

impl crate::Blob for Blob {
    async fn read_at(
        &self,
        offset: u64,
        buf: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let buf = buf.into();
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
            IoBufsMut::Chunked(mut chunks) => {
                // Read into a temporary buffer and copy to preserve the chunked structure
                let len: usize = chunks.iter().map(|b| b.len()).sum();
                let mut temp = vec![0u8; len];
                file.read_exact(&mut temp)
                    .await
                    .map_err(|_| Error::ReadFailed)?;
                let mut offset = 0;
                for chunk in chunks.iter_mut() {
                    let chunk_len = chunk.len();
                    chunk
                        .as_mut()
                        .copy_from_slice(&temp[offset..offset + chunk_len]);
                    offset += chunk_len;
                }
                Ok(IoBufsMut::Chunked(chunks))
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
