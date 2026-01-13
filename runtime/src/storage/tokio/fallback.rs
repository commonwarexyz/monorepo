use super::Header;
use crate::Error;
use bytes::{Buf, BufMut};
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
    async fn read_at(&self, mut buf: impl BufMut + Send, offset: u64) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        let target_len = buf.remaining_mut();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::ReadFailed)?;
        // Read directly into caller's buffer using read_buf
        let mut read = 0;
        while read < target_len {
            let n = file
                .read_buf(&mut buf)
                .await
                .map_err(|_| Error::ReadFailed)?;
            if n == 0 {
                return Err(Error::ReadFailed);
            }
            read += n;
        }
        Ok(())
    }

    async fn write_at(&self, mut buf: impl Buf + Send, offset: u64) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;
        // Write directly from caller's buffer
        file.write_all_buf(&mut buf)
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
