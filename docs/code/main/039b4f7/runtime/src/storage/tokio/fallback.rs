use crate::Error;
use commonware_utils::{hex, StableBuf};
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
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        let mut file = self.file.lock().await;
        let mut buf = buf.into();
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::ReadFailed)?;
        file.read_exact(buf.as_mut())
            .await
            .map_err(|_| Error::ReadFailed)?;
        Ok(buf)
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;
        file.write_all(buf.into().as_ref())
            .await
            .map_err(|_| Error::WriteFailed)?;
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.file.lock().await;
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
