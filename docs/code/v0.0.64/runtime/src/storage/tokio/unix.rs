use crate::Error;
use commonware_utils::{hex, StableBuf};
use std::{fs::File, os::unix::fs::FileExt, sync::Arc};
use tokio::task;

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
}

impl Blob {
    pub fn new(partition: String, name: &[u8], file: File) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
        }
    }
}

impl crate::Blob for Blob {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        let file = self.file.clone();
        task::spawn_blocking(move || {
            file.read_exact_at(buf.as_mut(), offset)?;
            Ok(buf)
        })
        .await
        .map_err(|_| Error::ReadFailed)?
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        let buf = buf.into();
        let file = self.file.clone();
        task::spawn_blocking(move || {
            file.write_all_at(buf.as_ref(), offset)?;
            Ok(())
        })
        .await
        .map_err(|_| Error::WriteFailed)?
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let file = self.file.clone();
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
