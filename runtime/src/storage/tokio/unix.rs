use super::Header;
use crate::Error;
use bytes::{Buf, BufMut, BytesMut};
use commonware_utils::hex;
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
    async fn read_at(&self, mut buf: impl BufMut + Send, offset: u64) -> Result<(), Error> {
        let len = buf.remaining_mut();
        let file = self.file.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        // spawn_blocking requires 'static, so we need an owned buffer
        let mut owned = BytesMut::zeroed(len);
        let result = task::spawn_blocking(move || -> std::io::Result<BytesMut> {
            file.read_exact_at(&mut owned, offset)?;
            Ok(owned)
        })
        .await
        .map_err(|_| Error::ReadFailed)??;
        buf.put_slice(&result);
        Ok(())
    }

    async fn write_at(&self, mut buf: impl Buf + Send, offset: u64) -> Result<(), Error> {
        // spawn_blocking requires 'static, so copy from caller's buffer
        // (zero-copy if caller passes Bytes)
        let owned = buf.copy_to_bytes(buf.remaining());
        let file = self.file.clone();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            file.write_all_at(&owned, offset)?;
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
