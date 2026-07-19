use super::Header;
use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut};
use commonware_codec::Encode;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
use std::{
    io::SeekFrom,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
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
    /// Version recorded in the blob header, needed to rewrite it at sync.
    blob_version: u16,
    /// The pruned floor: bytes below it were dropped. Seeded from the
    /// header at open and persisted back at sync while `floor_dirty`.
    floor: Arc<AtomicU64>,
    /// Whether the in-RAM floor has advanced past the persisted one.
    floor_dirty: Arc<AtomicBool>,
}

impl Blob {
    pub fn new(
        partition: String,
        name: &[u8],
        file: fs::File,
        pool: BufferPool,
        blob_version: u16,
        floor: u64,
    ) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(Mutex::new(file)),
            pool,
            blob_version,
            floor: Arc::new(AtomicU64::new(floor)),
            floor_dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn write_at_inner(
        file: &mut fs::File,
        offset: u64,
        bufs: &mut IoBufs,
    ) -> Result<(), Error> {
        let offset = offset
            .checked_add(Header::DATA_OFFSET_U64)
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

    async fn sync_inner(
        file: &mut fs::File,
        partition: &str,
        name: &[u8],
        blob_version: u16,
        floor: &AtomicU64,
        floor_dirty: &AtomicBool,
    ) -> Result<(), Error> {
        // A dirty floor is rewritten into the header by the same sync that
        // makes the pruned state durable. The flag clears only after a
        // successful sync (a failure leaves it set for the next attempt),
        // and only if no concurrent prune advanced the floor past the
        // value written.
        let dirty = floor_dirty.load(Ordering::Relaxed);
        let synced_floor = floor.load(Ordering::Relaxed);
        if dirty {
            let header = Header::with_floor(blob_version, synced_floor);
            file.seek(SeekFrom::Start(0))
                .await
                .map_err(|_| Error::WriteFailed)?;
            file.write_all(&header.encode())
                .await
                .map_err(|_| Error::WriteFailed)?;
        }
        file.sync_all()
            .await
            .map_err(|e| Error::BlobSyncFailed(partition.to_string(), hex(name), e.into()))?;
        if dirty && floor.load(Ordering::Relaxed) == synced_floor {
            floor_dirty.store(false, Ordering::Relaxed);
        }
        Ok(())
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
        let floor = self.floor.load(Ordering::Relaxed);
        if offset < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        let mut file = self.file.lock().await;
        let offset = offset
            .checked_add(Header::DATA_OFFSET_U64)
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
        let floor = self.floor.load(Ordering::Relaxed);
        if offset < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        let mut file = self.file.lock().await;
        Self::write_at_inner(&mut file, offset, &mut bufs).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let mut bufs = bufs.into();
        let floor = self.floor.load(Ordering::Relaxed);
        if offset < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        if !bufs.has_remaining() {
            return Ok(());
        }

        let mut file = self.file.lock().await;
        Self::write_at_inner(&mut file, offset, &mut bufs).await?;
        Self::sync_inner(
            &mut file,
            &self.partition,
            &self.name,
            self.blob_version,
            &self.floor,
            &self.floor_dirty,
        )
        .await
    }

    async fn prune(&self, offset: u64) -> Result<(), Error> {
        let file = self.file.lock().await;
        let size = file
            .metadata()
            .await
            .map_err(|e| {
                Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e.into())
            })?
            .len()
            .saturating_sub(Header::DATA_OFFSET_U64);
        if offset > size {
            return Err(Error::BlobInsufficientLength);
        }
        // A floor advance is not accompanied by a hole punch: this backend
        // serves non-Unix platforms through portable `tokio::fs` APIs,
        // which expose no way to deallocate a file range, so pruned bytes
        // keep their space until the blob is removed.
        let old = self.floor.fetch_max(offset, Ordering::Relaxed);
        if offset > old {
            self.floor_dirty.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    fn floor(&self) -> u64 {
        self.floor.load(Ordering::Relaxed)
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let floor = self.floor.load(Ordering::Relaxed);
        if len < floor {
            return Err(Error::OffsetPruned(
                self.partition.clone(),
                hex(&self.name),
                floor,
            ));
        }
        let file = self.file.lock().await;
        let len = len
            .checked_add(Header::DATA_OFFSET_U64)
            .ok_or(Error::OffsetOverflow)?;
        file.set_len(len).await.map_err(|e| {
            Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e.into())
        })?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        Self::sync_inner(
            &mut file,
            &self.partition,
            &self.name,
            self.blob_version,
            &self.floor,
            &self.floor_dirty,
        )
        .await
    }

    async fn start_sync(&self) -> Handle<()> {
        let (tx, rx) = oneshot::channel();
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        let blob_version = self.blob_version;
        let floor = self.floor.clone();
        let floor_dirty = self.floor_dirty.clone();
        tokio::spawn(async move {
            let mut file = file.lock().await;
            let result = Self::sync_inner(
                &mut file,
                &partition,
                &name,
                blob_version,
                &floor,
                &floor_dirty,
            )
            .await;
            let _ = tx.send(result);
        });
        Handle::from_receiver(rx)
    }
}
