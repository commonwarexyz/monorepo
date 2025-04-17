use crate::Error;
use commonware_utils::{from_hex, hex};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prometheus_client::registry::Registry;
use std::io::SeekFrom;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
};

pub struct Metrics {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,
}

impl Metrics {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    pub fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            open_blobs: Gauge::default(),
            storage_reads: Counter::default(),
            storage_read_bytes: Counter::default(),
            storage_writes: Counter::default(),
            storage_write_bytes: Counter::default(),
        };

        registry.register(
            "open_blobs",
            "Number of open blobs",
            metrics.open_blobs.clone(),
        );
        registry.register(
            "storage_reads",
            "Total number of disk reads",
            metrics.storage_reads.clone(),
        );
        registry.register(
            "storage_read_bytes",
            "Total amount of data read from disk",
            metrics.storage_read_bytes.clone(),
        );
        registry.register(
            "storage_writes",
            "Total number of disk writes",
            metrics.storage_writes.clone(),
        );
        registry.register(
            "storage_write_bytes",
            "Total amount of data written to disk",
            metrics.storage_write_bytes.clone(),
        );

        metrics
    }
}

#[derive(Clone)]
pub struct Config {
    pub storage_directory: PathBuf,
    pub maximum_buffer_size: usize,
}

impl Config {
    pub fn new(storage_directory: PathBuf, maximum_buffer_size: usize) -> Self {
        Self {
            storage_directory,
            maximum_buffer_size,
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    metrics: Arc<Metrics>,
    fs: Arc<AsyncMutex<()>>,
    cfg: Config,
}

impl Storage {
    pub fn new(metrics: &mut Registry, cfg: Config) -> Self {
        Self {
            metrics: Arc::new(Metrics::new(metrics)),
            fs: AsyncMutex::new(()).into(),
            cfg,
        }
    }
}

pub struct Blob {
    metrics: Arc<Metrics>,
    partition: String,
    name: Vec<u8>,
    // Files must be seeked prior to any read or write operation and are thus
    // not safe to concurrently interact with. If we switched to mapping files
    // we could remove this lock.
    //
    // We also track the virtual file size because metadata isn't updated until
    // the file is synced (not to mention it is a lot less fs calls).
    file: Arc<AsyncMutex<(fs::File, u64)>>,
}

impl Blob {
    fn new(
        metrics: Arc<Metrics>,
        partition: String,
        name: &[u8],
        file: fs::File,
        len: u64,
    ) -> Self {
        metrics.open_blobs.inc();
        Self {
            metrics,
            partition,
            name: name.into(),
            file: Arc::new(AsyncMutex::new((file, len))),
        }
    }
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        // We implement `Clone` manually to ensure the `open_blobs` gauge is updated.
        self.metrics.open_blobs.inc();
        Self {
            metrics: self.metrics.clone(),
            partition: self.partition.clone(),
            name: self.name.clone(),
            file: self.file.clone(),
        }
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Blob, Error> {
        // Acquire the filesystem lock
        let _guard = self.fs.lock().await;

        // Construct the full path
        let path = self.cfg.storage_directory.join(partition).join(hex(name));
        let parent = match path.parent() {
            Some(parent) => parent,
            None => return Err(Error::PartitionCreationFailed(partition.into())),
        };

        // Create the partition directory if it does not exist
        fs::create_dir_all(parent)
            .await
            .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file in read-write mode, create if it does not exist
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .await
            .map_err(|_| Error::BlobOpenFailed(partition.into(), hex(name)))?;

        // Set the maximum buffer size
        file.set_max_buf_size(self.cfg.maximum_buffer_size);

        // Get the file length
        let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();

        // Construct the blob
        Ok(Blob::new(
            self.metrics.clone(),
            partition.into(),
            name,
            file,
            len,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        // Acquire the filesystem lock
        let _guard = self.fs.lock().await;

        // Remove all related files
        let path = self.cfg.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_path = path.join(hex(name));
            fs::remove_file(blob_path)
                .await
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;
        } else {
            fs::remove_dir_all(path)
                .await
                .map_err(|_| Error::PartitionMissing(partition.into()))?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        // Acquire the filesystem lock
        let _guard = self.fs.lock().await;

        // Scan the partition directory
        let path = self.cfg.storage_directory.join(partition);
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|_| Error::PartitionMissing(partition.into()))?;
        let mut blobs = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| Error::ReadFailed)? {
            let file_type = entry.file_type().await.map_err(|_| Error::ReadFailed)?;
            if !file_type.is_file() {
                return Err(Error::PartitionCorrupt(partition.into()));
            }
            if let Some(name) = entry.file_name().to_str() {
                let name = from_hex(name).ok_or(Error::PartitionCorrupt(partition.into()))?;
                blobs.push(name);
            }
        }
        Ok(blobs)
    }
}

impl crate::Blob for Blob {
    async fn len(&self) -> Result<u64, Error> {
        let (_, len) = *self.file.lock().await;
        Ok(len)
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        // Ensure the read is within bounds
        let mut file = self.file.lock().await;
        if offset + buf.len() as u64 > file.1 {
            return Err(Error::BlobInsufficientLength);
        }

        // Perform the read
        file.0
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::ReadFailed)?;
        file.0
            .read_exact(buf)
            .await
            .map_err(|_| Error::ReadFailed)?;
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(buf.len() as u64);
        Ok(())
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        // Perform the write
        let mut file = self.file.lock().await;
        file.0
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;
        file.0
            .write_all(buf)
            .await
            .map_err(|_| Error::WriteFailed)?;

        // Update the virtual file size
        let max_len = offset + buf.len() as u64;
        if max_len > file.1 {
            file.1 = max_len;
        }
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf.len() as u64);
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        // Perform the truncate
        let mut file = self.file.lock().await;
        file.0
            .set_len(len)
            .await
            .map_err(|_| Error::BlobTruncateFailed(self.partition.clone(), hex(&self.name)))?;

        // Update the virtual file size
        file.1 = len;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.lock().await;
        file.0
            .sync_all()
            .await
            .map_err(|_| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name)))
    }

    async fn close(self) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        file.0
            .sync_all()
            .await
            .map_err(|_| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name)))?;
        file.0
            .shutdown()
            .await
            .map_err(|_| Error::BlobCloseFailed(self.partition.clone(), hex(&self.name)))
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        self.metrics.open_blobs.dec();
    }
}
