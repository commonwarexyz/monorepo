use crate::Error;
use commonware_utils::{from_hex, hex, StableBuf};
use std::sync::Arc;
use std::{io::SeekFrom, path::PathBuf};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
};

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
    lock: Arc<AsyncMutex<()>>,
    cfg: Config,
}

impl Storage {
    pub fn new(cfg: Config) -> Self {
        Self {
            lock: AsyncMutex::new(()).into(),
            cfg,
        }
    }
}

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    // Files must be seeked prior to any read or write operation and are thus
    // not safe to concurrently interact with. If we switched to mapping files
    // we could remove this lock.
    file: Arc<AsyncMutex<fs::File>>,
}

impl Blob {
    fn new(partition: String, name: &[u8], file: fs::File) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(AsyncMutex::new(file)),
        }
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Blob, u64), Error> {
        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

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
            .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e))?;

        // Set the maximum buffer size
        file.set_max_buf_size(self.cfg.maximum_buffer_size);

        // Get the file length
        let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();

        // Construct the blob
        Ok((Blob::new(partition.into(), name, file), len))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

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
        let _guard = self.lock.lock().await;

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
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        // Ensure the read is within bounds
        let mut file = self.file.lock().await;
        let mut buf = buf.into();
        // Perform the read
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::ReadFailed)?;
        file.read_exact(buf.as_mut())
            .await
            .map_err(|_| Error::ReadFailed)?;
        Ok(buf)
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        // Perform the write
        let mut file = self.file.lock().await;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;
        file.write_all(buf.into().as_ref())
            .await
            .map_err(|_| Error::WriteFailed)?;
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        // Perform the truncate
        let file = self.file.lock().await;
        file.set_len(len)
            .await
            .map_err(|e| Error::BlobTruncateFailed(self.partition.clone(), hex(&self.name), e))?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.lock().await;
        file.sync_all()
            .await
            .map_err(|e| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), e))
    }

    async fn close(self) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        file.sync_all()
            .await
            .map_err(|e| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), e))?;
        file.shutdown()
            .await
            .map_err(|e| Error::BlobCloseFailed(self.partition.clone(), hex(&self.name), e))
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::{
        tests::run_storage_tests,
        tokio::{Config, Storage},
    };
    use rand::{Rng as _, SeedableRng};
    use std::env;

    #[tokio::test]
    async fn test_storage() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory = env::temp_dir().join(format!("storage_tokio_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config);
        run_storage_tests(storage).await;
    }
}
