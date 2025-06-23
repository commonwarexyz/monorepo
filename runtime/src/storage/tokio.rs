use crate::Error;
use commonware_utils::{from_hex, hex, StableBuf};
use std::{fs::File, path::PathBuf, sync::Arc};
use tokio::{fs, sync::Mutex, task};

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
    lock: Arc<Mutex<()>>,
    cfg: Config,
}

impl Storage {
    pub fn new(cfg: Config) -> Self {
        Self {
            lock: Arc::new(Mutex::new(())),
            cfg,
        }
    }
}

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<File>,
}

impl Blob {
    fn new(partition: String, name: &[u8], file: File) -> Self {
        Self {
            partition,
            name: name.into(),
            file: Arc::new(file),
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

        // Create the partition directory, if it does not exist
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

        // Convert to a blocking std::fs::File to use positional IO.
        let file = file.into_std().await;

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
        let file = self.file.clone();
        let mut buf = buf.into();

        task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileExt;
                file.read_exact_at(buf.as_mut(), offset)
                    .map_err(|_| Error::ReadFailed)?;
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::FileExt;
                let mut read = 0;
                while read < buf.len() {
                    let n = file
                        .seek_read(&mut buf.as_mut()[read..], offset + read as u64)
                        .map_err(|_| Error::ReadFailed)?;
                    if n == 0 {
                        return Err(Error::BlobInsufficientLength);
                    }
                    read += n;
                }
            }
            Ok(buf)
        })
        .await
        .map_err(|_| Error::ReadFailed)?
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        let file = self.file.clone();
        let buf = buf.into();

        task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileExt;
                file.write_all_at(buf.as_ref(), offset)
                    .map_err(|_| Error::WriteFailed)?;
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::FileExt;
                let mut written = 0;
                while written < buf.len() {
                    let n = file
                        .seek_write(&buf.as_ref()[written..], offset + written as u64)
                        .map_err(|_| Error::WriteFailed)?;
                    written += n;
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::WriteFailed)?
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || {
            file.set_len(len)
                .map_err(|e| Error::BlobTruncateFailed(partition, hex(&name), e))
        })
        .await
        .map_err(|_| Error::WriteFailed)?
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || {
            file.sync_all()
                .map_err(|e| Error::BlobSyncFailed(partition, hex(&name), e))
        })
        .await
        .map_err(|_| {
            Error::BlobSyncFailed(
                self.partition.clone(),
                hex(&self.name),
                std::io::Error::other("join error"),
            )
        })?
    }

    async fn close(self) -> Result<(), Error> {
        self.sync().await

        // When the file is dropped, it will be closed.
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
