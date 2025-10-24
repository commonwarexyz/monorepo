use crate::Error;
use commonware_utils::{from_hex, hex};
use std::{
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    sync::Arc,
};
#[cfg(not(unix))]
use tokio::task;
use tokio::{fs, sync::Mutex};

#[cfg(not(unix))]
mod fallback;
#[cfg(unix)]
mod unix;

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

impl crate::Storage for Storage {
    #[cfg(unix)]
    type Blob = unix::Blob;
    #[cfg(not(unix))]
    type Blob = fallback::Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Self::Blob, u64), Error> {
        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Construct the full path
        let blob_name = hex(name);
        let path = self.cfg.storage_directory.join(partition).join(&blob_name);
        let parent = match path.parent() {
            Some(parent) => parent,
            None => return Err(Error::PartitionCreationFailed(partition.into())),
        };

        // Create the partition directory, if it does not exist
        let partition_existed = fs::metadata(parent).await.is_ok();
        fs::create_dir_all(parent)
            .await
            .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        if !partition_existed {
            sync_directory(&self.cfg.storage_directory)
                .await
                .map_err(|err| match err.kind() {
                    ErrorKind::NotFound => Error::PartitionCreationFailed(partition.into()),
                    _ => Error::BlobSyncFailed(partition.into(), blob_name.clone(), err),
                })?;
        }

        // Open the file in read-write mode, create if it does not exist
        let open_attempt = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await;
        let (mut file, created) = match open_attempt {
            Ok(file) => (file, false),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                let created_file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .await
                    .map_err(|e| Error::BlobOpenFailed(partition.into(), blob_name.clone(), e))?;
                (created_file, true)
            }
            Err(err) => {
                return Err(Error::BlobOpenFailed(
                    partition.into(),
                    blob_name.clone(),
                    err,
                ))
            }
        };

        // Set the maximum buffer size
        file.set_max_buf_size(self.cfg.maximum_buffer_size);

        // Get the file length
        let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();

        if created {
            file.sync_all()
                .await
                .map_err(|err| Error::BlobSyncFailed(partition.into(), blob_name.clone(), err))?;

            sync_directory(parent)
                .await
                .map_err(|err| match err.kind() {
                    ErrorKind::NotFound => {
                        Error::BlobOpenFailed(partition.into(), blob_name.clone(), err)
                    }
                    _ => Error::BlobSyncFailed(partition.into(), blob_name.clone(), err),
                })?;
        }

        #[cfg(unix)]
        {
            // Convert to a blocking std::fs::File
            let file = file.into_std().await;

            // Construct the blob
            Ok((Self::Blob::new(partition.into(), name, file), len))
        }
        #[cfg(not(unix))]
        {
            // Construct the blob
            Ok((Self::Blob::new(partition.into(), name, file), len))
        }
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Remove all related files
        let path = self.cfg.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_name = hex(name);
            let blob_path = path.join(&blob_name);
            fs::remove_file(blob_path)
                .await
                .map_err(|_| Error::BlobMissing(partition.into(), blob_name.clone()))?;

            // Sync the partition directory to ensure the removal is durable
            sync_directory(&path)
                .await
                .map_err(|err| match err.kind() {
                    ErrorKind::NotFound => Error::PartitionMissing(partition.into()),
                    _ => Error::BlobSyncFailed(partition.into(), blob_name.clone(), err),
                })?;
        } else {
            fs::remove_dir_all(&path)
                .await
                .map_err(|_| Error::PartitionMissing(partition.into()))?;

            // Sync the storage directory to ensure the removal is durable
            sync_directory(&self.cfg.storage_directory)
                .await
                .map_err(|err| match err.kind() {
                    ErrorKind::NotFound => Error::PartitionMissing(partition.into()),
                    _ => Error::BlobSyncFailed(partition.into(), "partition".to_string(), err),
                })?;
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

async fn sync_directory(path: &Path) -> Result<(), IoError> {
    #[cfg(unix)]
    {
        let dir = fs::File::open(path).await?;
        dir.sync_all().await
    }
    #[cfg(not(unix))]
    {
        let path = path.to_path_buf();
        task::spawn_blocking(move || sync_directory_blocking(&path))
            .await
            .map_err(|err| IoError::new(ErrorKind::Other, err))?
    }
}

#[cfg(not(unix))]
fn sync_directory_blocking(path: &Path) -> Result<(), IoError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    let dir = options.open(path)?;
    dir.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::run_storage_tests;
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
