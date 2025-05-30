use crate::{
    iouring::{self, should_retry},
    Error,
};
use commonware_utils::{from_hex, hex, StableBuf, StableBufMut};
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt as _,
};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types};
use prometheus_client::registry::Registry;
use std::fs::{self, File};
use std::io::Error as IoError;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug)]
/// Configuration for a [Storage].
pub struct Config {
    /// Where to store blobs.
    pub storage_directory: PathBuf,
    /// Configuration for the io_uring instance.
    pub ring_config: iouring::Config,
}

#[derive(Clone)]
pub struct Storage {
    storage_directory: PathBuf,
    io_sender: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Storage {
    /// Returns a new `Storage` instance.
    pub fn start(cfg: Config, registry: &mut Registry) -> Self {
        let (io_sender, receiver) =
            mpsc::channel::<(SqueueEntry, oneshot::Sender<i32>)>(cfg.ring_config.size as usize);

        let storage = Storage {
            storage_directory: cfg.storage_directory.clone(),
            io_sender,
        };
        let metrics = Arc::new(iouring::Metrics::new(registry));
        std::thread::spawn(|| block_on(iouring::run(cfg.ring_config, metrics, receiver)));
        storage
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Blob, u64), Error> {
        // Construct the full path
        let path = self.storage_directory.join(partition).join(hex(name));
        let parent = path
            .parent()
            .ok_or_else(|| Error::PartitionMissing(partition.into()))?;

        // Create the partition directory if it does not exist
        fs::create_dir_all(parent).map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file in read-write mode, create if it does not exist
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e))?;

        // Get the file length
        let len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

        Ok((
            Blob::new(partition.into(), name, file, self.io_sender.clone()),
            len,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        let path = self.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_path = path.join(hex(name));
            fs::remove_file(blob_path)
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;
        } else {
            fs::remove_dir_all(path).map_err(|_| Error::PartitionMissing(partition.into()))?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        let path = self.storage_directory.join(partition);

        let entries =
            std::fs::read_dir(&path).map_err(|_| Error::PartitionMissing(partition.into()))?;

        let mut blobs = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| Error::ReadFailed)?;
            let file_type = entry.file_type().map_err(|_| Error::ReadFailed)?;

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

pub struct Blob {
    /// The partition this blob lives in
    partition: String,
    /// The name of the blob
    name: Vec<u8>,
    /// The underlying file
    file: Arc<File>,
    /// Where to send IO operations to be executed
    io_sender: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            file: self.file.clone(),
            io_sender: self.io_sender.clone(),
        }
    }
}

impl Blob {
    fn new(
        partition: String,
        name: &[u8],
        file: File,
        io_sender: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            file: Arc::new(file),
            io_sender,
        }
    }
}

impl crate::Blob for Blob {
    async fn read_at<B: StableBufMut>(&self, mut buf: B, offset: u64) -> Result<B, Error> {
        let fd = types::Fd(self.file.as_raw_fd());
        let mut total_read = 0;
        let len = buf.len();
        let buf_ref = buf.deref_mut();

        let mut io_sender = self.io_sender.clone();
        while total_read < len {
            // Figure out how much is left to read and where to read into
            let remaining = &mut buf_ref[total_read..];
            let offset = offset + total_read as u64;

            // Create an operation to do the read
            let op = opcode::Read::new(fd, remaining.as_mut_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            io_sender
                .send((op, sender))
                .await
                .map_err(|_| Error::ReadFailed)?;

            // Wait for the result
            let bytes_read = receiver.await.map_err(|_| Error::ReadFailed)?;
            if should_retry(bytes_read) {
                continue;
            }

            // A non-positive return value indicates an error.
            let bytes_read: usize = bytes_read.try_into().map_err(|_| Error::ReadFailed)?;
            if bytes_read == 0 {
                // A return value of 0 indicates EOF, which shouldn't happen because we
                // aren't done reading into `buf`. See `man pread`.
                return Err(Error::BlobInsufficientLength);
            }
            total_read += bytes_read;
        }
        Ok(buf)
    }

    async fn write_at<B: StableBuf>(&self, buf: B, offset: u64) -> Result<(), Error> {
        let fd = types::Fd(self.file.as_raw_fd());
        let mut total_written = 0;
        let buf_ref = buf.as_ref();

        let mut io_sender = self.io_sender.clone();
        while total_written < buf.len() {
            // Figure out how much is left to write and where to write from
            let remaining = &buf_ref[total_written..];
            let offset = offset + total_written as u64;

            // Create an operation to do the write
            let op = opcode::Write::new(fd, remaining.as_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            io_sender
                .send((op, sender))
                .await
                .map_err(|_| Error::WriteFailed)?;

            // Wait for the result
            let return_value = receiver.await.map_err(|_| Error::WriteFailed)?;
            if should_retry(return_value) {
                continue;
            }

            // A negative return value indicates an error.
            let bytes_written: usize = return_value.try_into().map_err(|_| Error::WriteFailed)?;

            total_written += bytes_written;
        }
        Ok(())
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.file.set_len(len).map_err(|e| {
            Error::BlobTruncateFailed(self.partition.clone(), hex(&self.name), IoError::other(e))
        })
    }

    async fn sync(&self) -> Result<(), Error> {
        loop {
            // Create an operation to do the sync
            let op = opcode::Fsync::new(types::Fd(self.file.as_raw_fd())).build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            self.io_sender
                .clone()
                .send((op, sender))
                .await
                .map_err(|_| {
                    Error::BlobSyncFailed(
                        self.partition.clone(),
                        hex(&self.name),
                        IoError::other("failed to send work"),
                    )
                })?;

            // Wait for the result
            let return_value = receiver.await.map_err(|_| {
                Error::BlobSyncFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    IoError::other("failed to read result"),
                )
            })?;
            if should_retry(return_value) {
                continue;
            }

            // If the return value is negative, it indicates an error.
            if return_value < 0 {
                return Err(Error::BlobSyncFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    IoError::other(format!("error code: {}", return_value)),
                ));
            }

            return Ok(());
        }
    }

    /// Drop all references to self.fd to close that resource.
    async fn close(self) -> Result<(), Error> {
        self.sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::run_storage_tests;
    use rand::{Rng as _, SeedableRng as _};
    use std::env;

    // Helper for creating test storage
    fn create_test_storage() -> (Storage, PathBuf) {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("commonware_iouring_storage_{}", rng.gen::<u64>()));

        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                ring_config: Default::default(),
            },
            &mut Registry::default(),
        );
        (storage, storage_directory)
    }

    #[tokio::test]
    async fn test_iouring_storage() {
        let (storage, storage_directory) = create_test_storage();
        run_storage_tests(storage).await;
        let _ = std::fs::remove_dir_all(storage_directory);
    }
}
