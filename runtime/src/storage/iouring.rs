//! This module provides an io_uring-based implementation of the [crate::Storage] trait,
//! offering fast, high-throughput file operations on Linux systems.
//!
//! ## Architecture
//!
//! I/O operations are sent via a [futures::channel::mpsc] channel to a dedicated io_uring event loop
//! running in another thread. Operation results are returned via a [futures::channel::oneshot] channel.
//!
//! ## Memory Safety
//!
//! We pass to the kernel, via io_uring, a pointer to the buffer being read from/written into.
//! Therefore, we ensure that the memory location is valid for the duration of the operation.
//! That is, it doesn't move or go out of scope until the operation completes.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring-storage` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.

use crate::{
    iouring::{self, should_retry},
    Blob as _, Error,
};
use commonware_utils::{from_hex, hex, StableBuf};
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt as _,
};
use io_uring::{opcode, types};
use prometheus_client::registry::Registry;
use std::{
    fs::{self, File},
    io::Error as IoError,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug)]
/// Configuration for a [Storage].
pub struct Config {
    /// Where to store blobs.
    pub storage_directory: PathBuf,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
}

#[derive(Clone)]
pub struct Storage {
    storage_directory: PathBuf,
    io_sender: mpsc::Sender<iouring::Op>,
}

impl Storage {
    /// Returns a new `Storage` instance.
    pub fn start(mut cfg: Config, registry: &mut Registry) -> Self {
        let (io_sender, receiver) = mpsc::channel::<iouring::Op>(cfg.iouring_config.size as usize);

        let storage = Storage {
            storage_directory: cfg.storage_directory.clone(),
            io_sender,
        };
        let metrics = Arc::new(iouring::Metrics::new(registry));

        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        cfg.iouring_config.single_issuer = true;

        std::thread::spawn(|| block_on(iouring::run(cfg.iouring_config, metrics, receiver)));
        storage
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Blob, u64), Error> {
        // Construct the full path
        let blob_name = hex(name);
        let path = self
            .storage_directory
            .join(partition)
            .join(&blob_name);
        let parent = path
            .parent()
            .ok_or_else(|| Error::PartitionMissing(partition.into()))?;

        // Create the partition directory if it does not exist
        let partition_existed = parent.exists();
        fs::create_dir_all(parent).map_err(|_| Error::PartitionCreationFailed(partition.into()))?;
        if !partition_existed {
            sync_directory(&self.storage_directory).map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => Error::PartitionCreationFailed(partition.into()),
                _ => Error::BlobSyncFailed(partition.into(), blob_name.clone(), err),
            })?;
        }

        // Open the file in read-write mode, create if it does not exist
        let (file, created) = match fs::OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => (file, false),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let created_file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|e| Error::BlobOpenFailed(partition.into(), blob_name.clone(), e))?;
                (created_file, true)
            }
            Err(err) => return Err(Error::BlobOpenFailed(partition.into(), blob_name.clone(), err)),
        };

        // Get the file length
        let len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

        // Create the blob
        let blob = Blob::new(partition.into(), name, file, self.io_sender.clone());
        if created {
            // Sync the blob to ensure it is durably created
            blob.sync().await?;
            // Sync the parent directory to ensure the creation of blob is durable
            sync_directory(parent).map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => {
                    Error::BlobOpenFailed(partition.into(), blob_name.clone(), err)
                }
                _ => Error::BlobSyncFailed(partition.into(), blob_name.clone(), err),
            })?;
        }

        Ok((blob, len))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        let path = self.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_name = hex(name);
            let blob_path = path.join(&blob_name);
            fs::remove_file(blob_path)
                .map_err(|_| Error::BlobMissing(partition.into(), blob_name.clone()))?;

            // Sync the partition directory to ensure the removal is durable
            sync_directory(&path).map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => Error::PartitionMissing(partition.into()),
                _ => Error::BlobSyncFailed(partition.into(), blob_name.clone(), err),
            })?;
        } else {
            fs::remove_dir_all(&path).map_err(|_| Error::PartitionMissing(partition.into()))?;

            // Sync the storage directory to ensure the removal is durable
            sync_directory(&self.storage_directory).map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => Error::PartitionMissing(partition.into()),
                _ => Error::BlobSyncFailed(partition.into(), "partition".to_string(), err),
            })?;
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

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    let file = std::fs::OpenOptions::new().read(true).open(path)?;
    file.sync_all()
}

pub struct Blob {
    /// The partition this blob lives in
    partition: String,
    /// The name of the blob
    name: Vec<u8>,
    /// The underlying file
    file: Arc<File>,
    /// Where to send IO operations to be executed
    io_sender: mpsc::Sender<iouring::Op>,
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
        io_sender: mpsc::Sender<iouring::Op>,
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
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        let fd = types::Fd(self.file.as_raw_fd());
        let mut bytes_read = 0;
        let buf_len = buf.len();
        let mut io_sender = self.io_sender.clone();
        while bytes_read < buf_len {
            // Figure out how much is left to read and where to read into
            let remaining = unsafe {
                std::slice::from_raw_parts_mut(
                    buf.as_mut_ptr().add(bytes_read),
                    buf_len - bytes_read,
                )
            };
            let offset = offset + bytes_read as u64;

            // Create an operation to do the read
            let op = opcode::Read::new(fd, remaining.as_mut_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            io_sender
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: Some(buf),
                })
                .await
                .map_err(|_| Error::ReadFailed)?;

            // Wait for the result
            let (result, got_buf) = receiver.await.map_err(|_| Error::ReadFailed)?;
            buf = got_buf.unwrap();
            if should_retry(result) {
                continue;
            }

            // A non-positive return value indicates an error.
            let op_bytes_read: usize = result.try_into().map_err(|_| Error::ReadFailed)?;
            if op_bytes_read == 0 {
                // A return value of 0 indicates EOF, which shouldn't happen because we
                // aren't done reading into `buf`. See `man pread`.
                return Err(Error::BlobInsufficientLength);
            }
            bytes_read += op_bytes_read;
        }
        Ok(buf)
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        let mut buf = buf.into();
        let fd = types::Fd(self.file.as_raw_fd());
        let mut bytes_written = 0;
        let buf_len = buf.len();
        let mut io_sender = self.io_sender.clone();
        while bytes_written < buf_len {
            // Figure out how much is left to write and where to write from
            let remaining = unsafe {
                std::slice::from_raw_parts(
                    buf.as_mut_ptr().add(bytes_written) as *const u8,
                    buf_len - bytes_written,
                )
            };
            let offset = offset + bytes_written as u64;

            // Create an operation to do the write
            let op = opcode::Write::new(fd, remaining.as_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();

            // Submit the operation
            let (sender, receiver) = oneshot::channel();
            io_sender
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: Some(buf),
                })
                .await
                .map_err(|_| Error::WriteFailed)?;

            // Wait for the result
            let (return_value, got_buf) = receiver.await.map_err(|_| Error::WriteFailed)?;
            buf = got_buf.unwrap();
            if should_retry(return_value) {
                continue;
            }

            // A negative return value indicates an error.
            let op_bytes_written: usize =
                return_value.try_into().map_err(|_| Error::WriteFailed)?;

            bytes_written += op_bytes_written;
        }
        Ok(())
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.file.set_len(len).map_err(|e| {
            Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), IoError::other(e))
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
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: None,
                })
                .await
                .map_err(|_| {
                    Error::BlobSyncFailed(
                        self.partition.clone(),
                        hex(&self.name),
                        IoError::other("failed to send work"),
                    )
                })?;

            // Wait for the result
            let (return_value, _) = receiver.await.map_err(|_| {
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
                    IoError::other(format!("error code: {return_value}")),
                ));
            }

            return Ok(());
        }
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
                iouring_config: Default::default(),
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
