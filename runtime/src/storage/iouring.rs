use crate::Error;
use commonware_utils::{from_hex, hex};
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt as _, StreamExt as _,
};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types, IoUring};
use std::fs::{self, File};
use std::io::{Error as IoError, ErrorKind};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct IoUringConfig {
    /// Size of the ring.
    pub size: u32,
    /// If true, use IOPOLL mode.
    pub iopoll: bool,
    /// If true, use single issuer mode.
    pub single_issuer: bool,
}

impl Default for IoUringConfig {
    fn default() -> Self {
        Self {
            size: 128,
            iopoll: false,
            single_issuer: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub storage_directory: PathBuf,
    pub ring_config: IoUringConfig,
}

fn new_ring(cfg: &IoUringConfig) -> Result<IoUring, std::io::Error> {
    let mut builder = &mut IoUring::builder();
    if cfg.iopoll {
        builder = builder.setup_iopoll();
    }
    if cfg.single_issuer {
        builder = builder.setup_single_issuer();
    }
    builder.build(cfg.size)
}

/// Background task that polls for completed work and notifies waiters on completion.
/// The user data field of all operations received on `receiver` will be ignored.
async fn do_work(
    cfg: IoUringConfig,
    mut receiver: mpsc::Receiver<(SqueueEntry, oneshot::Sender<i32>)>,
) {
    let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");
    let mut next_work_id: u64 = 0;
    // Maps a work ID to the sender that we will send the result to.
    let mut waiters: std::collections::HashMap<_, oneshot::Sender<i32>> =
        std::collections::HashMap::with_capacity(cfg.size as usize);

    loop {
        // Try to get a completion
        if let Some(cqe) = ring.completion().next() {
            let work_id = cqe.user_data();
            let result = cqe.result();
            let sender = waiters.remove(&work_id).expect("work is missing");
            // Notify with the result of this operation
            let _ = sender.send(result);
            continue;
        }

        // Try to fill the submission queue with incoming work.
        // Stop if we are at the max number of processing work.
        while waiters.len() < cfg.size as usize {
            // Wait for more work
            let (mut work, sender) = if waiters.is_empty() {
                // Block until there is something to do
                match receiver.next().await {
                    Some(work) => work,
                    None => return,
                }
            } else {
                // Handle incoming work
                match receiver.try_next() {
                    // Got work without blocking
                    Ok(Some(work_item)) => work_item,
                    // Channel closed, shut down
                    Ok(None) => return,
                    // No new work available, wait for a completion
                    Err(_) => break,
                }
            };

            // Assign a unique id
            let work_id = next_work_id;
            work = work.user_data(work_id);
            // Use wrapping add in case we overflow
            next_work_id = next_work_id.wrapping_add(1);

            // We'll send the result of this operation to `sender`.
            waiters.insert(work_id, sender);

            // Submit the operation to the ring
            unsafe {
                ring.submission()
                    .push(&work)
                    .expect("unable to push to queue");
            }
        }

        // Wait for at least 1 item to be in the completion queue.
        // Note that we block until anything is in the completion queue,
        // even if it's there before this call. That is, a completion
        // that arrived before this call will be counted and cause this
        // call to return. Note that waiters.len() > 0 here.
        ring.submit_and_wait(1).expect("unable to submit to ring");
    }
}

#[derive(Clone)]
pub struct Storage {
    storage_directory: PathBuf,
    io_sender: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Storage {
    /// Returns a new `Storage` instance.
    /// The `Spawner` is used to spawn the background task that handles IO operations.
    pub fn start(cfg: &Config) -> Self {
        let (io_sender, receiver) =
            mpsc::channel::<(SqueueEntry, oneshot::Sender<i32>)>(cfg.ring_config.size as usize);

        let storage = Storage {
            storage_directory: cfg.storage_directory.clone(),
            io_sender,
        };
        let iouring_config = cfg.ring_config.clone();
        std::thread::spawn(|| block_on(do_work(iouring_config, receiver)));
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
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let fd = types::Fd(self.file.as_raw_fd());
        let mut total_read = 0;

        let mut io_sender = self.io_sender.clone();
        while total_read < buf.len() {
            // Figure out how much is left to read and where to read into
            let remaining = &mut buf[total_read..];
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

            // If the return value is non-positive, it indicates an error.
            let bytes_read: usize = bytes_read.try_into().map_err(|_| Error::ReadFailed)?;
            if bytes_read == 0 {
                // Got EOF before filling buffer.
                return Err(Error::BlobInsufficientLength);
            }
            total_read += bytes_read;
        }

        Ok(())
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        let fd = types::Fd(self.file.as_raw_fd());
        let mut total_written = 0;

        let mut io_sender = self.io_sender.clone();
        while total_written < buf.len() {
            // Figure out how much is left to write and where to write from
            let remaining = &buf[total_written..];
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

            // If the return value is non-positive, it indicates an error.
            let bytes_written: usize = return_value.try_into().map_err(|_| Error::WriteFailed)?;
            if bytes_written == 0 {
                return Err(Error::WriteFailed);
            }

            total_written += bytes_written;
        }
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.file.set_len(len).map_err(|e| {
            Error::BlobTruncateFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, e),
            )
        })
    }

    async fn sync(&self) -> Result<(), Error> {
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
                    IoError::new(ErrorKind::Other, "failed to send work"),
                )
            })?;

        // Wait for the result
        let return_value = receiver.await.map_err(|_| {
            Error::BlobSyncFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, "failed to read result"),
            )
        })?;
        // If the return value is negative, it indicates an error.
        if return_value < 0 {
            return Err(Error::BlobSyncFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, format!("error code: {}", return_value)),
            ));
        }

        Ok(())
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

        let storage = Storage::start(&Config {
            storage_directory: storage_directory.clone(),
            ring_config: Default::default(),
        });
        (storage, storage_directory)
    }

    #[tokio::test]
    async fn test_iouring_storage() {
        let (storage, storage_directory) = create_test_storage();
        run_storage_tests(storage).await;
        let _ = std::fs::remove_dir_all(storage_directory);
    }
}
