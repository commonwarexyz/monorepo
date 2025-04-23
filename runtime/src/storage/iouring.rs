use crate::{Error, Spawner};
use commonware_macros::select;
use commonware_utils::{from_hex, hex};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    SinkExt as _, StreamExt as _,
};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types, IoUring};
use std::{
    collections::HashMap,
    fs::{self, File},
    future::Future,
    io::{Error as IoError, ErrorKind},
    os::fd::{AsRawFd as _, OwnedFd},
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

const IOURING_SIZE: u32 = 128;

#[derive(Clone)]
pub struct Config {
    pub storage_directory: PathBuf,
}

impl Config {
    pub fn new(storage_directory: PathBuf) -> Self {
        Self { storage_directory }
    }
}

/// A future that resolves to the next completion queue entry when available
struct NextCompletionFuture<'a> {
    ring: &'a mut IoUring,
}

impl<'a> NextCompletionFuture<'a> {
    fn new(ring: &'a mut IoUring) -> Self {
        Self { ring }
    }
}

impl Future for NextCompletionFuture<'_> {
    type Output = io_uring::cqueue::Entry;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Try to get a completion
        if let Some(cqe) = self.ring.completion().next() {
            return Poll::Ready(cqe);
        }

        // Submit any pending operations
        self.ring.submit().expect("unable to submit to ring");

        // No completions yet, register waker and return Pending
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Background task that polls for completed work and notifies waiters on completion.
/// The user data field of all operations received on `receiver` will be ignored.
async fn do_work(mut receiver: mpsc::Receiver<(SqueueEntry, oneshot::Sender<i32>)>) {
    let mut ring = IoUring::new(IOURING_SIZE).expect("failed to create io_uring");
    let mut next_work_id: u64 = 0;
    // Maps a work ID to the sender that we will send the result to.
    let mut waiters: HashMap<_, oneshot::Sender<i32>> =
        HashMap::with_capacity(IOURING_SIZE as usize);

    loop {
        let completed_work_fut = NextCompletionFuture::new(&mut ring);
        let new_work_fut = if waiters.len() < IOURING_SIZE as usize {
            Either::Left(receiver.next())
        } else {
            // We're at the limit for maximum number of ongoing operations.
            // Wait for a completion to free up space.
            Either::Right(futures::future::pending())
        };

        select! {
            new_work = new_work_fut => {
                let Some((mut op,sender)) = new_work else {
                    // Channel closed, exit the loop
                    break;
                };

                // Assign a unique id
                let work_id = next_work_id;
                op = op.user_data(work_id);
                // Use wrapping add in case we overflow
                next_work_id = next_work_id.wrapping_add(1);

                // We'll send the result of this operation to `sender`.
                waiters.insert(work_id, sender);

                // Submit the operation to the ring
                unsafe {
                    ring.submission().push(&op).expect("unable to push to queue");
                }
            },
            completed_work = completed_work_fut => {
                let work_id = completed_work.user_data();
                let result = completed_work.result();
                let sender = waiters.remove(&work_id).expect("work is missing");
                // Notify with the result of this operation
                let _ =  sender.send(result);
            },
        }
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
    pub fn start<S: Spawner>(cfg: &Config, spawner: S) -> Self {
        let (io_sender, receiver) =
            mpsc::channel::<(SqueueEntry, oneshot::Sender<i32>)>(IOURING_SIZE as usize);

        let storage = Storage {
            storage_directory: cfg.storage_directory.clone(),
            io_sender,
        };
        spawner.spawn(|_| do_work(receiver));
        storage
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Blob, Error> {
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

        Ok(Blob::new(
            partition.into(),
            name,
            file,
            len,
            self.io_sender.clone(),
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
    /// The underlying file descriptor
    fd: Arc<OwnedFd>,
    /// The length of the blob
    len: Arc<AtomicU64>,
    /// Where to send IO operations to be executed
    io_sender: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            fd: self.fd.clone(),
            len: self.len.clone(),
            io_sender: self.io_sender.clone(),
        }
    }
}

impl Blob {
    fn new(
        partition: String,
        name: &[u8],
        file: File,
        len: u64,
        io_sender: mpsc::Sender<(SqueueEntry, oneshot::Sender<i32>)>,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            fd: Arc::new(OwnedFd::from(file)),
            len: Arc::new(AtomicU64::new(len)),
            io_sender,
        }
    }
}

impl crate::Blob for Blob {
    async fn len(&self) -> Result<u64, Error> {
        Ok(self.len.load(Ordering::Relaxed))
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let current_len = self.len.load(Ordering::Relaxed);
        if offset + buf.len() as u64 > current_len {
            return Err(Error::BlobInsufficientLength);
        }

        let fd = types::Fd(self.fd.as_raw_fd());
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
        let fd = types::Fd(self.fd.as_raw_fd());
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

        // Update the virtual file size
        let max_len = offset + buf.len() as u64;
        if max_len > self.len.load(Ordering::Relaxed) {
            self.len.store(max_len, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        // Create an operation to do the truncate
        let op = opcode::Fallocate::new(types::Fd(self.fd.as_raw_fd()), len)
            .mode(0) // 0 means truncate
            .build();

        // Submit the operation
        let (sender, receiver) = oneshot::channel();
        self.io_sender
            .clone()
            .send((op, sender))
            .await
            .map_err(|_| {
                Error::BlobTruncateFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    IoError::new(ErrorKind::Other, "failed to send work"),
                )
            })?;

        // Wait for the result
        let return_value = receiver.await.map_err(|_| {
            Error::BlobTruncateFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, "failed to read result"),
            )
        })?;

        // If the return value is negative, it indicates an error.
        if return_value < 0 {
            return Err(Error::BlobTruncateFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(
                    ErrorKind::Other,
                    format!("got error code: {}", return_value),
                ),
            ));
        }
        // Update length
        self.len.store(len, Ordering::SeqCst);
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        // Create an operation to do the sync
        let op = opcode::Fsync::new(types::Fd(self.fd.as_raw_fd())).build();

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
                IoError::new(
                    ErrorKind::Other,
                    format!("got error code: {}", return_value),
                ),
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
    use crate::{
        storage::tests::run_storage_tests,
        tokio::{Spawner, SpawnerConfig},
    };
    use prometheus_client::registry::Registry;
    use rand::{Rng as _, SeedableRng as _};
    use std::env;

    // Helper for creating test storage
    fn create_test_storage() -> (Storage, PathBuf) {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("commonware_iouring_storage_{}", rng.gen::<u64>()));

        // Initialize runtime
        let runtime = Arc::new(tokio::runtime::Handle::current());

        let spawner = Spawner::new(
            String::new(),
            SpawnerConfig { catch_panics: true },
            &mut Registry::default(),
            runtime,
        );

        let storage = Storage::start(&Config::new(storage_directory.clone()), spawner);
        (storage, storage_directory)
    }

    #[tokio::test]
    async fn test_iouring_storage() {
        let (storage, storage_directory) = create_test_storage();
        run_storage_tests(storage).await;
        let _ = std::fs::remove_dir_all(storage_directory);
    }
}
