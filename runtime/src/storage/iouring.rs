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
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use commonware_macros::select;
use commonware_utils::{from_hex, hex};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    SinkExt as _, StreamExt as _,
};
use io_uring::{opcode, types, IoUring};

use crate::{Error, Spawner};

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

impl<'a> Future for NextCompletionFuture<'a> {
    type Output = io_uring::cqueue::Entry;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Try to get a completion
        if let Some(cqe) = self.ring.completion().next() {
            return Poll::Ready(cqe);
        }

        // Submit any pending operations, which might generate completions
        self.ring.submit().expect("unable to submit to ring");

        // Try again after submitting
        if let Some(cqe) = self.ring.completion().next() {
            return Poll::Ready(cqe);
        }

        // No completions yet, register waker and return Pending
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Background task that polls for completed work and notifies waiters on completion.
async fn do_work(mut receiver: mpsc::Receiver<(io_uring::squeue::Entry, oneshot::Sender<i32>)>) {
    // Create ring
    let mut id: u64 = 0;
    let mut ring = IoUring::new(IOURING_SIZE).expect("failed to create io_uring instance");
    let mut waiters: HashMap<_, oneshot::Sender<i32>> =
        HashMap::with_capacity(IOURING_SIZE as usize);

    loop {
        let completion = NextCompletionFuture::new(&mut ring);
        let work = if waiters.len() < IOURING_SIZE as usize {
            Either::Left(receiver.next())
        } else {
            Either::Right(futures::future::pending())
        };

        select! {
            next_work = work => {
                let Some((op,sender)) = next_work else {
                    // Channel closed, exit the loop
                    break;
                };

                // Assign a unique id
                let work_id = id;
                id = id.wrapping_add(1);

                // Register the waiter
                waiters.insert(work_id, sender);

                // Submit the operation to the ring
                unsafe {
                    ring.submission().push(&op).expect("unable to push to queue");
                }
            },
            cqe = completion => {
                let work_id = cqe.user_data();
                let result = cqe.result();
                let sender = waiters.remove(&work_id).expect("work is missing");
                let _ =  sender.send(result);
            },
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    storage_directory: PathBuf,
    io_sender: mpsc::Sender<(io_uring::squeue::Entry, oneshot::Sender<i32>)>,
}

impl Storage {
    pub fn start<S: Spawner>(cfg: &Config, spawner: S) -> Self {
        let (sender, receiver) =
            mpsc::channel::<(io_uring::squeue::Entry, oneshot::Sender<i32>)>(IOURING_SIZE as usize);
        let storage = Storage {
            storage_directory: cfg.storage_directory.clone(),
            io_sender: sender.clone(),
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
    partition: String,
    name: Vec<u8>,
    fd: Arc<OwnedFd>,
    len: AtomicU64,
    io_sender: mpsc::Sender<(io_uring::squeue::Entry, oneshot::Sender<i32>)>,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            fd: self.fd.clone(),
            len: AtomicU64::new(self.len.load(Ordering::Relaxed)),
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
        io_sender: mpsc::Sender<(io_uring::squeue::Entry, oneshot::Sender<i32>)>,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            fd: Arc::new(OwnedFd::from(file)),
            len: AtomicU64::new(len),
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
            let remaining = &mut buf[total_read..];
            let offset = offset + total_read as u64;

            let op = opcode::Read::new(fd, remaining.as_mut_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();

            let (sender, receiver) = oneshot::channel();
            let _ = io_sender
                .send((op, sender))
                .await
                .map_err(|_| Error::ReadFailed)?;
            // Wait for the operation to complete
            let result = receiver.await.map_err(|_| Error::ReadFailed)?;

            // If the return value is non-positive, it indicates an error.
            let bytes_read: usize = result.try_into().map_err(|_| Error::ReadFailed)?;
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
            let remaining = &buf[total_written..];
            let offset = offset + total_written as u64;

            // Submit write operation using the shared adapter
            let op = opcode::Write::new(fd, remaining.as_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();
            let (sender, receiver) = oneshot::channel();
            let _ = io_sender
                .send((op, sender))
                .await
                .map_err(|_| Error::WriteFailed)?;
            // Wait for the operation to complete
            let result = receiver.await.map_err(|_| Error::WriteFailed)?;

            let bytes_written: usize = result.try_into().map_err(|_| Error::WriteFailed)?;
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
        let op = opcode::Fallocate::new(types::Fd(self.fd.as_raw_fd()), len)
            .mode(0) // 0 means truncate
            .build();

        let (sender, receiver) = oneshot::channel();
        let _ = self
            .io_sender
            .clone()
            .send((op, sender))
            .await
            .map_err(|_| {
                Error::BlobTruncateFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    IoError::new(ErrorKind::Other, "channel send failed"),
                )
            })?;
        // Wait for the operation to complete
        let result = receiver.await.map_err(|_| {
            Error::BlobTruncateFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, "TODO"),
            )
        })?;

        // If the return value is non-positive, it indicates an error.
        if result <= 0 {
            return Err(Error::BlobTruncateFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, "TODO"),
            ));
        }
        // Update length
        self.len.store(len, Ordering::SeqCst);
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let op = opcode::Fsync::new(types::Fd(self.fd.as_raw_fd())).build();

        let (sender, receiver) = oneshot::channel();
        let _ = self
            .io_sender
            .clone()
            .send((op, sender))
            .await
            .map_err(|_| {
                Error::BlobSyncFailed(
                    self.partition.clone(),
                    hex(&self.name),
                    IoError::new(ErrorKind::Other, "TODO"),
                )
            })?;
        // Wait for the operation to complete
        let result = receiver.await.map_err(|_| {
            Error::BlobSyncFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, "TODO"),
            )
        })?;
        // If the return value is non-positive, it indicates an error.
        if result <= 0 {
            return Err(Error::BlobSyncFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::new(ErrorKind::Other, "TODO"),
            ));
        }

        Ok(())
    }

    async fn close(self) -> Result<(), Error> {
        // Just sync before dropping
        self.sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{metered::Metrics, tests::run_storage_tests},
        tokio::{Spawner, SpawnerConfig},
    };
    use prometheus_client::registry::Registry;
    use rand::{Rng as _, SeedableRng as _};
    use std::env;

    #[tokio::test]
    async fn test_iouring_storage() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("commonware_iouring_storage_{}", rng.gen::<u64>()));

        // Initialize runtime
        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());

        let spawner = Spawner::new(
            String::new(),
            SpawnerConfig { catch_panics: true },
            &mut Registry::default(),
            runtime.clone(),
        );

        let storage = Storage::start(&Config::new(storage_directory.clone()), spawner);
        run_storage_tests(storage).await;
    }
}
