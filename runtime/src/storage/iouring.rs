use std::{
    collections::HashMap,
    fs::{self, File},
    os::fd::{AsRawFd as _, OwnedFd},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use commonware_utils::{from_hex, hex};
use futures::channel::oneshot;
use io_uring::{opcode, types, IoUring};

use crate::Error;

#[derive(Clone)]
pub struct Config {
    pub storage_directory: PathBuf,
}

impl Config {
    pub fn new(storage_directory: PathBuf) -> Self {
        Self { storage_directory }
    }
}

// New type to handle io_uring operations
struct IoUringRuntimeAdapter {
    // (iouring, waiters) where waiters maps a work_id to a sender that
    // will be notified when the work (i.e. database operation) completes.
    work: Mutex<(IoUring, HashMap<u64, oneshot::Sender<i32>>)>,
    // Notification mechanism for completion events
    is_incomplete_work: tokio::sync::Notify,
    // Counter for generating unique operation IDs
    next_work_id: AtomicU64,
}

impl IoUringRuntimeAdapter {
    fn new() -> Self {
        let ring = IoUring::new(128).expect("Failed to create io_uring instance");
        Self {
            work: Mutex::new((ring, HashMap::new())),
            is_incomplete_work: tokio::sync::Notify::new(),
            next_work_id: AtomicU64::new(1),
        }
    }

    /// Submit the operation to the ring and get a future that contains
    /// the result of the operation.
    /// The meaning of the result depends on the operation type.
    /// The `op`'s user data field will be overwritten by this method.
    async fn submit_work(&self, op: io_uring::squeue::Entry) -> Result<i32, Error> {
        // Wrap the operation with this unique work_id to identify it later
        let work_id = self.next_work_id.fetch_add(1, Ordering::SeqCst);
        let op = op.user_data(work_id);

        // Add operation to submission queue and create a channel to wait for completion
        let (sender, receiver) = oneshot::channel();
        {
            let mut work = self.work.lock().unwrap();
            let (ring, waiters) = &mut *work;

            waiters.insert(work_id, sender);
            unsafe {
                ring.submission()
                    .push(&op)
                    .map_err(|_| Error::WriteFailed)?;
            }
            ring.submit().map_err(|_| Error::WriteFailed)?;
        }

        // Notify there's incomplete work
        self.is_incomplete_work.notify_one();

        // Wait for completion
        let res = receiver.await.map_err(|_| Error::RecvFailed)?; // TODO danlaine: update error
        Ok(res)
    }

    /// Background task that polls for completed work and notifies waiters on completion.
    async fn do_work(self: Arc<Self>) {
        loop {
            // Process any new items on the completion queue
            let (is_incomplete_work, is_completed_work) = {
                let mut work = self.work.lock().unwrap();
                let (ring, waiters) = &mut *work;
                ring.submit().unwrap_or(0);

                let mut completed = Vec::new();
                while let Some(cqe) = ring.completion().next() {
                    let work_id = cqe.user_data();
                    completed.push((work_id, cqe.result()));
                }

                // Notify that each operation has completed.
                for (work_id, result) in completed.iter() {
                    if let Some(sender) = waiters.remove(work_id) {
                        let _ = sender.send(*result);
                    }
                }

                (!waiters.is_empty(), !completed.is_empty())
            };

            match (is_incomplete_work, is_completed_work) {
                (_, true) => {
                    // We found completed work last; optimistically loop back to check for more
                    continue;
                }
                (true, false) => {
                    // We're waiting for work to complete but didn't find any completed work.
                    // Yield to allow other tasks to run before checking again.
                    tokio::task::yield_now().await;
                }
                (false, false) => {
                    // We're not waiting for any work to finish.
                    // Wait for notification about new work.
                    self.is_incomplete_work.notified().await;
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    storage_directory: PathBuf,
    io_ring: Arc<IoUringRuntimeAdapter>,
}

impl Storage {
    pub fn new(config: Config) -> Self {
        let adapter = Arc::new(IoUringRuntimeAdapter::new());

        Self {
            storage_directory: config.storage_directory,
            io_ring: adapter,
        }
    }
}

impl Storage {
    pub fn start(&self) {
        // Start the completion handler in a separate task
        let ring = self.io_ring.clone();
        tokio::spawn(ring.do_work());
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Blob, Error> {
        // Construct the full path
        let path = self.storage_directory.join(partition).join(hex(name));
        let parent = path
            .parent()
            .ok_or_else(|| Error::BlobOpenFailed(partition.into(), hex(name)))?;

        // Create the partition directory if it does not exist
        fs::create_dir_all(parent).map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file in read-write mode, create if it does not exist
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| Error::BlobOpenFailed(partition.into(), hex(name)))?;

        // Get the file length
        let len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

        Ok(Blob::new(
            partition.into(),
            name,
            file,
            len,
            self.io_ring.clone(),
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
    io_ring: Arc<IoUringRuntimeAdapter>,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            fd: self.fd.clone(),
            len: AtomicU64::new(self.len.load(Ordering::Relaxed)),
            io_ring: self.io_ring.clone(),
        }
    }
}

impl Blob {
    fn new(
        partition: String,
        name: &[u8],
        file: File,
        len: u64,
        io_ring: Arc<IoUringRuntimeAdapter>,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            fd: Arc::new(OwnedFd::from(file)),
            len: AtomicU64::new(len),
            io_ring,
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

        while total_read < buf.len() {
            let remaining = &mut buf[total_read..];
            let offset = offset + total_read as u64;

            let op = opcode::Read::new(fd, remaining.as_mut_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();
            let result = self.io_ring.submit_work(op).await?;

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

        while total_written < buf.len() {
            let remaining = &buf[total_written..];
            let offset = offset + total_written as u64;

            // Submit write operation using the shared adapter
            let op = opcode::Write::new(fd, remaining.as_ptr(), remaining.len() as _)
                .offset(offset as _)
                .build();
            let result = self.io_ring.submit_work(op).await?;

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
        self.io_ring
            .submit_work(op)
            .await
            .map_err(|_| Error::BlobTruncateFailed(self.partition.clone(), hex(&self.name)))?;

        // Update length
        self.len.store(len, Ordering::SeqCst);
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let op = opcode::Fsync::new(types::Fd(self.fd.as_raw_fd())).build();
        // Submit fsync operation via io_uring
        self.io_ring
            .submit_work(op)
            .await
            .map_err(|_| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name)))?;

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
    use crate::storage::tests::run_storage_tests;
    use rand::{Rng as _, SeedableRng as _};
    use std::env;

    #[tokio::test]
    async fn test_iouring_storage() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("commonware_iouring_storage_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory.clone());
        let storage = Storage::new(config);
        run_storage_tests(storage).await;
    }
}
