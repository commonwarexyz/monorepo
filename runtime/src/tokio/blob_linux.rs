use std::{
    fs::{self, File},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::Arc,
};

use commonware_utils::{from_hex, hex};
use io_uring::{opcode, types, IoUring};
use tokio::sync::Mutex;

use crate::Error;

#[derive(Clone)]
pub struct Storage {
    lock: Arc<Mutex<()>>,
    storage_directory: PathBuf,
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Blob, Error> {
        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Construct the full path
        let path = self.storage_directory.join(partition).join(hex(name));
        let parent = match path.parent() {
            Some(parent) => parent,
            None => return Err(Error::PartitionCreationFailed(partition.into())),
        };

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

        // Construct the blob
        Ok(Blob::new(
            partition.into(),
            name,
            file,
            len as u32, // TODO danlaine: handle overflow
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Remove all related files
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
        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Scan the partition directory
        let path = self.storage_directory.join(partition);
        let mut entries = tokio::fs::read_dir(path)
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

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    file: Arc<Mutex<(File, IoUring, u32)>>,
}

impl Blob {
    pub fn new(partition: String, name: &[u8], file: File, len: u32) -> Self {
        let ring = IoUring::new(32).unwrap();
        Self {
            partition,
            name: name.into(),
            file: Arc::new(Mutex::new((file, ring, len))),
        }
    }
}

impl crate::Blob for Blob {
    async fn len(&self) -> Result<u64, Error> {
        Ok(self.file.lock().await.2 as u64)
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        // Lock the file to ensure safe access
        let mut foo = self.file.lock().await;

        let (file, ring, len) = &mut *foo;

        if offset + buf.len() as u64 > *len as u64 {
            return Err(Error::BlobInsufficientLength);
        }

        // Get the raw file descriptor
        let fd = file.as_raw_fd();
        let mut total_read = 0;

        while total_read < buf.len() {
            let remaining = &mut buf[total_read..];

            // Prepare the read operation
            let read_e =
                opcode::Read::new(types::Fd(fd), remaining.as_mut_ptr(), remaining.len() as _)
                    .offset(offset as _)
                    .build()
                    .user_data(0); // User data can be used to identify the operation

            // Submit the operation to the ring
            unsafe {
                ring.submission()
                    .push(&read_e)
                    .map_err(|_| Error::ReadFailed)?; // TODO danlaine: consider changing error values.
            }

            // Wait for the operation to complete
            ring.submit_and_wait(1).map_err(|_| Error::ReadFailed)?;

            // Process the completion event
            let cqe = ring.completion().next().ok_or(Error::ReadFailed)?;

            // If the return value is non-positive, it indicates an error.
            let bytes_read: usize = cqe.result().try_into().map_err(|_| Error::ReadFailed)?;
            if bytes_read == 0 {
                // Got EOF before filling buffer.
                return Err(Error::BlobInsufficientLength);
            }

            total_read += bytes_read;
        }

        Ok(())
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        let mut file = self.file.lock().await;

        let (file, ring, len) = &mut *file;

        // Get the raw file descriptor
        let fd = file.as_raw_fd();
        let mut total_written = 0;

        while total_written < buf.len() {
            let remaining = &buf[total_written..];

            // Prepare the write operation
            let write_e =
                opcode::Write::new(types::Fd(fd), remaining.as_ptr(), remaining.len() as _)
                    .offset(offset as _)
                    .build();

            // Submit the operation to the ring
            unsafe {
                ring.submission()
                    .push(&write_e)
                    .map_err(|_| Error::WriteFailed)?; // TODO danlaine: consider changing error values.
            }

            // Wait for the operation to complete
            ring.submit_and_wait(1).map_err(|_| Error::WriteFailed)?;

            // Process the completion event
            let cqe = ring.completion().next().ok_or(Error::ReadFailed)?;
            let bytes_written: usize = cqe.result().try_into().map_err(|_| Error::ReadFailed)?;
            if bytes_written == 0 {
                return Err(Error::WriteFailed);
            }
            total_written += bytes_written;
        }

        // Update the virtual file size
        let max_len = offset + buf.len() as u64;
        if max_len > *len as u64 {
            *len = max_len as u32;
        }
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        // Perform the truncate
        let mut file = self.file.lock().await;
        file.0
            .set_len(len)
            .map_err(|_| Error::BlobTruncateFailed(self.partition.clone(), hex(&self.name)))?;

        // Update the virtual file size
        file.2 = len as u32; // todo danlaine: handle overflow
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.lock().await;
        file.0
            .sync_all()
            .map_err(|_| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name)))
    }

    async fn close(self) -> Result<(), Error> {
        self.sync().await
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        //self.metrics.open_blobs.dec();
    }
}
