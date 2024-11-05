use std::future::IntoFuture;

use super::{Config, Error};
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use tracing::debug;

const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

pub struct Metadata<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    cursor: usize,
    blobs: [(B, u32); 2],
}

pub struct Batch {
    pending: Vec<u8>,
}

impl Batch {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    pub fn append(&mut self, key: &[u8], value: Bytes) -> Result<(), Error> {
        let key_len = key.len().try_into().map_err(|_| Error::DataTooBig)?;
        self.pending.put_u32(key_len);
        self.pending.put(key);
        let value_len = value.len().try_into().map_err(|_| Error::DataTooBig)?;
        self.pending.put_u32(value_len);
        self.pending.put(value);
        Ok(())
    }
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Blob, E: Storage<B>> Metadata<B, E> {
    async fn verify(blob: &B) -> Result<Option<(u32, u32)>, Error> {
        // Get blob length
        let len = blob.len().await?;
        let len = len.try_into().map_err(|_| Error::BlobTooLarge(len))?;
        if len == 0 {
            // Empty blob
            return Ok(None);
        }

        // Read blob
        let mut buf = vec![0u8; len];
        blob.read_at(&mut buf, 0).await?;

        // Verify integrity
        let stored_checksum = u32::from_be_bytes(buf[buf.len() - 4..].try_into().unwrap());
        let computed_checksum = crc32fast::hash(&buf[..buf.len() - 4]);
        if stored_checksum != computed_checksum {
            // Truncate and return none
            debug!(
                stored = stored_checksum,
                computed = computed_checksum,
                "checksum mismatch: truncating"
            );
            blob.truncate(0).await?;
            blob.sync().await?;
            return Ok(None);
        }

        // Get parent
        let parent = u32::from_be_bytes(buf[..4].try_into().unwrap());

        // Return info
        Ok(Some((parent, computed_checksum)))
    }

    pub async fn init(runtime: E, cfg: Config) -> Result<Self, Error> {
        // Open dedicated blobs
        let left = runtime.open(&cfg.partition, BLOB_NAMES[0]).await?;
        let right = runtime.open(&cfg.partition, BLOB_NAMES[1]).await?;

        // Find latest blob (check which includes a hash of the other)
        let left_result = Self::verify(&left).await?;
        let right_result = Self::verify(&right).await?;

        // Set checksums
        let mut left_parent = 0;
        let mut left_checksum = 0;
        if let Some((parent, checksum)) = left_result {
            left_parent = parent;
            left_checksum = checksum;
        }
        let mut right_parent = 0;
        let mut right_checksum = 0;
        if let Some((parent, checksum)) = right_result {
            right_parent = parent;
            right_checksum = checksum;
        }

        // Choose latest blob
        let mut cursor = 0;
        if right_checksum != 0 {
            if right_parent == left_checksum {
                cursor = 1;
            } else if left_parent == right_checksum {
                cursor = 0;
            } else {
                panic!("cannot determine latest blob");
            }
        }

        // Return metadata
        Ok(Self {
            runtime,
            cfg,
            cursor,
            blobs: [(left, left_checksum), (right, right_checksum)],
        })
    }

    pub async fn commit(&mut self, batch: Batch) -> Result<(), Error> {
        // Get current blob
        let past_checksum = &self.blobs[self.cursor].1;

        // Get next blob
        let next_cursor = 1 - self.cursor;
        let next_blob = &self.blobs[next_cursor].0;

        // Create buffer
        let mut buf = Vec::with_capacity(4 + batch.pending.len() + 4);
        buf.put_u32(*past_checksum);
        buf.put(&batch.pending[..]);
        buf.put_u32(crc32fast::hash(&buf[..]));

        // Write batch
        next_blob.write_at(&buf, 0).await?;
        next_blob.sync().await?;

        // Switch blobs
        self.cursor = next_cursor;
        Ok(())
    }
}
