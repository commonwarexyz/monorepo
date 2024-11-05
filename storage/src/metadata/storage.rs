use std::future::IntoFuture;

use super::{Config, Error};
use commonware_runtime::{Blob, Storage};
use tracing::debug;

const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

pub struct Metadata<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    cursor: usize,
    blobs: [B; 2],
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

        // Choose latest blob
        let mut cursor = 0;
        if let Some((right_parent, right_checksum)) = right_result {
            match left_result {
                Some((left_parent, left_checksum)) => {
                    if right_parent == left_checksum {
                        cursor = 1;
                    } else if left_parent == right_checksum {
                        cursor = 0;
                    } else {
                        panic!("cannot determine latest blob");
                    }
                }
                None => {
                    cursor = 1;
                }
            }
        }

        // Return metadata
        Ok(Self {
            runtime,
            cfg,
            cursor,
            blobs: [left, right],
        })
    }
}
