//! Maps blob indices to named blobs in the journal's partition.

use crate::{
    journal::{contiguous::metrics::BlobsMetrics, Error},
    Context,
};
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::paged::{AppendWriter, CacheRef},
    Error as RError,
};
use std::{collections::BTreeMap, num::NonZeroUsize};
use tracing::debug;

/// Opens and removes the journal's blobs.
pub(super) struct BlobIo<E: Context> {
    context: E,
    partition: String,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,
    pub(super) metrics: BlobsMetrics,
}

impl<E: Context> BlobIo<E> {
    pub(super) fn new(
        context: E,
        partition: String,
        page_cache: CacheRef,
        write_buffer: NonZeroUsize,
    ) -> Self {
        let metrics = BlobsMetrics::new(&context);
        Self {
            context,
            partition,
            page_cache,
            write_buffer,
            metrics,
        }
    }

    /// Scan the partition and open every existing blob as a writable [`AppendWriter`], keyed by
    /// blob number.
    pub(super) async fn open_all(
        &self,
    ) -> Result<BTreeMap<u64, AppendWriter<E::Blob>>, Error> {
        let stored = match self.context.scan(&self.partition).await {
            Ok(names) => names,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        let mut blobs = BTreeMap::new();
        for name in stored {
            let hex_name = hex(&name);
            let bytes: [u8; 8] = name
                .clone()
                .try_into()
                .map_err(|_| Error::InvalidBlobName(hex_name.clone()))?;
            let index = u64::from_be_bytes(bytes);
            let (blob, size) = self
                .context
                .open(&self.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            debug!(index, blob = hex_name, size, "loaded blob");
            let writer =
                AppendWriter::new(blob, size, self.write_buffer.get(), self.page_cache.clone())
                    .await
                    .map_err(Error::Runtime)?;
            blobs.insert(index, writer);
        }
        Ok(blobs)
    }

    /// Open the given blob as a writable [`AppendWriter`], creating it if it does not exist.
    pub(super) async fn open(&self, blob: u64) -> Result<AppendWriter<E::Blob>, Error> {
        let name = blob.to_be_bytes();
        let (blob, size) = self
            .context
            .open(&self.partition, &name)
            .await
            .map_err(Error::Runtime)?;
        AppendWriter::new(blob, size, self.write_buffer.get(), self.page_cache.clone())
            .await
            .map_err(Error::Runtime)
    }

    /// Remove the given blob from storage.
    pub(super) async fn remove_blob(&self, blob: u64) -> Result<(), Error> {
        self.context
            .remove(&self.partition, Some(&blob.to_be_bytes()))
            .await
            .map_err(Error::Runtime)
    }

    /// Remove the partition itself, treating "already missing" as success.
    pub(super) async fn remove_partition(&self) -> Result<(), Error> {
        match self.context.remove(&self.partition, None).await {
            Ok(()) | Err(RError::PartitionMissing(_)) => Ok(()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }
}
