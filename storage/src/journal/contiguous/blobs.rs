//! Blob storage for contiguous journals.

use crate::{
    journal::{contiguous::metrics::BlobsMetrics, Error},
    Context,
};
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::paged::{AppendWriter, CacheRef, Sealed},
    telemetry::metrics::GaugeExt as _,
    Blob, Error as RError,
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
    fn new(
        context: E,
        partition: String,
        page_cache: CacheRef,
        write_buffer: NonZeroUsize,
        tracked: usize,
    ) -> Self {
        let metrics = BlobsMetrics::new(&context);
        let _ = metrics.tracked.try_set(tracked);
        Self {
            context,
            partition,
            page_cache,
            write_buffer,
            metrics,
        }
    }

    /// Open the given blob as a writable [`AppendWriter`], creating it if it does not exist.
    pub(super) async fn open_append(&self, blob: u64) -> Result<AppendWriter<E::Blob>, Error> {
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

/// The writable tail blob.
pub(super) struct Tail<B: Blob> {
    pub(super) blob: u64,
    pub(super) writer: AppendWriter<B>,
}

/// The blobs that comprise a contiguous journal.
pub(super) struct Blobs<E: Context> {
    pub(super) io: BlobIo<E>,
    // The first blob's number.
    pub(super) base_blob: u64,
    // The immutable sealed blobs.
    pub(super) sealed: Vec<Sealed<E::Blob>>,
    // The writable tail blob.
    pub(super) tail: Tail<E::Blob>,
}

/// Configuration for [`RecoveryBlobs`].
#[derive(Clone)]
pub(super) struct Config {
    /// Partition where blobs live. Each blob named by its `u64` big-endian bytes.
    pub partition: String,
    /// The page cache used for reads of full pages.
    pub page_cache: CacheRef,
    /// The capacity, in bytes, of the tail's write buffer.
    pub write_buffer: NonZeroUsize,
}
/// Recovery-phase store holding every blob as a writable [`AppendWriter`].
/// Transformed into [`Blobs`] at recovery completion.
pub(super) struct RecoveryBlobs<E: Context> {
    io: BlobIo<E>,
    pending: BTreeMap<u64, AppendWriter<E::Blob>>,
}

impl<E: Context> RecoveryBlobs<E> {
    /// Scan the partition and open every existing blob as an [`AppendWriter`].
    pub(super) async fn open(context: E, cfg: Config) -> Result<Self, Error> {
        let stored = match context.scan(&cfg.partition).await {
            Ok(names) => names,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        let mut pending = BTreeMap::new();
        for name in stored {
            let hex_name = hex(&name);
            let bytes: [u8; 8] = name
                .clone()
                .try_into()
                .map_err(|_| Error::InvalidBlobName(hex_name.clone()))?;
            let index = u64::from_be_bytes(bytes);
            let (blob, size) = context
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            debug!(index, blob = hex_name, size, "loaded blob");
            let writer =
                AppendWriter::new(blob, size, cfg.write_buffer.get(), cfg.page_cache.clone())
                    .await
                    .map_err(Error::Runtime)?;
            pending.insert(index, writer);
        }

        let io = BlobIo::new(
            context,
            cfg.partition,
            cfg.page_cache,
            cfg.write_buffer,
            pending.len(),
        );
        Ok(Self { io, pending })
    }

    /// All blob numbers in ascending order.
    pub(super) fn blobs(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }

    /// The oldest blob number.
    pub(super) fn oldest_blob(&self) -> Option<u64> {
        self.pending.keys().next().copied()
    }

    /// The newest blob number.
    pub(super) fn newest_blob(&self) -> Option<u64> {
        self.pending.keys().next_back().copied()
    }

    /// Logical size, in bytes, of the given blob, or `None` if it does not exist.
    pub(super) async fn blob_size(&self, blob: u64) -> Option<u64> {
        match self.pending.get(&blob) {
            Some(writer) => Some(writer.size().await),
            None => None,
        }
    }

    /// Shrink the given blob to `size` bytes and sync it.
    /// No-op if the blob is absent or already at or below `size`.
    pub(super) async fn truncate_blob(&self, blob: u64, size: u64) -> Result<(), Error> {
        let Some(blob) = self.pending.get(&blob) else {
            return Ok(());
        };
        let current = blob.size().await;
        if size < current {
            blob.resize(size).await.map_err(Error::Runtime)?;
            blob.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Drop the blob's handle and remove it from storage.
    pub(super) async fn remove_blob(&mut self, blob: u64) -> Result<(), Error> {
        if let Some(writer) = self.pending.remove(&blob) {
            drop(writer);
            self.io.remove_blob(blob).await?;
            self.io.metrics.tracked.dec();
        }
        Ok(())
    }

    /// Seal every blob below `tail_blob` and return the resulting [`Blobs`].
    /// Opens a new tail blob if none exists at `tail_blob`.
    ///
    /// The caller determines `tail_blob` from the recovered size; it may name a blob that does
    /// not exist on disk (an empty journal, a crash after the newest blob filled but before the
    /// next opened, or a reset).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corruption`] if a pending blob is greater than `tail_blob` (remove
    /// it first via [`Self::remove_blob`]) or if the retained blobs are not contiguous.
    pub(super) async fn into_blobs(self, tail_blob: u64) -> Result<Blobs<E>, Error> {
        if let Some(newest) = self.pending.keys().next_back().copied() {
            if newest > tail_blob {
                return Err(Error::Corruption(format!(
                    "into_blobs: blobs > tail_blob {tail_blob} exist (newest={newest})"
                )));
            }
        }

        let io = self.io;
        let mut sealed = Vec::with_capacity(self.pending.len());
        let mut tail: Option<Tail<E::Blob>> = None;
        let mut expected = self.pending.keys().next().copied();
        for (blob, writer) in self.pending {
            if expected != Some(blob) {
                return Err(Error::Corruption(format!(
                    "into_blobs: retained blobs must be contiguous (expected {expected:?}, got \
                     {blob})"
                )));
            }
            expected = blob.checked_add(1);
            if blob == tail_blob {
                tail = Some(Tail { blob, writer });
            } else {
                let s = writer.seal().await.map_err(Error::Runtime)?;
                sealed.push(s);
            }
        }
        if let Some(expected) = expected {
            if tail.is_none() && expected != tail_blob {
                return Err(Error::Corruption(format!(
                    "into_blobs: sealed blobs end at {expected} but tail is {tail_blob}"
                )));
            }
        }
        // If the caller requested a tail that doesn't exist among the pending blobs, open it.
        let tail = match tail {
            Some(tail) => tail,
            None => {
                let writer = io.open_append(tail_blob).await?;
                io.metrics.tracked.inc();
                Tail {
                    blob: tail_blob,
                    writer,
                }
            }
        };

        let base_blob = tail_blob - sealed.len() as u64;
        Ok(Blobs {
            io,
            base_blob,
            sealed,
            tail,
        })
    }

    /// Remove all existing blobs and install a fresh empty tail at `tail_blob`.
    pub(super) async fn reset(mut self, tail_blob: u64) -> Result<Blobs<E>, Error> {
        let pending = std::mem::take(&mut self.pending);
        for (blob, writer) in pending {
            drop(writer);
            self.io.remove_blob(blob).await?;
        }
        let _ = self.io.metrics.tracked.try_set(0);

        let writer = self.io.open_append(tail_blob).await?;
        self.io.metrics.tracked.inc();
        Ok(Blobs {
            io: self.io,
            base_blob: tail_blob,
            sealed: Vec::new(),
            tail: Tail {
                blob: tail_blob,
                writer,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _, Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU16};
    use rstest::rstest;
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(64);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
    const WRITE_BUFFER: NonZeroUsize = NZUsize!(256);

    fn test_cfg(pooler: &impl BufferPooler, partition: &str) -> Config {
        Config {
            partition: partition.into(),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: WRITE_BUFFER,
        }
    }

    #[rstest]
    #[case::missing_blob_is_a_noop(1, 2, 0)]
    #[case::existing_blob_can_be_shrunk(0, 2, 2)]
    #[case::same_size_is_a_noop(0, 5, 5)]
    #[case::larger_size_is_a_noop(0, 8, 5)]
    fn test_recovery_blobs_truncate_blob(
        #[case] blob: u64,
        #[case] truncate_to: u64,
        #[case] expected_size: u64,
    ) {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-truncate-init");

            {
                let init = RecoveryBlobs::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let blobs = init.into_blobs(0).await.unwrap();
                blobs.tail.writer.append(b"hello").await.unwrap();
                blobs.tail.writer.sync().await.unwrap();
            }

            let init = RecoveryBlobs::open(context.child("repair"), cfg.clone())
                .await
                .unwrap();

            // Init-time truncation is a repair tool: it only shrinks existing blobs and is a
            // no-op for missing blobs or requests at/above the current size.
            init.truncate_blob(blob, truncate_to).await.unwrap();
            drop(init);

            let reopened = RecoveryBlobs::open(context.child("verify"), cfg).await.unwrap();
            assert_eq!(reopened.blob_size(blob).await.unwrap_or(0), expected_size);
        });
    }

    /// Empty partition -> RecoveryBlobs with no blobs -> Blobs with just a fresh tail.
    #[test_traced]
    fn test_recovery_blobs_empty_then_install_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-empty");
            let init = RecoveryBlobs::open(context, cfg).await.unwrap();
            assert!(init.blobs().is_empty());
            let blobs = init.into_blobs(0).await.unwrap();
            assert_eq!(blobs.tail.blob, 0);
            assert_eq!(blobs.base_blob, 0);
            assert!(blobs.sealed.is_empty());
        });
    }

    /// Blobs strictly below the tail are sealed, in dense ascending order, and stay readable.
    #[test_traced]
    fn test_blobs_into_blobs_seals_history() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-seal-history");
            {
                let init = RecoveryBlobs::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let blobs = init.into_blobs(0).await.unwrap();
                blobs.tail.writer.append(b"hello").await.unwrap();
                blobs.tail.writer.sync().await.unwrap();
                let blob1 = blobs.io.open_append(1).await.unwrap();
                blob1.append(b"world").await.unwrap();
                blob1.sync().await.unwrap();
            }

            let init = RecoveryBlobs::open(context.child("reopen"), cfg).await.unwrap();
            assert_eq!(init.blobs(), vec![0, 1]);
            let blobs = init.into_blobs(1).await.unwrap();
            assert_eq!(blobs.base_blob, 0);
            assert_eq!(blobs.sealed.len(), 1);
            assert_eq!(blobs.tail.blob, 1);

            // The sealed historical blob is readable through its handle.
            let bufs = blobs.sealed[0].read_at(0, 5).await.unwrap();
            assert_eq!(bufs.coalesce().as_ref(), b"hello");
            // The tail is readable through its writer.
            let bufs = blobs.tail.writer.read_at(0, 5).await.unwrap();
            assert_eq!(bufs.coalesce().as_ref(), b"world");
        });
    }

    /// `reset` removes every blob and installs a fresh empty tail.
    #[test_traced]
    fn test_recovery_blobs_reset_clears_and_installs_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reset");
            {
                let init = RecoveryBlobs::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let blobs = init.into_blobs(0).await.unwrap();
                blobs.tail.writer.append(b"junk").await.unwrap();
                blobs.tail.writer.sync().await.unwrap();
            }

            let init = RecoveryBlobs::open(context.child("reset"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(init.blobs(), vec![0]);
            let blobs = init.reset(7).await.unwrap();
            assert!(blobs.sealed.is_empty());
            assert_eq!(blobs.base_blob, 7);
            assert_eq!(blobs.tail.blob, 7);
            assert_eq!(blobs.tail.writer.size().await, 0);

            // Only the fresh tail blob remains on disk.
            drop(blobs);
            let reopened = RecoveryBlobs::open(context.child("verify"), cfg).await.unwrap();
            assert_eq!(reopened.blobs(), vec![7]);
        });
    }

    /// `into_blobs` rejects pending blobs newer than the requested tail.
    #[test_traced]
    fn test_blobs_into_blobs_rejects_newer_blobs() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reject-newer");
            {
                let init = RecoveryBlobs::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let blobs = init.into_blobs(0).await.unwrap();
                blobs.tail.writer.append(b"a").await.unwrap();
                blobs.tail.writer.sync().await.unwrap();
                let newer = blobs.io.open_append(3).await.unwrap();
                newer.append(b"b").await.unwrap();
                newer.sync().await.unwrap();
            }

            let init = RecoveryBlobs::open(context.child("reopen"), cfg).await.unwrap();
            match init.into_blobs(0).await {
                Err(Error::Corruption(_)) => {}
                Err(err) => panic!("expected corruption, got: {err:?}"),
                Ok(_) => panic!("expected corruption, got parts"),
            }
        });
    }

    /// `into_blobs` rejects a non-dense run of retained blobs.
    #[test_traced]
    fn test_blobs_into_blobs_rejects_gap() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reject-gap");
            {
                let init = RecoveryBlobs::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let blobs = init.into_blobs(0).await.unwrap();
                blobs.tail.writer.append(b"a").await.unwrap();
                blobs.tail.writer.sync().await.unwrap();
                // Create blob 2, leaving a gap at blob 1.
                let newer = blobs.io.open_append(2).await.unwrap();
                newer.append(b"b").await.unwrap();
                newer.sync().await.unwrap();
            }

            let init = RecoveryBlobs::open(context.child("reopen"), cfg).await.unwrap();
            match init.into_blobs(2).await {
                Err(Error::Corruption(_)) => {}
                Err(err) => panic!("expected corruption, got: {err:?}"),
                Ok(_) => panic!("expected corruption, got parts"),
            }
        });
    }
}
