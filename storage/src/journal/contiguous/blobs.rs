//! Blob storage for a contiguous journal: a dense run of sealed blobs ending in one
//! writable tail.

use super::snapshot::Snapshot;
use crate::{journal::Error, Context};
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::paged::{CacheRef, Sealed, Writer},
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
    Blob, Error as RError,
};
use futures::future::try_join_all;
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tracing::debug;

/// Metrics for a journal's blobs.
struct Metrics {
    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl Metrics {
    fn new<E: Context>(context: &E) -> Self {
        Self {
            tracked: context.gauge("tracked", "Number of blobs held"),
            synced: context.counter("synced", "Number of blob syncs"),
            pruned: context.counter("pruned", "Number of blobs pruned"),
        }
    }
}

/// A storage partition holding blobs.
pub(super) struct Partition<E: Context> {
    context: E,
    name: String,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,
}

impl<E: Context> Partition<E> {
    pub(super) const fn new(
        context: E,
        name: String,
        page_cache: CacheRef,
        write_buffer: NonZeroUsize,
    ) -> Self {
        Self {
            context,
            name,
            page_cache,
            write_buffer,
        }
    }

    /// Open the given blob as a [`Writer`], creating it if it does not exist.
    pub(super) async fn open(&self, blob: u64) -> Result<Writer<E::Blob>, Error> {
        let name = blob.to_be_bytes();
        let (blob, size) = self
            .context
            .open(&self.name, &name)
            .await
            .map_err(Error::Runtime)?;
        Writer::new(blob, size, self.write_buffer.get(), self.page_cache.clone())
            .await
            .map_err(Error::Runtime)
    }

    /// Scan the partition and open every existing blob as a [`Writer`], keyed by blob
    /// number. Used before [Blobs::recover] so recovery can inspect and repair the writers.
    pub(super) async fn open_all(&self) -> Result<BTreeMap<u64, Writer<E::Blob>>, Error> {
        let stored = match self.context.scan(&self.name).await {
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
            let writer = self.open(index).await?;
            debug!(index, blob = hex_name, "loaded blob");
            blobs.insert(index, writer);
        }
        Ok(blobs)
    }

    /// Remove the given blob.
    pub(super) async fn remove(&self, blob: u64) -> Result<(), Error> {
        self.context
            .remove(&self.name, Some(&blob.to_be_bytes()))
            .await
            .map_err(Error::Runtime)
    }

    /// Remove the partition itself, treating "already missing" as success.
    async fn remove_all(&self) -> Result<(), Error> {
        match self.context.remove(&self.name, None).await {
            Ok(()) | Err(RError::PartitionMissing(_)) => Ok(()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }
}

/// The writable tail blob.
struct Tail<B: Blob> {
    blob: u64,
    writer: Writer<B>,
}

/// A dense run of sealed blobs ending in one writable tail, stored in a partition.
///
/// Every operation that adds or drops blobs keeps the run dense and replaces the sealed slice
/// whole, so a [Snapshot] holding the old slice keeps valid handles. The journal owns all
/// position arithmetic; this type is told blob numbers and byte offsets and trusts them.
///
/// Any error returned by a `&mut self` method leaves the run in an unspecified state; the
/// journal must be considered unusable and dropped.
pub(super) struct Blobs<E: Context> {
    partition: Partition<E>,
    metrics: Metrics,

    /// The one writable blob; appends go here.
    tail: Tail<E::Blob>,

    /// Number of the first blob in [Self::sealed].
    base_blob: u64,

    /// Sealed historical blobs, ascending and dense from `base_blob`.
    sealed: Arc<[Sealed<E::Blob>]>,

    /// Number of live [Snapshot]s. Gates in-place truncation during rewind.
    readers: Arc<AtomicUsize>,
}

impl<E: Context> Blobs<E> {
    /// Build a run from recovered writers: seal every blob below `tail_blob` and install the
    /// tail, opening an empty one if absent.
    ///
    /// Retained blobs must be contiguous: positions map to blobs by arithmetic, so a gap would
    /// make some retained position unreadable. No blob may exceed `tail_blob`, and any blobs
    /// present must end at `tail_blob` (the caller derives `tail_blob` from the recovered size,
    /// which is in turn derived from these blobs).
    pub(super) async fn recover(
        partition: Partition<E>,
        pending: BTreeMap<u64, Writer<E::Blob>>,
        tail_blob: u64,
    ) -> Result<Self, Error> {
        if let Some(&newest) = pending.keys().next_back() {
            if newest > tail_blob {
                return Err(Error::Corruption(format!(
                    "blobs > tail blob {tail_blob} exist (newest={newest})"
                )));
            }
        }
        let oldest = pending.keys().next().copied();
        let mut sealed = Vec::with_capacity(pending.len());
        let mut tail = None;
        let mut expected = oldest;
        for (blob, writer) in pending {
            if expected != Some(blob) {
                return Err(Error::Corruption(format!(
                    "retained blobs must be contiguous (expected {expected:?}, got {blob})"
                )));
            }
            expected = blob.checked_add(1);
            if blob == tail_blob {
                tail = Some(Tail { blob, writer });
            } else {
                sealed.push(writer.seal().await.map_err(Error::Runtime)?);
            }
        }
        let tail = match tail {
            Some(tail) => tail,
            None => Tail {
                blob: tail_blob,
                writer: partition.open(tail_blob).await?,
            },
        };

        let metrics = Metrics::new(&partition.context);
        let _ = metrics.tracked.try_set(sealed.len() + 1);
        let blobs = Self {
            partition,
            metrics,
            base_blob: tail.blob - sealed.len() as u64,
            tail,
            sealed: sealed.into(),
            readers: Arc::new(AtomicUsize::new(0)),
        };
        if !blobs.sealed.is_empty() {
            debug_assert_eq!(Some(blobs.base_blob), oldest);
        }
        blobs.check_invariants();
        Ok(blobs)
    }

    /// Assert the run invariant: `sealed` is exactly the blobs `[base_blob, tail.blob)`.
    fn check_invariants(&self) {
        debug_assert!(self.base_blob <= self.tail.blob);
        debug_assert_eq!(self.sealed.len() as u64, self.tail.blob - self.base_blob);
    }

    /// The tail's blob.
    pub(super) const fn tail_blob(&self) -> u64 {
        self.tail.blob
    }

    /// Number of the first retained blob.
    pub(super) const fn base_blob(&self) -> u64 {
        self.base_blob
    }

    /// The tail's writer; appends go through it.
    pub(super) const fn tail_writer(&self) -> &Writer<E::Blob> {
        &self.tail.writer
    }

    /// Test helper: make one blob durable (sealed history or the tail).
    #[cfg(test)]
    pub(super) async fn sync_blob(&self, blob: u64) -> Result<(), Error> {
        if blob == self.tail.blob {
            return self.tail.writer.sync().await.map_err(Error::Runtime);
        }
        match blob
            .checked_sub(self.base_blob)
            .and_then(|idx| self.sealed.get(idx as usize))
        {
            Some(sealed) => sealed.sync().await.map_err(Error::Runtime),
            None => Ok(()),
        }
    }

    /// Capture a [Snapshot] backing `size` and `pruning_boundary`.
    pub(super) fn snapshot(&self, size: u64, pruning_boundary: u64) -> Snapshot<E::Blob> {
        Snapshot::new(
            self.base_blob,
            self.sealed.clone(),
            self.tail.writer.reader(),
            size,
            pruning_boundary,
            self.readers.clone(),
        )
    }

    /// Seal the tail (no fsync) and open the next blob as the new tail.
    pub(super) async fn roll(&mut self) -> Result<(), Error> {
        // Open the next tail first so a failure leaves the current tail untouched.
        let next_blob = self.tail.blob.checked_add(1).ok_or(Error::OffsetOverflow)?;
        let new_writer = self.partition.open(next_blob).await?;
        let old = std::mem::replace(
            &mut self.tail,
            Tail {
                blob: next_blob,
                writer: new_writer,
            },
        );
        let sealed = old.writer.seal().await.map_err(Error::Runtime)?;
        self.metrics.tracked.inc();

        let mut sealed_vec: Vec<Sealed<E::Blob>> = self.sealed.to_vec();
        sealed_vec.push(sealed);
        self.sealed = sealed_vec.into();
        self.check_invariants();
        Ok(())
    }

    /// Drop every blob below `min_blob` and remove its file, oldest-first (gap-free on
    /// failure). Snapshots holding the old slice keep reading the removed blobs.
    ///
    /// The caller guarantees `base_blob < min_blob <= tail_blob`. A crash mid-removal leaves
    /// orphan files below the new base; reopen re-absorbs them as retained-but-pruned history.
    pub(super) async fn prune_below(&mut self, min_blob: u64) -> Result<(), Error> {
        debug_assert!(self.base_blob < min_blob && min_blob <= self.tail.blob);
        let drop_count = (min_blob - self.base_blob) as usize;
        let old_base = self.base_blob;
        self.sealed = self.sealed[drop_count..].to_vec().into();
        self.base_blob = min_blob;
        self.check_invariants();

        for blob in old_base..min_blob {
            self.partition.remove(blob).await?;
            self.metrics.tracked.dec();
            self.metrics.pruned.inc();
        }
        Ok(())
    }

    /// Shrink the tail in place. Racing readers get clean errors from the resize, never torn
    /// bytes.
    pub(super) async fn rewind_tail(&mut self, byte_offset: u64) -> Result<(), Error> {
        let current_bytes = self.tail.writer.size().await;
        if byte_offset < current_bytes {
            self.tail
                .writer
                .resize(byte_offset)
                .await
                .map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Rewind into a sealed blob: demote it to the writable tail, truncated to `byte_offset`,
    /// discarding every newer blob.
    ///
    /// The caller guarantees `blob < tail_blob` (a non-retained target is treated as
    /// corruption) and has already durably lowered any external recovery watermark to at most
    /// the rewind target; this method only moves blob state.
    ///
    /// In-place truncation requires no outstanding [Snapshot]s. Returns [Error::BlobInUse]
    /// otherwise.
    pub(super) async fn rewind_into_sealed(
        &mut self,
        blob: u64,
        byte_offset: u64,
    ) -> Result<(), Error> {
        let idx = blob
            .checked_sub(self.base_blob)
            .map(|idx| idx as usize)
            .filter(|&idx| idx < self.sealed.len())
            .ok_or_else(|| Error::Corruption(format!("rewind target blob {blob} not retained")))?;

        if self.readers.load(Ordering::Acquire) != 0 {
            return Err(Error::BlobInUse(blob));
        }

        // Sync the target before destructive work so a crash recovers a size no shorter than
        // the rewind target.
        self.sealed[idx].sync().await.map_err(Error::Runtime)?;
        self.metrics.synced.inc();

        // Reopen the target as the writable tail and truncate in place. The fresh Writer
        // gets a fresh page-cache id, so pages cached under the sealed handle's id are
        // unreachable.
        let new_writer = self.partition.open(blob).await?;
        let current_bytes = new_writer.size().await;
        if byte_offset < current_bytes {
            new_writer
                .resize(byte_offset)
                .await
                .map_err(Error::Runtime)?;
        }

        // Remove newer blobs newest-first so a crash leaves a contiguous prefix: the old
        // tail, then sealed blobs down to the target.
        let old_tail_blob = self.tail.blob;
        self.tail = Tail {
            blob,
            writer: new_writer,
        };
        self.partition.remove(old_tail_blob).await?;
        self.metrics.tracked.dec();
        for newer in ((blob + 1)..old_tail_blob).rev() {
            self.partition.remove(newer).await?;
            self.metrics.tracked.dec();
        }

        // Sealed history now ends below the target, which is the tail.
        self.sealed = self.sealed[..idx].to_vec().into();
        self.check_invariants();
        Ok(())
    }

    /// Remove every blob and start a fresh empty run with its tail at `tail_blob`.
    pub(super) async fn clear(&mut self, tail_blob: u64) -> Result<(), Error> {
        for blob in self.base_blob..=self.tail.blob {
            self.partition.remove(blob).await?;
        }
        let _ = self.metrics.tracked.try_set(0);
        let new_writer = self.partition.open(tail_blob).await?;
        self.metrics.tracked.inc();
        self.tail = Tail {
            blob: tail_blob,
            writer: new_writer,
        };
        self.base_blob = tail_blob;
        self.sealed = Vec::new().into();
        self.check_invariants();
        Ok(())
    }

    /// Make every blob from `start_blob` onward durable: sealed blobs through their handles,
    /// the tail through the writer.
    ///
    /// Blobs are synced concurrently. Ordering is not required for recovery: appends only add
    /// data, so committed blobs are never at risk, and recovery truncates at the first short or
    /// missing blob, so a crash that leaves a gap still recovers a contiguous prefix no shorter
    /// than the last completed commit.
    pub(super) async fn sync_from(&mut self, start_blob: u64) -> Result<(), Error> {
        let start_blob = start_blob.max(self.base_blob);
        let dirty_sealed = &self.sealed[(start_blob - self.base_blob) as usize..];
        try_join_all(dirty_sealed.iter().map(|sealed| sealed.sync()))
            .await
            .map_err(Error::Runtime)?;
        self.metrics.synced.inc_by(dirty_sealed.len() as u64);

        self.tail.writer.sync().await.map_err(Error::Runtime)?;
        self.metrics.synced.inc();
        Ok(())
    }

    /// Remove every blob and the partition itself.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        let tail_blob = self.tail.blob;
        drop(self.tail);
        for blob in self.base_blob..=tail_blob {
            self.partition.remove(blob).await?;
        }
        self.partition.remove_all().await
    }
}
