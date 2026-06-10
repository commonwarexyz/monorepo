//! Blob management for a contiguous journal.

use crate::{journal::Error, Context};
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::paged::{self, CacheRef, Sealed, Writer},
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
    Blob, Error as RError, IoBuf, IoBufMut, IoBufs,
};
use futures::future::try_join_all;
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    ops::Range,
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

    /// Scan a partition's blob names, treating a missing partition as empty.
    async fn scan_names(context: &E, name: &str) -> Result<Vec<Vec<u8>>, Error> {
        match context.scan(name).await {
            Ok(names) => Ok(names),
            Err(RError::PartitionMissing(_)) => Ok(Vec::new()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    /// Scan the partition and open every existing blob as a [`Writer`], keyed by blob index.
    pub(super) async fn open_all(&self) -> Result<BTreeMap<u64, Writer<E::Blob>>, Error> {
        let stored = Self::scan_names(&self.context, &self.name).await?;

        let mut blobs = BTreeMap::new();
        for name in stored {
            let hex_name = hex(&name);
            let bytes: [u8; 8] = name
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

    /// Remove an entire partition by name, treating "already missing" as success.
    pub(super) async fn remove_all(context: &E, name: &str) -> Result<(), Error> {
        match context.remove(name, None).await {
            Ok(()) | Err(RError::PartitionMissing(_)) => Ok(()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    /// Select the blob partition for `prefix` using legacy-first compatibility rules: the
    /// legacy partition (`prefix` itself) if it contains data, otherwise `{prefix}-blobs`.
    /// Both containing data is corruption.
    // TODO(#2941): Remove legacy partition support
    pub(super) async fn select(context: &E, prefix: &str) -> Result<String, Error> {
        let new_partition = format!("{prefix}-blobs");
        let legacy_blobs = Self::scan_names(context, prefix).await?;
        let new_blobs = Self::scan_names(context, &new_partition).await?;

        if !legacy_blobs.is_empty() && !new_blobs.is_empty() {
            return Err(Error::Corruption(format!(
                "both legacy and blobs partitions contain data: legacy={prefix} blobs={new_partition}"
            )));
        }

        if !legacy_blobs.is_empty() {
            Ok(prefix.into())
        } else {
            Ok(new_partition)
        }
    }
}

/// A journal's blobs: contiguous sealed blobs ending in one writable tail.
pub(super) struct Blobs<E: Context> {
    partition: Partition<E>,
    metrics: Metrics,

    /// The one writable blob, at `oldest_blob_index + sealed.len()`; appends go here.
    tail: Writer<E::Blob>,

    /// Index of the first blob in [Self::sealed].
    oldest_blob_index: u64,

    /// Sealed historical blobs, ascending and contiguous from `oldest_blob_index`.
    sealed: Arc<[Sealed<E::Blob>]>,

    /// Number of live readers. Gates in-place truncation during rewind.
    readers: Arc<AtomicUsize>,
}

impl<E: Context> Blobs<E> {
    /// Build from recovered writers: seal every blob below `tail_blob` and install the tail,
    /// opening an empty one if absent.
    ///
    /// # Invariants
    ///
    /// - Retained blobs must be contiguous.
    /// - No blob may exceed `tail_blob`.
    /// - Any blobs present must end at `tail_blob`.
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
                tail = Some(writer);
            } else {
                sealed.push(writer.seal().await.map_err(Error::Runtime)?);
            }
        }
        let tail = match tail {
            Some(writer) => writer,
            None => partition.open(tail_blob).await?,
        };

        // The retained blobs must reach the tail: `oldest_blob_index = tail_blob - sealed.len()`.
        // A gap (scanned blobs that do not end at `tail_blob`) is corruption.
        let oldest_blob_index = tail_blob
            .checked_sub(sealed.len() as u64)
            .filter(|&idx| sealed.is_empty() || Some(idx) == oldest)
            .ok_or_else(|| {
                Error::Corruption(format!("retained blobs must end at tail blob {tail_blob}"))
            })?;

        let metrics = Metrics::new(&partition.context);
        let _ = metrics.tracked.try_set(sealed.len() + 1);
        Ok(Self {
            partition,
            metrics,
            oldest_blob_index,
            tail,
            sealed: sealed.into(),
            readers: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Index of the oldest retained blob.
    pub(super) const fn oldest_blob_index(&self) -> u64 {
        self.oldest_blob_index
    }

    /// Index of the newest blob.
    pub(super) fn tail_blob_index(&self) -> u64 {
        self.oldest_blob_index + self.sealed.len() as u64
    }

    /// A write handle for the tail.
    pub(super) const fn tail_writer(&self) -> &Writer<E::Blob> {
        &self.tail
    }

    /// Whether any [`Snapshot`] is live. A new reader can't be created while the caller holds
    /// `&mut self`, so this only accounts for snapshots taken earlier. The Acquire load pairs
    /// with the Release in [`Snapshot`]'s drop, so a `false` result means their reads are done.
    pub(super) fn readers_outstanding(&self) -> bool {
        self.readers.load(Ordering::Acquire) != 0
    }

    /// Capture an owned [`Snapshot`] of the current blobs, readable within `bounds`. The
    /// snapshot counts itself in `readers` until dropped, gating in-place truncation during
    /// rewind.
    pub(super) fn to_snapshot(&self, bounds: Range<u64>) -> Snapshot<E::Blob> {
        self.readers.fetch_add(1, Ordering::Relaxed);
        Snapshot {
            oldest_blob_index: self.oldest_blob_index,
            sealed: self.sealed.clone(),
            tail_reader: self.tail.reader(),
            bounds,
            readers: self.readers.clone(),
        }
    }

    /// Seal the tail (no fsync) and open the next blob as the new tail.
    pub(super) async fn seal_tail(&mut self) -> Result<(), Error> {
        // Open the next tail first so a failure leaves the current tail untouched.
        let next_blob = self
            .tail_blob_index()
            .checked_add(1)
            .ok_or(Error::OffsetOverflow)?;
        let new_writer = self.partition.open(next_blob).await?;
        let old_writer = std::mem::replace(&mut self.tail, new_writer);
        let sealed = old_writer.seal().await.map_err(Error::Runtime)?;
        self.metrics.tracked.inc();

        // Rebuild is O(n).
        self.sealed = self
            .sealed
            .iter()
            .cloned()
            .chain(std::iter::once(sealed))
            .collect::<Vec<Sealed<E::Blob>>>()
            .into();
        Ok(())
    }

    /// Drop every blob below `min_blob` and remove its file, oldest-first. Readers holding
    /// the old slice keep reading the removed blobs.
    ///
    /// # Invariants
    ///
    /// - `oldest_blob_index < min_blob <= tail_blob_index`
    pub(super) async fn prune(&mut self, min_blob: u64) -> Result<(), Error> {
        debug_assert!(self.oldest_blob_index < min_blob && min_blob <= self.tail_blob_index());
        let drop_count = (min_blob - self.oldest_blob_index) as usize;
        let prev_oldest_blob_index = self.oldest_blob_index;
        self.sealed = self.sealed[drop_count..].to_vec().into();
        self.oldest_blob_index = min_blob;

        for blob in prev_oldest_blob_index..min_blob {
            self.partition.remove(blob).await?;
            self.metrics.tracked.dec();
            self.metrics.pruned.inc();
        }
        Ok(())
    }

    /// Rewind the tail to `byte_offset`, shrinking it in place.
    ///
    /// # Invariants
    ///
    /// - `byte_offset <= tail size`
    ///
    /// # Errors
    /// Returns [Error::BlobInUse] if there are outstanding readers: the tail is shared mutable
    /// state, so truncating it could tear a live snapshot's reads of bytes a later append reuses.
    pub(super) async fn rewind_tail(&mut self, byte_offset: u64) -> Result<(), Error> {
        let current_bytes = self.tail.size().await;
        debug_assert!(byte_offset <= current_bytes);
        if byte_offset < current_bytes {
            // Refuse the in-place truncation while any snapshot is live.
            if self.readers_outstanding() {
                return Err(Error::BlobInUse(self.tail_blob_index()));
            }
            self.tail
                .resize(byte_offset)
                .await
                .map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Rewind into a sealed blob: demote it to the writable tail, rewinding to `byte_offset`,
    /// and discarding every newer blob.
    ///
    /// # Invariants
    ///
    /// - `blob < tail_blob_index`
    ///
    /// # Errors
    /// Returns [Error::BlobInUse] if there are outstanding readers.
    pub(super) async fn rewind_into_sealed(
        &mut self,
        blob: u64,
        byte_offset: u64,
    ) -> Result<(), Error> {
        let idx = blob
            .checked_sub(self.oldest_blob_index)
            .map(|idx| idx as usize)
            .filter(|&idx| idx < self.sealed.len())
            .ok_or_else(|| Error::Corruption(format!("rewind target blob {blob} not retained")))?;

        // Refuse the in-place truncation while any snapshot is live.
        if self.readers_outstanding() {
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

        // Remove blobs newest-first so a crash leaves a contiguous prefix: the old tail, then
        // sealed blobs down to the target. Capture the old tail before truncating `sealed`
        // (which redefines `tail_blob`).
        let old_tail_blob = self.tail_blob_index();
        self.tail = new_writer;
        self.partition.remove(old_tail_blob).await?;
        self.metrics.tracked.dec();
        for newer in ((blob + 1)..old_tail_blob).rev() {
            self.partition.remove(newer).await?;
            self.metrics.tracked.dec();
        }

        // Sealed history now ends below the target, which is the tail.
        self.sealed = self.sealed[..idx].to_vec().into();
        Ok(())
    }

    /// Remove every blob and start an empty journal with its tail at `tail_blob`.
    ///
    /// Safe with live readers, like [Self::prune]: snapshots keep their own handles, which the
    /// runtime's read-after-remove contract keeps valid.
    pub(super) async fn clear(&mut self, tail_blob: u64) -> Result<(), Error> {
        for blob in self.oldest_blob_index..=self.tail_blob_index() {
            self.partition.remove(blob).await?;
        }
        let _ = self.metrics.tracked.try_set(0);
        self.tail = self.partition.open(tail_blob).await?;
        self.metrics.tracked.inc();
        self.oldest_blob_index = tail_blob;
        self.sealed = Vec::new().into();
        Ok(())
    }

    /// Make every blob from `start_blob` onward durable.
    pub(super) async fn sync_from(&mut self, start_blob: u64) -> Result<(), Error> {
        let start_blob = start_blob.max(self.oldest_blob_index);
        let dirty_sealed = &self.sealed[(start_blob - self.oldest_blob_index) as usize..];
        try_join_all(dirty_sealed.iter().map(|sealed| sealed.sync()))
            .await
            .map_err(Error::Runtime)?;
        self.metrics.synced.inc_by(dirty_sealed.len() as u64);

        self.tail.sync().await.map_err(Error::Runtime)?;
        self.metrics.synced.inc();
        Ok(())
    }

    /// Remove every blob and the partition itself.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        let tail_blob = self.tail_blob_index();
        drop(self.tail);
        for blob in self.oldest_blob_index..=tail_blob {
            self.partition.remove(blob).await?;
        }
        Partition::remove_all(&self.partition.context, &self.partition.name).await
    }

    /// Test helper: open `blob` as an independent writer, outside this journal's tracking
    /// (simulates a crash-artifact blob).
    #[cfg(test)]
    pub(super) async fn test_open_blob(&self, blob: u64) -> Result<Writer<E::Blob>, Error> {
        self.partition.open(blob).await
    }

    /// Test helper: make one blob durable.
    #[cfg(test)]
    pub(super) async fn sync_blob(&self, blob: u64) -> Result<(), Error> {
        if blob == self.tail_blob_index() {
            return self.tail.sync().await.map_err(Error::Runtime);
        }
        match blob
            .checked_sub(self.oldest_blob_index)
            .and_then(|idx| self.sealed.get(idx as usize))
        {
            Some(sealed) => sealed.sync().await.map_err(Error::Runtime),
            None => Ok(()),
        }
    }
}

/// A read handle for one blob, resolved from a [`Snapshot`].
pub(super) enum Handle<'a, B: Blob> {
    Sealed(&'a Sealed<B>),
    Tail(&'a paged::Reader<B>),
}

impl<B: Blob> Handle<'_, B> {
    pub(super) async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        match self {
            Self::Sealed(s) => s.read_at(offset, len).await.map_err(Error::Runtime),
            Self::Tail(t) => t.read_at(offset, len).await.map_err(Error::Runtime),
        }
    }

    /// Read up to `len` bytes starting at `offset`, returning the bytes and how many were
    /// available.
    pub(super) async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<(IoBuf, usize), Error> {
        match self {
            Self::Sealed(s) => {
                let available = usize::try_from(s.size().saturating_sub(offset))
                    .unwrap_or(usize::MAX)
                    .min(len);
                let bufs = s.read_at(offset, available).await.map_err(Error::Runtime)?;
                Ok((bufs.coalesce(), available))
            }
            Self::Tail(t) => {
                let (buf, available) = t
                    .read_up_to(offset, len, IoBufMut::with_capacity(len))
                    .await
                    .map_err(Error::Runtime)?;
                Ok((buf.freeze(), available))
            }
        }
    }

    /// The blob's size, if it can be observed without waiting.
    pub(super) fn try_size(&self) -> Option<u64> {
        match self {
            Self::Sealed(s) => Some(s.size()),
            Self::Tail(t) => t.try_size(),
        }
    }

    pub(super) async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<(), Error> {
        match self {
            Self::Sealed(s) => s
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
            Self::Tail(t) => t
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
        }
    }

    pub(super) fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        match self {
            Self::Sealed(s) => s.try_read_sync(offset, buf),
            Self::Tail(t) => t.try_read_sync(offset, buf),
        }
    }
}

/// An owned copy of the journal's blob handles and bounds, captured by [`Blobs::to_snapshot`].
/// Later appends, seals, and prunes are invisible to it: it serves the positions in its frozen
/// `bounds` from the handles retained at capture, so even pruned blobs stay readable. A rewind
/// would mutate the tail (shared with the writer) or a sealed blob in place, so it counts itself
/// in `readers` for its lifetime and rewind refuses ([Error::BlobInUse]) while the count is nonzero.
pub(super) struct Snapshot<B: Blob> {
    /// Index of the first blob in [Self::sealed].
    pub(super) oldest_blob_index: u64,

    /// Sealed historical blobs, ascending and contiguous from `oldest_blob_index`.
    pub(super) sealed: Arc<[Sealed<B>]>,

    /// Read handle for the tail, blob [`Self::tail_blob_index`].
    pub(super) tail_reader: paged::Reader<B>,

    /// The positions readable through this snapshot.
    pub(super) bounds: Range<u64>,

    /// The journal's live-reader count, shared with [`Blobs`]. Incremented at capture and
    /// decremented on drop; a nonzero count blocks in-place truncation of the tail and of
    /// sealed blobs during rewind.
    readers: Arc<AtomicUsize>,
}

impl<B: Blob> Snapshot<B> {
    /// Validate a position to be read: must lie within `bounds`.
    pub(super) const fn validate_readable(&self, pos: u64) -> Result<(), Error> {
        if pos >= self.bounds.end {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.bounds.start {
            return Err(Error::ItemPruned(pos));
        }
        Ok(())
    }

    /// Validate a replay start cursor, which may also sit at `bounds.end`.
    pub(super) const fn validate_cursor(&self, pos: u64) -> Result<(), Error> {
        if pos > self.bounds.end {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.bounds.start {
            return Err(Error::ItemPruned(pos));
        }
        Ok(())
    }

    /// Index of the newest blob.
    pub(super) fn tail_blob_index(&self) -> u64 {
        self.oldest_blob_index + self.sealed.len() as u64
    }

    /// Resolve the read handle for `blob`, if retained.
    pub(super) fn handle(&self, blob: u64) -> Option<Handle<'_, B>> {
        if blob == self.tail_blob_index() {
            return Some(Handle::Tail(&self.tail_reader));
        }
        let idx = blob.checked_sub(self.oldest_blob_index)?;
        self.sealed.get(idx as usize).map(Handle::Sealed)
    }

    /// Resolve the read handle for `blob`, treating absence as corruption: callers only ask
    /// for blobs implied by positions validated against `bounds`.
    pub(super) fn require_handle(&self, blob: u64) -> Result<Handle<'_, B>, Error> {
        self.handle(blob)
            .ok_or_else(|| Error::Corruption(format!("blob {blob} missing from snapshot")))
    }
}

impl<B: Blob> Drop for Snapshot<B> {
    fn drop(&mut self) {
        self.readers.fetch_sub(1, Ordering::Release);
    }
}
