//! Blob management for a contiguous journal.

use crate::{journal::Error, Context};
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::paged::{CacheRef, Replay as PagedReplay, Sealed, Writer},
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
    Blob as RBlob, Buf, Error as RError, IoBufMut, IoBufs,
};
use futures::future::try_join_all;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};
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
pub(super) struct Writable<E: Context> {
    partition: Partition<E>,
    metrics: Metrics,

    /// The writable tail.
    tail: Writer<E::Blob>,

    /// Index of the first blob in [Self::sealed].
    oldest_blob_index: u64,

    /// Sealed historical blobs.
    sealed: Arc<[Sealed<E::Blob>]>,
}

impl<E: Context> Writable<E> {
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
        let mut tail: Option<Writer<E::Blob>> = None;
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
    pub(super) const fn tail_writer(&mut self) -> &mut Writer<E::Blob> {
        &mut self.tail
    }

    /// Borrow the current blobs for a live reader.
    pub(super) fn reader(&self) -> Blobs<'_, E::Blob> {
        Blobs {
            oldest_blob_index: self.oldest_blob_index,
            sealed: SealedBlobs::Borrowed(&self.sealed),
            tail: Blob::Writer(&self.tail),
        }
    }

    /// Capture owned blob handles for a snapshot reader.
    pub(super) async fn snapshot(&mut self) -> Result<Blobs<'static, E::Blob>, Error> {
        Ok(Blobs {
            oldest_blob_index: self.oldest_blob_index,
            sealed: SealedBlobs::Owned(self.sealed.clone()),
            tail: Blob::Sealed(self.tail.snapshot().await.map_err(Error::Runtime)?),
        })
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
        assert!(self.oldest_blob_index < min_blob && min_blob <= self.tail_blob_index());
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
    pub(super) async fn rewind_tail(&mut self, byte_offset: u64) -> Result<(), Error> {
        let current_bytes = self.tail.size();
        assert!(byte_offset <= current_bytes);
        if byte_offset < current_bytes {
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

        // Sync the target before destructive work so a crash recovers a size no shorter than
        // the rewind target.
        self.sealed[idx].sync().await.map_err(Error::Runtime)?;
        self.metrics.synced.inc();

        // Reopen the target as the writable tail and truncate in place. The fresh Writer
        // gets a fresh page-cache id, so pages cached under the sealed handle's id are
        // unreachable.
        let mut new_writer = self.partition.open(blob).await?;
        let current_bytes = new_writer.size();
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
    /// Safe with live readers, like [Self::prune]: snapshot readers keep their own handles, which
    /// the runtime's read-after-remove contract keeps valid.
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
}

/// Blob handles used by a reader.
///
/// Live readers borrow the writable tail and sealed history. Snapshot readers own cloned sealed
/// history and an owned sealed tail.
pub(super) struct Blobs<'a, B: RBlob> {
    /// Index of the first sealed blob.
    oldest_blob_index: u64,
    /// Sealed historical blobs.
    sealed: SealedBlobs<'a, B>,
    /// Tail blob.
    tail: Blob<'a, B>,
}

enum SealedBlobs<'a, B: RBlob> {
    Borrowed(&'a [Sealed<B>]),
    Owned(Arc<[Sealed<B>]>),
}

impl<B: RBlob> SealedBlobs<'_, B> {
    fn as_slice(&self) -> &[Sealed<B>] {
        match self {
            Self::Borrowed(sealed) => sealed,
            Self::Owned(sealed) => sealed,
        }
    }
}

/// A read handle for one journal blob.
pub(super) enum Blob<'a, B: RBlob> {
    Writer(&'a Writer<B>),
    Sealed(Sealed<B>),
}

impl<B: RBlob> Clone for Blob<'_, B> {
    fn clone(&self) -> Self {
        match self {
            Self::Writer(writer) => Self::Writer(writer),
            Self::Sealed(sealed) => Self::Sealed(sealed.clone()),
        }
    }
}

impl<'a, B: RBlob> Blob<'a, B> {
    /// Return the blob's logical size.
    pub(super) fn size(&self) -> u64 {
        match self {
            Self::Writer(writer) => writer.size(),
            Self::Sealed(sealed) => sealed.size(),
        }
    }

    /// Read into `buf` if the data is already cached.
    pub(super) fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        match self {
            Self::Writer(writer) => writer.try_read_sync(offset, buf),
            Self::Sealed(sealed) => sealed.try_read_sync(offset, buf),
        }
    }

    /// Read exactly `len` bytes at `offset`.
    pub(super) async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        match self {
            Self::Writer(writer) => writer.read_at(offset, len).await.map_err(Error::Runtime),
            Self::Sealed(sealed) => sealed.read_at(offset, len).await.map_err(Error::Runtime),
        }
    }

    /// Read up to `len` bytes at `offset`.
    pub(super) async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        match self {
            Self::Writer(writer) => writer
                .read_up_to(offset, len, bufs)
                .await
                .map_err(Error::Runtime),
            Self::Sealed(sealed) => sealed
                .read_up_to(offset, len, bufs)
                .await
                .map_err(Error::Runtime),
        }
    }

    /// Return a sequential replay handle starting at `offset`.
    pub(super) fn replay_from(
        self,
        offset: u64,
        buffer_size: NonZeroUsize,
    ) -> Result<Replay<'a, B>, Error> {
        match self {
            Self::Writer(writer) => Replay::view(Self::Writer(writer), offset, buffer_size),
            Self::Sealed(sealed) => {
                let mut replay = sealed.replay(buffer_size).map_err(Error::Runtime)?;
                replay.seek_to(offset).map_err(Error::Runtime)?;
                Ok(Replay::paged(replay))
            }
        }
    }

    /// Read fixed-size items at sorted byte offsets into `buf`.
    pub(super) async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        match self {
            Self::Writer(writer) => writer
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
            Self::Sealed(sealed) => sealed
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime),
        }
    }
}

/// Sequential replay over either a sealed paged blob or a live writer view.
pub(super) struct Replay<'a, B: RBlob> {
    inner: ReplayInner<'a, B>,
}

enum ReplayInner<'a, B: RBlob> {
    Paged(PagedReplay<B>),
    View(ViewReplay<'a, B>),
}

impl<'a, B: RBlob> Replay<'a, B> {
    const fn paged(replay: PagedReplay<B>) -> Self {
        Self {
            inner: ReplayInner::Paged(replay),
        }
    }

    fn view(
        blob: Blob<'a, B>,
        offset: u64,
        buffer_size: NonZeroUsize,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: ReplayInner::View(ViewReplay::new(blob, offset, buffer_size)?),
        })
    }

    pub(super) fn is_exhausted(&self) -> bool {
        match &self.inner {
            ReplayInner::Paged(replay) => replay.is_exhausted(),
            ReplayInner::View(replay) => replay.is_exhausted(),
        }
    }

    pub(super) async fn ensure(&mut self, n: usize) -> Result<bool, Error> {
        match &mut self.inner {
            ReplayInner::Paged(replay) => replay.ensure(n).await.map_err(Error::Runtime),
            ReplayInner::View(replay) => replay.ensure(n).await,
        }
    }
}

impl<B: RBlob> Buf for Replay<'_, B> {
    fn remaining(&self) -> usize {
        match &self.inner {
            ReplayInner::Paged(replay) => replay.remaining(),
            ReplayInner::View(replay) => replay.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match &self.inner {
            ReplayInner::Paged(replay) => replay.chunk(),
            ReplayInner::View(replay) => replay.chunk(),
        }
    }

    fn advance(&mut self, cnt: usize) {
        match &mut self.inner {
            ReplayInner::Paged(replay) => replay.advance(cnt),
            ReplayInner::View(replay) => replay.advance(cnt),
        }
    }
}

/// Sequential read buffer over a live journal blob view.
struct ViewReplay<'a, B: RBlob> {
    blob: Blob<'a, B>,
    offset: u64,
    buffer_size: NonZeroUsize,
    buf: Vec<u8>,
    cursor: usize,
    exhausted: bool,
}

impl<'a, B: RBlob> ViewReplay<'a, B> {
    fn new(blob: Blob<'a, B>, offset: u64, buffer_size: NonZeroUsize) -> Result<Self, Error> {
        if offset > blob.size() {
            return Err(Error::Runtime(RError::BlobInsufficientLength));
        }

        Ok(Self {
            blob,
            offset,
            buffer_size,
            buf: Vec::with_capacity(buffer_size.get()),
            cursor: 0,
            exhausted: false,
        })
    }

    const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    async fn ensure(&mut self, n: usize) -> Result<bool, Error> {
        while self.remaining() < n && !self.exhausted {
            self.compact();

            let blob_size = self.blob.size();
            let remaining = blob_size.saturating_sub(self.offset);
            if remaining == 0 {
                self.exhausted = true;
                break;
            }

            let needed = n.saturating_sub(self.remaining());
            let read_len = self
                .buffer_size
                .get()
                .max(needed)
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let (buf, read) = self
                .blob
                .read_up_to(self.offset, read_len, IoBufMut::with_capacity(read_len))
                .await?;
            self.offset = self
                .offset
                .checked_add(read as u64)
                .ok_or(Error::OffsetOverflow)?;
            self.buf.extend_from_slice(&buf.chunk()[..read]);
            if self.offset == blob_size {
                self.exhausted = true;
            }
        }

        Ok(self.remaining() >= n)
    }

    fn compact(&mut self) {
        match self.cursor {
            0 => {}
            cursor if cursor == self.buf.len() => {
                self.buf.clear();
                self.cursor = 0;
            }
            cursor => {
                self.buf.drain(..cursor);
                self.cursor = 0;
            }
        }
    }
}

impl<B: RBlob> Buf for ViewReplay<'_, B> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.cursor
    }

    fn chunk(&self) -> &[u8] {
        &self.buf[self.cursor..]
    }

    fn advance(&mut self, cnt: usize) {
        self.cursor = self
            .cursor
            .checked_add(cnt)
            .expect("advance overflowed replay cursor");
        assert!(self.cursor <= self.buf.len(), "advanced past replay buffer");
    }
}

impl<B: RBlob> Blobs<'_, B> {
    /// Index of the newest blob (the tail).
    pub(super) fn tail_blob_index(&self) -> u64 {
        self.oldest_blob_index + self.sealed.as_slice().len() as u64
    }

    /// Resolve a blob, if retained.
    pub(super) fn get(&self, blob: u64) -> Option<Blob<'_, B>> {
        if blob == self.tail_blob_index() {
            return Some(self.tail.clone());
        }
        self.sealed
            .as_slice()
            .get(blob.checked_sub(self.oldest_blob_index)? as usize)
            .cloned()
            .map(Blob::Sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, IoBufMut, Runner as _, Storage as _};
    use commonware_utils::{NZUsize, NZU16};

    fn assert_insufficient_length(result: Result<(IoBufMut, usize), Error>) {
        assert!(matches!(
            result,
            Err(Error::Runtime(RError::BlobInsufficientLength))
        ));
    }

    impl<E: Context> Writable<E> {
        /// Open `blob` as an independent writer, outside this journal's tracking
        /// (simulates a crash-artifact blob).
        pub(crate) async fn open_blob(&self, blob: u64) -> Result<Writer<E::Blob>, Error> {
            self.partition.open(blob).await
        }

        /// Make one blob durable.
        pub(crate) async fn sync_blob(&mut self, blob: u64) -> Result<(), Error> {
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

    #[test]
    fn test_read_up_to_eof_parity() {
        const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(64);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(3));
            let (blob, size) = context
                .open("read_up_to_eof_parity", b"blob")
                .await
                .unwrap();
            let mut writer = Writer::new(blob, size, 128, cache_ref).await.unwrap();
            writer.append(b"abc").await.unwrap();

            let size = writer.size();
            let tail = Blob::Writer(&writer);
            assert_insufficient_length(tail.read_up_to(size, 1, IoBufMut::with_capacity(1)).await);
            assert_eq!(
                tail.read_up_to(size, 0, IoBufMut::with_capacity(0))
                    .await
                    .unwrap()
                    .1,
                0
            );

            let snapshot = writer.snapshot().await.unwrap();
            let snapshot_blob = Blob::Sealed(snapshot);
            assert_insufficient_length(
                snapshot_blob
                    .read_up_to(size, 1, IoBufMut::with_capacity(1))
                    .await,
            );
            assert_eq!(
                snapshot_blob
                    .read_up_to(size, 0, IoBufMut::with_capacity(0))
                    .await
                    .unwrap()
                    .1,
                0
            );

            let sealed = writer.seal().await.unwrap();
            let sealed_blob = Blob::Sealed(sealed);
            assert_insufficient_length(
                sealed_blob
                    .read_up_to(size, 1, IoBufMut::with_capacity(1))
                    .await,
            );
            assert_eq!(
                sealed_blob
                    .read_up_to(size, 0, IoBufMut::with_capacity(0))
                    .await
                    .unwrap()
                    .1,
                0
            );
        });
    }
}
