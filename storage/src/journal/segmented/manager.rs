//! Common blob management for segmented journals.
//!
//! This module provides `Manager`, a reusable component that handles
//! section-based blob storage, pruning, syncing, and metrics.

use crate::journal::Error;
use commonware_formatting::hex;
use commonware_runtime::{
    Blob, BufferPool, Error as RError, Handle, IoBuf, IoBufMut, IoBufs, Metrics, ReadOptions,
    Storage,
    buffer::{
        Write,
        paged::{CacheRef, Recovery as PagedRecovery, Replay, Writer},
    },
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use futures::future::{join_all, try_join_all};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    mem::take,
    num::NonZeroUsize,
};
use tracing::debug;

/// List stored blob names, treating a missing partition as an empty journal.
pub(super) async fn stored_names<E: Storage>(
    context: &E,
    partition: &str,
) -> Result<Vec<Vec<u8>>, Error> {
    match context.scan(partition).await {
        Ok(names) => Ok(names),
        Err(RError::PartitionMissing(_)) => Ok(Vec::new()),
        Err(err) => Err(Error::Runtime(err)),
    }
}

/// Decode the canonical big-endian section number stored in a blob name.
pub(super) fn section_from_name(name: &[u8]) -> Result<u64, Error> {
    let section = name
        .try_into()
        .map_err(|_| Error::InvalidBlobName(hex(name)))?;
    Ok(u64::from_be_bytes(section))
}

/// A minimal [`Blob`] wrapper for [`Manager`].
pub trait SectionBuffer: Send + Sync {
    /// Returns the current logical size of the buffer including any buffered data.
    fn size(&self) -> u64;

    /// Ensure all data accepted by this buffer is durably persisted.
    fn sync(&mut self) -> impl Future<Output = Result<(), RError>> + Send;

    /// Start making data currently accepted by this buffer durable.
    ///
    /// The returned handle covers every write accepted before this call returns; later writes
    /// need a new sync. Implementations must wait for an outstanding sync before mutating the
    /// underlying blob and may reuse an in-flight handle when no newer writes need syncing.
    fn start_sync(&mut self) -> impl Future<Output = Handle<()>> + Send;

    /// Wait for any started sync to complete without starting a new sync.
    fn wait_for_sync(&mut self) -> impl Future<Output = Result<(), RError>> + Send;

    /// Shorten an unpublished section during initialization.
    fn truncate_pending(&mut self, len: u64) -> impl Future<Output = Result<(), RError>> + Send;

    /// Irreversibly publish this section for appends.
    fn publish(&mut self);
}

impl<B: Blob> SectionBuffer for AppendBuffer<B> {
    fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn sync(&mut self) -> Result<(), RError> {
        Self::sync(self).await
    }

    async fn start_sync(&mut self) -> Handle<()> {
        Self::start_sync(self).await
    }

    async fn wait_for_sync(&mut self) -> Result<(), RError> {
        Self::wait_for_sync(self).await
    }

    async fn truncate_pending(&mut self, len: u64) -> Result<(), RError> {
        self.truncate_pending(len).await
    }

    fn publish(&mut self) {
        Self::publish(self);
    }
}

impl<B: Blob> SectionBuffer for WriteBuffer<B> {
    fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn sync(&mut self) -> Result<(), RError> {
        Self::sync(self).await
    }

    async fn start_sync(&mut self) -> Handle<()> {
        Self::start_sync(self).await
    }

    async fn wait_for_sync(&mut self) -> Result<(), RError> {
        Self::wait_for_sync(self).await
    }

    async fn truncate_pending(&mut self, len: u64) -> Result<(), RError> {
        self.truncate_pending(len).await
    }

    fn publish(&mut self) {
        Self::publish(self);
    }
}

/// Factory for creating section buffers from raw blobs.
pub trait BufferFactory<B: Blob>: Clone + Send + Sync {
    /// The buffer type produced by this factory.
    type Buffer: SectionBuffer;

    /// Create a new buffer wrapping the given blob with the specified size.
    fn create(
        &self,
        blob: B,
        size: u64,
    ) -> impl Future<Output = Result<Self::Buffer, RError>> + Send;
}

/// Factory for creating [`Writer`] buffers with page caching.
#[derive(Clone)]
pub struct AppendFactory {
    /// The size of the write buffer.
    pub write_buffer: NonZeroUsize,
    /// The page cache for read caching.
    pub page_cache_ref: CacheRef,
}

impl<B: Blob> BufferFactory<B> for AppendFactory {
    type Buffer = AppendBuffer<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Ok(AppendBuffer::Pending(Some(
            PagedRecovery::open(
                blob,
                size,
                self.write_buffer.get(),
                self.page_cache_ref.clone(),
            )
            .await?,
        )))
    }
}

/// Factory for creating [`Write`] buffers without caching.
#[derive(Clone)]
pub struct WriteFactory {
    /// The capacity of the write buffer.
    pub capacity: NonZeroUsize,
    /// The buffer pool used by write buffers.
    pub pool: BufferPool,
}

impl<B: Blob> BufferFactory<B> for WriteFactory {
    type Buffer = WriteBuffer<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Ok(WriteBuffer {
            inner: Write::new(blob, size, self.capacity, self.pool.clone()),
            pending: true,
        })
    }
}

/// A section is either owned by initialization or permanently append-only.
pub enum AppendBuffer<B: Blob> {
    /// Initialization owns the retained end until replay finishes.
    Pending(Option<PagedRecovery<B>>),
    /// An initialized section.
    Live(Writer<B>),
}

impl<B: Blob> AppendBuffer<B> {
    /// Publish this section once. Only recovery can construct the pending variant.
    pub fn publish(&mut self) {
        if let Self::Pending(pending) = self {
            *self = Self::Live(pending.take().expect("pending section").into());
        }
    }

    /// Repair an unpublished section. Initialized sections cannot be shortened. Panics if the
    /// requested end would shorten a published section.
    pub async fn truncate_pending(&mut self, end: u64) -> Result<(), RError> {
        match self {
            Self::Pending(p) => p.as_mut().expect("pending section").truncate(end).await,
            Self::Live(w) if end >= w.size() => Ok(()),
            Self::Live(_) => panic!("cannot truncate a published section"),
        }
    }

    /// Return the section's logical length.
    pub const fn size(&self) -> u64 {
        match self {
            Self::Pending(p) => p.as_ref().expect("pending section").size(),
            Self::Live(w) => w.size(),
        }
    }

    /// Make all section writes durable.
    pub async fn sync(&mut self) -> Result<(), RError> {
        match self {
            Self::Pending(p) => p.as_mut().expect("pending section").sync().await,
            Self::Live(w) => w.sync().await,
        }
    }

    /// Begin syncing all accepted section writes.
    pub async fn start_sync(&mut self) -> Handle<()> {
        match self {
            Self::Pending(p) => p.as_mut().expect("pending section").start_sync().await,
            Self::Live(w) => w.start_sync().await,
        }
    }

    /// Wait for previously started synchronization.
    pub async fn wait_for_sync(&mut self) -> Result<(), RError> {
        match self {
            Self::Pending(p) => p.as_mut().expect("pending section").wait_for_sync().await,
            Self::Live(w) => w.wait_for_sync().await,
        }
    }

    /// Read logical section bytes.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, RError> {
        match self {
            Self::Pending(p) => {
                p.as_ref()
                    .expect("pending section")
                    .read_at(offset, len)
                    .await
            }
            Self::Live(w) => w.read_at(offset, len).await,
        }
    }

    /// Read at most the requested number of bytes.
    pub async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        buf: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), RError> {
        match self {
            Self::Pending(p) => {
                p.as_ref()
                    .expect("pending section")
                    .read_up_to(offset, len, buf)
                    .await
            }
            Self::Live(w) => w.read_up_to(offset, len, buf).await,
        }
    }

    /// Read fixed-width items into the supplied buffer.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, RError> {
        match self {
            Self::Pending(p) => {
                p.as_ref()
                    .expect("pending section")
                    .read_many_into(buf, offsets, item_size)
                    .await
            }
            Self::Live(w) => w.read_many_into(buf, offsets, item_size).await,
        }
    }

    /// Read from the cache and buffered tip if available.
    pub fn try_read_sync_into(&self, buf: &mut [u8], offset: u64) -> bool {
        match self {
            Self::Pending(p) => p
                .as_ref()
                .expect("pending section")
                .try_read_sync_into(buf, offset),
            Self::Live(w) => w.try_read_sync_into(buf, offset),
        }
    }

    /// Read section bytes sequentially.
    pub async fn replay(
        &mut self,
        buffer: NonZeroUsize,
        options: ReadOptions,
    ) -> Result<Replay<B>, RError> {
        match self {
            Self::Pending(p) => {
                p.as_mut()
                    .expect("pending section")
                    .replay(buffer, options)
                    .await
            }
            Self::Live(w) => w.replay(buffer, options).await,
        }
    }

    /// Validate the section prefix above a previously proven boundary.
    pub async fn recoverable_prefix_len(
        &self,
        proven: u64,
        buffer: NonZeroUsize,
        options: ReadOptions,
    ) -> Result<u64, RError> {
        self.recoverable_prefix_len_at_most(proven, u64::MAX, buffer, options)
            .await
    }

    /// Validate only the pages intersecting the selected prefix.
    pub async fn recoverable_prefix_len_at_most(
        &self,
        proven: u64,
        max_size: u64,
        buffer: NonZeroUsize,
        options: ReadOptions,
    ) -> Result<u64, RError> {
        match self {
            Self::Pending(p) => {
                p.as_ref()
                    .expect("pending section")
                    .recoverable_prefix_len_at_most(proven, max_size, buffer, options)
                    .await
            }
            Self::Live(w) => {
                w.recoverable_prefix_len_at_most(proven, max_size, buffer, options)
                    .await
            }
        }
    }

    /// Append to a published section.
    pub async fn append(&mut self, buf: &[u8]) -> Result<u64, RError> {
        self.publish();
        let Self::Live(w) = self else { unreachable!() };
        w.append(buf).await
    }

    /// Append to a published section.
    pub async fn append_owned(&mut self, buf: IoBuf) -> Result<u64, RError> {
        self.publish();
        let Self::Live(w) = self else { unreachable!() };
        w.append_owned(buf).await
    }
}

impl<B: Blob> crate::journal::frame::FrameReader for AppendBuffer<B> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        Ok(self.read_at(offset, len).await?)
    }

    async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        buf: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        Ok(self.read_up_to(offset, len, buf).await?)
    }
}

/// Uncached section storage with a one-way initialization boundary.
pub struct WriteBuffer<B: Blob> {
    inner: Write<B>,
    pending: bool,
}
impl<B: Blob> WriteBuffer<B> {
    /// Publish the section.
    pub const fn publish(&mut self) {
        self.pending = false;
    }

    /// Repair the unpublished section. Panics if a published section would be shortened.
    pub async fn truncate_pending(&mut self, len: u64) -> Result<(), RError> {
        if len >= self.inner.size() {
            return Ok(());
        }
        assert!(self.pending, "cannot truncate a published section");
        self.inner.resize(len).await?;
        self.inner.sync().await
    }

    /// Current section length.
    pub const fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Read section bytes.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, RError> {
        self.inner.read_at(offset, len).await
    }

    /// Write bytes after closing initialization.
    pub async fn write_at(&mut self, offset: u64, buf: Vec<u8>) -> Result<(), RError> {
        self.publish();
        self.inner.write_at(offset, buf).await
    }

    /// Sync section bytes.
    pub async fn sync(&mut self) -> Result<(), RError> {
        self.inner.sync().await
    }

    /// Begin syncing section bytes.
    pub async fn start_sync(&mut self) -> Handle<()> {
        self.inner.start_sync().await
    }

    /// Drain an existing sync.
    pub async fn wait_for_sync(&mut self) -> Result<(), RError> {
        self.inner.wait_for_sync().await
    }
}

/// Configuration for blob management.
#[derive(Clone)]
pub struct Config<F> {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The factory for creating section buffers.
    pub factory: F,
}

/// Manages a collection of section-based blobs.
///
/// Each section is stored in a separate blob, named by its section number
/// (big-endian u64). This component handles initialization, pruning, syncing,
/// and metrics.
///
/// # In-flight syncs
///
/// Syncs started by [Manager::start_sync] complete in the background, so every path that removes a
/// blob from `blobs` (`prune`, `remove_section`, `truncate_pending`, `clear`, `destroy`) must call
/// [SectionBuffer::wait_for_sync] before dropping it. This resolves the sync's shared completion
/// first, guaranteeing that caller-held sync handles always report the sync's true result and that
/// no buffer is dropped with I/O in flight.
pub struct Manager<E: Storage + Metrics, F: BufferFactory<E::Blob>> {
    context: E,
    partition: String,
    factory: F,

    /// One blob per section.
    pub(crate) blobs: BTreeMap<u64, F::Buffer>,

    /// A section number before which all sections have been pruned during
    /// the current execution. Not persisted across restarts.
    oldest_retained_section: u64,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl<E: Storage + Metrics, F: BufferFactory<E::Blob>> Manager<E, F> {
    /// Wait for all started syncs to complete before their blobs are dropped.
    async fn wait_for_syncs<'a>(
        blobs: impl IntoIterator<Item = &'a mut F::Buffer>,
    ) -> Result<(), Error>
    where
        F::Buffer: 'a,
    {
        try_join_all(blobs.into_iter().map(|blob| blob.wait_for_sync()))
            .await
            .map(|_| ())
            .map_err(Error::Runtime)
    }

    /// Initialize a new `Manager`.
    ///
    /// Scans the partition for existing blobs and opens them.
    pub async fn init(context: E, cfg: Config<F>) -> Result<Self, Error> {
        // Open each canonical section in storage order.
        let mut blobs = BTreeMap::new();
        let stored_blobs = stored_names(&context, &cfg.partition).await?;

        for name in stored_blobs {
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            let section = section_from_name(&name)?;
            debug!(section, blob = hex(&name), size, "loaded section");
            let buffer = cfg.factory.create(blob, size).await?;
            blobs.insert(section, buffer);
        }

        // Initialize metrics
        let tracked = context.gauge("tracked", "Number of blobs");
        let synced = context.counter("synced", "Number of syncs");
        let pruned = context.counter("pruned", "Number of blobs pruned");
        let _ = tracked.try_set(blobs.len());

        Ok(Self {
            context,
            partition: cfg.partition,
            factory: cfg.factory,
            blobs,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,
        })
    }

    /// Publish every recovered section without allowing a return to recovery ownership.
    pub fn publish_all(&mut self) {
        for blob in self.blobs.values_mut() {
            blob.publish();
        }
    }

    /// Publish recovered sections at or above `start` after their replay has completed.
    pub fn publish_from(&mut self, start: u64) {
        for (_, blob) in self.blobs.range_mut(start..) {
            blob.publish();
        }
    }

    /// Ensures that a section pruned during the current execution is not accessed.
    pub const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }

    /// Get a mutable reference to a blob for a section, if it exists.
    ///
    /// Unlike [Self::get], skips the prune guard: the caller (an owned replay reader)
    /// holds the journal, so no prune can interleave.
    pub fn get_mut(&mut self, section: u64) -> Option<&mut F::Buffer> {
        self.blobs.get_mut(&section)
    }

    /// Get a reference to a blob for a section, if it exists.
    pub fn get(&self, section: u64) -> Result<Option<&F::Buffer>, Error> {
        self.prune_guard(section)?;
        Ok(self.blobs.get(&section))
    }

    /// Get a mutable reference to a blob, creating it if it doesn't exist.
    pub async fn get_or_create(&mut self, section: u64) -> Result<&mut F::Buffer, Error> {
        self.prune_guard(section)?;

        if !self.blobs.contains_key(&section) {
            let name = section.to_be_bytes();
            let (blob, size) = self.context.open(&self.partition, &name).await?;
            let buffer = self.factory.create(blob, size).await?;
            self.tracked.inc();
            self.blobs.insert(section, buffer);
        }

        let blob = self.blobs.get_mut(&section).unwrap();
        blob.publish();
        Ok(blob)
    }

    /// Sync the given `sections` to storage.
    pub async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        for &section in &sections {
            self.prune_guard(section)?;
        }
        let futures: Vec<_> = self
            .blobs
            .iter_mut()
            .filter(|(section, _)| sections.contains(section))
            .map(|(_, blob)| blob.sync())
            .collect();
        let count = futures.len() as u64;
        try_join_all(futures).await.map_err(Error::Runtime)?;
        self.synced.inc_by(count);
        Ok(())
    }

    /// Start syncing the given `sections` to storage.
    ///
    /// The returned handle completes once every selected section's sync completes, failing with
    /// the first error encountered. Sections with an in-flight sync and no newer writes reuse
    /// that sync's handle rather than starting a new one.
    ///
    /// The handle is a detached observer: dropping it does not cancel the sync, and a failure of
    /// the started sync resurfaces from the buffer on the section's next operation. A failure to
    /// flush buffered data while starting the sync, however, is reported only through the
    /// returned handle, so callers must observe the handle to detect it.
    pub async fn start_sync(
        &mut self,
        sections: impl crate::Sections,
    ) -> Result<Handle<()>, Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        for &section in &sections {
            self.prune_guard(section)?;
        }
        let futures: Vec<_> = self
            .blobs
            .iter_mut()
            .filter(|(section, _)| sections.contains(section))
            .map(|(_, blob)| blob.start_sync())
            .collect();

        // Count every selected section, including reused and clean no-op syncs, matching
        // `sync` and `sync_all`.
        self.synced.inc_by(futures.len() as u64);
        let handles = join_all(futures).await;
        Ok(Handle::from_future(async move {
            try_join_all(handles).await.map(|_| ())
        }))
    }

    /// Sync all sections to storage.
    pub async fn sync_all(&mut self) -> Result<(), Error> {
        let count = self.blobs.len() as u64;
        try_join_all(self.blobs.values_mut().map(|b| b.sync()))
            .await
            .map_err(Error::Runtime)?;
        self.synced.inc_by(count);
        Ok(())
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        // Prune any blobs that are smaller than the minimum
        let mut pruned = false;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            // Stop pruning if we reach the minimum
            if section >= min {
                break;
            }

            // Remove blob from map
            let mut blob = self.blobs.remove(&section).unwrap();
            blob.wait_for_sync().await?;
            let size = blob.size();
            drop(blob);

            // Remove blob from storage
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            pruned = true;

            debug!(section, size, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        if pruned {
            self.oldest_retained_section = min;
        }

        Ok(pruned)
    }

    /// Returns true when `section` is below the prune floor.
    pub const fn pruned(&self, section: u64) -> bool {
        section < self.oldest_retained_section
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.blobs.first_key_value().map(|(&s, _)| s)
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.blobs.last_key_value().map(|(&s, _)| s)
    }

    /// Returns true if no blobs exist.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Returns the number of sections (blobs).
    pub fn num_sections(&self) -> usize {
        self.blobs.len()
    }

    /// Returns an iterator over all sections starting from `start_section`.
    pub fn sections_from(
        &mut self,
        start_section: u64,
    ) -> impl Iterator<Item = (&u64, &mut F::Buffer)> {
        self.blobs.range_mut(start_section..)
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.blobs.keys().copied()
    }

    /// Remove a specific section. Returns true if the section existed and was removed.
    pub async fn remove_section(&mut self, section: u64) -> Result<bool, Error> {
        self.prune_guard(section)?;

        if let Some(mut blob) = self.blobs.remove(&section) {
            blob.wait_for_sync().await?;
            let size = blob.size();
            drop(blob);
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section, size, "removed section");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove all underlying blobs.
    pub async fn destroy(mut self) -> Result<(), Error> {
        Self::wait_for_syncs(self.blobs.values_mut()).await?;
        for (section, blob) in self.blobs.into_iter() {
            let size = blob.size();
            drop(blob);
            debug!(section, size, "destroyed blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        match self.context.remove(&self.partition, None).await {
            Ok(()) => {}
            // Partition already removed or never existed.
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }

    /// Clear all blobs, resetting the manager to an empty state.
    ///
    /// Unlike `destroy`, this keeps the manager alive so it can be reused.
    pub async fn clear(&mut self) -> Result<(), Error> {
        Self::wait_for_syncs(self.blobs.values_mut()).await?;
        let blobs = take(&mut self.blobs);
        for (section, blob) in blobs {
            let size = blob.size();
            drop(blob);
            debug!(section, size, "cleared blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        let _ = self.tracked.try_set(0);
        self.oldest_retained_section = 0;
        Ok(())
    }

    /// Truncate by removing all sections after `section` and resizing the target section.
    pub async fn truncate_pending(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Remove sections in descending order (newest first) to maintain a contiguous record
        // if a crash occurs during truncate. Section `u64::MAX` has no successor, so there are
        // no sections above it to remove.
        let sections_to_remove: Vec<u64> = match section.checked_add(1) {
            Some(next) => self.blobs.range(next..).rev().map(|(&s, _)| s).collect(),
            None => Vec::new(),
        };

        for s in sections_to_remove {
            // Remove the underlying blob from storage
            let mut blob = self.blobs.remove(&s).unwrap();
            blob.wait_for_sync().await?;
            drop(blob);
            self.context
                .remove(&self.partition, Some(&s.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section = s, "removed blob during truncate");
        }

        // If the section exists, truncate it to the given size. No explicit sync barrier is
        // needed here: the buffer waits for any in-flight sync before mutating the blob.
        if let Some(blob) = self.blobs.get_mut(&section) {
            let current_size = blob.size();
            if size < current_size {
                blob.truncate_pending(size).await?;
                debug!(
                    section,
                    old_size = current_size,
                    new_size = size,
                    "truncated blob"
                );
            }
        }

        Ok(())
    }

    /// Resize only the given section without affecting other sections.
    pub async fn truncate_pending_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Get the blob at the given section
        if let Some(blob) = self.blobs.get_mut(&section) {
            // Truncate the blob to the given size
            let current = blob.size();
            if size < current {
                blob.truncate_pending(size).await?;
                debug!(section, from = current, to = size, "truncated section");
            }
        }

        Ok(())
    }

    /// Returns the byte size of the given section.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;
        Ok(self.blobs.get(&section).map_or(0, |blob| blob.size()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        BufferPooler as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use futures::{
        FutureExt as _,
        future::{BoxFuture, Shared},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    impl<E: Storage + Metrics, F: BufferFactory<E::Blob>> Manager<E, F> {
        pub fn test_configuration(&self) -> (E, String, F) {
            (
                self.context.child("reopen_fixture"),
                self.partition.clone(),
                self.factory.clone(),
            )
        }
    }

    type SyncSender = oneshot::Sender<Result<(), RError>>;
    type PendingSyncs = Arc<Mutex<Vec<SyncSender>>>;

    /// A shared sync result, mirroring the runtime buffers' internal completion sharing.
    type SharedSync = Shared<BoxFuture<'static, Result<(), RError>>>;

    #[derive(Clone)]
    struct TestFactory {
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
    }

    #[test]
    #[should_panic(expected = "cannot truncate a published section")]
    fn test_published_paged_section_rejects_truncation() {
        deterministic::Runner::default().start(|context| async move {
            let (blob, size) = context.open("published", b"paged").await.unwrap();
            let cache = CacheRef::from_pooler(
                &context,
                commonware_utils::NZU16!(64),
                commonware_utils::NZUsize!(4),
            );
            let mut writer = Writer::new(blob, size, 1024, cache).await.unwrap();
            writer.append(&[1; 8]).await.unwrap();
            let mut buffer = AppendBuffer::Live(writer);
            buffer.truncate_pending(4).await.unwrap();
        });
    }
    #[test]
    #[should_panic(expected = "cannot truncate a published section")]
    fn test_published_uncached_section_rejects_truncation() {
        deterministic::Runner::default().start(|context| async move {
            let (blob, _) = context.open("published", b"uncached").await.unwrap();
            let mut buffer = WriteBuffer {
                inner: Write::new(
                    blob,
                    8,
                    commonware_utils::NZUsize!(1024),
                    context.storage_buffer_pool().clone(),
                ),
                pending: false,
            };
            buffer.truncate_pending(4).await.unwrap();
        });
    }

    struct TestBuffer {
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
        syncing: Option<SharedSync>,
    }

    impl SectionBuffer for TestBuffer {
        fn publish(&mut self) {}

        fn size(&self) -> u64 {
            0
        }

        async fn sync(&mut self) -> Result<(), RError> {
            Ok(())
        }

        async fn start_sync(&mut self) -> Handle<()> {
            if let Some(syncing) = &self.syncing {
                return Handle::from_future(syncing.clone());
            }
            let (sender, receiver) = oneshot::channel();
            self.pending.lock().push(sender);
            let sync = async move {
                receiver.await.map_err(|_| RError::Closed)??;
                Ok(())
            }
            .boxed()
            .shared();
            self.syncing = Some(sync.clone());
            Handle::from_future(sync)
        }

        async fn wait_for_sync(&mut self) -> Result<(), RError> {
            if let Some(syncing) = self.syncing.take() {
                self.wait_for_syncs.fetch_add(1, Ordering::Relaxed);
                syncing.await?;
            }
            Ok(())
        }

        async fn truncate_pending(&mut self, _len: u64) -> Result<(), RError> {
            Ok(())
        }
    }

    impl<B: Blob> BufferFactory<B> for TestFactory {
        type Buffer = TestBuffer;

        async fn create(&self, _blob: B, _size: u64) -> Result<Self::Buffer, RError> {
            Ok(TestBuffer {
                pending: self.pending.clone(),
                wait_for_syncs: self.wait_for_syncs.clone(),
                syncing: None,
            })
        }
    }

    fn test_config(pending: PendingSyncs, wait_for_syncs: Arc<AtomicUsize>) -> Config<TestFactory> {
        Config {
            partition: "test".into(),
            factory: TestFactory {
                pending,
                wait_for_syncs,
            },
        }
    }

    fn release_pending_syncs(pending: &PendingSyncs) {
        for sender in std::mem::take(&mut *pending.lock()) {
            let _ = sender.send(Ok(()));
        }
    }

    fn complete_next_pending_sync(pending: &PendingSyncs, result: Result<(), RError>) {
        let sender = {
            let mut pending = pending.lock();
            assert!(!pending.is_empty(), "no pending sync to complete");
            pending.remove(0)
        };
        let _ = sender.send(result);
    }

    #[test]
    fn test_start_sync_multiple_sections_returns_combined_handle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs);
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create first section");
            manager
                .get_or_create(2)
                .await
                .expect("failed to create second section");
            let handle = manager
                .start_sync([1, 2])
                .await
                .expect("failed to start sync");
            assert_eq!(pending.lock().len(), 2);
            futures::pin_mut!(handle);

            // Complete only the first section's sync: the combined handle must stay pending.
            complete_next_pending_sync(&pending, Ok(()));
            assert!(
                futures::poll!(handle.as_mut()).is_pending(),
                "combined sync handle must wait for every selected section"
            );

            complete_next_pending_sync(&pending, Ok(()));
            handle.await.expect("sync handle should complete");
            manager.destroy().await.expect("destroy failed");
        });
    }

    // Reuse applies only when no new data was written since the sync started: a section with
    // newer writes flushes them (waiting on the in-flight sync) and starts a new sync, so
    // callers must call start_sync again to get a handle covering the new data.
    #[test]
    fn test_start_sync_reuses_in_flight_section_handle_without_waiting() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs);
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create section");
            let first = manager.start_sync(1).await.expect("failed to start sync");
            assert_eq!(pending.lock().len(), 1);

            let second = manager
                .start_sync(1)
                .await
                .expect("failed to observe in-flight sync");
            assert_eq!(
                pending.lock().len(),
                1,
                "repeated start_sync should observe the in-flight section sync"
            );
            futures::pin_mut!(second);

            // The reused handle must remain tied to the in-flight sync.
            assert!(
                futures::poll!(second.as_mut()).is_pending(),
                "reused start_sync handle must wait for the in-flight sync"
            );

            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");
            second.await.expect("reused sync handle should complete");
            manager.destroy().await.expect("destroy failed");
        });
    }

    #[test]
    fn test_truncate_waits_for_in_flight_start_sync() {
        for fails in [false, true] {
            deterministic::Runner::default().start(|context| async move {
                let pending = PendingSyncs::default();
                let wait_for_syncs = Arc::new(AtomicUsize::new(0));
                let cfg = test_config(pending.clone(), wait_for_syncs.clone());
                let mut manager = Manager::init(context.child("manager"), cfg).await.unwrap();
                manager.get_or_create(1).await.unwrap();
                manager.get_or_create(2).await.unwrap();
                let handle = manager.start_sync(2).await.unwrap();
                let result = {
                    let truncate = manager.truncate_pending(1, 0);
                    futures::pin_mut!(truncate);
                    assert!(futures::poll!(&mut truncate).is_pending());
                    assert_eq!(wait_for_syncs.load(Ordering::Relaxed), 1);
                    complete_next_pending_sync(
                        &pending,
                        if fails { Err(RError::Closed) } else { Ok(()) },
                    );
                    truncate.await
                };
                if fails {
                    assert!(matches!(result, Err(Error::Runtime(RError::Closed))));
                    assert!(matches!(handle.await, Err(RError::Closed)));
                } else {
                    result.unwrap();
                    handle.await.unwrap();
                    assert_eq!(manager.newest_section(), Some(1));
                    manager.destroy().await.unwrap();
                }
            });
        }
    }

    #[test]
    fn test_prune_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs.clone());
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create section");
            let handle = manager.start_sync(1).await.expect("failed to start sync");
            assert_eq!(pending.lock().len(), 1);

            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let waiter = context.child("prune").spawn(|_| async move {
                assert!(manager.prune(2).await.expect("prune failed"));
                completed_clone.fetch_add(1, Ordering::Relaxed);
                manager
            });

            while wait_for_syncs.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "prune must wait for the in-flight start_sync handle"
            );

            release_pending_syncs(&pending);
            handle.await.expect("sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let manager = waiter.await.expect("prune task failed");
            assert!(manager.is_empty());
        });
    }

    #[test]
    fn test_destroy_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs.clone());
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create section");
            let handle = manager.start_sync(1).await.expect("failed to start sync");
            assert_eq!(pending.lock().len(), 1);

            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let waiter = context.child("destroy").spawn(|_| async move {
                manager.destroy().await.expect("destroy failed");
                completed_clone.fetch_add(1, Ordering::Relaxed);
            });

            while wait_for_syncs.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "destroy must wait for the in-flight start_sync handle"
            );

            release_pending_syncs(&pending);
            handle.await.expect("sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            waiter.await.expect("destroy task failed");
        });
    }

    #[test]
    fn test_destroy_surfaces_failed_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs);
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create section");
            let handle = manager.start_sync(1).await.expect("failed to start sync");
            complete_next_pending_sync(&pending, Err(RError::Closed));

            let err = manager
                .destroy()
                .await
                .expect_err("destroy should surface the sync failure");
            assert!(matches!(err, Error::Runtime(RError::Closed)));
            assert!(matches!(
                handle.await.expect_err("sync handle should fail"),
                RError::Closed
            ));
        });
    }
}
