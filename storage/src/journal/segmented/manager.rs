//! Common blob management for segmented journals.
//!
//! This module provides `Manager`, a reusable component that handles
//! section-based blob storage, pruning, syncing, and metrics.
//!
//! # Open blobs
//!
//! A journal can accumulate more sections than a process has file descriptors, so buffers are
//! kept open in two tiers, each capped by [Config::max_open_blobs]: a *resident* tier of
//! writable buffers, evicted oldest-first, and a *reopened* CLOCK cache serving reads of
//! evicted sections. Sizes are tracked for every section, so the metadata accessors never open
//! a blob.
//!
//! # In-flight syncs
//!
//! Syncs started by [Manager::start_sync] complete in the background, so every path that
//! drops a resident buffer (`prune`, `remove_section`, `rewind`, `clear`, `destroy`, and
//! eviction) must call [SectionBuffer::wait_for_sync] before dropping it. This resolves the
//! sync's shared completion first, guaranteeing that caller-held sync handles always report
//! the sync's true result and that no buffer is dropped with I/O in flight.

use crate::journal::Error;
use commonware_formatting::hex;
use commonware_runtime::{
    Blob, BufferPool, Error as RError, Handle, Metrics, Storage,
    buffer::{
        Write,
        paged::{CacheRef, Writer},
    },
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use commonware_utils::{cache::Clock, sync::RwLock};
use futures::future::{join_all, try_join_all};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    mem::take,
    num::NonZeroUsize,
    ops::Deref,
    sync::Arc,
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

    /// Whether every byte accepted by this buffer has been written to the underlying blob.
    ///
    /// A flushed buffer can be dropped without losing an accepted write.
    fn is_flushed(&self) -> bool;

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

    /// Resize the logical size of the buffer.
    fn resize(&mut self, len: u64) -> impl Future<Output = Result<(), RError>> + Send;
}

impl<B: Blob> SectionBuffer for Writer<B> {
    fn size(&self) -> u64 {
        Self::size(self)
    }

    fn is_flushed(&self) -> bool {
        Self::is_flushed(self)
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

    async fn resize(&mut self, len: u64) -> Result<(), RError> {
        Self::resize(self, len).await
    }
}

impl<B: Blob> SectionBuffer for Write<B> {
    fn size(&self) -> u64 {
        Self::size(self)
    }

    fn is_flushed(&self) -> bool {
        Self::is_flushed(self)
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

    async fn resize(&mut self, len: u64) -> Result<(), RError> {
        Self::resize(self, len).await
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
    type Buffer = Writer<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Writer::new(
            blob,
            size,
            self.write_buffer.get(),
            self.page_cache_ref.clone(),
        )
        .await
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
    type Buffer = Write<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Ok(Write::new(blob, size, self.capacity, self.pool.clone()))
    }
}

/// Configuration for blob management.
#[derive(Clone)]
pub struct Config<F> {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The factory for creating section buffers.
    pub factory: F,

    /// The maximum number of blobs to keep open per tier, so at most `2 * max_open_blobs`
    /// in total.
    ///
    /// A soft limit: a section holding unflushed writes is never closed.
    pub max_open_blobs: NonZeroUsize,
}

/// A read handle to a section's buffer, returned by [Manager::get].
///
/// Dereferences to the buffer so callers use its read API directly.
///
/// A [Section::Reopened] handle reads the blob, so it would miss writes still buffered in a
/// resident buffer. It cannot: a section is flushed before leaving the resident tier and
/// dropped from the reopened tier on the way back in, and the `'a` borrow blocks appends while
/// a handle is alive. Do not give this handle an owned lifetime.
pub enum Section<'a, B> {
    /// A buffer held in the resident tier. Borrowing the manager prevents eviction while this
    /// handle lives.
    Resident(&'a B),

    /// A buffer reopened to serve reads of a non-resident section. The handle owns its
    /// reference, so eviction from the reopened tier cannot close the blob under a read.
    Reopened(Arc<B>),
}

impl<B> Deref for Section<'_, B> {
    type Target = B;

    fn deref(&self) -> &B {
        match self {
            Self::Resident(buffer) => buffer,
            Self::Reopened(buffer) => buffer,
        }
    }
}

/// Manages a collection of section-based blobs.
///
/// Each section is stored in a separate blob, named by its section number
/// (big-endian u64). This component handles initialization, pruning, syncing,
/// and metrics, keeping a bounded number of blobs open (see the module docs).
pub struct Manager<E: Storage + Metrics, F: BufferFactory<E::Blob>> {
    context: E,
    partition: String,
    factory: F,

    /// The logical size of every section, whether or not its buffer is open.
    ///
    /// A resident section's buffer is authoritative because it includes data still buffered;
    /// this records the size a section had when it last left the resident tier, which is exact
    /// because a section is synced before it is evicted.
    sizes: BTreeMap<u64, u64>,

    /// Writable buffers, bounded by [Self::max_open_blobs].
    resident: BTreeMap<u64, F::Buffer>,

    /// Read-only buffers reopened to serve reads of non-resident sections.
    ///
    /// Disjoint from [Self::resident]: a section entering the resident tier is removed here,
    /// so no section is ever open for writing twice.
    reopened: RwLock<Clock<u64, Arc<F::Buffer>>>,

    /// The maximum number of buffers held in each tier.
    max_open_blobs: NonZeroUsize,

    /// A section number before which all sections have been pruned during
    /// the current execution. Not persisted across restarts.
    oldest_retained_section: u64,

    tracked: Gauge,
    opened: Gauge,
    synced: Counter,
    pruned: Counter,
    evicted: Counter,
    reopens: Counter,
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
    /// Storage cannot size a blob without opening it, so every section is opened once to record
    /// its size; only the newest [Config::max_open_blobs] stay open. Nothing is written through
    /// them, so the rest need no sync.
    pub async fn init(context: E, cfg: Config<F>) -> Result<Self, Error> {
        // Open each canonical section in storage order, retaining only the newest buffers.
        let mut sizes = BTreeMap::new();
        let mut resident = BTreeMap::new();
        let stored_blobs = stored_names(&context, &cfg.partition).await?;

        for name in stored_blobs {
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            let section = section_from_name(&name)?;
            debug!(section, blob = hex(&name), size, "loaded section");
            let buffer = cfg.factory.create(blob, size).await?;
            sizes.insert(section, buffer.size());
            resident.insert(section, buffer);

            // Evicting the lowest section leaves the newest sections resident whatever order
            // the partition scan returned.
            while resident.len() > cfg.max_open_blobs.get() {
                let oldest = *resident
                    .first_key_value()
                    .expect("resident tier is over capacity")
                    .0;
                resident.remove(&oldest);
            }
        }

        // Initialize metrics
        let tracked = context.gauge("tracked", "Number of blobs");
        let opened = context.gauge("opened", "Number of blobs held open");
        let synced = context.counter("synced", "Number of syncs");
        let pruned = context.counter("pruned", "Number of blobs pruned");
        let evicted = context.counter("evicted", "Number of blobs closed to respect the limit");
        let reopens = context.counter("reopens", "Number of blobs reopened to serve a read");
        let _ = tracked.try_set(sizes.len());
        let _ = opened.try_set(resident.len());

        Ok(Self {
            context,
            partition: cfg.partition,
            factory: cfg.factory,
            sizes,
            resident,
            reopened: RwLock::new(Clock::new(cfg.max_open_blobs)),
            max_open_blobs: cfg.max_open_blobs,
            oldest_retained_section: 0,
            tracked,
            opened,
            synced,
            pruned,
            evicted,
            reopens,
        })
    }

    /// Ensures that a section pruned during the current execution is not accessed.
    pub const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }

    /// Record the number of blobs currently held open across both tiers.
    fn record_open(&self) {
        let open = self.resident.len() + self.reopened.read().len();
        let _ = self.opened.try_set(open);
    }

    /// Drop a flushed resident buffer, recording its final size.
    ///
    /// Waiting resolves any started sync's shared completion so caller-held handles still
    /// report its true result; syncing then keeps a later [Self::sync] honest, since that skips
    /// non-resident sections. Neither can make buffered data durable, as only a flushed buffer
    /// is evicted, and syncing a clean one issues no fsync.
    async fn evict(&mut self, section: u64) -> Result<(), Error> {
        let mut buffer = self
            .resident
            .remove(&section)
            .expect("evicted section is resident");
        assert!(buffer.is_flushed(), "evicted buffer holds unflushed data");
        buffer.wait_for_sync().await.map_err(Error::Runtime)?;
        buffer.sync().await.map_err(Error::Runtime)?;
        let size = buffer.size();
        drop(buffer);

        self.sizes.insert(section, size);
        self.evicted.inc();
        self.record_open();
        debug!(section, size, "evicted section buffer");
        Ok(())
    }

    /// Evict resident sections until the tier holds at most [Self::max_open_blobs], never
    /// evicting `keep`.
    ///
    /// Takes the oldest flushed section, which a journal appending to its newest is least
    /// likely to write next. Closing an unflushed buffer would discard its writes or make them
    /// durable ahead of the caller's own [Self::sync], so the limit yields instead.
    async fn enforce_limit(&mut self, keep: u64) -> Result<(), Error> {
        while self.resident.len() > self.max_open_blobs.get() {
            let Some((&section, _)) = self
                .resident
                .iter()
                .find(|&(&section, buffer)| section != keep && buffer.is_flushed())
            else {
                break;
            };
            self.evict(section).await?;
        }
        Ok(())
    }

    /// Open `section`'s buffer, returning it with its logical size.
    ///
    /// The size is the buffer's, not the blob's, which also covers per-page checksum records.
    /// [Self::size] reports the buffer's, so recording the blob's would make an evicted section
    /// report a different size than a resident one.
    async fn open(&self, section: u64) -> Result<(F::Buffer, u64), Error> {
        let name = section.to_be_bytes();
        let (blob, size) = self.context.open(&self.partition, &name).await?;
        let buffer = self.factory.create(blob, size).await?;
        let size = buffer.size();
        Ok((buffer, size))
    }

    /// Get a mutable reference to a resident buffer, opening the section if it exists but is
    /// not resident.
    ///
    /// Returns `None` when the section does not exist. Making a section resident removes it
    /// from the reopened tier, so no section is ever open for writing twice.
    pub async fn resident_mut(&mut self, section: u64) -> Result<Option<&mut F::Buffer>, Error> {
        self.prune_guard(section)?;
        if !self.contains(section) {
            return Ok(None);
        }
        if !self.resident.contains_key(&section) {
            let (buffer, _) = self.open(section).await?;
            self.reopened.write().remove(&section);
            self.resident.insert(section, buffer);
            self.enforce_limit(section).await?;
            self.record_open();
        }
        Ok(self.resident.get_mut(&section))
    }

    /// Get a read handle to a section, if it exists.
    ///
    /// A non-resident section is reopened read-only and cached in the reopened tier. Two
    /// concurrent reads of the same non-resident section may each open the blob; both handles
    /// are read-only, so only the redundant open is wasted.
    pub async fn get(&self, section: u64) -> Result<Option<Section<'_, F::Buffer>>, Error> {
        self.prune_guard(section)?;
        if let Some(buffer) = self.resident.get(&section) {
            return Ok(Some(Section::Resident(buffer)));
        }
        if !self.contains(section) {
            return Ok(None);
        }
        if let Some(buffer) = self.reopened.read().get(&section) {
            return Ok(Some(Section::Reopened(buffer.clone())));
        }

        // Open outside the lock: the tier holds read-only buffers, so a concurrent open of the
        // same section is redundant rather than unsound.
        let (buffer, size) = self.open(section).await?;
        debug!(section, size, "reopened section to serve a read");
        let buffer = Arc::new(buffer);
        self.reopened.write().put(section, buffer.clone());
        self.reopens.inc();
        self.record_open();
        Ok(Some(Section::Reopened(buffer)))
    }

    /// Get a read handle to a section without performing I/O, if one is already open.
    ///
    /// Returns `None` when the section does not exist, is not open, or the reopened tier is
    /// concurrently being modified.
    pub fn try_get(&self, section: u64) -> Option<Section<'_, F::Buffer>> {
        self.prune_guard(section).ok()?;
        if let Some(buffer) = self.resident.get(&section) {
            return Some(Section::Resident(buffer));
        }
        let reopened = self.reopened.try_read()?;
        let buffer = reopened.get(&section)?;
        Some(Section::Reopened(buffer.clone()))
    }

    /// Get a mutable reference to a blob, creating it if it doesn't exist.
    pub async fn get_or_create(&mut self, section: u64) -> Result<&mut F::Buffer, Error> {
        self.prune_guard(section)?;

        if !self.resident.contains_key(&section) {
            let (buffer, size) = self.open(section).await?;
            if self.sizes.insert(section, size).is_none() {
                self.tracked.inc();
            }
            self.reopened.write().remove(&section);
            self.resident.insert(section, buffer);
            self.enforce_limit(section).await?;
            self.record_open();
        }

        // `enforce_limit` never evicts the section it is asked to keep.
        Ok(self
            .resident
            .get_mut(&section)
            .expect("requested section is resident"))
    }

    /// Sync the given `sections` to storage.
    ///
    /// Non-resident sections are skipped: only a resident buffer accepts writes and eviction
    /// syncs before closing, and sections closed during [Self::init] were never written here.
    pub async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        for &section in &sections {
            self.prune_guard(section)?;
        }
        let futures: Vec<_> = self
            .resident
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
    /// that sync's handle rather than starting a new one. A section that is not resident is
    /// already durable and is skipped.
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
            .resident
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

    /// Sync every open section to storage.
    ///
    /// Sections whose buffer is closed are skipped on the same grounds as [Self::sync]: only a
    /// resident buffer can accept a write, and eviction syncs before closing.
    pub async fn sync_all(&mut self) -> Result<(), Error> {
        let count = self.resident.len() as u64;
        try_join_all(self.resident.values_mut().map(|b| b.sync()))
            .await
            .map_err(Error::Runtime)?;
        self.synced.inc_by(count);
        Ok(())
    }

    /// Drop every open buffer for `section` without syncing, returning its size if it was
    /// resident.
    ///
    /// Unlike [Self::evict], this does not preserve the section: it is only for a blob that is
    /// being removed, so buffered data is discarded rather than flushed.
    async fn discard(&mut self, section: u64) -> Result<Option<u64>, Error> {
        self.reopened.write().remove(&section);
        let size = match self.resident.remove(&section) {
            Some(mut buffer) => {
                buffer.wait_for_sync().await.map_err(Error::Runtime)?;
                let size = buffer.size();
                drop(buffer);
                Some(size)
            }
            None => None,
        };
        self.record_open();
        Ok(size)
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        // Prune any blobs that are smaller than the minimum
        let mut pruned = false;
        while let Some((&section, &recorded)) = self.sizes.first_key_value() {
            // Stop pruning if we reach the minimum
            if section >= min {
                break;
            }

            let size = self.discard(section).await?.unwrap_or(recorded);
            self.sizes.remove(&section);

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
        self.sizes.first_key_value().map(|(&s, _)| s)
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.sizes.last_key_value().map(|(&s, _)| s)
    }

    /// Returns true if no blobs exist.
    pub fn is_empty(&self) -> bool {
        self.sizes.is_empty()
    }

    /// Returns the number of sections (blobs).
    pub fn num_sections(&self) -> usize {
        self.sizes.len()
    }

    /// Returns true if the section exists.
    pub fn contains(&self, section: u64) -> bool {
        self.sizes.contains_key(&section)
    }

    /// Returns all section numbers from `start_section`, in ascending order.
    pub fn sections_from(&self, start_section: u64) -> impl Iterator<Item = u64> + '_ {
        self.sizes.range(start_section..).map(|(&s, _)| s)
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.sizes.keys().copied()
    }

    /// Remove a specific section. Returns true if the section existed and was removed.
    pub async fn remove_section(&mut self, section: u64) -> Result<bool, Error> {
        self.prune_guard(section)?;

        let Some(recorded) = self.sizes.remove(&section) else {
            return Ok(false);
        };
        let size = self.discard(section).await?.unwrap_or(recorded);
        self.context
            .remove(&self.partition, Some(&section.to_be_bytes()))
            .await?;
        self.tracked.dec();
        debug!(section, size, "removed section");
        Ok(true)
    }

    /// Remove all underlying blobs.
    pub async fn destroy(mut self) -> Result<(), Error> {
        Self::wait_for_syncs(self.resident.values_mut()).await?;
        self.reopened.write().clear();
        self.resident.clear();
        for (section, size) in self.sizes {
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
        Self::wait_for_syncs(self.resident.values_mut()).await?;
        self.reopened.write().clear();
        self.resident.clear();
        for (section, size) in take(&mut self.sizes) {
            debug!(section, size, "cleared blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        let _ = self.tracked.try_set(0);
        let _ = self.opened.try_set(0);
        self.oldest_retained_section = 0;
        Ok(())
    }

    /// Rewind by removing all sections after `section` and resizing the target section.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Remove sections in descending order (newest first) to maintain a contiguous record
        // if a crash occurs during rewind. Section `u64::MAX` has no successor, so there are
        // no sections above it to remove.
        let sections_to_remove: Vec<u64> = match section.checked_add(1) {
            Some(next) => self.sizes.range(next..).rev().map(|(&s, _)| s).collect(),
            None => Vec::new(),
        };

        for s in sections_to_remove {
            // Remove the underlying blob from storage
            self.discard(s).await?;
            self.sizes.remove(&s);
            self.context
                .remove(&self.partition, Some(&s.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section = s, "removed blob during rewind");
        }

        // If the section exists, truncate it to the given size. No explicit sync barrier is
        // needed here: the buffer waits for any in-flight sync before mutating the blob.
        self.rewind_section(section, size).await
    }

    /// Resize only the given section without affecting other sections.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Consult the recorded size first so a rewind that would not shrink the section does
        // not reopen it. A section that does not exist reports zero, so it is never shrunk.
        let current = self.size(section)?;
        if size >= current {
            return Ok(());
        }

        let blob = self
            .resident_mut(section)
            .await?
            .expect("a section with a nonzero size exists");
        blob.resize(size).await?;
        self.sizes.insert(section, size);
        debug!(section, from = current, to = size, "rewound section");

        Ok(())
    }

    /// Returns the byte size of the given section.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;
        if let Some(blob) = self.resident.get(&section) {
            return Ok(blob.size());
        }
        Ok(self.sizes.get(&section).copied().unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, channel::oneshot, sync::Mutex};
    use futures::{
        FutureExt as _,
        future::{BoxFuture, Shared},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    type SyncSender = oneshot::Sender<Result<(), RError>>;
    type PendingSyncs = Arc<Mutex<Vec<SyncSender>>>;

    /// A shared sync result, mirroring the runtime buffers' internal completion sharing.
    type SharedSync = Shared<BoxFuture<'static, Result<(), RError>>>;

    #[derive(Clone)]
    struct TestFactory {
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
    }

    struct TestBuffer {
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
        syncing: Option<SharedSync>,
    }

    impl SectionBuffer for TestBuffer {
        fn size(&self) -> u64 {
            0
        }

        fn is_flushed(&self) -> bool {
            true
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

        async fn resize(&mut self, _len: u64) -> Result<(), RError> {
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
            max_open_blobs: NZUsize!(64),
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
