//! Common blob management for segmented journals.
//!
//! This module provides `Manager`, a reusable component that handles
//! section-based blob storage, pruning, syncing, and metrics.

use crate::journal::Error;
use commonware_formatting::hex;
use commonware_runtime::{
    Blob, BufferPool, Error as RError, Handle, Metrics, Storage,
    buffer::{
        Write,
        paged::{CHECKSUM_SIZE, CacheRef, Recovery as PagedRecovery},
    },
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use futures::future::{join_all, try_join_all};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    future::Future,
    mem::take,
    num::{NonZeroU16, NonZeroUsize},
    ops::{Deref, DerefMut},
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

/// Remove sections and whole pages above a ceiling before opening exclusive recovery owners.
/// The containing page remains intact for checksum validation and exact logical truncation.
pub(super) async fn truncate_paged_tail<E: Storage>(
    context: &E,
    partition: &str,
    page_size: NonZeroU16,
    section: u64,
    end: u64,
) -> Result<(), Error> {
    let mut sections = stored_names(context, partition)
        .await?
        .iter()
        .map(|name| section_from_name(name))
        .collect::<Result<Vec<_>, _>>()?;
    sections.sort_unstable();
    for stored in sections.into_iter().rev() {
        if stored > section {
            context
                .remove(partition, Some(&stored.to_be_bytes()))
                .await?;
            continue;
        }
        if stored == section {
            let (blob, size) = context.open(partition, &stored.to_be_bytes()).await?;

            // An unrepresentable physical ceiling excludes no representable blob bytes.
            let page_size = u64::from(page_size.get());
            let ceiling = end
                .div_ceil(page_size)
                .saturating_mul(page_size + CHECKSUM_SIZE);
            if ceiling < size {
                blob.resize(ceiling).await?;
                blob.sync().await?;
            }
        }
        break;
    }
    Ok(())
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

    /// Shorten the buffer. A shorter length is durable when this returns.
    fn truncate(&mut self, len: u64) -> impl Future<Output = Result<(), RError>> + Send;
}

impl<B: Blob> SectionBuffer for PagedRecovery<B> {
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

    async fn truncate(&mut self, len: u64) -> Result<(), RError> {
        Self::truncate(self, len).await
    }
}

/// A buffered writer over a shared blob handle, so owned readers can share the section's open.
pub struct WriteBuffer<B: Blob> {
    pub blob: Arc<B>,
    writer: Write<Arc<B>>,
}

impl<B: Blob> Deref for WriteBuffer<B> {
    type Target = Write<Arc<B>>;

    fn deref(&self) -> &Self::Target {
        &self.writer
    }
}

impl<B: Blob> DerefMut for WriteBuffer<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.writer
    }
}

// Glob's recovery owner controls access to truncation for uncached sections.
impl<B: Blob> SectionBuffer for WriteBuffer<B> {
    fn size(&self) -> u64 {
        self.writer.size()
    }

    async fn sync(&mut self) -> Result<(), RError> {
        self.writer.sync().await
    }

    async fn start_sync(&mut self) -> Handle<()> {
        self.writer.start_sync().await
    }

    async fn wait_for_sync(&mut self) -> Result<(), RError> {
        self.writer.wait_for_sync().await
    }

    async fn truncate(&mut self, len: u64) -> Result<(), RError> {
        if len < self.writer.size() {
            self.writer.resize(len).await?;
            self.writer.sync().await?;
        }
        Ok(())
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

/// Factory for creating cached sections whose repair permission belongs to the journal.
#[derive(Clone)]
pub struct AppendFactory {
    /// The size of the write buffer.
    pub write_buffer: NonZeroUsize,
    /// The page cache for read caching.
    pub page_cache_ref: CacheRef,
}

impl<B: Blob> BufferFactory<B> for AppendFactory {
    type Buffer = PagedRecovery<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        PagedRecovery::open(
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
    type Buffer = WriteBuffer<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        let blob = Arc::new(blob);
        Ok(WriteBuffer {
            writer: Write::new(blob.clone(), size, self.capacity, self.pool.clone()),
            blob,
        })
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

    /// Sections above this ceiling remain unopened until truncation or clear removes them.
    ceiling: u64,

    /// Unopened sections above `ceiling` in ascending order, so removal can run newest-first.
    discarded: Vec<u64>,

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
        Self::init_bounded(context, cfg, u64::MAX).await
    }

    /// Open only sections through `ceiling`. [Self::truncate_pending] or [Self::clear] removes the
    /// remaining sections and must run before the caller publishes the manager.
    pub async fn init_bounded(context: E, cfg: Config<F>, ceiling: u64) -> Result<Self, Error> {
        let mut blobs = BTreeMap::new();
        let mut discarded = Vec::new();
        for name in stored_names(&context, &cfg.partition).await? {
            let section = section_from_name(&name)?;
            if section > ceiling {
                discarded.push(section);
                continue;
            }
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            debug!(section, blob = hex(&name), size, "loaded section");
            let buffer = cfg.factory.create(blob, size).await?;
            blobs.insert(section, buffer);
        }
        discarded.sort_unstable();

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
            ceiling,
            discarded,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,
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
        assert!(
            section <= self.ceiling,
            "sections above the initialization ceiling must be truncated before creation"
        );

        match self.blobs.entry(section) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let name = section.to_be_bytes();
                let (blob, size) = self.context.open(&self.partition, &name).await?;
                let buffer = self.factory.create(blob, size).await?;
                self.tracked.inc();
                Ok(entry.insert(buffer))
            }
        }
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
    /// the started sync, or of the flush that precedes it, resurfaces from the buffer on the
    /// section's next sync or flushing operation.
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

            // Remove blob from storage
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            drop(blob);
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
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            drop(blob);
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
            debug!(section, size, "destroyed blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            drop(blob);
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
        self.remove_discarded().await?;
        Self::wait_for_syncs(self.blobs.values_mut()).await?;
        let blobs = take(&mut self.blobs);
        for (section, blob) in blobs {
            let size = blob.size();
            debug!(section, size, "cleared blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            drop(blob);
        }
        let _ = self.tracked.try_set(0);
        self.oldest_retained_section = 0;
        Ok(())
    }

    /// Truncate by removing all sections after `section` and resizing the target section. A
    /// shorter section length is durable when this returns.
    pub async fn truncate_pending(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;
        assert!(
            section <= self.ceiling,
            "truncation must remove every section above the initialization ceiling"
        );
        self.remove_discarded().await?;

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
            self.context
                .remove(&self.partition, Some(&s.to_be_bytes()))
                .await?;
            drop(blob);
            self.tracked.dec();
            debug!(section = s, "removed blob during truncate");
        }

        self.truncate_pending_section(section, size).await
    }

    /// Remove unopened suffix sections newest-first and lift the ceiling that held them. Callers
    /// run this before shortening or clearing the opened prefix.
    async fn remove_discarded(&mut self) -> Result<(), Error> {
        for section in take(&mut self.discarded).into_iter().rev() {
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            debug!(section, "removed unopened blob");
        }
        self.ceiling = u64::MAX;
        Ok(())
    }

    /// Truncate only the given section without affecting other sections. A shorter length is
    /// durable when this returns.
    pub async fn truncate_pending_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Get the blob at the given section
        if let Some(blob) = self.blobs.get_mut(&section) {
            // Truncate the blob to the given size
            let current = blob.size();
            if size < current {
                blob.truncate(size).await?;
                debug!(section, from = current, to = size, "truncated section");
            }
        }

        Ok(())
    }

    /// Durably truncate independent sections to their selected upper bounds.
    pub async fn truncate_pending_sections(
        &mut self,
        sizes: &BTreeMap<u64, u64>,
    ) -> Result<(), Error> {
        if sizes.is_empty() {
            return Ok(());
        }
        for &section in sizes.keys() {
            self.prune_guard(section)?;
        }
        let futures = self.blobs.iter_mut().filter_map(|(section, blob)| {
            let &size = sizes.get(section)?;
            (size < blob.size()).then(|| blob.truncate(size))
        });
        try_join_all(futures).await.map_err(Error::Runtime)?;
        Ok(())
    }

    /// Returns the byte size of the given section.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;
        Ok(self.blobs.get(&section).map_or(0, |blob| blob.size()))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use commonware_runtime::{
        BlobVersion, BufferPooler, Name, ReadOptions, Runner as _, Spawner as _, Supervisor,
        WriteOptions,
        buffer::paged::Writer,
        deterministic,
        telemetry::metrics::{Metric, Registered},
    };
    use commonware_utils::{NZU16, channel::oneshot, sync::Mutex};
    use futures::{
        FutureExt as _,
        future::{BoxFuture, Shared},
    };
    use std::{
        ops::RangeInclusive,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// Materialize a crash that retains new page bytes but loses their checksum lengths.
    pub(in super::super) async fn seed_torn_suffix<E: Storage + BufferPooler>(
        context: &E,
        partition: &str,
        section: u64,
        page: &[u8],
        suffix_pages: usize,
    ) {
        // Seed one acknowledged page whose physical encoding can prefix the crash image.
        let physical = page.len() + CHECKSUM_SIZE as usize;
        let source = format!("{partition}-source");
        let (raw, size) = context.open(&source, b"source").await.unwrap();
        let raw = Arc::new(raw);
        let cache = CacheRef::from_pooler(
            context,
            (page.len() as u16).try_into().unwrap(),
            commonware_utils::NZUsize!(4),
        );
        let mut writer = Writer::new(Arc::clone(&raw), size, 2 * page.len(), cache)
            .await
            .unwrap();
        writer.append(page).await.unwrap();
        writer.sync().await.unwrap();
        let acknowledged = raw
            .read_at(0, physical, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();

        // The empty tip and page-aligned direct append issue one unsynced write wholly beyond
        // the acknowledged page. The raw handle shares the writer's open and observes those bytes.
        writer
            .append_owned(page.repeat(suffix_pages).into())
            .await
            .unwrap();
        let mut image = raw
            .read_at(0, physical * (suffix_pages + 1), ReadOptions::default())
            .await
            .unwrap()
            .coalesce()
            .as_ref()
            .to_vec();
        assert_eq!(&image[..physical], acknowledged.as_ref());
        drop(writer);
        drop(raw);

        // Clear the unacknowledged pages' length slots to model torn checksum publication.
        for page_index in 1..=suffix_pages {
            let footer = page_index * physical + page.len();
            image[footer..footer + 2].fill(0);
            image[footer + 6..footer + 8].fill(0);
        }
        let (blob, _) = context
            .open(partition, &section.to_be_bytes())
            .await
            .unwrap();
        blob.write_at(0, image, WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
    }

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
        on_drop: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    struct TestBuffer<B: Blob> {
        /// Keeps the raw blob owner alive while the test buffer models an open section.
        _blob: B,
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
        syncing: Option<SharedSync>,
        on_drop: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    impl<B: Blob> Drop for TestBuffer<B> {
        fn drop(&mut self) {
            if let Some(on_drop) = &self.on_drop {
                on_drop();
            }
        }
    }

    impl<B: Blob> SectionBuffer for TestBuffer<B> {
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

        async fn truncate(&mut self, _len: u64) -> Result<(), RError> {
            Ok(())
        }
    }

    impl<B: Blob> BufferFactory<B> for TestFactory {
        type Buffer = TestBuffer<B>;

        async fn create(&self, blob: B, _size: u64) -> Result<Self::Buffer, RError> {
            Ok(TestBuffer {
                _blob: blob,
                pending: self.pending.clone(),
                wait_for_syncs: self.wait_for_syncs.clone(),
                syncing: None,
                on_drop: self.on_drop.clone(),
            })
        }
    }

    fn test_config(pending: PendingSyncs, wait_for_syncs: Arc<AtomicUsize>) -> Config<TestFactory> {
        Config {
            partition: "test".into(),
            factory: TestFactory {
                pending,
                wait_for_syncs,
                on_drop: None,
            },
        }
    }

    /// Blob removals observed by a [Reversed] context as (partition, name) pairs, in call order.
    type Removals = Arc<Mutex<Vec<(String, Option<Vec<u8>>)>>>;

    /// Deterministic context that lists blob names in reverse order and records every removal.
    ///
    /// The deterministic runtime lists names in ascending order, which hides removal loops that
    /// rely on listing order instead of sorting.
    struct Reversed {
        inner: deterministic::Context,
        removals: Removals,
    }

    impl Supervisor for Reversed {
        fn name(&self) -> Name {
            self.inner.name()
        }

        fn child(&self, label: &'static str) -> Self {
            Self {
                inner: self.inner.child(label),
                removals: self.removals.clone(),
            }
        }

        fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
            Self {
                inner: self.inner.with_attribute(key, value),
                removals: self.removals,
            }
        }
    }

    impl Metrics for Reversed {
        fn register<N: Into<String>, H: Into<String>, M: Metric>(
            &self,
            name: N,
            help: H,
            metric: M,
        ) -> Registered<M> {
            self.inner.register(name, help, metric)
        }

        fn encode(&self) -> String {
            self.inner.encode()
        }
    }

    impl Storage for Reversed {
        type Blob = <deterministic::Context as Storage>::Blob;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: RangeInclusive<BlobVersion>,
        ) -> Result<(Self::Blob, u64, BlobVersion), RError> {
            self.inner.open_versioned(partition, name, versions).await
        }

        async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), RError> {
            self.inner.remove(partition, name).await?;
            self.removals
                .lock()
                .push((partition.into(), name.map(<[u8]>::to_vec)));
            Ok(())
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, RError> {
            let mut names = self.inner.scan(partition).await?;
            names.reverse();
            Ok(names)
        }
    }

    /// Expected [Removals] of `sections` from the test partition, in order.
    fn removed(sections: &[u64]) -> Vec<(String, Option<Vec<u8>>)> {
        sections
            .iter()
            .map(|section| ("test".into(), Some(section.to_be_bytes().to_vec())))
            .collect()
    }

    #[test]
    fn test_init_bounded_leaves_later_sections_unopened() {
        deterministic::Runner::default().start(|context| async move {
            // Seed empty blobs for sections 1, 2 and 5 with an unbounded manager. The drop hook is
            // installed only after seeding, so `dropped` counts only drops of buffers built by the
            // bounded managers below.
            let dropped = Arc::new(AtomicUsize::new(0));
            let mut cfg = test_config(PendingSyncs::default(), Arc::new(AtomicUsize::new(0)));
            let mut manager = Manager::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            for section in [1, 2, 5] {
                manager.get_or_create(section).await.unwrap();
            }
            drop(manager);

            // Only sections up to the ceiling are opened. The rest stay in storage until
            // truncation removes them by name.
            let observed = dropped.clone();
            cfg.factory.on_drop = Some(Arc::new(move || {
                observed.fetch_add(1, Ordering::Relaxed);
            }));
            let mut manager = Manager::init_bounded(context.child("bounded"), cfg.clone(), 2)
                .await
                .unwrap();
            assert_eq!(manager.sections().collect::<Vec<_>>(), vec![1, 2]);
            assert_eq!(manager.newest_section(), Some(2));
            assert_eq!(context.scan("test").await.unwrap().len(), 3);

            // Truncating to the ceiling removes the unopened section 5 and keeps both opened ones.
            manager.truncate_pending(2, 0).await.unwrap();
            assert_eq!(
                context.scan("test").await.unwrap(),
                vec![1u64.to_be_bytes().to_vec(), 2u64.to_be_bytes().to_vec()]
            );

            // Dropping the manager releases every buffer it built. A count of two means the factory
            // built buffers only for sections 1 and 2.
            drop(manager);
            assert_eq!(
                dropped.load(Ordering::Relaxed),
                2,
                "section 5 must never be opened"
            );

            // A ceiling below every stored section opens nothing and truncation removes them all.
            // Section 0 has no blob, and truncating to it does not create one.
            let mut manager = Manager::init_bounded(context.child("empty"), cfg, 0)
                .await
                .unwrap();
            assert!(manager.sections().next().is_none());
            assert_eq!(manager.newest_section(), None);
            manager.truncate_pending(0, 0).await.unwrap();
            assert!(context.scan("test").await.unwrap().is_empty());

            // This manager built no buffers, so the drop count is unchanged.
            drop(manager);
            assert_eq!(dropped.load(Ordering::Relaxed), 2);
        });
    }

    #[test]
    #[should_panic(
        expected = "truncation must remove every section above the initialization ceiling"
    )]
    fn test_truncate_pending_above_ceiling_panics() {
        deterministic::Runner::default().start(|context| async move {
            // Seed section 1 for the bounded manager to open and section 5 for it to leave
            // unopened. No section is stored at 3 or 4.
            let cfg = test_config(PendingSyncs::default(), Arc::new(AtomicUsize::new(0)));
            let mut manager = Manager::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            manager.get_or_create(1).await.unwrap();
            manager.get_or_create(5).await.unwrap();
            drop(manager);

            // The ceiling bounds the target even when a gap separates it from the first unopened
            // section. Truncation removes every unopened section, so it cannot retain one.
            let mut manager = Manager::init_bounded(context.child("bounded"), cfg, 2)
                .await
                .unwrap();
            manager.truncate_pending(4, 0).await.unwrap();
        });
    }

    #[test]
    #[should_panic(
        expected = "sections above the initialization ceiling must be truncated before creation"
    )]
    fn test_get_or_create_above_ceiling_panics() {
        deterministic::Runner::default().start(|context| async move {
            // Seed only section 5, which the ceiling of 2 below leaves unopened.
            let cfg = test_config(PendingSyncs::default(), Arc::new(AtomicUsize::new(0)));
            let mut manager = Manager::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            manager.get_or_create(5).await.unwrap();
            drop(manager);

            // Creating a section above the ceiling would adopt the stored bytes of a section
            // awaiting removal.
            let mut manager = Manager::init_bounded(context.child("bounded"), cfg, 2)
                .await
                .unwrap();
            manager.get_or_create(5).await.unwrap();
        });
    }

    #[test]
    fn test_truncate_pending_removes_unopened_sections_newest_first() {
        deterministic::Runner::default().start(|context| async move {
            // Seed two sections at or below the ceiling of 2 and three above it.
            let cfg = test_config(PendingSyncs::default(), Arc::new(AtomicUsize::new(0)));
            let mut manager = Manager::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            for section in [1, 2, 5, 6, 7] {
                manager.get_or_create(section).await.unwrap();
            }
            drop(manager);

            // Reopen with names listed newest-first. The unopened sections above the ceiling are
            // then collected in descending order and only a sort restores ascending order.
            let removals = Removals::default();
            let reversed = Reversed {
                inner: context.child("bounded"),
                removals: removals.clone(),
            };
            let mut manager = Manager::init_bounded(reversed, cfg, 2).await.unwrap();
            assert_eq!(manager.sections().collect::<Vec<_>>(), vec![1, 2]);

            // Truncation removes unopened sections newest-first, so a crash mid-removal leaves a
            // prefix of the stored sections. No opened section lies above target 2, so the log
            // holds only unopened-section removals. Without the sort they would run 5, 6, 7.
            manager.truncate_pending(2, 0).await.unwrap();
            assert_eq!(*removals.lock(), removed(&[7, 6, 5]));

            // Both opened sections survive in the manager and in storage. The plain context lists
            // names in ascending order.
            assert_eq!(manager.sections().collect::<Vec<_>>(), vec![1, 2]);
            assert_eq!(
                context.scan("test").await.unwrap(),
                vec![1u64.to_be_bytes().to_vec(), 2u64.to_be_bytes().to_vec()]
            );
        });
    }

    #[test]
    fn test_truncate_paged_tail_removes_sections_newest_first() {
        deterministic::Runner::default().start(|context| async move {
            // Create empty stored sections on both sides of the target.
            for section in [1u64, 2, 5, 6, 7] {
                context.open("test", &section.to_be_bytes()).await.unwrap();
            }

            // List names newest-first. Walking this listing backward without a sort would reach
            // section 1 first and stop before removing anything above the target.
            let removals = Removals::default();
            let reversed = Reversed {
                inner: context.child("reversed"),
                removals: removals.clone(),
            };

            // End 0 gives a physical ceiling of zero bytes for any page size and target section 2
            // is empty, so no resize runs. The call changes storage only by removing sections.
            truncate_paged_tail(&reversed, "test", NZU16!(64), 2, 0)
                .await
                .unwrap();

            // Every section above the target is removed newest-first and the rest are retained.
            assert_eq!(*removals.lock(), removed(&[7, 6, 5]));
            assert_eq!(
                context.scan("test").await.unwrap(),
                vec![1u64.to_be_bytes().to_vec(), 2u64.to_be_bytes().to_vec()]
            );
        });
    }

    #[test]
    fn test_clear_removes_unopened_sections_and_lifts_ceiling() {
        deterministic::Runner::default().start(|context| async move {
            // Seed section 1 for the bounded manager to open and section 5 for it to leave
            // unopened.
            let cfg = test_config(PendingSyncs::default(), Arc::new(AtomicUsize::new(0)));
            let mut manager = Manager::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            manager.get_or_create(1).await.unwrap();
            manager.get_or_create(5).await.unwrap();
            drop(manager);

            // Clearing a bounded manager removes the unopened section along with the opened one.
            let mut manager = Manager::init_bounded(context.child("bounded"), cfg, 2)
                .await
                .unwrap();
            manager.clear().await.unwrap();
            assert!(context.scan("test").await.unwrap().is_empty());

            // No stored section remains above the ceiling, so it no longer restricts creation. The
            // stored section 5 was removed, so creating it opens a fresh empty blob.
            manager.get_or_create(5).await.unwrap();
            assert_eq!(manager.sections().collect::<Vec<_>>(), vec![5]);
        });
    }

    #[test]
    fn test_cleanup_drops_each_owner_after_removal() {
        for operation in [
            "prune",
            "remove_section",
            "destroy",
            "clear",
            "truncate_pending",
        ] {
            deterministic::Runner::default().start(|context| async move {
                // Observe each buffer drop against the partition contents visible at that instant.
                let drops = Arc::new(Mutex::new(Vec::new()));
                let observed = drops.clone();
                let observer = context.child("drop_observer");
                let mut cfg = test_config(PendingSyncs::default(), Arc::new(AtomicUsize::new(0)));
                cfg.factory.on_drop = Some(Arc::new(move || {
                    // Deterministic namespace reads complete on their first poll.
                    let names = observer.scan("test").now_or_never().and_then(Result::ok);
                    observed.lock().push(names);
                }));
                let mut manager = Manager::init(context.child("manager"), cfg).await.unwrap();
                manager.get_or_create(1).await.unwrap();
                manager.get_or_create(2).await.unwrap();

                // Every cleanup path must remove persistent names before releasing their owners.
                match operation {
                    "prune" => assert!(manager.prune(3).await.unwrap()),
                    "remove_section" => {
                        assert!(manager.remove_section(1).await.unwrap());
                        assert!(manager.remove_section(2).await.unwrap());
                    }
                    "destroy" => manager.destroy().await.unwrap(),
                    "clear" => manager.clear().await.unwrap(),
                    "truncate_pending" => manager.truncate_pending(0, 0).await.unwrap(),
                    _ => unreachable!(),
                }

                // Each drop observes only names whose owners remain live.
                let remaining = if operation == "truncate_pending" {
                    1u64
                } else {
                    2u64
                };
                assert_eq!(
                    *drops.lock(),
                    vec![
                        Some(vec![remaining.to_be_bytes().to_vec()]),
                        Some(Vec::new())
                    ],
                    "{operation}",
                );
            });
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
                // Hold a sync on the section that truncation will remove.
                let pending = PendingSyncs::default();
                let wait_for_syncs = Arc::new(AtomicUsize::new(0));
                let cfg = test_config(pending.clone(), wait_for_syncs.clone());
                let mut manager = Manager::init(context.child("manager"), cfg).await.unwrap();
                manager.get_or_create(1).await.unwrap();
                manager.get_or_create(2).await.unwrap();
                let handle = manager.start_sync(2).await.unwrap();

                // Truncation must wait for that sync and surface its completion result.
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

                // A failed sync is fatal to this manager; success leaves only the retained section.
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
