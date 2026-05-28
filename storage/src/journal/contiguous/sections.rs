//! Typed sealed/tail section store for contiguous journals.
//!
//! The store has a two-phase lifecycle:
//!
//! 1. [`SectionsInit::open`] scans the partition and opens every blob as [`Append<B>`] so the
//!    caller can perform format-level recovery (e.g. truncate trailing partial-item bytes).
//! 2. [`SectionsInit::into_sections`] seals every section that is not the chosen tail and returns
//!    a [`Sections`] whose historical entries are [`Sealed<B>`] handles.
//!
//! `Sections` is the steady-state store: historical sections are immutable by construction (no
//! write API on [`Sealed`]), and only the tail can mutate.
//!
//! Both phases share plumbing — partition I/O, metric registration, the prune guard — via the
//! private [`SectionsCore`] type. Each phase owns its own collection of section handles; only the
//! shape of that collection differs.

use crate::journal::Error;
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::paged::{Append, CacheRef, Replay, Sealed},
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
    Blob, Error as RError, IoBufs, Metrics, Storage,
};
use std::{collections::BTreeMap, mem::take, num::NonZeroUsize};
use tracing::debug;

/// Configuration for both lifecycle phases.
#[derive(Clone)]
pub(super) struct Config {
    /// Partition that stores one blob per section, named with the section's big-endian u64 bytes.
    pub partition: String,

    /// Page cache shared by every section in this store.
    pub page_cache: CacheRef,

    /// Write buffer size used when opening tail sections as [`Append`].
    pub write_buffer: NonZeroUsize,
}

/// Shared plumbing for [`SectionsInit`] and [`Sections`]: partition I/O, metrics, and the prune
/// guard. Both phases embed a `SectionsCore` so blob open/remove, metric registration, and the
/// prune-guard predicate are defined exactly once.
struct SectionsCore<E: Storage + Metrics> {
    context: E,
    partition: String,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,

    /// Sections pruned during this process's execution. Reads to sections below this value return
    /// [`Error::AlreadyPrunedToSection`]. Not persisted across restarts. Only meaningful for the
    /// steady-state [`Sections`]; [`SectionsInit`] ignores it.
    oldest_retained_section: u64,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl<E: Storage + Metrics> SectionsCore<E> {
    /// Build the core from a freshly-scanned partition, initializing `tracked` to `n`.
    fn build(context: E, cfg: Config, n: usize) -> Self {
        let tracked = context.gauge("tracked", "Number of blobs");
        let synced = context.counter("synced", "Number of syncs");
        let pruned = context.counter("pruned", "Number of blobs pruned");
        let _ = tracked.try_set(n);
        Self {
            context,
            partition: cfg.partition,
            page_cache: cfg.page_cache,
            write_buffer: cfg.write_buffer,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,
        }
    }

    /// Open the blob for `section` as an [`Append`].
    async fn open_append(&self, section: u64) -> Result<Append<E::Blob>, Error> {
        let (blob, size) = self
            .context
            .open(&self.partition, &section.to_be_bytes())
            .await?;
        Append::new(blob, size, self.write_buffer.get(), self.page_cache.clone())
            .await
            .map_err(Error::Runtime)
    }

    /// Remove a section's underlying blob from the partition.
    async fn remove_blob(&self, section: u64) -> Result<(), Error> {
        self.context
            .remove(&self.partition, Some(&section.to_be_bytes()))
            .await
            .map_err(Error::Runtime)
    }

    /// Remove the partition itself. Treats `PartitionMissing` as success.
    async fn remove_partition(&self) -> Result<(), Error> {
        match self.context.remove(&self.partition, None).await {
            Ok(()) | Err(RError::PartitionMissing(_)) => Ok(()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }
}

/// Pre-tail-install state: every section is open as [`Append`] so the caller can perform recovery
/// before sealing.
pub(super) struct SectionsInit<E: Storage + Metrics> {
    core: SectionsCore<E>,
    pending: BTreeMap<u64, Append<E::Blob>>,
}

impl<E: Storage + Metrics> SectionsInit<E> {
    /// Scan the partition and open every blob as an [`Append`].
    pub(super) async fn open(context: E, cfg: Config) -> Result<Self, Error> {
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        let mut pending = BTreeMap::new();
        for name in stored_blobs {
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            let hex_name = hex(&name);
            let section = match <[u8; 8]>::try_from(name.as_slice()) {
                Ok(bytes) => u64::from_be_bytes(bytes),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, size, "loaded section");
            let append = Append::new(blob, size, cfg.write_buffer.get(), cfg.page_cache.clone())
                .await
                .map_err(Error::Runtime)?;
            pending.insert(section, append);
        }

        let core = SectionsCore::build(context, cfg, pending.len());
        Ok(Self { core, pending })
    }

    /// All known section numbers, in ascending order.
    pub(super) fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.pending.keys().copied()
    }

    pub(super) fn oldest_section(&self) -> Option<u64> {
        self.pending.first_key_value().map(|(&s, _)| s)
    }

    pub(super) fn newest_section(&self) -> Option<u64> {
        self.pending.last_key_value().map(|(&s, _)| s)
    }

    /// Byte size of `section`.
    pub(super) async fn section_size(&self, section: u64) -> Result<u64, Error> {
        match self.pending.get(&section) {
            Some(app) => Ok(app.size().await),
            None => Err(Error::SectionOutOfRange(section)),
        }
    }

    /// Borrow the [`Append`] for `section`, for read-only format-level recovery (e.g. replay).
    pub(super) fn section(&self, section: u64) -> Option<&Append<E::Blob>> {
        self.pending.get(&section)
    }

    /// Truncate `section` to `size` bytes. No-op if `size` is already at or above the current size.
    pub(super) async fn truncate_section(&self, section: u64, size: u64) -> Result<(), Error> {
        if let Some(app) = self.pending.get(&section) {
            let cur = app.size().await;
            if size < cur {
                app.resize(size).await.map_err(Error::Runtime)?;
                debug!(section, from = cur, to = size, "truncated pending section");
            }
        }
        Ok(())
    }

    /// Consume the builder, removing every existing blob and installing a fresh empty tail at
    /// `tail_section`.
    // Only caller (`fixed::Journal::init_at_size`) is `#[stability(ALPHA)]`; this becomes dead
    // when the stability lint strips ALPHA items.
    #[allow(dead_code)]
    pub(super) async fn reset(mut self, tail_section: u64) -> Result<Sections<E>, Error> {
        for (section, blob) in take(&mut self.pending) {
            drop(blob);
            self.core.remove_blob(section).await?;
        }
        let blob = self.core.open_append(tail_section).await?;
        let _ = self.core.tracked.try_set(1);
        Ok(Sections {
            core: self.core,
            sealed: BTreeMap::new(),
            tail: Some(Tail {
                section: tail_section,
                blob,
            }),
        })
    }

    /// Consume the builder, sealing every section that is not `tail_section` and (optionally)
    /// installing the tail.
    ///
    /// - `Some(s)` with `s` present in pending: that handle becomes the tail; all others are sealed.
    /// - `Some(s)` with `s` not present: a fresh empty blob is opened at `s` as the tail; all
    ///   pending sections are sealed.
    /// - `None`: every pending section is sealed and the resulting [`Sections`] has no tail.
    ///   The caller must call [`Sections::install_tail`] before any tail-bound operation.
    pub(super) async fn into_sections(
        mut self,
        tail_section: Option<u64>,
    ) -> Result<Sections<E>, Error> {
        let tail = match tail_section {
            Some(s) => Some(Tail {
                section: s,
                blob: match self.pending.remove(&s) {
                    Some(existing) => existing,
                    None => {
                        let blob = self.core.open_append(s).await?;
                        self.core.tracked.inc();
                        blob
                    }
                },
            }),
            None => None,
        };

        let mut sealed = BTreeMap::new();
        for (s, app) in self.pending {
            sealed.insert(s, app.seal().await.map_err(Error::Runtime)?);
        }

        Ok(Sections {
            core: self.core,
            sealed,
            tail,
        })
    }
}

struct Tail<B: Blob> {
    section: u64,
    blob: Append<B>,
}

/// Steady-state section store. Historical sections are read-only [`Sealed`] handles; only the
/// tail can mutate.
pub(super) struct Sections<E: Storage + Metrics> {
    core: SectionsCore<E>,
    sealed: BTreeMap<u64, Sealed<E::Blob>>,
    tail: Option<Tail<E::Blob>>,
}

impl<E: Storage + Metrics> Sections<E> {
    /// Borrow the tail's [`Append`] if-and-only-if the tail is at `section`.
    fn tail_blob(&self, section: u64) -> Option<&Append<E::Blob>> {
        self.tail
            .as_ref()
            .and_then(|t| (t.section == section).then_some(&t.blob))
    }

    /// Oldest section number across `sealed` and the tail.
    pub(super) fn oldest_section(&self) -> Option<u64> {
        [
            self.sealed.first_key_value().map(|(&s, _)| s),
            self.tail.as_ref().map(|t| t.section),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Newest section number across `sealed` and the tail.
    pub(super) fn newest_section(&self) -> Option<u64> {
        [
            self.sealed.last_key_value().map(|(&s, _)| s),
            self.tail.as_ref().map(|t| t.section),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    /// All section numbers in ascending order.
    pub(super) fn sections(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .sealed
            .keys()
            .copied()
            .chain(self.tail.as_ref().map(|t| t.section))
            .collect();
        out.sort_unstable();
        out
    }

    /// Sections >= `start_section` in ascending order.
    pub(super) fn sections_from(&self, start_section: u64) -> Vec<u64> {
        self.sections()
            .into_iter()
            .filter(|&s| s >= start_section)
            .collect()
    }

    pub(super) async fn section_size(&self, section: u64) -> Result<u64, Error> {
        self.core.prune_guard(section)?;
        if let Some(s) = self.sealed.get(&section) {
            return Ok(s.size());
        }
        if let Some(blob) = self.tail_blob(section) {
            return Ok(blob.size().await);
        }
        Err(Error::SectionOutOfRange(section))
    }

    pub(super) async fn read_at(
        &self,
        section: u64,
        offset: u64,
        len: usize,
    ) -> Result<IoBufs, Error> {
        self.core.prune_guard(section)?;
        if let Some(s) = self.sealed.get(&section) {
            return s.read_at(offset, len).await.map_err(Error::Runtime);
        }
        if let Some(blob) = self.tail_blob(section) {
            return blob.read_at(offset, len).await.map_err(Error::Runtime);
        }
        Err(Error::SectionOutOfRange(section))
    }

    pub(super) async fn read_many_into(
        &self,
        section: u64,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: usize,
    ) -> Result<(), Error> {
        self.core.prune_guard(section)?;
        if let Some(s) = self.sealed.get(&section) {
            return s
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime);
        }
        if let Some(blob) = self.tail_blob(section) {
            return blob
                .read_many_into(buf, offsets, item_size)
                .await
                .map_err(Error::Runtime);
        }
        Err(Error::SectionOutOfRange(section))
    }

    /// Synchronous read attempt for a section. Returns `true` only if the full range was satisfied
    /// without I/O.
    pub(super) fn try_read_sync(&self, section: u64, offset: u64, buf: &mut [u8]) -> bool {
        if section < self.core.oldest_retained_section {
            return false;
        }
        if let Some(s) = self.sealed.get(&section) {
            return s.try_read_sync(offset, buf);
        }
        if let Some(blob) = self.tail_blob(section) {
            return blob.try_read_sync(offset, buf);
        }
        false
    }

    /// Try to read a section's size synchronously. Sealed sections always succeed (the size is in
    /// memory). For the tail, returns `None` if a writer currently holds the lock.
    pub(super) fn try_section_size(&self, section: u64) -> Option<u64> {
        if let Some(s) = self.sealed.get(&section) {
            return Some(s.size());
        }
        self.tail_blob(section).and_then(Append::try_size)
    }

    /// Append bytes to the tail.
    pub(super) async fn append_to_tail(&self, buf: &[u8]) -> Result<(), Error> {
        let tail = self
            .tail
            .as_ref()
            .ok_or_else(|| Error::Corruption("no tail installed".into()))?;
        tail.blob.append(buf).await.map_err(Error::Runtime)
    }

    /// Sync `section`. No-op unless `section` is the tail (sealed sections are already durable).
    pub(super) async fn sync_section(&self, section: u64) -> Result<(), Error> {
        if let Some(blob) = self.tail_blob(section) {
            self.core.synced.inc();
            blob.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Install a fresh empty tail at `section`. Errors if a tail is already installed.
    pub(super) async fn install_tail(&mut self, section: u64) -> Result<(), Error> {
        if self.tail.is_some() {
            return Err(Error::Corruption("tail already installed".into()));
        }
        let blob = self.core.open_append(section).await?;
        self.core.tracked.inc();
        self.tail = Some(Tail { section, blob });
        Ok(())
    }

    /// Seal the current tail and install a fresh empty tail at `next_section`.
    pub(super) async fn roll_tail(&mut self, next_section: u64) -> Result<(), Error> {
        let tail = self
            .tail
            .take()
            .ok_or_else(|| Error::Corruption("no tail to roll".into()))?;
        let prev_section = tail.section;
        let sealed = tail.blob.seal().await.map_err(Error::Runtime)?;
        self.sealed.insert(prev_section, sealed);

        let blob = self.core.open_append(next_section).await?;
        self.core.tracked.inc();
        self.tail = Some(Tail {
            section: next_section,
            blob,
        });
        Ok(())
    }

    /// Prune all sections strictly less than `min`. Removes sealed sections and, if the tail
    /// itself is below `min`, also removes the tail (leaving the store with no tail; callers that
    /// maintain a tail invariant must guard their prune calls).
    pub(super) async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        let mut pruned = false;
        while let Some((&section, _)) = self.sealed.first_key_value() {
            if section >= min {
                break;
            }
            let blob = self.sealed.remove(&section).unwrap();
            let size = blob.size();
            drop(blob);
            self.core.remove_blob(section).await?;
            debug!(section, size, "pruned blob");
            pruned = true;
            self.core.tracked.dec();
            self.core.pruned.inc();
        }
        if let Some(t) = &self.tail {
            if t.section < min {
                let tail = self.tail.take().unwrap();
                let tail_section = tail.section;
                let size = tail.blob.size().await;
                drop(tail.blob);
                self.core.remove_blob(tail_section).await?;
                debug!(section = tail_section, size, "pruned tail blob");
                pruned = true;
                self.core.tracked.dec();
                self.core.pruned.inc();
            }
        }
        if pruned {
            self.core.oldest_retained_section = min;
        }
        Ok(pruned)
    }

    /// Rewind: remove all sections strictly greater than `section`, then truncate `section` to
    /// `size` bytes.
    ///
    /// If `section` was sealed, it is promoted to the tail (the prior tail and any sealed sections
    /// above it are removed). Sections are removed newest-first to preserve a contiguous prefix
    /// in the event of a crash mid-rewind.
    pub(super) async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.core.prune_guard(section)?;

        // Remove tail if it is strictly greater than the target section.
        if let Some(t) = &self.tail {
            if t.section > section {
                let tail = self.tail.take().unwrap();
                let tail_section = tail.section;
                drop(tail.blob);
                self.core.remove_blob(tail_section).await?;
                self.core.tracked.dec();
                debug!(section = tail_section, "removed tail during rewind");
            }
        }

        // Remove sealed sections strictly greater than the target, newest-first. At `u64::MAX`
        // there can be no greater section, so the range is empty.
        let to_remove: Vec<u64> = match section.checked_add(1) {
            Some(start) => self.sealed.range(start..).rev().map(|(&s, _)| s).collect(),
            None => Vec::new(),
        };
        for s in to_remove {
            let blob = self.sealed.remove(&s).unwrap();
            drop(blob);
            self.core.remove_blob(s).await?;
            self.core.tracked.dec();
            debug!(section = s, "removed sealed during rewind");
        }

        // Truncate the target section.
        if let Some(t) = &self.tail {
            if t.section == section {
                let cur = t.blob.size().await;
                if size < cur {
                    t.blob.resize(size).await.map_err(Error::Runtime)?;
                    debug!(section, old_size = cur, new_size = size, "rewound tail");
                }
                return Ok(());
            }
        }

        // Tail wasn't at `section`. If a Sealed exists there, promote it to the new tail.
        if self.sealed.remove(&section).is_some() {
            debug_assert!(
                self.tail.is_none(),
                "rewind invariant: tail must be absent before promotion"
            );
            let blob = self.core.open_append(section).await?;
            let cur = blob.size().await;
            if size < cur {
                blob.resize(size).await.map_err(Error::Runtime)?;
                debug!(
                    section,
                    old_size = cur,
                    new_size = size,
                    "rewound promoted section as tail"
                );
            }
            self.tail = Some(Tail { section, blob });
        }

        // If the section didn't exist at all, the rewind target is silently skipped.
        Ok(())
    }

    /// Remove all sections and reset the store to empty (with no tail).
    pub(super) async fn clear(&mut self) -> Result<(), Error> {
        self.purge(false).await
    }

    /// Remove every blob and then the partition itself, consuming the store.
    pub(super) async fn destroy(mut self) -> Result<(), Error> {
        self.purge(true).await
    }

    /// Drop every blob, removing it from the partition. If `remove_partition` is `true`, also
    /// remove the partition itself.
    async fn purge(&mut self, remove_partition: bool) -> Result<(), Error> {
        for (section, blob) in take(&mut self.sealed) {
            let size = blob.size();
            drop(blob);
            debug!(section, size, "removed sealed blob");
            self.core.remove_blob(section).await?;
        }
        if let Some(tail) = self.tail.take() {
            let size = tail.blob.size().await;
            drop(tail.blob);
            debug!(section = tail.section, size, "removed tail blob");
            self.core.remove_blob(tail.section).await?;
        }
        let _ = self.core.tracked.try_set(0);
        self.core.oldest_retained_section = 0;

        if remove_partition {
            self.core.remove_partition().await?;
        }
        Ok(())
    }

    /// Build a [`Replay`] for `section`. Returns `(replay, blob_logical_size)`.
    pub(super) async fn replay_section(
        &self,
        section: u64,
        buffer: NonZeroUsize,
    ) -> Result<(Replay<E::Blob>, u64), Error> {
        self.core.prune_guard(section)?;
        if let Some(s) = self.sealed.get(&section) {
            let size = s.size();
            let r = s.replay(buffer).map_err(Error::Runtime)?;
            return Ok((r, size));
        }
        if let Some(blob) = self.tail_blob(section) {
            let size = blob.size().await;
            let r = blob.replay(buffer).await.map_err(Error::Runtime)?;
            return Ok((r, size));
        }
        Err(Error::SectionOutOfRange(section))
    }
}
