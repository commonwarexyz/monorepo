//! Typed section store for contiguous journals.
//!
//! Contiguous journals maintain a section lifecycle invariant: only the newest section (the tail)
//! ever receives new bytes; every historical section is full and immutable. This module encodes
//! that invariant in two types:
//!
//! - [`SectionsInit`] — opened during recovery, holds every section as a writable
//!   [`Append`]. The caller can inspect sizes and truncate trailing bytes from any section before
//!   transitioning to steady state.
//! - [`Sections`] — steady state. Historical sections are [`Sealed`] (no `RwLock`, cheap clones);
//!   at most one tail is [`Append`]. The type does not expose a method that would let the caller
//!   mutate a sealed section.
//!
//! Both types embed a private [`SectionsCore`] that owns shared plumbing (the runtime context, the
//! partition name, the page cache, metrics, and the in-process prune guard).
//!
//! # Durability
//!
//! Sealing a tail writes buffered bytes to the blob but does not fsync them.
//! [`Sections::sync_section`] dispatches to either [`Sealed::sync`] or [`Append::sync`] and is what
//! the journal's commit/sync loop calls to make a dirty (sealed or tail) section durable.
//! Journal-level dirty tracking must therefore continue to cover a section after
//! [`Sections::roll_tail`] seals it.

use crate::{
    journal::{contiguous::metrics::SectionsMetrics, Error},
    Context,
};
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::paged::{Append, CacheRef, Replay, Sealed},
    telemetry::metrics::GaugeExt as _,
    Blob, Error as RError, IoBufs,
};
use std::{collections::BTreeMap, num::NonZeroUsize};
use tracing::debug;

/// Configuration for [`SectionsInit`] / [`Sections`].
#[derive(Clone)]
pub(super) struct Config {
    /// Partition where blobs live. Each section is one blob named by its `u64` big-endian bytes.
    pub partition: String,
    /// The page cache used for reads of full pages.
    pub page_cache: CacheRef,
    /// The capacity, in bytes, of the tail's write buffer.
    pub write_buffer: NonZeroUsize,
}

/// Shared plumbing embedded in both [`SectionsInit`] and [`Sections`].
struct SectionsCore<E: Context> {
    context: E,
    partition: String,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,

    /// Sections pruned during the current process. Reads / syncs of any section below this return
    /// [`Error::AlreadyPrunedToSection`]. Not persisted across restarts.
    oldest_retained_section: u64,

    metrics: SectionsMetrics,
}

impl<E: Context> SectionsCore<E> {
    fn new(
        context: E,
        partition: String,
        page_cache: CacheRef,
        write_buffer: NonZeroUsize,
        tracked: usize,
    ) -> Self {
        let metrics = SectionsMetrics::new(&context);
        let _ = metrics.tracked.try_set(tracked);
        Self {
            context,
            partition,
            page_cache,
            write_buffer,
            oldest_retained_section: 0,
            metrics,
        }
    }

    /// Open `section`'s blob as a writable [`Append`]. Creates the blob if it does not exist.
    async fn open_append(&self, section: u64) -> Result<Append<E::Blob>, Error> {
        let name = section.to_be_bytes();
        let (blob, size) = self
            .context
            .open(&self.partition, &name)
            .await
            .map_err(Error::Runtime)?;
        Append::new(blob, size, self.write_buffer.get(), self.page_cache.clone())
            .await
            .map_err(Error::Runtime)
    }

    /// Remove `section`'s blob from storage.
    async fn remove_blob(&self, section: u64) -> Result<(), Error> {
        self.context
            .remove(&self.partition, Some(&section.to_be_bytes()))
            .await
            .map_err(Error::Runtime)
    }

    /// Remove the partition itself, treating "already missing" as success.
    async fn remove_partition(&self) -> Result<(), Error> {
        match self.context.remove(&self.partition, None).await {
            Ok(()) | Err(RError::PartitionMissing(_)) => Ok(()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    /// Rejects reads / syncs of sections that were pruned during the current process.
    const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }
}

/// Recovery-phase section store. Every section is held as a writable [`Append`] so the caller can
/// inspect sizes and apply truncations before transitioning to steady state.
pub(super) struct SectionsInit<E: Context> {
    core: SectionsCore<E>,
    pending: BTreeMap<u64, Append<E::Blob>>,
}

impl<E: Context> SectionsInit<E> {
    /// Scan the partition and open every existing blob as an [`Append`].
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
            let section = u64::from_be_bytes(bytes);
            let (blob, size) = context
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            debug!(section, blob = hex_name, size, "loaded section");
            let append = Append::new(blob, size, cfg.write_buffer.get(), cfg.page_cache.clone())
                .await
                .map_err(Error::Runtime)?;
            pending.insert(section, append);
        }

        let core = SectionsCore::new(
            context,
            cfg.partition,
            cfg.page_cache,
            cfg.write_buffer,
            pending.len(),
        );
        Ok(Self { core, pending })
    }

    /// All section numbers in ascending order.
    pub(super) fn sections(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }

    pub(super) fn oldest_section(&self) -> Option<u64> {
        self.pending.keys().next().copied()
    }

    pub(super) fn newest_section(&self) -> Option<u64> {
        self.pending.keys().next_back().copied()
    }

    /// Logical size, in bytes, of the given section. Returns 0 if the section does not exist.
    pub(super) async fn section_size(&self, section: u64) -> Result<u64, Error> {
        match self.pending.get(&section) {
            Some(blob) => Ok(blob.size().await),
            None => Ok(0),
        }
    }

    /// Shrink the given section to `size` bytes. No-op if the section is absent or already at or
    /// below the requested size. Shrinking is synced so init-time repairs are durable before
    /// [`Self::into_sections`] runs.
    pub(super) async fn truncate_section(&self, section: u64, size: u64) -> Result<(), Error> {
        let Some(blob) = self.pending.get(&section) else {
            return Ok(());
        };
        let current = blob.size().await;
        if size < current {
            blob.resize(size).await.map_err(Error::Runtime)?;
            blob.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Remove a single section (drop the handle, remove the blob).
    pub(super) async fn remove_section(&mut self, section: u64) -> Result<(), Error> {
        if let Some(blob) = self.pending.remove(&section) {
            drop(blob);
            self.core.remove_blob(section).await?;
            self.core.metrics.tracked.dec();
        }
        Ok(())
    }

    /// Transition to steady state. Every section strictly less than `tail_section` becomes sealed,
    /// and the section identified by `tail_section` becomes the tail. If no blob currently exists
    /// for that section, a fresh empty one is opened. If `tail_section` is `None`, the resulting
    /// store has no tail.
    ///
    /// Repair operations on [`SectionsInit`] sync their own mutations before this method runs.
    /// Reopening an unchanged section as [`Sealed`] must not force startup fsyncs for every
    /// historical blob.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corruption`] if any pending section is strictly greater than the requested
    /// `tail_section`. The caller must remove such sections first via [`Self::remove_section`].
    pub(super) async fn into_sections(
        self,
        tail_section: Option<u64>,
    ) -> Result<Sections<E>, Error> {
        if let (Some(tail), Some(newest)) = (tail_section, self.pending.keys().next_back().copied())
        {
            if newest > tail {
                return Err(Error::Corruption(format!(
                    "into_sections: sections > tail_section {tail} exist (newest={newest})"
                )));
            }
        }

        let mut sealed = BTreeMap::new();
        let mut tail_slot: Option<Tail<E::Blob>> = None;
        let core = self.core;
        for (section, blob) in self.pending {
            if Some(section) == tail_section {
                tail_slot = Some(Tail { section, blob });
            } else {
                let s = blob.seal().await.map_err(Error::Runtime)?;
                sealed.insert(section, s);
            }
        }
        // If the caller requested a tail that doesn't exist among the pending blobs, open it.
        if let Some(tail) = tail_section {
            if tail_slot.is_none() {
                let blob = core.open_append(tail).await?;
                core.metrics.tracked.inc();
                tail_slot = Some(Tail {
                    section: tail,
                    blob,
                });
            }
        }

        Ok(Sections {
            core,
            sealed,
            tail: tail_slot,
        })
    }

    /// Remove all existing blobs and install a fresh empty tail at `tail_section`. Used by
    /// `init_at_size`-style flows and crash-recovery for an interrupted clear.
    pub(super) async fn reset(mut self, tail_section: u64) -> Result<Sections<E>, Error> {
        let pending = std::mem::take(&mut self.pending);
        for (section, blob) in pending {
            drop(blob);
            self.core.remove_blob(section).await?;
        }
        let _ = self.core.metrics.tracked.try_set(0);
        self.core.oldest_retained_section = 0;

        let blob = self.core.open_append(tail_section).await?;
        self.core.metrics.tracked.inc();
        Ok(Sections {
            core: self.core,
            sealed: BTreeMap::new(),
            tail: Some(Tail {
                section: tail_section,
                blob,
            }),
        })
    }
}

/// The writable tail. Holds the section index and the live [`Append`] handle.
struct Tail<B: Blob> {
    section: u64,
    blob: Append<B>,
}

/// Steady-state section store. Historical sections are immutable [`Sealed`] views; at most one
/// section is the writable [`Append`] tail. There is no API that mutates a sealed section.
pub(super) struct Sections<E: Context> {
    core: SectionsCore<E>,
    sealed: BTreeMap<u64, Sealed<E::Blob>>,
    tail: Option<Tail<E::Blob>>,
}

impl<E: Context> Sections<E> {
    /// Oldest section in the store (sealed or tail).
    pub(super) fn oldest_section(&self) -> Option<u64> {
        let sealed_oldest = self.sealed.keys().next().copied();
        let tail_section = self.tail.as_ref().map(|t| t.section);
        match (sealed_oldest, tail_section) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// Newest section in the store (sealed or tail).
    pub(super) fn newest_section(&self) -> Option<u64> {
        let sealed_newest = self.sealed.keys().next_back().copied();
        let tail_section = self.tail.as_ref().map(|t| t.section);
        match (sealed_newest, tail_section) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// Section index of the tail, if a tail exists.
    #[allow(dead_code)]
    pub(super) fn tail_section(&self) -> Option<u64> {
        self.tail.as_ref().map(|t| t.section)
    }

    /// Returns `true` if no sections exist.
    #[allow(dead_code)]
    pub(super) fn is_empty(&self) -> bool {
        self.sealed.is_empty() && self.tail.is_none()
    }

    /// Logical size, in bytes, of the given section. Returns 0 if the section does not exist.
    pub(super) async fn section_size(&self, section: u64) -> Result<u64, Error> {
        self.core.prune_guard(section)?;
        if let Some(s) = self.sealed.get(&section) {
            return Ok(s.size());
        }
        if let Some(t) = &self.tail {
            if t.section == section {
                return Ok(t.blob.size().await);
            }
        }
        // Missing unpruned sections are reported as zero-length so recovery code can distinguish an
        // empty tail from an out-of-range read.
        Ok(0)
    }

    /// Non-blocking variant of [`Self::section_size`]. Returns `None` for any section other than
    /// the tail when it cannot be observed without waiting.
    #[allow(dead_code)]
    pub(super) fn try_section_size(&self, section: u64) -> Option<u64> {
        if section < self.core.oldest_retained_section {
            return None;
        }
        if let Some(s) = self.sealed.get(&section) {
            return Some(s.size());
        }
        if let Some(t) = &self.tail {
            if t.section == section {
                return t.blob.try_size();
            }
        }
        // Mirror `section_size`: absent-but-unpruned sections behave like empty sections for sizing.
        Some(0)
    }

    /// Read exactly `len` bytes at `(section, offset)`.
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
        if let Some(t) = &self.tail {
            if t.section == section {
                return t.blob.read_at(offset, len).await.map_err(Error::Runtime);
            }
        }
        Err(Error::SectionOutOfRange(section))
    }

    /// Read multiple disjoint, sorted, equally-sized items from one section into a contiguous
    /// caller buffer.
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
        if let Some(t) = &self.tail {
            if t.section == section {
                return t
                    .blob
                    .read_many_into(buf, offsets, item_size)
                    .await
                    .map_err(Error::Runtime);
            }
        }
        Err(Error::SectionOutOfRange(section))
    }

    /// Synchronous read from page cache / in-memory partial page. Returns `false` if any bytes
    /// would require I/O.
    pub(super) fn try_read_sync(&self, section: u64, offset: u64, buf: &mut [u8]) -> bool {
        if self.core.prune_guard(section).is_err() {
            return false;
        }
        if let Some(s) = self.sealed.get(&section) {
            return s.try_read_sync(offset, buf);
        }
        if let Some(t) = &self.tail {
            if t.section == section {
                return t.blob.try_read_sync(offset, buf);
            }
        }
        false
    }

    /// Return a [`Replay`] of the given section's logical bytes, plus the section's size.
    pub(super) async fn replay_section(
        &self,
        section: u64,
        buffer: NonZeroUsize,
    ) -> Result<(Replay<E::Blob>, u64), Error> {
        self.core.prune_guard(section)?;
        if let Some(s) = self.sealed.get(&section) {
            let replay = s.replay(buffer).map_err(Error::Runtime)?;
            return Ok((replay, s.size()));
        }
        if let Some(t) = &self.tail {
            if t.section == section {
                let r = t.blob.replay(buffer).await.map_err(Error::Runtime)?;
                let size = t.blob.size().await;
                return Ok((r, size));
            }
        }
        Err(Error::SectionOutOfRange(section))
    }

    /// Append `buf` to the tail. Requires a tail to exist.
    pub(super) async fn append_to_tail(&self, buf: &[u8]) -> Result<(), Error> {
        let tail = self
            .tail
            .as_ref()
            .expect("append_to_tail requires an installed tail");
        tail.blob.append(buf).await.map_err(Error::Runtime)
    }

    /// Make the given section durable. Dispatches to [`Sealed::sync`] for a historical section or
    /// [`Append::sync`] for the tail. No-op (and no metric bump) if the section does not exist.
    pub(super) async fn sync_section(&self, section: u64) -> Result<(), Error> {
        self.core.prune_guard(section)?;
        let synced = if let Some(s) = self.sealed.get(&section) {
            s.sync().await.map_err(Error::Runtime)?;
            true
        } else if let Some(t) = &self.tail {
            if t.section == section {
                t.blob.sync().await.map_err(Error::Runtime)?;
                true
            } else {
                false
            }
        } else {
            false
        };
        if synced {
            self.core.metrics.synced.inc();
        }
        Ok(())
    }

    /// Open a fresh empty tail at `section`. Panics if a tail already exists.
    pub(super) async fn install_tail(&mut self, section: u64) -> Result<(), Error> {
        assert!(self.tail.is_none(), "install_tail requires no current tail");
        let blob = self.core.open_append(section).await?;
        self.core.metrics.tracked.inc();
        self.tail = Some(Tail { section, blob });
        Ok(())
    }

    /// Seal the current tail (no fsync) and open `next_section` as the new tail. Panics if no
    /// tail exists.
    pub(super) async fn roll_tail(&mut self, next_section: u64) -> Result<(), Error> {
        let old = self
            .tail
            .take()
            .expect("roll_tail requires an installed tail");
        let s = old.blob.seal().await.map_err(Error::Runtime)?;
        self.sealed.insert(old.section, s);
        let blob = self.core.open_append(next_section).await?;
        self.core.metrics.tracked.inc();
        self.tail = Some(Tail {
            section: next_section,
            blob,
        });
        Ok(())
    }

    /// Prune all sections strictly less than `min`. Returns `true` if any section was removed.
    ///
    /// If the tail's section is below `min`, the tail is removed too — callers that maintain a
    /// tail invariant must re-install one via [`Self::install_tail`].
    pub(super) async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        let mut pruned = false;
        // Drop sealed sections in ascending order.
        while let Some((&section, _)) = self.sealed.first_key_value() {
            if section >= min {
                break;
            }
            let s = self.sealed.remove(&section).unwrap();
            drop(s);
            self.core.remove_blob(section).await?;
            self.core.metrics.tracked.dec();
            self.core.metrics.pruned.inc();
            debug!(section, "pruned sealed section");
            pruned = true;
        }
        // If the tail is below min, drop it too.
        if let Some(tail) = self.tail.as_ref() {
            if tail.section < min {
                let old = self.tail.take().unwrap();
                drop(old.blob);
                self.core.remove_blob(old.section).await?;
                self.core.metrics.tracked.dec();
                self.core.metrics.pruned.inc();
                debug!(section = old.section, "pruned tail section");
                pruned = true;
            }
        }
        if pruned {
            self.core.oldest_retained_section = min;
        }
        Ok(pruned)
    }

    /// Rewind to `(section, size)`. Removes every section strictly greater than `section`
    /// newest-first, ensures `section` is the tail (opening it if it is missing), and finally
    /// resizes that tail to `size`.
    ///
    /// # Crash safety
    ///
    /// Sections are removed newest-first; a crash mid-rewind leaves a contiguous prefix. The
    /// pre-demote sync runs before any destructive work — a sync failure leaves the in-memory
    /// state matching the pre-rewind on-disk state.
    pub(super) async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.core.prune_guard(section)?;

        // Step 1: make the target durable before destructive work. If demotion or newer-section
        // removal later fails, recovery can still retain the target section.
        let target_is_sealed = if let Some(s) = self.sealed.get(&section) {
            s.sync().await.map_err(Error::Runtime)?;
            self.core.metrics.synced.inc();
            true
        } else {
            false
        };

        // Step 2: collect sections strictly newer than the target, newest-first. Drop the tail if
        // it's above target.
        if let Some(tail) = self.tail.as_ref() {
            if tail.section > section {
                let old = self.tail.take().unwrap();
                drop(old.blob);
                self.core.remove_blob(old.section).await?;
                self.core.metrics.tracked.dec();
            }
        }
        let to_remove: Vec<u64> = match section.checked_add(1) {
            Some(after_section) => self
                .sealed
                .range(after_section..)
                .rev()
                .map(|(&s, _)| s)
                .collect(),
            None => Vec::new(),
        };
        for s in to_remove {
            let sealed = self.sealed.remove(&s).unwrap();
            drop(sealed);
            self.core.remove_blob(s).await?;
            self.core.metrics.tracked.dec();
            debug!(section = s, "removed section during rewind");
        }

        // Step 3: ensure the target is the tail. If currently sealed, demote. If it was a missing
        // gap that became exposed by dropping the newer tail, open an empty tail there.
        if target_is_sealed {
            // Remove the sealed handle to release its Arc + page-cache id before reopening.
            // (Both Append::new and the prior Sealed reference the same Blob handle, but only one
            // should be live at a time per the contiguous invariant.)
            let _ = self.sealed.remove(&section);
            self.core.metrics.tracked.dec();
            let blob = self.core.open_append(section).await?;
            self.core.metrics.tracked.inc();
            self.tail = Some(Tail { section, blob });
        }
        if self.tail.is_none() {
            let blob = self.core.open_append(section).await?;
            self.core.metrics.tracked.inc();
            self.tail = Some(Tail { section, blob });
        }

        // Step 4: resize the tail down to `size` (no-op if already shorter).
        if let Some(tail) = self.tail.as_ref() {
            if tail.section == section {
                let current = tail.blob.size().await;
                if size < current {
                    tail.blob.resize(size).await.map_err(Error::Runtime)?;
                }
            }
        }

        Ok(())
    }

    /// Drop every section (sealed + tail) and remove all blobs. The store ends up empty.
    pub(super) async fn clear(&mut self) -> Result<(), Error> {
        if let Some(old) = self.tail.take() {
            drop(old.blob);
            self.core.remove_blob(old.section).await?;
        }
        let sealed = std::mem::take(&mut self.sealed);
        for (section, s) in sealed {
            drop(s);
            self.core.remove_blob(section).await?;
        }
        let _ = self.core.metrics.tracked.try_set(0);
        self.core.oldest_retained_section = 0;
        Ok(())
    }

    /// Drop every section, remove all blobs AND the partition. Consumes `self`.
    pub(super) async fn destroy(mut self) -> Result<(), Error> {
        self.clear().await?;
        self.core.remove_partition().await
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
    #[case::missing_section_is_a_noop(1, 2, 0)]
    #[case::existing_section_can_be_shrunk(0, 2, 2)]
    #[case::same_size_is_a_noop(0, 5, 5)]
    #[case::larger_size_is_a_noop(0, 8, 5)]
    fn test_sections_init_truncate_section(
        #[case] section: u64,
        #[case] truncate_to: u64,
        #[case] expected_size: u64,
    ) {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-truncate-init");

            {
                let init = SectionsInit::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let sections = init.into_sections(Some(0)).await.unwrap();
                sections.append_to_tail(b"hello").await.unwrap();
                sections.sync_section(0).await.unwrap();
            }

            let init = SectionsInit::open(context.child("repair"), cfg.clone())
                .await
                .unwrap();

            // Init-time truncation is a repair tool: it only shrinks existing sections and is a
            // no-op for missing sections or requests at/above the current size.
            init.truncate_section(section, truncate_to).await.unwrap();
            drop(init);

            let reopened = SectionsInit::open(context.child("verify"), cfg)
                .await
                .unwrap();
            assert_eq!(reopened.section_size(section).await.unwrap(), expected_size);
        });
    }

    /// Empty partition → SectionsInit with no sections → Sections with just a tail.
    #[test_traced]
    fn test_sections_init_empty_then_install_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-empty");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            assert!(init.sections().is_empty());
            let sections = init.into_sections(Some(0)).await.unwrap();
            assert_eq!(sections.tail_section(), Some(0));
            assert!(sections.sealed.is_empty());
        });
    }

    /// `roll_tail` seals the old tail and opens the next one without making the old tail durable.
    ///
    /// We assert this indirectly: after roll_tail the in-memory state contains a sealed section
    /// AND a new tail, but Append::seal's contract guarantees no fsync. The runtime-level
    /// `test_seal_no_fsync` (in `sealed.rs`) provides the direct proof.
    #[test_traced]
    fn test_sections_roll_tail_seals_old_into_sealed_map() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-roll");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            let mut sections = init.into_sections(Some(0)).await.unwrap();

            // Append some data into section 0.
            sections.append_to_tail(b"hello").await.unwrap();
            // Roll to section 1.
            sections.roll_tail(1).await.unwrap();
            assert_eq!(sections.tail_section(), Some(1));
            assert!(sections.sealed.contains_key(&0));

            // Sealed section 0 must be readable.
            let bufs = sections.read_at(0, 0, 5).await.unwrap();
            assert_eq!(bufs.coalesce().as_ref(), b"hello");
        });
    }

    /// sync_section dispatches to the sealed handle (after rollover) and to the tail before
    /// rollover.
    #[test_traced]
    fn test_sections_sync_section_dispatches_sealed_and_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-sync");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            let mut sections = init.into_sections(Some(0)).await.unwrap();

            sections.append_to_tail(b"a").await.unwrap();
            // Sync the tail.
            sections.sync_section(0).await.unwrap();
            // Roll then sync the now-sealed section 0.
            sections.roll_tail(1).await.unwrap();
            sections.sync_section(0).await.unwrap();
            // sync_section on a missing section is a no-op.
            sections.sync_section(99).await.unwrap();
        });
    }

    /// Rewinding into a sealed section promotes it back to the tail and removes newer sections
    /// newest-first.
    #[test_traced]
    fn test_sections_rewind_promotes_sealed_to_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-rewind");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            let mut sections = init.into_sections(Some(0)).await.unwrap();

            // Build sections 0, 1, 2 with data.
            sections.append_to_tail(b"sec0").await.unwrap();
            sections.roll_tail(1).await.unwrap();
            sections.append_to_tail(b"sec1").await.unwrap();
            sections.roll_tail(2).await.unwrap();
            sections.append_to_tail(b"sec2").await.unwrap();
            assert_eq!(sections.tail_section(), Some(2));
            assert!(sections.sealed.contains_key(&0));
            assert!(sections.sealed.contains_key(&1));

            // Rewind into sealed section 0.
            sections.rewind(0, 2).await.unwrap();
            assert_eq!(sections.tail_section(), Some(0));
            assert!(sections.sealed.is_empty());
            assert_eq!(sections.section_size(0).await.unwrap(), 2);

            // Bytes are preserved.
            let bufs = sections.read_at(0, 0, 2).await.unwrap();
            assert_eq!(bufs.coalesce().as_ref(), b"se");
        });
    }

    /// Rewinding to a missing target opens that section as an empty tail after newer sections are
    /// removed.
    #[test_traced]
    fn test_sections_rewind_installs_missing_target_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-rewind-missing");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            let mut sections = init.into_sections(Some(0)).await.unwrap();

            sections.append_to_tail(b"sec0").await.unwrap();
            sections.roll_tail(2).await.unwrap();
            sections.append_to_tail(b"sec2").await.unwrap();

            sections.rewind(1, 0).await.unwrap();
            assert_eq!(sections.tail_section(), Some(1));
            assert!(sections.sealed.contains_key(&0));
            assert!(!sections.sealed.contains_key(&2));
            assert_eq!(sections.section_size(1).await.unwrap(), 0);
        });
    }

    /// Rewinding to `u64::MAX` has no newer sections to scan, so the removal range is empty.
    #[test_traced]
    fn test_sections_rewind_max_section_does_not_overflow() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-rewind-max");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            let mut sections = init.into_sections(None).await.unwrap();

            sections.rewind(u64::MAX, 0).await.unwrap();
            assert_eq!(sections.tail_section(), Some(u64::MAX));
            assert_eq!(sections.section_size(u64::MAX).await.unwrap(), 0);
        });
    }

    /// Prune drops sections below `min` and updates the in-process retained boundary.
    #[test_traced]
    fn test_sections_prune_drops_below_min() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-prune");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            let mut sections = init.into_sections(Some(0)).await.unwrap();

            sections.append_to_tail(b"x").await.unwrap();
            sections.roll_tail(1).await.unwrap();
            sections.append_to_tail(b"y").await.unwrap();
            sections.roll_tail(2).await.unwrap();

            assert!(sections.prune(2).await.unwrap());
            assert_eq!(sections.tail_section(), Some(2));
            assert!(sections.sealed.is_empty());

            // Read of pruned section returns AlreadyPrunedToSection.
            let err = sections.section_size(0).await.unwrap_err();
            assert!(matches!(err, Error::AlreadyPrunedToSection(2)));
        });
    }

    /// reset clears all sections and installs a fresh tail.
    #[test_traced]
    fn test_sections_init_reset_clears_and_installs_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reset");
            // First create some sections.
            {
                let init = SectionsInit::open(context.child("a"), cfg.clone())
                    .await
                    .unwrap();
                let mut sections = init.into_sections(Some(0)).await.unwrap();
                sections.append_to_tail(b"x").await.unwrap();
                sections.roll_tail(1).await.unwrap();
                sections.append_to_tail(b"y").await.unwrap();
                sections.sync_section(1).await.unwrap();
            }

            // Reopen and reset to a different tail.
            let init = SectionsInit::open(context.child("b"), cfg).await.unwrap();
            assert_eq!(init.sections(), vec![0, 1]);
            let sections = init.reset(5).await.unwrap();
            assert_eq!(sections.tail_section(), Some(5));
            assert!(sections.sealed.is_empty());
            assert_eq!(sections.section_size(5).await.unwrap(), 0);
        });
    }

    /// destroy removes blobs AND the partition.
    #[test_traced]
    fn test_sections_destroy_removes_partition() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-destroy");
            // Create state.
            {
                let init = SectionsInit::open(context.child("a"), cfg.clone())
                    .await
                    .unwrap();
                let sections = init.into_sections(Some(0)).await.unwrap();
                sections.append_to_tail(b"x").await.unwrap();
                sections.sync_section(0).await.unwrap();
                sections.destroy().await.unwrap();
            }

            // Reopen — partition is gone, no sections.
            let init = SectionsInit::open(context.child("b"), cfg).await.unwrap();
            assert!(init.sections().is_empty());
        });
    }

    /// into_sections must reject a tail_section that is not the newest.
    #[test_traced]
    fn test_sections_into_sections_rejects_newer_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reject");
            // Create sections 0, 1, 2.
            {
                let init = SectionsInit::open(context.child("a"), cfg.clone())
                    .await
                    .unwrap();
                let mut sections = init.into_sections(Some(0)).await.unwrap();
                sections.append_to_tail(b"x").await.unwrap();
                sections.roll_tail(1).await.unwrap();
                sections.append_to_tail(b"y").await.unwrap();
                sections.roll_tail(2).await.unwrap();
                sections.sync_section(2).await.unwrap();
            }

            // Try to claim section 1 is the tail with section 2 still present.
            let init = SectionsInit::open(context.child("b"), cfg).await.unwrap();
            assert_eq!(init.sections(), vec![0, 1, 2]);
            let result = init.into_sections(Some(1)).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }
}
