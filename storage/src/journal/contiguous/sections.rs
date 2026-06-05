//! Recovery-phase section store for contiguous journals.
//!
//! Only the newest section (the tail) ever receives new bytes; every other section is
//! immutable. [`SectionsInit`] opens every section as a writable [`AppendWriter`] so recovery
//! can inspect sizes and truncate trailing bytes, then [`SectionsInit::into_sections`] seals
//! all sections below the tail and returns [`Sections`]: a dense, ascending run of [`Sealed`]
//! handles plus the writable [`Tail`].
//!
//! Sealing flushes buffered bytes without fsync. A section stays dirty after sealing until the
//! journal's commit/sync makes it durable via [`Sealed::sync`].

use crate::{
    journal::{contiguous::metrics::SectionsMetrics, Error},
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

/// Configuration for [`SectionsInit`].
#[derive(Clone)]
pub(super) struct Config {
    /// Partition where blobs live. Each section is one blob named by its `u64` big-endian bytes.
    pub partition: String,
    /// The page cache used for reads of full pages.
    pub page_cache: CacheRef,
    /// The capacity, in bytes, of the tail's write buffer.
    pub write_buffer: NonZeroUsize,
}

/// Opens and removes section blobs.
pub(super) struct SectionIo<E: Context> {
    context: E,
    partition: String,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,
    pub(super) metrics: SectionsMetrics,
}

impl<E: Context> SectionIo<E> {
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
            metrics,
        }
    }

    /// Open `section`'s blob as a writable [`AppendWriter`]. Creates the blob if it does not
    /// exist.
    pub(super) async fn open_append(&self, section: u64) -> Result<AppendWriter<E::Blob>, Error> {
        let name = section.to_be_bytes();
        let (blob, size) = self
            .context
            .open(&self.partition, &name)
            .await
            .map_err(Error::Runtime)?;
        AppendWriter::new(blob, size, self.write_buffer.get(), self.page_cache.clone())
            .await
            .map_err(Error::Runtime)
    }

    /// Remove `section`'s blob from storage.
    pub(super) async fn remove_blob(&self, section: u64) -> Result<(), Error> {
        self.context
            .remove(&self.partition, Some(&section.to_be_bytes()))
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

/// The writable tail section.
pub(super) struct Tail<B: Blob> {
    pub(super) section: u64,
    pub(super) writer: AppendWriter<B>,
}

/// Output of [`SectionsInit::into_sections`]: `sealed[i]` is section `base_section + i`, and
/// the tail is section `base_section + sealed.len()`.
pub(super) struct Sections<E: Context> {
    pub(super) io: SectionIo<E>,
    pub(super) base_section: u64,
    pub(super) sealed: Vec<Sealed<E::Blob>>,
    pub(super) tail: Tail<E::Blob>,
}

/// Recovery-phase store holding every section as a writable [`AppendWriter`].
pub(super) struct SectionsInit<E: Context> {
    io: SectionIo<E>,
    pending: BTreeMap<u64, AppendWriter<E::Blob>>,
}

impl<E: Context> SectionsInit<E> {
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
            let section = u64::from_be_bytes(bytes);
            let (blob, size) = context
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            debug!(section, blob = hex_name, size, "loaded section");
            let append =
                AppendWriter::new(blob, size, cfg.write_buffer.get(), cfg.page_cache.clone())
                    .await
                    .map_err(Error::Runtime)?;
            pending.insert(section, append);
        }

        let io = SectionIo::new(
            context,
            cfg.partition,
            cfg.page_cache,
            cfg.write_buffer,
            pending.len(),
        );
        Ok(Self { io, pending })
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

    /// Shrink the given section to `size` bytes and sync it. No-op if the section is absent or
    /// already at or below `size`.
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

    /// Drop the section's handle and remove its blob.
    pub(super) async fn remove_section(&mut self, section: u64) -> Result<(), Error> {
        if let Some(blob) = self.pending.remove(&section) {
            drop(blob);
            self.io.remove_blob(section).await?;
            self.io.metrics.tracked.dec();
        }
        Ok(())
    }

    /// Seal every section below `tail_section` and return the resulting [`Sections`]. Opens a
    /// fresh tail blob if none exists at `tail_section`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corruption`] if a pending section is greater than `tail_section` (remove
    /// it first via [`Self::remove_section`]) or if the retained sections are not dense.
    pub(super) async fn into_sections(self, tail_section: u64) -> Result<Sections<E>, Error> {
        if let Some(newest) = self.pending.keys().next_back().copied() {
            if newest > tail_section {
                return Err(Error::Corruption(format!(
                    "into_sections: sections > tail_section {tail_section} exist (newest={newest})"
                )));
            }
        }

        let io = self.io;
        let mut sealed = Vec::with_capacity(self.pending.len());
        let mut tail_slot: Option<Tail<E::Blob>> = None;
        let mut expected = self.pending.keys().next().copied();
        for (section, blob) in self.pending {
            // Positions map to sections by arithmetic, so retained sections must be dense.
            if expected != Some(section) {
                return Err(Error::Corruption(format!(
                    "into_sections: retained sections must be dense (expected {expected:?}, got \
                     {section})"
                )));
            }
            expected = section.checked_add(1);
            if section == tail_section {
                tail_slot = Some(Tail {
                    section,
                    writer: blob,
                });
            } else {
                let s = blob.seal().await.map_err(Error::Runtime)?;
                sealed.push(s);
            }
        }
        if let Some(expected) = expected {
            if tail_slot.is_none() && expected != tail_section {
                return Err(Error::Corruption(format!(
                    "into_sections: sealed sections end at {expected} but tail is {tail_section}"
                )));
            }
        }
        // If the caller requested a tail that doesn't exist among the pending blobs, open it.
        let tail = match tail_slot {
            Some(tail) => tail,
            None => {
                let writer = io.open_append(tail_section).await?;
                io.metrics.tracked.inc();
                Tail {
                    section: tail_section,
                    writer,
                }
            }
        };

        let base_section = tail_section - sealed.len() as u64;
        Ok(Sections {
            io,
            base_section,
            sealed,
            tail,
        })
    }

    /// Remove all existing blobs and install a fresh empty tail at `tail_section`. Used by
    /// `init_at_size`-style flows and crash-recovery for an interrupted clear.
    pub(super) async fn reset(mut self, tail_section: u64) -> Result<Sections<E>, Error> {
        let pending = std::mem::take(&mut self.pending);
        for (section, blob) in pending {
            drop(blob);
            self.io.remove_blob(section).await?;
        }
        let _ = self.io.metrics.tracked.try_set(0);

        let writer = self.io.open_append(tail_section).await?;
        self.io.metrics.tracked.inc();
        Ok(Sections {
            io: self.io,
            base_section: tail_section,
            sealed: Vec::new(),
            tail: Tail {
                section: tail_section,
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
                let sections = init.into_sections(0).await.unwrap();
                sections.tail.writer.append(b"hello").await.unwrap();
                sections.tail.writer.sync().await.unwrap();
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

    /// Empty partition -> SectionsInit with no sections -> Sections with just a fresh tail.
    #[test_traced]
    fn test_sections_init_empty_then_install_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-empty");
            let init = SectionsInit::open(context, cfg).await.unwrap();
            assert!(init.sections().is_empty());
            let sections = init.into_sections(0).await.unwrap();
            assert_eq!(sections.tail.section, 0);
            assert_eq!(sections.base_section, 0);
            assert!(sections.sealed.is_empty());
        });
    }

    /// Sections strictly below the tail are sealed, in dense ascending order, and stay readable.
    #[test_traced]
    fn test_sections_into_sections_seals_history() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-seal-history");
            {
                let init = SectionsInit::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let sections = init.into_sections(0).await.unwrap();
                sections.tail.writer.append(b"hello").await.unwrap();
                sections.tail.writer.sync().await.unwrap();
                let section1 = sections.io.open_append(1).await.unwrap();
                section1.append(b"world").await.unwrap();
                section1.sync().await.unwrap();
            }

            let init = SectionsInit::open(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(init.sections(), vec![0, 1]);
            let sections = init.into_sections(1).await.unwrap();
            assert_eq!(sections.base_section, 0);
            assert_eq!(sections.sealed.len(), 1);
            assert_eq!(sections.tail.section, 1);

            // The sealed historical section is readable through its handle.
            let bufs = sections.sealed[0].read_at(0, 5).await.unwrap();
            assert_eq!(bufs.coalesce().as_ref(), b"hello");
            // The tail is readable through its writer.
            let bufs = sections.tail.writer.read_at(0, 5).await.unwrap();
            assert_eq!(bufs.coalesce().as_ref(), b"world");
        });
    }

    /// `reset` removes every blob and installs a fresh empty tail.
    #[test_traced]
    fn test_sections_init_reset_clears_and_installs_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reset");
            {
                let init = SectionsInit::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let sections = init.into_sections(0).await.unwrap();
                sections.tail.writer.append(b"junk").await.unwrap();
                sections.tail.writer.sync().await.unwrap();
            }

            let init = SectionsInit::open(context.child("reset"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(init.sections(), vec![0]);
            let sections = init.reset(7).await.unwrap();
            assert!(sections.sealed.is_empty());
            assert_eq!(sections.base_section, 7);
            assert_eq!(sections.tail.section, 7);
            assert_eq!(sections.tail.writer.size().await, 0);

            // Only the fresh tail blob remains on disk.
            drop(sections);
            let reopened = SectionsInit::open(context.child("verify"), cfg)
                .await
                .unwrap();
            assert_eq!(reopened.sections(), vec![7]);
        });
    }

    /// `into_sections` rejects pending sections newer than the requested tail.
    #[test_traced]
    fn test_sections_into_sections_rejects_newer_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reject-newer");
            {
                let init = SectionsInit::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let sections = init.into_sections(0).await.unwrap();
                sections.tail.writer.append(b"a").await.unwrap();
                sections.tail.writer.sync().await.unwrap();
                let newer = sections.io.open_append(3).await.unwrap();
                newer.append(b"b").await.unwrap();
                newer.sync().await.unwrap();
            }

            let init = SectionsInit::open(context.child("reopen"), cfg)
                .await
                .unwrap();
            match init.into_sections(0).await {
                Err(Error::Corruption(_)) => {}
                Err(err) => panic!("expected corruption, got: {err:?}"),
                Ok(_) => panic!("expected corruption, got parts"),
            }
        });
    }

    /// `into_sections` rejects a non-dense run of retained sections.
    #[test_traced]
    fn test_sections_into_sections_rejects_gap() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cfg = test_cfg(&context, "p-reject-gap");
            {
                let init = SectionsInit::open(context.child("create"), cfg.clone())
                    .await
                    .unwrap();
                let sections = init.into_sections(0).await.unwrap();
                sections.tail.writer.append(b"a").await.unwrap();
                sections.tail.writer.sync().await.unwrap();
                // Create section 2, leaving a gap at section 1.
                let newer = sections.io.open_append(2).await.unwrap();
                newer.append(b"b").await.unwrap();
                newer.sync().await.unwrap();
            }

            let init = SectionsInit::open(context.child("reopen"), cfg)
                .await
                .unwrap();
            match init.into_sections(2).await {
                Err(Error::Corruption(_)) => {}
                Err(err) => panic!("expected corruption, got: {err:?}"),
                Ok(_) => panic!("expected corruption, got parts"),
            }
        });
    }
}
