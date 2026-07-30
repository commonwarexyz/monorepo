//! Segmented journal for oversized values.
//!
//! This module combines [super::fixed::Journal] with [super::glob::Glob] to handle
//! entries that reference variable-length "oversized" values. It provides coordinated
//! operations and built-in crash recovery.
//!
//! # Architecture
//!
//! ```text
//! +-------------------+     +-------------------+
//! | Fixed Journal     |     | Glob (Values)     |
//! | (Index Entries)   |     |                   |
//! +-------------------+     +-------------------+
//! | entry_0           | --> | value_0           |
//! | entry_1           | --> | value_1           |
//! | ...               |     | ...               |
//! +-------------------+     +-------------------+
//! ```
//!
//! Each index entry contains `(value_offset, value_size)` pointing to its value in glob.
//!
//! # Crash Recovery
//!
//! On unclean shutdown, the index journal and glob may have different lengths:
//! - Index entry pointing to non-existent glob data (dangerous)
//! - Glob value without index entry (orphan - acceptable but cleaned up)
//! - Glob sections without corresponding index sections (orphan sections - removed)
//!
//! Both constructors are driven by a checkpoint the caller published. The journal keeps no
//! recovery metadata of its own, so a caller that needs its acknowledged data protected must
//! record what it acknowledged (see [crate::archive::prunable] and [crate::freezer::Freezer]).
//!
//! [Oversized::init] takes the durable index size of each section. A caller raises a section's
//! size only once a joint index+value sync covering it has completed, so everything below it must
//! survive. Before [Oversized::init] returns its [Replay], recovery:
//! 1. Rejects a durable size beyond the retained index and verifies its boundary entry and value
//! 2. Scans index/value pairs forward from that floor, requiring contiguous value offsets and
//!    valid value checksums
//! 3. Truncates both journals at the first invalid pair and removes orphan value sections
//!
//! This catches an interior value hole even if later index pages and values survived the same
//! interrupted flush. Fixed-index replay treats a checksum or layout failure it detects below a
//! durable size as corruption rather than repairable crash debris. A section the checkpoint says
//! nothing about is scanned from zero, so a journal written before its caller published any
//! checkpoint still recovers. Recovery does not authenticate or fully revalidate the durable
//! prefix: value checksums strictly below a floor remain lazy and are checked by `get_value()`.
//!
//! [Oversized::init_from_checkpoint] serves a caller whose committed record is a fixed-size
//! boundary rather than a per-section map. [crate::freezer::Freezer] is one: its checkpoint is a
//! single record stored inside another store's metadata and its sections are never pruned, so it
//! cannot name every section's size. The boundary carries the stronger claim that nothing above it
//! was ever committed, which its table relies on: a surviving later section would be appended over
//! once the restored journal rolls over.
//!
//! That constructor therefore restores exactly the state the boundary describes instead of
//! scanning for one: sections below the checkpoint are verified complete (their last entry must
//! end exactly at the glob's size, without reading values) and adopted unchanged, the checkpointed
//! section is durably truncated to the committed size, and everything after it is removed.
//! Interior entries and value checksums below the checkpoint are verified lazily on access.
//!
//! [Oversized::prune], [Oversized::rewind], and [Oversized::rewind_section] move data backward, so
//! the caller must durably lower the affected checkpoint entries before calling them. Recovery
//! truncations are made durable before returning, so neither a dropped index entry nor stale value
//! bytes can survive a crash once later appends may reuse the freed offsets.

use super::{
    fixed::{Config as FixedConfig, Journal as FixedJournal, Replay as FixedReplay},
    glob::{Config as GlobConfig, Glob},
    manager::PreparedRewind,
};
use crate::journal::Error;
use commonware_codec::{Codec, CodecFixed, CodecShared};
use commonware_runtime::{
    BatchOperation, BufferPooler, Error as RError, Handle, Metrics, RemoveTarget, Storage,
};
use futures::future::try_join;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    num::NonZeroUsize,
};
use tracing::{debug, warn};

/// Trait for index entries that reference oversized values in glob storage.
///
/// Implementations must provide access to the value location for crash recovery validation,
/// and a way to set the location when appending.
pub trait Record: CodecFixed<Cfg = ()> + Clone {
    /// Returns `(value_offset, value_size)` for crash recovery validation.
    fn value_location(&self) -> (u64, u32);

    /// Returns a new entry with the value location set.
    ///
    /// Called during `append` after the value is written to glob storage.
    fn with_location(self, offset: u64, size: u32) -> Self;
}

/// Configuration for oversized journal.
#[derive(Clone)]
pub struct Config<C> {
    /// Partition for the fixed index journal.
    pub index_partition: String,

    /// Partition for the glob value storage.
    pub value_partition: String,

    /// Page cache for index journal caching.
    pub index_page_cache: commonware_runtime::buffer::paged::CacheRef,

    /// Write buffer size for the index journal.
    pub index_write_buffer: NonZeroUsize,

    /// Write buffer size for the value journal.
    pub value_write_buffer: NonZeroUsize,

    /// Optional compression level for values (using zstd).
    pub compression: Option<u8>,

    /// Codec configuration for values.
    pub codec_config: C,
}

/// Segmented journal for entries with oversized values.
///
/// Combines a fixed-size index journal with glob storage for variable-length values.
/// Provides coordinated operations and crash recovery. Both constructors require the caller's
/// durable checkpoint: [Oversized::init] returns a [Replay] that must be drained and finished
/// before the journal is usable, and [Oversized::init_from_checkpoint] returns a journal directly.
///
/// Mutating functions consume the journal and return it only on success: an error (or a dropped
/// future) destroys the handle. Mutations on pruned sections fail with
/// [Error::AlreadyPrunedToSection]. Check [Oversized::pruned] first to keep the handle.
pub struct Oversized<E: BufferPooler + Storage + Metrics, I: Record, V: Codec> {
    index: FixedJournal<E, I>,
    values: Glob<E, V>,
}

/// Child rewind state awaiting successful application of its shared batch.
pub(crate) struct PreparedOversizedRewind {
    index: PreparedRewind,
    values: PreparedRewind,
}

impl<E: BufferPooler + Storage + Metrics, I: Record + Send + Sync, V: CodecShared> std::fmt::Debug
    for Oversized<E, I, V>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oversized")
            .field("oldest_section", &self.oldest_section())
            .field("newest_section", &self.newest_section())
            .finish_non_exhaustive()
    }
}

impl<E: BufferPooler + Storage + Metrics, I: Record + Send + Sync, V: CodecShared>
    Oversized<E, I, V>
{
    /// Initialize from the caller's per-section durable sizes and begin replay recovery.
    ///
    /// `checkpoint` maps a section to the index size a completed joint index+value sync proved
    /// durable. Recovery reconciles every index/value pair above that floor, then returns a
    /// [Replay] that verifies the index journal while protecting acknowledged data below it. A
    /// section the checkpoint omits is scanned from zero, so an empty checkpoint recovers a
    /// journal written before its caller published one. Drain the replay and call
    /// [Replay::finish] to obtain a usable [Oversized].
    pub async fn init(
        context: E,
        cfg: Config<V::Cfg>,
        checkpoint: BTreeMap<u64, u64>,
        buffer: NonZeroUsize,
    ) -> Result<Replay<E, I, V>, Error> {
        let oversized = Self::open(context, cfg).await?.repair(&checkpoint).await?;
        oversized.into_replay(buffer, checkpoint).await
    }

    /// Initialize by restoring a separately published durable boundary.
    ///
    /// `checkpoint` is `(section, index size)`, where sections are sequential starting at zero.
    /// Recovery keeps exactly this state: sections below `section` are verified complete and
    /// adopted unchanged, `section` is truncated to `index_size`, and everything after it is
    /// removed. Anything the checkpoint covers that is missing or inconsistent fails with
    /// [Error::Corruption]. Callers must only provide a checkpoint that was durably synced before
    /// it was published (see [crate::freezer::Freezer]). `index_size` must be a multiple of the
    /// fixed index entry size.
    pub async fn init_from_checkpoint(
        context: E,
        cfg: Config<V::Cfg>,
        checkpoint: (u64, u64),
    ) -> Result<Self, Error> {
        let mut batch = Vec::new();
        let (mut oversized, prepared) =
            Self::init_from_checkpoint_into(context, cfg, checkpoint, &mut batch).await?;
        oversized.index.apply_batch_operations(batch).await?;
        oversized.finalize_rewind(prepared);
        Ok(oversized)
    }

    /// Prepare checkpoint restoration as part of a caller-owned atomic batch.
    pub(crate) async fn init_from_checkpoint_into(
        context: E,
        cfg: Config<V::Cfg>,
        checkpoint: (u64, u64),
        batch: &mut Vec<BatchOperation<E::Blob>>,
    ) -> Result<(Self, PreparedOversizedRewind), Error> {
        let (section, index_size) = checkpoint;
        let chunk_size = FixedJournal::<E, I>::CHUNK_SIZE as u64;
        if !index_size.is_multiple_of(chunk_size) {
            return Err(Error::Corruption(format!(
                "section {section} checkpointed end {index_size} is not item-aligned"
            )));
        }
        Self::open(context, cfg)
            .await?
            .restore_into(section, index_size, batch)
            .await
    }

    /// Open the index and value journals without reconciling them.
    async fn open(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let index_cfg = FixedConfig {
            partition: cfg.index_partition,
            page_cache: cfg.index_page_cache,
            write_buffer: cfg.index_write_buffer,
        };
        let index = FixedJournal::open(context.child("index"), index_cfg).await?;

        let value_cfg = GlobConfig {
            partition: cfg.value_partition,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            write_buffer: cfg.value_write_buffer,
        };
        let values = Glob::init(context.child("values"), value_cfg).await?;

        Ok(Self { index, values })
    }

    /// Perform crash recovery by validating index entries and values above each durable floor.
    async fn repair(mut self, checkpoint: &BTreeMap<u64, u64>) -> Result<Self, Error> {
        let chunk_size = FixedJournal::<E, I>::CHUNK_SIZE as u64;
        let sections: Vec<u64> = self.index.sections().collect();
        let section_set: HashSet<u64> = sections.iter().copied().collect();

        // A durable size vouches for index and value data made durable by a completed joint sync.
        // Missing index storage below one is unrecoverable loss, not crash debris.
        for (&section, &watermark) in checkpoint {
            if watermark != 0 && !section_set.contains(&section) {
                return Err(Error::Corruption(format!(
                    "section {section} is missing below durable end {watermark}"
                )));
            }
        }

        let mut rewound_index = Vec::new();
        let mut rewound_values = Vec::new();
        for section in sections {
            let watermark = checkpoint.get(&section).copied().unwrap_or(0);
            if !watermark.is_multiple_of(chunk_size) {
                return Err(Error::Corruption(format!(
                    "section {section} durable end {watermark} is not item-aligned"
                )));
            }

            // Remove any interior hole above the durable end before reading entries by position.
            // A page recovered through its shorter checksum slot is refused by the page cache even
            // inside its committed prefix, so an unrepaired hole reports durable entries as
            // unreadable. Everything discarded here sits above the durable end.
            self.index = self.index.repair_prefix(section, watermark).await?;

            let index_size = self.index.size(section)?;
            if watermark > index_size {
                return Err(Error::Corruption(format!(
                    "section {section} retains {index_size} of durable {watermark}"
                )));
            }

            let glob_size = self.values.size(section)?;
            let entry_count = index_size / chunk_size;
            let floor_count = watermark / chunk_size;

            // Derive the value floor from the last durable entry, the one below-floor read
            // recovery needs. Verifying the entry's value checksum eagerly is deliberate policy
            // rather than a crash-model obligation: deeper values stay lazy until `get_value`.
            let mut glob_target = if floor_count == 0 {
                0
            } else {
                let entry = match self.index.get(section, floor_count - 1).await {
                    Ok(entry) => entry,
                    Err(Error::ItemOutOfRange(_) | Error::Runtime(RError::InvalidChecksum)) => {
                        return Err(Error::Corruption(format!(
                            "section {section} durable entry {} is unreadable",
                            floor_count - 1
                        )));
                    }
                    Err(err) => return Err(err),
                };
                let (offset, size) = entry.value_location();
                let end = offset
                    .checked_add(u64::from(size))
                    .ok_or(Error::Corruption(format!(
                        "section {section} durable entry {} overflows its value range",
                        floor_count - 1
                    )))?;
                if end > glob_size || !self.values.verify(section, offset, size).await? {
                    return Err(Error::Corruption(format!(
                        "section {section} durable entry {} has an unreadable value",
                        floor_count - 1
                    )));
                }
                end
            };

            // Starting at the durable floor, keep only the first contiguous sequence of
            // checksum-valid index/value pairs. This catches an interior value hole even when
            // a later value and index page survived the same interrupted flush.
            let mut valid_count = floor_count;
            for position in floor_count..entry_count {
                let entry = match self.index.get(section, position).await {
                    Ok(entry) => entry,
                    Err(Error::ItemOutOfRange(_) | Error::Runtime(RError::InvalidChecksum)) => {
                        warn!(section, position, "invalid index entry: truncating");
                        break;
                    }
                    Err(err) => return Err(err),
                };
                let (offset, size) = entry.value_location();
                // Before recovery watermarks existed, an empty index section could retain an
                // orphan value prefix. A later, durably synced first entry then began after that
                // prefix. At a zero floor, adopt that first entry's offset as the start of the
                // contiguous sequence so upgrading does not discard the acknowledged entry.
                let expected_offset = if position == 0 { offset } else { glob_target };
                let Some(end) = offset.checked_add(u64::from(size)) else {
                    warn!(section, position, "value range overflows: truncating");
                    break;
                };
                if offset != expected_offset
                    || end > glob_size
                    || !self.values.verify(section, offset, size).await?
                {
                    warn!(
                        section,
                        position,
                        offset,
                        size,
                        expected_offset,
                        glob_size,
                        "invalid value: truncating"
                    );
                    break;
                }
                valid_count = position + 1;
                glob_target = end;
            }

            let valid_size = valid_count * chunk_size;
            if valid_size < index_size {
                debug!(
                    section,
                    index_size, valid_size, "rewinding invalid index suffix"
                );
                self.index = self.index.rewind_section(section, valid_size).await?;
                rewound_index.push(section);
            }

            if glob_size > glob_target {
                debug!(
                    section,
                    glob_size, glob_target, "truncating glob trailing garbage"
                );
                self.values = self.values.rewind_section(section, glob_target).await?;
                rewound_values.push(section);
            }
        }

        // Make the truncations durable before appends can reuse the freed value ranges. A
        // dropped index entry that stayed durable would be adopted by a later recovery
        // referencing whatever bytes a subsequent append placed at its offsets, and stale
        // glob bytes that stayed durable would satisfy a later entry's range with another
        // record's frame.
        self.values = self.values.sync(&rewound_values).await?;
        self.index = self.index.sync(&rewound_index).await?;

        // Clean up orphan value sections that don't exist in index
        self.cleanup_orphan_value_sections().await
    }

    /// Restore the journals to exactly the durable state `(section, index_size)`
    /// describes (see [Self::init_from_checkpoint]).
    async fn restore_into(
        mut self,
        section: u64,
        index_size: u64,
        batch: &mut Vec<BatchOperation<E::Blob>>,
    ) -> Result<(Self, PreparedOversizedRewind), Error> {
        // Sections below the checkpoint were durable when it was published and never appended to
        // again. Verify each terminal index/value boundary, then adopt the section unchanged.
        let below: Vec<u64> = self
            .index
            .sections()
            .take_while(|candidate| *candidate < section)
            .collect();
        let mut expected = 0;
        for candidate in below {
            if candidate != expected {
                return Err(Error::Corruption(format!(
                    "section {expected} is missing below checkpoint section {section}"
                )));
            }
            let index_size = self.index.size(candidate)?;
            let glob_size = self.values.size(candidate)?;
            self.verify_complete(candidate, index_size, glob_size)
                .await?;
            expected += 1;
        }
        if expected != section {
            return Err(Error::Corruption(format!(
                "section {expected} is missing below checkpoint section {section}"
            )));
        }

        // A later page may survive while the checkpointed page falls back to its shorter,
        // committed checksum. Remove that unusable suffix before reading committed entries.
        self.index = self.index.repair_prefix(section, index_size).await?;
        let retained = self.index.size(section)?;
        if retained < index_size {
            return Err(Error::Corruption(format!(
                "section {section} retains {retained} of committed {index_size}"
            )));
        }

        // Read the checkpoint boundary before removing any suffix. The preceding prefix repair
        // makes a fallback-recovered checkpoint page readable as the section tip.
        let value_size = self.index_value_end(section, index_size).await?;
        let glob_size = self.values.size(section)?;
        if value_size > glob_size {
            return Err(Error::Corruption(format!(
                "section {section} last committed entry ends at {value_size}, glob size is {glob_size}"
            )));
        }

        let prepared = self
            .rewind_validated_into(section, index_size, value_size, batch)
            .await?;

        Ok((self, prepared))
    }

    /// Verify a section's journals agree: the last entry's value range must end exactly
    /// at the glob's size.
    async fn verify_complete(
        &self,
        section: u64,
        index_size: u64,
        glob_size: u64,
    ) -> Result<(), Error> {
        let entry_end = self.index_value_end(section, index_size).await?;
        if entry_end != glob_size {
            return Err(Error::Corruption(format!(
                "section {section} last entry ends at {entry_end}, glob size is {glob_size}"
            )));
        }

        Ok(())
    }

    /// Return the end of the value referenced by a section's last retained index entry.
    async fn index_value_end(&self, section: u64, index_size: u64) -> Result<u64, Error> {
        let chunk_size = FixedJournal::<E, I>::CHUNK_SIZE as u64;
        if !index_size.is_multiple_of(chunk_size) {
            return Err(Error::Corruption(format!(
                "section {section} index end {index_size} is not item-aligned"
            )));
        }
        if index_size == 0 {
            return Ok(0);
        }

        let position = index_size / chunk_size - 1;
        let entry = match self.index.get(section, position).await {
            Ok(entry) => entry,
            Err(
                Error::Codec(_)
                | Error::ItemOutOfRange(_)
                | Error::Runtime(RError::InvalidChecksum),
            ) => {
                return Err(Error::Corruption(format!(
                    "section {section} last entry is unreadable"
                )));
            }
            Err(err) => return Err(err),
        };

        let (offset, size) = entry.value_location();
        offset
            .checked_add(u64::from(size))
            .ok_or(Error::Corruption(format!(
                "section {section} last entry overflows its value range"
            )))
    }

    /// Remove any value sections that don't have corresponding index sections.
    ///
    /// This can happen if a crash occurs after writing to values but before
    /// writing to index for a new section. Since sections don't have to be
    /// contiguous, we compare the actual sets of sections rather than just
    /// comparing the newest section numbers.
    async fn cleanup_orphan_value_sections(mut self) -> Result<Self, Error> {
        // Collect index sections into a set for O(1) lookup
        let index_sections: HashSet<u64> = self.index.sections().collect();

        // Find value sections that don't exist in index
        let orphan_sections: Vec<u64> = self
            .values
            .sections()
            .filter(|s| !index_sections.contains(s))
            .collect();

        for &section in &orphan_sections {
            warn!(section, "removing orphan value section");
        }
        self.values.remove_sections(&orphan_sections).await?;

        Ok(self)
    }

    /// Append entry + value.
    ///
    /// Writes value to glob first, then writes index entry with the value location.
    ///
    /// Returns `(self, position, offset, size)` where:
    /// - `position`: Position in the index journal
    /// - `offset`: Byte offset in glob
    /// - `size`: Size of value in glob (including checksum)
    pub async fn append(
        mut self,
        section: u64,
        entry: I,
        value: &V,
    ) -> Result<(Self, u64, u64, u32), Error> {
        // Write value first (glob). This will typically write to an in-memory
        // buffer and return quickly (only blocks when the buffer is full).
        let (offset, size);
        (self.values, offset, size) = self.values.append(section, value).await?;

        // Update entry with actual location and write to index
        let entry_with_location = entry.with_location(offset, size);
        let position;
        (self.index, position) = self.index.append(section, &entry_with_location).await?;

        Ok((self, position, offset, size))
    }

    /// Get entry at position (index entry only, not value).
    pub async fn get(&self, section: u64, position: u64) -> Result<I, Error> {
        self.index.get(section, position).await
    }

    /// Get the last entry for a section, if any.
    ///
    /// Returns `Ok(None)` if the section is empty.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    pub async fn last(&self, section: u64) -> Result<Option<I>, Error> {
        self.index.last(section).await
    }

    /// Get value using offset/size from entry.
    ///
    /// The offset should be the byte offset from `append()` or from the entry's `value_location()`.
    pub async fn get_value(&self, section: u64, offset: u64, size: u32) -> Result<V, Error> {
        self.values.get(section, offset, size).await
    }

    /// Consume the journal into an owned [Replay] reader over every index entry.
    ///
    /// Setup flushes the index journal's buffered pages so the reader observes every accepted
    /// write. A checksum or layout failure below a section's durable size is reported as
    /// [Error::Corruption] instead of being repaired.
    async fn into_replay(
        self,
        buffer: NonZeroUsize,
        durable_ends: BTreeMap<u64, u64>,
    ) -> Result<Replay<E, I, V>, Error> {
        let Self { index, values, .. } = self;
        let index = index
            .replay_with_durable_ends(0, 0, buffer, durable_ends)
            .await?;
        Ok(Replay { index, values })
    }

    /// Sync both journals for `sections`.
    pub async fn sync(mut self, sections: impl crate::Sections) -> Result<Self, Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        (self.index, self.values) =
            try_join(self.index.sync(&sections), self.values.sync(&sections)).await?;
        Ok(self)
    }

    /// Start syncing both journals for the given `sections`.
    ///
    /// The returned handle completes once both journals' syncs complete, which is the point at
    /// which the caller may raise its durable size for those sections.
    ///
    /// An error reported by the returned [Handle] is fatal to the journal: the caller must stop
    /// using the returned journal.
    pub async fn start_sync(
        mut self,
        sections: impl crate::Sections,
    ) -> Result<(Self, Handle<()>), Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        let ((index, index_handle), (values, values_handle)) = try_join(
            self.index.start_sync(&sections),
            self.values.start_sync(&sections),
        )
        .await?;
        self.index = index;
        self.values = values;

        Ok((
            self,
            Handle::from_future(
                async move { try_join(index_handle, values_handle).await.map(|_| ()) },
            ),
        ))
    }

    /// Sync all sections.
    pub async fn sync_all(mut self) -> Result<Self, Error> {
        (self.index, self.values) = try_join(self.index.sync_all(), self.values.sync_all()).await?;
        Ok(self)
    }

    /// Prune both journals. Returns true if any sections were pruned.
    ///
    /// The caller must durably remove the pruned sections from its checkpoint first: a crash
    /// between that removal and these blob removals merely leaves old sections to be scanned
    /// again, while the reverse order can report a pruned section as lost.
    ///
    /// After both journals wait for in-flight section syncs, all selected index and value blobs
    /// are committed in one namespace batch. In-memory state is updated only after that batch
    /// succeeds.
    pub async fn prune(mut self, min: u64) -> Result<(Self, bool), Error> {
        let mut operations = self.index.prune_targets(min).await?;
        operations.extend(self.values.prune_targets(min).await?);
        self.index.apply_batch_operations(operations).await?;

        let index_pruned = self.index.finalize_prune(min);
        let value_pruned = self.values.finalize_prune(min);
        Ok((self, index_pruned || value_pruned))
    }

    /// Rewind both journals to a specific section and index size.
    ///
    /// This rewinds the section to the given index size and removes all sections
    /// after the given section. The value size is derived from the last entry.
    ///
    /// The child blobs' complete retained-tail updates and every later-section removal share one
    /// storage batch.
    ///
    /// The caller must durably lower its checkpoint to this boundary first, or recovery will
    /// report the discarded data as lost.
    ///
    /// `index_size` must be item-aligned and no larger than the section's retained size.
    pub async fn rewind(self, section: u64, index_size: u64) -> Result<Self, Error> {
        let value_size = self.preflight_rewind(section, index_size).await?;
        self.rewind_validated(section, index_size, value_size).await
    }

    /// Validate a rewind and derive its value boundary without mutating either journal.
    async fn preflight_rewind(&self, section: u64, index_size: u64) -> Result<u64, Error> {
        let retained = self.index.size(section)?;
        let exists = self.index.sections().any(|candidate| candidate == section);
        if !exists {
            return if index_size == 0 {
                Ok(0)
            } else {
                Err(Error::SectionOutOfRange(section))
            };
        }

        let chunk_size = FixedJournal::<E, I>::CHUNK_SIZE as u64;
        if !index_size.is_multiple_of(chunk_size) || index_size > retained {
            return Err(Error::InvalidRewind(index_size));
        }
        if index_size == 0 {
            return Ok(0);
        }

        let entry = self.index.get(section, index_size / chunk_size - 1).await?;
        let (offset, size) = entry.value_location();
        offset
            .checked_add(u64::from(size))
            .ok_or(Error::OffsetOverflow)
    }

    /// Apply a rewind whose index and value boundaries have already been validated.
    async fn rewind_validated(
        mut self,
        section: u64,
        index_size: u64,
        value_size: u64,
    ) -> Result<Self, Error> {
        let mut batch = Vec::new();
        let prepared = self
            .rewind_validated_into(section, index_size, value_size, &mut batch)
            .await?;
        self.index.apply_batch_operations(batch).await?;
        self.finalize_rewind(prepared);
        Ok(self)
    }

    /// Stage the index first so its buffered page state cannot reference reused value bytes.
    async fn rewind_validated_into(
        &mut self,
        section: u64,
        index_size: u64,
        value_size: u64,
        batch: &mut Vec<BatchOperation<E::Blob>>,
    ) -> Result<PreparedOversizedRewind, Error> {
        let index = self.index.rewind_into(section, index_size, batch).await?;
        let values = self.values.rewind_into(section, value_size, batch).await?;
        Ok(PreparedOversizedRewind { index, values })
    }

    /// Rewind only the given section to a specific index size.
    ///
    /// Unlike `rewind`, this does not affect other sections.
    /// The value size is derived from the last entry after rewinding the index.
    ///
    /// Both retained-tail updates share one storage batch. The caller must durably lower its
    /// checkpoint for `section` first (see [Self::rewind]).
    /// `index_size` must be item-aligned and no larger than the section's retained size.
    pub async fn rewind_section(mut self, section: u64, index_size: u64) -> Result<Self, Error> {
        let value_size = self.preflight_rewind(section, index_size).await?;
        let mut batch = Vec::new();
        let index = self
            .index
            .rewind_section_into(section, index_size, &mut batch)
            .await?;
        let values = self
            .values
            .rewind_section_into(section, value_size, &mut batch)
            .await?;
        self.index.apply_batch_operations(batch).await?;
        self.finalize_rewind(PreparedOversizedRewind { index, values });
        Ok(self)
    }

    /// Finalize both child journals after their shared batch succeeds.
    pub(crate) fn finalize_rewind(&mut self, prepared: PreparedOversizedRewind) {
        self.index.finalize_rewind(prepared.index);
        self.values.finalize_rewind(prepared.values);
    }

    /// Get index size for checkpoint.
    ///
    /// The value size can be derived from the last entry's location when needed.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.index.size(section)
    }

    /// Get the value size for a section, derived from the last entry's location.
    pub async fn value_size(&self, section: u64) -> Result<u64, Error> {
        match self.index.last(section).await {
            Ok(Some(entry)) => {
                let (offset, size) = entry.value_location();
                offset
                    .checked_add(u64::from(size))
                    .ok_or(Error::OffsetOverflow)
            }
            Ok(None) | Err(Error::SectionOutOfRange(_)) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Returns true when `section` is below the prune floor.
    ///
    /// The floor only tracks prunes from the current execution and resets at init, so a
    /// section pruned in a previous execution reports false.
    pub fn pruned(&self, section: u64) -> bool {
        self.index.pruned(section)
    }

    /// Returns the oldest section number, if any exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.index.oldest_section()
    }

    /// Returns the newest section number, if any exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.index.newest_section()
    }

    /// Return a context capable of removing this journal's namespace entries.
    pub(crate) fn destroy_context(&self) -> E {
        self.index.destroy_context()
    }

    /// Wait for pending child syncs, then return the journal's removal operations.
    pub(crate) async fn into_remove_targets(self) -> Result<Vec<RemoveTarget>, Error> {
        let Self { index, values } = self;
        let mut targets = index.into_remove_targets().await?;
        targets.extend(values.into_remove_targets().await?);
        Ok(targets)
    }

    /// Destroy all underlying storage.
    ///
    /// The caller must durably invalidate any externally persisted checkpoint before calling this
    /// method.
    pub async fn destroy(self) -> Result<(), Error> {
        let context = self.destroy_context();
        let targets = self.into_remove_targets().await?;
        context
            .apply_batch(targets.into_iter().map(Into::into).collect())
            .await
            .map_err(Error::Runtime)
    }
}

/// Owned replay reader over an [Oversized]'s index entries.
///
/// Yields `(section, position, entry)` in order. Dropping the reader before it is exhausted
/// destroys the journal: recovery is re-initialization. Call [Replay::finish] on an exhausted
/// reader to obtain the journal.
pub struct Replay<E: BufferPooler + Storage + Metrics, I: Record, V: Codec> {
    index: FixedReplay<E, I>,
    values: Glob<E, V>,
}

impl<E: BufferPooler + Storage + Metrics, I: Record + Send + Sync, V: CodecShared> Replay<E, I, V> {
    /// Returns the next `(section, position, entry)`, or `None` once every section is
    /// exhausted.
    ///
    /// An error ends the section that produced it, and iteration continues with the next section.
    /// [Error::ReplayInterrupted] and errors from a mutable repair end the replay.
    pub async fn next(&mut self) -> Option<Result<(u64, u64, I), Error>> {
        self.index.next().await
    }

    /// Returns the journal.
    ///
    /// Fails when the reader was not fully drained or yielded an error: the journal is
    /// destroyed and recovery is re-initialization.
    pub fn finish(self) -> Result<Oversized<E, I, V>, Error> {
        Ok(Oversized {
            index: self.index.finish()?,
            values: self.values,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::snapshot_partition;
    use commonware_codec::{FixedSize, Read, ReadExt, Write};
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Blob as _, Buf, BufMut, BufferPool, BufferPooler, Metrics, Name, RemoveTarget, Runner,
        Storage, Supervisor,
        buffer::paged::CacheRef,
        deterministic,
        mocks::SyncFaultContext,
        telemetry::metrics::{Metric, Registered},
    };
    use commonware_utils::{NZU16, NZUsize, sync::Mutex};
    use std::sync::Arc;

    #[derive(Clone)]
    struct RecordingContext<E> {
        inner: E,
        batches: Arc<Mutex<Vec<Vec<RemoveTarget>>>>,
    }

    impl<E: Supervisor> Supervisor for RecordingContext<E> {
        fn name(&self) -> Name {
            self.inner.name()
        }

        fn child(&self, label: &'static str) -> Self {
            Self {
                inner: self.inner.child(label),
                batches: self.batches.clone(),
            }
        }

        fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
            self.inner = self.inner.with_attribute(key, value);
            self
        }
    }

    impl<E: Metrics> Metrics for RecordingContext<E> {
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

    impl<E: BufferPooler> BufferPooler for RecordingContext<E> {
        fn network_buffer_pool(&self) -> &BufferPool {
            self.inner.network_buffer_pool()
        }

        fn storage_buffer_pool(&self) -> &BufferPool {
            self.inner.storage_buffer_pool()
        }
    }

    impl<E: Storage> Storage for RecordingContext<E> {
        type Blob = E::Blob;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: std::ops::RangeInclusive<u16>,
        ) -> Result<(Self::Blob, u64, u16), RError> {
            self.inner.open_versioned(partition, name, versions).await
        }

        async fn apply_batch(
            &self,
            operations: Vec<BatchOperation<Self::Blob>>,
        ) -> Result<(), RError> {
            let targets = operations
                .iter()
                .filter_map(|operation| match operation {
                    BatchOperation::Remove(target) => Some(target.clone()),
                    BatchOperation::Resize { .. } | BatchOperation::Update { .. } => None,
                })
                .collect();
            self.batches.lock().push(targets);
            self.inner.apply_batch(operations).await
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, RError> {
            self.inner.scan(partition).await
        }
    }

    /// Convert offset + size to byte end position (for truncation tests).
    fn byte_end(offset: u64, size: u32) -> u64 {
        offset + u64::from(size)
    }

    /// Recover with no published checkpoint, the state a caller that has never synced (or that
    /// predates checkpoints entirely) presents.
    async fn init_oversized<E, I, V>(
        context: E,
        cfg: Config<V::Cfg>,
    ) -> Result<Oversized<E, I, V>, Error>
    where
        E: BufferPooler + Storage + Metrics,
        I: Record + Send + Sync,
        V: CodecShared,
    {
        init_oversized_at(context, cfg, BTreeMap::new()).await
    }

    /// Recover with `checkpoint` as the caller's durable index size for each section.
    async fn init_oversized_at<E, I, V>(
        context: E,
        cfg: Config<V::Cfg>,
        checkpoint: BTreeMap<u64, u64>,
    ) -> Result<Oversized<E, I, V>, Error>
    where
        E: BufferPooler + Storage + Metrics,
        I: Record + Send + Sync,
        V: CodecShared,
    {
        let mut replay = Oversized::init(context, cfg, checkpoint, NZUsize!(1024)).await?;
        while let Some(result) = replay.next().await {
            result?;
        }
        replay.finish()
    }

    /// Test index entry that stores a u64 id and references a value.
    #[derive(Debug, Clone, PartialEq)]
    struct TestEntry {
        id: u64,
        value_offset: u64,
        value_size: u32,
    }

    impl TestEntry {
        fn new(id: u64, value_offset: u64, value_size: u32) -> Self {
            Self {
                id,
                value_offset,
                value_size,
            }
        }
    }

    impl Write for TestEntry {
        fn write(&self, buf: &mut impl BufMut) {
            self.id.write(buf);
            self.value_offset.write(buf);
            self.value_size.write(buf);
        }
    }

    impl Read for TestEntry {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            let id = u64::read(buf)?;
            let value_offset = u64::read(buf)?;
            let value_size = u32::read(buf)?;
            Ok(Self {
                id,
                value_offset,
                value_size,
            })
        }
    }

    impl FixedSize for TestEntry {
        const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE;
    }

    impl Record for TestEntry {
        fn value_location(&self) -> (u64, u32) {
            (self.value_offset, self.value_size)
        }

        fn with_location(mut self, offset: u64, size: u32) -> Self {
            self.value_offset = offset;
            self.value_size = size;
            self
        }
    }

    fn test_cfg(pooler: &impl BufferPooler) -> Config<()> {
        Config {
            index_partition: "test-index".into(),
            value_partition: "test-values".into(),
            index_page_cache: CacheRef::from_pooler(pooler, NZU16!(64), NZUsize!(8)),
            index_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            compression: None,
            codec_config: (),
        }
    }

    /// Simple test value type with unit config.
    type TestValue = [u8; 16];

    #[test_traced]
    fn test_destroy_submits_one_batch_for_both_partitions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let batches = Arc::new(Mutex::new(Vec::new()));
            let context = RecordingContext {
                inner: context,
                batches: batches.clone(),
            };
            let cfg = test_cfg(&context);
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg.clone())
                    .await
                    .expect("Failed to init");

            oversized.destroy().await.expect("Failed to destroy");

            assert_eq!(
                *batches.lock(),
                vec![vec![
                    RemoveTarget::Partition(cfg.index_partition),
                    RemoveTarget::Partition(cfg.value_partition),
                ]]
            );
        });
    }

    #[test_traced]
    fn test_prune_submits_one_batch_for_both_partitions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let batches = Arc::new(Mutex::new(Vec::new()));
            let context = RecordingContext {
                inner: context,
                batches: batches.clone(),
            };
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=3 {
                let value = [section as u8; 16];
                (oversized, _, _, _) = oversized
                    .append(section, TestEntry::new(section, 0, 0), &value)
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync_all().await.expect("Failed to sync");

            let pruned;
            (oversized, pruned) = oversized.prune(3).await.expect("Failed to prune");
            assert!(pruned);

            let target = |partition: &str, section: u64| RemoveTarget::Blob {
                partition: partition.into(),
                name: section.to_be_bytes().to_vec(),
            };
            assert_eq!(
                *batches.lock(),
                vec![vec![
                    target(&cfg.index_partition, 1),
                    target(&cfg.index_partition, 2),
                    target(&cfg.value_partition, 1),
                    target(&cfg.value_partition, 2),
                ]]
            );

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            // Append entry with value
            let value: TestValue = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
            let entry = TestEntry::new(42, 0, 0);
            let (position, offset, size);
            (oversized, position, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");

            assert_eq!(position, 0);

            // Get entry
            let retrieved_entry = oversized.get(1, position).await.expect("Failed to get");
            assert_eq!(retrieved_entry.id, 42);

            // Get value
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_crash_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate oversized journal
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append multiple entries
            let mut locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to persist");
            drop(oversized);

            // Simulate crash: truncate glob to lose last 2 values
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Calculate size to keep first 3 entries
            let keep_size = byte_end(locations[2].1, locations[2].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should recover and rewind index
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 3 entries should still be valid
            for i in 0..3u8 {
                let (position, offset, size) = locations[i as usize];
                let entry = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // Entry at position 3 should fail (index was rewound)
            let result = oversized.get(1, 3).await;
            assert!(result.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(123, 0, 0);
            let (position, offset, size);
            (oversized, position, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Reopen and verify
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            let retrieved_entry = oversized.get(1, position).await.expect("Failed to get");
            assert_eq!(retrieved_entry.id, 123);

            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // One sub-page entry/value per section stays buffered until synced.
            let mut located = Vec::new();
            for section in 1u64..=3 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                located.push((section, position, offset, size, value));
            }

            // Sync sections 1 and 3 (both index and values); a nonexistent section (99) is
            // skipped, not an error.
            oversized = oversized
                .sync(&[1, 3, 99])
                .await
                .expect("Failed to sync sections");
            drop(oversized);

            // Only the synced sections survive the unclean drop, with both index and value durable.
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");
            for &(section, position, offset, size, value) in &located {
                let result = oversized.get(section, position).await;
                if section == 2 {
                    assert!(result.is_err(), "unsynced section 2 must not be durable");
                    continue;
                }
                assert_eq!(result.expect("synced entry durable").id, section);
                let retrieved = oversized
                    .get_value(section, offset, size)
                    .await
                    .expect("synced value durable");
                assert_eq!(retrieved, value);
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    /// Assert that every entry recovery adopted in section 1 reads back the value that was
    /// appended with it.
    async fn assert_adopted_entries_consistent(
        oversized: &Oversized<deterministic::Context, TestEntry, TestValue>,
    ) {
        let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
        for position in 0..oversized.size(1).expect("size") / chunk {
            let entry = oversized.get(1, position).await.expect("Failed to get");
            let (offset, size) = entry.value_location();
            let value = oversized
                .get_value(1, offset, size)
                .await
                .expect("adopted entry must reference durable bytes");
            assert_eq!(
                value, [entry.id as u8; 16],
                "entry {} must read back the value appended with it",
                entry.id
            );
        }
    }

    #[test_traced]
    fn test_oversized_rewind_truncation_durable_before_offset_reuse() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            // One fully durable entry/value pair.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Rewind entry 1 away and append entry 2 at entry 1's glob offset, then crash
            // between the value sync and the index sync: entry 2's bytes (same size, valid
            // checksum) become durable at the exact range entry 1 referenced. Only the
            // durable truncation in `rewind` prevents recovery from resurrecting entry 1
            // pointing at entry 2's value. The range and checksum checks cannot reject it.
            oversized = oversized.rewind(1, 0).await.expect("Failed to rewind");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            oversized.values = oversized
                .values
                .sync(1)
                .await
                .expect("Failed to sync values");
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            assert_eq!(
                oversized.size(1).expect("size"),
                0,
                "rewound entry must not be revived over reused value bytes"
            );
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_recovery_never_adopts_entries_for_lost_values() {
        // Crash 1: entry 1 becomes durable but its value does not (an index write surviving
        // a crash its value bytes did not).
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            oversized.index = oversized.index.sync(1).await.expect("Failed to sync index");
        });

        // Boot 2: recovery rewinds entry 1 (its range is out of bounds) and must make that
        // truncation durable. A new append then reuses entry 1's offset. Crash 2 lands
        // after the value sync and before the index sync.
        let (_, checkpoint) =
            deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                let mut oversized: Oversized<_, TestEntry, TestValue> =
                    init_oversized(context.child("second"), test_cfg(&context))
                        .await
                        .expect("Failed to reinit");
                assert_eq!(
                    oversized.size(1).expect("size"),
                    0,
                    "entry without durable value bytes must be rewound"
                );
                (oversized, _, _, _) = oversized
                    .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                    .await
                    .expect("Failed to append");
                oversized.values = oversized
                    .values
                    .sync(1)
                    .await
                    .expect("Failed to sync values");
            });

        // Boot 3: without a durable truncation in recovery, the index would still hold
        // entry 1, now range-valid over entry 2's bytes.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("third"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_rewind_preparation_failure_preserves_durable_state() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            // One fully durable entry/value pair.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Boot 2: the glob cannot be synced while preparing the rewind, so the shared
            // index/value batch must not commit.
            let faulty_values = SyncFaultContext {
                inner: context.child("second"),
                fail_partition: "test-values".into(),
            };
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(faulty_values, test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            assert!(
                oversized.rewind(1, 0).await.is_err(),
                "rewind must fail when its retained value state cannot be made durable"
            );
        });

        // Preparation did not publish the index truncation, so recovery observes the complete
        // pre-rewind entry/value pair.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("third"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert_eq!(oversized.size(1).expect("size"), chunk);
            assert_eq!(oversized.get(1, 0).await.expect("entry").id, 1);
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_recovery_glob_truncation_durable_before_offset_reuse() {
        // Crash 1: the index truncation is durable but the glob still holds entry 2's
        // frame (the state a crash inside `rewind` leaves behind).
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            oversized = oversized.sync(1).await.expect("Failed to sync");
            oversized.index = oversized
                .index
                .rewind(1, chunk)
                .await
                .expect("Failed to rewind index");
            oversized.index = oversized.index.sync(1).await.expect("Failed to sync index");
        });

        // Boot 2: recovery truncates the glob to entry 1's end and must make that
        // truncation durable. Entry 3 (same size) then reuses entry 2's freed range.
        // Crash 2 lands after the index sync and before the values sync.
        let (_, checkpoint) =
            deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                let mut oversized: Oversized<_, TestEntry, TestValue> =
                    init_oversized(context.child("second"), test_cfg(&context))
                        .await
                        .expect("Failed to reinit");
                (oversized, _, _, _) = oversized
                    .append(1, TestEntry::new(3, 0, 0), &[3; 16])
                    .await
                    .expect("Failed to append");
                oversized.index = oversized.index.sync(1).await.expect("Failed to sync index");
            });

        // Boot 3: without a durable glob truncation in recovery, entry 3 would be
        // adopted referencing entry 2's still-durable frame.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("third"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_rewind_crash_between_truncations_recovers_post_rewind() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            // Two fully durable entry/value pairs.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            // Replay `rewind(1, chunk)`'s steps up to the worst crash point: the index
            // truncation is durable but the freed value bytes are not yet rewound.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            oversized = oversized.sync(1).await.expect("Failed to sync");
            oversized.index = oversized
                .index
                .rewind(1, chunk)
                .await
                .expect("Failed to rewind index");
            oversized.index = oversized.index.sync(1).await.expect("Failed to sync index");
        });

        // Recovery must truncate the orphaned value bytes and land on the post-rewind
        // state.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert_eq!(oversized.size(1).expect("size"), chunk);
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            let (offset, size) = entry.value_location();
            assert_eq!(
                oversized.values.size(1).expect("glob size"),
                byte_end(offset, size),
                "orphaned value bytes must be truncated"
            );
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_start_sync_completion_means_recoverable() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            let (_oversized, handle) = oversized.start_sync(1).await.expect("Failed to start sync");
            handle.await.expect("sync must complete");
            // Crash: everything covered by the completed handle must survive.
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert_eq!(oversized.size(1).expect("size"), chunk);
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_sync_values_failure_recovers_clean() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let faulty_values = SyncFaultContext {
                inner: context.child("first"),
                fail_partition: "test-values".into(),
            };
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(faulty_values, test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");

            // The value sync fails, so the caller is never acknowledged. The index sync
            // may still land, but recovery must not adopt an entry whose value bytes never
            // became durable.
            assert!(oversized.sync(1).await.is_err(), "value sync must fail");
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            assert_eq!(
                oversized.size(1).expect("size"),
                0,
                "entry without durable value bytes must be rewound"
            );
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_start_sync_values_failure_recovers_clean() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let faulty_values = SyncFaultContext {
                inner: context.child("first"),
                fail_partition: "test-values".into(),
            };
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(faulty_values, test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");

            // The value sync fails, so the handle must surface the failure and the caller
            // is never acknowledged.
            let (_oversized, handle) = oversized.start_sync(1).await.expect("Failed to start sync");
            assert!(handle.await.is_err(), "value sync must fail");
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            assert_eq!(
                oversized.size(1).expect("size"),
                0,
                "entry without durable value bytes must be rewound"
            );
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_start_sync_dropped_handle_driven_by_next_sync() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");

            // Drop the handle without observing it: the next sync must wait for the
            // started syncs and complete the work.
            let (oversized, handle) = oversized.start_sync(1).await.expect("Failed to start sync");
            drop(handle);
            oversized.sync(1).await.expect("Failed to sync");
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert_eq!(oversized.size(1).expect("size"), chunk);
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_init_rejects_section_missing_below_checkpoint() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Nothing was ever written, so a checkpoint claiming durable data is unrecoverable
            // loss rather than crash debris.
            let cfg = test_cfg(&context);
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                init_oversized_at(context, cfg, BTreeMap::from([(1, chunk)])).await;
            assert!(matches!(result, Err(Error::Corruption(_))), "{result:?}");
        });
    }

    #[test_traced]
    fn test_init_rejects_checkpoint_beyond_retained_index() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // A checkpoint past the retained index, and one that does not land on an item
            // boundary, are both corruption.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            for (instance, checkpoint) in [("beyond", 2 * chunk), ("unaligned", chunk - 1)] {
                let result: Result<Oversized<_, TestEntry, TestValue>, Error> = init_oversized_at(
                    context.child(instance),
                    cfg.clone(),
                    BTreeMap::from([(1, checkpoint)]),
                )
                .await;
                assert!(matches!(result, Err(Error::Corruption(_))), "{result:?}");
            }
        });
    }

    #[test_traced]
    fn test_init_rejects_damaged_value_below_checkpoint() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            let (offset, size);
            (oversized, _, offset, size) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Damage the value the checkpoint's boundary entry points at.
            oversized
                .values
                .inject(1, offset, vec![0xFF; size as usize])
                .await
                .expect("Failed to damage value");
            oversized.values = oversized
                .values
                .sync(1)
                .await
                .expect("Failed to sync damaged value");
            drop(oversized);

            // Below the checkpoint the damage is loud. Without one it is repairable tail debris.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let result: Result<Oversized<_, TestEntry, TestValue>, Error> = init_oversized_at(
                context.child("second"),
                cfg.clone(),
                BTreeMap::from([(1, 2 * chunk)]),
            )
            .await;
            assert!(matches!(result, Err(Error::Corruption(_))), "{result:?}");

            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("third"), cfg)
                    .await
                    .expect("Failed to reinit");
            assert_eq!(oversized.size(1).expect("size"), chunk);
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_recovery_rejects_entry_with_torn_value_bytes() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            // One fully durable entry/value pair.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Append entry 2, make its index entry durable, then persist the glob's LENGTH
            // over entry 2's range without its bytes (writeback-mode metadata journaling):
            // overwrite the frame with same-length garbage and sync the values journal.
            let (offset, size);
            (oversized, _, offset, size) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            oversized.index = oversized.index.sync(1).await.expect("Failed to sync index");
            oversized
                .values
                .inject(1, offset, vec![0xFF; size as usize])
                .await
                .expect("Failed to overwrite value bytes");
            oversized.values = oversized
                .values
                .sync(1)
                .await
                .expect("Failed to sync values");
        });

        // Entry 2's range fits within the glob, so only the checksum check can reject it.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), test_cfg(&context))
                    .await
                    .expect("Failed to reinit");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert_eq!(
                oversized.size(1).expect("size"),
                chunk,
                "entry with torn value bytes must be rewound"
            );
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_repairs_torn_interior_value() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Establish a durable floor at entry 0.
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(0, 0, 0), &[0; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let floor = BTreeMap::from([(1, chunk)]);

            // Persist three more pairs without advancing the floor, then damage the middle
            // value. Entry 3 remains a valid island beyond the hole.
            let mut locations = Vec::new();
            for id in 1..=3u64 {
                let (offset, size);
                (oversized, _, offset, size) = oversized
                    .append(1, TestEntry::new(id, 0, 0), &[id as u8; 16])
                    .await
                    .expect("Failed to append");
                locations.push((offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to persist");
            let (offset, size) = locations[1];
            oversized
                .values
                .inject(1, offset, vec![0xFF; size as usize])
                .await
                .expect("Failed to damage interior value");
            oversized.values = oversized
                .values
                .sync(1)
                .await
                .expect("Failed to sync damaged value");
            drop(oversized);

            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized_at(context.child("second"), cfg.clone(), floor.clone())
                    .await
                    .expect("Failed to recover");
            assert_eq!(oversized.size(1).expect("size"), 2 * chunk);
            assert_adopted_entries_consistent(&oversized).await;
            assert_eq!(oversized.get(1, 0).await.expect("entry").id, 0);
            assert_eq!(oversized.get(1, 1).await.expect("entry").id, 1);
            assert!(oversized.get(1, 2).await.is_err());

            // The repaired ranges can be reused and made durable.
            let position;
            (oversized, position, _, _) = oversized
                .append(1, TestEntry::new(4, 0, 0), &[4; 16])
                .await
                .expect("Failed to append after recovery");
            assert_eq!(position, 2);
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized_at(context.child("third"), cfg, floor)
                    .await
                    .expect("Failed to reopen");
            assert_adopted_entries_consistent(&oversized).await;
            assert_eq!(oversized.get(1, 2).await.expect("entry").id, 4);
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_scans_past_torn_interior_index_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so each entry is on its own page.
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Persist five entry/value pairs, with a durable floor covering only the first two.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            for i in 1..=5u8 {
                (oversized, _, _, _) = oversized
                    .append(1, TestEntry::new(i as u64, 0, 0), &[i; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            drop(oversized);

            // Corrupt the CRC record of the THIRD entry's index page: the backward open
            // scan stops at the (valid) last page, so the torn page survives in bounds.
            let physical_page = TestEntry::SIZE as u64 + 12;
            let (index_blob, size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open index blob");
            assert_eq!(size, 5 * physical_page);
            index_blob
                .write_at_sync(2 * physical_page + TestEntry::SIZE as u64, vec![0xFF; 12])
                .await
                .expect("Failed to corrupt index page");
            drop(index_blob);

            // Corrupt the fourth and fifth values so the backward scan must walk past
            // their entries and read the torn page.
            let (values_blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open values blob");
            values_blob
                .write_at_sync(60, vec![0xFF; 20])
                .await
                .expect("Failed to corrupt value");
            values_blob
                .write_at_sync(80, vec![0xFF; 20])
                .await
                .expect("Failed to corrupt value");
            drop(values_blob);

            // Recovery scans past the invalid tail values and the torn page (surfaced
            // as a checksum failure, not a generic read error) to the last valid pair.
            let oversized: Oversized<_, TestEntry, TestValue> = init_oversized_at(
                context.child("second"),
                cfg,
                BTreeMap::from([(1, 2 * chunk)]),
            )
            .await
            .expect("Failed to reinit");
            assert_eq!(oversized.size(1).expect("size"), 2 * chunk);
            assert_adopted_entries_consistent(&oversized).await;
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_reads_durable_entry_in_fallback_recovered_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // A 64-byte index page holds three 20-byte entries plus a 4-byte remainder, so a
            // three-entry sync lands mid-page.
            const PAGE: u64 = 64;
            let cfg = test_cfg(&context);
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;

            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            for id in 0..3u64 {
                (oversized, _, _, _) = oversized
                    .append(1, TestEntry::new(id, 0, 0), &[id as u8; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            let floor = oversized.size(1).expect("missing section");
            assert_eq!(floor, 3 * chunk);
            assert!(
                floor < PAGE,
                "the durable end must fall inside the first page"
            );

            // Fill the first page and spill into the next, then materialize both.
            for id in 3..8u64 {
                (oversized, _, _, _) = oversized
                    .append(1, TestEntry::new(id, 0, 0), &[id as u8; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to materialize");
            drop(oversized);

            // Model a torn rewrite of the first page: the bytes the rewrite appended never
            // landed, while the committed prefix and its slot did. The page falls back to the
            // committed length and stays checksum-valid there.
            let (index_blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open index");
            index_blob
                .write_at_sync(floor, vec![0xFF; (PAGE - floor) as usize])
                .await
                .expect("Failed to tear the rewritten suffix");
            drop(index_blob);

            // Every byte below the durable end survived, so recovery must read the boundary
            // entry out of the committed prefix and keep all three entries.
            let recovered: Oversized<_, TestEntry, TestValue> = init_oversized_at(
                context.child("second"),
                cfg.clone(),
                BTreeMap::from([(1, floor)]),
            )
            .await
            .expect("durable entries in a fallback-recovered page must be readable");
            assert_eq!(recovered.size(1).expect("missing section"), floor);
        });
    }

    #[test_traced]
    fn test_replay_rejects_torn_index_page_below_checkpoint() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            for id in 0..3u64 {
                (oversized, _, _, _) = oversized
                    .append(1, TestEntry::new(id, 0, 0), &[id as u8; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Damage entry 1 while entry 2's page remains readable. The checkpoint covers all
            // three entries, so replay must preserve the evidence instead of truncating.
            let physical_page = TestEntry::SIZE as u64 + 12;
            let (index_blob, size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open index");
            index_blob
                .write_at_sync(physical_page + TestEntry::SIZE as u64, vec![0xFF; 12])
                .await
                .expect("Failed to damage index");
            drop(index_blob);

            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let mut replay: Replay<_, TestEntry, TestValue> = Oversized::init(
                context.child("second"),
                cfg.clone(),
                BTreeMap::from([(1, 3 * chunk)]),
                NZUsize!(1024),
            )
            .await
            .expect("Failed to begin recovery");
            assert!(matches!(replay.next().await, Some(Ok((1, 0, _)))));
            assert!(matches!(
                replay.next().await,
                Some(Err(Error::Corruption(_)))
            ));
            assert!(matches!(replay.finish(), Err(Error::ReplayFailed)));

            let (_, retained) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to reopen index");
            assert_eq!(retained, size, "durable corruption must not be truncated");
        });
    }

    #[test_traced]
    fn test_oversized_invalid_rewinds_do_not_mutate_storage() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            for (section, id) in [(1, 1), (1, 2), (2, 3)] {
                (oversized, _, _, _) = oversized
                    .append(section, TestEntry::new(id, 0, 0), &[id as u8; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync_all().await.expect("Failed to sync");
            drop(oversized);

            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            for (section_only, index_size, actor) in [
                (false, chunk + 1, "rewind_unaligned"),
                (true, chunk + 1, "rewind_section_unaligned"),
                (false, 3 * chunk, "rewind_oversized"),
                (true, 3 * chunk, "rewind_section_oversized"),
            ] {
                let oversized: Oversized<_, TestEntry, TestValue> =
                    init_oversized(context.child(actor), cfg.clone())
                        .await
                        .expect("Failed to reopen");
                let before = (
                    snapshot_partition(&context, &cfg.index_partition).await,
                    snapshot_partition(&context, &cfg.value_partition).await,
                );

                let result = if section_only {
                    oversized.rewind_section(1, index_size).await
                } else {
                    oversized.rewind(1, index_size).await
                };
                assert!(
                    matches!(result, Err(Error::InvalidRewind(size)) if size == index_size),
                    "invalid rewind returned {result:?}"
                );

                let after = (
                    snapshot_partition(&context, &cfg.index_partition).await,
                    snapshot_partition(&context, &cfg.value_partition).await,
                );
                assert_eq!(
                    after, before,
                    "invalid rewind must not mutate physical storage"
                );
            }
        });
    }

    fn assert_restore_rejects_unaligned_checkpoint(index_size: u64) {
        let executor = deterministic::Runner::default();
        executor.start(move |context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            for (section, id) in [(1, 1), (1, 2), (2, 3)] {
                (oversized, _, _, _) = oversized
                    .append(section, TestEntry::new(id, 0, 0), &[id as u8; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync_all().await.expect("Failed to sync");
            drop(oversized);

            let before = (
                snapshot_partition(&context, &cfg.index_partition).await,
                snapshot_partition(&context, &cfg.value_partition).await,
            );
            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init_from_checkpoint(
                    context.child("invalid"),
                    cfg.clone(),
                    (1, index_size),
                )
                .await;
            assert!(matches!(result, Err(Error::Corruption(_))), "{result:?}");
            let after = (
                snapshot_partition(&context, &cfg.index_partition).await,
                snapshot_partition(&context, &cfg.value_partition).await,
            );
            assert_eq!(
                after, before,
                "invalid checkpoint must not mutate physical storage"
            );
        });
    }

    #[test_traced]
    fn test_oversized_restore_rejects_unaligned_checkpoint_without_mutation() {
        let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;

        // A sub-entry and a past-entry checkpoint fail the same alignment check.
        for index_size in [chunk - 1, chunk + 1] {
            assert_restore_rejects_unaligned_checkpoint(index_size);
        }
    }

    #[test_traced]
    fn test_oversized_restore_rejects_short_boundary_value_without_mutation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            for section in 0..=1 {
                (oversized, _, _, _) = oversized
                    .append(section, TestEntry::new(section, 0, 0), &[section as u8; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync_all().await.expect("Failed to sync");
            drop(oversized);

            let (blob, size) = context
                .open(&cfg.value_partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open boundary values");
            blob.resize(size - 1)
                .await
                .expect("Failed to shorten values");
            blob.sync().await.expect("Failed to sync shortened values");
            drop(blob);

            let before = (
                snapshot_partition(&context, &cfg.index_partition).await,
                snapshot_partition(&context, &cfg.value_partition).await,
            );
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init_from_checkpoint(context.child("invalid"), cfg.clone(), (0, chunk))
                    .await;
            assert!(matches!(result, Err(Error::Corruption(_))), "{result:?}");

            let after = (
                snapshot_partition(&context, &cfg.index_partition).await,
                snapshot_partition(&context, &cfg.value_partition).await,
            );
            assert_eq!(
                after, before,
                "invalid checkpoint must not mutate physical storage"
            );
        });
    }

    fn assert_restore_rejects_unaligned_lower_section(index_size: u64) {
        let executor = deterministic::Runner::default();
        executor.start(move |context| async move {
            let cfg = test_cfg(&context);
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let (offset, size);
            (oversized, _, offset, size) = oversized
                .append(0, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append first lower entry");
            let first_value_end = byte_end(offset, size);
            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append second lower entry");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(3, 0, 0), &[3; 16])
                .await
                .expect("Failed to append checkpoint entry");
            oversized = oversized.sync_all().await.expect("Failed to sync");

            oversized.index = oversized
                .index
                .rewind_section(0, index_size)
                .await
                .expect("Failed to make lower index unaligned");
            oversized.values = oversized
                .values
                .rewind_section(
                    0,
                    if index_size < chunk {
                        0
                    } else {
                        first_value_end
                    },
                )
                .await
                .expect("Failed to align lower values with complete entries");
            oversized.index = oversized.index.sync(0).await.expect("Failed to sync index");
            oversized.values = oversized
                .values
                .sync(0)
                .await
                .expect("Failed to sync values");
            drop(oversized);

            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init_from_checkpoint(context.child("second"), cfg, (1, chunk)).await;
            assert!(matches!(result, Err(Error::Corruption(_))), "{result:?}");
        });
    }

    #[test_traced]
    fn test_oversized_restore_rejects_unaligned_lower_section() {
        let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;

        // A sub-entry and a partial-entry size fail the same lower-section alignment check.
        for index_size in [1, chunk + 1] {
            assert_restore_rejects_unaligned_lower_section(index_size);
        }
    }

    #[test_traced]
    fn test_oversized_restore_discards_beyond_checkpoint() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            // One committed entry, then torn state beyond the checkpoint: entries in
            // section 0 and 1 whose index becomes durable ahead of their values.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(0).await.expect("Failed to sync");
            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(3, 0, 0), &[3; 16])
                .await
                .expect("Failed to append");
            oversized.index = oversized
                .index
                .sync(&[0, 1])
                .await
                .expect("Failed to sync index");
        });

        // Restore truncates to the checkpoint without validating the discarded state.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init_from_checkpoint(
                    context.child("second"),
                    test_cfg(&context),
                    (0, chunk),
                )
                .await
                .expect("Failed to reinit");
            assert_eq!(oversized.size(0).expect("size"), chunk);
            assert_eq!(oversized.newest_section(), Some(0));
            assert_adopted_entries_consistent(&oversized).await;

            // The restored journal remains usable for appends past the checkpoint.
            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(4, 0, 0), &[4; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(0).await.expect("Failed to sync");
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_restore_repairs_suffix_after_partial_checkpoint_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context);
            cfg.index_write_buffer = NZUsize!(1);
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(0, 0, 0), &[0; 16])
                .await
                .expect("Failed to append checkpointed entry");
            oversized = oversized.sync(0).await.expect("Failed to sync checkpoint");

            // Fill later pages, preserving the first page's shorter checksum in its alternate
            // slot, then make the full state durable so it can be edited deterministically.
            for id in 1..7 {
                (oversized, _, _, _) = oversized
                    .append(0, TestEntry::new(id, 0, 0), &[id as u8; 16])
                    .await
                    .expect("Failed to append suffix entry");
            }
            oversized = oversized.sync(0).await.expect("Failed to sync suffix");
            drop(oversized);

            // Restore the first page's old zero padding without touching either checksum slot.
            // Its committed one-entry fallback remains valid while the longer checksum and later
            // pages describe an unusable suffix, matching an interrupted page extension.
            let (index, _) = context
                .open(&cfg.index_partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open index section");
            index
                .write_at_sync(chunk, vec![0; 64 - TestEntry::SIZE])
                .await
                .expect("Failed to tear index page extension");
            drop(index);

            let mut oversized: Oversized<_, TestEntry, TestValue> =
                Oversized::init_from_checkpoint(context.child("second"), cfg, (0, chunk))
                    .await
                    .expect("Failed to restore checkpoint");
            assert_eq!(oversized.size(0).expect("size"), chunk);
            assert_eq!(
                oversized.get(0, 0).await.expect("Failed to read entry").id,
                0
            );

            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(7, 0, 0), &[7; 16])
                .await
                .expect("Failed to append after repair");
            oversized = oversized
                .sync(0)
                .await
                .expect("Failed to sync after repair");
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_restore_incomplete_section_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Two committed sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync_all().await.expect("Failed to sync");
            drop(oversized);

            // Truncate section 0's values, simulating lost durable state below the
            // checkpoint
            let (blob, len) = context
                .open("test-values", &0u64.to_be_bytes())
                .await
                .expect("Failed to open values blob");
            blob.resize(len - 1).await.expect("Failed to resize");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // The checkpoint covers the damaged section, so init must fail. Nothing is
            // repaired, so the failure persists across restarts.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            for instance in ["second", "third"] {
                let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                    Oversized::init_from_checkpoint(
                        context.child(instance),
                        test_cfg(&context),
                        (1, chunk),
                    )
                    .await;
                assert!(matches!(result, Err(Error::Corruption(_))));
            }
        });
    }

    #[test_traced]
    fn test_oversized_restore_rejects_fully_missing_lower_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            for section in 0..=1 {
                (oversized, _, _, _) = oversized
                    .append(section, TestEntry::new(section, 0, 0), &[section as u8; 16])
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync_all().await.expect("Failed to sync");
            drop(oversized);

            // Losing both halves leaves no orphan for either partition scan to discover. The
            // sequential checkpoint still proves that section 0 must exist.
            for partition in [&cfg.index_partition, &cfg.value_partition] {
                context
                    .remove(partition, Some(&0u64.to_be_bytes()))
                    .await
                    .expect("Failed to remove section");
            }

            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let result: Result<Oversized<_, TestEntry, TestValue>, Error> =
                Oversized::init_from_checkpoint(context.child("second"), cfg, (1, chunk)).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_oversized_restore_defers_committed_value_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Two committed sections.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), test_cfg(&context))
                    .await
                    .expect("Failed to init");
            let (offset, size);
            (oversized, _, offset, size) = oversized
                .append(0, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync_all().await.expect("Failed to sync");

            // Make one committed value unreadable without changing the section extent.
            oversized
                .values
                .inject(0, offset, vec![0xFF; size as usize])
                .await
                .expect("Failed to corrupt value");
            oversized.values = oversized.values.sync(0).await.expect("Failed to sync");
            drop(oversized);

            // Restore validates only the terminal index/value boundary. The unreadable value is
            // reported when that entry is accessed.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            let oversized: Oversized<_, TestEntry, TestValue> = Oversized::init_from_checkpoint(
                context.child("second"),
                test_cfg(&context),
                (1, chunk),
            )
            .await
            .expect("Failed to reinit");
            assert!(matches!(
                oversized.get_value(0, offset, size).await,
                Err(Error::ChecksumMismatch(_, _))
            ));
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            let (offset, size) = entry.value_location();
            assert_eq!(
                oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value"),
                [2; 16]
            );
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_replay_empty_finishes_immediately() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let replay = Oversized::<_, TestEntry, TestValue>::init(
                context,
                cfg,
                BTreeMap::new(),
                NZUsize!(1024),
            )
            .await
            .expect("Failed to init");

            // An empty journal's reader is exhausted from the start
            let oversized = replay.finish().expect("failed to finish replay");
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_replay_finish_before_drain_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            let replay = Oversized::<_, TestEntry, TestValue>::init(
                context.child("second"),
                cfg,
                BTreeMap::new(),
                NZUsize!(1024),
            )
            .await
            .expect("Failed to re-init");
            assert!(matches!(replay.finish(), Err(Error::ReplayFailed)));
        });
    }

    #[test_traced]
    fn test_oversized_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            // Append to multiple sections
            for section in 1u64..=5 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }

            // Prune sections < 3
            (oversized, _) = oversized.prune(3).await.expect("Failed to prune");

            // The public accessor mirrors the guard
            assert!(oversized.pruned(1));
            assert!(oversized.pruned(2));
            assert!(!oversized.pruned(3));

            // Sections 1, 2 should be gone
            assert!(oversized.get(1, 0).await.is_err());
            assert!(oversized.get(2, 0).await.is_err());

            // Sections 3, 4, 5 should exist
            assert!(oversized.get(3, 0).await.is_ok());
            assert!(oversized.get(4, 0).await.is_ok());
            assert!(oversized.get(5, 0).await.is_ok());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_empty_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create oversized journal
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append to section 2 only (section 1 remains empty after being opened)
            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            (oversized, _, _, _) = oversized
                .append(2, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(2).await.expect("Failed to sync");
            drop(oversized);

            // Reinitialize - recovery should handle the empty/non-existent section 1
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 2 entry should be valid
            let entry = oversized.get(2, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 1);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_all_entries_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 5 entries
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to persist");
            drop(oversized);

            // Truncate glob to 0 bytes - ALL entries become invalid
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should recover and rewind index to 0
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // No entries should be accessible
            let result = oversized.get(1, 0).await;
            assert!(result.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 0);

            let retrieved = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_multiple_sections_mixed_validity() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Section 1: 3 entries
            let mut section1_locations = Vec::new();
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                section1_locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Section 2: 5 entries
            let mut section2_locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [10 + i; 16];
                let entry = TestEntry::new(10 + i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(2, entry, &value)
                    .await
                    .expect("Failed to append");
                section2_locations.push((position, offset, size));
            }
            oversized = oversized.sync(2).await.expect("Failed to sync");

            // Section 3: 2 entries
            for i in 0..2u8 {
                let value: TestValue = [20 + i; 16];
                let entry = TestEntry::new(20 + i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(3, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(3).await.expect("Failed to sync");
            drop(oversized);

            // Truncate section 1 glob to keep only first entry
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(section1_locations[0].1, section1_locations[0].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Truncate section 2 glob to keep first 3 entries
            let (blob, _) = context
                .open(&cfg.value_partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(section2_locations[2].1, section2_locations[2].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Section 3 remains intact

            // Reinitialize
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 1: only position 0 valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(1, 1).await.is_err());
            assert!(oversized.get(1, 2).await.is_err());

            // Section 2: positions 0,1,2 valid
            assert!(oversized.get(2, 0).await.is_ok());
            assert!(oversized.get(2, 1).await.is_ok());
            assert!(oversized.get(2, 2).await.is_ok());
            assert!(oversized.get(2, 3).await.is_err());
            assert!(oversized.get(2, 4).await.is_err());

            // Section 3: both positions valid
            assert!(oversized.get(3, 0).await.is_ok());
            assert!(oversized.get(3, 1).await.is_ok());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_corrupted_last_index_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so each entry is on its own page.
            // This allows corrupting just the last entry's page without affecting others.
            // Physical page size = TestEntry::SIZE (20) + 12 (CRC record) = 32 bytes.
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 5 entries (each on its own page)
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to persist");
            drop(oversized);

            // Corrupt the last page's CRC to trigger page-level integrity failure
            let (blob, size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Physical page size = 20 + 12 = 32 bytes
            // 5 entries = 5 pages = 160 bytes total
            // Last page CRC starts at offset 160 - 12 = 148
            assert_eq!(size, 160);
            let last_page_crc_offset = size - 12;
            blob.write_at_sync(last_page_crc_offset, vec![0xFF; 12])
                .await
                .expect("Failed to corrupt");
            drop(blob);

            // Reinitialize - should detect page corruption and truncate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 4 entries should be valid (on pages 0-3)
            for i in 0..4u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entry 4 should be gone (its page was corrupted)
            assert!(oversized.get(1, 4).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 4);

            let retrieved = oversized.get(1, 4).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_all_entries_valid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append entries to multiple sections
            for section in 1u64..=3 {
                for i in 0..10u8 {
                    let value: TestValue = [(section as u8) * 10 + i; 16];
                    let entry = TestEntry::new(section * 100 + i as u64, 0, 0);
                    (oversized, _, _, _) = oversized
                        .append(section, entry, &value)
                        .await
                        .expect("Failed to append");
                }
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Reinitialize with no corruption - should be fast
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // All entries should be valid
            for section in 1u64..=3 {
                for i in 0..10u8 {
                    let entry = oversized
                        .get(section, i as u64)
                        .await
                        .expect("Failed to get");
                    assert_eq!(entry.id, section * 100 + i as u64);
                }
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_single_entry_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with single entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            (oversized, _, _, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate glob to 0 - single entry becomes invalid
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Entry should be gone
            assert!(oversized.get(1, 0).await.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_last_entry_off_by_one() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate glob to be off by 1 byte from last entry
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Last entry needs: offset + size bytes
            // Truncate to offset + size - 1 (missing 1 byte)
            let last = &locations[2];
            let truncate_to = byte_end(last.1, last.2) - 1;
            blob.resize(truncate_to).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(1, 1).await.is_ok());

            // Entry 2 should be gone (truncated)
            assert!(oversized.get(1, 2).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 2);

            let retrieved = oversized.get(1, 2).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_missing_entirely() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Delete the glob file entirely
            context
                .remove(&cfg.value_partition, Some(&1u64.to_be_bytes()))
                .await
                .expect("Failed to remove");

            // The checkpoint covers the missing values, so this is storage loss rather than an
            // interrupted unacknowledged write.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert!(matches!(
                init_oversized_at::<_, TestEntry, TestValue>(
                    context.child("second"),
                    cfg,
                    BTreeMap::from([(1, 3 * chunk)])
                )
                .await,
                Err(Error::Corruption(_))
            ));
        });
    }

    #[test_traced]
    fn test_recovery_can_append_after_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to persist");
            drop(oversized);

            // Truncate glob to keep only first 2 entries
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(locations[1].1, locations[1].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Verify first 2 entries exist
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(1, 1).await.is_ok());
            assert!(oversized.get(1, 2).await.is_err());

            // Append new entries after recovery
            for i in 10..15u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append after recovery");
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Verify new entries at positions 2, 3, 4, 5, 6
            for i in 0..5u8 {
                let entry = oversized
                    .get(1, 2 + i as u64)
                    .await
                    .expect("Failed to get new entry");
                assert_eq!(entry.id, (10 + i) as u64);
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_pruned_ahead_of_index_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=3 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Plant an impossible state by pruning the glob without the index.
            use crate::journal::segmented::glob::{Config as GlobConfig, Glob};
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");
            (glob, _) = glob.prune(2).await.expect("Failed to prune glob");
            glob = glob.sync_all().await.expect("Failed to sync glob");
            drop(glob);

            // Section 1 was covered by the checkpoint. Losing its value blob is unrecoverable
            // storage corruption, not an interrupted prune state.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert!(matches!(
                init_oversized_at::<_, TestEntry, TestValue>(
                    context.child("second"),
                    cfg,
                    BTreeMap::from([(1, chunk), (2, chunk), (3, chunk)])
                )
                .await,
                Err(Error::Corruption(_))
            ));
        });
    }

    #[test_traced]
    fn test_recovery_index_partition_deleted() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate multiple sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=3 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Delete index blob for section 2 (simulate corruption/loss)
            context
                .remove(&cfg.index_partition, Some(&2u64.to_be_bytes()))
                .await
                .expect("Failed to remove index");

            // The missing index section is covered by the checkpoint.
            let chunk = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            assert!(matches!(
                init_oversized_at::<_, TestEntry, TestValue>(
                    context.child("second"),
                    cfg,
                    BTreeMap::from([(1, chunk), (2, chunk), (3, chunk)])
                )
                .await,
                Err(Error::Corruption(_))
            ));
        });
    }

    #[test_traced]
    fn test_recovery_index_synced_but_glob_not() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append entries and sync
            let mut locations = Vec::new();
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Add more entries WITHOUT syncing (simulates unsynced writes)
            for i in 10..15u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            // Note: NOT calling sync() here
            drop(oversized);

            // Simulate crash where index was synced but glob wasn't:
            // Truncate glob back to the synced size (3 entries)
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let synced_size = byte_end(locations[2].1, locations[2].2);
            blob.resize(synced_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should rewind index to match glob
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // First 3 entries should be valid
            for i in 0..3u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entries 3-7 should be gone (unsynced, index rewound)
            assert!(oversized.get(1, 3).await.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_synced_but_index_not() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so each entry is exactly one page.
            // This allows truncating by entry count to equal truncating by full pages,
            // maintaining page-level integrity.
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append entries and sync
            let mut locations = Vec::new();
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to persist");
            drop(oversized);

            // Simulate crash: truncate INDEX but leave GLOB intact
            // This creates orphan data in glob (glob ahead of index)
            let (blob, _size) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Keep only first 2 index entries (2 full pages)
            // Physical page size = logical (20) + CRC record (12) = 32 bytes
            let physical_page_size = (TestEntry::SIZE + 12) as u64;
            blob.resize(2 * physical_page_size)
                .await
                .expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - glob has orphan data from entry 3
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid
            for i in 0..2u8 {
                let (position, offset, size) = locations[i as usize];
                let entry = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // Entry at position 2 should fail (index was truncated)
            assert!(oversized.get(1, 2).await.is_err());

            // Append new entries - should work despite orphan data in glob
            let mut new_locations = Vec::new();
            for i in 10..13u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append after recovery");

                // New entries start at position 2 (after the 2 valid entries)
                assert_eq!(position, (i - 10 + 2) as u64);
                new_locations.push((position, offset, size, i));

                // Verify we can read the new entry
                let retrieved = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(retrieved.id, i as u64);

                let retrieved_value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(retrieved_value, value);
            }

            // Sync and restart again to verify persistence with orphan data
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Reinitialize after adding data on top of orphan glob data
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("third"), cfg)
                    .await
                    .expect("Failed to reinit after append");

            // Read all valid entries in the index
            // First 2 entries from original data
            for i in 0..2u8 {
                let (position, offset, size) = locations[i as usize];
                let entry = oversized.get(1, position).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // New entries added after recovery
            for (position, offset, size, expected_id) in &new_locations {
                let entry = oversized
                    .get(1, *position)
                    .await
                    .expect("Failed to get new entry after restart");
                assert_eq!(entry.id, *expected_id as u64);

                let value = oversized
                    .get_value(1, *offset, *size)
                    .await
                    .expect("Failed to get new value after restart");
                assert_eq!(value, [*expected_id; 16]);
            }

            // Verify total entry count: 2 original + 3 new = 5
            assert!(oversized.get(1, 4).await.is_ok());
            assert!(oversized.get(1, 5).await.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_partial_index_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 3 entries
            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Simulate crash during write: truncate index to partial entry
            // Each entry is TestEntry::SIZE (20) + 4 (CRC32) = 24 bytes
            // Truncate to 3 full entries + 10 bytes of partial entry
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let partial_size = 3 * 24 + 10; // 3 full entries + partial
            blob.resize(partial_size).await.expect("Failed to resize");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should handle partial entry gracefully
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 3 entries should still be valid
            for i in 0..3u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entry 3 should not exist (partial entry was removed)
            assert!(oversized.get(1, 3).await.is_err());

            // Append new entry after recovery
            let value: TestValue = [42; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 3);

            // Verify we can read the new entry
            let retrieved = oversized.get(1, 3).await.expect("Failed to get new entry");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get new value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_only_partial_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with single entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            (oversized, _, _, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Truncate index to only partial data (less than one full entry)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(10).await.expect("Failed to resize"); // Less than chunk size
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should handle gracefully (rewind to 0)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // No entries should exist
            assert!(oversized.get(1, 0).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 0);

            let retrieved = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_crash_during_rewind_index_ahead() {
        // Simulates crash where index was rewound but glob wasn't
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so each entry is exactly one page.
            // This allows truncating by entry count to equal truncating by full pages,
            // maintaining page-level integrity.
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Simulate crash during rewind: truncate index to 2 entries but leave glob intact
            // This simulates: rewind(index) succeeded, crash before rewind(glob)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Physical page size = logical (20) + CRC record (12) = 32 bytes
            let physical_page_size = (TestEntry::SIZE + 12) as u64;
            blob.resize(2 * physical_page_size)
                .await
                .expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - recovery should succeed (glob has orphan data)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid
            for i in 0..2u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entries 2-4 should be gone (index was truncated)
            assert!(oversized.get(1, 2).await.is_err());

            // Should be able to append new entries
            let pos;
            (oversized, pos, _, _) = oversized
                .append(1, TestEntry::new(100, 0, 0), &[100u8; 16])
                .await
                .expect("Failed to append");
            assert_eq!(pos, 2);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_crash_during_rewind_glob_ahead() {
        // Simulates crash where glob was rewound but index wasn't
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Simulate crash during rewind: truncate glob to 2 entries but leave index intact
            // This simulates: rewind(glob) succeeded, crash before rewind(index)
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(locations[1].1, locations[1].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - recovery should detect index entries pointing beyond glob
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should be valid (index rewound to match glob)
            for i in 0..2u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Entries 2-4 should be gone (index rewound during recovery)
            assert!(oversized.get(1, 2).await.is_err());

            // Should be able to append after recovery
            let value: TestValue = [99; 16];
            let entry = TestEntry::new(100, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 2);

            let retrieved = oversized.get(1, 2).await.expect("Failed to get");
            assert_eq!(retrieved.id, 100);
            let retrieved_value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, value);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_get_value_invalid_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (offset, _size);
            (oversized, _, offset, _size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Size 0 - should fail
            assert!(oversized.get_value(1, offset, 0).await.is_err());

            // Size < value size - should fail with codec error, checksum mismatch, or
            // insufficient length (if size < 4 bytes for checksum)
            for size in 1..4u32 {
                let result = oversized.get_value(1, offset, size).await;
                assert!(
                    matches!(
                        result,
                        Err(Error::Codec(_))
                            | Err(Error::ChecksumMismatch(_, _))
                            | Err(Error::Runtime(_))
                    ),
                    "expected error, got: {:?}",
                    result
                );
            }

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_oversized_get_value_wrong_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (offset, correct_size);
            (oversized, _, offset, correct_size) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Size too small - will fail to decode or checksum mismatch
            // (checksum mismatch can occur because we read wrong bytes as the checksum)
            let result = oversized.get_value(1, offset, correct_size - 1).await;
            assert!(
                matches!(
                    result,
                    Err(Error::Codec(_)) | Err(Error::ChecksumMismatch(_, _))
                ),
                "expected Codec or ChecksumMismatch error, got: {:?}",
                result
            );

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_values_has_orphan_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with sections 1 and 2
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=2 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Manually create an orphan value section (section 3) without corresponding index
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");
            let orphan_value: TestValue = [99; 16];
            (glob, _, _) = glob
                .append(3, &orphan_value)
                .await
                .expect("Failed to append orphan");
            glob = glob.sync(3).await.expect("Failed to sync glob");
            drop(glob);

            // Reinitialize - should detect and remove the orphan section
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Sections 1 and 2 should still be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(2, 0).await.is_ok());

            // Newest section should be 2 (orphan was removed)
            assert_eq!(oversized.newest_section(), Some(2));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_values_has_multiple_orphan_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let batches = Arc::new(Mutex::new(Vec::new()));
            let context = RecordingContext {
                inner: context,
                batches: batches.clone(),
            };
            let cfg = test_cfg(&context);

            // Create and populate with only section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            (oversized, _, _, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Manually create multiple orphan value sections (2, 3, 4)
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in 2u64..=4 {
                let orphan_value: TestValue = [section as u8; 16];
                (glob, _, _) = glob
                    .append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob = glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Reinitialize - should detect and remove all orphan sections
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 should still be valid
            assert!(oversized.get(1, 0).await.is_ok());

            // Newest section should be 1 (orphans removed)
            assert_eq!(oversized.newest_section(), Some(1));
            assert_eq!(
                *batches.lock(),
                vec![vec![
                    RemoveTarget::Blob {
                        partition: cfg.value_partition.clone(),
                        name: 2u64.to_be_bytes().to_vec(),
                    },
                    RemoveTarget::Blob {
                        partition: cfg.value_partition.clone(),
                        name: 3u64.to_be_bytes().to_vec(),
                    },
                    RemoveTarget::Blob {
                        partition: cfg.value_partition.clone(),
                        name: 4u64.to_be_bytes().to_vec(),
                    },
                ]]
            );

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_index_empty_but_values_exist() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Manually create value sections without any index entries
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in 1u64..=3 {
                let orphan_value: TestValue = [section as u8; 16];
                (glob, _, _) = glob
                    .append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob = glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Initialize oversized - should remove all orphan value sections
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // No sections should exist
            assert_eq!(oversized.newest_section(), None);
            assert_eq!(oversized.oldest_section(), None);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_orphan_section_append_after() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            let (offset1, size1);
            (oversized, _, offset1, size1) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Manually create orphan value sections (2, 3)
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in 2u64..=3 {
                let orphan_value: TestValue = [section as u8; 16];
                (glob, _, _) = glob
                    .append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob = glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Reinitialize - should remove orphan sections
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 should still be valid
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 1);
            let value = oversized
                .get_value(1, offset1, size1)
                .await
                .expect("Failed to get value");
            assert_eq!(value, [1; 16]);

            // Should be able to append to section 2 after recovery
            let new_value: TestValue = [42; 16];
            let new_entry = TestEntry::new(42, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(2, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");
            assert_eq!(pos, 0);

            // Verify the new entry
            let retrieved = oversized.get(2, 0).await.expect("Failed to get");
            assert_eq!(retrieved.id, 42);
            let retrieved_value = oversized
                .get_value(2, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(retrieved_value, new_value);

            // Sync and restart to verify persistence
            oversized = oversized.sync(2).await.expect("Failed to sync");
            drop(oversized);

            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("third"), cfg)
                    .await
                    .expect("Failed to reinit after append");

            // Both sections should be valid
            assert!(oversized.get(1, 0).await.is_ok());
            assert!(oversized.get(2, 0).await.is_ok());
            assert_eq!(oversized.newest_section(), Some(2));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_no_orphan_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate with sections 1, 2, 3 (no orphans)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in 1u64..=3 {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Reinitialize - no orphan cleanup needed
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // All sections should be valid
            for section in 1u64..=3 {
                let entry = oversized.get(section, 0).await.expect("Failed to get");
                assert_eq!(entry.id, section);
            }
            assert_eq!(oversized.newest_section(), Some(3));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_orphan_with_empty_index_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate section 1 with entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            (oversized, _, _, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");
            drop(oversized);

            // Manually create orphan value section 2
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");
            let orphan_value: TestValue = [2; 16];
            (glob, _, _) = glob
                .append(2, &orphan_value)
                .await
                .expect("Failed to append orphan");
            glob = glob.sync(2).await.expect("Failed to sync glob");
            drop(glob);

            // Now truncate index section 1 to 0 (making it empty but still tracked)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should handle empty index section and remove orphan value section
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Section 1 should exist but have no entries (empty after truncation)
            assert!(oversized.get(1, 0).await.is_err());

            // Orphan section 2 should be removed
            assert_eq!(oversized.newest_section(), Some(1));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_orphan_sections_with_gaps() {
        // Test non-contiguous sections: index has [1, 3, 5], values has [1, 2, 3, 4, 5, 6]
        // Orphan sections 2, 4, 6 should be removed
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create index with sections 1, 3, 5 (gaps)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for section in [1u64, 3, 5] {
                let value: TestValue = [section as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Manually create orphan value sections 2, 4, 6 (filling gaps and beyond)
            let glob_cfg = GlobConfig {
                partition: cfg.value_partition.clone(),
                compression: cfg.compression,
                codec_config: (),
                write_buffer: cfg.value_write_buffer,
            };
            let mut glob: Glob<_, TestValue> = Glob::init(context.child("glob"), glob_cfg)
                .await
                .expect("Failed to init glob");

            for section in [2u64, 4, 6] {
                let orphan_value: TestValue = [section as u8; 16];
                (glob, _, _) = glob
                    .append(section, &orphan_value)
                    .await
                    .expect("Failed to append orphan");
                glob = glob.sync(section).await.expect("Failed to sync glob");
            }
            drop(glob);

            // Reinitialize - should remove orphan sections 2, 4, 6
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg)
                    .await
                    .expect("Failed to reinit");

            // Sections 1, 3, 5 should still be valid
            for section in [1u64, 3, 5] {
                let entry = oversized.get(section, 0).await.expect("Failed to get");
                assert_eq!(entry.id, section);
            }

            // Verify only sections 1, 3, 5 exist (orphans removed)
            assert_eq!(oversized.oldest_section(), Some(1));
            assert_eq!(oversized.newest_section(), Some(5));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_glob_trailing_garbage_truncated() {
        // Tests the bug fix: when value is written to glob but index entry isn't
        // (crash after value write, before index write), recovery should truncate
        // the glob trailing garbage so subsequent appends start at correct offset.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            // Append 2 entries
            let mut locations = Vec::new();
            for i in 0..2u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Record where next entry SHOULD start (end of entry 1)
            let expected_next_offset = byte_end(locations[1].1, locations[1].2);
            drop(oversized);

            // Simulate crash: write garbage to glob (simulating partial value write)
            let (blob, size) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, expected_next_offset);

            // Write 100 bytes of garbage (simulating partial/failed value write)
            let garbage = vec![0xDE; 100];
            blob.write_at_sync(size, garbage)
                .await
                .expect("Failed to write garbage");
            drop(blob);

            // Verify glob now has trailing garbage
            let (blob, new_size) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(new_size, expected_next_offset + 100);
            drop(blob);

            // Reinitialize - should truncate the trailing garbage
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First 2 entries should still be valid
            for i in 0..2u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);
            }

            // Append new entry - should start at expected_next_offset, NOT at garbage end
            let new_value: TestValue = [99; 16];
            let new_entry = TestEntry::new(99, 0, 0);
            let (pos, offset, _size);
            (oversized, pos, offset, _size) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");

            // Verify position is 2 (after the 2 existing entries)
            assert_eq!(pos, 2);

            // Verify offset is at expected_next_offset (garbage was truncated)
            assert_eq!(offset, expected_next_offset);

            // Verify we can read the new entry
            let retrieved = oversized.get(1, 2).await.expect("Failed to get new entry");
            assert_eq!(retrieved.id, 99);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_entry_with_overflow_offset() {
        // Tests that an entry with offset near u64::MAX that would overflow
        // when added to size is detected as invalid during recovery.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use page size = entry size so one entry per page
            let cfg = Config {
                index_partition: "test-index".into(),
                value_partition: "test-values".into(),
                index_page_cache: CacheRef::from_pooler(
                    &context,
                    NZU16!(TestEntry::SIZE as u16),
                    NZUsize!(8),
                ),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: (),
            };

            // Create and populate with valid entry
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            (oversized, _, _, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to persist");
            drop(oversized);

            // Build a corrupted entry with offset near u64::MAX that would overflow.
            // We need to write a valid page (with correct page-level CRC) containing
            // the semantically-invalid entry data.
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Build entry data: id (8) + value_offset (8) + value_size (4) = 20 bytes
            let mut entry_data = Vec::new();
            1u64.write(&mut entry_data); // id
            (u64::MAX - 10).write(&mut entry_data); // value_offset (near max)
            100u32.write(&mut entry_data); // value_size (offset + size overflows)
            assert_eq!(entry_data.len(), TestEntry::SIZE);

            // Build page-level CRC record (12 bytes):
            // len1 (2) + crc1 (4) + len2 (2) + crc2 (4)
            let crc = Crc32::checksum(&entry_data);
            let len1 = TestEntry::SIZE as u16;
            let mut crc_record = Vec::new();
            crc_record.extend_from_slice(&len1.to_be_bytes()); // len1
            crc_record.extend_from_slice(&crc.to_be_bytes()); // crc1
            crc_record.extend_from_slice(&0u16.to_be_bytes()); // len2 (unused)
            crc_record.extend_from_slice(&0u32.to_be_bytes()); // crc2 (unused)
            assert_eq!(crc_record.len(), 12);

            // Write the complete physical page: entry_data + crc_record
            let mut page = entry_data;
            page.extend_from_slice(&crc_record);
            blob.write_at_sync(0, page)
                .await
                .expect("Failed to write corrupted page");
            drop(blob);

            // Reinitialize - recovery should detect the invalid entry
            // (offset + size would overflow, and even with saturating_add it exceeds glob_size)
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // The corrupted entry should have been rewound (invalid)
            assert!(oversized.get(1, 0).await.is_err());

            // Should be able to append after recovery
            let new_value: TestValue = [99; 16];
            let new_entry = TestEntry::new(99, 0, 0);
            let (pos, new_offset);
            (oversized, pos, new_offset, _) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");

            // Position should be 0 (corrupted entry was removed)
            assert_eq!(pos, 0);
            // Offset should be 0 (glob was truncated to 0)
            assert_eq!(new_offset, 0);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_preserves_legacy_orphan_value_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Build the legacy state: an empty index section retained its old value bytes, then
            // the pre-watermark implementation appended and durably synced a new first entry
            // after that orphan prefix.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(1, 0, 0), &[1; 16])
                .await
                .expect("Failed to append old value");
            oversized = oversized.sync(1).await.expect("Failed to sync old value");
            drop(oversized);

            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open index");
            blob.resize(0).await.expect("Failed to empty index");
            blob.sync().await.expect("Failed to sync empty index");
            drop(blob);

            let mut oversized =
                Oversized::<_, TestEntry, TestValue>::open(context.child("legacy"), cfg.clone())
                    .await
                    .expect("Failed to open legacy journal");
            let (offset, size);
            (oversized, _, offset, size) = oversized
                .append(1, TestEntry::new(2, 0, 0), &[2; 16])
                .await
                .expect("Failed to append legacy entry");
            assert!(offset > 0, "legacy entry must follow the orphan prefix");
            oversized = oversized
                .sync(1)
                .await
                .expect("Failed to persist legacy entry");
            drop(oversized);

            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("recovered"), cfg)
                    .await
                    .expect("Failed to recover legacy journal");
            assert_eq!(oversized.get(1, 0).await.expect("entry").id, 2);
            assert_eq!(
                oversized.get_value(1, offset, size).await.expect("value"),
                [2; 16]
            );
            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_empty_section_persistence() {
        // Tests that sections that become empty (all entries removed/rewound)
        // are handled correctly across restart cycles.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create and populate section 1 with entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            for i in 0..3u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                (oversized, _, _, _) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Also create section 2 to ensure it survives
            let value2: TestValue = [10; 16];
            let entry2 = TestEntry::new(10, 0, 0);
            (oversized, _, _, _) = oversized
                .append(2, entry2, &value2)
                .await
                .expect("Failed to append to section 2");
            oversized = oversized.sync(2).await.expect("Failed to sync section 2");
            drop(oversized);

            // Truncate section 1's index to 0 (making it empty)
            let (blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(0).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // First restart - recovery should handle empty section 1
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // Section 1 should exist but have no entries
            assert!(oversized.get(1, 0).await.is_err());

            // Section 2 should still be valid
            let entry = oversized.get(2, 0).await.expect("Failed to get section 2");
            assert_eq!(entry.id, 10);

            // Section 1 should still be tracked (blob exists but is empty)
            assert_eq!(oversized.oldest_section(), Some(1));

            // Append to empty section 1. Recovery removed its orphaned value suffix.
            let new_value: TestValue = [99; 16];
            let new_entry = TestEntry::new(99, 0, 0);
            let (pos, offset, size);
            (oversized, pos, offset, size) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append to empty section");
            assert_eq!(pos, 0);
            assert_eq!(offset, 0);
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Verify the new entry is readable despite orphan data before it
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 99);
            let value = oversized
                .get_value(1, offset, size)
                .await
                .expect("Failed to get value");
            assert_eq!(value, new_value);

            drop(oversized);

            // Second restart - verify persistence
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("third"), cfg.clone())
                    .await
                    .expect("Failed to reinit again");

            // Section 1's new entry should be valid
            let entry = oversized.get(1, 0).await.expect("Failed to get");
            assert_eq!(entry.id, 99);

            // Section 2 should still be valid
            let entry = oversized.get(2, 0).await.expect("Failed to get section 2");
            assert_eq!(entry.id, 10);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_get_value_size_equals_crc_size() {
        // Tests the boundary condition where size = 4 (just CRC, no data).
        // This should fail because there's no actual data to decode.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let offset;
            (oversized, _, offset, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Size = 4 (exactly CRC_SIZE) means 0 bytes of actual data
            // This should fail with ChecksumMismatch or decode error
            let result = oversized.get_value(1, offset, 4).await;
            assert!(result.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_get_value_size_just_over_crc() {
        // Tests size = 5 (CRC + 1 byte of data).
        // This should fail because the data is too short to decode.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let value: TestValue = [42; 16];
            let entry = TestEntry::new(1, 0, 0);
            let offset;
            (oversized, _, offset, _) = oversized
                .append(1, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(1).await.expect("Failed to sync");

            // Size = 5 means 1 byte of actual data (after stripping CRC)
            // This should fail with checksum mismatch since we're reading wrong bytes
            let result = oversized.get_value(1, offset, 5).await;
            assert!(result.is_err());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_maximum_section_numbers() {
        // Test recovery with very large section numbers near u64::MAX to check
        // for overflow edge cases in section arithmetic.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Use section numbers near u64::MAX
            let large_sections = [u64::MAX - 3, u64::MAX - 2, u64::MAX - 1];

            // Create and populate with large section numbers
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for &section in &large_sections {
                let value: TestValue = [(section & 0xFF) as u8; 16];
                let entry = TestEntry::new(section, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(section, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((section, (position, offset, size)));
                oversized = oversized.sync(section).await.expect("Failed to sync");
            }
            drop(oversized);

            // Simulate crash: truncate glob for middle section
            let middle_section = large_sections[1];
            let (blob, size) = context
                .open(&cfg.value_partition, &middle_section.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size / 2).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Reinitialize - should recover without overflow panics
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit");

            // First and last sections should still be valid
            let entry = oversized
                .get(large_sections[0], 0)
                .await
                .expect("Failed to get first section");
            assert_eq!(entry.id, large_sections[0]);

            let entry = oversized
                .get(large_sections[2], 0)
                .await
                .expect("Failed to get last section");
            assert_eq!(entry.id, large_sections[2]);

            // Middle section should have been rewound (no entries)
            assert!(oversized.get(middle_section, 0).await.is_err());

            // Verify we can still append to these large sections
            let new_value: TestValue = [0xAB; 16];
            let new_entry = TestEntry::new(999, 0, 0);
            (oversized, _, _, _) = oversized
                .append(middle_section, new_entry, &new_value)
                .await
                .expect("Failed to append after recovery");

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_recovery_crash_during_recovery_rewind() {
        // Tests a nested crash scenario: initial crash leaves inconsistent state,
        // then a second crash occurs during recovery's rewind operation.
        // This simulates the worst-case where recovery itself is interrupted.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Phase 1: Create valid data with 5 entries
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to init");

            let mut locations = Vec::new();
            for i in 0..5u8 {
                let value: TestValue = [i; 16];
                let entry = TestEntry::new(i as u64, 0, 0);
                let (position, offset, size);
                (oversized, position, offset, size) = oversized
                    .append(1, entry, &value)
                    .await
                    .expect("Failed to append");
                locations.push((position, offset, size));
            }
            oversized = oversized.sync(1).await.expect("Failed to sync");
            let chunk_size = FixedJournal::<deterministic::Context, TestEntry>::CHUNK_SIZE as u64;
            drop(oversized);

            // Phase 2: Simulate first crash - truncate glob to lose last 2 entries
            let (blob, _) = context
                .open(&cfg.value_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let keep_size = byte_end(locations[2].1, locations[2].2);
            blob.resize(keep_size).await.expect("Failed to truncate");
            blob.sync().await.expect("Failed to sync");
            drop(blob);

            // Phase 3: Simulate crash during recovery's rewind
            // Recovery would try to rewind index from 5 entries to 3 entries.
            // Simulate partial rewind by manually truncating index to 4 entries
            // (as if crash occurred mid-rewind).
            let (index_blob, _) = context
                .open(&cfg.index_partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open index blob");
            let partial_rewind_size = 4 * chunk_size; // 4 entries instead of 3
            index_blob
                .resize(partial_rewind_size)
                .await
                .expect("Failed to resize");
            index_blob.sync().await.expect("Failed to sync");
            drop(index_blob);

            // Phase 4: Second recovery attempt should handle the inconsistent state
            // Index has 4 entries, but glob only supports 3.
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to reinit after nested crash");

            // Only first 3 entries should be valid (recovery should rewind again)
            for i in 0..3u8 {
                let entry = oversized.get(1, i as u64).await.expect("Failed to get");
                assert_eq!(entry.id, i as u64);

                let (_, offset, size) = locations[i as usize];
                let value = oversized
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value");
                assert_eq!(value, [i; 16]);
            }

            // Entry 3 should not exist (index was rewound to match glob)
            assert!(oversized.get(1, 3).await.is_err());

            // Verify append works after nested crash recovery
            let new_value: TestValue = [0xFF; 16];
            let new_entry = TestEntry::new(100, 0, 0);
            let (pos, offset, _size);
            (oversized, pos, offset, _size) = oversized
                .append(1, new_entry, &new_value)
                .await
                .expect("Failed to append");
            assert_eq!(pos, 3); // Should be position 3 (after the 3 valid entries)

            // Verify the offset starts where entry 2 ended (no gaps)
            assert_eq!(offset, byte_end(locations[2].1, locations[2].2));

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_rewind_to_zero_index_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let value: TestValue = [1; 16];
            let entry = TestEntry::new(1, 0, 0);
            (oversized, _, _, _) = oversized
                .append(0, entry, &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync(0).await.expect("Failed to sync");

            oversized = oversized
                .rewind(0, 0)
                .await
                .expect("rewind to zero index_size must not fail");

            assert_eq!(oversized.last(0).await.unwrap(), None);
            assert_eq!(oversized.size(0).unwrap(), 0);
            assert_eq!(oversized.value_size(0).await.unwrap(), 0);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_rewind_to_zero_on_missing_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            oversized = oversized
                .rewind(0, 0)
                .await
                .expect("rewind on missing section must not fail");

            assert!(matches!(
                oversized.last(0).await,
                Err(Error::SectionOutOfRange(0))
            ));
            assert_eq!(oversized.value_size(0).await.unwrap(), 0);

            oversized.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_rewind_nonzero_on_missing_section_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let result = oversized.rewind(0, 1).await;
            assert!(
                matches!(result, Err(Error::SectionOutOfRange(0))),
                "nonzero index_size on missing section must fail, got: {result:?}"
            );
        });
    }

    #[test_traced]
    fn test_rewind_section_nonzero_on_missing_section_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let result = oversized.rewind_section(0, 1).await;
            assert!(
                matches!(result, Err(Error::SectionOutOfRange(0))),
                "nonzero index_size on missing section must fail, got: {result:?}"
            );
        });
    }

    #[test_traced]
    fn test_last_pruned_section_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut oversized: Oversized<_, TestEntry, TestValue> =
                init_oversized(context, cfg).await.expect("Failed to init");

            let value: TestValue = [1; 16];
            (oversized, _, _, _) = oversized
                .append(0, TestEntry::new(1, 0, 0), &value)
                .await
                .expect("Failed to append");
            (oversized, _, _, _) = oversized
                .append(1, TestEntry::new(2, 0, 0), &value)
                .await
                .expect("Failed to append");
            oversized = oversized.sync_all().await.expect("Failed to sync");

            (oversized, _) = oversized.prune(1).await.expect("Failed to prune");

            assert!(matches!(
                oversized.last(0).await,
                Err(Error::AlreadyPrunedToSection(1))
            ));
            assert!(oversized.last(1).await.unwrap().is_some());

            oversized.destroy().await.expect("Failed to destroy");
        });
    }
}
