//! Segmented journal for fixed-size items.
//!
//! # Format
//!
//! Data is stored in one blob per section. Items are stored sequentially:
//!
//! ```text
//! +--------+--------+--------+----------+
//! | item_0 | item_1 |   ...  | item_n-1 |
//! +--------+--------+--------+----------+
//! ```
//!
//! # Sync
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. Use the
//! `sync` method to force pending data to be written.
//!
//! # Pruning
//!
//! All data must be assigned to a `section`. This allows pruning entire sections
//! (and their corresponding blobs) independently.

use super::manager::{
    AppendFactory, Config as ManagerConfig, Manager, section_from_name, stored_names,
};
use crate::journal::{Error, decode_sync};
use commonware_codec::{CodecFixed, CodecFixedShared, Copying, DecodeExt as _, ReadExt as _};
use commonware_runtime::{
    Blob, Error as RError, Handle, Metrics, ReadOptions, Storage,
    buffer::paged::{CacheRef, Replay as BlobReplay, Writer},
};
use commonware_utils::NZUsize;
use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
    num::{NonZeroU16, NonZeroUsize},
};
use tracing::{trace, warn};

/// State for replaying a single section's blob.
struct SectionReplay<B: Blob> {
    section: u64,
    reader: BlobReplay<B>,
    position: u64,
}

/// Configuration for the fixed segmented journal.
#[derive(Clone)]
pub struct Config {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,

    /// The size of the buffer used to replay each blob when the journal opens, through the
    /// [Recovery] that [Journal::preflight_floors] returns or inside [Journal::init_at_most].
    pub replay_buffer: NonZeroUsize,
}

/// The journal's state, boxed so the public [Journal] handle stays pointer-sized.
struct Inner<E: Storage + Metrics, A: CodecFixed> {
    manager: Manager<E, AppendFactory>,
    _array: PhantomData<A>,
}

impl<E: Storage + Metrics, A: CodecFixedShared> Inner<E, A> {
    /// Size of each entry.
    const CHUNK_SIZE: usize = A::SIZE;
    const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Return canonical section names in numeric order without opening writers.
    async fn stored(context: &E, cfg: &Config) -> Result<BTreeMap<u64, Vec<u8>>, Error> {
        // Recovery relies on numeric section order for checkpoint coverage and reverse deletion.
        let mut stored = BTreeMap::new();
        for name in stored_names(context, &cfg.partition).await? {
            let section = section_from_name(&name)?;
            stored.insert(section, name);
        }
        Ok(stored)
    }

    /// Prove each validation floor and capture its terminal entry without mutating storage.
    async fn preflight_floors(
        context: E,
        cfg: Config,
        minimum_items: &BTreeMap<u64, u64>,
        read_options: ReadOptions,
    ) -> Result<Recovery<E, A>, Error> {
        let stored = Self::stored(&context, &cfg).await?;
        let page_size = cfg.page_cache.page_size();
        let mut floors = BTreeMap::new();
        let mut boundaries = BTreeMap::new();

        for (&section, &items) in minimum_items {
            // Every advertised floor must name a retained, representable byte prefix.
            let Some(name) = stored.get(&section) else {
                return Err(Error::Corruption(format!(
                    "section {section} has a validation floor but no blob"
                )));
            };
            let required = items.checked_mul(Self::CHUNK_SIZE_U64).ok_or_else(|| {
                Error::Corruption(format!(
                    "section {section} validation floor {items} overflows its byte size"
                ))
            })?;
            if required == 0 {
                boundaries.insert(section, None);
                continue;
            }

            // A published marker covers only pages that a completed index/value sync or the
            // runtime's startup durability guarantee made durable. Validate the terminal index
            // page that binds the two journals.
            let (blob, _) = context.open(&cfg.partition, name).await?;
            let entry = Self::boundary(&blob, page_size, section, required).await?;
            floors.insert(section, required);
            boundaries.insert(section, Some(entry));
        }

        let buffer = cfg.replay_buffer;
        Ok(Recovery {
            boundaries,
            floors,
            finished: stored.is_empty(),
            unopened: Some((context, cfg)),
            ..Recovery::new(buffer, read_options)
        })
    }

    /// Prove every checkpoint-covered index boundary without mutating damaged storage.
    async fn preflight_restore(
        context: E,
        cfg: Config,
        section: u64,
        size: u64,
    ) -> Result<Recovery<E, A>, Error> {
        // The checkpoint can only identify a boundary between fixed-size items.
        if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::Corruption(format!(
                "section {section} checkpoint size {size} is not item-aligned"
            )));
        }

        // A non-empty current checkpoint requires its section blob to exist.
        let stored = Self::stored(&context, &cfg).await?;
        if size > 0 && !stored.contains_key(&section) {
            return Err(Error::Corruption(format!(
                "section {section} has a checkpoint but no blob"
            )));
        }

        let page_size = cfg.page_cache.page_size();
        let mut boundaries = BTreeMap::new();

        for (&candidate, name) in stored.range(..=section) {
            // Earlier sections end at their retained terminal page. The checkpoint supplies the
            // current section's exact logical boundary, which may precede an uncommitted suffix.
            let (blob, physical_size) = context.open(&cfg.partition, name).await?;
            let entry = if candidate == section {
                if size == 0 {
                    None
                } else {
                    Some(Self::boundary(&blob, page_size, section, size).await?)
                }
            } else if physical_size == 0 {
                None
            } else {
                let (logical_size, entry) = Writer::<E::Blob>::read_tail(
                    &blob,
                    physical_size,
                    page_size,
                    Self::CHUNK_SIZE,
                    ReadOptions::default(),
                )
                .await
                .map_err(|err| Self::boundary_error(candidate, physical_size, err))?;
                if !logical_size.is_multiple_of(Self::CHUNK_SIZE_U64) {
                    return Err(Error::Corruption(format!(
                        "section {candidate} is not a complete checkpoint-covered index"
                    )));
                }
                Some(A::decode(entry.coalesce()).map_err(Error::Codec)?)
            };
            boundaries.insert(candidate, entry);
        }
        boundaries.entry(section).or_insert(None);
        let buffer = cfg.replay_buffer;
        Ok(Recovery {
            boundaries,
            restore: Some((section, size)),
            unopened: Some((context, cfg)),
            ..Recovery::new(buffer, ReadOptions::default())
        })
    }

    /// Read and decode the terminal entry of a validated `size`-byte prefix.
    async fn boundary(
        blob: &E::Blob,
        page_size: NonZeroU16,
        section: u64,
        size: u64,
    ) -> Result<A, Error> {
        let entry = Writer::<E::Blob>::read_range(
            blob,
            page_size,
            size - Self::CHUNK_SIZE_U64,
            Self::CHUNK_SIZE,
            ReadOptions::default(),
        )
        .await
        .map_err(|err| Self::boundary_error(section, size, err))?;
        A::decode(entry.coalesce()).map_err(Error::Codec)
    }

    /// Classify an invalid or missing boundary as committed corruption without hiding I/O errors.
    ///
    /// `searched` is the extent the boundary read covered: the current section's logical
    /// boundary size, or an earlier section's physical blob size.
    fn boundary_error(section: u64, searched: u64, err: RError) -> Error {
        match err {
            RError::InvalidChecksum | RError::BlobInsufficientLength => Error::Corruption(format!(
                "section {section} does not retain a valid durable boundary within {searched} bytes"
            )),
            err => err.into(),
        }
    }

    /// Open the writer of every stored section through `ceiling`. Opening a writer discards a
    /// torn tail page. Later sections stay closed until a truncation removes them.
    async fn init(context: E, cfg: Config, ceiling: u64) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: AppendFactory {
                write_buffer: cfg.write_buffer,
                page_cache_ref: cfg.page_cache,
            },
        };
        Ok(Self {
            manager: Manager::init_bounded(context, manager_cfg, ceiling).await?,
            _array: PhantomData,
        })
    }

    /// See [Journal::append].
    async fn append(&mut self, section: u64, item: &A) -> Result<u64, Error> {
        // Buffer the item in place when it fits. Otherwise own the writer across the flush.
        let blob = self.manager.get_or_create(section).await?;
        let offset = match blob.try_append_value(item) {
            Some(offset) => offset,
            None => {
                // Return the writer to the manager only after the owned append succeeds.
                let blob = self.manager.take(section).await?;
                let (blob, offset) = blob.append_owned(item.encode_mut().into()).await?;
                self.manager.put(section, blob);
                offset
            }
        };
        if !offset.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::InvalidBlobSize(section, offset));
        }
        let position = offset / Self::CHUNK_SIZE_U64;
        trace!(section, position, "appended item");

        Ok(position)
    }

    /// See [Journal::get].
    async fn get(&self, section: u64, position: u64) -> Result<A, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let offset = position
            .checked_mul(Self::CHUNK_SIZE_U64)
            .ok_or(Error::ItemOutOfRange(position))?;

        // The read validates bounds against the blob's logical size.
        let buf = blob
            .read_at(offset, Self::CHUNK_SIZE)
            .await
            .map_err(|err| match err {
                commonware_runtime::Error::BlobInsufficientLength
                | commonware_runtime::Error::OffsetOverflow => Error::ItemOutOfRange(position),
                err => Error::Runtime(err),
            })?;
        A::decode(buf.coalesce()).map_err(Error::Codec)
    }

    /// See [Journal::get_many].
    async fn get_many(
        &self,
        section: u64,
        positions: &[u64],
        buf: &mut [u8],
    ) -> Result<(Vec<A>, usize), Error> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        if positions.is_empty() {
            return Ok((Vec::new(), 0));
        }
        assert!(
            buf.len() >= positions.len() * Self::CHUNK_SIZE,
            "get_many requires buf.len() >= positions.len() * CHUNK_SIZE"
        );
        let buf = &mut buf[..positions.len() * Self::CHUNK_SIZE];
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let mut offsets = positions.to_vec();
        for offset in &mut offsets {
            *offset = offset
                .checked_mul(Self::CHUNK_SIZE_U64)
                .ok_or(Error::ItemOutOfRange(*offset))?;
        }

        let hits = blob
            .read_many_into(buf, &offsets, NZUsize!(Self::CHUNK_SIZE))
            .await?;

        let mut items = Vec::with_capacity(positions.len());
        for i in 0..positions.len() {
            let slice = &buf[i * Self::CHUNK_SIZE..(i + 1) * Self::CHUNK_SIZE];
            items.push(A::decode(Copying(slice)).map_err(Error::Codec)?);
        }
        Ok((items, hits))
    }

    /// See [Journal::try_get_sync].
    fn try_get_sync(&self, section: u64, position: u64) -> Option<A> {
        let blob = self.manager.get(section).ok()??;
        let offset = position.checked_mul(Self::CHUNK_SIZE_U64)?;
        let remaining = blob.size().checked_sub(offset)?;
        if remaining < Self::CHUNK_SIZE_U64 {
            return None;
        }
        decode_sync::<A>(|buf| blob.try_read_sync_into(buf, offset))
    }

    /// See [Journal::last].
    async fn last(&self, section: u64) -> Result<Option<A>, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let size = blob.size();
        if size < Self::CHUNK_SIZE_U64 {
            return Ok(None);
        }

        let last_position = (size / Self::CHUNK_SIZE_U64) - 1;
        let offset = last_position * Self::CHUNK_SIZE_U64;
        let buf = blob.read_at(offset, Self::CHUNK_SIZE).await?;
        A::decode(buf.coalesce()).map_err(Error::Codec).map(Some)
    }

    /// See [Journal::sync].
    async fn sync(mut self: Box<Self>, sections: impl crate::Sections) -> Result<Box<Self>, Error> {
        self.manager = self.manager.sync(sections).await?;
        Ok(self)
    }

    /// See [Journal::start_sync].
    async fn start_sync(
        mut self: Box<Self>,
        sections: impl crate::Sections,
    ) -> Result<(Box<Self>, Handle<()>), Error> {
        let (manager, handle) = self.manager.start_sync(sections).await?;
        self.manager = manager;
        Ok((self, handle))
    }

    /// See [Journal::sync_all].
    async fn sync_all(mut self: Box<Self>) -> Result<Box<Self>, Error> {
        self.manager = self.manager.sync_all().await?;
        Ok(self)
    }

    /// See [Journal::prune].
    async fn prune(mut self: Box<Self>, min: u64) -> Result<(Box<Self>, bool), Error> {
        let (manager, pruned) = self.manager.prune(min).await?;
        self.manager = manager;
        Ok((self, pruned))
    }

    /// See [Journal::pruned].
    const fn pruned(&self, section: u64) -> bool {
        self.manager.pruned(section)
    }

    /// See [Journal::oldest_section].
    fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// See [Journal::newest_section].
    fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// See [Journal::sections].
    fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.manager.sections()
    }

    /// See [Journal::section_len].
    fn section_len(&self, section: u64) -> Result<u64, Error> {
        let size = self.manager.size(section)?;
        Ok(size / Self::CHUNK_SIZE_U64)
    }

    /// See [Journal::size].
    fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section)
    }

    /// Truncate one unpublished section without affecting other sections.
    async fn truncate_pending_section(
        mut self: Box<Self>,
        section: u64,
        size: u64,
    ) -> Result<Box<Self>, Error> {
        self.manager = self.manager.truncate_pending_section(section, size).await?;
        Ok(self)
    }

    /// See [Journal::destroy].
    async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }

    /// See [Journal::clear].
    async fn clear(mut self: Box<Self>) -> Result<Box<Self>, Error> {
        self.manager = self.manager.clear().await?;
        Ok(self)
    }
}

/// A segmented journal with fixed-size entries.
///
/// Each section is stored in a separate blob. Within each blob, items are fixed-size.
///
/// # Repair
///
/// Opening a section reads its blob's last page to determine its length. If that page is
/// incomplete or fails its checksum check, opening searches backward for a valid page and
/// discards the damaged suffix. It does not scan the earlier pages.
///
/// Replay checks items in order. Torn pages or incomplete trailing items cause the section to be
/// truncated to the last complete, validated item.
///
/// Each section has a validation floor marking the prefix already known to be durable. Recovery
/// must preserve that prefix. Damage requiring truncation below the floor is an error.
///
/// A journal is available only once its contents are replayed or proven by a checkpoint.
/// [Journal::preflight_floors] returns a [Recovery] that replays and repairs every section from
/// position zero, and [Recovery::finish] returns the journal only after that replay completes.
/// [Journal::preflight_restore] returns a [Recovery] with nothing to replay: its checkpoint
/// proves the retained prefix, and [Recovery::finish] truncates the journal to it.
///
/// Mutating functions consume the journal and return it only on success: an error (or a dropped
/// future) destroys the handle. Mutations on pruned sections fail with
/// [Error::AlreadyPrunedToSection] without mutating. Check [Journal::pruned] first to keep the
/// handle.
pub struct Journal<E: Storage + Metrics, A: CodecFixed>(Box<Inner<E, A>>);

impl<E: Storage + Metrics, A: CodecFixedShared> std::fmt::Debug for Journal<E, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("oldest_section", &self.oldest_section())
            .field("newest_section", &self.newest_section())
            .finish_non_exhaustive()
    }
}

impl<E: Storage + Metrics, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry.
    pub const CHUNK_SIZE: usize = Inner::<E, A>::CHUNK_SIZE;

    /// Open through `(section, logical byte end)` and remove later sections.
    ///
    /// An end inside an item rounds down. All retained data is validated before returning. Payload
    /// reads stop at the bound, but every section name is validated, including names above it.
    pub async fn init_at_most(
        context: E,
        cfg: Config,
        section: u64,
        end: u64,
    ) -> Result<Self, Error> {
        let replay_buffer = cfg.replay_buffer;
        let mut end = end - end % Self::CHUNK_SIZE as u64;
        super::manager::truncate_paged_tail(
            &context,
            &cfg.partition,
            cfg.page_cache.page_size(),
            section,
            end,
        )
        .await?;
        let mut journal = Self(Box::new(Inner::init(context, cfg, u64::MAX).await?));

        // Resolve a torn page before truncation tries to rewrite its partial checksum.
        if end > 0
            && journal
                .0
                .manager
                .get(section)?
                .is_some_and(|blob| end < blob.size())
        {
            end = journal
                .recoverable_prefix_len_at_most(section, end, replay_buffer)
                .await?;
        }
        journal.0.manager = journal
            .0
            .manager
            .truncate_pending(section, end - end % Self::CHUNK_SIZE as u64)
            .await?;
        let mut recovery = journal.recover(replay_buffer).await?;
        while let Some(item) = recovery.next().await {
            item?;
        }
        recovery.finish().await
    }

    /// Consumes the opened journal into a [Recovery] that replays every section with no floor.
    async fn recover(self, buffer: NonZeroUsize) -> Result<Recovery<E, A>, Error> {
        let mut recovery = Recovery::new(buffer, ReadOptions::default());
        recovery.begin(self).await?;
        Ok(recovery)
    }

    /// Prove validation floors without opening a writer or mutating their blobs, and return the
    /// [Recovery] that replays every section.
    ///
    /// `minimum_items` maps a section to the number of items its durable marker protects. An
    /// empty map opens every section with no floor.
    ///
    /// The caller must drain the recovery and call [Recovery::finish] to obtain the journal. Each
    /// section is replayed from position zero with a buffer of [Config::replay_buffer] bytes,
    /// allocated lazily as the recovery advances. Every backing blob read performed by the replay
    /// uses `read_options`, including reads after advancing to another section.
    pub async fn preflight_floors(
        context: E,
        cfg: Config,
        minimum_items: &BTreeMap<u64, u64>,
        read_options: ReadOptions,
    ) -> Result<Recovery<E, A>, Error> {
        Inner::preflight_floors(context, cfg, minimum_items, read_options).await
    }

    /// Return the longest item-aligned prefix of `section` within `end` that lies within validated
    /// page prefixes, or `end` itself when the section does not exist. Reads only pages that
    /// intersect the prefix below `end`.
    pub(crate) async fn recoverable_prefix_len_at_most(
        &self,
        section: u64,
        end: u64,
        buffer: NonZeroUsize,
    ) -> Result<u64, Error> {
        let Some(blob) = self.0.manager.get(section)? else {
            return Ok(end);
        };
        let recoverable = blob
            .recoverable_prefix_len_at_most(0, end, buffer, ReadOptions::default())
            .await?;
        Ok(recoverable - recoverable % Self::CHUNK_SIZE as u64)
    }

    /// Validate the terminal boundary of every checkpoint-covered section without mutating
    /// storage, and return the [Recovery] that restores the checkpoint. Interior pages are not
    /// read.
    ///
    /// `size` is the logical byte size of `section` and must be a multiple of
    /// [Self::CHUNK_SIZE]. The checkpoint proves the retained items, so the recovery replays
    /// nothing: [Recovery::finish] durably truncates `section` to `size` bytes and removes every
    /// later section.
    pub async fn preflight_restore(
        context: E,
        cfg: Config,
        section: u64,
        size: u64,
    ) -> Result<Recovery<E, A>, Error> {
        Inner::preflight_restore(context, cfg, section, size).await
    }

    /// Append a new item to the journal in the given section.
    ///
    /// Returns the position of the item within the section (0-indexed).
    pub async fn append(mut self, section: u64, item: &A) -> Result<(Self, u64), Error> {
        let position = self.0.append(section, item).await?;
        Ok((self, position))
    }

    /// Read the item at the given section and position.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    /// - [Error::ItemOutOfRange] if the position is beyond the blob size.
    pub async fn get(&self, section: u64, position: u64) -> Result<A, Error> {
        self.0.get(section, position).await
    }

    /// Read multiple items from the same section into a caller buffer.
    ///
    /// `buf` must be at least `positions.len() * CHUNK_SIZE` bytes. All positions must be
    /// strictly increasing and within the section's bounds.
    ///
    /// Returns the decoded items and the number served without a blob read (page cache or tip
    /// buffer hits).
    pub async fn get_many(
        &self,
        section: u64,
        positions: &[u64],
        buf: &mut [u8],
    ) -> Result<(Vec<A>, usize), Error> {
        self.0.get_many(section, positions, buf).await
    }

    /// Get an item if it can be done synchronously (e.g. without I/O), returning `None` otherwise.
    pub fn try_get_sync(&self, section: u64, position: u64) -> Option<A> {
        self.0.try_get_sync(section, position)
    }

    /// Read the last item in a section, if any.
    ///
    /// Returns `Ok(None)` if the section is empty.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    pub async fn last(&self, section: u64) -> Result<Option<A>, Error> {
        self.0.last(section).await
    }

    /// Sync the given `sections` to storage.
    pub async fn sync(mut self, sections: impl crate::Sections) -> Result<Self, Error> {
        self.0 = self.0.sync(sections).await?;
        Ok(self)
    }

    /// Start syncing the given `sections` to storage.
    ///
    /// An error reported by the returned [Handle] is fatal to the journal: the caller
    /// must stop using the returned journal.
    pub async fn start_sync(
        mut self,
        sections: impl crate::Sections,
    ) -> Result<(Self, Handle<()>), Error> {
        let (inner, handle) = self.0.start_sync(sections).await?;
        self.0 = inner;
        Ok((self, handle))
    }

    /// Sync all sections to storage.
    pub async fn sync_all(mut self) -> Result<Self, Error> {
        self.0 = self.0.sync_all().await?;
        Ok(self)
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(mut self, min: u64) -> Result<(Self, bool), Error> {
        let (inner, pruned) = self.0.prune(min).await?;
        self.0 = inner;
        Ok((self, pruned))
    }

    /// Returns true when `section` is below the prune floor.
    ///
    /// The floor only tracks prunes from the current execution and resets at init, so a
    /// section pruned in a previous execution reports false.
    pub fn pruned(&self, section: u64) -> bool {
        self.0.pruned(section)
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.0.oldest_section()
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.0.newest_section()
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.sections()
    }

    /// Returns the number of items in the given section.
    pub fn section_len(&self, section: u64) -> Result<u64, Error> {
        self.0.section_len(section)
    }

    /// Returns the byte size of the given section.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.0.size(section)
    }

    /// Truncate only the given section to a specific byte offset.
    ///
    /// Other sections are unaffected.
    pub(crate) async fn truncate_pending_section(
        mut self,
        section: u64,
        size: u64,
    ) -> Result<Self, Error> {
        self.0 = self.0.truncate_pending_section(section, size).await?;
        Ok(self)
    }

    /// Remove all underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        self.0.destroy().await
    }

    /// Clear all data, resetting the journal to an empty state.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused.
    pub async fn clear(mut self) -> Result<Self, Error> {
        self.0 = self.0.clear().await?;
        Ok(self)
    }
}

/// Startup recovery returned by [Journal::preflight_floors] and [Journal::preflight_restore].
///
/// The recovery holds the evidence its preflight read and modifies nothing until it is asked to.
///
/// A recovery from [Journal::preflight_floors] yields `(section, position, item)` in order from
/// position zero of every section and repairs invalid trailing data as it is encountered, never
/// below a section's validation floor. Its first [Recovery::next] opens the writers, and
/// [Recovery::finish] returns the journal once the replay is drained.
///
/// A recovery from [Journal::preflight_restore] has nothing to replay. [Recovery::finish]
/// restores its checkpoint.
///
/// Dropping the recovery before [Recovery::finish] destroys the handle, and the owner must
/// initialize again.
pub struct Recovery<E: Storage + Metrics, A: CodecFixed> {
    /// Terminal entry at each validated logical boundary.
    boundaries: BTreeMap<u64, Option<A>>,

    /// Logical byte prefix of each section protected by a durable validation marker. Repair
    /// never truncates below it.
    floors: BTreeMap<u64, u64>,

    /// Checkpoint `(section, size)` that [Recovery::finish] restores in place of a replay.
    restore: Option<(u64, u64)>,

    /// Preflighted storage, held until its writers are opened.
    unopened: Option<(E, Config)>,

    /// The journal under replay, present once its writers are open.
    journal: Option<Journal<E, A>>,
    sections: VecDeque<SectionReplay<E::Blob>>,
    buffer: NonZeroUsize,
    read_options: ReadOptions,
    finished: bool,
    errored: bool,
    repairing: bool,
    in_progress: bool,
}

impl<E: Storage + Metrics, A: CodecFixedShared> Recovery<E, A> {
    /// A recovery with no evidence, no storage to open, and no section to replay.
    const fn new(buffer: NonZeroUsize, read_options: ReadOptions) -> Self {
        Self {
            boundaries: BTreeMap::new(),
            floors: BTreeMap::new(),
            restore: None,
            unopened: None,
            journal: None,
            sections: VecDeque::new(),
            buffer,
            read_options,
            finished: false,
            errored: false,
            repairing: false,
            in_progress: false,
        }
    }

    /// Terminal entries captured at each validated boundary.
    pub(crate) const fn boundaries(&self) -> &BTreeMap<u64, Option<A>> {
        &self.boundaries
    }

    /// Open the preflighted writers and start replaying them.
    async fn open(&mut self, context: E, cfg: Config) -> Result<(), Error> {
        let journal = Journal(Box::new(Inner::init(context, cfg, u64::MAX).await?));

        // Opening a writer may discard a torn tail, which must not reach into a proven prefix.
        for (&section, &floor) in &self.floors {
            let size = journal.size(section)?;
            if size < floor {
                return Err(Error::Corruption(format!(
                    "section {section} retains {size} of its {floor}-byte validation floor"
                )));
            }
        }
        self.begin(journal).await
    }

    /// Take the opened `journal` and capture a replay view of every section from position zero.
    async fn begin(&mut self, mut journal: Journal<E, A>) -> Result<(), Error> {
        // Capture independent replay views while returning each writer to the manager.
        let mut sections = VecDeque::new();
        let replayed: Vec<_> = journal.sections().collect();
        for section in replayed {
            let blob = journal.0.manager.take(section).await?;
            let (blob, reader) = blob.replay(self.buffer, self.read_options).await?;
            journal.0.manager.put(section, blob);
            sections.push_back(SectionReplay {
                section,
                reader,
                position: 0,
            });
        }
        self.sections = sections;
        self.journal = Some(journal);
        Ok(())
    }

    /// The manager of the journal under replay. A section is replayed only while its journal is
    /// open.
    fn manager(&mut self) -> &mut Manager<E, AppendFactory> {
        &mut self
            .journal
            .as_mut()
            .expect("replayed section has an open journal")
            .0
            .manager
    }

    /// Validate that the front section's checksum failure is a repairable torn page, returning
    /// the item-aligned truncation target and the validated replay prefix.
    async fn plan_repair(&mut self, source: RError) -> Result<(u64, u64), Error> {
        // Only a checksum failure is repairable: it marks a torn write, while any other error
        // is an I/O failure this repair must not mask.
        if !matches!(source, RError::InvalidChecksum) {
            return Err(source.into());
        }

        // The bytes already replayed are validated: they bound the truncation from below.
        let current = self.sections.front().expect("replayed section is present");
        let section = current.section;
        let size = current.reader.blob_size();
        let position = current.position;
        let valid_size = position
            .checked_mul(Inner::<E, A>::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;

        // Forward-validate from the replayed prefix to find where well-formed pages end. Only a
        // failed or cancelled repair removes a replayed section's writer, and either ends the
        // replay.
        let (buffer, read_options) = (self.buffer, self.read_options);
        let recoverable = self
            .manager()
            .get(section)?
            .expect("replayed section is present")
            .recoverable_prefix_len(valid_size, buffer, read_options)
            .await?;

        // A whole-blob recoverable prefix means the checksum failure did not come from a torn
        // page: surface the original error instead of truncating valid data.
        if recoverable >= size {
            return Err(source.into());
        }

        // Truncate to whole items, never below the validated replay prefix or the durability
        // floor: a cut inside either lost acknowledged data.
        let target = recoverable - recoverable % Inner::<E, A>::CHUNK_SIZE_U64;
        if target < valid_size {
            return Err(Error::ItemOutOfRange(position));
        }
        self.ensure_above_floor(section, target)?;

        Ok((valid_size, target))
    }

    /// Repair a torn page discovered by ordered replay and resume at the last complete item.
    async fn repair(&mut self, source: RError) -> Result<(), Error> {
        // A rejected plan mutates nothing: drop the damaged section and surface its error.
        let (valid_size, target) = match self.plan_repair(source).await {
            Ok(plan) => plan,
            Err(err) => {
                self.sections.pop_front();
                return Err(err);
            }
        };

        let current = self.sections.front().expect("replayed section is present");
        let (section, position) = (current.section, current.position);
        warn!(
            section,
            invalid_size = current.reader.blob_size(),
            new_size = target,
            "torn page detected: truncating"
        );

        // Mark the repair incomplete until a new reader has replaced the stale view.
        self.repairing = true;
        let current = self
            .sections
            .pop_front()
            .expect("repaired section is present");
        drop(current.reader);
        let writer = self.manager().take(section).await?;
        let writer = writer.truncate(target).await?;
        let (writer, mut reader) = writer.replay(self.buffer, self.read_options).await?;
        self.manager().put(section, writer);
        reader.seek_to(valid_size)?;
        self.sections.push_front(SectionReplay {
            section,
            reader,
            position,
        });
        self.repairing = false;
        Ok(())
    }

    /// Durably truncate the front section to its last complete item.
    async fn repair_tail(&mut self, section: u64, size: u64) -> Result<(), Error> {
        // Mark the repair incomplete until it is durable.
        self.repairing = true;
        let writer = self.manager().take(section).await?;
        let writer = writer.truncate(size).await?;
        self.manager().put(section, writer);
        self.repairing = false;
        Ok(())
    }

    /// Reject a repair that would remove any marker-protected item.
    fn ensure_above_floor(&self, section: u64, target: u64) -> Result<(), Error> {
        let floor = self.floors.get(&section).copied().unwrap_or(0);
        if target < floor {
            return Err(Error::Corruption(format!(
                "section {section} recovery target {target} is below its {floor}-byte validation floor"
            )));
        }
        Ok(())
    }

    /// Returns the next `(section, position, item)`, or `None` once every section is
    /// exhausted. A recovery from [Journal::preflight_restore] has no item to return: this
    /// returns `None` without opening a writer.
    ///
    /// For a recovery from [Journal::preflight_floors], the first call opens the writers and may
    /// discard a torn tail page. Nothing is modified before it, and an error opening them ends
    /// the replay.
    ///
    /// An error ends the section that produced it, and iteration continues with the next section.
    /// Errors while mutating storage to repair a section end the replay. Dropping a pending call
    /// also ends it. The next call returns [Error::ReplayInterrupted] and [Self::finish] fails.
    pub async fn next(&mut self) -> Option<Result<(u64, u64, A), Error>> {
        if self.in_progress {
            self.in_progress = false;
            self.repairing = false;
            self.sections.clear();
            return self.fail(Error::ReplayInterrupted);
        }

        // Leave this set if the future is dropped at any await in the replay.
        self.in_progress = true;
        let result = self.next_inner().await;
        self.in_progress = false;
        result
    }

    async fn next_inner(&mut self) -> Option<Result<(u64, u64, A), Error>> {
        // A checkpoint proves its retained items, and only [Self::finish] applies it.
        if self.restore.is_some() {
            return None;
        }

        // The first call applies the preflighted floors by opening the writers.
        if let Some((context, cfg)) = self.unopened.take()
            && let Err(err) = self.open(context, cfg).await
        {
            return self.fail(err);
        }

        // A failed storage repair may have dropped its writer. Stop after its error.
        if self.repairing {
            self.repairing = false;
            self.sections.clear();
        }
        while let Some(current) = self.sections.front_mut() {
            // Ensure we have enough data for one item
            match current.reader.ensure(Inner::<E, A>::CHUNK_SIZE).await {
                Ok(true) => {}
                Ok(false) => {
                    let valid_size =
                        match current.position.checked_mul(Inner::<E, A>::CHUNK_SIZE_U64) {
                            Some(size) => size,
                            None => return self.fail(Error::OffsetOverflow),
                        };
                    let blob_size = current.reader.blob_size();
                    if valid_size < blob_size {
                        let section = current.section;
                        if let Err(err) = self.ensure_above_floor(section, valid_size) {
                            self.sections.pop_front();
                            return self.fail(err);
                        }
                        warn!(
                            section,
                            invalid_size = blob_size,
                            new_size = valid_size,
                            "incomplete item detected: truncating"
                        );
                        if let Err(err) = self.repair_tail(section, valid_size).await {
                            self.sections.pop_front();
                            return self.fail(err);
                        }
                    }
                    self.sections.pop_front();
                    continue;
                }
                Err(err) => {
                    if let Err(err) = self.repair(err).await {
                        return self.fail(err);
                    }
                    continue;
                }
            }

            // Decode the item at the current position
            match A::read(&mut current.reader) {
                Ok(item) => {
                    let yielded = (current.section, current.position, item);
                    current.position += 1;
                    return Some(Ok(yielded));
                }
                Err(err) => {
                    self.sections.pop_front();
                    return self.fail(Error::Codec(err));
                }
            }
        }
        self.finished = true;
        None
    }

    /// Records a yielded error, which is fatal to the journal.
    const fn fail(&mut self, err: Error) -> Option<Result<(u64, u64, A), Error>> {
        self.errored = true;
        Some(Err(err))
    }

    /// Returns the journal.
    ///
    /// A recovery from [Journal::preflight_floors] fails with [Error::ReplayFailed] when it was
    /// not fully drained, yielded an error, or was interrupted. The journal is then destroyed and
    /// the owner must initialize again. Storage without any section has nothing to drain.
    ///
    /// A recovery from [Journal::preflight_restore] opens the sections through its checkpoint,
    /// truncates the checkpoint section, and removes every later section unread. The truncation
    /// is durable when this returns.
    pub async fn finish(mut self) -> Result<Journal<E, A>, Error> {
        if let Some((section, size)) = self.restore {
            let (context, cfg) = self
                .unopened
                .take()
                .expect("only finish opens a restored journal");
            let mut inner = Inner::init(context, cfg, section).await?;

            // The checkpoint preflight authorized this exact truncation. Make it durable before
            // the paired value journal can release any corresponding bytes.
            inner.manager = inner
                .manager
                .truncate_pending(section, size)
                .await?
                .sync(section)
                .await?;
            return Ok(Journal(Box::new(inner)));
        }
        if self.in_progress || self.errored || !self.finished {
            return Err(Error::ReplayFailed);
        }

        // Storage without any section is drained before a call to [Self::next] opens it.
        if let Some((context, cfg)) = self.unopened.take() {
            self.open(context, cfg).await?;
        }
        self.journal.ok_or(Error::ReplayFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::{
            SYNC_READ_STACK_SIZE,
            segmented::manager::tests::{
                BoundedOpen, FaultedContext, check_interrupted_bounded_open,
            },
        },
        utils::codec::View,
    };
    use commonware_codec::FixedSize;
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Error as RError, Runner, Spawner as _, Supervisor as _,
        buffer::paged::{CacheRef, corrupt_page},
        deterministic,
        mocks::{
            DelayedSyncContext, PendingSyncs, ReadGateContext, RecordingContext,
            fail_pending_syncs, release_pending_syncs,
        },
    };
    use commonware_utils::{NZU16, NZUsize, Widen};
    use core::num::NonZeroU16;
    use std::{
        ops::{Range, RangeInclusive},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// Drain a recovery, returning its journal with every replayed item.
    async fn drain<E: Storage + Metrics, A: CodecFixedShared>(
        mut recovery: Recovery<E, A>,
    ) -> Result<(Journal<E, A>, Vec<(u64, u64, A)>), Error> {
        let mut items = Vec::new();
        while let Some(item) = recovery.next().await {
            items.push(item?);
        }
        Ok((recovery.finish().await?, items))
    }

    /// Start the recovery of a journal with no validation floors.
    async fn recover<E: Storage + Metrics, A: CodecFixedShared>(
        context: E,
        cfg: Config,
        read_options: ReadOptions,
    ) -> Result<Recovery<E, A>, Error> {
        Journal::preflight_floors(context, cfg, &BTreeMap::new(), read_options).await
    }

    /// Open a journal with no validation floors, returning it with every replayed item.
    async fn replay_journal<E: Storage + Metrics, A: CodecFixedShared>(
        context: E,
        cfg: Config,
    ) -> Result<(Journal<E, A>, Vec<(u64, u64, A)>), Error> {
        drain(recover(context, cfg, ReadOptions::default()).await?).await
    }

    /// Open a journal with no validation floors.
    async fn init_journal<E: Storage + Metrics, A: CodecFixedShared>(
        context: E,
        cfg: Config,
    ) -> Result<Journal<E, A>, Error> {
        Ok(replay_journal(context, cfg).await?.0)
    }

    impl<E: Storage + Metrics, A: CodecFixedShared> Journal<E, A> {
        pub(in super::super) async fn test_reopen_at_most(
            self,
            section: u64,
            end: u64,
        ) -> Result<Self, Error> {
            let (context, partition, factory) = self.0.manager.test_configuration();
            let cfg = Config {
                partition,
                write_buffer: factory.write_buffer,
                replay_buffer: factory.write_buffer,
                page_cache: factory.page_cache_ref,
            };
            _ = self.sync_all().await?;
            Self::init_at_most(context, cfg, section, end).await
        }

        async fn test_reopen_section(self, section: u64, end: u64) -> Result<Self, Error> {
            let (context, partition, factory) = self.0.manager.test_configuration();
            let replay_buffer = factory.write_buffer;
            let cfg = Config {
                partition,
                write_buffer: replay_buffer,
                replay_buffer,
                page_cache: factory.page_cache_ref,
            };
            _ = self.sync_all().await?;
            let mut journal = Self(Box::new(Inner::init(context, cfg, u64::MAX).await?));
            journal.0.manager = journal
                .0
                .manager
                .truncate_pending_section(section, end)
                .await?;
            Ok(drain(journal.recover(replay_buffer).await?).await?.0)
        }
    }

    impl BoundedOpen for Journal<FaultedContext, u64> {
        const ITEM_SIZE: u64 = Self::CHUNK_SIZE as u64;

        async fn open(
            context: FaultedContext,
            page_cache: CacheRef,
            bound: Option<(u64, u64)>,
        ) -> Result<Self, Error> {
            let cfg = Config {
                partition: "bounded-open".into(),
                page_cache,
                write_buffer: NZUsize!(64),
                replay_buffer: NZUsize!(64),
            };
            match bound {
                Some((section, end)) => Self::init_at_most(context, cfg, section, end).await,
                None => init_journal(context, cfg).await,
            }
        }

        async fn extend(mut self, section: u64, items: Range<u64>) -> Self {
            for item in items {
                (self, _) = self.append(section, &item).await.unwrap();
            }
            self.sync_all().await.unwrap()
        }

        async fn items(&self, section: u64) -> Vec<u64> {
            let mut items = Vec::new();
            for position in 0..self.section_len(section).unwrap() {
                items.push(self.get(section, position).await.unwrap());
            }
            items
        }

        fn last_section(&self) -> Option<u64> {
            self.newest_section()
        }
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&[&value.to_be_bytes()])
    }

    fn test_cfg() -> Config {
        Config {
            partition: "test-partition".into(),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(1024),
        }
    }

    fn aligned_cfg() -> Config {
        Config {
            partition: "segmented-fixed-aligned".into(),
            page_cache: CacheRef::new(NZU16!(16), NZUsize!(4)),
            write_buffer: NZUsize!(128),
            replay_buffer: NZUsize!(1024),
        }
    }

    #[test_traced]
    fn test_fixed_cached_get_preserves_owned_byte_fields() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context, cfg).await.unwrap();
            (journal, _) = journal.append(1, &View::new(7)).await.unwrap();
            let decoded = journal.try_get_sync(1, 0).unwrap();
            journal.destroy().await.unwrap();
            assert_eq!(decoded.bytes.as_ref(), &7u64.to_be_bytes());
        });
    }

    /// Append two `SIZE`-byte items and read both back through the synchronous path.
    async fn check_cached_get<const SIZE: usize>(context: deterministic::Context) {
        let cfg = test_cfg();
        let mut journal = init_journal::<_, [u8; SIZE]>(context, cfg).await.unwrap();
        (journal, _) = journal.append(1, &[7u8; SIZE]).await.unwrap();
        (journal, _) = journal.append(1, &[8u8; SIZE]).await.unwrap();
        assert_eq!(journal.try_get_sync(1, 0), Some([7u8; SIZE]));
        assert_eq!(journal.try_get_sync(1, 1), Some([8u8; SIZE]));
        journal.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_fixed_cached_get_at_stack_buffer_boundary() {
        deterministic::Runner::default().start(|context| async move {
            check_cached_get::<SYNC_READ_STACK_SIZE>(context.child("stack")).await;
            check_cached_get::<{ SYNC_READ_STACK_SIZE + 1 }>(context.child("scratch")).await;
        });
    }

    fn lazy_recovery_cfg(partition: &str) -> Config {
        Config {
            partition: partition.into(),
            page_cache: CacheRef::new(NZU16!(16), NZUsize!(4)),
            write_buffer: NZUsize!(1),
            replay_buffer: NZUsize!(1024),
        }
    }

    /// Seed each section with sixteen durable u64 items.
    async fn seed<E: Storage + Metrics>(context: &E, cfg: &Config, sections: RangeInclusive<u64>) {
        let mut journal = init_journal(context.child("seed"), cfg.clone())
            .await
            .expect("failed to init");
        for section in sections {
            for value in 0..16u64 {
                (journal, _) = journal
                    .append(section, &value)
                    .await
                    .expect("failed to append");
            }
        }
        journal.sync_all().await.expect("failed to sync");
    }

    #[test]
    fn test_segmented_capped_init_bounds_torn_suffix_reads() {
        deterministic::Runner::default().start(|context| async move {
            for source_section in [0, 1] {
                for cap in [0, 8] {
                    // Compare a short and long discarded suffix behind the same retained cap.
                    let mut counts = Vec::new();
                    for pages in [16, 4096] {
                        let partition = format!("torn-cap-{source_section}-{cap}-{pages}");
                        let page: Vec<u8> = (0..9u64).flat_map(u64::to_be_bytes).collect();
                        assert_eq!(page.len(), 72);
                        super::super::manager::tests::seed_torn_suffix(
                            &context,
                            &partition,
                            source_section,
                            &page,
                            pages,
                        )
                        .await;

                        // Bounded initialization must read independently of the discarded suffix.
                        let cfg = Config {
                            partition,
                            page_cache: CacheRef::new(NZU16!(72), NZUsize!(4)),
                            write_buffer: NZUsize!(144),
                            replay_buffer: NZUsize!(144),
                        };
                        let (recorded, recordings) = RecordingContext::new(context.child("cap"));
                        let mut journal =
                            Journal::<_, u64>::init_at_most(recorded, cfg.clone(), 0, cap)
                                .await
                                .unwrap();
                        let retained = if source_section == 0 { cap } else { 0 };
                        assert_eq!(journal.size(0).unwrap(), retained);
                        counts.push(recordings.snapshot().reads.len());

                        // Appending after the cap must not reconnect any discarded items.
                        (journal, _) = journal.append(0, &999).await.unwrap();
                        drop(journal.sync_all().await.unwrap());
                        let (_, items) = replay_journal::<_, u64>(context.child("reopen"), cfg)
                            .await
                            .unwrap();
                        let actual: Vec<_> = items.into_iter().map(|item| item.2).collect();
                        let expected = if retained == 0 {
                            vec![999]
                        } else {
                            vec![0, 999]
                        };
                        assert_eq!(actual, expected);
                    }

                    // Suffix length must not change the number of reads needed for the same cap.
                    assert_eq!(
                        counts[0], counts[1],
                        "discarded suffix reads grew: {counts:?}"
                    );
                }
            }
        });
    }

    #[test_traced]
    fn test_bounded_initialization_bounds_scan() {
        deterministic::Runner::default().start(|context| async move {
            // Seed different journal lengths under the same page and buffer configuration.
            let mut counts = Vec::new();
            for count in [128, 65536] {
                let cfg = Config {
                    partition: format!("fixed-cap-scan-{count}"),
                    page_cache: CacheRef::new(NZU16!(64), NZUsize!(4)),
                    write_buffer: NZUsize!(65536),
                    replay_buffer: NZUsize!(65536),
                };
                let mut journal = init_journal::<_, u64>(
                    context.child(if count == 128 {
                        "seed_small"
                    } else {
                        "seed_large"
                    }),
                    cfg.clone(),
                )
                .await
                .unwrap();
                for value in 0..count {
                    (journal, _) = journal.append(0, &value).await.unwrap();
                }
                _ = journal.sync_all().await.unwrap();

                // Record the reads required to reopen at the same one-item boundary.
                let (recorded, recordings) =
                    RecordingContext::new(context.child(if count == 128 {
                        "cap_small"
                    } else {
                        "cap_large"
                    }));
                let journal = Journal::<_, u64>::init_at_most(recorded, cfg, 0, 8)
                    .await
                    .unwrap();
                assert_eq!(journal.section_len(0).unwrap(), 1);
                counts.push(recordings.snapshot().reads.len());
            }

            // Work below the cap must be independent of the discarded journal length.
            assert_eq!(
                counts[0], counts[1],
                "same one-item cap: small/large suffix read counts {counts:?}"
            );
        });
    }

    #[rstest::rstest]
    #[case(30)]
    #[case(31)]
    #[case(32)]
    fn test_bounded_initialization_recovers_torn_page(#[case] tail: u64) {
        deterministic::Runner::default().start(|context| async move {
            for cap in [0, 8, 16, 20, 24, 28, 29, 30, 31, 32, u64::MAX] {
                // Seed two sections so the bound must repair one and remove the later section.
                let cfg = Config {
                    partition: format!("capped-torn-{cap}"),
                    page_cache: CacheRef::new(NZU16!(5), NZUsize!(4)),
                    write_buffer: NZUsize!(256),
                    replay_buffer: NZUsize!(256),
                };
                let mut journal = init_journal::<_, u64>(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..4 {
                    (journal, _) = journal.append(0, &value).await.unwrap();
                }
                (journal, _) = journal.append(1, &100).await.unwrap();
                _ = journal.sync_all().await.unwrap();

                // A valid page prefix may end inside the last item after an interrupted append.
                let (blob, size) = context
                    .open(&cfg.partition, &0u64.to_be_bytes())
                    .await
                    .unwrap();
                let partial = commonware_runtime::buffer::paged::Recovery::open(
                    blob,
                    size,
                    cfg.write_buffer.get(),
                    cfg.page_cache.clone(),
                )
                .await
                .unwrap();
                partial.truncate(tail).await.unwrap();

                // A valid later page survives after the torn page in section zero.
                corrupt_page(&context, &cfg.partition, &0u64.to_be_bytes(), 4, 5).await;
                let journal =
                    Journal::<_, u64>::init_at_most(context.child("cap"), cfg.clone(), 0, cap)
                        .await
                        .unwrap();
                let expected_bytes = cap.min(16) / 8 * 8;
                assert_eq!(journal.size(0).unwrap(), expected_bytes, "cap {cap}");
                assert_eq!(journal.newest_section(), Some(0));
                drop(journal);

                // A normal restart must retain the repaired prefix and append at its exact end.
                let (mut journal, items) = replay_journal::<_, u64>(context.child("reopen"), cfg)
                    .await
                    .unwrap();
                let mut count = 0;
                for item in items {
                    assert_eq!(item.0, 0);
                    assert_eq!(item.2, count);
                    count += 1;
                }
                assert_eq!(count, expected_bytes / 8);
                let position;
                (journal, position) = journal.append(0, &99).await.unwrap();
                assert_eq!(position, expected_bytes / 8);
                journal.destroy().await.unwrap();
            }
        });
    }

    #[test]
    fn test_bounded_initialization_retries_after_storage_faults() {
        check_interrupted_bounded_open::<Journal<FaultedContext, u64>>();
    }

    #[test_traced]
    fn test_segmented_fixed_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            let pos0;
            (journal, pos0) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos0, 0);

            let pos1;
            (journal, pos1) = journal
                .append(1, &test_digest(1))
                .await
                .expect("failed to append");
            assert_eq!(pos1, 1);

            let pos2;
            (journal, pos2) = journal
                .append(2, &test_digest(2))
                .await
                .expect("failed to append");
            assert_eq!(pos2, 0);

            let item0 = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item0, test_digest(0));

            let item1 = journal.get(1, 1).await.expect("failed to get");
            assert_eq!(item1, test_digest(1));

            let item2 = journal.get(2, 0).await.expect("failed to get");
            assert_eq!(item2, test_digest(2));

            let err = journal.get(1, 2).await;
            assert!(matches!(err, Err(Error::ItemOutOfRange(2))));

            let err = journal.get(3, 0).await;
            assert!(matches!(err, Err(Error::SectionOutOfRange(3))));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    /// Eight-byte items form a sub-page section, 64 KiB plus one item, or two 128 KiB buffers
    /// plus one item. Every case leaves a partial page after sync.
    #[rstest::rstest]
    #[case(100)]
    #[case(8193)]
    #[case(32769)]
    fn test_segmented_fixed_synced_sections_partial_pages(#[case] items: u64) {
        const PAGE_SIZE: usize = 4096;
        const WRITE_BUFFER: usize = 131072;
        const SECTIONS: u64 = 8;
        const CACHE_PAGES: usize = 4;

        deterministic::Runner::default().start(move |context| async move {
            let cfg = Config {
                partition: "segmented-fixed-buffers".into(),
                page_cache: CacheRef::new(NZU16!(PAGE_SIZE as u16), NZUsize!(CACHE_PAGES)),
                write_buffer: NZUsize!(WRITE_BUFFER),
                replay_buffer: NZUsize!(WRITE_BUFFER),
            };
            let mut journal = init_journal::<_, u64>(context.child("journal"), cfg)
                .await
                .unwrap();
            for section in 0..SECTIONS {
                for value in 0..items {
                    (journal, _) = journal.append(section, &value).await.unwrap();
                }
                journal = journal.sync_all().await.unwrap();
            }

            for section in 0..SECTIONS {
                assert_eq!(journal.get(section, 0).await.unwrap(), 0);
                assert_eq!(journal.get(section, items - 1).await.unwrap(), items - 1);
                (journal, _) = journal.append(section, &items).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();
            for section in 0..SECTIONS {
                assert_eq!(journal.get(section, items).await.unwrap(), items);
            }
        });
    }

    #[test_traced]
    fn test_segmented_fixed_append_buffer_boundaries() {
        // A digest exceeds the two-page buffer, fills it exactly, or crosses it after
        // buffered appends.
        for page_size in [NZU16!(8), NZU16!(16), PAGE_SIZE] {
            deterministic::Runner::default().start(|context| async move {
                let cfg = Config {
                    partition: "buffer-boundaries".into(),
                    page_cache: CacheRef::new(page_size, PAGE_CACHE_SIZE),
                    write_buffer: NZUsize!(1),
                    replay_buffer: NZUsize!(128),
                };
                let mut journal = init_journal(context.child("initial"), cfg.clone())
                    .await
                    .unwrap();
                for section in [1, 3] {
                    for position in 0..10 {
                        let item = test_digest(section * 100 + position);
                        let appended;
                        (journal, appended) = journal.append(section, &item).await.unwrap();
                        assert_eq!(appended, position);
                        assert_eq!(journal.section_len(section).unwrap(), position + 1);
                        assert_eq!(journal.get(section, position).await.unwrap(), item);
                    }
                }
                journal = journal.sync_all().await.unwrap();
                drop(journal);

                let (mut journal, items) = replay_journal::<_, Digest>(context, cfg).await.unwrap();
                let mut items = items.into_iter();
                for section in [1, 3] {
                    for position in 0..10 {
                        assert_eq!(
                            items.next().unwrap(),
                            (section, position, test_digest(section * 100 + position))
                        );
                    }
                }
                assert!(items.next().is_none());
                let position;
                (journal, position) = journal.append(3, &test_digest(310)).await.unwrap();
                assert_eq!(position, 10);
                assert_eq!(journal.get(3, 10).await.unwrap(), test_digest(310));
                journal.destroy().await.unwrap();
            });
        }
    }

    #[test_traced]
    fn test_segmented_fixed_replay_empty_finishes_immediately() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Storage without any section is drained from the start
            let replay =
                recover::<_, Digest>(context.child("storage"), cfg, ReadOptions::default())
                    .await
                    .expect("failed to replay");
            let journal = replay.finish().await.expect("failed to finish replay");
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay_propagates_read_options() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let cfg = Config {
                replay_buffer: NZUsize!(56),
                ..aligned_cfg()
            };
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            for section in 1..=2 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            drop(journal.sync_all().await.expect("failed to sync"));

            let mut replay = recover(context.child("replay"), cfg, ReadOptions::DONT_CACHE)
                .await
                .expect("failed to replay");
            recordings.clear();

            // The first call opens both writers, each reading its tail page once. The first lazy
            // refill follows and must carry the caller's policy.
            let (section, position, item) = replay
                .next()
                .await
                .expect("missing first replay item")
                .expect("failed to read first replay item");
            assert_eq!((section, position, item), (1, 0, test_digest(1)));
            let reads = recordings.snapshot().reads;
            let (opened, replayed) = reads.split_at(2);
            assert_eq!(opened, [ReadOptions::default(); 2]);
            assert!(!replayed.is_empty());
            assert!(
                replayed
                    .iter()
                    .all(|options| *options == ReadOptions::DONT_CACHE)
            );

            // Crossing into the next section must preserve the same policy.
            recordings.clear();
            let (section, position, item) = replay
                .next()
                .await
                .expect("missing second replay item")
                .expect("failed to read second replay item");
            assert_eq!((section, position, item), (2, 0, test_digest(2)));
            let reads = recordings.snapshot().reads;
            assert!(!reads.is_empty());
            assert!(
                reads
                    .iter()
                    .all(|options| *options == ReadOptions::DONT_CACHE)
            );
            assert!(replay.next().await.is_none());

            let journal = replay.finish().await.expect("failed to finish replay");
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay_leaves_page_cache_cold() {
        deterministic::Runner::default().start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let cfg = aligned_cfg();
            let page_cache = cfg.page_cache.clone();
            let mut journal = init_journal::<_, [u8; 16]>(context.child("storage"), cfg.clone())
                .await
                .unwrap();

            // Each item fills one logical page, so a synchronous probe checks each page.
            for value in 0..2 {
                (journal, _) = journal.append(1, &[value; 16]).await.unwrap();
            }
            drop(journal.sync(1).await.unwrap());
            page_cache.clear();

            let replay =
                recover::<_, [u8; 16]>(context.child("replay"), cfg, ReadOptions::DONT_CACHE)
                    .await
                    .unwrap();
            let (journal, items) = drain(replay).await.unwrap();
            assert_eq!(items, vec![(1, 0, [0; 16]), (1, 1, [1; 16])]);
            for position in 0..2 {
                assert!(journal.try_get_sync(1, position).is_none());
            }

            recordings.clear();
            assert_eq!(journal.get(1, 0).await.unwrap(), [0; 16]);
            assert!(!recordings.snapshot().reads.is_empty());
            assert_eq!(journal.try_get_sync(1, 0), Some([0; 16]));
            recordings.clear();
            assert_eq!(journal.get(1, 0).await.unwrap(), [0; 16]);
            assert!(recordings.snapshot().reads.is_empty());
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_segmented_fixed_clean_recovery_uses_replay_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let cfg = lazy_recovery_cfg("segmented-fixed-lazy-recovery");

            // Sixteen u64s occupy eight physical pages. Persist a clean journal whose tiny write
            // buffer would force an eager recovery scan to issue one read per page.
            seed(&context, &cfg, 1..=1).await;

            // A preflight without floors reads nothing. Opening needs only the terminal page used
            // to open Writer. Recovery belongs to replay, whose 448-byte budget holds sixteen
            // 28-byte physical pages and reads them four pages at a time.
            recordings.clear();
            let cfg = Config {
                replay_buffer: NZUsize!(448),
                ..cfg
            };
            let replay = recover::<_, u64>(context.child("reopen"), cfg, ReadOptions::default())
                .await
                .expect("failed to reopen");
            assert!(recordings.snapshot().reads.is_empty());

            let (journal, _) = drain(replay).await.expect("failed to replay");
            assert_eq!(recordings.snapshot().reads.len(), 3);
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_floor_preflight_reads_boundary_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let cfg = lazy_recovery_cfg("segmented-fixed-floor-boundary");
            seed(&context, &cfg, 1..=1).await;

            // A durable floor proves its prefix. Preflight reads only the page containing the
            // terminal entry and leaves the ordinary replay pass to inspect the suffix.
            recordings.clear();
            let floors = BTreeMap::from([(1, 16)]);
            let preflight = Journal::<_, u64>::preflight_floors(
                context.child("preflight"),
                cfg,
                &floors,
                ReadOptions::default(),
            )
            .await
            .expect("failed to preflight");
            assert_eq!(recordings.snapshot().reads.len(), 1);
            let (journal, items) = drain(preflight).await.expect("failed to replay");
            assert_eq!(items.len(), 16);
            journal.destroy().await.expect("failed to destroy");
        });
    }

    /// A recovery leaves a torn tail in place until its first call opens the writers.
    #[test_traced]
    fn test_segmented_fixed_recovery_modifies_nothing_before_next() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = lazy_recovery_cfg("segmented-fixed-untouched-preflight");
            seed(&context, &cfg, 1..=1).await;

            // Tear the terminal page, which opening the writer discards.
            let name = 1u64.to_be_bytes();
            let (blob, size) = context
                .open(&cfg.partition, &name)
                .await
                .expect("failed to open");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");
            drop(blob);

            // A floor below the tear is proven by reading it, and a dropped recovery leaves the
            // torn page in place.
            let floors = BTreeMap::from([(1, 14)]);
            let preflight = Journal::<_, u64>::preflight_floors(
                context.child("preflight"),
                cfg.clone(),
                &floors,
                ReadOptions::default(),
            )
            .await
            .expect("failed to preflight");
            assert_eq!(preflight.boundaries()[&1], Some(13));
            drop(preflight);
            let (_, untouched) = context
                .open(&cfg.partition, &name)
                .await
                .expect("failed to open");
            assert_eq!(untouched, size - 1);

            // The first call opens the writer and discards the torn page: seven 28-byte physical
            // pages remain, holding the fourteen items the replay returns.
            let (journal, items) = replay_journal::<_, u64>(context.child("replay"), cfg.clone())
                .await
                .expect("failed to replay");
            assert_eq!(items.len(), 14);
            drop(journal);
            let (_, repaired) = context
                .open(&cfg.partition, &name)
                .await
                .expect("failed to open");
            assert_eq!(repaired, 7 * 28);
        });
    }

    #[test_traced]
    fn test_segmented_fixed_restore_reads_boundaries_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let cfg = lazy_recovery_cfg("segmented-fixed-restore-boundaries");
            seed(&context, &cfg, 0..=1).await;

            // The checkpoint makes both retained sections durable. Restore needs one terminal
            // boundary read per section, independent of the eight pages stored in each.
            recordings.clear();
            let mut preflight = Journal::<_, u64>::preflight_restore(
                context.child("preflight"),
                cfg,
                1,
                16 * u64::SIZE as u64,
            )
            .await
            .expect("failed to preflight");
            assert_eq!(recordings.snapshot().reads.len(), 2);

            // The checkpoint leaves nothing to replay, and asking opens no writer.
            assert!(preflight.next().await.is_none());
            assert_eq!(recordings.snapshot().reads.len(), 2);
            preflight
                .finish()
                .await
                .expect("failed to finish preflight")
                .destroy()
                .await
                .expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_restore_retains_empty_checkpoint_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = lazy_recovery_cfg("segmented-fixed-empty-restore");
            let mut journal = init_journal(context.child("seed"), cfg.clone())
                .await
                .expect("failed to init");
            for section in 0..=2 {
                (journal, _) = journal
                    .append(section, &section)
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");
            journal = journal
                .test_reopen_section(1, 0)
                .await
                .expect("failed to empty checkpoint section");
            journal = journal.sync(1).await.expect("failed to sync empty section");
            drop(journal);

            let journal = Journal::<_, u64>::preflight_restore(context.child("restore"), cfg, 1, 0)
                .await
                .expect("failed to preflight")
                .finish()
                .await
                .expect("failed to finish preflight");

            assert_eq!(journal.sections().collect::<Vec<_>>(), vec![0, 1]);
            assert_eq!(journal.size(1).expect("missing checkpoint section"), 0);
            journal.destroy().await.expect("failed to destroy");
        });
    }

    /// Replay never repairs below a floor. A torn page under it is committed damage, reported
    /// as corruption whether the section ends at its floor or keeps a suffix above it.
    #[rstest::rstest]
    #[case::section_ends_at_floor(16)]
    #[case::suffix_above_floor(8)]
    fn test_segmented_fixed_floor_rejects_below_floor_repair(#[case] floor: u64) {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = lazy_recovery_cfg("segmented-fixed-floor-repair");
            seed(&context, &cfg, 0..=1).await;

            // Tear the page holding items four and five, below either floor. The preflight reads
            // only the terminal boundary page, so it succeeds without validating the interior.
            corrupt_page(&context, &cfg.partition, &1u64.to_be_bytes(), 2, 16).await;
            let floors = BTreeMap::from([(1, floor)]);
            let mut replay = Journal::<_, u64>::preflight_floors(
                context.child("floors"),
                cfg.clone(),
                &floors,
                ReadOptions::default(),
            )
            .await
            .expect("failed to preflight");

            // The floor covers the torn page, so replay cannot repair it.
            let mut outcome = None;
            while let Some(item) = replay.next().await {
                if let Err(err) = item {
                    outcome = Some(err);
                    break;
                }
            }
            assert!(matches!(outcome, Some(Error::Corruption(_))));
            assert!(matches!(replay.finish().await, Err(Error::ReplayFailed)));

            // The floor-proven bytes stay untouched: eight 28-byte physical pages.
            let (_, blob_size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("failed to open");
            assert_eq!(blob_size, 8 * 28);
        });
    }

    #[test_traced]
    fn test_segmented_fixed_restore_rejects_damaged_earlier_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = lazy_recovery_cfg("segmented-fixed-restore-earlier-boundary");
            seed(&context, &cfg, 0..=1).await;

            // Tear the terminal page of the section below the checkpoint section.
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("failed to open");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");
            drop(blob);

            // The checkpoint covers every earlier section whole, so one without a valid terminal
            // boundary is committed damage that restore reports and leaves untouched.
            let result = Journal::<_, u64>::preflight_restore(
                context.child("restore"),
                cfg.clone(),
                1,
                16 * Widen::<u64>::widen(u64::SIZE),
            )
            .await;
            assert!(matches!(result, Err(Error::Corruption(_))));
            let (_, blob_size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("failed to open");
            assert_eq!(blob_size, size - 1);
        });
    }

    #[test_traced]
    fn test_segmented_fixed_floor_preflight_reads_terminal_entry_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let cfg = aligned_cfg();
            let mut journal = init_journal(context.child("seed"), cfg.clone())
                .await
                .expect("failed to init");
            for value in 0..2 {
                (journal, _) = journal
                    .append(1, &test_digest(value))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync(1).await.expect("failed to sync");
            drop(journal);

            recordings.clear();
            let floors = BTreeMap::from([(1, 2)]);
            let preflight = Journal::<_, Digest>::preflight_floors(
                context.child("reopen"),
                cfg,
                &floors,
                ReadOptions::default(),
            )
            .await
            .expect("failed to preflight");

            // Two 32-byte items occupy four 16-byte pages. The terminal entry spans two pages, and
            // no earlier entry page is read before the replay.
            assert_eq!(recordings.snapshot().reads.len(), 2);
            let (journal, items) = drain(preflight).await.expect("failed to reopen");
            assert_eq!(items.len(), 2);
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay_finish_before_drain_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal::<_, Digest>(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");
            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            drop(journal.sync_all().await.expect("failed to sync"));

            let replay = recover::<_, Digest>(context.child("replay"), cfg, ReadOptions::default())
                .await
                .expect("failed to replay");
            assert!(matches!(replay.finish().await, Err(Error::ReplayFailed)));
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..10 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            for i in 10u64..20 {
                (journal, _) = journal
                    .append(2, &test_digest(i))
                    .await
                    .expect("failed to append");
            }

            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let (journal, items) =
                replay_journal::<_, Digest>(context.child("second"), cfg.clone())
                    .await
                    .expect("failed to replay");

            assert_eq!(items.len(), 20);
            for (i, item) in items.iter().enumerate().take(10) {
                assert_eq!(item.0, 1);
                assert_eq!(item.1, i as u64);
                assert_eq!(item.2, test_digest(i as u64));
            }
            for (i, item) in items.iter().enumerate().skip(10).take(10) {
                assert_eq!(item.0, 2);
                assert_eq!(item.1, (i - 10) as u64);
                assert_eq!(item.2, test_digest(i as u64));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            for section in 1u64..=5 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            (journal, _) = journal.prune(3).await.expect("failed to prune");

            let err = journal.get(1, 0).await;
            assert!(matches!(err, Err(Error::AlreadyPrunedToSection(3))));

            let err = journal.get(2, 0).await;
            assert!(matches!(err, Err(Error::AlreadyPrunedToSection(3))));

            let item = journal.get(3, 0).await.expect("should exist");
            assert_eq!(item, test_digest(3));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_pruned_after_full_prune() {
        // `pruned` must keep reporting the floor after every blob is removed, when
        // `oldest_section` returns None (indistinguishable from a fresh journal).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            for section in 1u64..=3 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            (journal, _) = journal.prune(10).await.expect("failed to prune");
            assert_eq!(journal.oldest_section(), None);
            assert!(journal.pruned(3));
            assert!(journal.pruned(9));
            assert!(!journal.pruned(10));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_truncate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1, 2, 3
            for section in 1u64..=3 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            // Verify all sections exist
            for section in 1u64..=3 {
                let size = journal.size(section).expect("failed to get size");
                assert!(size > 0, "section {section} should have data");
            }

            // Truncate to section 1 (should remove sections 2, 3)
            let size = journal.size(1).expect("failed to get size");
            journal = journal
                .test_reopen_at_most(1, size)
                .await
                .expect("failed to truncate");

            // Verify section 1 still has data
            let size = journal.size(1).expect("failed to get size");
            assert!(size > 0, "section 1 should still have data");

            // Verify sections 2, 3 are removed
            for section in 2u64..=3 {
                let size = journal.size(section).expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data in section 1 is still readable
            let item = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item, test_digest(1));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_truncate_max_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            // Append to the maximal section. `section + 1` has no representable successor.
            (journal, _) = journal
                .append(u64::MAX, &test_digest(0))
                .await
                .expect("failed to append");
            journal = journal.sync_all().await.expect("failed to sync");

            // Truncating the maximal section removes no sections above it and must not panic.
            let size = journal.size(u64::MAX).expect("failed to get size");
            journal = journal
                .test_reopen_at_most(u64::MAX, size)
                .await
                .expect("failed to truncate");

            // The section is intact and readable.
            assert_eq!(journal.size(u64::MAX).expect("failed to get size"), size);
            assert_eq!(journal.get(u64::MAX, 0).await.unwrap(), test_digest(0));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_truncate_many_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1-10
            for section in 1u64..=10 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            // Truncate to section 5 (should remove sections 6-10)
            let size = journal.size(5).expect("failed to get size");
            journal = journal
                .test_reopen_at_most(5, size)
                .await
                .expect("failed to truncate");

            // Verify sections 1-5 still have data
            for section in 1u64..=5 {
                let size = journal.size(section).expect("failed to get size");
                assert!(size > 0, "section {section} should still have data");
            }

            // Verify sections 6-10 are removed
            for section in 6u64..=10 {
                let size = journal.size(section).expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data integrity via replay
            drop(journal);
            let (journal, items) = replay_journal::<_, Digest>(context.child("replay"), cfg)
                .await
                .expect("failed to replay");
            assert_eq!(items.len(), 5);
            for (i, (section, _, item)) in items.iter().enumerate() {
                assert_eq!(*section, (i + 1) as u64);
                assert_eq!(*item, test_digest((i + 1) as u64));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_truncate_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create sections 1-5
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");
            for section in 1u64..=5 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            // Truncate to section 2
            let size = journal.size(2).expect("failed to get size");
            journal = journal
                .test_reopen_at_most(2, size)
                .await
                .expect("failed to truncate");
            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Re-init and verify only sections 1-2 exist
            let journal = init_journal::<_, Digest>(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Verify sections 1-2 have data
            for section in 1u64..=2 {
                let size = journal.size(section).expect("failed to get size");
                assert!(size > 0, "section {section} should have data after restart");
            }

            // Verify sections 3-5 are gone
            for section in 3u64..=5 {
                let size = journal.size(section).expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be gone after restart");
            }

            // Verify data integrity
            let item1 = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item1, test_digest(1));
            let item2 = journal.get(2, 0).await.expect("failed to get");
            assert_eq!(item2, test_digest(2));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_corruption_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("failed to open blob");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");

            drop(blob);
            let (journal, items) =
                replay_journal::<_, Digest>(context.child("second"), cfg.clone())
                    .await
                    .expect("failed to replay");
            assert_eq!(items.len(), 4);

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate journal
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Reopen and verify data persisted
            let journal = init_journal::<_, Digest>(context.child("second"), cfg)
                .await
                .expect("failed to re-init");

            for i in 0u64..5 {
                let item = journal.get(1, i).await.expect("failed to get");
                assert_eq!(item, test_digest(i));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // One sub-page item per section stays buffered until synced.
            for section in 1u64..=3 {
                (journal, _) = journal
                    .append(section, &test_digest(section))
                    .await
                    .expect("failed to append");
            }

            // Sync sections 1 and 3; a nonexistent section (99) is skipped, not an error.
            journal
                .sync(&[1, 3, 99])
                .await
                .expect("failed to sync sections");

            // Only the synced sections survive the unclean drop.
            let journal = init_journal::<_, Digest>(context.child("second"), cfg)
                .await
                .expect("failed to re-init");
            assert_eq!(
                journal.get(1, 0).await.expect("section 1 durable"),
                test_digest(1)
            );
            assert_eq!(
                journal.get(3, 0).await.expect("section 3 durable"),
                test_digest(3)
            );
            assert!(matches!(
                journal.get(2, 0).await,
                Err(Error::ItemOutOfRange(0)) | Err(Error::SectionOutOfRange(2))
            ));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_section_len() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            assert_eq!(journal.section_len(1).unwrap(), 0);

            for i in 0u64..5 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }

            assert_eq!(journal.section_len(1).unwrap(), 5);
            assert_eq!(journal.section_len(2).unwrap(), 0);

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_non_contiguous_sections() {
        // Test that sections with gaps in numbering work correctly.
        // Sections 1, 5, 10 should all be independent and accessible.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections with gaps: 1, 5, 10
            (journal, _) = journal
                .append(1, &test_digest(100))
                .await
                .expect("failed to append");
            (journal, _) = journal
                .append(5, &test_digest(500))
                .await
                .expect("failed to append");
            (journal, _) = journal
                .append(10, &test_digest(1000))
                .await
                .expect("failed to append");
            journal = journal.sync_all().await.expect("failed to sync");

            // Verify random access to each section
            assert_eq!(journal.get(1, 0).await.unwrap(), test_digest(100));
            assert_eq!(journal.get(5, 0).await.unwrap(), test_digest(500));
            assert_eq!(journal.get(10, 0).await.unwrap(), test_digest(1000));

            // Verify non-existent sections return appropriate errors
            for missing_section in [0u64, 2, 3, 4, 6, 7, 8, 9, 11] {
                let result = journal.get(missing_section, 0).await;
                assert!(
                    matches!(result, Err(Error::SectionOutOfRange(_))),
                    "Expected SectionOutOfRange for section {}, got {:?}",
                    missing_section,
                    result
                );
            }

            // Drop and reopen to test replay
            drop(journal);
            let (journal, items) =
                replay_journal::<_, Digest>(context.child("second"), cfg.clone())
                    .await
                    .expect("failed to replay");

            // Verify all items replayed in order
            assert_eq!(items.len(), 3, "Should have 3 items");
            assert_eq!(items[0], (1, 0, test_digest(100)));
            assert_eq!(items[1], (5, 0, test_digest(500)));
            assert_eq!(items[2], (10, 0, test_digest(1000)));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_empty_section_in_middle() {
        // Test that replay correctly handles an empty section between sections with data.
        // Section 1 has data, section 2 is empty, section 3 has data.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append to section 1
            (journal, _) = journal
                .append(1, &test_digest(100))
                .await
                .expect("failed to append");

            // Create section 2 but make it empty via truncate
            (journal, _) = journal
                .append(2, &test_digest(200))
                .await
                .expect("failed to append");
            journal = journal.sync(2).await.expect("failed to sync");
            journal = journal
                .test_reopen_section(2, 0)
                .await
                .expect("failed to truncate");

            // Append to section 3
            (journal, _) = journal
                .append(3, &test_digest(300))
                .await
                .expect("failed to append");

            journal = journal.sync_all().await.expect("failed to sync");

            // Verify section lengths
            assert_eq!(journal.section_len(1).unwrap(), 1);
            assert_eq!(journal.section_len(2).unwrap(), 0);
            assert_eq!(journal.section_len(3).unwrap(), 1);

            // Drop and reopen to test replay
            drop(journal);
            let (journal, items) =
                replay_journal::<_, Digest>(context.child("second"), cfg.clone())
                    .await
                    .expect("failed to replay");

            // Replay all - should get items from sections 1 and 3, skipping empty section 2
            assert_eq!(
                items.len(),
                2,
                "Should have 2 items (skipping empty section)"
            );
            assert_eq!(items[0], (1, 0, test_digest(100)));
            assert_eq!(items[1], (3, 0, test_digest(300)));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_validates_pages_before_trailing_bytes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const LOGICAL_PAGE_SIZE: u64 = 5;
            const SECTION: u64 = 0;

            let cfg = Config {
                partition: "segmented-fixed-validate-before-tail-trim".into(),
                page_cache: CacheRef::new(NZU16!(LOGICAL_PAGE_SIZE as u16), NZUsize!(4)),
                write_buffer: NZUsize!(128),
                replay_buffer: NZUsize!(1024),
            };
            let mut journal = init_journal::<_, u64>(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for value in [11u64, 22, 33, 44] {
                (journal, _) = journal.append(SECTION, &value).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();
            drop(journal);

            let (blob, size) = context
                .open(&cfg.partition, &SECTION.to_be_bytes())
                .await
                .unwrap();
            let writer = commonware_runtime::buffer::paged::Recovery::open(
                blob,
                size,
                128,
                cfg.page_cache.clone(),
            )
            .await
            .unwrap();
            let writer = writer.truncate(30).await.unwrap();
            writer.sync().await.unwrap();

            // Five-byte integrity pages crossed by eight-byte journal items:
            //
            // pages: [0..5) [5..10) [10..15) [15..20) [20..25) [25..30)
            // state:    ok      ok       ok       ok       torn      ok
            // items: [0......8) [8.......16) [16......24) [24..30 tail)
            //
            // Backward sizing stops at valid page 5 and reports 30 logical bytes. Item alignment
            // alone selects 24, inside torn page 4, which `Recovery::truncate` cannot preserve.
            // Forward page validation finds 20 contiguous bytes and selects safe item boundary 16.
            corrupt_page(
                &context,
                &cfg.partition,
                &SECTION.to_be_bytes(),
                4,
                LOGICAL_PAGE_SIZE,
            )
            .await;

            let journal = init_journal::<_, u64>(context.child("recover"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.section_len(SECTION).unwrap(), 2);
            assert_eq!(journal.get(SECTION, 0).await.unwrap(), 11);
            assert_eq!(journal.get(SECTION, 1).await.unwrap(), 22);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_segmented_fixed_repairs_torn_interior_page() {
        const SECTION: u64 = 0;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = aligned_cfg();
            let mut journal = init_journal::<_, u64>(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for value in 0..6 {
                (journal, _) = journal.append(SECTION, &value).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();
            drop(journal);

            // The three 16-byte logical pages each contain two complete u64 items. Tear the
            // interior page while its neighbors stay valid:
            //
            // pages: [0........16) [16.......32) [32.......48)
            // state:     valid          torn          valid
            // items: [0.......1]    [2.......3]    [4.......5]
            //
            // Backward sizing sees valid page 2 and reports the item-aligned length 48. Recovery
            // must still scan forward, truncate to page 0's 16-byte prefix, and discard items 2-5.
            corrupt_page(&context, &cfg.partition, &SECTION.to_be_bytes(), 1, 16).await;

            let mut journal = init_journal::<_, u64>(context.child("recover"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.section_len(SECTION).unwrap(), 2);
            assert_eq!(journal.get(SECTION, 0).await.unwrap(), 0);
            assert_eq!(journal.get(SECTION, 1).await.unwrap(), 1);
            assert!(matches!(
                journal.get(SECTION, 2).await,
                Err(Error::ItemOutOfRange(2))
            ));

            // The repair truncation is durable: appends resume at the repaired boundary and
            // survive reopen.
            let position;
            (journal, position) = journal.append(SECTION, &99).await.unwrap();
            assert_eq!(position, 2);
            journal.sync_all().await.unwrap();

            let journal = init_journal::<_, u64>(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.section_len(SECTION).unwrap(), 3);
            assert_eq!(journal.get(SECTION, 0).await.unwrap(), 0);
            assert_eq!(journal.get(SECTION, 1).await.unwrap(), 1);
            assert_eq!(journal.get(SECTION, 2).await.unwrap(), 99);
            journal.destroy().await.unwrap();
        });
    }

    /// Dropping [Recovery::next] while a tail or torn-page repair awaits durability fails the
    /// replay, and re-initialization repairs from durable state.
    #[rstest::rstest]
    #[case::tail(false)]
    #[case::torn(true)]
    fn test_segmented_fixed_replay_dropped_during_repair_fails_replay(#[case] torn: bool) {
        const SECTION: u64 = 0;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Six u64 items fill three 16-byte pages.
            let cfg = aligned_cfg();
            let mut journal = init_journal::<_, u64>(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for value in 0..6 {
                (journal, _) = journal.append(SECTION, &value).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();
            drop(journal);

            // Tearing interior page 1 leaves items 0-1, and replay repairs it on the first read.
            // Cutting the tail inside item 5 leaves items 0-4, and replay repairs it after them.
            let (drained, retained) = if torn {
                corrupt_page(&context, &cfg.partition, &SECTION.to_be_bytes(), 1, 16).await;
                (0, 2)
            } else {
                let (blob, size) = context
                    .open(&cfg.partition, &SECTION.to_be_bytes())
                    .await
                    .unwrap();
                let writer = commonware_runtime::buffer::paged::Recovery::open(
                    blob,
                    size,
                    cfg.write_buffer.get(),
                    cfg.page_cache.clone(),
                )
                .await
                .unwrap();
                writer.truncate(44).await.unwrap();
                (5, 5)
            };

            // Replay up to the damage, gate syncs so the repair suspends, and drop the in-flight
            // next().
            let pending = PendingSyncs::default();
            let gated = DelayedSyncContext {
                inner: context.child("second"),
                pending: pending.clone(),
            };
            let mut replay = recover::<_, u64>(gated, cfg.clone(), ReadOptions::default())
                .await
                .unwrap();
            for value in 0..drained {
                assert_eq!(
                    replay.next().await.unwrap().unwrap(),
                    (SECTION, value, value)
                );
            }
            pending.arm();
            {
                let next = replay.next();
                futures::pin_mut!(next);
                assert!(futures::poll!(next.as_mut()).is_pending());
            }
            release_pending_syncs(&pending);

            // The interrupted repair fails the replay.
            assert!(matches!(
                replay.next().await,
                Some(Err(Error::ReplayInterrupted))
            ));
            assert!(replay.next().await.is_none());
            assert!(matches!(replay.finish().await, Err(Error::ReplayFailed)));

            // Re-initialization repairs from durable state.
            let journal = init_journal::<_, u64>(context.child("third"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.section_len(SECTION).unwrap(), retained);
            for value in 0..retained {
                assert_eq!(journal.get(SECTION, value).await.unwrap(), value);
            }
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_segmented_fixed_truncation_recovery_across_page_boundary() {
        // Test that truncating a single byte from a blob that has items straddling a page boundary
        // correctly recovers by removing the incomplete item.
        //
        // With PAGE_SIZE=44 and ITEM_SIZE=32:
        // - Item 0: bytes 0-31
        // - Item 1: bytes 32-63 (straddles page boundary at 44)
        // - Item 2: bytes 64-95 (straddles page boundary at 88)
        //
        // After 3 items we have 96 bytes = 2 full pages + 8 bytes. Truncating 1 byte leaves 95
        // bytes, which is not a multiple of 32. Recovery should truncate to 64 bytes (2 complete
        // items).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("first"), cfg.clone())
                .await
                .expect("failed to init");

            // Append 3 items (just over 2 pages worth)
            for i in 0u64..3 {
                (journal, _) = journal
                    .append(1, &test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal = journal.sync_all().await.expect("failed to sync");

            // Verify all 3 items are readable
            for i in 0u64..3 {
                let item = journal.get(1, i).await.expect("failed to get");
                assert_eq!(item, test_digest(i));
            }
            drop(journal);

            // Truncate the blob by exactly 1 byte to simulate partial write
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("failed to open blob");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");
            drop(blob);

            // Reopen and drain recovery. Writer removes the torn physical tail while replay rounds
            // the remaining logical prefix down to complete items.
            let journal = init_journal::<_, Digest>(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-init");

            // Verify section now has only 2 items
            assert_eq!(journal.section_len(1).unwrap(), 2);

            // Verify size is the expected multiple of ITEM_SIZE (this would fail if we didn't trim
            // items and just relied on page-level checksum recovery).
            assert_eq!(journal.size(1).unwrap(), 64);

            // Items 0 and 1 should still be readable
            let item0 = journal.get(1, 0).await.expect("failed to get item 0");
            assert_eq!(item0, test_digest(0));
            let item1 = journal.get(1, 1).await.expect("failed to get item 1");
            assert_eq!(item1, test_digest(1));

            // Item 2 should return ItemOutOfRange
            let err = journal.get(1, 2).await;
            assert!(
                matches!(err, Err(Error::ItemOutOfRange(2))),
                "expected ItemOutOfRange(2), got {:?}",
                err
            );

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_journal_clear() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "clear-test".into(),
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            };

            let mut journal: Journal<_, Digest> =
                init_journal(context.child("journal"), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

            // Append items across multiple sections
            for section in 0..5u64 {
                for i in 0..10u64 {
                    (journal, _) = journal
                        .append(section, &test_digest(section * 1000 + i))
                        .await
                        .expect("Failed to append");
                }
                journal = journal.sync(section).await.expect("Failed to sync");
            }

            // Verify we have data
            assert_eq!(journal.get(0, 0).await.unwrap(), test_digest(0));
            assert_eq!(journal.get(4, 0).await.unwrap(), test_digest(4000));

            // Clear the journal
            journal = journal.clear().await.expect("Failed to clear");

            // After clear, all reads should fail
            for section in 0..5u64 {
                assert!(matches!(
                    journal.get(section, 0).await,
                    Err(Error::SectionOutOfRange(s)) if s == section
                ));
            }

            // Append new data after clear
            for i in 0..5u64 {
                (journal, _) = journal
                    .append(10, &test_digest(i * 100))
                    .await
                    .expect("Failed to append after clear");
            }
            journal = journal.sync(10).await.expect("Failed to sync after clear");

            // New data should be readable
            assert_eq!(journal.get(10, 0).await.unwrap(), test_digest(0));

            // Old sections should still be missing
            assert!(matches!(
                journal.get(0, 0).await,
                Err(Error::SectionOutOfRange(0))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_last_missing_section_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let journal = init_journal::<_, Digest>(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            assert!(matches!(
                journal.last(0).await,
                Err(Error::SectionOutOfRange(0))
            ));
            assert!(matches!(
                journal.last(99).await,
                Err(Error::SectionOutOfRange(99))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_last_after_truncate_to_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            (journal, _) = journal.append(0, &test_digest(0)).await.unwrap();
            (journal, _) = journal.append(0, &test_digest(1)).await.unwrap();
            journal = journal.sync(0).await.unwrap();

            assert!(journal.last(0).await.unwrap().is_some());

            journal = journal.test_reopen_at_most(0, 0).await.unwrap();
            assert_eq!(journal.last(0).await.unwrap(), None);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_last_pruned_section_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal::<_, Digest>(context.child("storage"), cfg.clone())
                .await
                .expect("failed to init");

            (journal, _) = journal.append(0, &test_digest(0)).await.unwrap();
            (journal, _) = journal.append(1, &test_digest(1)).await.unwrap();
            journal = journal.sync_all().await.unwrap();

            (journal, _) = journal.prune(1).await.unwrap();

            assert!(matches!(
                journal.last(0).await,
                Err(Error::AlreadyPrunedToSection(1))
            ));
            assert!(journal.last(1).await.unwrap().is_some());

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg).await.unwrap();
            (journal, _) = journal.append(0, &test_digest(0)).await.unwrap();
            assert_eq!(journal.section_len(0).unwrap(), 1);

            let mut buf = [];
            let (items, hits) = journal.get_many(0, &[], &mut buf).await.unwrap();
            assert!(items.is_empty());
            assert_eq!(hits, 0);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_single_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg).await.unwrap();

            for i in 0..5 {
                (journal, _) = journal.append(0, &test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.section_len(0).unwrap(), 5);

            // Read all 5 items in one call. The reusable buffer is intentionally oversized:
            // get_many slices it to the exact length the batch needs.
            let chunk = Journal::<deterministic::Context, Digest>::CHUNK_SIZE;
            let mut buf = vec![0u8; 6 * chunk];
            let (items, _) = journal
                .get_many(0, &[0, 1, 2, 3, 4], &mut buf)
                .await
                .unwrap();

            for (i, item) in items.iter().enumerate() {
                assert_eq!(*item, test_digest(i as u64));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_subset() {
        // Read a sparse subset of positions.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg).await.unwrap();

            for i in 0..10 {
                (journal, _) = journal.append(0, &test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.section_len(0).unwrap(), 10);

            let chunk = Journal::<deterministic::Context, Digest>::CHUNK_SIZE;
            let positions = [1, 4, 7, 9];
            let mut buf = vec![0u8; positions.len() * chunk];
            let (items, _) = journal.get_many(0, &positions, &mut buf).await.unwrap();

            for (i, &pos) in positions.iter().enumerate() {
                assert_eq!(items[i], test_digest(pos));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_bad_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let journal = init_journal::<_, Digest>(context.child("storage"), cfg)
                .await
                .unwrap();

            let mut buf = vec![0u8; 64];
            let err = journal.get_many(99, &[0], &mut buf).await.unwrap_err();
            assert!(matches!(err, Error::SectionOutOfRange(99)));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_get_many_matches_get() {
        // Verify batch read matches individual reads.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg).await.unwrap();

            for i in 0..8 {
                (journal, _) = journal.append(0, &test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.section_len(0).unwrap(), 8);
            journal = journal.sync_all().await.unwrap();

            let chunk = Journal::<deterministic::Context, Digest>::CHUNK_SIZE;
            let positions: Vec<u64> = (0..8).collect();
            let mut buf = vec![0u8; positions.len() * chunk];
            let (batch, _) = journal.get_many(0, &positions, &mut buf).await.unwrap();

            for pos in &positions {
                let single = journal.get(0, *pos).await.unwrap();
                assert_eq!(batch[*pos as usize], single);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("prune").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                let (journal, pruned) = journal.prune(2).await.expect("failed to prune");
                assert!(pruned);
                completed_clone.fetch_add(1, Ordering::Relaxed);
                journal
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "prune must wait for in-flight syncs on pruned sections"
            );

            release_pending_syncs(&pending);
            handle
                .await
                .expect("sync handle should complete despite pruning");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let journal = waiter.await.expect("prune task failed");
            assert_eq!(journal.oldest_section(), None);
        });
    }

    #[test_traced]
    fn test_segmented_fixed_destroy_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("destroy").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                journal.destroy().await.expect("failed to destroy");
                completed_clone.fetch_add(1, Ordering::Relaxed);
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "destroy must wait for in-flight syncs"
            );

            release_pending_syncs(&pending);
            handle
                .await
                .expect("sync handle should complete despite destruction");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            waiter.await.expect("destroy task failed");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_clear_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("clear").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                journal = journal.clear().await.expect("failed to clear");
                completed_clone.fetch_add(1, Ordering::Relaxed);
                journal
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "clear must wait for in-flight syncs"
            );

            release_pending_syncs(&pending);
            handle
                .await
                .expect("sync handle should complete despite clearing");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let mut journal = waiter.await.expect("clear task failed");

            // The journal must remain usable after clear.
            assert_eq!(journal.oldest_section(), None);
            let position;
            (journal, position) = journal
                .append(1, &test_digest(1))
                .await
                .expect("failed to append after clear");
            assert_eq!(position, 0);
            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune_surfaces_failed_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_cfg();
            let mut journal = init_journal(context.child("storage"), cfg)
                .await
                .expect("failed to init");

            (journal, _) = journal
                .append(1, &test_digest(0))
                .await
                .expect("failed to append");
            let handle;
            (journal, handle) = journal.start_sync(1).await.expect("failed to start sync");
            fail_pending_syncs(&pending);

            let err = journal
                .prune(2)
                .await
                .expect_err("prune must surface a failed in-flight sync");
            assert!(matches!(err, Error::Runtime(RError::Io(_))));

            let err = handle.await.expect_err("sync handle should fail");
            assert!(matches!(err, RError::Io(_)));
        });
    }

    /// Cancelling the read that opens the writers or an ordinary replay read invalidates the
    /// replay without changing its durable data.
    #[rstest::rstest]
    #[case::finish(false)]
    #[case::next(true)]
    fn test_segmented_fixed_replay_dropped_during_read_fails_replay(
        #[case] resume: bool,
        #[values(0, 2)] drained: u64,
    ) {
        deterministic::Runner::default().start(|context| async move {
            const SECTION: u64 = 0;

            // Twelve u64 items fill six 16-byte pages. The replay reads one page at a time and
            // keeps three more in flight, so the call after the first page's two items starts
            // another read.
            let cfg = Config {
                replay_buffer: NZUsize!(16),
                ..aligned_cfg()
            };
            let mut journal = init_journal::<_, u64>(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            for value in 0..12 {
                (journal, _) = journal.append(SECTION, &value).await.unwrap();
            }
            drop(journal.sync_all().await.unwrap());

            let (gated, gate) =
                ReadGateContext::new(context.child("cancel"), cfg.partition.clone());
            let mut replay = recover::<_, u64>(gated, cfg.clone(), ReadOptions::default())
                .await
                .unwrap();

            // Dropping a call before it is polled starts no read and leaves the replay usable.
            // The first polled call opens the writer, so with nothing drained the gate parks its
            // tail read.
            drop(replay.next());
            for value in 0..drained {
                assert_eq!(
                    replay.next().await.unwrap().unwrap(),
                    (SECTION, value, value)
                );
            }
            gate.arm();
            {
                let next = replay.next();
                futures::pin_mut!(next);
                assert!(futures::poll!(next.as_mut()).is_pending());
                assert!(gate.blocked() > 0);
            }
            gate.disarm();

            if resume {
                assert!(matches!(
                    replay.next().await,
                    Some(Err(Error::ReplayInterrupted))
                ));
                assert!(replay.next().await.is_none());
                assert!(replay.next().await.is_none());
            }
            assert!(matches!(replay.finish().await, Err(Error::ReplayFailed)));

            let (journal, items) = replay_journal::<_, u64>(context.child("reopen"), cfg)
                .await
                .unwrap();
            let expected: Vec<_> = (0..12).map(|value| (SECTION, value, value)).collect();
            assert_eq!(items, expected);
            journal.destroy().await.unwrap();
        });
    }
}
