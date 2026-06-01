//! Item-aware adapter for the contiguous variable journal's data backend.
//!
//! [`VariableData`] wraps a [`Sections`] store and adds the variable-length item primitives that
//! `contiguous::variable::Journal` needs (varint-prefixed reads, multi-section item-stream
//! replay, etc.). It owns section lifecycle through [`Sections`] but delegates item encoding and
//! decoding to `variable_format`, keeping storage repair policy separate from wire-format parsing.
//!
//! # Invariants
//!
//! [`VariableData::init`] trims the newest data section to the last valid item boundary before the
//! journal becomes readable. Cross-journal recovery in `contiguous::variable::Journal` handles
//! short non-tail data sections and keeps the data journal aligned with the offsets index.

use crate::{
    journal::{
        contiguous::sections::{Config as SectionsConfig, Sections, SectionsInit},
        variable_format::{
            read_item, read_many_consecutive, scan_replay_item, skip_replay, try_read_item_sync,
            ReplayScan, SectionReader,
        },
        Error,
    },
    Context,
};
use commonware_codec::{varint::MAX_U32_VARINT_SIZE, Codec, CodecShared};
use commonware_runtime::{
    buffer::paged::{Append, CacheRef, Replay},
    Blob, Buf, IoBuf,
};
use commonware_utils::NZUsize;
use futures::stream::{self, Stream, StreamExt as _};
use std::num::NonZeroUsize;

/// Buffer size used for init-time tail replay.
const INIT_REPLAY_BUFFER: NonZeroUsize = NZUsize!(1024);

/// Configuration for [`VariableData`].
#[derive(Clone)]
pub(super) struct Config<C> {
    /// Partition where data sections are stored.
    pub partition: String,
    /// Optional `zstd` compression level for item payloads.
    pub compression: Option<u8>,
    /// Codec configuration passed to item decoding.
    pub codec_config: C,
    /// Page cache used by the underlying section store.
    pub page_cache: CacheRef,
    /// Tail write-buffer capacity.
    pub write_buffer: NonZeroUsize,
}

/// Variable-item view over a section store.
pub(super) struct VariableData<E: Context, V: Codec> {
    sections: Sections<E>,
    compression: Option<u8>,
    codec_config: V::Cfg,
}

/// Read-only adapter that exposes one section to shared variable-format helpers.
struct SectionView<'a, E: Context> {
    sections: &'a Sections<E>,
    section: u64,
}

impl<E: Context> SectionReader for SectionView<'_, E> {
    async fn size(&self) -> Result<u64, Error> {
        self.sections.section_size(self.section).await
    }

    async fn read_prefix(&self, offset: u64, len: usize) -> Result<IoBuf, Error> {
        let size = self.sections.section_size(self.section).await?;
        let available = size
            .saturating_sub(offset)
            .min(len as u64)
            .try_into()
            .map_err(|_| Error::OffsetOverflow)?;
        if available == 0 {
            return Err(Error::Corruption(format!(
                "no bytes available in data section {} at offset {offset}",
                self.section
            )));
        }
        Ok(self
            .sections
            .read_at(self.section, offset, available)
            .await?
            .coalesce())
    }

    async fn read_exact(&self, offset: u64, len: usize) -> Result<IoBuf, Error> {
        Ok(self
            .sections
            .read_at(self.section, offset, len)
            .await?
            .coalesce())
    }

    fn try_size(&self) -> Option<u64> {
        self.sections.try_section_size(self.section)
    }

    fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        self.sections.try_read_sync(self.section, offset, buf)
    }
}

impl<E: Context, V: CodecShared> VariableData<E, V> {
    /// Open the data backend and truncate any trailing partial-item bytes on the tail. The
    /// contiguous-variable invariant guarantees only the tail can have such junk.
    pub(super) async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let sections_cfg = SectionsConfig {
            partition: cfg.partition,
            page_cache: cfg.page_cache,
            write_buffer: cfg.write_buffer,
        };
        let init = SectionsInit::open(context, sections_cfg).await?;

        let compressed = cfg.compression.is_some();
        let tail_section = init.newest_section();
        if let Some(tail) = tail_section {
            let blob = init
                .section(tail)
                .expect("tail section exists per newest_section");
            let valid_offset =
                Self::find_valid_offset::<V>(blob, compressed, &cfg.codec_config).await?;
            init.truncate_section(tail, valid_offset).await?;
        }
        let sections = init.into_sections(tail_section).await?;

        Ok(Self {
            sections,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        })
    }

    /// Replay `blob` and return the byte offset just past the last successfully decoded item.
    /// Stops at structural trailing bytes, treating them as junk. Complete items that fail decode
    /// are returned as corruption rather than silently truncated.
    async fn find_valid_offset<V2: CodecShared>(
        blob: &Append<E::Blob>,
        compressed: bool,
        cfg: &V2::Cfg,
    ) -> Result<u64, Error> {
        let mut replay = blob
            .replay(INIT_REPLAY_BUFFER)
            .await
            .map_err(Error::Runtime)?;
        Self::valid_offset_from_replay::<_, V2>(&mut replay, compressed, cfg).await
    }

    /// Scan an already-open replay stream to the last structurally valid item boundary.
    async fn valid_offset_from_replay<B: Blob, V2: CodecShared>(
        replay: &mut Replay<B>,
        compressed: bool,
        cfg: &V2::Cfg,
    ) -> Result<u64, Error> {
        let mut offset = 0;
        let mut valid_offset = 0;
        loop {
            match scan_replay_item::<_, V2>(replay, &mut offset, &mut valid_offset, cfg, compressed)
                .await?
            {
                ReplayScan::Item(_) => {}
                ReplayScan::End { valid_offset, .. } => return Ok(valid_offset),
            }
        }
    }

    /// Return the byte offset just past the last successfully decoded item in `section`.
    pub(super) async fn valid_offset(
        &self,
        section: u64,
        buffer_size: NonZeroUsize,
    ) -> Result<u64, Error> {
        if self.sections.section_size(section).await? == 0 {
            return Ok(0);
        }
        let (mut replay, _) = self.sections.replay_section(section, buffer_size).await?;
        Self::valid_offset_from_replay::<_, V>(
            &mut replay,
            self.compression.is_some(),
            &self.codec_config,
        )
        .await
    }

    /// Borrow `section` as a [`SectionReader`] without exposing section lifecycle operations.
    const fn section_view(&self, section: u64) -> SectionView<'_, E> {
        SectionView {
            sections: &self.sections,
            section,
        }
    }

    /// Oldest retained data section, if any.
    pub(super) fn oldest_section(&self) -> Option<u64> {
        self.sections.oldest_section()
    }

    /// Newest retained data section, if any.
    pub(super) fn newest_section(&self) -> Option<u64> {
        self.sections.newest_section()
    }

    /// Returns `true` when no data sections are retained.
    pub(super) fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// Number of retained data sections.
    pub(super) fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Read the item at `(section, offset)`.
    pub(super) async fn get(&self, section: u64, offset: u64) -> Result<V, Error> {
        let view = self.section_view(section);
        read_item(
            &view,
            offset,
            &self.codec_config,
            self.compression.is_some(),
        )
        .await
        .map(|(_, _, item)| item)
    }

    /// Read multiple items from the same section that are byte-adjacent in storage.
    ///
    /// `offsets` must be strictly increasing. Returns [`Error::OffsetDataMismatch`] if the
    /// on-disk varint at any offset disagrees with the gap to the next offset.
    pub(super) async fn get_many_consecutive(
        &self,
        section: u64,
        offsets: &[u64],
    ) -> Result<Vec<V>, Error> {
        let view = self.section_view(section);
        read_many_consecutive(
            section,
            &view,
            offsets,
            &self.codec_config,
            self.compression.is_some(),
        )
        .await
    }

    /// Try to read the item at `(section, offset)` synchronously.
    pub(super) fn try_get_sync_into(
        &self,
        section: u64,
        offset: u64,
        buf: &mut Vec<u8>,
    ) -> Option<V> {
        let view = self.section_view(section);
        try_read_item_sync(
            &view,
            offset,
            &self.codec_config,
            self.compression.is_some(),
            buf,
        )
    }

    /// Returns a stream of items starting at `(start_section, start_offset)`. Each emitted tuple
    /// is `(section, offset, item_size, item)`.
    pub(super) async fn replay(
        &self,
        start_section: u64,
        start_offset: u64,
        buffer_size: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, u32, V), Error>> + Send + '_, Error> {
        let compressed = self.compression.is_some();
        let cfg = self.codec_config.clone();

        // Pre-create per-section replay handles so the stream owns no borrow back into `self`
        // except via the page cache reachable through each Replay's underlying Blob handle.
        let mut per_section: Vec<(u64, Replay<E::Blob>, u64)> = Vec::new();
        if let Some(newest) = self.sections.newest_section() {
            if start_section <= newest {
                let oldest = self.sections.oldest_section().unwrap();
                let first = start_section.max(oldest);
                for section in self.sections.sections_from(first) {
                    let (replay, _size) =
                        self.sections.replay_section(section, buffer_size).await?;
                    let skip = if section == start_section {
                        start_offset
                    } else {
                        0
                    };
                    per_section.push((section, replay, skip));
                }
            }
        }

        let stream = stream::iter(per_section).flat_map(move |(section, replay, skip)| {
            let cfg = cfg.clone();
            stream::unfold(
                ReplayState {
                    section,
                    replay,
                    skip_bytes: skip,
                    offset: 0,
                    valid_offset: skip,
                    cfg,
                    compressed,
                    done: false,
                },
                |mut state| async move {
                    if state.done {
                        return None;
                    }
                    let mut batch: Vec<Result<(u64, u64, u32, V), Error>> = Vec::new();
                    loop {
                        if state.skip_bytes > 0 {
                            match skip_replay(
                                &mut state.replay,
                                &mut state.skip_bytes,
                                &mut state.offset,
                                &mut state.valid_offset,
                            )
                            .await
                            {
                                Ok(true) => {}
                                Ok(false) => {
                                    state.done = true;
                                    return if batch.is_empty() {
                                        None
                                    } else {
                                        Some((batch, state))
                                    };
                                }
                                Err(err) => {
                                    batch.push(Err(err));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            }
                            continue;
                        }

                        match scan_replay_item::<_, V>(
                            &mut state.replay,
                            &mut state.offset,
                            &mut state.valid_offset,
                            &state.cfg,
                            state.compressed,
                        )
                        .await
                        {
                            Ok(ReplayScan::Item(item)) => {
                                batch.push(Ok((state.section, item.offset, item.size, item.item)));
                            }
                            Ok(ReplayScan::End { .. }) => {
                                state.done = true;
                                return if batch.is_empty() {
                                    None
                                } else {
                                    Some((batch, state))
                                };
                            }
                            Err(err) => {
                                batch.push(Err(err));
                                state.done = true;
                                return Some((batch, state));
                            }
                        }

                        if !batch.is_empty() && state.replay.remaining() < MAX_U32_VARINT_SIZE {
                            return Some((batch, state));
                        }
                    }
                },
            )
            .flat_map(stream::iter)
            .boxed()
        });

        Ok(stream)
    }

    /// Append pre-encoded bytes to `section`. Returns the byte offset within `section` at which
    /// the first byte was written.
    ///
    /// If `section` is ahead of the current tail, this rolls the tail forward. If no tail exists,
    /// it installs `section` as the fresh tail. Panics if `section < tail_section`.
    pub(super) async fn append_raw(&mut self, section: u64, buf: &[u8]) -> Result<u64, Error> {
        match self.sections.tail_section() {
            None => self.sections.install_tail(section).await?,
            Some(tail) => {
                assert!(
                    section >= tail,
                    "append_raw section {section} < tail {tail}"
                );
                let mut current = tail;
                while current < section {
                    self.sections.roll_tail(current + 1).await?;
                    current += 1;
                }
            }
        }
        let base_offset = self.sections.section_size(section).await?;
        self.sections.append_to_tail(buf).await?;
        Ok(base_offset)
    }

    /// Make the given section durable. Dispatches to either `Sealed::sync` or `Append::sync`.
    pub(super) async fn sync(&self, section: u64) -> Result<(), Error> {
        self.sections.sync_section(section).await
    }

    /// Prune sections strictly less than `min_section`.
    pub(super) async fn prune(&mut self, min_section: u64) -> Result<bool, Error> {
        self.sections.prune(min_section).await
    }

    /// Rewind to `(section, byte_offset)`. Removes any sections strictly greater than `section`
    /// (newest-first) and truncates `section` to `byte_offset` bytes.
    pub(super) async fn rewind(&mut self, section: u64, byte_offset: u64) -> Result<(), Error> {
        self.sections.rewind(section, byte_offset).await
    }

    /// Drop every section (sealed + tail) and remove all blobs.
    #[commonware_macros::stability(ALPHA)]
    pub(super) async fn clear(&mut self) -> Result<(), Error> {
        self.sections.clear().await
    }

    /// Drop every section, remove all blobs AND the partition.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        self.sections.destroy().await
    }
}

/// State for replaying a single section's items.
struct ReplayState<B: Blob, C> {
    section: u64,
    replay: Replay<B>,
    skip_bytes: u64,
    offset: u64,
    valid_offset: u64,
    cfg: C,
    compressed: bool,
    done: bool,
}
