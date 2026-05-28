//! Typed sealed/tail data store for [`super::variable::Journal`].
//!
//! Mirrors the API surface that [`crate::journal::segmented::variable::Journal`] exposes to its
//! callers, but is implemented over the byte-level typed [`super::sections::Sections`] store:
//! historical data sections are owned as
//! [`commonware_runtime::buffer::paged::Sealed`] handles and only the current tail can
//! mutate.
//!
//! Variable-length items are length-prefixed with a u32 varint. The on-disk format is
//! byte-for-byte identical to `segmented::variable`; this module reuses that module's encode and
//! decode helpers so storage formats remain interchangeable.

use crate::journal::{
    contiguous::sections::{Config as SectionsConfig, Sections, SectionsInit},
    variable_format::{decode_item, decode_length_prefix, find_item, ItemInfo},
    Error,
};
use commonware_codec::{varint::MAX_U32_VARINT_SIZE, Codec, CodecShared};
use commonware_runtime::{
    buffer::paged::{Append, CacheRef, Replay},
    Blob, Buf, IoBuf,
};
use futures::stream::{self, Stream, StreamExt as _};
use std::{io::Cursor, num::NonZeroUsize};
use tracing::warn;

/// Configuration for [`VariableData`]. Mirrors
/// [`crate::journal::segmented::variable::Config`].
#[derive(Clone)]
pub(super) struct Config<C> {
    pub partition: String,
    pub compression: Option<u8>,
    pub codec_config: C,
    pub page_cache: CacheRef,
    pub write_buffer: NonZeroUsize,
}

/// Typed sealed/tail data store for variable-length items.
pub(super) struct VariableData<E: crate::Context, V: Codec> {
    sections: Sections<E>,
    compression: Option<u8>,
    codec_config: V::Cfg,
}

impl<E: crate::Context, V: CodecShared> VariableData<E, V> {
    /// Initialize a [`VariableData`].
    ///
    /// All sections are loaded; the newest is chosen as the tail and replayed to truncate any
    /// trailing partial-item bytes (the only place such junk can appear under the contiguous
    /// variable invariants). All earlier sections are sealed.
    pub(super) async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let sections_cfg = SectionsConfig {
            partition: cfg.partition,
            page_cache: cfg.page_cache,
            write_buffer: cfg.write_buffer,
        };
        let init = SectionsInit::open(context, sections_cfg).await?;

        // If there is at least one section, replay the newest (still writable) to find the last
        // valid item end and truncate any trailing partial-item bytes. Earlier sections are full
        // per the contiguous variable invariant ("all non-final sections are full"), so they are
        // safe to seal as-is.
        let tail_section = init.newest_section();
        if let Some(s) = tail_section {
            let tail = init
                .section(s)
                .expect("section returned by `newest_section()` must exist");
            let valid_offset =
                Self::find_valid_offset(tail, cfg.compression.is_some(), &cfg.codec_config).await?;
            init.truncate_section(s, valid_offset).await?;
        }
        let sections = init.into_sections(tail_section).await?;

        Ok(Self {
            sections,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        })
    }

    /// Replay `blob` from offset 0 and return the byte offset just after the last successfully
    /// decoded item. Truncation to this offset removes any trailing partial-item bytes.
    async fn find_valid_offset(
        blob: &Append<E::Blob>,
        compressed: bool,
        codec_config: &V::Cfg,
    ) -> Result<u64, Error> {
        let blob_size = blob.size().await;
        let mut replay = blob.replay(REPLAY_BUFFER_SIZE).await?;
        let mut valid_offset = 0u64;
        let mut offset = 0u64;
        loop {
            // Try to ensure enough bytes for a varint header.
            match replay.ensure(MAX_U32_VARINT_SIZE).await {
                Ok(true) => {}
                Ok(false) => {
                    if replay.remaining() == 0 {
                        return Ok(valid_offset);
                    }
                    // Else: try to decode from remaining bytes (might still be enough for a
                    // tiny varint + zero-length item).
                }
                Err(err) => return Err(Error::Runtime(err)),
            }

            let before_remaining = replay.remaining();
            let (item_size, varint_len) = match decode_length_prefix(&mut replay) {
                Ok(r) => r,
                Err(err) => {
                    if replay.is_exhausted() || before_remaining < MAX_U32_VARINT_SIZE {
                        // Treat as trailing junk and stop at the last valid offset.
                        if valid_offset < blob_size {
                            warn!(
                                bad_offset = offset,
                                new_size = valid_offset,
                                "variable_data: trailing bytes detected during init"
                            );
                        }
                        return Ok(valid_offset);
                    }
                    return Err(err);
                }
            };

            // Ensure full item body is available.
            match replay.ensure(item_size).await {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        bad_offset = offset,
                        new_size = valid_offset,
                        "variable_data: incomplete item at end during init"
                    );
                    return Ok(valid_offset);
                }
                Err(err) => return Err(Error::Runtime(err)),
            }

            let next_offset = offset
                .checked_add(varint_len as u64)
                .and_then(|o| o.checked_add(item_size as u64))
                .ok_or(Error::OffsetOverflow)?;

            // Decode to confirm validity. Failures stop the replay at the prior valid offset.
            match decode_item::<V>((&mut replay).take(item_size), codec_config, compressed) {
                Ok(_) => {
                    valid_offset = next_offset;
                    offset = next_offset;
                }
                Err(err) => {
                    warn!(
                        bad_offset = offset,
                        new_size = valid_offset,
                        %err,
                        "variable_data: decode failure during init, truncating"
                    );
                    return Ok(valid_offset);
                }
            }
        }
    }

    /// Returns the oldest section number, if any.
    pub(super) fn oldest_section(&self) -> Option<u64> {
        self.sections.oldest_section()
    }

    /// Returns the newest section number, if any.
    pub(super) fn newest_section(&self) -> Option<u64> {
        self.sections.newest_section()
    }

    /// Returns true if no sections exist.
    pub(super) fn is_empty(&self) -> bool {
        self.sections.oldest_section().is_none()
    }

    /// Returns the number of sections.
    pub(super) fn num_sections(&self) -> usize {
        self.sections.sections().len()
    }

    /// Sync `section` if it is the tail. Sealed sections are already durable.
    pub(super) async fn sync(&self, section: u64) -> Result<(), Error> {
        self.sections.sync_section(section).await
    }

    /// Remove all underlying blobs.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        self.sections.destroy().await
    }

    /// Clear all sections, resetting to empty.
    // Only caller (`variable::Journal::clear_to_size`) is `#[stability(ALPHA)]`; this becomes
    // dead when the stability lint strips ALPHA items.
    #[allow(dead_code)]
    pub(super) async fn clear(&mut self) -> Result<(), Error> {
        self.sections.clear().await
    }

    /// Prune all sections strictly less than `min`. Tail is never pruned.
    pub(super) async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.sections.prune(min).await
    }

    /// Rewind: remove sections strictly greater than `section`, then truncate `section` to
    /// `offset` bytes. If `section` was sealed it is promoted to the new tail.
    pub(super) async fn rewind_to_offset(
        &mut self,
        section: u64,
        offset: u64,
    ) -> Result<(), Error> {
        self.sections.rewind(section, offset).await
    }

    /// Append pre-encoded item bytes to `section`. If `section` is the current tail, the bytes
    /// are appended directly. If `section` is the tail's successor (rollover), the current tail
    /// is sealed and a new empty tail is opened at `section` first.
    ///
    /// Returns the byte offset within `section` at which the bytes were written.
    pub(super) async fn append_raw(&mut self, section: u64, buf: &[u8]) -> Result<u64, Error> {
        let cur_tail = self.sections.newest_section();
        match cur_tail {
            Some(t) if t == section => {}
            Some(t) if t.checked_add(1) == Some(section) => {
                self.sections.roll_tail(section).await?;
            }
            None => {
                // No sections yet: install a tail at `section`.
                self.sections.install_tail(section).await?;
            }
            Some(t) => {
                return Err(Error::Corruption(format!(
                    "variable_data: append to section {section} but tail is at {t}"
                )));
            }
        }
        let offset = self.sections.section_size(section).await?;
        self.sections.append_to_tail(buf).await?;
        Ok(offset)
    }

    /// Read a single item from `section` at `offset`.
    pub(super) async fn get(&self, section: u64, offset: u64) -> Result<V, Error> {
        let compressed = self.compression.is_some();
        let cfg = &self.codec_config;

        // Read up to varint header.
        let remaining = self
            .sections
            .section_size(section)
            .await?
            .checked_sub(offset)
            .ok_or(Error::Runtime(
                commonware_runtime::Error::BlobInsufficientLength,
            ))?;
        let header_max = MAX_U32_VARINT_SIZE.min(remaining.try_into().unwrap_or(usize::MAX));
        if header_max == 0 {
            return Err(Error::Runtime(
                commonware_runtime::Error::BlobInsufficientLength,
            ));
        }
        let buf = self.sections.read_at(section, offset, header_max).await?;
        let bytes = buf.coalesce();
        let mut cursor = Cursor::new(bytes.as_ref());
        let (_, item_info) = find_item(&mut cursor, offset)?;

        match item_info {
            ItemInfo::Complete {
                varint_len,
                data_len,
            } => {
                let payload = &bytes.as_ref()[varint_len..varint_len + data_len];
                decode_item::<V>(payload, cfg, compressed)
            }
            ItemInfo::Incomplete {
                varint_len,
                prefix_len,
                total_len,
            } => {
                let prefix =
                    IoBuf::copy_from_slice(&bytes.as_ref()[varint_len..varint_len + prefix_len]);
                let remainder_len = total_len - prefix_len;
                let remainder_offset = offset
                    .checked_add(varint_len as u64)
                    .and_then(|o| o.checked_add(prefix_len as u64))
                    .ok_or(Error::OffsetOverflow)?;
                let remainder = self
                    .sections
                    .read_at(section, remainder_offset, remainder_len)
                    .await?
                    .coalesce();
                let chained = prefix.chain(remainder);
                decode_item::<V>(chained, cfg, compressed)
            }
        }
    }

    /// Read consecutive items from `section` whose offsets are strictly increasing and adjacent.
    pub(super) async fn get_many_consecutive(
        &self,
        section: u64,
        offsets: &[u64],
    ) -> Result<Vec<V>, Error> {
        match offsets.len() {
            0 => return Ok(Vec::new()),
            1 => return Ok(vec![self.get(section, offsets[0]).await?]),
            _ => {}
        }

        let start = offsets[0];
        let end = offsets[offsets.len() - 1];
        if end <= start {
            // Non-strictly-increasing; fall back to individual reads.
            let mut items = Vec::with_capacity(offsets.len());
            for &off in offsets {
                items.push(self.get(section, off).await?);
            }
            return Ok(items);
        }

        let range_len = usize::try_from(end - start).map_err(|_| Error::OffsetOverflow)?;
        let bytes = self
            .sections
            .read_at(section, start, range_len)
            .await?
            .coalesce();
        let bytes = bytes.as_ref();

        let compressed = self.compression.is_some();
        let cfg = &self.codec_config;
        let mut items = Vec::with_capacity(offsets.len());
        let mut local_offset = 0usize;

        for window in offsets.windows(2) {
            let offset = window[0];
            let next_offset = window[1];
            assert!(offset < next_offset, "offsets must be strictly increasing");
            let item_len =
                usize::try_from(next_offset - offset).map_err(|_| Error::OffsetOverflow)?;

            let mut cursor = Cursor::new(&bytes[local_offset..]);
            let (size, varint_len) = decode_length_prefix(&mut cursor)?;
            let actual_len = size + varint_len;
            if actual_len != item_len {
                return Err(Error::OffsetDataMismatch {
                    section,
                    offset,
                    expected_len: item_len,
                    actual_len,
                });
            }

            let data_start = local_offset
                .checked_add(varint_len)
                .ok_or(Error::OffsetOverflow)?;
            let data_end = local_offset
                .checked_add(item_len)
                .ok_or(Error::OffsetOverflow)?;
            items.push(decode_item::<V>(
                &bytes[data_start..data_end],
                cfg,
                compressed,
            )?);
            local_offset = data_end;
        }

        // The last item is decoded individually because we don't know its end offset.
        items.push(self.get(section, end).await?);
        Ok(items)
    }

    /// Synchronously try to decode an item, returning `None` on cache miss or pruned section.
    pub(super) fn try_get_sync_into(
        &self,
        section: u64,
        offset: u64,
        buf: &mut Vec<u8>,
    ) -> Option<V> {
        let size = self.sections.try_section_size(section)?;
        let remaining = size.checked_sub(offset)?;
        let header_len = usize::try_from(remaining.min(MAX_U32_VARINT_SIZE as u64)).ok()?;
        if header_len == 0 {
            return None;
        }

        let mut header = [0u8; MAX_U32_VARINT_SIZE];
        if !self
            .sections
            .try_read_sync(section, offset, &mut header[..header_len])
        {
            return None;
        }
        let mut cursor = Cursor::new(&header[..header_len]);
        let (_, item_info) = find_item(&mut cursor, offset).ok()?;
        let (varint_len, data_len) = match item_info {
            ItemInfo::Complete {
                varint_len,
                data_len,
            } => (varint_len, data_len),
            ItemInfo::Incomplete {
                varint_len,
                total_len,
                ..
            } => (varint_len, total_len),
        };
        let item_len = varint_len.checked_add(data_len)?;
        if item_len > usize::try_from(remaining).ok()? {
            return None;
        }

        if item_len <= header_len {
            return decode_item::<V>(
                &header[varint_len..varint_len + data_len],
                &self.codec_config,
                self.compression.is_some(),
            )
            .ok();
        }

        buf.resize(item_len, 0);
        if !self.sections.try_read_sync(section, offset, buf) {
            return None;
        }
        decode_item::<V>(
            &buf[varint_len..varint_len + data_len],
            &self.codec_config,
            self.compression.is_some(),
        )
        .ok()
    }

    /// Stream items starting at `(start_section, start_offset)`. Yields
    /// `(section, offset, size, item)` tuples.
    ///
    /// Unlike [`crate::journal::segmented::variable::Journal::replay`], this method does **not**
    /// truncate trailing junk.
    /// Truncation is performed eagerly in [`Self::init`] for the tail section; sealed sections
    /// are guaranteed clean by the contiguous variable invariants. A trailing-junk error from
    /// the underlying [`Replay`] therefore indicates real corruption.
    pub(super) async fn replay(
        &self,
        start_section: u64,
        mut start_offset: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, u32, V), Error>> + Send + '_, Error> {
        let codec_config = self.codec_config.clone();
        let compressed = self.compression.is_some();
        let mut replays = Vec::new();
        for section in self.sections.sections_from(start_section) {
            let (replay, _size) = self.sections.replay_section(section, buffer).await?;
            replays.push((section, replay));
        }

        Ok(stream::iter(replays).flat_map(move |(section, replay)| {
            let skip_bytes = if section == start_section {
                let s = start_offset;
                start_offset = 0;
                s
            } else {
                0
            };
            stream::unfold(
                ReplayState {
                    section,
                    replay,
                    skip_bytes,
                    offset: 0,
                    codec_config: codec_config.clone(),
                    compressed,
                    done: false,
                },
                |mut state| async move {
                    if state.done {
                        return None;
                    }
                    let mut batch: Vec<Result<(u64, u64, u32, V), Error>> = Vec::new();
                    loop {
                        match state.replay.ensure(MAX_U32_VARINT_SIZE).await {
                            Ok(true) => {}
                            Ok(false) => {
                                if state.replay.remaining() == 0 {
                                    state.done = true;
                                    return if batch.is_empty() {
                                        None
                                    } else {
                                        Some((batch, state))
                                    };
                                }
                            }
                            Err(err) => {
                                batch.push(Err(err.into()));
                                state.done = true;
                                return Some((batch, state));
                            }
                        }

                        if state.skip_bytes > 0 {
                            let to_skip =
                                state.skip_bytes.min(state.replay.remaining() as u64) as usize;
                            state.replay.advance(to_skip);
                            state.skip_bytes -= to_skip as u64;
                            state.offset += to_skip as u64;
                            continue;
                        }

                        let before_remaining = state.replay.remaining();
                        let (item_size, varint_len) = match decode_length_prefix(&mut state.replay)
                        {
                            Ok(r) => r,
                            Err(err) => {
                                if state.replay.is_exhausted()
                                    || before_remaining < MAX_U32_VARINT_SIZE
                                {
                                    // End-of-blob, no more items.
                                    state.done = true;
                                    return if batch.is_empty() {
                                        None
                                    } else {
                                        Some((batch, state))
                                    };
                                }
                                batch.push(Err(err));
                                state.done = true;
                                return Some((batch, state));
                            }
                        };

                        match state.replay.ensure(item_size).await {
                            Ok(true) => {}
                            Ok(false) => {
                                // Incomplete item -- sealed/post-init sections shouldn't have
                                // this, so propagate as a runtime read error.
                                batch.push(Err(Error::Runtime(
                                    commonware_runtime::Error::BlobInsufficientLength,
                                )));
                                state.done = true;
                                return Some((batch, state));
                            }
                            Err(err) => {
                                batch.push(Err(err.into()));
                                state.done = true;
                                return Some((batch, state));
                            }
                        }

                        let item_offset = state.offset;
                        let next_offset = match state
                            .offset
                            .checked_add(varint_len as u64)
                            .and_then(|o| o.checked_add(item_size as u64))
                        {
                            Some(o) => o,
                            None => {
                                batch.push(Err(Error::OffsetOverflow));
                                state.done = true;
                                return Some((batch, state));
                            }
                        };
                        match decode_item::<V>(
                            (&mut state.replay).take(item_size),
                            &state.codec_config,
                            state.compressed,
                        ) {
                            Ok(decoded) => {
                                batch.push(Ok((
                                    state.section,
                                    item_offset,
                                    item_size as u32,
                                    decoded,
                                )));
                                state.offset = next_offset;
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
        }))
    }
}

/// Buffer size used internally when replaying for truncation.
const REPLAY_BUFFER_SIZE: NonZeroUsize = match NonZeroUsize::new(1024) {
    Some(n) => n,
    None => unreachable!(),
};

/// Per-section state for the replay stream.
struct ReplayState<B: Blob, C> {
    section: u64,
    replay: Replay<B>,
    skip_bytes: u64,
    offset: u64,
    codec_config: C,
    compressed: bool,
    done: bool,
}
