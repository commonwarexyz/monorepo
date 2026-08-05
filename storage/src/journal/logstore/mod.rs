//! Oversized journal over [LogStorage]: the log-storage pilot consumer.
//!
//! Same shape as the per-file [oversized journal](super::segmented::oversized)
//! -- a fixed-size index entry referencing a variable-length value -- with each
//! section's index entries and values stored as two logs of one [LogStorage]
//! family. All mutations since the last [Oversized::sync] stage in the family's
//! single transaction and commit as one atomic batch: an index entry and its
//! value bytes become durable together or not at all, so the per-file journal's
//! crash repair (backward validity scans, orphan cleanup, durable-truncation
//! ordering) has no counterpart here. [Oversized::rewind] and [Oversized::prune]
//! are batch boundaries too: they commit everything staged along with their own
//! mutations.
//!
//! Values use the per-file journal's exact frame -- optionally zstd-compressed
//! codec bytes followed by a CRC32 -- so entry `(offset, size)` locations are
//! byte-compatible and benchmark payloads weigh the same on both backends.
//!
//! Staged batches are bounded by the backend's per-transaction caps (by
//! default 384 MiB of payload and 1024 touched logs). A mutation that would
//! cross a cap fails, and because consuming errors destroy the handle, the
//! whole staged batch dies with it: consumers must sync below the caps
//! (qmdb's measured worst-case batch of ~154 MiB fits). [Oversized::init]
//! waits on the family's single writer, so a second concurrent init over the
//! same family blocks indefinitely until the first journal is dropped.
//!
//! New deployments only: there is no import path from a per-file journal, and
//! crash recovery is the backend's, not this module's.

use super::{Error, segmented::oversized::Record};
use commonware_codec::{Codec, CodecShared, FixedSize as _};
use commonware_cryptography::{Crc32, crc32};
use commonware_runtime::{
    BufMut, Error as RError, IoBufMut, LogFamily, LogStorage, LogTransaction,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io::Cursor,
    marker::PhantomData,
    num::NonZeroUsize,
    ops::Bound,
};
use zstd::{bulk::compress, decode_all};

/// The family's write transaction.
type Txn<S> = <<S as LogStorage>::Family as LogFamily>::Transaction;
/// A committed log handle of the family.
type FamilyLog<S> = <<S as LogStorage>::Family as LogFamily>::Log;
/// A log staged for creation in the current batch.
type FamilyDraft<S> = <Txn<S> as LogTransaction>::Draft;
/// A section's two logs as found at init, either possibly missing.
type Halves<S> = BTreeMap<u64, (Option<FamilyLog<S>>, Option<FamilyLog<S>>)>;

/// Configuration for the log-storage oversized journal.
#[derive(Clone)]
pub struct Config<C> {
    /// The family holding the journal's logs. One journal per family.
    pub family: String,

    /// Optional compression level for values (using zstd).
    pub compression: Option<u8>,

    /// Codec configuration for values.
    pub codec_config: C,
}

/// One section's pair of logs.
enum Slot<S: LogStorage> {
    /// Committed in an earlier batch; readable through the transaction's
    /// staged view (committed data plus this batch's mutations).
    Committed {
        index: FamilyLog<S>,
        values: FamilyLog<S>,
    },
    /// Created in the current batch; invisible outside the transaction until
    /// the next sync.
    Staged {
        index: FamilyDraft<S>,
        values: FamilyDraft<S>,
    },
}

/// Segmented journal for entries with oversized values, stored in a
/// [LogStorage] family.
///
/// Mutating functions consume the journal and return it only on success: an
/// error (or a dropped future) destroys the handle, and recovery is
/// re-initialization ([Oversized::init] reopens the family, which recovers a
/// poisoned commit). Dropping the journal aborts the staged batch. Mutations
/// on pruned sections fail with [Error::AlreadyPrunedToSection].
pub struct Oversized<S: LogStorage, I: Record, V: Codec> {
    storage: S,
    family_name: String,
    family: S::Family,
    /// The current batch. Always live: every commit acquires the successor
    /// before returning.
    txn: Txn<S>,
    sections: BTreeMap<u64, Slot<S>>,
    /// Sections below this fail mutation; resets at init like the per-file
    /// journal's floor.
    pruned_floor: u64,
    compression: Option<u8>,
    codec_config: V::Cfg,
    _entry: PhantomData<I>,
}

/// The index log's name for `section`.
fn index_name(section: u64) -> Vec<u8> {
    format!("{section:016x}.index").into_bytes()
}

/// The values log's name for `section`.
fn values_name(section: u64) -> Vec<u8> {
    format!("{section:016x}.values").into_bytes()
}

/// Parses a log name minted by [index_name] or [values_name] into
/// `(section, is_index)`, rejecting anything this module did not write.
fn parse_name(name: &[u8]) -> Option<(u64, bool)> {
    let hex = name.get(..16)?;
    if !hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let section = u64::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
    match &name[16..] {
        b".index" => Some((section, true)),
        b".values" => Some((section, false)),
        _ => None,
    }
}

/// Encodes a value frame: optionally compressed codec bytes plus a CRC32.
fn encode_value<V: CodecShared>(value: &V, compression: Option<u8>) -> Result<Vec<u8>, Error> {
    let mut buf = if let Some(level) = compression {
        let encoded = value.encode();
        compress(&encoded, level as i32).map_err(|_| Error::CompressionFailed)?
    } else {
        let mut buf = Vec::with_capacity(value.encode_size() + crc32::Digest::SIZE);
        value.write(&mut buf);
        buf
    };
    let checksum = Crc32::checksum(&buf);
    buf.put_u32(checksum);
    Ok(buf)
}

/// Decodes a value frame written by [encode_value].
fn decode_value<V: CodecShared>(
    buf: &[u8],
    compression: Option<u8>,
    codec_config: &V::Cfg,
) -> Result<V, Error> {
    if buf.len() < crc32::Digest::SIZE {
        return Err(Error::Corruption(format!(
            "value frame shorter than its checksum: {} bytes",
            buf.len()
        )));
    }
    let (data, footer) = buf.split_at(buf.len() - crc32::Digest::SIZE);
    let stored = u32::from_be_bytes(footer.try_into().expect("checksum is 4 bytes"));
    let computed = Crc32::checksum(data);
    if computed != stored {
        return Err(Error::ChecksumMismatch(stored, computed));
    }
    if compression.is_some() {
        let decompressed = decode_all(Cursor::new(data)).map_err(|_| Error::DecompressionFailed)?;
        V::decode_cfg(decompressed.as_ref(), codec_config).map_err(Error::Codec)
    } else {
        V::decode_cfg(data, codec_config).map_err(Error::Codec)
    }
}

impl<S: LogStorage, I: Record + Send + Sync, V: CodecShared> Oversized<S, I, V> {
    /// Bytes one index entry occupies (entries carry no per-item checksum:
    /// physical integrity is the backend's).
    pub const CHUNK_SIZE: usize = I::SIZE;

    /// Open the journal, creating its family if absent.
    ///
    /// Reopening a family whose last commit was interrupted recovers it in the
    /// backend; committed batches are atomic, so no state is repaired here. A
    /// family holds exactly one journal: any log this module did not write, or
    /// a section missing one of its two logs, fails with [Error::Corruption].
    pub async fn init(storage: S, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let family = storage.open_family(&cfg.family).await?;
        // Acquire the writer first: scans below then observe a quiescent
        // committed state.
        let txn = family.transaction().await?;

        let mut halves: Halves<S> = BTreeMap::new();
        for name in family.scan().await? {
            let Some((section, is_index)) = parse_name(&name) else {
                return Err(Error::Corruption(format!(
                    "foreign log in family: {name:?}"
                )));
            };
            let log = family
                .open(&name)
                .await?
                .ok_or_else(|| Error::Corruption(format!("scanned log absent: {name:?}")))?;
            let pair = halves.entry(section).or_default();
            let half = if is_index { &mut pair.0 } else { &mut pair.1 };
            *half = Some(log);
        }
        let mut sections = BTreeMap::new();
        for (section, pair) in halves {
            let (Some(index), Some(values)) = pair else {
                return Err(Error::Corruption(format!(
                    "section {section} is missing one of its logs"
                )));
            };
            sections.insert(section, Slot::Committed { index, values });
        }

        Ok(Self {
            storage,
            family_name: cfg.family,
            family,
            txn,
            sections,
            pruned_floor: 0,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            _entry: PhantomData,
        })
    }

    /// Fails when `section` is below the prune floor.
    const fn guard(&self, section: u64) -> Result<(), Error> {
        if section < self.pruned_floor {
            return Err(Error::AlreadyPrunedToSection(self.pruned_floor));
        }
        Ok(())
    }

    /// The section's slot, or the per-file journal's errors for pruned and
    /// absent sections.
    fn slot(&self, section: u64) -> Result<&Slot<S>, Error> {
        self.guard(section)?;
        self.sections
            .get(&section)
            .ok_or(Error::SectionOutOfRange(section))
    }

    /// Stages creation of `section`'s logs if it does not exist yet.
    fn ensure_section(&mut self, section: u64) -> Result<(), Error> {
        if self.sections.contains_key(&section) {
            return Ok(());
        }
        let index = self.txn.create(&index_name(section))?;
        let values = self.txn.create(&values_name(section))?;
        self.sections
            .insert(section, Slot::Staged { index, values });
        Ok(())
    }

    /// Reads `len` bytes at `offset` from the staged view of the section's
    /// index log.
    async fn read_index(
        &self,
        slot: &Slot<S>,
        offset: u64,
        len: usize,
    ) -> Result<IoBufMut, RError> {
        let bufs = match slot {
            Slot::Committed { index, .. } => self.txn.read_at(index, offset, len).await?,
            Slot::Staged { index, .. } => self.txn.read_draft_at(index, offset, len).await?,
        };
        Ok(bufs.coalesce())
    }

    /// Reads `len` bytes at `offset` from the staged view of the section's
    /// values log.
    async fn read_values(
        &self,
        slot: &Slot<S>,
        offset: u64,
        len: usize,
    ) -> Result<IoBufMut, RError> {
        let bufs = match slot {
            Slot::Committed { values, .. } => self.txn.read_at(values, offset, len).await?,
            Slot::Staged { values, .. } => self.txn.read_draft_at(values, offset, len).await?,
        };
        Ok(bufs.coalesce())
    }

    /// The staged length of the section's index log in bytes.
    fn index_len(&self, slot: &Slot<S>) -> u64 {
        match slot {
            Slot::Committed { index, .. } => self.txn.len(index),
            Slot::Staged { index, .. } => self.txn.len_draft(index),
        }
    }

    /// Append entry + value to the current batch.
    ///
    /// Nothing is durable until the next [Oversized::sync]; reads through this
    /// journal observe the append immediately.
    ///
    /// Returns `(self, position, offset, size)` where:
    /// - `position`: Position in the section's index log
    /// - `offset`: Byte offset of the value in the section's values log
    /// - `size`: Size of the value frame (including checksum)
    // Async only for signature parity with the per-file journal, whose append
    // performs I/O; staging here is in-memory.
    #[allow(clippy::unused_async)]
    pub async fn append(
        mut self,
        section: u64,
        entry: I,
        value: &V,
    ) -> Result<(Self, u64, u64, u32), Error> {
        self.guard(section)?;
        let frame = encode_value(value, self.compression)?;
        let size = u32::try_from(frame.len()).map_err(|_| Error::ValueTooLarge)?;
        self.ensure_section(section)?;

        let mut entry_buf = Vec::with_capacity(I::SIZE);
        let (index_offset, offset) = match self.sections.get(&section).expect("section ensured") {
            Slot::Committed { index, values } => {
                let offset = self.txn.append(values, frame)?;
                entry.with_location(offset, size).write(&mut entry_buf);
                (self.txn.append(index, entry_buf)?, offset)
            }
            Slot::Staged { index, values } => {
                let offset = self.txn.append_draft(values, frame)?;
                entry.with_location(offset, size).write(&mut entry_buf);
                (self.txn.append_draft(index, entry_buf)?, offset)
            }
        };
        debug_assert_eq!(index_offset % I::SIZE as u64, 0);
        Ok((self, index_offset / I::SIZE as u64, offset, size))
    }

    /// Get entry at position (index entry only, not value).
    pub async fn get(&self, section: u64, position: u64) -> Result<I, Error> {
        let slot = self.slot(section)?;
        let offset = position
            .checked_mul(I::SIZE as u64)
            .ok_or(Error::OffsetOverflow)?;
        let buf = self
            .read_index(slot, offset, I::SIZE)
            .await
            .map_err(|error| match error {
                RError::LogInsufficientLength => Error::ItemOutOfRange(position),
                other => Error::Runtime(other),
            })?;
        let mut bytes = buf.as_ref();
        I::read_cfg(&mut bytes, &()).map_err(Error::Codec)
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
        let entries = self.index_len(self.slot(section)?) / I::SIZE as u64;
        if entries == 0 {
            return Ok(None);
        }
        self.get(section, entries - 1).await.map(Some)
    }

    /// Get value using offset/size from entry.
    ///
    /// The offset should be the byte offset from `append()` or from the
    /// entry's `value_location()`.
    pub async fn get_value(&self, section: u64, offset: u64, size: u32) -> Result<V, Error> {
        let slot = self.slot(section)?;
        let buf = self
            .read_values(slot, offset, size as usize)
            .await
            .map_err(Error::Runtime)?;
        decode_value(buf.as_ref(), self.compression, &self.codec_config)
    }

    /// Get index size (in bytes) for a section, or 0 if it does not exist.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.guard(section)?;
        Ok(self
            .sections
            .get(&section)
            .map_or(0, |slot| self.index_len(slot)))
    }

    /// Get the value size for a section, derived from the last entry's
    /// location.
    pub async fn value_size(&self, section: u64) -> Result<u64, Error> {
        match self.last(section).await {
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
    /// The floor only tracks prunes from the current execution and resets at
    /// init, so a section pruned in a previous execution reports false.
    pub const fn pruned(&self, section: u64) -> bool {
        section < self.pruned_floor
    }

    /// Returns the oldest section number, if any exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.sections.first_key_value().map(|(&s, _)| s)
    }

    /// Returns the newest section number, if any exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.sections.last_key_value().map(|(&s, _)| s)
    }

    /// Commit the staged batch and start the next one.
    ///
    /// Durability is family-wide: every append, rewind, and prune staged since
    /// the last batch boundary commits atomically, whatever section it touched.
    pub async fn sync(self) -> Result<Self, Error> {
        self.commit_batch().await
    }

    /// Commits the staged batch, reopens logs created in it (their drafts die
    /// with the transaction), and acquires the next batch's transaction.
    async fn commit_batch(self) -> Result<Self, Error> {
        let Self {
            storage,
            family_name,
            family,
            txn,
            mut sections,
            pruned_floor,
            compression,
            codec_config,
            _entry,
        } = self;
        txn.commit().await?;
        for (&section, slot) in sections.iter_mut() {
            if let Slot::Staged { .. } = slot {
                let index = family.open(&index_name(section)).await?.ok_or_else(|| {
                    Error::Corruption(format!("section {section} index absent after commit"))
                })?;
                let values = family.open(&values_name(section)).await?.ok_or_else(|| {
                    Error::Corruption(format!("section {section} values absent after commit"))
                })?;
                *slot = Slot::Committed { index, values };
            }
        }
        let txn = family.transaction().await?;
        Ok(Self {
            storage,
            family_name,
            family,
            txn,
            sections,
            pruned_floor,
            compression,
            codec_config,
            _entry,
        })
    }

    /// Stages removal of a section's logs and forgets the slot.
    fn stage_remove(&mut self, section: u64) -> Result<(), Error> {
        match self.sections.remove(&section).expect("section exists") {
            Slot::Committed { index, values } => {
                self.txn.remove(&index)?;
                self.txn.remove(&values)?;
            }
            Slot::Staged { index, values } => {
                self.txn.discard(index)?;
                self.txn.discard(values)?;
            }
        }
        Ok(())
    }

    /// Stages the rewind of `section` to `index_size` (its values log follows
    /// the last retained entry's end).
    async fn stage_rewind(&mut self, section: u64, index_size: u64) -> Result<(), Error> {
        let Some(slot) = self.sections.get(&section) else {
            // Mirror the per-file journal: a missing section only rewinds to
            // zero.
            return if index_size == 0 {
                Ok(())
            } else {
                Err(Error::SectionOutOfRange(section))
            };
        };
        if index_size > self.index_len(slot) {
            return Err(Error::InvalidRewind(index_size));
        }
        let value_size = if index_size == 0 {
            0
        } else {
            let entry = self.get(section, index_size / I::SIZE as u64 - 1).await?;
            let (offset, size) = entry.value_location();
            offset
                .checked_add(u64::from(size))
                .ok_or(Error::OffsetOverflow)?
        };
        match self.sections.get(&section).expect("checked above") {
            Slot::Committed { index, values } => {
                self.txn.rewind(index, index_size)?;
                self.txn.rewind(values, value_size)?;
            }
            Slot::Staged { index, values } => {
                self.txn.rewind_draft(index, index_size)?;
                self.txn.rewind_draft(values, value_size)?;
            }
        }
        Ok(())
    }

    /// Rewind to a specific section and index size, removing all sections
    /// after it. The value size is derived from the last retained entry.
    ///
    /// A batch boundary: the rewind and everything staged before it commit as
    /// one atomic batch, durable before this returns.
    pub async fn rewind(mut self, section: u64, index_size: u64) -> Result<Self, Error> {
        self.guard(section)?;
        if !index_size.is_multiple_of(I::SIZE as u64) {
            return Err(Error::InvalidRewind(index_size));
        }
        let later: Vec<u64> = self
            .sections
            .range((Bound::Excluded(section), Bound::Unbounded))
            .map(|(&s, _)| s)
            .collect();
        for s in later {
            self.stage_remove(s)?;
        }
        self.stage_rewind(section, index_size).await?;
        self.commit_batch().await
    }

    /// Rewind only the given section to a specific index size.
    ///
    /// Unlike `rewind`, this does not affect other sections. A batch boundary
    /// (see [Oversized::rewind]).
    pub async fn rewind_section(mut self, section: u64, index_size: u64) -> Result<Self, Error> {
        self.guard(section)?;
        if !index_size.is_multiple_of(I::SIZE as u64) {
            return Err(Error::InvalidRewind(index_size));
        }
        self.stage_rewind(section, index_size).await?;
        self.commit_batch().await
    }

    /// Remove all sections below `min`. Returns true if any were removed.
    ///
    /// A batch boundary when anything is removed (see [Oversized::rewind]);
    /// otherwise only the floor advances.
    pub async fn prune(mut self, min: u64) -> Result<(Self, bool), Error> {
        self.pruned_floor = self.pruned_floor.max(min);
        let victims: Vec<u64> = self.sections.range(..min).map(|(&s, _)| s).collect();
        if victims.is_empty() {
            return Ok((self, false));
        }
        for s in victims {
            self.stage_remove(s)?;
        }
        let journal = self.commit_batch().await?;
        Ok((journal, true))
    }

    /// Consumes the journal and returns an owned [Replay] reader over index
    /// entries starting from `start_position` in `start_section`, observing
    /// the staged batch.
    // Async only for signature parity with the per-file journal, whose replay
    // setup flushes buffered pages; the staged view needs no flush.
    #[allow(clippy::unused_async)]
    pub async fn replay(
        self,
        start_section: u64,
        start_position: u64,
        buffer: NonZeroUsize,
    ) -> Result<Replay<S, I, V>, Error> {
        let pending: VecDeque<(u64, u64)> = self
            .sections
            .range(start_section..)
            .map(|(&s, _)| {
                (
                    s,
                    if s == start_section {
                        start_position
                    } else {
                        0
                    },
                )
            })
            .collect();
        Ok(Replay {
            journal: self,
            pending,
            current: None,
            chunk_entries: (buffer.get() / I::SIZE).max(1) as u64,
        })
    }

    /// Destroy the journal's family and all of its logs.
    pub async fn destroy(self) -> Result<(), Error> {
        let Self {
            storage,
            family_name,
            txn,
            ..
        } = self;
        // Abort the staged batch so the destroy does not wait on the writer.
        drop(txn);
        storage.destroy_family(&family_name).await?;
        Ok(())
    }
}

/// The [Replay] reader's progress within one section.
struct ReplayCursor<I> {
    section: u64,
    /// Position of the next entry to yield.
    next: u64,
    /// Entry count of the section at replay start.
    total: u64,
    /// Decoded entries starting at position `next`.
    buffered: VecDeque<I>,
}

/// Owned replay reader over an [Oversized]'s index entries.
///
/// Yields `(section, position, entry)` in order. An error ends the section
/// that produced it, and iteration continues with the next section. Reads are
/// non-destructive, so [Replay::finish] returns the journal at any point.
pub struct Replay<S: LogStorage, I: Record, V: Codec> {
    journal: Oversized<S, I, V>,
    /// Sections not yet started, each with its first position.
    pending: VecDeque<(u64, u64)>,
    current: Option<ReplayCursor<I>>,
    /// Entries fetched per read.
    chunk_entries: u64,
}

impl<S: LogStorage, I: Record + Send + Sync, V: CodecShared> Replay<S, I, V> {
    /// Returns the next `(section, position, entry)`, or `None` once every
    /// section is exhausted.
    pub async fn next(&mut self) -> Option<Result<(u64, u64, I), Error>> {
        loop {
            let Some(cursor) = &mut self.current else {
                let (section, start) = self.pending.pop_front()?;
                let total = match self.journal.size(section) {
                    Ok(size) => size / I::SIZE as u64,
                    Err(error) => return Some(Err(error)),
                };
                if start < total {
                    self.current = Some(ReplayCursor {
                        section,
                        next: start,
                        total,
                        buffered: VecDeque::new(),
                    });
                }
                continue;
            };
            if let Some(entry) = cursor.buffered.pop_front() {
                let position = cursor.next;
                cursor.next += 1;
                return Some(Ok((cursor.section, position, entry)));
            }
            if cursor.next >= cursor.total {
                self.current = None;
                continue;
            }

            // Refill from the index log.
            let count = self.chunk_entries.min(cursor.total - cursor.next);
            let slot = match self.journal.slot(cursor.section) {
                Ok(slot) => slot,
                Err(error) => {
                    self.current = None;
                    return Some(Err(error));
                }
            };
            let buf = match self
                .journal
                .read_index(
                    slot,
                    cursor.next * I::SIZE as u64,
                    (count * I::SIZE as u64) as usize,
                )
                .await
            {
                Ok(buf) => buf,
                Err(error) => {
                    self.current = None;
                    return Some(Err(Error::Runtime(error)));
                }
            };
            let cursor = self.current.as_mut().expect("cursor is live");
            let mut bytes = buf.as_ref();
            for _ in 0..count {
                match I::read_cfg(&mut bytes, &()) {
                    Ok(entry) => cursor.buffered.push_back(entry),
                    Err(error) => {
                        self.current = None;
                        return Some(Err(Error::Codec(error)));
                    }
                }
            }
        }
    }

    /// Returns the journal.
    pub fn finish(self) -> Result<Oversized<S, I, V>, Error> {
        Ok(self.journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{FixedSize, Read, ReadExt as _, Write};
    use commonware_macros::test_traced;
    use commonware_runtime::{Buf, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    /// Test index entry that stores a u64 id and references a value.
    #[derive(Debug, Clone, PartialEq)]
    struct TestEntry {
        id: u64,
        value_offset: u64,
        value_size: u32,
    }

    impl TestEntry {
        fn new(id: u64) -> Self {
            Self {
                id,
                value_offset: 0,
                value_size: 0,
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

    type TestValue = [u8; 16];
    type TestJournal = Oversized<deterministic::Context, TestEntry, TestValue>;

    fn test_cfg() -> Config<()> {
        Config {
            family: "test-oversized".into(),
            compression: None,
            codec_config: (),
        }
    }

    const CHUNK: u64 = TestJournal::CHUNK_SIZE as u64;

    /// Append entry `id` with value `[id; 16]` to `section`.
    async fn append(journal: TestJournal, section: u64, id: u8) -> (TestJournal, u64, u64, u32) {
        journal
            .append(section, TestEntry::new(id as u64), &[id; 16])
            .await
            .expect("Failed to append")
    }

    /// Assert that every entry in `section` reads back the value appended
    /// with it.
    async fn assert_entries_consistent(journal: &TestJournal, section: u64) {
        for position in 0..journal.size(section).expect("size") / CHUNK {
            let entry = journal.get(section, position).await.expect("Failed to get");
            let (offset, size) = entry.value_location();
            let value = journal
                .get_value(section, offset, size)
                .await
                .expect("entry must reference readable bytes");
            assert_eq!(value, [entry.id as u8; 16]);
        }
    }

    #[test_traced]
    fn test_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");

            // Staged appends are readable before any sync.
            let (journal, position, offset, size) = append(journal, 1, 42).await;
            assert_eq!(position, 0);
            assert_eq!(journal.get(1, 0).await.expect("Failed to get").id, 42);
            assert_eq!(
                journal
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value"),
                [42; 16]
            );

            // And still after.
            let journal = journal.sync().await.expect("Failed to sync");
            assert_eq!(journal.get(1, 0).await.expect("Failed to get").id, 42);
            assert!(matches!(
                journal.get(1, 1).await,
                Err(Error::ItemOutOfRange(1))
            ));
            assert!(matches!(
                journal.get(2, 0).await,
                Err(Error::SectionOutOfRange(2))
            ));
        });
    }

    #[test_traced]
    fn test_batch_atomicity_and_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");

            // One batch spanning three sections.
            for section in 1u64..=3 {
                (journal, _, _, _) = append(journal, section, section as u8).await;
                (journal, _, _, _) = append(journal, section, section as u8).await;
            }
            let journal = journal.sync().await.expect("Failed to sync");
            drop(journal);

            // Every section's pair persists, consistent.
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert_eq!(journal.oldest_section(), Some(1));
            assert_eq!(journal.newest_section(), Some(3));
            for section in 1u64..=3 {
                assert_eq!(journal.size(section).expect("size"), 2 * CHUNK);
                assert_entries_consistent(&journal, section).await;
            }
        });
    }

    #[test_traced]
    fn test_unsynced_batch_lost() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            let (journal, _, _, _) = append(journal, 1, 1).await;
            // Dropping the journal aborts the staged batch.
            drop(journal);

            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert_eq!(journal.oldest_section(), None);
            assert_eq!(journal.size(1).expect("size"), 0);
        });
    }

    #[test_traced]
    fn test_rewind_and_reappend_atomic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            let (journal, _, _, _) = append(journal, 1, 1).await;
            let (journal, _, _, _) = append(journal, 1, 2).await;
            let journal = journal.sync().await.expect("Failed to sync");

            // Rewind entry 2 away, then reappend at its freed offsets: the
            // per-file journal needed durable-truncation ordering to keep a
            // crash from reviving entry 2 over entry 3's bytes; here the
            // rewind committed atomically before the reappend stages.
            let journal = journal.rewind(1, CHUNK).await.expect("Failed to rewind");
            assert_eq!(journal.value_size(1).await.expect("value size"), 20);
            let (journal, position, offset, _) = append(journal, 1, 3).await;
            assert_eq!(position, 1);
            assert_eq!(offset, 20);
            let journal = journal.sync().await.expect("Failed to sync");
            drop(journal);

            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert_eq!(journal.size(1).expect("size"), 2 * CHUNK);
            assert_entries_consistent(&journal, 1).await;
        });
    }

    #[test_traced]
    fn test_rewind_removes_later_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            for section in 1u64..=3 {
                (journal, _, _, _) = append(journal, section, section as u8).await;
            }
            let journal = journal.sync().await.expect("Failed to sync");

            let journal = journal.rewind(1, CHUNK).await.expect("Failed to rewind");
            assert_eq!(journal.newest_section(), Some(1));
            drop(journal);

            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert_eq!(journal.newest_section(), Some(1));
            assert_eq!(journal.size(1).expect("size"), CHUNK);
            assert_entries_consistent(&journal, 1).await;
        });
    }

    #[test_traced]
    fn test_rewind_section_keeps_later_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            for section in 1u64..=2 {
                (journal, _, _, _) = append(journal, section, section as u8).await;
            }
            let journal = journal.sync().await.expect("Failed to sync");

            let journal = journal
                .rewind_section(1, 0)
                .await
                .expect("Failed to rewind section");
            assert_eq!(journal.size(1).expect("size"), 0);
            assert_eq!(journal.value_size(1).await.expect("value size"), 0);
            assert_eq!(journal.size(2).expect("size"), CHUNK);
            assert_entries_consistent(&journal, 2).await;
        });
    }

    #[test_traced]
    fn test_rewind_rejections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            let (journal, _, _, _) = append(journal, 1, 1).await;
            let journal = journal.sync().await.expect("Failed to sync");

            // Rejections stage nothing, but the handle is destroyed either
            // way: re-init after each.
            assert!(matches!(
                journal.rewind(1, CHUNK - 1).await,
                Err(Error::InvalidRewind(_))
            ));
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert!(matches!(
                journal.rewind(1, 2 * CHUNK).await,
                Err(Error::InvalidRewind(_))
            ));
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert!(matches!(
                journal.rewind_section(9, CHUNK).await,
                Err(Error::SectionOutOfRange(9))
            ));

            // Nothing was lost along the way.
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert_eq!(journal.size(1).expect("size"), CHUNK);
        });
    }

    #[test_traced]
    fn test_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            for section in 1u64..=3 {
                (journal, _, _, _) = append(journal, section, section as u8).await;
            }
            let journal = journal.sync().await.expect("Failed to sync");

            let (journal, pruned) = journal.prune(3).await.expect("Failed to prune");
            assert!(pruned);
            assert!(journal.pruned(2));
            assert!(!journal.pruned(3));
            assert_eq!(journal.oldest_section(), Some(3));
            assert!(matches!(
                journal.get(1, 0).await,
                Err(Error::AlreadyPrunedToSection(3))
            ));

            // Idempotent, and the floor never regresses.
            let (journal, pruned) = journal.prune(2).await.expect("Failed to prune");
            assert!(!pruned);
            assert!(journal.pruned(2));
            drop(journal);

            // Removals persisted; the floor resets at init.
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert_eq!(journal.oldest_section(), Some(3));
            assert!(!journal.pruned(2));
            assert_entries_consistent(&journal, 3).await;
        });
    }

    #[test_traced]
    fn test_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            let mut id = 0u8;
            for section in 1u64..=3 {
                for _ in 0..3 {
                    (journal, _, _, _) = append(journal, section, id).await;
                    id += 1;
                }
            }
            let journal = journal.sync().await.expect("Failed to sync");
            // Replay observes the staged batch too.
            let (journal, _, _, _) = append(journal, 3, id).await;

            // From (section 2, position 1), with a buffer smaller than one
            // section's entries to force chunked reads.
            let mut replay = journal
                .replay(2, 1, NZUsize!(2 * TestJournal::CHUNK_SIZE))
                .await
                .expect("Failed to replay");
            let mut seen = Vec::new();
            while let Some(item) = replay.next().await {
                let (section, position, entry) = item.expect("Failed to read entry");
                seen.push((section, position, entry.id));
            }
            assert_eq!(
                seen,
                vec![
                    (2, 1, 4),
                    (2, 2, 5),
                    (3, 0, 6),
                    (3, 1, 7),
                    (3, 2, 8),
                    (3, 3, 9)
                ]
            );

            // The journal comes back and the staged append is still staged.
            let journal = replay.finish().expect("Failed to finish");
            assert_eq!(journal.size(3).expect("size"), 4 * CHUNK);
        });
    }

    #[test_traced]
    fn test_compression_round_trip() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                compression: Some(3),
                ..test_cfg()
            };
            let journal = TestJournal::init(context.child("journal"), cfg.clone())
                .await
                .expect("Failed to init");
            let (journal, _, offset, size) = append(journal, 1, 7).await;
            let journal = journal.sync().await.expect("Failed to sync");
            drop(journal);

            let journal = TestJournal::init(context.child("journal"), cfg)
                .await
                .expect("Failed to reinit");
            assert_eq!(
                journal
                    .get_value(1, offset, size)
                    .await
                    .expect("Failed to get value"),
                [7; 16]
            );
        });
    }

    #[test_traced]
    fn test_last_and_value_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            assert_eq!(journal.value_size(1).await.expect("value size"), 0);

            let (journal, _, _, _) = append(journal, 1, 1).await;
            let (journal, _, offset, size) = append(journal, 1, 2).await;
            assert_eq!(
                journal
                    .last(1)
                    .await
                    .expect("Failed to get last")
                    .unwrap()
                    .id,
                2
            );
            assert_eq!(
                journal.value_size(1).await.expect("value size"),
                offset + u64::from(size)
            );
        });
    }

    #[test_traced]
    fn test_destroy() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to init");
            let (journal, _, _, _) = append(journal, 1, 1).await;
            let journal = journal.sync().await.expect("Failed to sync");
            journal.destroy().await.expect("Failed to destroy");

            let journal = TestJournal::init(context.child("journal"), test_cfg())
                .await
                .expect("Failed to reinit");
            assert_eq!(journal.oldest_section(), None);
        });
    }

    #[test_traced]
    fn test_foreign_log_fails_init() {
        use commonware_runtime::{LogFamily as _, LogStorage as _, LogTransaction as _};

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // A log this module did not write, committed directly into the
            // family.
            let family = context.open_family("test-oversized").await.unwrap();
            let mut txn = family.transaction().await.unwrap();
            txn.create(b"interloper").unwrap();
            txn.commit().await.unwrap();
            drop(family);

            assert!(matches!(
                TestJournal::init(context.child("journal"), test_cfg()).await,
                Err(Error::Corruption(_))
            ));
        });
    }
}
