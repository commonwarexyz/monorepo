//! Simple section-based blob storage for values.
//!
//! This module provides a minimal blob storage optimized for storing values where
//! the size is tracked externally (in an index entry). Unlike the segmented variable
//! journal, this format does not include a size prefix since the caller already
//! knows the size.
//!
//! # Format
//!
//! Each entry is stored as:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! |     Compressed Data (variable)    |   CRC32   |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! - **Compressed Data**: zstd compressed (if enabled) or raw codec output
//! - **CRC32**: 4-byte checksum of the compressed data
//!
//! # Read Flow
//!
//! 1. Get `(offset, size)` from index entry
//! 2. Read `size` bytes directly from blob at byte offset
//! 3. Last 4 bytes are CRC32, verify it
//! 4. Decompress remaining bytes if compression enabled
//! 5. Decode value

#[commonware_macros::stability(ALPHA)]
use super::manager::stored_names;
use super::manager::{Config as ManagerConfig, Manager, WriteFactory};
use crate::{
    Context,
    journal::{Error, frame},
};
use bytes::Bytes;
use commonware_codec::{Codec, CodecShared, FixedSize};
use commonware_cryptography::{Crc32, crc32};
#[cfg(any(test, feature = "test-utils"))]
use commonware_runtime::WriteOptions;
// Shared by the ALPHA reader and the test-only corrupt_frame helper.
#[cfg_attr(
    not(any(test, feature = "test-utils")),
    commonware_macros::stability(ALPHA)
)]
use commonware_runtime::{Blob, ReadOptions, Storage};
use commonware_runtime::{BufMut, Error as RError, Handle};
use std::{collections::BTreeMap, num::NonZeroUsize};
#[commonware_macros::stability(ALPHA)]
use std::{iter, ops::Range, sync::Arc};
use zstd::zstd_safe::compress_bound;

/// Physical overhead appended to every frame: the CRC32 of the frame's data.
pub(crate) const CHECKSUM_SIZE: usize = crc32::Digest::SIZE;

/// Configuration for blob storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// Optional zstd compression level for stored values.
    ///
    /// Keep the choice between `None` and `Some(_)` fixed while stored values are retained.
    /// Only the compression level may change between initializations when compression is enabled.
    pub compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding items.
    pub codec_config: C,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Verify and decode one frame (see the module's format section).
fn decode<V: Codec>(
    buf: impl AsRef<[u8]> + Into<Bytes>,
    compressed: bool,
    cfg: &V::Cfg,
) -> Result<V, Error> {
    if buf.as_ref().len() < CHECKSUM_SIZE {
        return Err(Error::Runtime(RError::BlobInsufficientLength));
    }
    let data_len = buf.as_ref().len() - CHECKSUM_SIZE;
    let data = &buf.as_ref()[..data_len];
    let stored_checksum = u32::from_be_bytes(
        buf.as_ref()[data_len..]
            .try_into()
            .expect("checksum is 4 bytes"),
    );
    let checksum = Crc32::checksum(data);
    if checksum != stored_checksum {
        return Err(Error::ChecksumMismatch(stored_checksum, checksum));
    }
    if compressed {
        let decompressed = frame::decompress(data)?;
        V::decode_cfg(decompressed, cfg).map_err(Error::Codec)
    } else {
        // One Bytes owner lets retained codec fields share the read allocation.
        V::decode_cfg(buf.into().slice(..data_len), cfg).map_err(Error::Codec)
    }
}

/// Split `locations` into consecutive runs of byte-adjacent frames spanning at most `max_bytes`.
///
/// A frame larger than `max_bytes` forms its own run. Every location must already be range
/// checked so that its end does not overflow.
#[commonware_macros::stability(ALPHA)]
fn coalesced_runs(
    locations: &[(u64, u32)],
    max_bytes: NonZeroUsize,
) -> impl Iterator<Item = Range<usize>> + '_ {
    let max_bytes = max_bytes.get() as u64;
    let mut start = 0;
    iter::from_fn(move || {
        let (offset, size) = *locations.get(start)?;
        let mut byte_end = offset + u64::from(size);
        let mut end = start + 1;
        while let Some(&(next_offset, next_size)) = locations.get(end) {
            let next_end = next_offset + u64::from(next_size);
            if next_offset != byte_end || next_end - offset > max_bytes {
                break;
            }
            byte_end = next_end;
            end += 1;
        }
        let run = start..end;
        start = end;
        Some(run)
    })
}

/// An owned read-only view of one Glob section with a fixed byte extent.
///
/// Appends do not extend this reader's bounds. Dropping the glob or removing its section does
/// not invalidate the reader. Truncating into its extent makes reads of the affected bytes
/// unspecified; callers must finish those reads before reusing their locations.
///
/// The reader shares the section's open blob handle; see [Storage::open] for handle uniqueness.
#[commonware_macros::stability(ALPHA)]
pub struct Reader<B: Blob, V: Codec> {
    blob: Arc<B>,
    size: u64,
    compressed: bool,
    codec_config: V::Cfg,
}

#[commonware_macros::stability(ALPHA)]
impl<B: Blob, V: Codec> Clone for Reader<B, V> {
    fn clone(&self) -> Self {
        Self {
            blob: self.blob.clone(),
            size: self.size,
            compressed: self.compressed,
            codec_config: self.codec_config.clone(),
        }
    }
}

#[commonware_macros::stability(ALPHA)]
impl<B: Blob, V: CodecShared> Reader<B, V> {
    /// Open an existing section without recovering, writing, or syncing its contents.
    ///
    /// Captures the stored byte length. The caller must exclude mutation and removal while
    /// opening, and keep the captured bytes unchanged while reading. For an appendable glob, use
    /// [Glob::snapshot] instead. Missing sections return [Error::SectionOutOfRange] without
    /// creating a blob. Opening fails while another handle to the section is alive (see
    /// [Storage::open]); share one reader by cloning it.
    pub async fn open(
        context: &impl Storage<Blob = B>,
        cfg: Config<V::Cfg>,
        section: u64,
    ) -> Result<Self, Error> {
        let name = section.to_be_bytes();
        if !stored_names(context, &cfg.partition)
            .await?
            .iter()
            .any(|stored| stored.as_slice() == name)
        {
            return Err(Error::SectionOutOfRange(section));
        }
        let (blob, size) = context.open(&cfg.partition, &name).await?;
        Ok(Self {
            blob: Arc::new(blob),
            size,
            compressed: cfg.compression.is_some(),
            codec_config: cfg.codec_config,
        })
    }

    /// Returns the captured size of the section in bytes.
    pub const fn size(&self) -> u64 {
        self.size
    }

    fn check_range(&self, offset: u64, size: u32) -> Result<(), Error> {
        let end = offset
            .checked_add(u64::from(size))
            .ok_or(Error::OffsetOverflow)?;
        if end > self.size || (size as usize) < CHECKSUM_SIZE {
            return Err(Error::Runtime(RError::BlobInsufficientLength));
        }
        Ok(())
    }

    /// Read a value at the byte offset and frame size returned by [Glob::append].
    ///
    /// Rejects ranges outside the captured extent before reading storage. Each read verifies
    /// the frame's checksum and decodes using the glob's compression and codec configuration.
    pub async fn get(&self, offset: u64, size: u32) -> Result<V, Error> {
        self.check_range(offset, size)?;
        let buf = self
            .blob
            .read_at(offset, size as usize, ReadOptions::default())
            .await?
            .freeze()
            .coalesce();
        decode(buf, self.compressed, &self.codec_config)
    }

    /// Read values in the order supplied, combining byte-adjacent locations into one I/O.
    ///
    /// Each location is the `(offset, size)` returned by [Glob::append]. Locations need not
    /// be sorted or unique; only consecutive, byte-adjacent entries share a read. Gaps are
    /// never read. Every range is checked against the captured extent before any I/O, and
    /// each value's checksum and codec are checked independently.
    ///
    /// Coalesced reads are limited to `max_batch_bytes`. A single frame larger than this
    /// budget is read alone.
    pub async fn get_many(
        &self,
        locations: &[(u64, u32)],
        max_batch_bytes: NonZeroUsize,
    ) -> Result<Vec<V>, Error> {
        for &(offset, size) in locations {
            self.check_range(offset, size)?;
        }

        let mut values = Vec::with_capacity(locations.len());
        for run in coalesced_runs(locations, max_batch_bytes) {
            let frames = &locations[run];
            let (offset, _) = frames[0];
            let (last_offset, last_size) = frames[frames.len() - 1];
            let len = usize::try_from(last_offset + u64::from(last_size) - offset)
                .map_err(|_| Error::SizeOverflow)?;
            let buf = self
                .blob
                .read_at(offset, len, ReadOptions::default())
                .await?
                .freeze()
                .coalesce();
            // Share one Bytes owner across the frames in this physical read.
            let buf = Bytes::from(buf);
            let mut cursor = 0;
            for &(_, size) in frames {
                let next = cursor + size as usize;
                values.push(decode(
                    buf.slice(cursor..next),
                    self.compressed,
                    &self.codec_config,
                )?);
                cursor = next;
            }
        }
        Ok(values)
    }
}

/// The glob's state, boxed so the public [Glob] handle stays pointer-sized.
struct Inner<E: Context, V: Codec> {
    manager: Manager<E, WriteFactory>,

    /// Compression level (if enabled).
    compression: Option<u8>,

    /// Codec configuration.
    codec_config: V::Cfg,
}

impl<E: Context, V: CodecShared> Inner<E, V> {
    /// See [Glob::init].
    async fn init(context: E, cfg: Config<V::Cfg>, ceiling: u64) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: WriteFactory {
                capacity: cfg.write_buffer,
                pool: context.storage_buffer_pool().clone(),
            },
        };
        let manager = Manager::init_bounded(context, manager_cfg, ceiling).await?;

        Ok(Self {
            manager,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        })
    }

    /// See [Glob::append].
    async fn append(&mut self, section: u64, value: &V) -> Result<(u64, u32), Error> {
        // Encode and optionally compress, then append checksum
        let buf = if let Some(level) = self.compression {
            // Compressed: encode first, then compress, then append checksum
            let encoded = value.encode();
            let mut compressed = Vec::with_capacity(compress_bound(encoded.len()) + CHECKSUM_SIZE);
            frame::compress_into(level, &encoded, &mut compressed)?;
            let checksum = Crc32::checksum(&compressed);
            compressed.put_u32(checksum);
            compressed
        } else {
            // Uncompressed: pre-allocate exact size to avoid copying
            let entry_size = value.encode_size() + CHECKSUM_SIZE;
            let mut buf = Vec::with_capacity(entry_size);
            value.write(&mut buf);
            let checksum = Crc32::checksum(&buf);
            buf.put_u32(checksum);
            buf
        };

        // Write to blob
        let entry_size = u32::try_from(buf.len()).map_err(|_| Error::ValueTooLarge)?;
        let writer = self.manager.get_or_create(section).await?;
        let offset = writer.size();
        writer.write_at(offset, buf).await.map_err(Error::Runtime)?;

        Ok((offset, entry_size))
    }

    /// See [Glob::get].
    async fn get(&self, section: u64, offset: u64, size: u32) -> Result<V, Error> {
        let writer = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        // Read via buffered writer (handles read-through for buffered data)
        let buf = writer.read_at(offset, size as usize).await?.coalesce();

        decode(buf, self.compression.is_some(), &self.codec_config)
    }

    /// See [Recovery::verify].
    async fn verify(&self, section: u64, offset: u64, size: u32) -> Result<bool, Error> {
        // A frame is at least its checksum trailer.
        if (size as usize) < CHECKSUM_SIZE {
            return Ok(false);
        }
        let Some(writer) = self.manager.get(section)? else {
            return Ok(false);
        };

        let buf = match writer.read_at(offset, size as usize).await {
            Ok(buf) => buf.coalesce(),
            Err(RError::BlobInsufficientLength | RError::OffsetOverflow) => return Ok(false),
            Err(err) => return Err(Error::Runtime(err)),
        };
        let data_len = buf.len() - CHECKSUM_SIZE;
        let stored_checksum = u32::from_be_bytes(
            buf.as_ref()[data_len..]
                .try_into()
                .expect("checksum is 4 bytes"),
        );
        Ok(Crc32::checksum(&buf.as_ref()[..data_len]) == stored_checksum)
    }

    /// See [Glob::capture].
    #[commonware_macros::stability(ALPHA)]
    fn capture(&self, section: u64) -> Result<Reader<E::Blob, V>, Error> {
        let writer = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;
        Ok(Reader {
            blob: writer.blob().clone(),
            size: writer.size(),
            compressed: self.compression.is_some(),
            codec_config: self.codec_config.clone(),
        })
    }

    /// See [Glob::inject].
    #[cfg(test)]
    async fn inject(&mut self, section: u64, offset: u64, buf: Vec<u8>) -> Result<(), Error> {
        let writer = self.manager.get_or_create(section).await?;
        writer.write_at(offset, buf).await.map_err(Error::Runtime)
    }

    /// See [Glob::sync].
    async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        self.manager.sync(sections).await
    }

    /// See [Glob::start_sync].
    async fn start_sync(&mut self, sections: impl crate::Sections) -> Result<Handle<()>, Error> {
        self.manager.start_sync(sections).await
    }

    /// See [Glob::sync_all].
    async fn sync_all(&mut self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// See [Glob::size].
    fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section)
    }

    /// Truncate an initialization-owned suffix.
    async fn truncate_pending(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.truncate_pending(section, size).await
    }

    /// See [Glob::prune].
    async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.manager.prune(min).await
    }

    /// See [Glob::pruned].
    const fn pruned(&self, section: u64) -> bool {
        self.manager.pruned(section)
    }

    /// See [Glob::oldest_section].
    fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// See [Glob::newest_section].
    fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// See [Glob::sections].
    fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.manager.sections()
    }

    /// See [Glob::remove_section].
    async fn remove_section(&mut self, section: u64) -> Result<bool, Error> {
        self.manager.remove_section(section).await
    }

    /// See [Glob::destroy].
    async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }
}

/// Simple section-based blob storage for values.
///
/// Uses [`buffer::Write`](commonware_runtime::buffer::Write) for batching writes.
/// Reads go directly to blobs without any caching (ideal for large values that
/// shouldn't pollute a page cache).
///
/// Mutating functions consume the glob and return it only on success: an error (or a dropped
/// future) destroys the handle. Mutations on pruned sections fail with
/// [Error::AlreadyPrunedToSection] without mutating. Check [Glob::pruned] first to keep the
/// handle.
pub struct Glob<E: Context, V: Codec>(Box<Inner<E, V>>);

impl<E: Context, V: CodecShared> std::fmt::Debug for Glob<E, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Glob")
            .field("oldest_section", &self.oldest_section())
            .field("newest_section", &self.newest_section())
            .finish_non_exhaustive()
    }
}

impl<E: Context, V: CodecShared> Glob<E, V> {
    /// Initialize blob storage, opening existing section blobs.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        Ok(Recovery::init(context, cfg, u64::MAX).await?.into())
    }

    /// Append value to section.
    ///
    /// The returned offset is the byte offset where the entry was written.
    /// The returned size is the total bytes written (compressed_data + crc32).
    /// Both should be stored in the index entry for later retrieval.
    pub async fn append(mut self, section: u64, value: &V) -> Result<(Self, u64, u32), Error> {
        let (offset, size) = self.0.append(section, value).await?;
        Ok((self, offset, size))
    }

    /// Read value at offset with known size (from index entry).
    ///
    /// The offset should be the byte offset returned by `append()`.
    /// Reads directly from blob without any caching.
    pub async fn get(&self, section: u64, offset: u64, size: u32) -> Result<V, Error> {
        self.0.get(section, offset, size).await
    }

    /// Capture an owned reader of all values currently appended to `section`.
    ///
    /// Syncs the section to flush buffered bytes and resolve pending write failures before
    /// sharing its blob. A completed sync is reused when no newer writes have occurred.
    /// The reader supports concurrent appends and section removal; truncation into its captured
    /// extent make affected reads unspecified.
    ///
    /// Returns [Error::AlreadyPrunedToSection] for a pruned section and
    /// [Error::SectionOutOfRange] for a missing section.
    #[commonware_macros::stability(ALPHA)]
    pub async fn snapshot(self, section: u64) -> Result<(Self, Reader<E::Blob, V>), Error> {
        let (glob, handle) = self.start_sync(section).await?;
        let reader = glob.capture(section)?;
        handle.await.map_err(Error::Runtime)?;
        Ok((glob, reader))
    }

    /// Capture an owned reader of the current extent of `section` without I/O.
    ///
    /// Call after a flush of `section` (such as [Glob::start_sync]) and before any further append
    /// to it: the reader reads the blob directly, so buffered bytes count toward its extent but
    /// are unreadable. The reader is usable before the sync completes; if the sync handle fails,
    /// discard the reader along with the glob.
    ///
    /// Returns [Error::AlreadyPrunedToSection] for a pruned section and
    /// [Error::SectionOutOfRange] for a missing section.
    #[commonware_macros::stability(ALPHA)]
    pub(super) fn capture(&self, section: u64) -> Result<Reader<E::Blob, V>, Error> {
        self.0.capture(section)
    }

    /// Inject arbitrary bytes at `offset` in `section`, bypassing entry framing.
    #[cfg(test)]
    pub(super) async fn inject(
        &mut self,
        section: u64,
        offset: u64,
        buf: Vec<u8>,
    ) -> Result<(), Error> {
        self.0.inject(section, offset, buf).await
    }

    /// Sync the given `sections` to disk (flushes write buffers).
    pub async fn sync(mut self, sections: impl crate::Sections) -> Result<Self, Error> {
        self.0.sync(sections).await?;
        Ok(self)
    }

    /// Start syncing the given `sections` to disk.
    ///
    /// An error reported by the returned [Handle] is fatal to the glob: the caller
    /// must stop using the returned glob.
    pub async fn start_sync(
        mut self,
        sections: impl crate::Sections,
    ) -> Result<(Self, Handle<()>), Error> {
        let handle = self.0.start_sync(sections).await?;
        Ok((self, handle))
    }

    /// Sync all sections to disk.
    pub async fn sync_all(mut self) -> Result<Self, Error> {
        self.0.sync_all().await?;
        Ok(self)
    }

    /// Get the current size of a section (including buffered data).
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.0.size(section)
    }

    /// Prune sections before min.
    pub async fn prune(mut self, min: u64) -> Result<(Self, bool), Error> {
        let pruned = self.0.prune(min).await?;
        Ok((self, pruned))
    }

    /// Returns true when `section` is below the prune floor.
    ///
    /// The floor only tracks prunes from the current execution and resets at init, so a
    /// section pruned in a previous execution reports false.
    pub fn pruned(&self, section: u64) -> bool {
        self.0.pruned(section)
    }

    /// Returns the number of the oldest section.
    pub fn oldest_section(&self) -> Option<u64> {
        self.0.oldest_section()
    }

    /// Returns the number of the newest section.
    pub fn newest_section(&self) -> Option<u64> {
        self.0.newest_section()
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.sections()
    }

    /// Remove a specific section. Returns true if the section existed and was removed.
    pub async fn remove_section(mut self, section: u64) -> Result<(Self, bool), Error> {
        let removed = self.0.remove_section(section).await?;
        Ok((self, removed))
    }

    /// Destroy all blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        self.0.destroy().await
    }
}

/// Owns value sections until paired initialization has finished.
pub(crate) struct Recovery<E: Context, V: Codec>(Box<Inner<E, V>>);

impl<E: Context, V: CodecShared> From<Recovery<E, V>> for Glob<E, V> {
    /// Publish every value section after paired recovery.
    fn from(recovery: Recovery<E, V>) -> Self {
        Self(recovery.0)
    }
}

impl<E: Context, V: CodecShared> Recovery<E, V> {
    /// Open value sections through `ceiling` under paired initialization ownership. Later sections
    /// stay closed until paired recovery removes them.
    pub(crate) async fn init(context: E, cfg: Config<V::Cfg>, ceiling: u64) -> Result<Self, Error> {
        Ok(Self(Box::new(Inner::init(context, cfg, ceiling).await?)))
    }

    /// Check whether the entry at `(offset, size)` in `section` has a valid trailing checksum.
    ///
    /// Returns `Ok(false)` if the frame is smaller than its checksum trailer, the section
    /// does not exist, the range is not fully covered by the section, or the checksum does
    /// not match. Other read failures are propagated.
    pub(crate) async fn verify(&self, section: u64, offset: u64, size: u32) -> Result<bool, Error> {
        self.0.verify(section, offset, size).await
    }

    /// Truncate to a specific section and size.
    ///
    /// Truncates the section to the given size and removes all sections after it. A shorter
    /// length is durable when this returns.
    pub(crate) async fn truncate(mut self, section: u64, size: u64) -> Result<Self, Error> {
        self.0.truncate_pending(section, size).await?;
        Ok(self)
    }

    /// Truncate only the given section to a specific size.
    ///
    /// Other sections are unaffected. A shorter length is durable when this returns.
    pub(crate) async fn truncate_section(mut self, section: u64, size: u64) -> Result<Self, Error> {
        self.0
            .manager
            .truncate_pending_section(section, size)
            .await?;
        Ok(self)
    }

    /// Durably truncate the selected independent value sections.
    pub(crate) async fn truncate_sections(
        mut self,
        sizes: &BTreeMap<u64, u64>,
    ) -> Result<Self, Error> {
        self.0.manager.truncate_pending_sections(sizes).await?;
        Ok(self)
    }

    /// Return the size of a section during recovery.
    pub(crate) fn size(&self, section: u64) -> Result<u64, Error> {
        self.0.size(section)
    }

    /// Return the retained section numbers.
    pub(crate) fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.sections()
    }

    /// Make repaired value sections durable.
    pub(crate) async fn sync(mut self, sections: impl crate::Sections) -> Result<Self, Error> {
        self.0.sync(sections).await?;
        Ok(self)
    }

    /// Remove an orphaned value section.
    pub(crate) async fn remove_section(mut self, section: u64) -> Result<Self, Error> {
        self.0.remove_section(section).await?;
        Ok(self)
    }
}

/// Flip one byte inside value frame `frame` of the blob at `name`, breaking that frame's CRC
/// while leaving every other frame valid. Models a value torn by a crash after its index entry
/// became durable. Addresses uncompressed fixed-size frames: `frame_size` is the encoded value
/// size plus its CRC32.
#[cfg(any(test, feature = "test-utils"))]
pub async fn corrupt_frame(
    storage: &impl Storage,
    partition: &str,
    name: &[u8],
    frame: u64,
    frame_size: u64,
) {
    let offset = frame * frame_size;
    let (blob, size) = storage.open(partition, name).await.unwrap();
    assert!(offset < size, "corruption target must be inside the blob");
    let byte = blob
        .read_at(offset, 1, ReadOptions::default())
        .await
        .unwrap()
        .coalesce();
    blob.write_at(offset, vec![byte.as_ref()[0] ^ 0xFF], WriteOptions::SYNC)
        .await
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Runner, Supervisor as _, deterministic,
        mocks::{
            DelayedSyncContext, PendingSyncs, RecordingContext, WriteFaultContext, WriteFaults,
            fail_pending_syncs, release_pending_syncs,
        },
    };
    use commonware_utils::{NZUsize, probability};
    use rand::Rng as _;

    impl<E: crate::Context, V: CodecShared> Glob<E, V> {
        pub(in super::super) fn test_configuration(&self) -> (E, Config<V::Cfg>) {
            let (context, partition, factory) = self.0.manager.test_configuration();
            (
                context,
                Config {
                    partition,
                    write_buffer: factory.capacity,
                    compression: self.0.compression,
                    codec_config: self.0.codec_config.clone(),
                },
            )
        }

        async fn test_reopen_section(self, section: u64, end: u64) -> Result<Self, Error> {
            let (context, partition, factory) = self.0.manager.test_configuration();
            let cfg = Config {
                partition,
                write_buffer: factory.capacity,
                compression: self.0.compression,
                codec_config: self.0.codec_config.clone(),
            };
            _ = self.sync_all().await?;
            let pending = Recovery::init(context, cfg, u64::MAX).await?;
            let pending = pending.truncate_section(section, end).await?;
            Ok(pending.into())
        }
    }

    fn test_cfg() -> Config<()> {
        Config {
            partition: "test-partition".into(),
            compression: None,
            codec_config: (),
            write_buffer: NZUsize!(1024),
        }
    }

    #[test_traced]
    fn test_snapshot_lifetime() {
        for compression in [None, Some(3)] {
            deterministic::Runner::default().start(|context| async move {
                let cfg = Config {
                    compression,
                    ..test_cfg()
                };
                let glob = Glob::<_, [u8; 64]>::init(context, cfg).await.unwrap();
                let (glob, offset, size) = glob.append(1, &[42; 64]).await.unwrap();
                let (glob, reader) = glob.snapshot(1).await.unwrap();
                assert_eq!(reader.size(), u64::from(size));

                let ((glob, next_offset, next_size), value) =
                    futures::try_join!(glob.append(1, &[7; 64]), reader.get(offset, size)).unwrap();
                assert_eq!(value, [42; 64]);
                let glob = glob.sync(1).await.unwrap();
                assert!(matches!(
                    reader.get(next_offset, next_size).await,
                    Err(Error::Runtime(RError::BlobInsufficientLength))
                ));

                let retained = reader.clone();
                drop(reader);
                let (glob, removed) = glob.remove_section(1).await.unwrap();
                assert!(removed);
                let (glob, _, _) = glob.append(1, &[9; 64]).await.unwrap();
                let glob = glob.sync(1).await.unwrap();
                assert_eq!(retained.get(offset, size).await.unwrap(), [42; 64]);

                let (glob, offset, size) = glob.append(2, &[11; 64]).await.unwrap();
                let (glob, pruned_reader) = glob.snapshot(2).await.unwrap();
                let (glob, _) = glob.prune(3).await.unwrap();
                assert_eq!(pruned_reader.get(offset, size).await.unwrap(), [11; 64]);

                let (glob, offset, size) = glob.append(3, &[13; 64]).await.unwrap();
                let (glob, destroyed_reader) = glob.snapshot(3).await.unwrap();
                glob.destroy().await.unwrap();
                assert_eq!(destroyed_reader.get(offset, size).await.unwrap(), [13; 64]);
            });
        }
    }

    #[test_traced]
    fn test_capture_after_start_sync() {
        deterministic::Runner::default().start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let glob = Glob::<_, u32>::init(context, test_cfg()).await.unwrap();
            let (glob, offset, size) = glob.append(0, &42).await.unwrap();
            let (glob, first) = glob.start_sync(0).await.unwrap();
            let reader = glob.capture(0).unwrap();

            assert_eq!(pending.starts(), 1);
            assert_eq!(pending.completions(), 0);
            assert_eq!(reader.get(offset, size).await.unwrap(), 42);

            let (glob, second) = glob.start_sync(0).await.unwrap();
            let repeated = glob.capture(0).unwrap();
            assert_eq!(pending.starts(), 1, "the pending cut should be reused");
            assert_eq!(repeated.size(), reader.size());
            assert!(matches!(glob.capture(1), Err(Error::SectionOutOfRange(1))));

            release_pending_syncs(&pending);
            first.await.unwrap();
            second.await.unwrap();

            let (glob, next_offset, next_size) = glob.append(0, &7).await.unwrap();
            assert_eq!(reader.get(offset, size).await.unwrap(), 42);
            assert!(matches!(
                reader.get(next_offset, next_size).await,
                Err(Error::Runtime(RError::BlobInsufficientLength))
            ));
            drop(glob);
        });
    }

    #[test_traced]
    fn test_capture_keeps_sync_failure() {
        deterministic::Runner::default().start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let glob = Glob::<_, u32>::init(context, test_cfg()).await.unwrap();
            let (glob, _, _) = glob.append(0, &42).await.unwrap();
            let (glob, handle) = glob.start_sync(0).await.unwrap();
            let _reader = glob.capture(0).unwrap();

            fail_pending_syncs(&pending);
            assert!(matches!(handle.await, Err(RError::Io(_))));
            drop(glob);
        });
    }

    #[test_traced]
    fn test_capture_pruned_section() {
        deterministic::Runner::default().start(|context| async move {
            let glob = Glob::<_, u32>::init(context, test_cfg()).await.unwrap();
            let (glob, _, _) = glob.append(1, &42).await.unwrap();
            let (glob, pruned) = glob.prune(2).await.unwrap();
            assert!(pruned);
            assert!(matches!(
                glob.capture(1),
                Err(Error::AlreadyPrunedToSection(2))
            ));
        });
    }

    #[test_traced]
    fn test_snapshot_bounds_before_io() {
        deterministic::Runner::default().start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let glob = Glob::<_, u32>::init(context, test_cfg()).await.unwrap();
            let (glob, _, size) = glob.append(0, &42).await.unwrap();
            let (glob, reader) = glob.snapshot(0).await.unwrap();
            drop(glob);
            recordings.clear();
            for (offset, size) in [(u64::MAX, size), (1, size), (0, 0), (0, 3)] {
                assert!(reader.get(offset, size).await.is_err());
            }
            assert!(recordings.snapshot().reads.is_empty());
            assert_eq!(reader.get(0, size).await.unwrap(), 42);
        });
    }

    #[test_traced]
    fn test_snapshot_missing_section() {
        deterministic::Runner::default().start(|context| async move {
            let glob = Glob::<_, u32>::init(context.child("missing"), test_cfg())
                .await
                .unwrap();
            assert!(matches!(
                glob.snapshot(1).await,
                Err(Error::SectionOutOfRange(1))
            ));
            let glob = Glob::<_, u32>::init(context.child("pruned"), test_cfg())
                .await
                .unwrap();
            let (glob, _, _) = glob.append(1, &42).await.unwrap();
            let (glob, _) = glob.prune(2).await.unwrap();
            assert!(matches!(
                glob.snapshot(1).await,
                Err(Error::AlreadyPrunedToSection(2))
            ));
        });
    }

    #[test_traced]
    fn test_snapshot_flush_failure() {
        deterministic::Runner::default().start(|context| async move {
            let faults = WriteFaults::default();
            let context = WriteFaultContext {
                inner: context,
                faults: faults.clone(),
            };
            let glob = Glob::<_, u32>::init(context, test_cfg()).await.unwrap();
            let (glob, _, _) = glob.append(0, &42).await.unwrap();
            assert_eq!(faults.writes(), 0);
            faults.arm();
            assert!(matches!(glob.snapshot(0).await, Err(Error::Runtime(_))));
        });
    }

    #[test_traced]
    fn test_reader_open_is_read_only() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_cfg();
            let glob = Glob::<_, u32>::init(context.child("writer"), cfg.clone())
                .await
                .unwrap();
            let (glob, offset, size) = glob.append(1, &42).await.unwrap();
            drop(glob.sync(1).await.unwrap());

            let pending = PendingSyncs::default();
            pending.arm();
            pending.unblock();
            let (context, recordings) = RecordingContext::new(DelayedSyncContext {
                inner: context.child("reader"),
                pending: pending.clone(),
            });
            assert!(matches!(
                Reader::<_, u32>::open(&context, cfg.clone(), 2).await,
                Err(Error::SectionOutOfRange(2))
            ));
            assert_eq!(
                context.scan(&cfg.partition).await.unwrap(),
                vec![1u64.to_be_bytes().to_vec()]
            );
            let reader = Reader::<_, u32>::open(&context, cfg, 1).await.unwrap();
            assert_eq!(reader.size(), u64::from(size));
            assert!(recordings.snapshot().reads.is_empty());
            assert_eq!(reader.get(offset, size).await.unwrap(), 42);
            assert_eq!(recordings.snapshot().reads.len(), 1);
            assert!(recordings.snapshot().writes.is_empty());
            assert_eq!(pending.calls(), 0);
        });
    }

    #[test_traced]
    fn test_reader_get_many_coalesces_with_budget() {
        for compression in [None, Some(3)] {
            deterministic::Runner::default().start(|context| async move {
                let (context, recordings) = RecordingContext::new(context);
                let cfg = Config {
                    compression,
                    ..test_cfg()
                };
                let mut glob = Glob::<_, u32>::init(context, cfg).await.unwrap();
                let mut locations = Vec::new();
                for value in 0..5 {
                    let (offset, size);
                    (glob, offset, size) = glob.append(0, &value).await.unwrap();
                    locations.push((offset, size));
                }
                let (glob, reader) = glob.snapshot(0).await.unwrap();
                drop(glob);
                let pair_bytes = (locations[0].1 + locations[1].1) as usize;
                let cases: &[(&[usize], usize, usize)] = &[
                    (&[], 0, usize::MAX),
                    (&[0, 1, 2, 3], 1, usize::MAX),
                    (&[0, 1, 3, 4], 2, usize::MAX),
                    (&[4, 1, 1, 2], 3, usize::MAX),
                    (&[0, 1, 2, 3], 2, pair_bytes),
                    (&[0, 1], 2, 1),
                ];
                for &(indices, reads, budget) in cases {
                    let requested = indices.iter().map(|&i| locations[i]).collect::<Vec<_>>();
                    recordings.clear();
                    let values = reader
                        .get_many(&requested, NonZeroUsize::new(budget).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(
                        values,
                        indices.iter().map(|&i| i as u32).collect::<Vec<_>>()
                    );
                    assert_eq!(recordings.snapshot().reads.len(), reads);
                }
            });
        }
    }

    #[test]
    fn test_coalesced_runs() {
        let locations = [(0, 8), (8, 8), (16, 8), (32, 8), (40, 64), (104, 8), (0, 8)];
        let runs = |max: usize| {
            coalesced_runs(&locations, NonZeroUsize::new(max).unwrap()).collect::<Vec<_>>()
        };
        assert_eq!(runs(usize::MAX), vec![0..3, 3..6, 6..7]);
        assert_eq!(runs(16), vec![0..2, 2..3, 3..4, 4..5, 5..6, 6..7]);
        assert_eq!(coalesced_runs(&[], NZUsize!(1)).count(), 0);
    }

    #[test_traced]
    fn test_reader_get_many_rejects_ranges_before_io() {
        deterministic::Runner::default().start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let glob = Glob::<_, u32>::init(context, test_cfg()).await.unwrap();
            let (glob, offset, size) = glob.append(0, &42).await.unwrap();
            let (_, reader) = glob.snapshot(0).await.unwrap();
            recordings.clear();
            for invalid in [(u64::MAX, size), (offset + 1, size), (0, 0), (0, 3)] {
                assert!(
                    reader
                        .get_many(&[(offset, size), invalid], NZUsize!(64))
                        .await
                        .is_err()
                );
                assert!(recordings.snapshot().reads.is_empty());
            }
        });
    }

    #[test_traced]
    fn test_reader_get_many_checks_each_frame() {
        deterministic::Runner::default().start(|context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let cfg = test_cfg();
            let mut glob = Glob::<_, u32>::init(context.child("writer"), cfg.clone())
                .await
                .unwrap();
            let mut locations = Vec::new();
            for value in 0..3 {
                let (offset, size);
                (glob, offset, size) = glob.append(0, &value).await.unwrap();
                locations.push((offset, size));
            }
            drop(glob.sync(0).await.unwrap());
            corrupt_frame(&context, &cfg.partition, &0u64.to_be_bytes(), 1, 8).await;
            let reader = Reader::<_, u32>::open(&context, cfg.clone(), 0)
                .await
                .unwrap();
            recordings.clear();
            assert!(matches!(
                reader.get_many(&locations, NZUsize!(64)).await,
                Err(Error::ChecksumMismatch(_, _))
            ));
            assert_eq!(recordings.snapshot().reads.len(), 1);
            recordings.clear();
            assert_eq!(
                reader
                    .get_many(&[locations[0], locations[2]], NZUsize!(64))
                    .await
                    .unwrap(),
                vec![0, 2]
            );
            assert_eq!(recordings.snapshot().reads.len(), 2);

            // One open per blob: release the first reader before reopening with another codec.
            drop(reader);
            let reader = Reader::<_, u64>::open(&context, cfg, 0).await.unwrap();
            assert!(matches!(
                reader.get_many(&locations, NZUsize!(64)).await,
                Err(Error::Codec(_))
            ));
        });
    }

    #[test_traced]
    fn test_reader_get_many_retains_decoded_bytes() {
        for compression in [None, Some(3)] {
            deterministic::Runner::default().start(|context| async move {
                let cfg = Config {
                    partition: "bytes".into(),
                    compression,
                    codec_config: (..).into(),
                    write_buffer: NZUsize!(1024),
                };
                let mut glob = Glob::<_, Bytes>::init(context, cfg).await.unwrap();
                let expected = [Bytes::from(vec![7; 31]), Bytes::from(vec![9; 73])];
                let mut locations = Vec::new();
                for value in &expected {
                    let (offset, size);
                    (glob, offset, size) = glob.append(0, value).await.unwrap();
                    locations.push((offset, size));
                }
                let (glob, reader) = glob.snapshot(0).await.unwrap();
                let values = reader.get_many(&locations, NZUsize!(1024)).await.unwrap();
                drop(reader);
                glob.destroy().await.unwrap();
                assert_eq!(values, expected);
            });
        }
    }

    #[test_traced]
    fn test_glob_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append a value
            let value: i32 = 42;
            let (glob, offset, size) = glob.append(1, &value).await.expect("Failed to append");
            assert_eq!(offset, 0);

            // Get the value back
            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            // Sync and verify
            let glob = glob.sync(1).await.expect("Failed to sync");
            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_get_view() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (..).into(),
                write_buffer: NZUsize!(1024),
            };
            let glob: Glob<_, Bytes> = Glob::init(context.child("storage"), cfg)
                .await
                .expect("Failed to init glob");

            // Append a value that stays in the buffered tip
            let value = Bytes::from(vec![7u8; 32]);
            let (glob, offset, size) = glob.append(1, &value).await.expect("Failed to append");

            // Two live reads decode views of the same tip buffer
            let a = glob.get(1, offset, size).await.expect("Failed to get");
            let b = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(a, value);
            assert_eq!(b, value);
            assert_eq!(a.as_ptr(), b.as_ptr());

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_multiple_values() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append multiple values
            let values: Vec<i32> = vec![1, 2, 3, 4, 5];
            let mut locations = Vec::new();

            for value in &values {
                let offset;
                let size;
                (glob, offset, size) = glob.append(1, value).await.expect("Failed to append");
                locations.push((offset, size));
            }

            // Get all values back
            for (i, (offset, size)) in locations.iter().enumerate() {
                let retrieved = glob.get(1, *offset, *size).await.expect("Failed to get");
                assert_eq!(retrieved, values[i]);
            }

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_with_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: Some(3), // zstd level 3
                codec_config: (),
                write_buffer: NZUsize!(1024),
            };
            let glob: Glob<_, [u8; 100]> = Glob::init(context.child("storage"), cfg)
                .await
                .expect("Failed to init glob");

            // Append a value
            let value: [u8; 100] = [0u8; 100]; // Compressible data
            let (glob, offset, size) = glob.append(1, &value).await.expect("Failed to append");

            // Size should be smaller due to compression
            assert!(size < 100 + 4);

            // Get the value back
            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_compressed_entries_match_reference_format() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: Some(19),
                codec_config: ((..).into(), ()),
                write_buffer: NZUsize!(1024),
            };
            let mut glob: Glob<_, Vec<u8>> = Glob::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to init glob");

            // Random bytes stay larger than the write buffer after compression, so that entry
            // is written through to the blob.
            let mut values: Vec<Vec<u8>> = [0usize, 1, 127, 4096, 70_000]
                .into_iter()
                .map(|len| (0..len).map(|i| (i % 7) as u8).collect())
                .collect();
            let mut random = vec![0; 4096];
            context.fill_bytes(&mut random);
            values.push(random);

            let mut entries = Vec::new();
            for value in values {
                let offset;
                let size;
                (glob, offset, size) = glob.append(1, &value).await.expect("Failed to append");

                let mut expected = zstd::bulk::compress(&value.encode(), 19).unwrap();
                let checksum = Crc32::checksum(&expected);
                expected.put_u32(checksum);
                let writer = glob.0.manager.get(1).unwrap().unwrap();
                let stored = writer.read_at(offset, size as usize).await.unwrap();
                assert_eq!(stored.coalesce().as_ref(), expected.as_slice());
                assert_eq!(glob.get(1, offset, size).await.unwrap(), value);
                entries.push((offset, size, expected, value));
            }
            assert!(entries.last().unwrap().1 > 1024);
            let glob = glob.sync(1).await.expect("Failed to sync");
            drop(glob);

            // Persisted entries keep the same bytes and values.
            let glob: Glob<_, Vec<u8>> = Glob::init(context.child("second"), cfg)
                .await
                .expect("Failed to reinit glob");
            let writer = glob.0.manager.get(1).unwrap().unwrap();
            for (offset, size, expected, value) in &entries {
                let stored = writer.read_at(*offset, *size as usize).await.unwrap();
                assert_eq!(stored.coalesce().as_ref(), expected.as_slice());
                assert_eq!(glob.get(1, *offset, *size).await.unwrap(), *value);
            }

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append to multiple sections
            for section in 1..=5 {
                (glob, _, _) = glob
                    .append(section, &(section as i32))
                    .await
                    .expect("Failed to append");
                glob = glob.sync(section).await.expect("Failed to sync");
            }

            // Prune sections < 3
            let (glob, _) = glob.prune(3).await.expect("Failed to prune");

            // The public accessor mirrors the guard
            assert!(glob.pruned(1));
            assert!(glob.pruned(2));
            assert!(!glob.pruned(3));

            // Sections 1 and 2 should be gone
            assert!(glob.get(1, 0, 8).await.is_err());
            assert!(glob.get(2, 0, 8).await.is_err());

            // Sections 3-5 should still exist
            assert!(glob.0.manager.blobs.contains_key(&3));
            assert!(glob.0.manager.blobs.contains_key(&4));
            assert!(glob.0.manager.blobs.contains_key(&5));

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_checksum_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append a value
            let value: i32 = 42;
            let (glob, offset, size) = glob.append(1, &value).await.expect("Failed to append");
            let mut glob = glob.sync(1).await.expect("Failed to sync");

            // Corrupt the data by writing directly to the underlying blob
            let writer = glob.0.manager.blobs.get_mut(&1).unwrap();
            writer
                .write_at(offset, vec![0xFF, 0xFF, 0xFF, 0xFF])
                .await
                .expect("Failed to corrupt");
            writer.sync().await.expect("Failed to sync");

            // Get should fail with checksum mismatch
            let result = glob.get(1, offset, size).await;
            assert!(matches!(result, Err(Error::ChecksumMismatch(_, _))));

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_truncate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append multiple values and track sizes
            let values: Vec<i32> = vec![1, 2, 3, 4, 5];
            let mut locations = Vec::new();

            for value in &values {
                let offset;
                let size;
                (glob, offset, size) = glob.append(1, value).await.expect("Failed to append");
                locations.push((offset, size));
            }
            glob = glob.sync(1).await.expect("Failed to sync");

            // Truncate to after the third value
            let (third_offset, third_size) = locations[2];
            let truncate_size = third_offset + u64::from(third_size);
            let glob = glob
                .test_reopen_section(1, truncate_size)
                .await
                .expect("Failed to truncate");

            // First three values should still be readable
            for (i, (offset, size)) in locations.iter().take(3).enumerate() {
                let retrieved = glob.get(1, *offset, *size).await.expect("Failed to get");
                assert_eq!(retrieved, values[i]);
            }

            // Fourth and fifth values should fail (reading past end of blob)
            let (fourth_offset, fourth_size) = locations[3];
            let result = glob.get(1, fourth_offset, fourth_size).await;
            assert!(result.is_err());

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    /// Reopen a section at a shorter size, append over the freed bytes without a sync, then
    /// crash with the append retained or lost and any unsynced resize lost. Recovery must not
    /// stitch the discarded frames behind the new value.
    #[test_traced]
    fn test_glob_truncate_survives_crash() {
        // A buffer smaller than one 8-byte frame writes every value straight to the blob.
        let cfg = || Config {
            write_buffer: NZUsize!(4),
            ..test_cfg()
        };
        for retained in [true, false] {
            // Seed durable history, reopen after its first frame, and leave a replacement unsynced.
            let executor = deterministic::Runner::default();
            let ((kept, offset, size), checkpoint) =
                executor.start_and_recover(move |context| async move {
                    let mut glob: Glob<_, i32> =
                        Glob::init(context.child("first"), cfg()).await.unwrap();
                    let mut kept = 0;
                    for value in 1..=3 {
                        let (offset, size);
                        (glob, offset, size) = glob.append(1, &value).await.unwrap();
                        if value == 1 {
                            kept = offset + u64::from(size);
                        }
                    }
                    let glob = glob.sync(1).await.unwrap();

                    // Keep or lose unsynced writes and lose unsynced resizes at the crash.
                    *context.storage_fault_config().write() = if retained {
                        deterministic::FaultConfig {
                            write_rate: Some(deterministic::WriteConfig {
                                failure_rate: probability!(0.0),
                                retention_rate: probability!(1.0),
                                mode: deterministic::PartialWriteMode::Prefix,
                            }),
                            resize_rate: Some(deterministic::ResizeConfig {
                                failure_rate: probability!(0.0),
                                partial_rate: probability!(0.0),
                            }),
                            ..Default::default()
                        }
                    } else {
                        deterministic::FaultConfig::default()
                    };
                    let glob = glob.test_reopen_section(1, kept).await.unwrap();
                    assert_eq!(glob.size(1).unwrap(), kept);
                    let (glob, offset, size) = glob.append(1, &4).await.unwrap();
                    assert_eq!(offset, kept);
                    drop(glob);
                    (kept, offset, size)
                });

            // Recovery may retain or lose the replacement, but cannot restore the discarded suffix.
            deterministic::Runner::from(checkpoint).start(move |context| async move {
                *context.storage_fault_config().write() = deterministic::FaultConfig::default();
                let glob: Glob<_, i32> = Glob::init(context.child("second"), cfg()).await.unwrap();
                let end = if retained {
                    offset + u64::from(size)
                } else {
                    kept
                };
                let recovered = glob.size(1).unwrap();
                assert_eq!(
                    recovered, end,
                    "recovered {recovered} bytes, not the {end} byte prefix of the new history"
                );
                assert_eq!(glob.get(1, 0, kept as u32).await.unwrap(), 1);
                if retained {
                    assert_eq!(glob.get(1, offset, size).await.unwrap(), 4);
                }
                glob.destroy().await.unwrap();
            });
        }
    }

    #[test_traced]
    fn test_glob_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate glob
            let glob: Glob<_, i32> = Glob::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to init glob");

            let value: i32 = 42;
            let (glob, offset, size) = glob.append(1, &value).await.expect("Failed to append");
            let glob = glob.sync(1).await.expect("Failed to sync");
            drop(glob);

            // Reopen and verify
            let glob: Glob<_, i32> = Glob::init(context.child("second"), cfg)
                .await
                .expect("Failed to reinit glob");

            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_get_invalid_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            let (glob, offset, _size) = glob.append(1, &42).await.expect("Failed to append");
            let glob = glob.sync(1).await.expect("Failed to sync");

            // Size 0 - should fail
            assert!(glob.get(1, offset, 0).await.is_err());

            // Size < CRC_SIZE (1, 2, 3 bytes) - should fail with BlobInsufficientLength
            for size in 1..4u32 {
                let result = glob.get(1, offset, size).await;
                assert!(matches!(
                    result,
                    Err(Error::Runtime(RError::BlobInsufficientLength))
                ));
            }

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_get_wrong_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            let (glob, offset, correct_size) = glob.append(1, &42).await.expect("Failed to append");
            let glob = glob.sync(1).await.expect("Failed to sync");

            // Size too small (but >= CRC_SIZE) - checksum mismatch
            let result = glob.get(1, offset, correct_size - 1).await;
            assert!(matches!(result, Err(Error::ChecksumMismatch(_, _))));

            glob.destroy().await.expect("Failed to destroy");
        });
    }
}
