//! Implementations of the `Storage` trait that can be used by the runtime.

#[commonware_macros::stability(BETA)]
use crate::BlobHeaderLayout;
use commonware_macros::stability_scope;

stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    /// Flush the whole filesystem containing `dir` at startup so that bytes a prior process wrote
    /// but did not `fsync` are crash-durable before any storage structure reads.
    ///
    /// Per-platform guarantee:
    /// - **Linux**: `syncfs(2)` makes all data on the storage filesystem crash-durable.
    /// - **macOS/BSD**: best-effort `sync(2)`; it does not flush the drive cache, so it is **not**
    ///   crash-durable.
    /// - **Windows**: best-effort whole-volume `FlushFileBuffers`; it needs admin and is skipped
    ///   otherwise, so it is **not** crash-durable.
    ///
    /// Assumes storage lives on a single filesystem; on Linux reliable error detection needs kernel
    /// >= 5.8. A missing `dir` is treated as success.
    pub(crate) fn sync(dir: &std::path::Path) -> std::io::Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                use std::os::fd::AsRawFd;
                let file = match std::fs::File::open(dir) {
                    Ok(file) => file,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(e) => return Err(e),
                };
                // SAFETY: `file` owns a valid fd that lives across the call; `syncfs` takes only
                // that fd, performs no memory access, and returns -1 on error.
                if unsafe { libc::syncfs(file.as_raw_fd()) } == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                tracing::debug!(
                    storage_directory = %dir.display(),
                    "made storage filesystem durable at startup (syncfs)"
                );
                Ok(())
            } else if #[cfg(unix)] {
                // SAFETY: `sync` takes no arguments and cannot fail.
                unsafe { libc::sync() };
                tracing::debug!(
                    storage_directory = %dir.display(),
                    "best-effort storage flush at startup (sync(); not a crash-durability guarantee)"
                );
                Ok(())
            } else if #[cfg(windows)] {
                // Resolve the volume containing `dir` (e.g. `C:\...` -> `\\.\C:`). `sync_all` on a
                // volume handle is `FlushFileBuffers`, which flushes every open file on the volume.
                // Best-effort (see fn docs): opening the volume needs admin, so a failure (or a
                // non-disk storage path) is logged, not fatal.
                use std::path::{Component, Prefix};
                let volume = dir.components().next().and_then(|component| match component {
                    Component::Prefix(prefix) => match prefix.kind() {
                        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                            Some(format!(r"\\.\{}:", drive as char))
                        }
                        _ => None,
                    },
                    _ => None,
                });
                let flushed = volume.as_deref().map(|volume| {
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(volume)
                        .and_then(|handle| handle.sync_all())
                });
                match flushed {
                    Some(Ok(())) => tracing::debug!(
                        storage_directory = %dir.display(),
                        "made storage volume durable at startup (FlushFileBuffers)"
                    ),
                    Some(Err(e)) => tracing::debug!(
                        storage_directory = %dir.display(),
                        error = %e,
                        "best-effort volume flush skipped at startup; not crash-durable"
                    ),
                    None => tracing::debug!(
                        storage_directory = %dir.display(),
                        "unable to guarantee storage durability at startup"
                    ),
                }
                Ok(())
            } else {
                tracing::debug!(
                    storage_directory = %dir.display(),
                    "no whole-filesystem durable flush on this platform; recovered-data durability not guaranteed"
                );
                Ok(())
            }
        }
    }
});

stability_scope!(ALPHA {
    pub mod audited;
    pub mod faulty;
    pub mod memory;
});
stability_scope!(ALPHA, cfg(feature = "iouring-storage") {
    pub mod iouring;
});
stability_scope!(BETA, cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage"))) {
    pub mod tokio;
});
stability_scope!(BETA {
    use crate::{Buf, BufMut, BlobInfo};
    use commonware_codec::{DecodeExt, Encode, FixedSize, Read as CodecRead, Write as CodecWrite};
    use commonware_cryptography::Crc32;
    use commonware_formatting::hex;
    use std::ops::RangeInclusive;
    use tracing::warn;

    pub mod metered;

    /// Errors that can occur when validating a blob header.
    #[derive(Debug)]
    pub(crate) enum HeaderError {
        InvalidMagic {
            found: [u8; 4],
        },
        UnsupportedRuntimeVersion {
            expected: u16,
            found: u16,
        },
        VersionMismatch {
            expected: RangeInclusive<u16>,
            found: u16,
        },
        InvalidHeaderChecksum,
        InvalidDataOffset {
            found: u64,
        },
        TruncatedHeader {
            data_offset: u64,
            raw_len: u64,
        },
    }

    impl HeaderError {
        /// Returns true if this parse failure could be the signature of a creation interrupted
        /// before the header became durable, making the blob a candidate for
        /// [Header::interrupted_creation] classification.
        ///
        /// [HeaderError::VersionMismatch] and [HeaderError::InvalidDataOffset] are excluded:
        /// for V1 both fire only after the CRC has validated, so the header was completely
        /// written and the failure is a genuine version or format disagreement. (A V0
        /// version mismatch is checked without a CRC, but V0 recovery is out of scope.)
        pub(crate) const fn may_be_torn_creation(&self) -> bool {
            matches!(
                self,
                Self::InvalidMagic { .. }
                    | Self::UnsupportedRuntimeVersion { .. }
                    | Self::InvalidHeaderChecksum
                    | Self::TruncatedHeader { .. }
            )
        }

        /// Converts this error into an [`Error`](enum@crate::Error) with partition and name context.
        pub(crate) fn into_error(self, partition: &str, name: &[u8]) -> crate::Error {
            match self {
                Self::InvalidMagic { found } => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    format!("invalid magic: found {found:?}"),
                ),
                Self::UnsupportedRuntimeVersion { expected, found } => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    format!("unsupported runtime version: expected {expected}, found {found}"),
                ),
                Self::VersionMismatch { expected, found } => {
                    crate::Error::BlobVersionMismatch { expected, found }
                }
                Self::InvalidHeaderChecksum => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    "invalid header checksum".into(),
                ),
                Self::InvalidDataOffset { found } => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    format!(
                        "invalid header data offset: expected a power of two in {:?}, found {found}",
                        Header::SUPPORTED_DATA_OFFSETS
                    ),
                ),
                Self::TruncatedHeader {
                    data_offset,
                    raw_len,
                } => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    format!("truncated header: data offset {data_offset}, raw length {raw_len}"),
                ),
            }
        }
    }

    /// Fixed-size header prelude at the start of each [crate::Blob].
    ///
    /// On-disk layout (big-endian). The prelude is 8 bytes; a V1 header extends it:
    ///
    /// | bytes    | field                        | owner       | question it answers                              |
    /// |----------|------------------------------|-------------|--------------------------------------------------|
    /// | 0-3      | magic (per layout)           | runtime     | is this file one of our blobs, and which layout? |
    /// | 4-5      | runtime version (u16)        | runtime     | can this build read this container layout?       |
    /// | 6-7      | blob version (u16)           | application | can this application interpret the contents?     |
    /// | 8-11     | data offset (u32, V1 only)   | runtime     | where do the contents begin?                     |
    /// | 12-15    | CRC32 of bytes 0-11 (V1 only)| runtime     | is this header intact?                           |
    /// | 16..     | zero padding (V1 only)       | runtime     | (spacing up to the data offset; reserved)        |
    ///
    /// The magic selects the header region layout ([BlobHeaderLayout]): a V0 header region is
    /// the 8-byte prelude alone with data at offset 8, while a V1 header region extends to its
    /// recorded data offset, so data begins on an aligned boundary.
    ///
    /// The blob version is opaque to the runtime: creation stamps the newest version the caller
    /// requested, reopening rejects versions outside the caller's range, and the stored value is
    /// surfaced in [crate::BlobInfo].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Header {
        magic: [u8; Self::MAGIC_LENGTH],
        runtime_version: u16,
        pub(crate) blob_version: u16,
    }

    impl Header {
        /// Size of the header prelude in bytes.
        pub(crate) const PRELUDE_SIZE: usize = 8;

        /// Size of the header prelude as u64 for offset calculations.
        pub(crate) const PRELUDE_SIZE_U64: u64 = Self::PRELUDE_SIZE as u64;

        /// Size of the V1 header extension in bytes (data offset + CRC32).
        pub(crate) const EXTENSION_SIZE: usize = 8;

        /// Number of leading bytes needed to parse any header: the prelude plus the V1
        /// extension.
        pub(crate) const PARSE_LEN: usize = Self::PRELUDE_SIZE + Self::EXTENSION_SIZE;

        /// Data offset written when creating a blob with [BlobHeaderLayout::V1]: the header
        /// region occupies exactly one 4096-byte page.
        ///
        /// This is the writer's current choice, not a format bound: it can change to any
        /// power of two in [Self::SUPPORTED_DATA_OFFSETS] (e.g. for devices with larger
        /// storage pages) without a new layout version or a migration.
        pub(crate) const V1_DATA_OFFSET: u64 = 4096;

        /// Power-of-two data offsets accepted when parsing a V1 header. These are format
        /// bounds: shipped blobs carry offsets down to the minimum (one storage page), so it
        /// can never be raised, and readers reject offsets above the maximum (which also
        /// bounds the read issued for the padded header region), so writers can never exceed
        /// it without a new layout version.
        const SUPPORTED_DATA_OFFSETS: RangeInclusive<u64> = 4096..=(1 << 20);

        /// Length of magic bytes.
        pub(crate) const MAGIC_LENGTH: usize = 4;

        /// Returns true if a blob is missing a valid header (new or corrupted).
        pub(crate) const fn missing(raw_len: u64) -> bool {
            raw_len < Self::PRELUDE_SIZE_U64
        }

        /// Returns true if a blob's raw contents are consistent with the creation of a
        /// [BlobHeaderLayout::V1] blob that was interrupted before its header became durable.
        ///
        /// A torn creation can only leave a subset of the canonical header-region bytes a
        /// writer produces (writes tear at any point, and unsynced pages flush in any order),
        /// with every unflushed byte zero. The file must therefore be a zero-subset of ONE
        /// canonical image: the magic and runtime version are fixed; the data offset, if any
        /// of its bytes persisted, must be a supported power of two whose region covers the
        /// file; everything past the 16-byte header must be zero; and any persisted CRC bytes
        /// must agree with a single candidate image (some blob version and offset consistent
        /// with every other persisted byte). Bytes from two different valid headers cannot
        /// both survive.
        ///
        /// Only meaningful for contents whose header failed to parse. Accepting a file implies
        /// it holds no synced data: a synced V1 blob has a durable, parseable header and its
        /// data lies past the data offset, while this requires the header region to be
        /// incomplete and nothing but the header region to be present.
        pub(crate) fn interrupted_creation(raw: &[u8]) -> bool {
            // Longer than the largest header region a writer can produce: the tail is data,
            // so this cannot be a torn creation.
            if raw.len() as u64 > *Self::SUPPORTED_DATA_OFFSETS.end() {
                return false;
            }

            // Magic and runtime version (bytes 0-5).
            let mut canonical = [0u8; 6];
            canonical[..4].copy_from_slice(&BlobHeaderLayout::V1.magic());
            canonical[4..6]
                .copy_from_slice(&BlobHeaderLayout::V1.runtime_version().to_be_bytes());
            for (byte, expected) in raw.iter().zip(canonical) {
                if *byte != 0 && *byte != expected {
                    return false;
                }
            }

            // Zero padding (bytes 16 to the data offset).
            if raw.len() > 16 && raw[16..].iter().any(|&byte| byte != 0) {
                return false;
            }

            // Data offset (bytes 8-11): a power of two has a single nonzero byte, so a
            // nonzero persisted value must equal a supported offset exactly, and the file
            // cannot extend past the region that offset defines. Unpersisted bytes leave
            // every supported offset covering the file as a candidate.
            let mut offset_bytes = [0u8; 4];
            if raw.len() > 8 {
                let persisted_len = raw.len().min(12) - 8;
                offset_bytes[..persisted_len].copy_from_slice(&raw[8..8 + persisted_len]);
            }
            let offset = u32::from_be_bytes(offset_bytes) as u64;
            let offsets: Vec<u32> = if offset != 0 {
                if !offset.is_power_of_two()
                    || !Self::SUPPORTED_DATA_OFFSETS.contains(&offset)
                    || raw.len() as u64 > offset
                {
                    return false;
                }
                vec![offset as u32]
            } else {
                let mut candidate = *Self::SUPPORTED_DATA_OFFSETS.start();
                let mut offsets = Vec::new();
                while candidate <= *Self::SUPPORTED_DATA_OFFSETS.end() {
                    if candidate >= raw.len() as u64 {
                        offsets.push(candidate as u32);
                    }
                    candidate <<= 1;
                }
                offsets
            };

            // CRC (bytes 12-15): persisted bytes must agree with the CRC of a single
            // candidate image, over some blob version consistent with the persisted version
            // bytes (6-7). All-zero CRC bytes are consistent with any image; otherwise the
            // (rare, unparseable-header-only) search below is bounded by 2^16 versions per
            // candidate offset.
            let mut crc_bytes = [0u8; 4];
            if raw.len() > 12 {
                let persisted_len = raw.len().min(16) - 12;
                crc_bytes[..persisted_len].copy_from_slice(&raw[12..12 + persisted_len]);
            }
            if crc_bytes.iter().all(|&byte| byte == 0) {
                return true;
            }
            let version_byte = |index: usize| raw.get(index).copied().filter(|&byte| byte != 0);
            let (hi, lo) = (version_byte(6), version_byte(7));
            let mut image = [0u8; 12];
            image[..4].copy_from_slice(&BlobHeaderLayout::V1.magic());
            image[4..6].copy_from_slice(&BlobHeaderLayout::V1.runtime_version().to_be_bytes());
            for offset in offsets {
                image[8..12].copy_from_slice(&offset.to_be_bytes());
                for version in 0..=u16::MAX {
                    let bytes = version.to_be_bytes();
                    if hi.is_some_and(|byte| byte != bytes[0])
                        || lo.is_some_and(|byte| byte != bytes[1])
                    {
                        continue;
                    }
                    image[6..8].copy_from_slice(&bytes);
                    let crc = Crc32::checksum(&image).to_be_bytes();
                    if crc_bytes
                        .iter()
                        .zip(crc)
                        .all(|(&byte, expected)| byte == 0 || byte == expected)
                    {
                        return true;
                    }
                }
            }
            false
        }

        /// Creates the header region for a new blob using the latest version from the range and
        /// the given layout. Returns (encoded header region, info for the new blob); the data
        /// offset is the region's length.
        ///
        /// Callers writing this region over an existing blob must truncate it to zero first, so
        /// a torn write cannot splice old bytes into a fully valid header with a wrong version:
        /// every partial state then remains classifiable as an interrupted creation.
        pub(crate) fn create(
            versions: &RangeInclusive<u16>,
            layout: BlobHeaderLayout,
        ) -> (Vec<u8>, BlobInfo) {
            let blob_version = *versions.end();
            let header = Self {
                magic: layout.magic(),
                runtime_version: layout.runtime_version(),
                blob_version,
            };
            let info = BlobInfo {
                size: 0,
                blob_version,
                layout,
            };
            match layout {
                BlobHeaderLayout::V0 => (header.encode().into(), info),
                BlobHeaderLayout::V1 => {
                    let data_offset = Self::V1_DATA_OFFSET;
                    let mut region = Vec::with_capacity(data_offset as usize);
                    region.extend_from_slice(&header.encode());
                    region.extend_from_slice(&(data_offset as u32).to_be_bytes());
                    let crc = Crc32::checksum(&region);
                    region.extend_from_slice(&crc.to_be_bytes());
                    region.resize(data_offset as usize, 0);
                    (region, info)
                }
            }
        }

        /// Parses and validates a blob's header from its first [Self::PARSE_LEN] bytes (or all
        /// of them, for blobs shorter than that), returning the blob's metadata and data offset.
        ///
        /// `head` must hold the blob's first `min(raw_len, PARSE_LEN)` bytes with
        /// `raw_len >= PRELUDE_SIZE`, where `raw_len` is the blob's raw on-disk length.
        pub(crate) fn parse(
            head: &[u8],
            raw_len: u64,
            versions: &RangeInclusive<u16>,
        ) -> Result<(BlobInfo, u64), HeaderError> {
            let header: Self = Self::decode(&head[..Self::PRELUDE_SIZE])
                .expect("header decode should never fail for correct size input");
            let layout = header.validate()?;
            let data_offset = match layout {
                BlobHeaderLayout::V0 => {
                    if !versions.contains(&header.blob_version) {
                        return Err(HeaderError::VersionMismatch {
                            expected: versions.clone(),
                            found: header.blob_version,
                        });
                    }
                    Self::PRELUDE_SIZE_U64
                }
                BlobHeaderLayout::V1 => {
                    if head.len() < Self::PARSE_LEN {
                        return Err(HeaderError::TruncatedHeader {
                            data_offset: Self::PARSE_LEN as u64,
                            raw_len,
                        });
                    }
                    let prelude = head[..Self::PRELUDE_SIZE].try_into().unwrap();
                    let extension = head[Self::PRELUDE_SIZE..Self::PARSE_LEN].try_into().unwrap();
                    Self::parse_extension(prelude, extension, raw_len, versions)?
                }
            };
            let info = BlobInfo {
                size: raw_len - data_offset,
                blob_version: header.blob_version,
                layout,
            };
            Ok((info, data_offset))
        }

        /// Parses and validates a V1 header extension, returning the data offset. The offset
        /// must be a power of two in [Self::SUPPORTED_DATA_OFFSETS], so V1 data always begins
        /// storage-page aligned.
        ///
        /// `raw_len` is the blob's raw on-disk length, which must cover the full header region.
        /// The blob version is checked last, once the CRC and region are intact, so every
        /// earlier error still describes a header that may merely be incompletely written.
        fn parse_extension(
            prelude: [u8; Self::PRELUDE_SIZE],
            extension: [u8; Self::EXTENSION_SIZE],
            raw_len: u64,
            versions: &RangeInclusive<u16>,
        ) -> Result<u64, HeaderError> {
            let mut checked = [0u8; Self::PRELUDE_SIZE + 4];
            checked[..Self::PRELUDE_SIZE].copy_from_slice(&prelude);
            checked[Self::PRELUDE_SIZE..].copy_from_slice(&extension[..4]);
            let crc = u32::from_be_bytes(extension[4..].try_into().unwrap());
            if Crc32::checksum(&checked) != crc {
                return Err(HeaderError::InvalidHeaderChecksum);
            }
            let data_offset = u32::from_be_bytes(extension[..4].try_into().unwrap()) as u64;
            if !data_offset.is_power_of_two()
                || !Self::SUPPORTED_DATA_OFFSETS.contains(&data_offset)
            {
                return Err(HeaderError::InvalidDataOffset { found: data_offset });
            }
            if raw_len < data_offset {
                return Err(HeaderError::TruncatedHeader {
                    data_offset,
                    raw_len,
                });
            }
            let blob_version = u16::from_be_bytes(prelude[6..8].try_into().unwrap());
            if !versions.contains(&blob_version) {
                return Err(HeaderError::VersionMismatch {
                    expected: versions.clone(),
                    found: blob_version,
                });
            }
            Ok(data_offset)
        }

        /// Validates the magic bytes and runtime version, returning the layout the magic
        /// identifies.
        ///
        /// The magic alone selects the layout; the runtime version must agree with it. Requiring
        /// agreement (rather than deriving the layout from the runtime version) means a header
        /// with any bytes zeroed by a torn write fails validation instead of parsing as a
        /// different layout.
        pub(crate) const fn validate(&self) -> Result<BlobHeaderLayout, HeaderError> {
            let Some(layout) = BlobHeaderLayout::from_magic(&self.magic) else {
                return Err(HeaderError::InvalidMagic { found: self.magic });
            };
            let runtime_version = layout.runtime_version();
            if self.runtime_version != runtime_version {
                return Err(HeaderError::UnsupportedRuntimeVersion {
                    expected: runtime_version,
                    found: self.runtime_version,
                });
            }
            Ok(layout)
        }
    }

    impl FixedSize for Header {
        const SIZE: usize = Self::PRELUDE_SIZE;
    }

    impl CodecWrite for Header {
        fn write(&self, buf: &mut impl BufMut) {
            buf.put_slice(&self.magic);
            buf.put_u16(self.runtime_version);
            buf.put_u16(self.blob_version);
        }
    }

    impl CodecRead for Header {
        type Cfg = ();
        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            if buf.remaining() < Self::PRELUDE_SIZE {
                return Err(commonware_codec::Error::EndOfBuffer);
            }
            let mut magic = [0u8; Self::MAGIC_LENGTH];
            buf.copy_to_slice(&mut magic);
            let runtime_version = buf.get_u16();
            let blob_version = buf.get_u16();
            Ok(Self {
                magic,
                runtime_version,
                blob_version,
            })
        }
    }

    /// Resolves a header that failed to parse: `Ok(None)` if the blob's raw contents are those
    /// of a creation that was interrupted before its header became durable (the caller
    /// recreates the blob), and the loud corruption error otherwise.
    pub(crate) fn resolve_unparseable(
        err: HeaderError,
        raw: &[u8],
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(BlobInfo, u64)>, crate::Error> {
        if err.may_be_torn_creation() && Header::interrupted_creation(raw) {
            warn!(
                partition,
                name = %hex(name),
                "recreating blob left torn by an interrupted creation"
            );
            Ok(None)
        } else {
            Err(err.into_error(partition, name))
        }
    }

    /// Validate that a partition name contains only allowed characters.
    ///
    /// Partition names must only contain alphanumeric characters, dashes ('-'),
    /// or underscores ('_').
    pub fn validate_partition_name(partition: &str) -> Result<(), crate::Error> {
        if partition.is_empty()
            || partition
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || ['_', '-'].contains(&c)))
        {
            return Err(crate::Error::PartitionNameInvalid(partition.into()));
        }
        Ok(())
    }
});

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Header {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let version: u16 = u.arbitrary()?;
        Ok(Self {
            magic: BlobHeaderLayout::V0.magic(),
            runtime_version: BlobHeaderLayout::V0.runtime_version(),
            blob_version: version,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Header, HeaderError};
    use crate::{Blob, BlobHeaderLayout, Buf, IoBuf, IoBufMut, IoBufs, IoBufsMut, Storage};
    use commonware_codec::{DecodeExt, Encode};
    use futures::FutureExt;

    /// A V0 header with the given blob version, for direct field manipulation in tests.
    fn v0_header(blob_version: u16) -> Header {
        Header {
            magic: BlobHeaderLayout::V0.magic(),
            runtime_version: BlobHeaderLayout::V0.runtime_version(),
            blob_version,
        }
    }

    /// Raw bytes of a V1 blob recording the given data offset, followed by `payload`, as a
    /// future writer choosing a larger creation offset would lay them out.
    pub(crate) fn v1_blob_bytes(data_offset: u64, blob_version: u16, payload: &[u8]) -> Vec<u8> {
        let header = Header {
            magic: BlobHeaderLayout::V1.magic(),
            runtime_version: BlobHeaderLayout::V1.runtime_version(),
            blob_version,
        };
        let mut raw = Vec::with_capacity(data_offset as usize + payload.len());
        raw.extend_from_slice(&header.encode());
        raw.extend_from_slice(&(data_offset as u32).to_be_bytes());
        let crc = commonware_cryptography::Crc32::checksum(&raw);
        raw.extend_from_slice(&crc.to_be_bytes());
        raw.resize(data_offset as usize, 0);
        raw.extend_from_slice(payload);
        raw
    }

    #[test]
    fn test_header_create_v0() {
        let (region, info) = Header::create(&(42..=42), BlobHeaderLayout::V0);
        assert_eq!(info.blob_version, 42);
        assert_eq!(info.size, 0);
        assert_eq!(region.len(), Header::PRELUDE_SIZE);
        let decoded: Header = Header::decode(region.as_slice()).unwrap();
        assert_eq!(decoded.magic, BlobHeaderLayout::V0.magic());
        assert_eq!(
            decoded.runtime_version,
            BlobHeaderLayout::V0.runtime_version()
        );
        assert_eq!(decoded.blob_version, 42);
    }

    #[test]
    fn test_header_create_v1() {
        let (region, info) = Header::create(&(0..=7), BlobHeaderLayout::V1);
        assert_eq!(info.blob_version, 7);
        assert_eq!(info.size, 0);
        assert_eq!(region.len(), Header::V1_DATA_OFFSET as usize);

        // The padding past the extension is zero.
        assert!(region[Header::PRELUDE_SIZE + Header::EXTENSION_SIZE..]
            .iter()
            .all(|&b| b == 0));

        // The region round-trips through parsing.
        let (parsed, data_offset) = Header::parse(
            &region[..Header::PARSE_LEN],
            Header::V1_DATA_OFFSET,
            &(0..=7),
        )
        .unwrap();
        assert_eq!(parsed.blob_version, 7);
        assert_eq!(parsed.layout, BlobHeaderLayout::V1);
        assert_eq!(data_offset, Header::V1_DATA_OFFSET);
    }

    /// Freeze the exact on-disk bytes of a V1 header so accidental format changes are caught
    /// (the padding is asserted zero in [test_header_create_v1]).
    #[test]
    fn test_header_v1_fixture_bytes() {
        let (region, _) = Header::create(&(3..=3), BlobHeaderLayout::V1);
        let expected = [
            b'C', b'W', b'I', b'1', // V1 magic
            0x00, 0x01, // runtime version 1
            0x00, 0x03, // blob version 3
            0x00, 0x00, 0x10, 0x00, // data offset 4096
        ];
        assert_eq!(&region[..12], &expected);
        // CRC32 over the first 12 bytes.
        let crc = u32::from_be_bytes(region[12..16].try_into().unwrap());
        assert_eq!(crc, commonware_cryptography::Crc32::checksum(&expected));
    }

    #[test]
    fn test_header_extension_accepts_in_range_offsets() {
        // The creation offset is a writer choice, not a format bound: any power of two in
        // SUPPORTED_DATA_OFFSETS parses, so a future writer can raise the creation offset and
        // this build still reads its blobs.
        for offset in [
            *Header::SUPPORTED_DATA_OFFSETS.start(),
            8192,
            65536,
            *Header::SUPPORTED_DATA_OFFSETS.end(),
        ] {
            let raw = v1_blob_bytes(offset, 0, b"");
            let (_, resolved) =
                Header::parse(&raw[..Header::PARSE_LEN], raw.len() as u64, &(0..=0)).unwrap();
            assert_eq!(resolved, offset, "offset {offset} should be accepted");
        }
    }

    #[test]
    fn test_header_extension_rejects_bad_crc() {
        let (mut region, _) = Header::create(&(0..=0), BlobHeaderLayout::V1);
        region[Header::PARSE_LEN - 1] ^= 0x01;
        let result = Header::parse(
            &region[..Header::PARSE_LEN],
            Header::V1_DATA_OFFSET,
            &(0..=0),
        );
        assert!(matches!(result, Err(HeaderError::InvalidHeaderChecksum)));
    }

    #[test]
    fn test_header_extension_rejects_bad_offset() {
        // A non-power-of-two (or out-of-bounds) data offset is rejected even with a valid CRC.
        for bad_offset in [0u32, 8, 2048, 4097, 1 << 21] {
            let (mut region, _) = Header::create(&(0..=0), BlobHeaderLayout::V1);
            region[Header::PRELUDE_SIZE..Header::PRELUDE_SIZE + 4]
                .copy_from_slice(&bad_offset.to_be_bytes());
            let crc = commonware_cryptography::Crc32::checksum(&region[..Header::PRELUDE_SIZE + 4]);
            region[Header::PRELUDE_SIZE + 4..Header::PARSE_LEN].copy_from_slice(&crc.to_be_bytes());
            let result = Header::parse(&region[..Header::PARSE_LEN], u64::MAX, &(0..=0));
            assert!(
                matches!(result, Err(HeaderError::InvalidDataOffset { found }) if found == bad_offset as u64),
                "offset {bad_offset} should be rejected"
            );
        }
    }

    #[test]
    fn test_header_extension_rejects_truncated_region() {
        let (region, _) = Header::create(&(0..=0), BlobHeaderLayout::V1);
        let result = Header::parse(
            &region[..Header::PARSE_LEN],
            Header::V1_DATA_OFFSET - 1,
            &(0..=0),
        );
        assert!(matches!(
            result,
            Err(HeaderError::TruncatedHeader { data_offset, raw_len })
            if data_offset == Header::V1_DATA_OFFSET && raw_len == Header::V1_DATA_OFFSET - 1
        ));
    }

    #[test]
    fn test_header_validate_success() {
        let header = v0_header(5);
        assert!(header.validate().is_ok());
        assert!(Header::parse(&header.encode(), Header::PRELUDE_SIZE_U64, &(3..=7)).is_ok());
        assert!(Header::parse(&header.encode(), Header::PRELUDE_SIZE_U64, &(5..=5)).is_ok());
    }

    #[test]
    fn test_header_validate_magic_mismatch() {
        let mut header = v0_header(5);
        header.magic = *b"XXXX";
        let result = header.validate();
        assert!(matches!(
            result,
            Err(HeaderError::InvalidMagic { found })
            if found == *b"XXXX"
        ));
    }

    #[test]
    fn test_header_validate_runtime_version_mismatch() {
        let mut header = v0_header(5);
        header.runtime_version = 99;
        let result = header.validate();
        assert!(matches!(
            result,
            Err(HeaderError::UnsupportedRuntimeVersion { expected, found })
            if expected == 0 && found == 99
        ));
    }

    /// Every parse failure converts to a contextual error naming its cause.
    #[test]
    fn test_header_error_messages() {
        let cases = [
            (
                HeaderError::InvalidMagic { found: *b"XXXX" },
                "invalid magic",
            ),
            (
                HeaderError::UnsupportedRuntimeVersion {
                    expected: 1,
                    found: 0,
                },
                "unsupported runtime version",
            ),
            (
                HeaderError::InvalidHeaderChecksum,
                "invalid header checksum",
            ),
            (
                HeaderError::InvalidDataOffset { found: 4097 },
                "invalid header data offset",
            ),
            (
                HeaderError::TruncatedHeader {
                    data_offset: Header::V1_DATA_OFFSET,
                    raw_len: 100,
                },
                "truncated header",
            ),
        ];
        for (err, needle) in cases {
            match err.into_error("partition", b"name") {
                crate::Error::BlobCorrupt(partition, _, reason) => {
                    assert_eq!(partition, "partition");
                    assert!(reason.contains(needle), "{reason}");
                }
                other => panic!("unexpected error: {other}"),
            }
        }

        // A version mismatch surfaces as its own error variant.
        let err = HeaderError::VersionMismatch {
            expected: 3..=7,
            found: 10,
        };
        assert!(matches!(
            err.into_error("partition", b"name"),
            crate::Error::BlobVersionMismatch { expected, found }
            if expected == (3..=7) && found == 10
        ));
    }

    /// Classification only triggers for parse failures a torn write can produce; failures
    /// that require a validated CRC describe completely written headers and stay loud.
    #[test]
    fn test_header_error_torn_creation_candidates() {
        assert!(HeaderError::InvalidMagic { found: [0; 4] }.may_be_torn_creation());
        assert!(HeaderError::UnsupportedRuntimeVersion {
            expected: 1,
            found: 0
        }
        .may_be_torn_creation());
        assert!(HeaderError::InvalidHeaderChecksum.may_be_torn_creation());
        assert!(HeaderError::TruncatedHeader {
            data_offset: Header::V1_DATA_OFFSET,
            raw_len: 100
        }
        .may_be_torn_creation());
        assert!(!HeaderError::VersionMismatch {
            expected: 0..=0,
            found: 1
        }
        .may_be_torn_creation());
        assert!(!HeaderError::InvalidDataOffset { found: 4097 }.may_be_torn_creation());
    }

    /// A magic with any byte zeroed by a torn write must be invalid, never another layout's
    /// magic: this is what lets an unparseable header safely identify a torn creation.
    #[test]
    fn test_header_magic_zero_subset_is_invalid() {
        for layout in [BlobHeaderLayout::V0, BlobHeaderLayout::V1] {
            for i in 0..Header::MAGIC_LENGTH {
                let mut magic = layout.magic();
                magic[i] = 0;
                assert!(BlobHeaderLayout::from_magic(&magic).is_none());
            }
        }
    }

    /// A torn V1 header write that persists the magic but zeroes the runtime version must fail
    /// validation rather than parse as V0 (which shares runtime version 0).
    #[test]
    fn test_header_torn_v1_does_not_parse_as_v0() {
        let header = Header {
            magic: BlobHeaderLayout::V1.magic(),
            runtime_version: 0,
            blob_version: 5,
        };
        let result = header.validate();
        assert!(matches!(
            result,
            Err(HeaderError::UnsupportedRuntimeVersion { expected, found })
            if expected == 1 && found == 0
        ));
    }

    #[test]
    fn test_header_v0_blob_version_out_of_range() {
        let header = v0_header(10);
        let result = Header::parse(&header.encode(), Header::PRELUDE_SIZE_U64, &(3..=7));
        assert!(matches!(
            result,
            Err(HeaderError::VersionMismatch { expected, found })
            if expected == (3..=7) && found == 10
        ));
    }

    /// A V1 blob version outside the accepted range is only reported once the CRC has
    /// validated: a torn version byte breaks the CRC first, so [HeaderError::VersionMismatch]
    /// always describes a completely written header.
    #[test]
    fn test_header_v1_blob_version_checked_after_crc() {
        let raw = v1_blob_bytes(Header::V1_DATA_OFFSET, 10, b"");

        // Intact header, version out of range: mismatch.
        let result = Header::parse(&raw[..Header::PARSE_LEN], raw.len() as u64, &(3..=7));
        assert!(matches!(
            result,
            Err(HeaderError::VersionMismatch { expected, found })
            if expected == (3..=7) && found == 10
        ));

        // Torn version byte: the CRC fails before any version verdict.
        let mut torn: Vec<u8> = raw[..Header::PARSE_LEN].to_vec();
        torn[7] = 0;
        let result = Header::parse(&torn, raw.len() as u64, &(3..=7));
        assert!(matches!(result, Err(HeaderError::InvalidHeaderChecksum)));
    }

    #[test]
    fn test_header_interrupted_creation_accepts_torn_states() {
        let region = v1_blob_bytes(Header::V1_DATA_OFFSET, 5, b"");
        let cases: &[(&str, Vec<u8>)] = &[
            ("only sizes flushed", vec![0u8; region.len()]),
            ("sub-prelude fragment", vec![0u8; 3]),
            ("prefix of the header", region[..10].to_vec()),
            ("full region", region.clone()),
            ("magic lost, extension flushed", {
                let mut raw = region.clone();
                raw[..4].fill(0);
                raw
            }),
            ("runtime version byte lost", {
                let mut raw = region.clone();
                raw[5] = 0;
                raw
            }),
            ("offset and CRC lost", {
                let mut raw = region.clone();
                raw[8..16].fill(0);
                raw
            }),
            ("short region, header intact", region[..100].to_vec()),
            (
                "larger creation offset",
                v1_blob_bytes(8192, 5, b"")[..6000].to_vec(),
            ),
            (
                "documented residual: V0 blob with all-zero payload and rotted magic",
                {
                    // Out-of-model corruption (rot, not tearing) of a degenerate payload: the
                    // bytes are a zero-subset of a canonical V1 image, indistinguishable from a
                    // torn creation, so this heals. Real payload bytes are non-canonical and
                    // keep genuine V0 blobs loud (see the reject table).
                    let mut raw = v0_header(5).encode().to_vec();
                    raw[3] = 0;
                    raw.extend_from_slice(&[0u8; 100]);
                    raw
                },
            ),
        ];
        for (label, raw) in cases {
            assert!(
                Header::interrupted_creation(raw),
                "{label} should classify as an interrupted creation"
            );
        }
    }

    #[test]
    fn test_header_interrupted_creation_rejects_foreign_bytes() {
        let region = v1_blob_bytes(Header::V1_DATA_OFFSET, 5, b"");
        let cases: &[(&str, Vec<u8>)] = &[
            ("non-canonical magic byte", {
                let mut raw = region.clone();
                raw[0] = b'X';
                raw
            }),
            ("non-canonical runtime version", {
                let mut raw = region.clone();
                raw[4] = 0x02;
                raw
            }),
            ("nonzero padding", {
                let mut raw = region.clone();
                raw[100] = 0xFF;
                raw
            }),
            ("data past the recorded offset", {
                let mut raw = region.clone();
                raw.push(1);
                raw
            }),
            ("non-power-of-two offset bytes", {
                let mut raw = region;
                raw[8..12].copy_from_slice(&4097u32.to_be_bytes());
                raw
            }),
            ("corrupt V0 blob with payload", {
                // The magic stays a zero-subset (byte 3 lost), so rejection must come from
                // the payload bytes themselves: real data is never canonical header bytes.
                let mut raw = v0_header(5).encode().to_vec();
                raw[3] = 0;
                raw.extend_from_slice(b"payload");
                raw
            }),
            (
                "longer than any header region",
                vec![0u8; (*Header::SUPPORTED_DATA_OFFSETS.end() + 1) as usize],
            ),
            ("mixed images: version from one, CRC from another", {
                // No single torn write can produce bytes from two different valid headers.
                let mut raw = v1_blob_bytes(Header::V1_DATA_OFFSET, 5, b"");
                let other = v1_blob_bytes(Header::V1_DATA_OFFSET, 6, b"");
                raw[12..16].copy_from_slice(&other[12..16]);
                raw
            }),
            ("corrupted CRC byte on an intact header", {
                let mut raw = v1_blob_bytes(Header::V1_DATA_OFFSET, 5, b"");
                raw[13] = raw[13].wrapping_add(1).max(1);
                raw
            }),
        ];
        for (label, raw) in cases {
            assert!(
                !Header::interrupted_creation(raw),
                "{label} must stay a loud corruption error"
            );
        }
    }

    #[test]
    fn test_header_bytes_round_trip() {
        let header = v0_header(123);
        let bytes = header.encode();
        let decoded: Header = Header::decode(bytes.as_ref()).unwrap();
        assert_eq!(header, decoded);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::Header;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Header>
        }
    }

    /// Runs the full suite of tests on the provided storage implementation.
    pub(crate) async fn run_storage_tests<S>(storage: S)
    where
        S: Storage + Send + Sync + 'static,
        S::Blob: Send + Sync,
    {
        test_open_and_write(&storage).await;
        test_remove(&storage).await;
        test_read_after_remove_blob(&storage).await;
        test_read_after_remove_partition(&storage).await;
        test_recreate_after_remove(&storage).await;
        test_read_after_remove_unsynced(&storage).await;
        test_read_after_remove_handle_clones(&storage).await;
        test_recreate_generations(&storage).await;
        test_read_after_remove_partition_multi(&storage).await;
        test_scan(&storage).await;
        test_concurrent_access(&storage).await;
        test_large_data(&storage).await;
        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_write_at_sync(&storage).await;
        test_start_sync(&storage).await;
        test_append_data(&storage).await;
        test_vectored_write_at(&storage).await;
        test_vectored_write_at_large_offset(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
        test_resize_then_open(&storage).await;
        test_partition_name_validation(&storage).await;
        test_blob_version_mismatch(&storage).await;
        test_aligned_layout(&storage).await;
        test_read_zero_length(&storage).await;
        test_read_at_buf_returns_same_buffer(&storage).await;
        test_read_at_buf_insufficient_capacity(&storage).await;
        test_read_at_buf_larger_capacity(&storage).await;
    }

    /// Test opening a blob, writing to it, and reading back the data.
    async fn test_open_and_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(0, b"hello world").await.unwrap();
        let read = blob.read_at(0, 11).await.unwrap();

        assert_eq!(
            read.coalesce(),
            b"hello world",
            "Blob content does not match expected value"
        );
    }

    /// Test removing a blob from storage.
    async fn test_remove<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"test_blob").await.unwrap();
        storage
            .remove("partition", Some(b"test_blob"))
            .await
            .unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert!(blobs.is_empty(), "Blob was not removed as expected");
    }

    /// An already-open handle remains fully readable after the blob is removed by name.
    async fn test_read_after_remove_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("read_after_remove", b"by_name").await.unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        blob.write_at(0, data.clone()).await.unwrap();
        blob.sync().await.unwrap();

        storage
            .remove("read_after_remove", Some(b"by_name"))
            .await
            .unwrap();

        // The name is gone but the open handle keeps reading the removed blob's bytes.
        let blobs = storage.scan("read_after_remove").await.unwrap();
        assert!(blobs.is_empty(), "Blob was not removed as expected");
        let read = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "open handle must remain readable after blob removal"
        );
    }

    /// An already-open handle remains fully readable after its entire partition is removed.
    async fn test_read_after_remove_partition<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("read_after_remove_partition", b"victim")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).rev().collect();
        blob.write_at(0, data.clone()).await.unwrap();
        blob.sync().await.unwrap();

        storage
            .remove("read_after_remove_partition", None)
            .await
            .unwrap();

        let read = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "open handle must remain readable after partition removal"
        );
    }

    /// Re-opening a removed blob's name creates an independent blob; the pre-removal handle keeps
    /// observing the removed blob's contents.
    async fn test_recreate_after_remove<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (old, _) = storage
            .open("recreate_after_remove", b"name")
            .await
            .unwrap();
        old.write_at(0, b"old contents").await.unwrap();
        old.sync().await.unwrap();

        storage
            .remove("recreate_after_remove", Some(b"name"))
            .await
            .unwrap();

        // Re-creating the name yields a fresh, empty, independent blob.
        let (new, len) = storage
            .open("recreate_after_remove", b"name")
            .await
            .unwrap();
        assert_eq!(len, 0, "recreated blob must start empty");
        new.write_at(0, b"new contents").await.unwrap();
        new.sync().await.unwrap();

        let old_read = old.read_at(0, 12).await.unwrap();
        assert_eq!(
            old_read.coalesce().as_ref(),
            b"old contents",
            "pre-removal handle must keep observing the removed blob"
        );
        let new_read = new.read_at(0, 12).await.unwrap();
        assert_eq!(new_read.coalesce().as_ref(), b"new contents");
    }

    /// Bytes written but never synced remain readable through an open handle after removal.
    async fn test_read_after_remove_unsynced<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("read_after_remove_unsynced", b"name")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        blob.write_at(0, data.clone()).await.unwrap();

        // Read through the handle before removal so the removal crosses an actively-used handle.
        let read = blob.read_at(0, 16).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), &data[..16]);

        storage
            .remove("read_after_remove_unsynced", Some(b"name"))
            .await
            .unwrap();

        // Unsynced bytes are still served in full.
        let read = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "unsynced bytes must remain readable after removal"
        );
        let read = blob.read_at(data.len() as u64 - 1, 1).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), &data[data.len() - 1..]);
    }

    /// Removal liveness is per-blob, not per-handle: clones taken before or after removal keep
    /// reading regardless of other handles' lifetimes, and out-of-bounds reads still fail.
    async fn test_read_after_remove_handle_clones<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (first, _) = storage
            .open("read_after_remove_clones", b"name")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        first.write_at(0, data.clone()).await.unwrap();
        first.sync().await.unwrap();
        let second = first.clone();
        // Opened independently: a distinct handle to the same blob, not a clone.
        let (independent, _) = storage
            .open("read_after_remove_clones", b"name")
            .await
            .unwrap();

        storage
            .remove("read_after_remove_clones", Some(b"name"))
            .await
            .unwrap();

        // A clone taken after removal reads too, and outlives the handle it was cloned from.
        let third = first.clone();
        drop(first);

        for handle in [&second, &third, &independent] {
            let read = handle.read_at(0, data.len()).await.unwrap();
            assert_eq!(read.coalesce().as_ref(), data.as_slice());
            assert!(
                handle.read_at(data.len() as u64, 1).await.is_err(),
                "out-of-bounds read must still fail after removal"
            );
        }
    }

    /// Every removed generation of a name stays readable through its own handle while the name
    /// is recreated and removed repeatedly.
    async fn test_recreate_generations<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let partition = "recreate_generations";

        // Hold a handle on each of three generations of the same name, each removed while open.
        let mut handles = Vec::new();
        for generation in 0u8..3 {
            let (blob, len) = storage.open(partition, b"name").await.unwrap();
            assert_eq!(len, 0, "each recreation must start empty");
            let data = vec![generation; 32];
            blob.write_at(0, data.clone()).await.unwrap();
            blob.sync().await.unwrap();
            storage.remove(partition, Some(b"name")).await.unwrap();
            handles.push((blob, data));
        }

        // Churn the name further with the removed generations still held.
        for _ in 0..5 {
            let (blob, _) = storage.open(partition, b"name").await.unwrap();
            blob.write_at(0, vec![0xFF; 8]).await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            storage.remove(partition, Some(b"name")).await.unwrap();
        }

        for (blob, data) in &handles {
            let read = blob.read_at(0, data.len()).await.unwrap();
            assert_eq!(
                read.coalesce().as_ref(),
                data.as_slice(),
                "each handle must keep observing its own generation"
            );
        }
    }

    /// Every handle into a removed partition stays readable, including a large blob at interior
    /// offsets, and recreating the partition yields independent blobs.
    async fn test_read_after_remove_partition_multi<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let partition = "read_after_remove_partition_multi";
        let (small_a, _) = storage.open(partition, b"a").await.unwrap();
        small_a.write_at(0, b"alpha").await.unwrap();
        small_a.sync().await.unwrap();
        // Deliberately never synced: partition removal must not lose unsynced bytes either.
        let (small_b, _) = storage.open(partition, b"b").await.unwrap();
        small_b.write_at(0, b"bravo").await.unwrap();

        const LARGE_LEN: usize = 1 << 20;
        let (large, _) = storage.open(partition, b"large").await.unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(LARGE_LEN).collect();
        large.write_at(0, data.clone()).await.unwrap();
        large.sync().await.unwrap();

        storage.remove(partition, None).await.unwrap();

        let read = small_a.read_at(0, 5).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), b"alpha");
        let read = small_b.read_at(0, 5).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), b"bravo");

        // Start, unaligned interior, and final-byte reads of the large blob.
        for (offset, len) in [(0usize, 4096), (123_457, 8192), (LARGE_LEN - 1, 1)] {
            let read = large.read_at(offset as u64, len).await.unwrap();
            assert_eq!(
                read.coalesce().as_ref(),
                &data[offset..offset + len],
                "offset={offset} len={len}"
            );
        }

        // Recreating the partition and a same-named blob yields an independent blob.
        let (fresh, len) = storage.open(partition, b"a").await.unwrap();
        assert_eq!(len, 0, "recreated blob must start empty");
        fresh.write_at(0, b"fresh").await.unwrap();
        fresh.sync().await.unwrap();
        let read = small_a.read_at(0, 5).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            b"alpha",
            "pre-removal handle must keep observing the removed partition's blob"
        );
    }

    /// Test scanning a partition for blobs.
    async fn test_scan<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"blob1").await.unwrap();
        storage.open("partition", b"blob2").await.unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert_eq!(
            blobs.len(),
            2,
            "Scan did not return the expected number of blobs"
        );
        assert!(
            blobs.contains(&b"blob1".to_vec()),
            "Blob1 is missing from scan results"
        );
        assert!(
            blobs.contains(&b"blob2".to_vec()),
            "Blob2 is missing from scan results"
        );
    }

    /// Test concurrent access to the same blob.
    async fn test_concurrent_access<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Initialize blob with data of sufficient length first
        blob.write_at(0, b"concurrent write").await.unwrap();

        // Read and write concurrently
        let write_task = tokio::spawn({
            let blob = blob.clone();
            async move {
                blob.write_at(0, IoBuf::from(b"concurrent write"))
                    .await
                    .unwrap();
            }
        });

        let read_task = tokio::spawn({
            let blob = blob.clone();
            async move { blob.read_at(0, 16).await.unwrap() }
        });

        write_task.await.unwrap();
        let buffer = read_task.await.unwrap();

        assert_eq!(
            buffer.coalesce(),
            b"concurrent write",
            "Concurrent access failed"
        );
    }

    /// Test handling of large data sizes.
    async fn test_large_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"large_blob").await.unwrap();

        let large_data = vec![42u8; 10 * 1024 * 1024]; // 10 MB
        blob.write_at(0, large_data.clone()).await.unwrap();

        let read = blob.read_at(0, 10 * 1024 * 1024).await.unwrap().coalesce();

        assert_eq!(read, large_data.as_slice(), "Large data read/write failed");
    }

    /// Test overwriting data in a blob.
    async fn test_overwrite_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_overwrite_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(0, b"initial data").await.unwrap();

        // Overwrite part of the data
        blob.write_at(8, b"overwrite").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 17).await.unwrap().coalesce();

        assert_eq!(
            read, b"initial overwrite",
            "Data was not overwritten correctly"
        );
    }

    /// Test reading from an offset beyond the written data.
    async fn test_read_beyond_bound<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_beyond_written_data", b"test_blob")
            .await
            .unwrap();

        // Write some data
        blob.write_at(0, b"hello").await.unwrap();

        // Attempt to read beyond the written data
        let result = blob.read_at(6, 10).await;
        assert!(
            result.is_err(),
            "Reading beyond written data should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(10);
        let result = blob.read_at_buf(6, 10, buf).await;
        assert!(
            result.is_err(),
            "read_at_buf beyond written data should return an error"
        );
    }

    /// Test writing data at a large offset.
    async fn test_write_at_large_offset<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        // Write data at a large offset
        blob.write_at(10_000, b"offset data").await.unwrap();

        // Read back the data
        let read = blob.read_at(10_000, 11).await.unwrap().coalesce();
        assert_eq!(read, b"offset data", "Data at large offset is incorrect");
    }

    /// Test writing and syncing data in one operation.
    async fn test_write_at_sync<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();

        // Empty writes should be accepted without extending the blob.
        blob.write_at_sync(1024, Vec::<u8>::new()).await.unwrap();
        drop(blob);

        let (blob, len) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 0);

        // Non-empty writes must be visible after reopen without a separate sync call.
        blob.write_at_sync(0, b"hello").await.unwrap();
        blob.write_at_sync(5, vec![IoBuf::from(b" "), IoBuf::from(b"world")])
            .await
            .unwrap();
        drop(blob);

        // Reopening a blob in the same process may still observe dirty kernel
        // page-cache state, so this doesn't really prove write durability.
        let (blob, len) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 11);
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    /// Test that `start_sync` durably persists data, matching `sync`.
    async fn test_start_sync<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("test_start_sync", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(0, b"hello world").await.unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);

        // The bytes must survive a reopen, just as they would after `sync`.
        let (blob, len) = storage.open("test_start_sync", b"test_blob").await.unwrap();
        assert_eq!(len, 11);
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    /// Test appending data to a blob.
    async fn test_append_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_append_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(0, b"first").await.unwrap();

        // Append data
        blob.write_at(5, b"second").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read, b"firstsecond", "Appended data is incorrect");
    }

    /// Test vectored writes at offset 0.
    async fn test_vectored_write_at<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let test = |partition, bufs: Vec<IoBuf>, context| async move {
            // Coalesce the input to test later when reading
            let expected = IoBufs::from(bufs.clone()).coalesce();
            let (blob, _) = storage.open(partition, b"test_blob").await.unwrap();

            // Write data
            blob.write_at(0, bufs).await.unwrap();

            // Read back the data
            let read = blob.read_at(0, expected.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), expected.as_ref(), "{context}");
        };

        test(
            "test_vectored_write_basic",
            vec![
                IoBuf::from(b"hello"),
                IoBuf::from(b" "),
                IoBuf::from(b"world"),
            ],
            "Vectored write content is incorrect",
        )
        .await;

        test(
            "test_vectored_write_empty_chunks",
            vec![
                IoBuf::default(),
                IoBuf::from(b"abc"),
                IoBuf::default(),
                IoBuf::from(b"def"),
                IoBuf::default(),
            ],
            "Vectored write with empties is incorrect",
        )
        .await;

        let chunk_count = 128;
        let mut bufs = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            bufs.push(IoBuf::from(vec![i as u8; i]));
        }

        test(
            "test_vectored_write_many_chunks",
            bufs,
            "Vectored write over batch size is incorrect",
        )
        .await;
    }

    /// Test vectored writes at large offset with many chunks.
    async fn test_vectored_write_at_large_offset<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_vectored_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        let chunk_count = 128;
        let mut bufs = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            bufs.push(IoBuf::from(vec![i as u8; i]));
        }
        let expected = IoBufs::from(bufs.clone()).coalesce();

        // Write vectored data at a large offset
        blob.write_at(5_000, bufs).await.unwrap();

        // Read back the data
        let read = blob
            .read_at(5_000, expected.len())
            .await
            .unwrap()
            .coalesce();

        assert_eq!(
            read.as_ref(),
            expected.as_ref(),
            "Vectored write at offset content is incorrect"
        );

        // Prefix gap should be zero-filled.
        let prefix = blob.read_at(0, 5_000).await.unwrap().coalesce();
        assert_eq!(prefix.as_ref(), [0u8; 5_000]);
    }

    /// Test reading and writing with interleaved offsets.
    async fn test_sequential_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Write data at different offsets
        blob.write_at(0, b"first").await.unwrap();
        blob.write_at(10, b"second").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read, b"first", "Data at offset 0 is incorrect");

        let read = blob.read_at(10, 6).await.unwrap().coalesce();
        assert_eq!(read, b"second", "Data at offset 10 is incorrect");
    }

    /// Test writing and reading large data in chunks.
    async fn test_sequential_chunk_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_large_data_in_chunks", b"large_blob")
            .await
            .unwrap();

        let chunk_size = 1024 * 1024; // 1 MB
        let num_chunks = 10;
        let data = vec![7u8; chunk_size];

        // Write data in chunks
        for i in 0..num_chunks {
            blob.write_at((i * chunk_size) as u64, data.clone())
                .await
                .unwrap();
        }

        // Read back the data in chunks
        for i in 0..num_chunks {
            let read = blob
                .read_at((i * chunk_size) as u64, chunk_size)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read, data.as_slice(), "Chunk {i} is incorrect");
        }
    }

    /// Test reading from an empty blob.
    async fn test_read_empty_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_empty_blob", b"empty_blob")
            .await
            .unwrap();

        let result = blob.read_at(0, 1).await;
        assert!(
            result.is_err(),
            "Reading from an empty blob should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(1);
        let result = blob.read_at_buf(0, 1, buf).await;
        assert!(
            result.is_err(),
            "read_at_buf from an empty blob should return an error"
        );
    }

    /// Test writing and reading with overlapping writes.
    async fn test_overlapping_writes<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_overlapping_writes", b"test_blob")
            .await
            .unwrap();

        // Write overlapping data
        blob.write_at(0, b"overlap").await.unwrap();
        blob.write_at(4, b"map").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 7).await.unwrap().coalesce();
        assert_eq!(read, b"overmap", "Overlapping writes are incorrect");
    }

    async fn test_resize_then_open<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        {
            let (blob, _) = storage
                .open("test_resize_then_open", b"test_blob")
                .await
                .unwrap();

            // Write some data
            blob.write_at(0, b"hello world").await.unwrap();

            // Resize the blob
            blob.resize(5).await.unwrap();

            // Sync the blob
            blob.sync().await.unwrap();
        }

        // Reopen the blob
        let (blob, len) = storage
            .open("test_resize_then_open", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 5, "Blob length after resize is incorrect");

        // Read back the data
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read, b"hello", "Resized data is incorrect");
    }

    /// Test that partition names are validated correctly.
    async fn test_partition_name_validation<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Valid partition names should not return PartitionNameInvalid
        for valid in [
            "partition",
            "my_partition",
            "my-partition",
            "partition123",
            "A1",
        ] {
            assert!(
                !matches!(
                    storage.open(valid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by open"
            );
            assert!(
                !matches!(
                    storage.remove(valid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by remove"
            );
            assert!(
                !matches!(
                    storage.scan(valid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by scan"
            );
        }

        // Invalid partition names should return PartitionNameInvalid
        for invalid in [
            "my/partition",
            "my.partition",
            "my partition",
            "../escape",
            "",
        ] {
            assert!(
                matches!(
                    storage.open(invalid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by open"
            );
            assert!(
                matches!(
                    storage.remove(invalid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by remove"
            );
            assert!(
                matches!(
                    storage.scan(invalid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by scan"
            );
        }
    }

    /// Test that opening a blob with an incompatible version range returns an error.
    async fn test_blob_version_mismatch<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create a blob with version 1
        let (blob, info) = storage
            .open_versioned(
                "test_version_mismatch",
                b"blob",
                1..=1,
                BlobHeaderLayout::V0,
            )
            .await
            .unwrap();
        assert_eq!(info.blob_version, 1);
        blob.sync().await.unwrap();
        drop(blob);

        // Reopen with a range that includes version 1
        let (_, info) = storage
            .open_versioned(
                "test_version_mismatch",
                b"blob",
                0..=2,
                BlobHeaderLayout::V0,
            )
            .await
            .unwrap();
        assert_eq!(info.blob_version, 1);

        // Try to open with version range that excludes version 1
        let result = storage
            .open_versioned(
                "test_version_mismatch",
                b"blob",
                2..=3,
                BlobHeaderLayout::V0,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(crate::Error::BlobVersionMismatch { expected, found })
                if expected == (2..=3) && found == 1
            ),
            "Expected BlobVersionMismatch error"
        );
    }

    /// Test aligned-layout blob creation, reopen, and cross-layout behavior.
    async fn test_aligned_layout<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create an aligned blob and write/read through logical offsets.
        let (blob, info) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0, BlobHeaderLayout::V1)
            .await
            .unwrap();
        assert_eq!(info.size, 0);
        assert!(matches!(info.layout, BlobHeaderLayout::V1));
        blob.write_at(0, b"hello world".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
        drop(blob);

        // Reopen: the recorded layout wins, even when the caller requests V0.
        let (blob, info) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0, BlobHeaderLayout::V0)
            .await
            .unwrap();
        assert_eq!(info.size, 11);
        assert!(matches!(info.layout, BlobHeaderLayout::V1));
        let read = blob.read_at(6, 5).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"world");

        // Resize preserves logical semantics.
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let (blob, info) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0, BlobHeaderLayout::V1)
            .await
            .unwrap();
        assert_eq!(info.size, 5);
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello");
        drop(blob);

        // A V0 blob reopened with a V1 request stays V0.
        let (blob, info) = storage
            .open_versioned(
                "test_aligned_layout",
                b"legacy",
                0..=0,
                BlobHeaderLayout::V0,
            )
            .await
            .unwrap();
        assert!(matches!(info.layout, BlobHeaderLayout::V0));
        blob.write_at(0, b"data".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let (blob, info) = storage
            .open_versioned(
                "test_aligned_layout",
                b"legacy",
                0..=0,
                BlobHeaderLayout::V1,
            )
            .await
            .unwrap();
        assert!(matches!(info.layout, BlobHeaderLayout::V0));
        assert_eq!(info.size, 4);
        let read = blob.read_at(0, 4).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"data");
    }

    /// Test that read_at with zero length returns an empty buffer.
    async fn test_read_zero_length<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_zero_len", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello").await.unwrap();

        // read_at with len=0 should succeed and return empty
        let output = blob.read_at(0, 0).await.unwrap();
        assert_eq!(output.len(), 0);

        // read_at_buf with len=0 should also succeed
        let buf = IoBufMut::with_capacity(16);
        let output = blob.read_at_buf(0, 0, buf).await.unwrap();
        assert_eq!(output.len(), 0);
    }

    /// Test that read_at_buf returns the same buffer that was passed in (contract verification).
    async fn test_read_at_buf_returns_same_buffer<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_contract", b"blob")
            .await
            .unwrap();

        // Write test data
        blob.write_at(0, b"hello world").await.unwrap();

        // Test with single buffer - verify same buffer is returned
        let input_buf = IoBufMut::zeroed(11);
        let input_ptr = input_buf.as_ref().as_ptr();
        let output = blob.read_at_buf(0, 11, input_buf).await.unwrap();
        assert!(
            output.is_single(),
            "Single input should return single output"
        );
        let output_ptr = output.chunk().as_ptr();
        assert_eq!(
            input_ptr, output_ptr,
            "read_at must return the same buffer that was passed in"
        );
        assert_eq!(output.chunk(), b"hello world");

        // Test with multi-chunk buffers - verify same buffers are returned with correct data
        let buf1 = IoBufMut::zeroed(5);
        let buf2 = IoBufMut::zeroed(6);
        let ptr1 = buf1.as_ref().as_ptr();
        let ptr2 = buf2.as_ref().as_ptr();
        let input_bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!input_bufs.is_single(), "Should be multi-chunk");

        let mut output = blob.read_at_buf(0, 11, input_bufs).await.unwrap();
        assert!(
            !output.is_single(),
            "Multi-chunk input should return multi-chunk output"
        );

        // Verify the buffers are the same and contain correct data.
        assert_eq!(
            output.chunk().as_ptr(),
            ptr1,
            "First chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b"hello");
        output.advance(5);
        assert_eq!(
            output.chunk().as_ptr(),
            ptr2,
            "Second chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b" world");
        output.advance(6);
        assert_eq!(output.remaining(), 0);

        // when requested len only fills the first chunk, read_at_buf
        // should still preserve caller-provided multi-chunk layout.
        let buf1 = IoBufMut::zeroed(2);
        let buf2 = IoBufMut::zeroed(2);
        let ptr1 = buf1.as_ref().as_ptr();
        let input_bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!input_bufs.is_single(), "Should be multi-chunk");

        let output = blob.read_at_buf(0, 2, input_bufs).await.unwrap();
        assert!(
            !output.is_single(),
            "Multi-chunk input should remain multi-chunk when len only uses first chunk"
        );
        assert_eq!(
            output.chunk().as_ptr(),
            ptr1,
            "First chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b"he");
    }

    /// Test that read_at_buf panics when buffer capacity < len.
    async fn test_read_at_buf_insufficient_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_capacity", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world").await.unwrap();

        // Single buffer with capacity 5, request 11 bytes
        let buf = IoBufMut::with_capacity(5);
        let result = std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, buf))
            .catch_unwind()
            .await;
        assert!(
            result.is_err(),
            "Expected panic for insufficient single buffer capacity"
        );

        // Chunked buffers with total capacity 8, request 11 bytes
        let bufs = IoBufsMut::from(vec![IoBufMut::with_capacity(4), IoBufMut::with_capacity(4)]);
        let result = std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, bufs))
            .catch_unwind()
            .await;
        assert!(
            result.is_err(),
            "Expected panic for insufficient multi-chunk buffer capacity"
        );
    }

    /// Test that read_at_buf works when buffer capacity exceeds len.
    async fn test_read_at_buf_larger_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_large_cap", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world").await.unwrap();

        // Buffer with capacity 64, request only 11 bytes
        let buf = IoBufMut::with_capacity(64);
        assert_eq!(buf.len(), 0, "with_capacity should start at len 0");
        let output = blob.read_at_buf(0, 11, buf).await.unwrap();
        assert_eq!(output.len(), 11);
        assert_eq!(output.coalesce(), b"hello world");

        // Buffer with capacity 64, request only 5 bytes (partial read)
        let buf = IoBufMut::with_capacity(64);
        let output = blob.read_at_buf(0, 5, buf).await.unwrap();
        assert_eq!(output.len(), 5);
        assert_eq!(output.coalesce(), b"hello");
    }
}
