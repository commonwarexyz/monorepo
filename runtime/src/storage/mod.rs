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
    use crate::{Buf, BufMut};
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
        InvalidHeaderPadding,
        TruncatedHeader {
            required_len: u64,
            raw_len: u64,
        },
    }

    impl HeaderError {
        /// Returns true if this parse failure could be the signature of a creation interrupted
        /// before the header became durable, making the blob a candidate for
        /// [Header::interrupted_creation] classification.
        ///
        /// [HeaderError::VersionMismatch] is excluded: for V1 it fires only once the CRC has
        /// validated and the full header region is present, so the header was completely
        /// written and the failure is a genuine version disagreement. (A V0 version mismatch
        /// is checked without a CRC, but V0 recovery is out of scope.)
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
                Self::InvalidHeaderPadding => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    "invalid header padding".into(),
                ),
                Self::TruncatedHeader {
                    required_len,
                    raw_len,
                } => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    format!("truncated header: required length {required_len}, raw length {raw_len}"),
                ),
            }
        }
    }

    /// Fixed-size header prelude at the start of each [crate::Blob].
    ///
    /// On-disk layout (big-endian). The prelude is 8 bytes and a V1 header extends it:
    ///
    /// | bytes    | field                        | owner       | question it answers                              |
    /// |----------|------------------------------|-------------|--------------------------------------------------|
    /// | 0-3      | magic (per layout)           | runtime     | is this file one of our blobs, and which layout? |
    /// | 4-5      | runtime version (u16)        | runtime     | can this build read this container layout?       |
    /// | 6-7      | blob version (u16)           | application | can this application interpret the contents?     |
    /// | 8-11     | CRC32 of bytes 0-7 (V1 only) | runtime     | is this header intact?                           |
    /// | 12..     | zero padding (V1 only)       | runtime     | (spacing up to the data offset; reserved)        |
    ///
    /// The magic selects the header region layout ([BlobHeaderLayout]), and the layout fully
    /// determines the geometry: a V0 header region is the 8-byte prelude alone with data at
    /// offset 8, while a V1 header region extends to [Self::V1_DATA_OFFSET], so data begins on
    /// an aligned boundary.
    ///
    /// The blob version is opaque to the runtime: creation stamps the newest version the caller
    /// requested, reopening rejects versions outside the caller's range, and the stored value is
    /// returned by [crate::Storage::open_versioned].
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

        /// Size of the V1 header extension in bytes (CRC32 over the prelude).
        pub(crate) const EXTENSION_SIZE: usize = 4;

        /// Number of leading bytes needed to parse any header: the prelude plus the V1
        /// extension.
        pub(crate) const PARSE_LEN: usize = Self::PRELUDE_SIZE + Self::EXTENSION_SIZE;

        /// The data offset of every [BlobHeaderLayout::V1] blob: the header region occupies
        /// exactly one 4096-byte page. Not stored on disk (the layout's magic implies it).
        ///
        /// Frozen for the lifetime of the V1 layout: torn-creation recovery relies on every
        /// V1 creation producing this exact region, so a different offset requires a new
        /// layout (with its own magic), not a change to this constant.
        pub(crate) const V1_DATA_OFFSET: u64 = 4096;

        /// The V1 data offset as a `usize`, for indexing buffers that hold the header region.
        pub(crate) const V1_DATA_OFFSET_USIZE: usize = Self::V1_DATA_OFFSET as usize;

        /// Length of magic bytes.
        pub(crate) const MAGIC_LENGTH: usize = 4;

        /// Returns true if a blob is missing a valid header (new or corrupted).
        pub(crate) const fn missing(raw_len: u64) -> bool {
            raw_len < Self::PRELUDE_SIZE_U64
        }

        /// Returns true if a blob's raw contents are consistent with the creation of a
        /// [BlobHeaderLayout::V1] blob that was interrupted before its header became durable.
        ///
        /// Creation writes the region with set_len(0) -> write -> sync, and this classifier
        /// models the states it recovers as a prefix of the canonical region, possibly
        /// followed by zeros (a persisted length without persisted bytes reads as zeros). A
        /// file is accepted iff it fits within the region and equals a canonical prefix
        /// followed by zeros: the magic and runtime version are fixed; the blob version
        /// bytes continue the prefix with whatever value the writer chose; the CRC bytes
        /// must be a prefix of the CRC over the preceding prelude, which can only have begun
        /// persisting once the full prelude did; and everything past the prefix must be
        /// zero.
        ///
        /// The prefix shape is a model, not a filesystem guarantee: device writeback before
        /// the sync completes may persist bytes out of order. A file that is not a canonical
        /// prefix (a lost byte followed by persisted ones, or a CRC that does not match its
        /// own prelude) stays loudly corrupt rather than healing, trading recovery
        /// coverage for avoiding broader acceptance that might erase nonzero data.
        pub(crate) fn interrupted_creation(raw: &[u8]) -> bool {
            // The file cannot extend past the region creation writes, and everything past
            // the parseable header must be zero padding.
            if raw.len() > Self::V1_DATA_OFFSET_USIZE {
                return false;
            }
            let head = &raw[..raw.len().min(Self::PARSE_LEN)];
            if raw[head.len()..].iter().any(|&byte| byte != 0) {
                return false;
            }

            // The written prefix ends after the last nonzero byte (trailing zeros are
            // indistinguishable from unwritten bytes).
            let written = head.iter().rposition(|&byte| byte != 0).map_or(0, |i| i + 1);

            let mut canonical = [0u8; Self::PARSE_LEN];
            canonical[..4].copy_from_slice(&BlobHeaderLayout::V1.magic());
            canonical[4..6]
                .copy_from_slice(&BlobHeaderLayout::V1.runtime_version().to_be_bytes());
            if written <= Self::PRELUDE_SIZE {
                // Torn at or before the CRC: the fixed bytes of the prefix must match; the
                // blob version bytes (6-7) are the writer's choice.
                head[..written.min(6)] == canonical[..written.min(6)]
            } else {
                // CRC bytes persisted, so the full prelude did too: it must be canonical
                // (with the writer's version), and the CRC bytes must be a prefix of the
                // CRC over it.
                if head[..6] != canonical[..6] {
                    return false;
                }
                canonical[6..8].copy_from_slice(&head[6..8]);
                let crc = Crc32::checksum(&canonical[..Self::PRELUDE_SIZE]);
                canonical[8..12].copy_from_slice(&crc.to_be_bytes());
                head[8..written] == canonical[8..written]
            }
        }

        /// Creates the header region for a new blob using the latest version from the range and
        /// the latest header layout. Returns (encoded header region, blob version); the data
        /// offset is the region's length.
        ///
        /// Callers writing this region over an existing blob must truncate it to zero first, so
        /// a torn write cannot splice old bytes into a fully valid header with a wrong version:
        /// every partial state in the canonical-prefix model then remains classifiable as an
        /// interrupted creation.
        pub(crate) fn create(versions: &RangeInclusive<u16>) -> (Vec<u8>, u16) {
            let layout = BlobHeaderLayout::V1;
            let blob_version = *versions.end();
            let header = Self {
                magic: layout.magic(),
                runtime_version: layout.runtime_version(),
                blob_version,
            };
            let mut region = Vec::with_capacity(Self::V1_DATA_OFFSET_USIZE);
            region.extend_from_slice(&header.encode());
            let crc = Crc32::checksum(&region);
            region.extend_from_slice(&crc.to_be_bytes());
            region.resize(Self::V1_DATA_OFFSET_USIZE, 0);
            (region, blob_version)
        }

        /// Parses and validates a blob's header from its leading bytes, returning the blob's
        /// logical size, blob version, and data offset.
        ///
        /// `raw` must hold the blob's first `min(raw_len, V1_DATA_OFFSET)` bytes with
        /// `raw_len >= PRELUDE_SIZE`, where `raw_len` is the blob's raw on-disk length.
        pub(crate) fn parse(
            raw: &[u8],
            raw_len: u64,
            versions: &RangeInclusive<u16>,
        ) -> Result<(u64, u16, u64), HeaderError> {
            debug_assert!(
                raw.len() >= raw_len.min(Self::V1_DATA_OFFSET) as usize,
                "caller must provide enough bytes to validate the header region"
            );

            let header: Self = Self::decode(&raw[..Self::PRELUDE_SIZE])
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
                    // The blob version is checked last, once the CRC and region are intact, so
                    // every earlier error still describes a header that may merely be
                    // incompletely written.
                    if raw.len() < Self::PARSE_LEN {
                        return Err(HeaderError::TruncatedHeader {
                            required_len: Self::PARSE_LEN as u64,
                            raw_len,
                        });
                    }
                    let crc = u32::from_be_bytes(
                        raw[Self::PRELUDE_SIZE..Self::PARSE_LEN].try_into().unwrap(),
                    );
                    if Crc32::checksum(&raw[..Self::PRELUDE_SIZE]) != crc {
                        return Err(HeaderError::InvalidHeaderChecksum);
                    }
                    if raw_len < Self::V1_DATA_OFFSET {
                        return Err(HeaderError::TruncatedHeader {
                            required_len: Self::V1_DATA_OFFSET,
                            raw_len,
                        });
                    }
                    if raw[Self::PARSE_LEN..Self::V1_DATA_OFFSET_USIZE]
                        .iter()
                        .any(|&byte| byte != 0)
                    {
                        return Err(HeaderError::InvalidHeaderPadding);
                    }
                    if !versions.contains(&header.blob_version) {
                        return Err(HeaderError::VersionMismatch {
                            expected: versions.clone(),
                            found: header.blob_version,
                        });
                    }
                    Self::V1_DATA_OFFSET
                }
            };
            Ok((raw_len - data_offset, header.blob_version, data_offset))
        }

        /// Validates the magic bytes and runtime version, returning the layout the magic
        /// identifies.
        ///
        /// The magic alone selects the layout, and the runtime version must agree with it. Requiring
        /// agreement (rather than deriving the layout from the runtime version) means a header
        /// with any layout-identifying bytes zeroed by a torn write fails validation instead
        /// of parsing as a different layout.
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

    /// Resolves a blob's header from its leading bytes.
    ///
    /// Returns `Some((logical_size, blob_version, data_offset))` for a valid header and
    /// `None` when the caller should (re)create the blob: the file is too short to hold a
    /// header, or its contents are those of a [BlobHeaderLayout::V1] creation interrupted
    /// before its header became durable. Anything else fails as corrupt or unacceptable.
    ///
    /// `raw` must hold the blob's first `min(raw_len, V1_DATA_OFFSET)` bytes, where
    /// `raw_len` is the blob's raw on-disk length.
    pub(crate) fn resolve_header(
        raw: &[u8],
        raw_len: u64,
        versions: &RangeInclusive<u16>,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(u64, u16, u64)>, crate::Error> {
        assert!(
            raw.len() as u64 >= raw_len.min(Header::V1_DATA_OFFSET),
            "caller must provide enough bytes to resolve the header region"
        );

        // Too short to hold any header: treat as new.
        if Header::missing(raw_len) {
            return Ok(None);
        }

        let err = match Header::parse(raw, raw_len, versions) {
            Ok(resolved) => return Ok(Some(resolved)),
            Err(err) => err,
        };

        // Heal a V1 creation interrupted before its header became durable: the failure
        // must be one a torn write can produce, and the contents must match the canonical
        // creation prefix. Files longer than the creation region hold data and never heal.
        if raw_len <= Header::V1_DATA_OFFSET
            && err.may_be_torn_creation()
            && Header::interrupted_creation(raw)
        {
            warn!(
                partition,
                name = %hex(name),
                "recreating blob left torn by an interrupted creation"
            );
            return Ok(None);
        }

        Err(err.into_error(partition, name))
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

    /// Raw bytes of a legacy V0 blob: an 8-byte header followed immediately by `payload`, as a
    /// pre-V1 writer laid them out.
    pub(crate) fn v0_blob_bytes(blob_version: u16, payload: &[u8]) -> Vec<u8> {
        let mut raw = v0_header(blob_version).encode().to_vec();
        raw.extend_from_slice(payload);
        raw
    }

    /// Raw bytes of a V1 blob with the given version, followed by `payload`.
    pub(crate) fn v1_blob_bytes(blob_version: u16, payload: &[u8]) -> Vec<u8> {
        let header = Header {
            magic: BlobHeaderLayout::V1.magic(),
            runtime_version: BlobHeaderLayout::V1.runtime_version(),
            blob_version,
        };
        let mut raw = Vec::with_capacity(Header::V1_DATA_OFFSET_USIZE + payload.len());
        raw.extend_from_slice(&header.encode());
        let crc = commonware_cryptography::Crc32::checksum(&raw);
        raw.extend_from_slice(&crc.to_be_bytes());
        raw.resize(Header::V1_DATA_OFFSET_USIZE, 0);
        raw.extend_from_slice(payload);
        raw
    }

    #[test]
    fn test_header_create_v1() {
        let (region, blob_version) = Header::create(&(0..=7));
        assert_eq!(blob_version, 7);
        assert_eq!(region.len(), Header::V1_DATA_OFFSET as usize);

        // The padding past the extension is zero.
        assert!(
            region[Header::PRELUDE_SIZE + Header::EXTENSION_SIZE..]
                .iter()
                .all(|&b| b == 0)
        );

        // The region round-trips through parsing.
        let (size, parsed_blob_version, data_offset) =
            Header::parse(&region, Header::V1_DATA_OFFSET, &(0..=7)).unwrap();
        assert_eq!(size, 0);
        assert_eq!(parsed_blob_version, 7);
        assert_eq!(data_offset, Header::V1_DATA_OFFSET);
    }

    /// Freeze the exact on-disk bytes of a V1 header so accidental format changes are caught
    /// (the padding is asserted zero in [test_header_create_v1]).
    #[test]
    fn test_header_v1_fixture_bytes() {
        let (region, _) = Header::create(&(3..=3));
        let expected = [
            b'C', b'W', b'I', b'1', // V1 magic
            0x00, 0x01, // runtime version 1
            0x00, 0x03, // blob version 3
        ];
        assert_eq!(&region[..8], &expected);
        // CRC32 over the 8-byte prelude.
        let crc = u32::from_be_bytes(region[8..12].try_into().unwrap());
        assert_eq!(crc, commonware_cryptography::Crc32::checksum(&expected));
    }

    #[test]
    fn test_header_extension_rejects_bad_crc() {
        let (mut region, _) = Header::create(&(0..=0));
        region[Header::PARSE_LEN - 1] ^= 0x01;
        let result = Header::parse(&region, Header::V1_DATA_OFFSET, &(0..=0));
        assert!(matches!(result, Err(HeaderError::InvalidHeaderChecksum)));
    }

    #[test]
    fn test_header_extension_rejects_truncated_region() {
        let (region, _) = Header::create(&(0..=0));
        let result = Header::parse(
            &region[..Header::V1_DATA_OFFSET_USIZE - 1],
            Header::V1_DATA_OFFSET - 1,
            &(0..=0),
        );
        assert!(matches!(
            result,
            Err(HeaderError::TruncatedHeader { required_len, raw_len })
            if required_len == Header::V1_DATA_OFFSET && raw_len == Header::V1_DATA_OFFSET - 1
        ));
    }

    #[test]
    fn test_header_v1_rejects_nonzero_padding() {
        let (mut region, _) = Header::create(&(0..=0));
        region[Header::PARSE_LEN] = 0x01;
        let result = Header::parse(&region, Header::V1_DATA_OFFSET, &(0..=0));
        assert!(matches!(result, Err(HeaderError::InvalidHeaderPadding)));
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
            (HeaderError::InvalidHeaderPadding, "invalid header padding"),
            (
                HeaderError::TruncatedHeader {
                    required_len: Header::V1_DATA_OFFSET,
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

    /// Classification only triggers for parse failures a torn write can produce. A version
    /// mismatch requires a validated CRC over a complete header region and stays loud.
    #[test]
    fn test_header_error_torn_creation_candidates() {
        assert!(HeaderError::InvalidMagic { found: [0; 4] }.may_be_torn_creation());
        assert!(
            HeaderError::UnsupportedRuntimeVersion {
                expected: 1,
                found: 0
            }
            .may_be_torn_creation()
        );
        assert!(HeaderError::InvalidHeaderChecksum.may_be_torn_creation());
        assert!(
            HeaderError::TruncatedHeader {
                required_len: Header::V1_DATA_OFFSET,
                raw_len: 100
            }
            .may_be_torn_creation()
        );
        assert!(!HeaderError::InvalidHeaderPadding.may_be_torn_creation());
        assert!(
            !HeaderError::VersionMismatch {
                expected: 0..=0,
                found: 1
            }
            .may_be_torn_creation()
        );
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
    /// validated and the region is complete: a torn version byte breaks the CRC first, so
    /// [HeaderError::VersionMismatch] always describes a completely written header.
    #[test]
    fn test_header_v1_blob_version_checked_after_crc() {
        let raw = v1_blob_bytes(10, b"");

        // Intact header, version out of range: mismatch.
        let result = Header::parse(&raw, raw.len() as u64, &(3..=7));
        assert!(matches!(
            result,
            Err(HeaderError::VersionMismatch { expected, found })
            if expected == (3..=7) && found == 10
        ));

        // Torn version byte: the CRC fails before any version verdict.
        let mut torn = raw;
        torn[7] = 0;
        let result = Header::parse(&torn, torn.len() as u64, &(3..=7));
        assert!(matches!(result, Err(HeaderError::InvalidHeaderChecksum)));
    }

    #[test]
    fn test_header_interrupted_creation_accepts_torn_states() {
        let region = v1_blob_bytes(5, b"");
        let cases: &[(&str, Vec<u8>)] = &[
            ("only sizes flushed", vec![0u8; region.len()]),
            ("sub-prelude fragment", vec![0u8; 3]),
            ("prefix of the magic", region[..2].to_vec()),
            ("prefix ending in the version bytes", region[..8].to_vec()),
            ("prefix ending mid-CRC", region[..10].to_vec()),
            ("full region", region.clone()),
            ("torn after the prelude, CRC unwritten", {
                let mut raw = region.clone();
                raw[8..12].fill(0);
                raw
            }),
            ("prefix with a persisted length", {
                let mut raw = vec![0u8; region.len()];
                raw[..10].copy_from_slice(&region[..10]);
                raw
            }),
            (
                "documented residual: V0 blob rotted into a canonical prefix",
                {
                    // The magics share the `CWI` brand, so a V0 blob whose surviving bytes
                    // form a canonical V1 prefix (a default version stamp of 0, an all-zero
                    // payload, and the tag byte lost) is byte-identical to a V1 creation
                    // torn inside the magic, and heals. Its logical length is lost, but
                    // every erased payload byte is zero. Any nonzero stamp, payload, or
                    // non-prefix survivor stays loud (see the reject table).
                    let mut raw = v0_blob_bytes(0, &[0u8; 100]);
                    raw[3] = 0;
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
        let region = v1_blob_bytes(5, b"");
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
            ("magic byte lost with later bytes persisted", {
                // Not a prefix: a write cannot persist byte 5 without byte 3.
                let mut raw = region.clone();
                raw[3] = 0;
                raw
            }),
            ("runtime version byte lost with later bytes persisted", {
                let mut raw = region.clone();
                raw[5] = 0;
                raw
            }),
            ("CRC that does not match its own prelude", {
                // Rot on an otherwise canonical region stays loud: the writer never
                // produces a prelude whose CRC bytes disagree with it.
                let mut raw = region.clone();
                raw[9] = raw[9].wrapping_add(1).max(1);
                raw
            }),
            ("nonzero padding", {
                let mut raw = region.clone();
                raw[100] = 0xFF;
                raw
            }),
            ("data past the header region", {
                let mut raw = region;
                raw.push(1);
                raw
            }),
            ("rotted-magic V0 blob with its version stamp", {
                // The nonzero version stamp makes byte 3 part of the written prefix, so
                // the zeroed magic byte is non-canonical, not unwritten. Only a V0 blob
                // whose surviving bytes form a canonical V1 prefix heals (see the accepts
                // table).
                let mut raw = v0_header(5).encode().to_vec();
                raw[3] = 0;
                raw.extend_from_slice(&[0u8; 100]);
                raw
            }),
            ("rotted-magic V0 blob with payload", {
                let mut raw = v0_header(5).encode().to_vec();
                raw[3] = 0;
                raw.extend_from_slice(&[0xAA, 0xBB]);
                raw
            }),
            (
                "all zeros, one byte longer than the creation region",
                vec![0u8; Header::V1_DATA_OFFSET as usize + 1],
            ),
            ("zero payload past the header region, CRC lost", {
                // A synced V1 blob whose payload is all zeros, with the CRC bytes rotted
                // away: the file extends past the header region, so healing it would
                // erase the payload.
                let mut raw = v1_blob_bytes(5, &[0u8; 100]);
                raw[8..12].fill(0);
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
        let (blob, _, blob_version) = storage
            .open_versioned("test_version_mismatch", b"blob", 1..=1)
            .await
            .unwrap();
        assert_eq!(blob_version, 1);
        blob.sync().await.unwrap();
        drop(blob);

        // Reopen with a range that includes version 1
        let (_, _, blob_version) = storage
            .open_versioned("test_version_mismatch", b"blob", 0..=2)
            .await
            .unwrap();
        assert_eq!(blob_version, 1);

        // Try to open with version range that excludes version 1
        let result = storage
            .open_versioned("test_version_mismatch", b"blob", 2..=3)
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

    /// Test aligned-layout blob creation, reopen, and resize through logical offsets.
    async fn test_aligned_layout<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create an aligned blob and write/read through logical offsets.
        let (blob, size, _) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, 0);
        blob.write_at(0, b"hello world".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
        drop(blob);

        // Reopen honors the recorded layout and logical size.
        let (blob, size, _) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, 11);
        let read = blob.read_at(6, 5).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"world");

        // Resize preserves logical semantics.
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let (blob, size, _) = storage
            .open_versioned("test_aligned_layout", b"blob", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, 5);
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello");
        drop(blob);
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
