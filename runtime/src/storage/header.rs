//! Blob header layouts shared by every storage backend: the on-disk prelude, the per-layout
//! geometry, and reopen-time resolution (including torn-creation recovery).

use commonware_macros::stability_scope;

stability_scope!(BETA {
    use crate::{Buf, BufMut};
    use commonware_codec::{DecodeExt, Encode, FixedSize, Read as CodecRead, Write as CodecWrite};
    use commonware_cryptography::Crc32;
    use commonware_formatting::hex;
    use std::ops::RangeInclusive;
    use tracing::warn;

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
        InvalidChecksum,
        InvalidPadding,
        Truncated {
            required_len: u64,
            raw_len: u64,
        },
    }

    impl HeaderError {
        /// Returns true if this parse failure could be the signature of a creation interrupted
        /// before the header became durable, making the blob a candidate for
        /// [Layout::interrupted_creation] classification.
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
                    | Self::InvalidChecksum
                    | Self::Truncated { .. }
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
                Self::InvalidChecksum => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    "invalid header checksum".into(),
                ),
                Self::InvalidPadding => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    "invalid header padding".into(),
                ),
                Self::Truncated {
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

    /// Version of a [crate::Blob]'s on-disk header layout.
    ///
    /// This versions the runtime's on-disk container (where data begins), not the blob's
    /// contents: the application-owned blob version passed to
    /// [crate::Storage::open_versioned] is a separate field and is unaffected by the layout.
    ///
    /// New blobs are always created with the latest layout. Reopening an existing blob honors
    /// the layout recorded in its header.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Layout {
        /// An 8-byte header, with data beginning immediately after it.
        V0,
        /// A header padded to one 4096-byte page, so data begins on an aligned boundary.
        V1,
    }

    impl Layout {
        /// The runtime version recorded in a header of this layout.
        pub(crate) const fn runtime_version(self) -> u16 {
            match self {
                Self::V0 => 0,
                Self::V1 => 1,
            }
        }

        /// The magic bytes recorded in a header of this layout: a fixed 3-byte brand (`CWI`,
        /// "is this file ours?") followed by a 1-byte layout tag ("which container layout?").
        ///
        /// The layout tag lives in the magic rather than the runtime version field because V0
        /// stamped that field as zero, and zeros are exactly what a torn header write leaves
        /// behind. Tags are nonzero and distinct, so no layout's magic can be turned into
        /// another's by zeroing bytes, and a torn write can never be misread as a complete
        /// header of a different layout.
        pub(crate) const fn magic(self) -> [u8; 4] {
            match self {
                Self::V0 => *b"CWIC",
                Self::V1 => *b"CWIK",
            }
        }

        /// The layout recorded by a header with the given magic bytes, if supported.
        pub(crate) const fn from_magic(magic: &[u8; 4]) -> Option<Self> {
            match magic {
                b"CWIC" => Some(Self::V0),
                b"CWIK" => Some(Self::V1),
                _ => None,
            }
        }

        /// The offset where blob data begins under this layout. Not stored on disk (the
        /// layout's magic implies it): a [Layout::V0] header is the bare prelude, while a
        /// [Layout::V1] header region occupies exactly one 4096-byte page.
        ///
        /// Each offset is frozen for the lifetime of its layout: torn-creation recovery
        /// relies on every V1 creation producing this exact region, so a different offset
        /// requires a new layout (with its own magic), not a change here.
        pub(crate) const fn data_offset(self) -> u64 {
            match self {
                Self::V0 => Header::PRELUDE_SIZE as u64,
                Self::V1 => 4096,
            }
        }

        /// Validates the header region past the prelude for this layout, which must be
        /// fully present: a [Layout::V0] region is the prelude alone, while a [Layout::V1]
        /// region extends to a CRC over the prelude and zero reserved padding out to the
        /// data offset.
        fn validate_region(self, raw: &[u8], raw_len: u64) -> Result<(), HeaderError> {
            match self {
                Self::V0 => Ok(()),
                Self::V1 => {
                    if raw.len() < Header::PARSE_LEN {
                        return Err(HeaderError::Truncated {
                            required_len: Header::PARSE_LEN as u64,
                            raw_len,
                        });
                    }
                    let crc = u32::from_be_bytes(
                        raw[Header::PRELUDE_SIZE..Header::PARSE_LEN].try_into().unwrap(),
                    );
                    if Crc32::checksum(&raw[..Header::PRELUDE_SIZE]) != crc {
                        return Err(HeaderError::InvalidChecksum);
                    }
                    if raw_len < self.data_offset() {
                        return Err(HeaderError::Truncated {
                            required_len: self.data_offset(),
                            raw_len,
                        });
                    }
                    if raw[Header::PARSE_LEN..self.data_offset() as usize]
                        .iter()
                        .any(|&byte| byte != 0)
                    {
                        return Err(HeaderError::InvalidPadding);
                    }
                    Ok(())
                }
            }
        }

        /// Returns true if a blob's raw contents are consistent with the creation of a
        /// blob with this layout that was interrupted before its header became durable.
        ///
        /// This runtime never creates [Layout::V0] blobs, so no contents qualify for V0 (a
        /// pre-V1 writer's torn creation is a sub-prelude file, healed as new before any
        /// parsing).
        ///
        /// [Layout::V1] creation writes the region with set_len(0) -> write -> sync, and
        /// this classifier models the states it recovers as a prefix of the canonical
        /// region, possibly followed by zeros (a persisted length without persisted bytes
        /// reads as zeros). A file is accepted iff it fits within the region and equals a
        /// canonical prefix followed by zeros: the magic and runtime version are fixed;
        /// the blob version bytes continue the prefix with whatever value the writer
        /// chose; the CRC bytes must be a prefix of the CRC over the preceding prelude,
        /// which can only have begun persisting once the full prelude did; and everything
        /// past the prefix must be zero.
        ///
        /// The prefix shape is a model, not a filesystem guarantee: device writeback before
        /// the sync completes may persist bytes out of order. A file that is not a canonical
        /// prefix (a lost byte followed by persisted ones, or a CRC that does not match its
        /// own prelude) stays loudly corrupt rather than healing, trading recovery
        /// coverage for avoiding broader acceptance that might erase nonzero data.
        pub(crate) fn interrupted_creation(self, raw: &[u8]) -> bool {
            match self {
                Self::V0 => false,
                Self::V1 => {
                    // The file cannot extend past the region creation writes, and
                    // everything past the parseable header must be zero padding.
                    if raw.len() > self.data_offset() as usize {
                        return false;
                    }
                    let head = &raw[..raw.len().min(Header::PARSE_LEN)];
                    if raw[head.len()..].iter().any(|&byte| byte != 0) {
                        return false;
                    }

                    // The written prefix ends after the last nonzero byte (trailing zeros
                    // are indistinguishable from unwritten bytes).
                    let written = head.iter().rposition(|&byte| byte != 0).map_or(0, |i| i + 1);

                    let mut canonical = [0u8; Header::PARSE_LEN];
                    canonical[..4].copy_from_slice(&self.magic());
                    canonical[4..6].copy_from_slice(&self.runtime_version().to_be_bytes());
                    if written <= Header::PRELUDE_SIZE {
                        // Torn at or before the CRC: the fixed bytes of the prefix must
                        // match; the blob version bytes (6-7) are the writer's choice.
                        head[..written.min(6)] == canonical[..written.min(6)]
                    } else {
                        // CRC bytes persisted, so the full prelude did too: it must be
                        // canonical (with the writer's version), and the CRC bytes must be
                        // a prefix of the CRC over it.
                        if head[..6] != canonical[..6] {
                            return false;
                        }
                        canonical[6..8].copy_from_slice(&head[6..8]);
                        let crc = Crc32::checksum(&canonical[..Header::PRELUDE_SIZE]);
                        canonical[8..12].copy_from_slice(&crc.to_be_bytes());
                        head[8..written] == canonical[8..written]
                    }
                }
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
    /// The magic selects the header region layout ([Layout]), and the layout fully
    /// determines the geometry: a V0 header region is the 8-byte prelude alone with data at
    /// offset 8, while a V1 header region extends to the V1 [Layout::data_offset], so data
    /// begins on an aligned boundary.
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

        /// Size of the V1 header extension in bytes (CRC32 over the prelude).
        pub(crate) const EXTENSION_SIZE: usize = 4;

        /// Number of leading bytes needed to parse any header: the prelude plus the V1
        /// extension.
        pub(crate) const PARSE_LEN: usize = Self::PRELUDE_SIZE + Self::EXTENSION_SIZE;

        /// Length of magic bytes.
        pub(crate) const MAGIC_LENGTH: usize = 4;

        /// Returns true if a blob is missing a valid header (new or corrupted).
        pub(crate) const fn missing(raw_len: u64) -> bool {
            raw_len < Self::PRELUDE_SIZE as u64
        }

        /// Number of leading bytes [resolve] needs for a blob of raw on-disk length
        /// `raw_len`: the full header region, capped by the file itself.
        pub(crate) const fn resolve_len(raw_len: u64) -> usize {
            if raw_len < Layout::V1.data_offset() {
                raw_len as usize
            } else {
                Layout::V1.data_offset() as usize
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
            let layout = Layout::V1;
            let blob_version = *versions.end();
            let header = Self {
                magic: layout.magic(),
                runtime_version: layout.runtime_version(),
                blob_version,
            };
            let mut region = Vec::with_capacity(Layout::V1.data_offset() as usize);
            region.extend_from_slice(&header.encode());
            let crc = Crc32::checksum(&region);
            region.extend_from_slice(&crc.to_be_bytes());
            region.resize(layout.data_offset() as usize, 0);
            (region, blob_version)
        }

        /// Parses and validates a blob's header from its leading bytes, returning the blob's
        /// logical size, blob version, and data offset.
        ///
        /// `raw` must hold the blob's first [Header::resolve_len] bytes with
        /// `raw_len >= PRELUDE_SIZE`, where `raw_len` is the blob's raw on-disk length.
        pub(crate) fn parse(
            raw: &[u8],
            raw_len: u64,
            versions: &RangeInclusive<u16>,
        ) -> Result<(u64, u16, u64), HeaderError> {
            let header: Self = Self::decode(&raw[..Self::PRELUDE_SIZE])
                .expect("header decode should never fail for correct size input");
            let layout = header.validate()?;
            layout.validate_region(raw, raw_len)?;

            // The blob version is checked only once the region is intact, so every earlier
            // error still describes a header that may merely be incompletely written.
            if !versions.contains(&header.blob_version) {
                return Err(HeaderError::VersionMismatch {
                    expected: versions.clone(),
                    found: header.blob_version,
                });
            }

            let data_offset = layout.data_offset();
            Ok((raw_len - data_offset, header.blob_version, data_offset))
        }

        /// Validates the magic bytes and runtime version, returning the layout the magic
        /// identifies.
        ///
        /// The magic alone selects the layout, and the runtime version must agree with it. Requiring
        /// agreement (rather than deriving the layout from the runtime version) means a header
        /// with any layout-identifying bytes zeroed by a torn write fails validation instead
        /// of parsing as a different layout.
        pub(crate) const fn validate(&self) -> Result<Layout, HeaderError> {
            let Some(layout) = Layout::from_magic(&self.magic) else {
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
    /// header, or its contents are those of a [Layout::V1] creation interrupted
    /// before its header became durable. Anything else fails as corrupt or unacceptable.
    ///
    /// `raw` must hold the blob's first [Header::resolve_len] bytes, where `raw_len` is
    /// the blob's raw on-disk length.
    pub(crate) fn resolve(
        raw: &[u8],
        raw_len: u64,
        versions: &RangeInclusive<u16>,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(u64, u16, u64)>, crate::Error> {
        assert!(
            raw.len() >= Header::resolve_len(raw_len),
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
        if raw_len <= Layout::V1.data_offset()
            && err.may_be_torn_creation()
            && Layout::V1.interrupted_creation(raw)
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
});

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Header {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let version: u16 = u.arbitrary()?;
        Ok(Self {
            magic: Layout::V0.magic(),
            runtime_version: Layout::V0.runtime_version(),
            blob_version: version,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Header, HeaderError, Layout};
    use commonware_codec::{DecodeExt, Encode};

    /// A V0 header with the given blob version, for direct field manipulation in tests.
    fn v0_header(blob_version: u16) -> Header {
        Header {
            magic: Layout::V0.magic(),
            runtime_version: Layout::V0.runtime_version(),
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
            magic: Layout::V1.magic(),
            runtime_version: Layout::V1.runtime_version(),
            blob_version,
        };
        let mut raw = Vec::with_capacity(Layout::V1.data_offset() as usize + payload.len());
        raw.extend_from_slice(&header.encode());
        let crc = commonware_cryptography::Crc32::checksum(&raw);
        raw.extend_from_slice(&crc.to_be_bytes());
        raw.resize(Layout::V1.data_offset() as usize, 0);
        raw.extend_from_slice(payload);
        raw
    }

    #[test]
    fn test_header_create_v1() {
        let (region, blob_version) = Header::create(&(0..=7));
        assert_eq!(blob_version, 7);
        assert_eq!(region.len(), Layout::V1.data_offset() as usize);

        // The padding past the extension is zero.
        assert!(region[Header::PARSE_LEN..].iter().all(|&b| b == 0));

        // The region round-trips through parsing.
        let (size, parsed_blob_version, data_offset) =
            Header::parse(&region, Layout::V1.data_offset(), &(0..=7)).unwrap();
        assert_eq!(size, 0);
        assert_eq!(parsed_blob_version, 7);
        assert_eq!(data_offset, Layout::V1.data_offset());
    }

    /// Freeze the exact on-disk bytes of a V1 header so accidental format changes are caught
    /// (the padding is asserted zero in [test_header_create_v1]).
    #[test]
    fn test_header_v1_fixture_bytes() {
        let (region, _) = Header::create(&(3..=3));
        let expected = [
            b'C', b'W', b'I', b'K', // V1 magic
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
        let result = Header::parse(&region, Layout::V1.data_offset(), &(0..=0));
        assert!(matches!(result, Err(HeaderError::InvalidChecksum)));
    }

    #[test]
    fn test_header_extension_rejects_truncated_region() {
        let (region, _) = Header::create(&(0..=0));
        let result = Header::parse(
            &region[..Layout::V1.data_offset() as usize - 1],
            Layout::V1.data_offset() - 1,
            &(0..=0),
        );
        assert!(matches!(
            result,
            Err(HeaderError::Truncated { required_len, raw_len })
            if required_len == Layout::V1.data_offset() && raw_len == Layout::V1.data_offset() - 1
        ));
    }

    #[test]
    fn test_header_v1_rejects_nonzero_padding() {
        let (mut region, _) = Header::create(&(0..=0));
        region[Header::PARSE_LEN] = 0x01;
        let result = Header::parse(&region, Layout::V1.data_offset(), &(0..=0));
        assert!(matches!(result, Err(HeaderError::InvalidPadding)));
    }

    #[test]
    fn test_header_validate_success() {
        let header = v0_header(5);
        assert!(header.validate().is_ok());
        assert!(Header::parse(&header.encode(), Layout::V0.data_offset(), &(3..=7)).is_ok());
        assert!(Header::parse(&header.encode(), Layout::V0.data_offset(), &(5..=5)).is_ok());
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
            (HeaderError::InvalidChecksum, "invalid header checksum"),
            (HeaderError::InvalidPadding, "invalid header padding"),
            (
                HeaderError::Truncated {
                    required_len: Layout::V1.data_offset(),
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
        assert!(HeaderError::InvalidChecksum.may_be_torn_creation());
        assert!(
            HeaderError::Truncated {
                required_len: Layout::V1.data_offset(),
                raw_len: 100
            }
            .may_be_torn_creation()
        );
        assert!(!HeaderError::InvalidPadding.may_be_torn_creation());
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
        for layout in [Layout::V0, Layout::V1] {
            for i in 0..Header::MAGIC_LENGTH {
                let mut magic = layout.magic();
                magic[i] = 0;
                assert!(Layout::from_magic(&magic).is_none());
            }
        }
    }

    /// A torn V1 header write that persists the magic but zeroes the runtime version must fail
    /// validation rather than parse as V0 (which shares runtime version 0).
    #[test]
    fn test_header_torn_v1_does_not_parse_as_v0() {
        let header = Header {
            magic: Layout::V1.magic(),
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
        let result = Header::parse(&header.encode(), Layout::V0.data_offset(), &(3..=7));
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
        assert!(matches!(result, Err(HeaderError::InvalidChecksum)));
    }

    #[test]
    fn test_header_interrupted_v1_creation_accepts_torn_states() {
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
                Layout::V1.interrupted_creation(raw),
                "{label} should classify as an interrupted creation"
            );
        }
    }

    /// This runtime never creates V0 blobs, so no contents qualify as an interrupted V0
    /// creation, including ones that heal under V1.
    #[test]
    fn test_layout_v0_interrupted_creation_rejects_all() {
        let (region, _) = Header::create(&(0..=0));
        assert!(Layout::V1.interrupted_creation(&region[..10]));
        assert!(!Layout::V0.interrupted_creation(&region[..10]));
        assert!(!Layout::V0.interrupted_creation(&[]));
    }

    #[test]
    fn test_header_interrupted_v1_creation_rejects_foreign_bytes() {
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
                vec![0u8; Layout::V1.data_offset() as usize + 1],
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
                !Layout::V1.interrupted_creation(raw),
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
}
