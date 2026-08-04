//! On-disk format of one family's write-ahead log.
//!
//! ```text
//! +-------------+ 0
//! | header      |  immutable after creation: magic, incarnation
//! +-------------+ 4096
//! | root slot 0 |  parity pair: a root with sequence `seq` lives in slot `seq & 1`,
//! +-------------+ 8192          so publishing a new root never touches the previous one
//! | root slot 1 |
//! +-------------+ 12288
//! | record space: extents located by the roots                                  | EOF
//! ```
//!
//! The live root names one contiguous, page-aligned extent holding the record stream
//! for the current epoch. An extent is durably zeroed before the root that names it is
//! written, which makes the first zero byte at a record boundary an exact end-of-log
//! marker, and means a valid root always names a complete snapshot: the snapshot at the
//! extent's head is synced before the root, so no completeness marker records exist.
//!
//! Record checksums are salted with the WAL's incarnation and the extent's epoch, so a
//! record from another file or another epoch can never validate even if zeroing were
//! somehow imperfect: defense in depth on top of an exact rule.
//!
//! Records are self-contained namespace operations framed as `len (varint) | body |
//! crc32c`. Replay applies them in order. Decoding distinguishes four outcomes: a valid
//! record; a clean end (leading zero: nothing was written here); a torn tail (a write
//! started and did not complete, including checksum failures); and corruption (a frame
//! whose checksum passes but whose body is malformed, which tearing cannot produce).

use bytes::Buf;
use commonware_codec::{EncodeSize, ReadExt as _, Write as _, varint::UInt};
use commonware_cryptography::{Crc32, Hasher as _};

/// Size of the header and root pages.
pub(super) const PAGE: usize = 4096;

/// Logical offsets of the two root slots, indexed by `seq & 1`.
pub(super) const ROOT_OFFSETS: [u64; 2] = [PAGE as u64, 2 * PAGE as u64];

/// First byte of the record space.
pub(super) const RECORD_SPACE: u64 = 3 * PAGE as u64;

/// Longest allowed blob name in a record.
pub(super) const MAX_NAME_LEN: usize = 64 * 1024;

/// Largest record body the writer can produce. Bodies are name-dominated today, with
/// headroom reserved for inline payloads; a longer length prefix can only be a torn
/// tail or hostile bytes.
pub(super) const MAX_RECORD_LEN: u32 = 128 << 10;

/// Largest extent a root may name. Extents are sized from the snapshot and sit far
/// below this; recovery rejects anything larger as hostile, which bounds its work.
pub(super) const MAX_EXTENT_BYTES: u64 = 4 << 30;

const HEADER_MAGIC: &[u8; 8] = b"CWWALHD1";
const ROOT_MAGIC: &[u8; 8] = b"CWWALRT1";

const HEADER_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_WAL_HEADER";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_WAL_ROOT";
const RECORD_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_WAL_RECORD";

/// Returns `body`'s checksum bound to `domain` and `salt`.
fn crc(domain: &[u8], salt: &[u8], body: &[u8]) -> [u8; 4] {
    Crc32::hash(&[domain, salt, body]).0
}

/// Validates that every byte of `page` beyond `used` is zero.
fn padding_is_zero(page: &[u8], used: usize) -> bool {
    page[used..].iter().all(|&b| b == 0)
}

/// The immutable identity of a WAL file, stored in the first page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Header {
    /// Identifies this WAL file forever: salts every record and root checksum, so
    /// bytes from any other file can never validate here.
    pub incarnation: [u8; 16],
}

impl Header {
    /// Encodes the header as a full page.
    pub fn encode(&self) -> Vec<u8> {
        let mut page = Vec::with_capacity(PAGE);
        page.extend_from_slice(HEADER_MAGIC);
        page.extend_from_slice(&self.incarnation);
        let sum = crc(HEADER_DOMAIN, &[], &page);
        page.extend_from_slice(&sum);
        page.resize(PAGE, 0);
        page
    }

    /// Decodes and validates a header page. Any failure is damage: WAL files are
    /// staged completely and renamed into place, so a visible file that does not
    /// validate was never a crash artifact.
    pub fn decode(page: &[u8]) -> Result<Self, String> {
        assert_eq!(page.len(), PAGE);
        let body = &page[..24];
        if crc(HEADER_DOMAIN, &[], body) != page[24..28] {
            return Err("header checksum mismatch".into());
        }
        if &body[..8] != HEADER_MAGIC {
            return Err("header magic mismatch".into());
        }
        if !padding_is_zero(page, 28) {
            return Err("header padding not zero".into());
        }
        Ok(Self {
            incarnation: body[8..24].try_into().unwrap(),
        })
    }
}

/// One contiguous, page-aligned region of the record space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Extent {
    pub offset: u64,
    pub len: u64,
}

impl Extent {
    /// First byte past the extent.
    pub const fn end(&self) -> u64 {
        self.offset + self.len
    }
}

/// A root: names the live journal extent for one epoch. The highest-sequence valid
/// root governs; its slot must equal `seq & 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Root {
    /// Monotonic publication counter; picks the slot.
    pub seq: u64,
    /// Salt for this extent's record checksums; bumped by every checkpoint.
    pub epoch: u64,
    /// The record extent this root makes live.
    pub extent: Extent,
    /// Blob id minting floor as of this checkpoint; ids are never reused.
    pub next_blob_id: u64,
}

impl Root {
    /// Encodes the root as a full page.
    pub fn encode(&self, incarnation: &[u8; 16]) -> Vec<u8> {
        let mut page = Vec::with_capacity(PAGE);
        page.extend_from_slice(ROOT_MAGIC);
        page.extend_from_slice(&self.seq.to_be_bytes());
        page.extend_from_slice(&self.epoch.to_be_bytes());
        page.extend_from_slice(&self.extent.offset.to_be_bytes());
        page.extend_from_slice(&self.extent.len.to_be_bytes());
        page.extend_from_slice(&self.next_blob_id.to_be_bytes());
        let sum = crc(ROOT_DOMAIN, incarnation, &page);
        page.extend_from_slice(&sum);
        page.resize(PAGE, 0);
        page
    }

    /// Decodes and validates a root page.
    ///
    /// Returns `None` for a page that never held a completed root write under this
    /// incarnation (all-zero, torn, or foreign: all checksum failures), and an error
    /// for a page that validates but is malformed, which only deliberate damage can
    /// produce.
    pub fn decode(page: &[u8], incarnation: &[u8; 16]) -> Result<Option<Self>, String> {
        assert_eq!(page.len(), PAGE);
        let body = &page[..48];
        if crc(ROOT_DOMAIN, incarnation, body) != page[48..52] {
            return Ok(None);
        }
        if &body[..8] != ROOT_MAGIC {
            return Err("root magic mismatch".into());
        }
        if !padding_is_zero(page, 52) {
            return Err("root padding not zero".into());
        }
        let root = Self {
            seq: u64::from_be_bytes(body[8..16].try_into().unwrap()),
            epoch: u64::from_be_bytes(body[16..24].try_into().unwrap()),
            extent: Extent {
                offset: u64::from_be_bytes(body[24..32].try_into().unwrap()),
                len: u64::from_be_bytes(body[32..40].try_into().unwrap()),
            },
            next_blob_id: u64::from_be_bytes(body[40..48].try_into().unwrap()),
        };
        let extent = root.extent;
        if extent.offset < RECORD_SPACE
            || !extent.offset.is_multiple_of(PAGE as u64)
            || extent.len == 0
            || extent.len > MAX_EXTENT_BYTES
            || extent.offset.checked_add(extent.len).is_none()
        {
            return Err("root names an invalid extent".into());
        }
        Ok(Some(root))
    }
}

/// The kind of a blob row. Only ordinary blobs exist today; the atomic kind is
/// reserved record space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Ordinary,
}

impl Kind {
    const fn encode(self) -> u8 {
        match self {
            Self::Ordinary => 0,
        }
    }

    fn decode(byte: u8) -> Result<Self, String> {
        match byte {
            0 => Ok(Self::Ordinary),
            other => Err(format!("unknown blob kind {other}")),
        }
    }
}

const TYPE_CREATE: u8 = 1;
const TYPE_DELETE: u8 = 2;
const TYPE_PARTITION: u8 = 3;
const TYPE_DELETE_PARTITION: u8 = 4;

/// A self-contained namespace operation. Applied in order at replay; the catalog is a
/// fold over the record stream, and the runtime applies the same records to the same
/// catalog, so there is exactly one state-mutation code path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Record {
    /// A blob exists: a live creation, or one row of a checkpoint snapshot (a snapshot
    /// is nothing but the whole catalog re-stated at the head of a fresh extent).
    Create {
        id: u64,
        kind: Kind,
        version: u16,
        partition: String,
        name: Vec<u8>,
    },
    /// The blob is gone. Its partition row persists.
    Delete { id: u64 },
    /// A partition exists even with no blobs (snapshots of empty partitions).
    Partition { partition: String },
    /// The partition and all its blobs are gone.
    DeletePartition { partition: String },
}

/// Outcome of decoding one frame from the record stream.
#[derive(Debug)]
pub(super) enum Frame {
    /// A valid record and the bytes it consumed.
    Record(Record, usize),
    /// A leading zero: nothing was ever written here. Exact, because extents are
    /// durably zeroed before use and no frame starts with a zero length byte.
    CleanEnd,
    /// A write started and did not complete: short frame or checksum failure. A
    /// bit-flip under a valid length also lands here; stopping replay is the safe
    /// direction for both.
    TornTail,
    /// A checksummed frame whose body is malformed. Torn writes cannot produce this;
    /// it is always a hard error.
    Corrupt(String),
}

impl Record {
    /// Appends this record's frame (length, body, checksum) to `out`.
    pub fn encode(&self, salt: &Salt, out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(self.body_size());
        match self {
            Self::Create {
                id,
                kind,
                version,
                partition,
                name,
            } => {
                body.push(TYPE_CREATE);
                UInt(*id).write(&mut body);
                body.push(kind.encode());
                body.extend_from_slice(&version.to_be_bytes());
                UInt(partition.len() as u32).write(&mut body);
                body.extend_from_slice(partition.as_bytes());
                UInt(name.len() as u32).write(&mut body);
                body.extend_from_slice(name);
            }
            Self::Delete { id } => {
                body.push(TYPE_DELETE);
                UInt(*id).write(&mut body);
            }
            Self::Partition { partition } => {
                body.push(TYPE_PARTITION);
                UInt(partition.len() as u32).write(&mut body);
                body.extend_from_slice(partition.as_bytes());
            }
            Self::DeletePartition { partition } => {
                body.push(TYPE_DELETE_PARTITION);
                UInt(partition.len() as u32).write(&mut body);
                body.extend_from_slice(partition.as_bytes());
            }
        }
        debug_assert_eq!(body.len(), self.body_size());
        UInt(body.len() as u32).write(out);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc(RECORD_DOMAIN, &salt.0, &body));
    }

    /// Size of this record's body (the frame adds a length varint and a checksum).
    fn body_size(&self) -> usize {
        1 + match self {
            Self::Create {
                id,
                partition,
                name,
                ..
            } => {
                UInt(*id).encode_size()
                    + 1
                    + 2
                    + UInt(partition.len() as u32).encode_size()
                    + partition.len()
                    + UInt(name.len() as u32).encode_size()
                    + name.len()
            }
            Self::Delete { id } => UInt(*id).encode_size(),
            Self::Partition { partition } | Self::DeletePartition { partition } => {
                UInt(partition.len() as u32).encode_size() + partition.len()
            }
        }
    }

    /// Decodes one frame from the start of `buf` (the unread remainder of the extent).
    pub fn decode(buf: &[u8], salt: &Salt) -> Frame {
        if buf.is_empty() || buf[0] == 0 {
            return Frame::CleanEnd;
        }
        let mut cursor = buf;
        let Ok(len) = UInt::<u32>::read(&mut cursor) else {
            return Frame::TornTail;
        };
        // Widened arithmetic: a hostile length near u32::MAX must not overflow into a
        // passing bounds check on 32-bit targets.
        let len = u32::from(len);
        if len > MAX_RECORD_LEN || u64::from(len) + 4 > cursor.remaining() as u64 {
            return Frame::TornTail;
        }
        let len = len as usize;
        let body = &cursor[..len];
        let sum = &cursor[len..len + 4];
        if crc(RECORD_DOMAIN, &salt.0, body) != sum {
            return Frame::TornTail;
        }
        let consumed = (buf.len() - cursor.len()) + len + 4;
        match Self::decode_body(body) {
            Ok(record) => Frame::Record(record, consumed),
            Err(reason) => Frame::Corrupt(reason),
        }
    }

    /// Decodes a checksummed body. Any failure here is corruption, not a torn tail.
    fn decode_body(mut body: &[u8]) -> Result<Self, String> {
        let kind = u8::read(&mut body).map_err(|e| e.to_string())?;
        let record = match kind {
            TYPE_CREATE => {
                let id = UInt::<u64>::read(&mut body).map_err(|e| e.to_string())?.0;
                let kind = Kind::decode(u8::read(&mut body).map_err(|e| e.to_string())?)?;
                let version = u16::read(&mut body).map_err(|e| e.to_string())?;
                let partition = read_partition(&mut body)?;
                let name_len = UInt::<u32>::read(&mut body).map_err(|e| e.to_string())?.0 as usize;
                if name_len > MAX_NAME_LEN {
                    return Err(format!("name length {name_len} exceeds {MAX_NAME_LEN}"));
                }
                if name_len > body.remaining() {
                    return Err("name length exceeds body".into());
                }
                let name = body[..name_len].to_vec();
                body.advance(name_len);
                Self::Create {
                    id,
                    kind,
                    version,
                    partition,
                    name,
                }
            }
            TYPE_DELETE => Self::Delete {
                id: UInt::<u64>::read(&mut body).map_err(|e| e.to_string())?.0,
            },
            TYPE_PARTITION => Self::Partition {
                partition: read_partition(&mut body)?,
            },
            TYPE_DELETE_PARTITION => Self::DeletePartition {
                partition: read_partition(&mut body)?,
            },
            other => return Err(format!("unknown record type {other}")),
        };
        if body.remaining() != 0 {
            return Err("trailing bytes in record body".into());
        }
        Ok(record)
    }
}

/// Reads a length-prefixed partition name.
fn read_partition(body: &mut &[u8]) -> Result<String, String> {
    let len = UInt::<u32>::read(body).map_err(|e| e.to_string())?.0 as usize;
    if len > MAX_NAME_LEN {
        return Err(format!("partition length {len} exceeds {MAX_NAME_LEN}"));
    }
    if len > body.remaining() {
        return Err("partition length exceeds body".into());
    }
    let partition = std::str::from_utf8(&body[..len])
        .map_err(|_| "partition is not utf-8".to_string())?
        .to_string();
    body.advance(len);
    Ok(partition)
}

/// The checksum salt binding records to one WAL file and one epoch.
pub(super) struct Salt(pub [u8; 24]);

impl Salt {
    /// Builds the salt for `epoch` of the WAL identified by `incarnation`.
    pub fn new(incarnation: &[u8; 16], epoch: u64) -> Self {
        let mut salt = [0u8; 24];
        salt[..16].copy_from_slice(incarnation);
        salt[16..].copy_from_slice(&epoch.to_be_bytes());
        Self(salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INCARNATION: [u8; 16] = *b"0123456789abcdef";

    fn sample_records() -> Vec<Record> {
        vec![
            Record::Create {
                id: 0,
                kind: Kind::Ordinary,
                version: 3,
                partition: "orders".into(),
                name: b"section-1".to_vec(),
            },
            Record::Delete { id: 0 },
            Record::Partition {
                partition: "empty".into(),
            },
            Record::DeletePartition {
                partition: "empty".into(),
            },
        ]
    }

    #[test]
    fn header_round_trip() {
        let header = Header {
            incarnation: INCARNATION,
        };
        let page = header.encode();
        assert_eq!(page.len(), PAGE);
        assert_eq!(Header::decode(&page).unwrap(), header);
    }

    #[test]
    fn header_damage_is_hard_error() {
        let mut page = Header {
            incarnation: INCARNATION,
        }
        .encode();
        page[3] ^= 1;
        assert!(Header::decode(&page).is_err());
        // Nonzero padding under a valid checksum is also damage.
        let mut page = Header {
            incarnation: INCARNATION,
        }
        .encode();
        page[100] = 1;
        assert!(Header::decode(&page).is_err());
        // All zeros (never written) is damage too: creation is staged and renamed.
        assert!(Header::decode(&vec![0u8; PAGE]).is_err());
    }

    #[test]
    fn root_round_trip_and_parity() {
        let root = Root {
            seq: 7,
            epoch: 3,
            extent: Extent {
                offset: RECORD_SPACE,
                len: 1 << 20,
            },
            next_blob_id: 42,
        };
        let page = root.encode(&INCARNATION);
        assert_eq!(Root::decode(&page, &INCARNATION).unwrap(), Some(root));
        // A root under a different incarnation reads as never-written, not damage.
        assert_eq!(Root::decode(&page, b"another-file-xyz").unwrap(), None);
        // All zeros reads as never-written.
        assert_eq!(Root::decode(&vec![0u8; PAGE], &INCARNATION).unwrap(), None);
    }

    #[test]
    fn root_invalid_extents_are_hard_errors() {
        for extent in [
            // Below the record space.
            Extent { offset: 0, len: 1 },
            // Misaligned.
            Extent {
                offset: RECORD_SPACE + 1,
                len: PAGE as u64,
            },
            // Empty.
            Extent {
                offset: RECORD_SPACE,
                len: 0,
            },
            // Oversized.
            Extent {
                offset: RECORD_SPACE,
                len: MAX_EXTENT_BYTES + 1,
            },
        ] {
            let page = Root {
                seq: 1,
                epoch: 1,
                extent,
                next_blob_id: 0,
            }
            .encode(&INCARNATION);
            assert!(Root::decode(&page, &INCARNATION).is_err(), "{extent:?}");
        }
    }

    #[test]
    fn record_round_trip() {
        let salt = Salt::new(&INCARNATION, 5);
        let mut buf = Vec::new();
        for record in sample_records() {
            record.encode(&salt, &mut buf);
        }
        let mut remaining = &buf[..];
        for expected in sample_records() {
            match Record::decode(remaining, &salt) {
                Frame::Record(record, consumed) => {
                    assert_eq!(record, expected);
                    remaining = &remaining[consumed..];
                }
                other => panic!("expected record, got {other:?}"),
            }
        }
        assert!(matches!(Record::decode(remaining, &salt), Frame::CleanEnd));
    }

    #[test]
    fn record_clean_end_is_exact() {
        let salt = Salt::new(&INCARNATION, 1);
        assert!(matches!(Record::decode(&[], &salt), Frame::CleanEnd));
        assert!(matches!(Record::decode(&[0, 7, 7], &salt), Frame::CleanEnd));
    }

    #[test]
    fn record_torn_tail_is_torn() {
        let salt = Salt::new(&INCARNATION, 1);
        let mut buf = Vec::new();
        Record::Delete { id: 9 }.encode(&salt, &mut buf);
        // Every strict prefix (except empty, which is a clean end) is a torn tail.
        for cut in 1..buf.len() {
            assert!(
                matches!(Record::decode(&buf[..cut], &salt), Frame::TornTail),
                "prefix of {cut} bytes"
            );
        }
        // A flipped body bit under an intact length is torn too (checksum fails).
        let mut flipped = buf.clone();
        flipped[1] ^= 1;
        assert!(matches!(Record::decode(&flipped, &salt), Frame::TornTail));
    }

    #[test]
    fn record_wrong_epoch_is_torn() {
        let mut buf = Vec::new();
        Record::Delete { id: 9 }.encode(&Salt::new(&INCARNATION, 1), &mut buf);
        let other = Salt::new(&INCARNATION, 2);
        assert!(matches!(Record::decode(&buf, &other), Frame::TornTail));
    }

    #[test]
    fn record_corruption_is_not_torn() {
        // A checksummed frame with an unknown type: tearing cannot produce this.
        let salt = Salt::new(&INCARNATION, 1);
        let body = vec![0xEEu8];
        let mut buf = Vec::new();
        UInt(body.len() as u32).write(&mut buf);
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&crc(RECORD_DOMAIN, &salt.0, &body));
        assert!(matches!(Record::decode(&buf, &salt), Frame::Corrupt(_)));
    }

    #[test]
    fn record_trailing_body_bytes_are_corrupt() {
        let salt = Salt::new(&INCARNATION, 1);
        let mut body = vec![TYPE_DELETE];
        UInt(9u64).write(&mut body);
        body.push(0xAB); // trailing garbage inside the checksummed body
        let mut buf = Vec::new();
        UInt(body.len() as u32).write(&mut buf);
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&crc(RECORD_DOMAIN, &salt.0, &body));
        assert!(matches!(Record::decode(&buf, &salt), Frame::Corrupt(_)));
    }

    #[test]
    fn record_hostile_length_is_torn() {
        let salt = Salt::new(&INCARNATION, 1);
        let mut buf = Vec::new();
        UInt(u32::MAX).write(&mut buf);
        buf.extend_from_slice(&[0xFF; 64]);
        assert!(matches!(Record::decode(&buf, &salt), Frame::TornTail));
    }
}
