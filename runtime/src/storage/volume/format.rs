//! On-disk format of a volume.
//!
//! A volume is stored inside one blob of an inner [crate::Storage] backend. Its logical
//! layout is three 4 KiB pages followed by fixed-size chunks:
//!
//! ```text
//! +-------------+ 0
//! | superblock  |  immutable after creation: magic, chunk size
//! +-------------+ 4096
//! | root slot 0 |  parity pair: a root with sequence `seq` lives in slot `seq & 1`,
//! +-------------+ 8192          so publishing a new root never touches the previous one
//! | root slot 1 |
//! +-------------+ 12288
//! | (unused up to one chunk, then chunk 1, chunk 2, ...)
//! +-------------+ EOF
//! ```
//!
//! Chunk `i` occupies bytes `[i * chunk_size, (i + 1) * chunk_size)`. Chunk 0 overlaps the
//! header pages and is never allocatable, so valid chunk ids start at 1.
//!
//! The live root names one contiguous extent of chunks holding the record journal for the
//! current epoch. The extent is durably zeroed before the root that names it is written,
//! which makes the first zero byte at a record boundary an exact end-of-log marker. Record
//! checksums are additionally salted with the epoch, so a record written under any other
//! epoch can never validate even if that zeroing were somehow imperfect.
//!
//! Records are self-contained operations framed as `len (varint) | body | crc32c`. Replay
//! applies them in order and stops at the first frame that reads as a torn tail. Bytes that
//! a torn write cannot produce (a checksummed record that is internally malformed) are
//! reported as corruption instead of silently ending replay.

use bytes::Buf;
use commonware_codec::{EncodeSize, Error as CodecError, ReadExt as _, Write as _, varint::UInt};
use commonware_cryptography::{Crc32, Hasher as _};

/// Size of the superblock and root pages.
pub(super) const PAGE: usize = 4096;

/// Logical offset of the superblock.
pub(super) const SUPERBLOCK_OFFSET: u64 = 0;

/// Logical offsets of the two root slots, indexed by `seq & 1`.
pub(super) const ROOT_OFFSETS: [u64; 2] = [PAGE as u64, 2 * PAGE as u64];

/// Smallest allowed chunk size. Must cover the three header pages so that chunk 0 (the
/// only chunk overlapping them) is the only reserved chunk.
pub(super) const MIN_CHUNK_SIZE: u32 = 64 * 1024;

/// Largest allowed chunk size. Bounded so per-chunk operations (zero-writes, shrink
/// copies, recovery tail checks) stay reasonably sized.
pub(super) const MAX_CHUNK_SIZE: u32 = 64 << 20;

/// Longest allowed blob name in a record.
pub(super) const MAX_NAME_LEN: usize = 64 * 1024;

/// Largest record body the writer can produce. Snapshot rows dominate record size; the
/// per-blob mapped-slot cap keeps every row comfortably below this, so a longer length
/// prefix can only be a torn tail or hostile bytes.
pub(super) const MAX_RECORD_LEN: u32 = 256 << 20;

/// Most mapped slots one blob may hold, so its snapshot row always fits a record.
pub(super) const MAX_MAPPED_SLOTS: usize = 16 << 20;

/// Largest journal extent. Written extents are sized from the snapshot and sit far
/// below this; recovery rejects anything larger as hostile, which bounds its work.
pub(super) const MAX_EXTENT_BYTES: u64 = 64 << 30;

const SUPERBLOCK_MAGIC: &[u8; 8] = b"CWVOLSB1";
const ROOT_MAGIC: &[u8; 8] = b"CWVOLRT1";

const SUPERBLOCK_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_VOLUME_SUPERBLOCK";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_VOLUME_ROOT";
const RECORD_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_VOLUME_RECORD";

/// Returns `body`'s checksum bound to `domain` and, for records, the epoch.
fn crc(domain: &[u8], salt: &[u8], body: &[u8]) -> [u8; 4] {
    Crc32::hash(&[domain, salt, body]).0
}

/// Validates that every byte of `page` beyond `used` is zero.
fn padding_is_zero(page: &[u8], used: usize) -> bool {
    page[used..].iter().all(|&b| b == 0)
}

/// The immutable identity of a volume, stored in the first page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Superblock {
    /// Chunk size in bytes. A power of two in `[MIN_CHUNK_SIZE, MAX_CHUNK_SIZE]`, frozen
    /// for the volume's lifetime.
    pub chunk_size: u32,
}

impl Superblock {
    /// Encodes the superblock as a full page.
    pub fn encode(&self) -> Vec<u8> {
        let mut page = Vec::with_capacity(PAGE);
        page.extend_from_slice(SUPERBLOCK_MAGIC);
        page.extend_from_slice(&self.chunk_size.to_be_bytes());
        let crc = crc(SUPERBLOCK_DOMAIN, &[], &page);
        page.extend_from_slice(&crc);
        page.resize(PAGE, 0);
        page
    }

    /// Decodes and validates a superblock page.
    ///
    /// Returns `None` for any page a torn creation could leave behind (recovery treats the
    /// volume as never created) and an error message for bytes that prove damage after a
    /// completed creation is impossible to rule out.
    pub fn decode(page: &[u8]) -> Result<Option<Self>, String> {
        assert_eq!(page.len(), PAGE);
        let body = &page[..12];
        if crc(SUPERBLOCK_DOMAIN, &[], body) != page[12..16] {
            return Ok(None);
        }
        if &body[..8] != SUPERBLOCK_MAGIC {
            return Err("superblock magic mismatch".into());
        }
        if !padding_is_zero(page, 16) {
            return Err("superblock padding not zero".into());
        }
        let chunk_size = u32::from_be_bytes(body[8..12].try_into().unwrap());
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) || !chunk_size.is_power_of_two()
        {
            return Err(format!("superblock chunk size invalid: {chunk_size}"));
        }
        Ok(Some(Self { chunk_size }))
    }
}

/// A contiguous run of chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Extent {
    /// First chunk of the run. At least 1.
    pub first_chunk: u32,
    /// Number of chunks in the run. At least 1.
    pub chunks: u32,
}

impl Extent {
    /// Logical byte offset where the extent begins.
    pub fn offset(&self, chunk_size: u32) -> u64 {
        u64::from(self.first_chunk) * u64::from(chunk_size)
    }

    /// Length of the extent in bytes.
    pub fn len(&self, chunk_size: u32) -> u64 {
        u64::from(self.chunks) * u64::from(chunk_size)
    }

    /// Logical byte offset just past the extent.
    pub fn end(&self, chunk_size: u32) -> u64 {
        self.offset(chunk_size) + self.len(chunk_size)
    }
}

/// A published root: which epoch is live and where its record journal lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Root {
    /// Monotonic publication counter. At least 1; lives in slot `seq & 1`.
    pub seq: u64,
    /// Journal epoch, bumped by every checkpoint. Salts all record checksums.
    pub epoch: u64,
    /// The journal extent for this epoch.
    pub extent: Extent,
}

impl Root {
    /// Encodes the root as a full page.
    pub fn encode(&self) -> Vec<u8> {
        let mut page = Vec::with_capacity(PAGE);
        page.extend_from_slice(ROOT_MAGIC);
        page.extend_from_slice(&self.seq.to_be_bytes());
        page.extend_from_slice(&self.epoch.to_be_bytes());
        page.extend_from_slice(&self.extent.first_chunk.to_be_bytes());
        page.extend_from_slice(&self.extent.chunks.to_be_bytes());
        let crc = crc(ROOT_DOMAIN, &[], &page);
        page.extend_from_slice(&crc);
        page.resize(PAGE, 0);
        page
    }

    /// Decodes and validates the root page stored in `slot`.
    ///
    /// Returns `None` for pages a crash can produce (all zero before first publication, or
    /// torn mid-overwrite) and an error message for states no crash can reach: a checksummed
    /// root in the wrong parity slot, invalid geometry, or nonzero padding.
    pub fn decode(page: &[u8], slot: usize) -> Result<Option<Self>, String> {
        assert_eq!(page.len(), PAGE);
        let body = &page[..32];
        if crc(ROOT_DOMAIN, &[], body) != page[32..36] {
            return Ok(None);
        }
        if &body[..8] != ROOT_MAGIC {
            return Err("root magic mismatch".into());
        }
        if !padding_is_zero(page, 36) {
            return Err("root padding not zero".into());
        }
        let seq = u64::from_be_bytes(body[8..16].try_into().unwrap());
        let epoch = u64::from_be_bytes(body[16..24].try_into().unwrap());
        let first_chunk = u32::from_be_bytes(body[24..28].try_into().unwrap());
        let chunks = u32::from_be_bytes(body[28..32].try_into().unwrap());
        if seq == 0 || epoch == 0 || first_chunk == 0 || chunks == 0 {
            return Err("root field zero".into());
        }
        if first_chunk.checked_add(chunks).is_none() {
            return Err("root extent exceeds chunk id space".into());
        }
        if seq & 1 != slot as u64 {
            return Err(format!("root seq {seq} found in slot {slot}"));
        }
        Ok(Some(Self {
            seq,
            epoch,
            extent: Extent {
                first_chunk,
                chunks,
            },
        }))
    }
}

/// A blob's sparse chunk map as recorded on disk: `(slot, chunk)` pairs for mapped slots.
pub(super) type Mappings = Vec<(u32, u32)>;

/// One self-contained journal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Record {
    /// A blob row. Live creation writes an empty blob; checkpoint snapshots write the full
    /// row. `id` must be greater than every id previously seen in the epoch.
    Create {
        id: u64,
        version: u16,
        name: Vec<u8>,
        len: u64,
        mappings: Mappings,
    },
    /// Drops a row. Its chunks become free once this record's batch is durable.
    Delete { id: u64 },
    /// One sync's staged state. Replay first truncates the blob to `trunc_floor`: slots
    /// wholly beyond the floor are unmapped, and a mapped slot straddling it is unmapped
    /// only when this record carries its replacement (a shrink that keeps part of a
    /// boundary chunk copies the kept prefix into a fresh chunk and remaps). Then `len`
    /// is set and `mappings` applied. `trunc_floor` is the minimum staged length since
    /// the blob's last record: journaling the length trajectory's floor (not just its
    /// endpoint) is what keeps replay from resurrecting chunks that a staged shrink
    /// unmapped before later writes re-extended the blob.
    Update {
        id: u64,
        trunc_floor: u64,
        len: u64,
        mappings: Mappings,
    },
}

const TYPE_CREATE: u8 = 1;
const TYPE_DELETE: u8 = 2;
const TYPE_UPDATE: u8 = 3;

/// The outcome of decoding one frame from the journal.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Frame {
    /// A valid record and the total bytes it consumed (frame included).
    Record(Record, usize),
    /// End of the log: leading zero, a frame that does not fit, or a checksum mismatch.
    /// Everything a torn batch tail can look like.
    End,
    /// A checksummed frame whose body is malformed. Torn writes cannot produce this; the
    /// volume must refuse to open rather than silently drop records.
    Corrupt(String),
}

impl Record {
    /// Appends this record's frame (under `epoch`'s checksum salt) to `out`.
    pub fn encode(&self, epoch: u64, out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(self.body_size());
        match self {
            Self::Create {
                id,
                version,
                name,
                len,
                mappings,
            } => {
                body.push(TYPE_CREATE);
                UInt(*id).write(&mut body);
                body.extend_from_slice(&version.to_be_bytes());
                UInt(name.len() as u32).write(&mut body);
                body.extend_from_slice(name);
                UInt(*len).write(&mut body);
                write_mappings(mappings, &mut body);
            }
            Self::Delete { id } => {
                body.push(TYPE_DELETE);
                UInt(*id).write(&mut body);
            }
            Self::Update {
                id,
                trunc_floor,
                len,
                mappings,
            } => {
                body.push(TYPE_UPDATE);
                UInt(*id).write(&mut body);
                UInt(*trunc_floor).write(&mut body);
                UInt(*len).write(&mut body);
                write_mappings(mappings, &mut body);
            }
        }
        debug_assert_eq!(body.len(), self.body_size());
        UInt(body.len() as u32).write(out);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc(RECORD_DOMAIN, &epoch.to_be_bytes(), &body));
    }

    /// Size of this record's body (the frame adds a length varint and a 4-byte checksum).
    fn body_size(&self) -> usize {
        1 + match self {
            Self::Create {
                id,
                name,
                len,
                mappings,
                ..
            } => {
                UInt(*id).encode_size()
                    + 2
                    + UInt(name.len() as u32).encode_size()
                    + name.len()
                    + UInt(*len).encode_size()
                    + mappings_size(mappings)
            }
            Self::Delete { id } => UInt(*id).encode_size(),
            Self::Update {
                id,
                trunc_floor,
                len,
                mappings,
            } => {
                UInt(*id).encode_size()
                    + UInt(*trunc_floor).encode_size()
                    + UInt(*len).encode_size()
                    + mappings_size(mappings)
            }
        }
    }

    /// Decodes one frame from the start of `buf` (the unread remainder of the extent).
    pub fn decode(buf: &[u8], epoch: u64) -> Frame {
        // A leading zero is the exact end-of-log marker (the extent was durably zeroed
        // before first use, and no frame starts with a zero length byte).
        if buf.is_empty() || buf[0] == 0 {
            return Frame::End;
        }
        let mut cursor = buf;
        let Ok(len) = UInt::<u32>::read(&mut cursor) else {
            return Frame::End;
        };
        // Widened arithmetic: on 32-bit targets a hostile length near u32::MAX must not
        // overflow into a passing bounds check. Lengths beyond what the writer can
        // produce read as a torn tail (End, not Corrupt): a torn length prefix is
        // arbitrary bytes, and callers bound how far they will fetch to satisfy one.
        let len = u32::from(len);
        if len > MAX_RECORD_LEN || u64::from(len) + 4 > cursor.remaining() as u64 {
            return Frame::End;
        }
        let len = len as usize;
        let body = &cursor[..len];
        let sum = &cursor[len..len + 4];
        if crc(RECORD_DOMAIN, &epoch.to_be_bytes(), body) != sum {
            return Frame::End;
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
                let version = u16::read(&mut body).map_err(|e| e.to_string())?;
                let name_len = UInt::<u32>::read(&mut body).map_err(|e| e.to_string())?.0 as usize;
                if name_len > MAX_NAME_LEN {
                    return Err(format!("name length {name_len} exceeds {MAX_NAME_LEN}"));
                }
                if name_len > body.remaining() {
                    return Err("name length exceeds body".into());
                }
                let name = body[..name_len].to_vec();
                body.advance(name_len);
                let len = UInt::<u64>::read(&mut body).map_err(|e| e.to_string())?.0;
                let mappings = read_mappings(&mut body)?;
                Self::Create {
                    id,
                    version,
                    name,
                    len,
                    mappings,
                }
            }
            TYPE_DELETE => {
                let id = UInt::<u64>::read(&mut body).map_err(|e| e.to_string())?.0;
                Self::Delete { id }
            }
            TYPE_UPDATE => {
                let id = UInt::<u64>::read(&mut body).map_err(|e| e.to_string())?.0;
                let trunc_floor = UInt::<u64>::read(&mut body).map_err(|e| e.to_string())?.0;
                let len = UInt::<u64>::read(&mut body).map_err(|e| e.to_string())?.0;
                if trunc_floor > len {
                    return Err(format!("trunc_floor {trunc_floor} exceeds len {len}"));
                }
                let mappings = read_mappings(&mut body)?;
                Self::Update {
                    id,
                    trunc_floor,
                    len,
                    mappings,
                }
            }
            other => return Err(format!("unknown record type {other}")),
        };
        if body.has_remaining() {
            return Err("trailing bytes in record body".into());
        }
        Ok(record)
    }
}

fn mappings_size(mappings: &Mappings) -> usize {
    UInt(mappings.len() as u32).encode_size()
        + mappings
            .iter()
            .map(|(slot, chunk)| UInt(*slot).encode_size() + UInt(*chunk).encode_size())
            .sum::<usize>()
}

fn write_mappings(mappings: &Mappings, out: &mut Vec<u8>) {
    UInt(mappings.len() as u32).write(out);
    for (slot, chunk) in mappings {
        UInt(*slot).write(out);
        UInt(*chunk).write(out);
    }
}

fn read_mappings(body: &mut &[u8]) -> Result<Mappings, String> {
    let count = UInt::<u32>::read(body)
        .map_err(|e: CodecError| e.to_string())?
        .0 as usize;
    // Each pair takes at least two bytes, so a checksummed count can never exceed this.
    if count > body.remaining() / 2 {
        return Err("mapping count exceeds body".into());
    }
    let mut mappings = Vec::with_capacity(count);
    for _ in 0..count {
        let slot = UInt::<u64>::read(body).map_err(|e| e.to_string())?.0;
        let chunk = UInt::<u64>::read(body).map_err(|e| e.to_string())?.0;
        let slot: u32 = slot
            .try_into()
            .map_err(|_| "slot exceeds u32".to_string())?;
        let chunk: u32 = chunk
            .try_into()
            .map_err(|_| "chunk exceeds u32".to_string())?;
        if chunk == 0 {
            return Err("chunk 0 is reserved".into());
        }
        mappings.push((slot, chunk));
    }
    Ok(mappings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records() -> Vec<Record> {
        vec![
            Record::Create {
                id: 0,
                version: 1,
                name: b"blob".to_vec(),
                len: 0,
                mappings: vec![],
            },
            Record::Create {
                id: 7,
                version: 0,
                name: vec![0xFF; 32],
                len: 5 << 20,
                mappings: vec![(0, 3), (1, 9), (5, 2)],
            },
            Record::Delete { id: 7 },
            Record::Update {
                id: 0,
                trunc_floor: 100,
                len: 4096,
                mappings: vec![(0, 1)],
            },
            Record::Update {
                id: u64::MAX,
                trunc_floor: 0,
                len: 0,
                mappings: vec![],
            },
        ]
    }

    #[test]
    fn superblock_round_trip() {
        let sb = Superblock {
            chunk_size: MIN_CHUNK_SIZE,
        };
        let page = sb.encode();
        assert_eq!(page.len(), PAGE);
        assert_eq!(Superblock::decode(&page).unwrap(), Some(sb));
    }

    #[test]
    fn superblock_torn_is_none() {
        let sb = Superblock {
            chunk_size: 1 << 20,
        };
        let mut page = sb.encode();
        // Any bit flip breaks the checksum, which reads as "never created".
        page[3] ^= 1;
        assert_eq!(Superblock::decode(&page).unwrap(), None);
        assert_eq!(Superblock::decode(&[0u8; PAGE]).unwrap(), None);
    }

    #[test]
    fn superblock_bad_padding_is_corrupt() {
        let sb = Superblock {
            chunk_size: 1 << 20,
        };
        let mut page = sb.encode();
        page[PAGE - 1] = 0xAB;
        assert!(Superblock::decode(&page).is_err());
    }

    #[test]
    fn superblock_bad_geometry_is_corrupt() {
        // A checksummed page with an out-of-range or non-power-of-two chunk size was not
        // written by this code.
        for chunk_size in [0u32, 4096, MIN_CHUNK_SIZE + 1, MAX_CHUNK_SIZE * 2] {
            let mut page = Vec::with_capacity(PAGE);
            page.extend_from_slice(SUPERBLOCK_MAGIC);
            page.extend_from_slice(&chunk_size.to_be_bytes());
            let crc = crc(SUPERBLOCK_DOMAIN, &[], &page);
            page.extend_from_slice(&crc);
            page.resize(PAGE, 0);
            assert!(Superblock::decode(&page).is_err(), "{chunk_size}");
        }
    }

    #[test]
    fn root_round_trip() {
        let root = Root {
            seq: 2,
            epoch: 1,
            extent: Extent {
                first_chunk: 1,
                chunks: 4,
            },
        };
        let page = root.encode();
        assert_eq!(Root::decode(&page, 0).unwrap(), Some(root));
    }

    #[test]
    fn root_torn_is_none() {
        let root = Root {
            seq: 3,
            epoch: 2,
            extent: Extent {
                first_chunk: 5,
                chunks: 1,
            },
        };
        let mut page = root.encode();
        page[20] ^= 0x80;
        assert_eq!(Root::decode(&page, 1).unwrap(), None);
        assert_eq!(Root::decode(&[0u8; PAGE], 1).unwrap(), None);
    }

    #[test]
    fn root_wrong_slot_is_corrupt() {
        let root = Root {
            seq: 3,
            epoch: 2,
            extent: Extent {
                first_chunk: 5,
                chunks: 1,
            },
        };
        let page = root.encode();
        assert!(Root::decode(&page, 0).is_err());
    }

    #[test]
    fn root_zero_fields_are_corrupt() {
        for (seq, epoch, first_chunk, chunks) in [
            (0u64, 1u64, 1u32, 1u32),
            (2, 0, 1, 1),
            (2, 1, 0, 1),
            (2, 1, 1, 0),
        ] {
            let root = Root {
                seq,
                epoch,
                extent: Extent {
                    first_chunk,
                    chunks,
                },
            };
            let page = root.encode();
            assert!(Root::decode(&page, (seq & 1) as usize).is_err());
        }
    }

    #[test]
    fn record_round_trip() {
        let epoch = 42;
        let mut log = Vec::new();
        for record in sample_records() {
            record.encode(epoch, &mut log);
        }
        // Terminate with zeroed extent tail.
        log.resize(log.len() + 64, 0);

        let mut buf = log.as_slice();
        let mut decoded = Vec::new();
        loop {
            match Record::decode(buf, epoch) {
                Frame::Record(record, consumed) => {
                    decoded.push(record);
                    buf = &buf[consumed..];
                }
                Frame::End => break,
                Frame::Corrupt(reason) => panic!("unexpected corruption: {reason}"),
            }
        }
        assert_eq!(decoded, sample_records());
    }

    #[test]
    fn record_torn_tail_is_end() {
        let epoch = 1;
        let mut log = Vec::new();
        Record::Delete { id: 9 }.encode(epoch, &mut log);

        // Any strict prefix of the frame reads as end-of-log.
        for cut in 0..log.len() {
            let mut torn = log[..cut].to_vec();
            torn.resize(log.len() + 16, 0);
            assert_eq!(Record::decode(&torn, epoch), Frame::End, "cut={cut}");
        }

        // A bit flip anywhere in the frame reads as end-of-log (checksum mismatch), except
        // in the length prefix where it may leave the frame short of its checksum.
        for bit in 0..log.len() * 8 {
            let mut flipped = log.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            flipped.resize(log.len() + 16, 0);
            assert!(
                matches!(Record::decode(&flipped, epoch), Frame::End),
                "bit={bit}"
            );
        }
    }

    #[test]
    fn record_wrong_epoch_is_end() {
        let mut log = Vec::new();
        Record::Delete { id: 9 }.encode(7, &mut log);
        assert!(matches!(Record::decode(&log, 8), Frame::End));
    }

    #[test]
    fn record_corruption_is_not_end() {
        let epoch = 3u64;

        // Unknown type byte under a valid checksum.
        let body = vec![9u8];
        let mut log = Vec::new();
        UInt(body.len() as u32).write(&mut log);
        log.extend_from_slice(&body);
        log.extend_from_slice(&crc(RECORD_DOMAIN, &epoch.to_be_bytes(), &body));
        assert!(matches!(Record::decode(&log, epoch), Frame::Corrupt(_)));

        // trunc_floor above len under a valid checksum.
        let mut body = vec![TYPE_UPDATE];
        UInt(1u64).write(&mut body);
        UInt(10u64).write(&mut body);
        UInt(5u64).write(&mut body);
        UInt(0u32).write(&mut body);
        let mut log = Vec::new();
        UInt(body.len() as u32).write(&mut log);
        log.extend_from_slice(&body);
        log.extend_from_slice(&crc(RECORD_DOMAIN, &epoch.to_be_bytes(), &body));
        assert!(matches!(Record::decode(&log, epoch), Frame::Corrupt(_)));

        // Reserved chunk 0 in a mapping under a valid checksum.
        let mut body = vec![TYPE_UPDATE];
        UInt(1u64).write(&mut body);
        UInt(0u64).write(&mut body);
        UInt(100u64).write(&mut body);
        UInt(1u32).write(&mut body);
        UInt(0u64).write(&mut body);
        UInt(0u64).write(&mut body);
        let mut log = Vec::new();
        UInt(body.len() as u32).write(&mut log);
        log.extend_from_slice(&body);
        log.extend_from_slice(&crc(RECORD_DOMAIN, &epoch.to_be_bytes(), &body));
        assert!(matches!(Record::decode(&log, epoch), Frame::Corrupt(_)));

        // Trailing garbage inside a checksummed body.
        let mut body = Vec::new();
        Record::Delete { id: 1 }.encode(epoch, &mut body);
        let mut inner = body[1..body.len() - 4].to_vec();
        inner.push(0xEE);
        let mut log = Vec::new();
        UInt(inner.len() as u32).write(&mut log);
        log.extend_from_slice(&inner);
        log.extend_from_slice(&crc(RECORD_DOMAIN, &epoch.to_be_bytes(), &inner));
        assert!(matches!(Record::decode(&log, epoch), Frame::Corrupt(_)));
    }

    #[test]
    fn extent_arithmetic() {
        let extent = Extent {
            first_chunk: 3,
            chunks: 2,
        };
        let chunk_size = MIN_CHUNK_SIZE;
        assert_eq!(extent.offset(chunk_size), 3 * u64::from(chunk_size));
        assert_eq!(extent.len(chunk_size), 2 * u64::from(chunk_size));
        assert_eq!(extent.end(chunk_size), 5 * u64::from(chunk_size));
    }
}
