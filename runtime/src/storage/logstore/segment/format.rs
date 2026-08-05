// Some format helpers are exercised only under cfg(test) and the fuzz
// feature, so non-test lib builds see them as dead.
#![allow(dead_code)]
//! On-disk format of one family: the manifest and its segments.
//!
//! ```text
//! manifest                              segment-NNNNNN
//! +-------------+ 0                     +-------------+ 0
//! | header      | identity, algorithm   | header      | identity, segment
//! +-------------+ 4096                  |             | seq, algorithm
//! | root slot 0 | the root with seq s   +-------------+ 4096
//! +-------------+ 8192  lives in slot   | records     | one envelope each
//! | root slot 1 |       s & 1           | ...         |
//! +-------------+ 12288                 | zero/torn   |
//!                                       +-------------+ EOF
//! ```
//!
//! Every record shares one outer envelope -- length, kind, body, checksum --
//! so tail decoding is uniform. Four kinds, all frozen now:
//! [Record::TransactionFrame] (the only kind Phase 1 produces; one frame = one
//! atomic transaction, data and commit decision together),
//! [Record::CheckpointChunk] and [Record::CheckpointEnd] (produced from
//! Phase 2), and [Record::RelocatedExtent] (produced by Phase 3 cleaning).
//!
//! **Checkpoints.** A checkpoint is a run of bounded [CheckpointChunk]s
//! terminated by one [CheckpointEnd] carrying the counts and an
//! order-sensitive completeness hash over all chunks; verifying that hash is
//! load-bearing, since chunk order, duplication, and omission within an
//! attempt are otherwise unbound. [Checkpoint::new] is the second validating
//! funnel (parallel to [ValidatedTxn]): production code encodes chunks and
//! ends only through it, so encoding is infallible. Within the byte range a
//! durable root locates, any tear, clean end, or leftover byte is hard
//! corruption, never a fallback -- publication order (checkpoint durable
//! before root) proves the checkpoint was complete.
//!
//! **Identity binding (load-bearing).** Checksums are CRC32C, domain-separated
//! and salted by family incarnation + epoch ([Salt]). A record checksum
//! additionally binds the segment sequence, the record kind, and the record's
//! relevant sequence (transaction sequence for frames, checkpoint sequence for
//! checkpoint records), so copied bytes or stale segment content can never
//! validate in the wrong family, segment, stream, or attempt. Payload block
//! checksums bind (log id, log offset), so a correct block served to the wrong
//! log or place fails verification. One algorithm-identifier byte in the
//! manifest and segment headers reserves a future swap to a keyed digest.
//! Per-block checksums defend misdirected reads and media rot; they
//! deliberately do NOT distinguish content eras at the same log and offset -- a
//! rewind followed by a reappend leaves both eras on disk with valid
//! checksums. Stale-era revival is defended by the cleaner's design and crash
//! enumeration, not by checksums; this is a decided trade, not an omission.
//!
//! Decoding one record has four outcomes ([Decoded]): a valid record; a clean
//! end; a torn tail (a write started and did not complete, including every
//! checksum failure); or corruption (a checksum that passes over a malformed
//! body, which tearing cannot produce and is always a hard error). Replay
//! stops at the first torn record and ignores every later byte, even a
//! structurally complete record. Decode limits are checked before any
//! allocation, so a compact hostile record cannot expand into unbounded
//! memory.
//!
//! **Replay obligations.** The four-outcome taxonomy relies on three
//! invariants the caller upholds: (1) the expected [TxnSeq] is sourced from a
//! durable root and strictly incremented; (2) active-tail truncation is
//! durable before appends resume; (3) replay that ends before
//! `root.next_txn - 1` is a hard corruption error, not a clean stop --
//! `next_txn` is the anti-truncation watermark.
//!
//! The root page is fixed-size and family-global. Slot selection is by root
//! validity alone: a root whose own checksum fails falls back to the other
//! slot; a valid root naming a bad checkpoint is a hard error (see [Root]).
//! The root also carries the checksum epoch: a salt component must have a
//! durable home, so this deliberately extends the plan's root field list.
//! The epoch policy is decided: pinned at 0 permanently for this backend,
//! since immutable identity-bound segments leave nothing for a salt advance
//! to fence off.
//!
//! A frame can only be encoded from a [ValidatedTxn], whose validating
//! constructor is the only way in: encoding is infallible, and replay decodes
//! frames back into the same type the live commit path applies.

use crate::Error;
use bytes::Buf;
use commonware_codec::{ReadExt as _, Write as _, varint::UInt};
use commonware_cryptography::{Crc32, Hasher as _, Sha256};

/// Size of the manifest header, root, and segment header pages.
pub(super) const PAGE: usize = 4096;

/// Manifest offsets of the two root slots, indexed by `seq & 1`.
pub(super) const ROOT_OFFSETS: [u64; 2] = [PAGE as u64, 2 * PAGE as u64];

/// First record byte of a segment (the header page precedes it).
pub(super) const SEGMENT_RECORDS: SegmentOffset = SegmentOffset(PAGE as u64);

/// Version stamped into every page; bumped only by an incompatible layout
/// change.
const FORMAT_VERSION: u16 = 1;

/// The one checksum algorithm currently defined. The identifier byte exists so
/// a future keyed digest is a version bump, not a format redesign.
const ALGORITHM_CRC32C: u8 = 1;

const MANIFEST_MAGIC: &[u8; 8] = b"CWLOGMF1";
const SEGMENT_MAGIC: &[u8; 8] = b"CWLOGSG1";
const ROOT_MAGIC: &[u8; 8] = b"CWLOGRT1";

const MANIFEST_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_LOGSTORE_MANIFEST";
const SEGMENT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_LOGSTORE_SEGMENT";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_LOGSTORE_ROOT";
const RECORD_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_LOGSTORE_RECORD";
const BLOCK_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_LOGSTORE_BLOCK";

// Frozen transaction bounds (Phase 0 sizing, logstore-sizing.md).

/// Maximum payload bytes one transaction carries: 384 MiB, 2.5x the worst
/// observed commit (a 153.5 MiB qmdb 1M-key ordered seed).
pub(super) const MAX_TRANSACTION_PAYLOAD: u64 = 384 << 20;

/// Maximum operation descriptors in one frame: ~3.4x the worst observed naive
/// mapping (~1,200); the net-state fold emits at most two per touched log, so
/// this cap is slack by construction.
pub(super) const MAX_TRANSACTION_OPS: usize = 4096;

/// Maximum logs one transaction touches: 2.5x the worst observed span (a
/// ~400-log naive marshal gap repair).
pub(super) const MAX_LOGS_TOUCHED: usize = 1024;

/// Maximum log name length in bytes: ~3x the longest observed consumer name
/// (86 bytes).
pub(super) const MAX_LOG_NAME_LEN: usize = 256;

// Independent hostile-input decode limits, checked before any allocation.

/// Maximum bytes in one checksummed payload block, so verifying a small random
/// read never hashes more than this.
pub(super) const MAX_BLOCK_BYTES: usize = 64 << 10;

/// Maximum payload blocks in one frame: a maximal payload in maximal blocks
/// plus one partial tail block per touched log.
pub(super) const MAX_PAYLOAD_BLOCKS: usize =
    (MAX_TRANSACTION_PAYLOAD / MAX_BLOCK_BYTES as u64) as usize + MAX_LOGS_TOUCHED;

/// Maximum extent-map entries one record may carry: matches
/// [MAX_PAYLOAD_BLOCKS], since cleaning cannot fragment below block
/// granularity.
pub(super) const MAX_EXTENT_DELTAS: usize = MAX_PAYLOAD_BLOCKS;

/// Maximum committed logs one checkpoint (and so one family) may hold: ~2x a
/// naive one-file-one-log mapping of the largest observed family
/// (logstore-sizing.md). Also the per-chunk decode bound.
pub(super) const MAX_CHECKPOINT_LOGS: usize = 1 << 20;

/// Maximum referenced segments one checkpoint may claim: 256 TiB at the
/// 256 MiB Phase 3 segment target. Also the per-chunk decode bound.
pub(super) const MAX_CHECKPOINT_SEGMENTS: usize = 1 << 20;

/// Maximum extents one checkpoint (and so one family) may hold: 1 << 23
/// extents of maximal 64 KiB blocks is 512 GiB of committed payload, ample
/// for a Phase 2 single-segment family, while a saturated checkpoint still
/// fits [MAX_CHECKPOINT_BYTES] (const-asserted with the chunk constants).
/// Admission fails closed at this cap until Phase 3 cleaning bounds
/// fragmentation.
pub(super) const MAX_CHECKPOINT_EXTENTS: usize = 1 << 23;

/// Maximum encoded bytes of one checkpoint, bounding what recovery reads from
/// a locator: every cap above saturated encodes to under 800 MiB
/// (const-asserted from the worst-case encodings by the chunk constants), so
/// 1 GiB is unreachable by an honest store and a larger claim is damage.
pub(super) const MAX_CHECKPOINT_BYTES: u64 = 1 << 30;

/// Maximum memory one decoded record may reserve: the payload cap plus 64 MiB
/// of headroom for every descriptor and name table at its own cap (~50x their
/// worst case).
pub(super) const MAX_DECODED_BYTES: usize = (MAX_TRANSACTION_PAYLOAD as usize) + (64 << 20);

/// Maximum encoded record length: the payload cap plus 16 MiB of framing
/// (descriptors reach ~1.3 MiB with every cap saturated); a longer length
/// prefix is a torn tail or hostile bytes.
pub(super) const MAX_RECORD_BYTES: u64 = MAX_TRANSACTION_PAYLOAD + (16 << 20);

/// Maximum I/O slices in one vectored frame write: two per payload block
/// (framing may split caller buffers) plus fixed envelope slices, rounded up.
pub(super) const MAX_IOVECS: usize = 16384;

const _: () = assert!(2 * MAX_PAYLOAD_BLOCKS < MAX_IOVECS);
const _: () = assert!(MAX_RECORD_BYTES as usize <= MAX_DECODED_BYTES);

/// One kind byte plus seven attribute bytes, reserved per log in create
/// descriptors and catalog rows; all zero until a later phase assigns meaning.
const RESERVED_LOG_BYTES: [u8; 8] = [0; 8];

/// A log's permanent identity within its family; never reused, even when a
/// removed name is recreated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LogId(pub u64);

impl LogId {
    /// The id minted after this one.
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// The family-wide monotonic sequence of one committed transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct TxnSeq(pub u64);

impl TxnSeq {
    /// The sequence following this one.
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// The monotonic sequence of one segment file of a family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SegmentSeq(pub u64);

/// The monotonic sequence of one checkpoint attempt of a family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CheckpointSeq(pub u64);

/// A byte offset in a log's logical space (what readers address).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LogOffset(pub u64);

/// A byte offset in a segment file (where bytes physically live). Distinct
/// from [LogOffset] so confusing the two is a type error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SegmentOffset(pub u64);

/// A family's persistent identity: minted at creation, changed only by
/// destroy-then-recreate, and bound into every checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Incarnation(pub [u8; 16]);

/// The checksum salt binding records and blocks to one family incarnation and
/// one epoch. Both components have durable homes -- the manifest header's
/// incarnation and the governing root's epoch fully determine every record's
/// salt -- so recovery can always reconstruct it.
#[derive(Clone, Copy)]
pub(super) struct Salt {
    bytes: [u8; 24],
    epoch: u64,
}

impl Salt {
    /// Builds the salt for `epoch` of the family identified by `incarnation`.
    pub fn new(incarnation: &Incarnation, epoch: u64) -> Self {
        let mut bytes = [0u8; 24];
        bytes[..16].copy_from_slice(&incarnation.0);
        bytes[16..].copy_from_slice(&epoch.to_be_bytes());
        Self { bytes, epoch }
    }

    /// The epoch this salt binds.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// What every record checksum in one segment binds besides the record's own
/// bytes; the record kind and its relevant sequence complete the binding per
/// record.
pub(super) struct Identity {
    pub salt: Salt,
    pub segment: SegmentSeq,
}

/// Returns `body`'s checksum bound to `domain`, `salt`, and `ctx`.
fn crc(domain: &[u8], salt: &[u8], ctx: &[u8], body: &[u8]) -> [u8; 4] {
    Crc32::hash(&[domain, salt, ctx, body]).0
}

/// Returns a record body's checksum under its full identity.
fn record_crc(ident: &Identity, kind: u8, seq: u64, body: &[u8]) -> [u8; 4] {
    let mut ctx = [0u8; 17];
    ctx[..8].copy_from_slice(&ident.segment.0.to_be_bytes());
    ctx[8] = kind;
    ctx[9..].copy_from_slice(&seq.to_be_bytes());
    crc(RECORD_DOMAIN, &ident.salt.bytes, &ctx, body)
}

/// Returns one payload block's checksum, bound to the log and logical offset
/// it serves. Random reads verify blocks with this alone, never the envelope.
pub(super) fn block_crc(salt: &Salt, log: LogId, at: LogOffset, block: &[u8]) -> [u8; 4] {
    let mut ctx = [0u8; 16];
    ctx[..8].copy_from_slice(&log.0.to_be_bytes());
    ctx[8..].copy_from_slice(&at.0.to_be_bytes());
    crc(BLOCK_DOMAIN, &salt.bytes, &ctx, block)
}

/// Validates that every byte of `page` beyond `used` is zero.
fn padding_is_zero(page: &[u8], used: usize) -> bool {
    page[used..].iter().all(|&b| b == 0)
}

/// Reads a big-endian u64 at `at`.
fn be64(page: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(page[at..at + 8].try_into().unwrap())
}

// Shared header layout: magic, version, algorithm, incarnation.
const HEADER_VERSION: usize = 8;
const HEADER_ALGORITHM: usize = 10;
const HEADER_INCARNATION: usize = 11;
const MANIFEST_BODY: usize = 27;
const SEGMENT_HEADER_SEQ: usize = 27;
const SEGMENT_BODY: usize = 35;

const _: () = assert!(MANIFEST_BODY + 4 <= PAGE);
const _: () = assert!(SEGMENT_BODY + 4 <= PAGE);

/// Writes the layout shared by both header pages.
fn write_header(page: &mut [u8], magic: &[u8; 8], incarnation: &Incarnation) {
    page[..8].copy_from_slice(magic);
    page[HEADER_VERSION..HEADER_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    page[HEADER_ALGORITHM] = ALGORITHM_CRC32C;
    page[HEADER_INCARNATION..HEADER_INCARNATION + 16].copy_from_slice(&incarnation.0);
}

/// Validates the layout shared by both header pages, returning the stored
/// incarnation.
fn check_header(body: &[u8], magic: &[u8; 8]) -> Result<Incarnation, String> {
    if &body[..8] != magic {
        return Err("header magic mismatch".into());
    }
    if body[HEADER_VERSION..HEADER_VERSION + 2] != FORMAT_VERSION.to_be_bytes() {
        return Err("unknown format version".into());
    }
    if body[HEADER_ALGORITHM] != ALGORITHM_CRC32C {
        return Err("unsupported checksum algorithm".into());
    }
    Ok(Incarnation(
        body[HEADER_INCARNATION..HEADER_INCARNATION + 16]
            .try_into()
            .unwrap(),
    ))
}

/// The manifest's first page: the family's immutable identity and checksum
/// algorithm. Manifests are staged and renamed into place, so a visible page
/// that does not validate is damage, never a crash artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ManifestHeader {
    pub incarnation: Incarnation,
}

impl ManifestHeader {
    /// Encodes the header as a full page.
    pub fn encode(&self) -> Vec<u8> {
        let mut page = vec![0u8; PAGE];
        write_header(&mut page, MANIFEST_MAGIC, &self.incarnation);
        let sum = crc(MANIFEST_DOMAIN, &[], &[], &page[..MANIFEST_BODY]);
        page[MANIFEST_BODY..MANIFEST_BODY + 4].copy_from_slice(&sum);
        page
    }

    /// Decodes and validates a header page. Any failure is damage.
    pub fn decode(page: &[u8]) -> Result<Self, String> {
        if page.len() != PAGE {
            return Err("header is not a full page".into());
        }
        let body = &page[..MANIFEST_BODY];
        if crc(MANIFEST_DOMAIN, &[], &[], body) != page[MANIFEST_BODY..MANIFEST_BODY + 4] {
            return Err("header checksum mismatch".into());
        }
        let incarnation = check_header(body, MANIFEST_MAGIC)?;
        if !padding_is_zero(page, MANIFEST_BODY + 4) {
            return Err("header padding is not zero".into());
        }
        Ok(Self { incarnation })
    }
}

/// A segment's first page: immutable, binding the family identity, this
/// segment's sequence, and the checksum algorithm. Segments become visible
/// complete (staging rename), so a visible header that does not validate is
/// damage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SegmentHeader {
    pub incarnation: Incarnation,
    pub seq: SegmentSeq,
}

impl SegmentHeader {
    /// Encodes the header as a full page.
    pub fn encode(&self) -> Vec<u8> {
        let mut page = vec![0u8; PAGE];
        write_header(&mut page, SEGMENT_MAGIC, &self.incarnation);
        page[SEGMENT_HEADER_SEQ..SEGMENT_HEADER_SEQ + 8].copy_from_slice(&self.seq.0.to_be_bytes());
        let sum = crc(SEGMENT_DOMAIN, &[], &[], &page[..SEGMENT_BODY]);
        page[SEGMENT_BODY..SEGMENT_BODY + 4].copy_from_slice(&sum);
        page
    }

    /// Decodes and validates a header page against the identity the caller
    /// expects; a foreign or misplaced segment is damage.
    pub fn decode(page: &[u8], incarnation: &Incarnation, seq: SegmentSeq) -> Result<Self, String> {
        if page.len() != PAGE {
            return Err("header is not a full page".into());
        }
        let body = &page[..SEGMENT_BODY];
        if crc(SEGMENT_DOMAIN, &[], &[], body) != page[SEGMENT_BODY..SEGMENT_BODY + 4] {
            return Err("header checksum mismatch".into());
        }
        let stored = check_header(body, SEGMENT_MAGIC)?;
        if stored != *incarnation {
            return Err("segment belongs to another incarnation".into());
        }
        if be64(body, SEGMENT_HEADER_SEQ) != seq.0 {
            return Err("segment sequence mismatch".into());
        }
        if !padding_is_zero(page, SEGMENT_BODY + 4) {
            return Err("header padding is not zero".into());
        }
        Ok(Self {
            incarnation: stored,
            seq,
        })
    }
}

// Root page layout (fixed big-endian fields; zero beyond ROOT_BODY + 4).
const ROOT_VERSION: usize = 8;
const ROOT_INCARNATION: usize = 10;
const ROOT_SEQ: usize = 26;
const ROOT_EPOCH: usize = 34;
const ROOT_CHECKPOINT: usize = 42; // presence flag, then the locator fields
const ROOT_ACTIVE: usize = 107;
const ROOT_REPLAY: usize = 115;
const ROOT_REPLAY_AT: usize = 123;
const ROOT_NEXT_LOG: usize = 131;
const ROOT_NEXT_TXN: usize = 139;
const ROOT_BODY: usize = 147;

const _: () = assert!(ROOT_BODY + 4 <= PAGE);

/// Where a complete checkpoint lives and what proves it whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CheckpointLocator {
    pub segment: SegmentSeq,
    pub start: SegmentOffset,
    /// Total encoded bytes of the checkpoint's records.
    pub len: u64,
    pub seq: CheckpointSeq,
    /// Completeness hash over all chunks, restated from the CheckpointEnd.
    pub hash: [u8; 32],
}

/// A fixed-size, family-global root. The root with sequence s lives in
/// manifest slot s & 1, so publishing never touches its predecessor.
///
/// Selection rule (applied by recovery): only a root's OWN checksum picks the
/// slot -- if it fails, fall back to the other slot. A valid root whose named
/// checkpoint is malformed or missing is a hard corruption error, never a
/// fallback: publication order (checkpoint durable before root) means a
/// durable root proves its checkpoint was complete, and falling back would
/// silently roll back acknowledged transactions.
///
/// Phase 1 writes roots with an empty checkpoint locator and replay from the
/// segment start; Phase 2 populates the locator without a format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Root {
    /// Monotonic publication counter; picks the slot.
    pub seq: u64,
    /// Checksum epoch governing every record this root reaches: readers must
    /// salt record decoding with it. Policy decided: pinned at 0 permanently
    /// for this backend (segments are immutable and identity-bound by segment
    /// sequence, so nothing needs a salt advance); the field is the salt
    /// component's durable home until a future format revision needs
    /// otherwise.
    pub epoch: u64,
    pub checkpoint: Option<CheckpointLocator>,
    /// The one segment accepting appends.
    pub active_segment: SegmentSeq,
    /// First transaction sequence recovery must replay.
    pub replay_from: TxnSeq,
    /// Where replay begins in the active segment: the durable tail at the
    /// checkpoint this root names (the segment's first record byte when it
    /// names none), the byte where `replay_from`'s frame will land. Extends
    /// the plan's root field list: without it recovery would re-read the
    /// whole segment to find the checkpoint boundary, defeating bounded
    /// replay.
    pub replay_at: SegmentOffset,
    /// Log id minting floor; ids are never reused.
    pub next_log: LogId,
    /// Transaction sequence minting floor.
    pub next_txn: TxnSeq,
}

impl Root {
    /// Encodes the root as a full page.
    pub fn encode(&self, incarnation: &Incarnation) -> Vec<u8> {
        let mut page = vec![0u8; PAGE];
        page[..8].copy_from_slice(ROOT_MAGIC);
        page[ROOT_VERSION..ROOT_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        page[ROOT_INCARNATION..ROOT_INCARNATION + 16].copy_from_slice(&incarnation.0);
        page[ROOT_SEQ..ROOT_SEQ + 8].copy_from_slice(&self.seq.to_be_bytes());
        page[ROOT_EPOCH..ROOT_EPOCH + 8].copy_from_slice(&self.epoch.to_be_bytes());
        if let Some(checkpoint) = &self.checkpoint {
            page[ROOT_CHECKPOINT] = 1;
            let at = ROOT_CHECKPOINT + 1;
            page[at..at + 8].copy_from_slice(&checkpoint.segment.0.to_be_bytes());
            page[at + 8..at + 16].copy_from_slice(&checkpoint.start.0.to_be_bytes());
            page[at + 16..at + 24].copy_from_slice(&checkpoint.len.to_be_bytes());
            page[at + 24..at + 32].copy_from_slice(&checkpoint.seq.0.to_be_bytes());
            page[at + 32..at + 64].copy_from_slice(&checkpoint.hash);
        }
        page[ROOT_ACTIVE..ROOT_ACTIVE + 8].copy_from_slice(&self.active_segment.0.to_be_bytes());
        page[ROOT_REPLAY..ROOT_REPLAY + 8].copy_from_slice(&self.replay_from.0.to_be_bytes());
        page[ROOT_REPLAY_AT..ROOT_REPLAY_AT + 8].copy_from_slice(&self.replay_at.0.to_be_bytes());
        page[ROOT_NEXT_LOG..ROOT_NEXT_LOG + 8].copy_from_slice(&self.next_log.0.to_be_bytes());
        page[ROOT_NEXT_TXN..ROOT_NEXT_TXN + 8].copy_from_slice(&self.next_txn.0.to_be_bytes());
        let sum = crc(ROOT_DOMAIN, &incarnation.0, &[], &page[..ROOT_BODY]);
        page[ROOT_BODY..ROOT_BODY + 4].copy_from_slice(&sum);
        page
    }

    /// Decodes and validates the root in `slot`.
    ///
    /// Returns `None` for a page that never held a completed root write under
    /// this incarnation (all-zero, torn, or foreign: all checksum failures),
    /// and an error for a page that validates but is malformed, which only
    /// damage can produce.
    pub fn decode(
        page: &[u8],
        incarnation: &Incarnation,
        slot: usize,
    ) -> Result<Option<Self>, String> {
        // A short page never held a completed root write, like a checksum
        // failure.
        if page.len() != PAGE {
            return Ok(None);
        }
        let body = &page[..ROOT_BODY];
        if crc(ROOT_DOMAIN, &incarnation.0, &[], body) != page[ROOT_BODY..ROOT_BODY + 4] {
            return Ok(None);
        }
        if &body[..8] != ROOT_MAGIC {
            return Err("root magic mismatch".into());
        }
        if body[ROOT_VERSION..ROOT_VERSION + 2] != FORMAT_VERSION.to_be_bytes() {
            return Err("unknown format version".into());
        }
        // Defense in depth: redundant with the incarnation-salted checksum.
        if body[ROOT_INCARNATION..ROOT_INCARNATION + 16] != incarnation.0 {
            return Err("root incarnation mismatch".into());
        }
        if !padding_is_zero(page, ROOT_BODY + 4) {
            return Err("root padding is not zero".into());
        }
        let seq = be64(body, ROOT_SEQ);
        if seq & 1 != slot as u64 {
            return Err("root in the wrong slot".into());
        }
        let checkpoint = match body[ROOT_CHECKPOINT] {
            0 => {
                if !padding_is_zero(&body[..ROOT_ACTIVE], ROOT_CHECKPOINT + 1) {
                    return Err("empty checkpoint locator is not zero".into());
                }
                None
            }
            1 => {
                let at = ROOT_CHECKPOINT + 1;
                Some(CheckpointLocator {
                    segment: SegmentSeq(be64(body, at)),
                    start: SegmentOffset(be64(body, at + 8)),
                    len: be64(body, at + 16),
                    seq: CheckpointSeq(be64(body, at + 24)),
                    hash: body[at + 32..at + 64].try_into().unwrap(),
                })
            }
            _ => return Err("invalid checkpoint flag".into()),
        };
        Ok(Some(Self {
            seq,
            epoch: be64(body, ROOT_EPOCH),
            checkpoint,
            active_segment: SegmentSeq(be64(body, ROOT_ACTIVE)),
            replay_from: TxnSeq(be64(body, ROOT_REPLAY)),
            replay_at: SegmentOffset(be64(body, ROOT_REPLAY_AT)),
            next_log: LogId(be64(body, ROOT_NEXT_LOG)),
            next_txn: TxnSeq(be64(body, ROOT_NEXT_TXN)),
        }))
    }
}

/// One log's net effect in a transaction: the pure fold output. Every mix of
/// staged operations reduces to at most one rewind and one contiguous run of
/// appended bytes per log, because appends only ever extend the tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum NetOp {
    /// The log is created, holding `run`.
    Create { name: Vec<u8>, run: Vec<u8> },
    /// An existing log is cut to `rewind_to` (when below `committed`) and/or
    /// extended by `run`. `generation` and `committed` are the pre-transaction
    /// state the transaction was validated against; replay revalidates them.
    Mutate {
        generation: u64,
        committed: u64,
        rewind_to: Option<u64>,
        run: Vec<u8>,
    },
    /// The log is removed.
    Remove { generation: u64, committed: u64 },
}

impl NetOp {
    /// The logical offset where this op's run begins.
    fn anchor(&self) -> u64 {
        match self {
            Self::Create { .. } | Self::Remove { .. } => 0,
            Self::Mutate {
                committed,
                rewind_to,
                ..
            } => rewind_to.unwrap_or(*committed),
        }
    }

    /// The bytes this op appends.
    fn run(&self) -> &[u8] {
        match self {
            Self::Create { run, .. } | Self::Mutate { run, .. } => run,
            Self::Remove { .. } => &[],
        }
    }

    /// How many wire descriptors this op encodes to.
    fn descriptors(&self) -> usize {
        match self {
            Self::Create { run, .. } => 1 + usize::from(!run.is_empty()),
            Self::Mutate { rewind_to, run, .. } => {
                usize::from(rewind_to.is_some()) + usize::from(!run.is_empty())
            }
            Self::Remove { .. } => 1,
        }
    }
}

/// A transaction's validated net state: the only input a frame can be encoded
/// from, and what replay decodes a frame back into, so live commits and
/// recovery apply exactly the same value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ValidatedTxn {
    epoch: u64,
    seq: TxnSeq,
    /// Net ops in canonical order: strictly ascending log id.
    ops: Vec<(LogId, NetOp)>,
}

impl ValidatedTxn {
    /// Validates one transaction's net state. The only constructor, so frame
    /// encoding is infallible.
    pub fn new(epoch: u64, seq: TxnSeq, ops: Vec<(LogId, NetOp)>) -> Result<Self, Error> {
        if ops.len() > MAX_LOGS_TOUCHED {
            return Err(Error::TransactionTooLarge(format!(
                "{} logs touched exceeds {MAX_LOGS_TOUCHED}",
                ops.len()
            )));
        }
        let mut payload: u64 = 0;
        let mut previous: Option<LogId> = None;
        for (log, op) in &ops {
            if previous.is_some_and(|p| p >= *log) {
                return Err(Error::InvalidTransaction(
                    "operations are not in canonical log order".into(),
                ));
            }
            previous = Some(*log);
            match op {
                NetOp::Create { name, .. } => {
                    // Names are arbitrary bytes, empty included; length is the
                    // only rule.
                    if name.len() > MAX_LOG_NAME_LEN {
                        return Err(Error::InvalidTransaction(format!(
                            "log name of {} bytes exceeds {MAX_LOG_NAME_LEN}",
                            name.len()
                        )));
                    }
                }
                NetOp::Mutate {
                    committed,
                    rewind_to,
                    run,
                    ..
                } => {
                    if let Some(to) = rewind_to {
                        if to >= committed {
                            return Err(Error::InvalidTransaction(
                                "rewind is not below the committed length".into(),
                            ));
                        }
                    } else if run.is_empty() {
                        return Err(Error::InvalidTransaction("mutation with no effect".into()));
                    }
                }
                NetOp::Remove { .. } => {}
            }
            let run = op.run().len() as u64;
            if op.anchor().checked_add(run).is_none() {
                return Err(Error::InvalidTransaction(
                    "append overflows the log length".into(),
                ));
            }
            payload = payload
                .checked_add(run)
                .ok_or_else(|| Error::TransactionTooLarge("payload length overflows".into()))?;
        }
        if payload > MAX_TRANSACTION_PAYLOAD {
            return Err(Error::TransactionTooLarge(format!(
                "payload of {payload} bytes exceeds {MAX_TRANSACTION_PAYLOAD}"
            )));
        }
        // The fold emits at most two descriptors per touched log, so the wire
        // cap cannot bind here.
        debug_assert!(
            ops.iter().map(|(_, op)| op.descriptors()).sum::<usize>() <= MAX_TRANSACTION_OPS
        );
        Ok(Self { epoch, seq, ops })
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn seq(&self) -> TxnSeq {
        self.seq
    }

    pub fn ops(&self) -> &[(LogId, NetOp)] {
        &self.ops
    }

    /// Upper bound on this transaction's encoded frame size, cheap enough for
    /// admission to size segments and reserves before encoding. Tracks
    /// [ValidatedTxn::write_body]: every varint at its bound, so it can only
    /// overshoot, never undershoot.
    pub fn frame_bound(&self) -> u64 {
        // Envelope, epoch, sequence, and the two counts.
        let mut bound: u64 = (5 + 1 + 4) + 10 + 10 + 5 + 5;
        for (_, op) in &self.ops {
            // At most two descriptors of a verb byte plus four varints; a
            // create adds its name and reserved bytes.
            bound += 2 * (1 + 4 * 10);
            if let NetOp::Create { name, .. } = op {
                bound += 5 + name.len() as u64 + 8;
            }
            // Each payload block adds a table entry, its bytes, and its
            // checksum.
            let run = op.run().len() as u64;
            bound += run + run.div_ceil(MAX_BLOCK_BYTES as u64) * (10 + 10 + 5 + 4);
        }
        bound
    }

    /// Logs with bytes to write: (log, anchor, run) in operation order.
    fn runs(&self) -> impl Iterator<Item = (LogId, u64, &[u8])> {
        self.ops.iter().filter_map(|(log, op)| {
            let run = op.run();
            (!run.is_empty()).then_some((*log, op.anchor(), run))
        })
    }

    /// Payload blocks in wire order: (log, logical offset, bytes).
    fn blocks(&self) -> impl Iterator<Item = (LogId, LogOffset, &[u8])> {
        self.runs().flat_map(|(log, anchor, run)| {
            run.chunks(MAX_BLOCK_BYTES)
                .enumerate()
                .map(move |(i, block)| {
                    (log, LogOffset(anchor + (i * MAX_BLOCK_BYTES) as u64), block)
                })
        })
    }

    /// Locates each payload block inside this frame's encoding; `encoded_len`
    /// must be the exact length [Record::encode] appends for this frame.
    ///
    /// Derived from the same block iterator as [ValidatedTxn::write_body] plus
    /// the envelope fact that a record ends with the payload runs, the
    /// per-block checksums, and the 4-byte record checksum, so the sites can
    /// never diverge from the encoding.
    pub fn block_sites(&self, encoded_len: usize) -> Vec<BlockSite> {
        let blocks: Vec<_> = self.blocks().collect();
        let payload: usize = blocks.iter().map(|(_, _, block)| block.len()).sum();
        let checksums = encoded_len - 4 - 4 * blocks.len();
        let mut next = checksums - payload;
        blocks
            .into_iter()
            .enumerate()
            .map(|(i, (log, at, block))| {
                let payload = next;
                next += block.len();
                BlockSite {
                    log,
                    at,
                    len: block.len() as u64,
                    payload,
                    crc: checksums + 4 * i,
                }
            })
            .collect()
    }

    /// Appends this transaction's complete frame record to `out`: the
    /// committer's entry point, so a frame is only ever encoded from a
    /// validated transaction.
    pub fn encode_frame(&self, ident: &Identity, out: &mut Vec<u8>) {
        debug_assert_eq!(self.epoch, ident.salt.epoch);
        let mut body =
            Vec::with_capacity(64 + self.runs().map(|(_, _, run)| run.len()).sum::<usize>());
        self.write_body(&ident.salt, &mut body);
        write_envelope(out, ident, KIND_TRANSACTION_FRAME, self.seq.0, &body);
    }

    /// Appends this frame's body: epoch, sequence, operation descriptors,
    /// payload block descriptors, payload, per-block checksums.
    fn write_body(&self, salt: &Salt, body: &mut Vec<u8>) {
        UInt(self.epoch).write(body);
        UInt(self.seq.0).write(body);
        let descriptors: usize = self.ops.iter().map(|(_, op)| op.descriptors()).sum();
        UInt(descriptors as u32).write(body);
        for (log, op) in &self.ops {
            match op {
                NetOp::Create { name, run } => {
                    body.push(OP_CREATE);
                    UInt(log.0).write(body);
                    UInt(0u64).write(body);
                    UInt(0u64).write(body);
                    UInt(name.len() as u32).write(body);
                    body.extend_from_slice(name);
                    body.extend_from_slice(&RESERVED_LOG_BYTES);
                    if !run.is_empty() {
                        body.push(OP_APPEND);
                        UInt(log.0).write(body);
                        UInt(0u64).write(body);
                        UInt(0u64).write(body);
                        UInt(run.len() as u64).write(body);
                    }
                }
                NetOp::Mutate {
                    generation,
                    committed,
                    rewind_to,
                    run,
                } => {
                    if let Some(to) = rewind_to {
                        body.push(OP_REWIND);
                        UInt(log.0).write(body);
                        UInt(*generation).write(body);
                        UInt(*committed).write(body);
                        UInt(*to).write(body);
                    }
                    if !run.is_empty() {
                        body.push(OP_APPEND);
                        UInt(log.0).write(body);
                        UInt(*generation).write(body);
                        UInt(*committed).write(body);
                        UInt(run.len() as u64).write(body);
                    }
                }
                NetOp::Remove {
                    generation,
                    committed,
                } => {
                    body.push(OP_REMOVE);
                    UInt(log.0).write(body);
                    UInt(*generation).write(body);
                    UInt(*committed).write(body);
                }
            }
        }
        UInt(self.blocks().count() as u32).write(body);
        for (log, at, block) in self.blocks() {
            UInt(log.0).write(body);
            UInt(at.0).write(body);
            UInt(block.len() as u32).write(body);
        }
        for (_, _, run) in self.runs() {
            body.extend_from_slice(run);
        }
        for (log, at, block) in self.blocks() {
            body.extend_from_slice(&block_crc(salt, log, at, block));
        }
    }
}

/// Where one payload block lives inside a frame's encoding, offsets relative
/// to the record's first byte ([ValidatedTxn::block_sites]).
#[derive(Clone, Copy, Debug)]
pub(super) struct BlockSite {
    /// The log the block belongs to.
    pub log: LogId,
    /// The block's logical offset in that log.
    pub at: LogOffset,
    /// Payload bytes in the block.
    pub len: u64,
    /// Offset of the block's payload.
    pub payload: usize,
    /// Offset of the block's 4-byte checksum.
    pub crc: usize,
}

/// One catalog row of a checkpoint: a log's committed identity and length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CatalogRow {
    pub log: LogId,
    pub generation: u64,
    pub committed: u64,
    pub name: Vec<u8>,
}

/// One extent-map entry of a checkpoint: where one checksummed block of a
/// log's bytes lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExtentRow {
    pub log: LogId,
    pub at: LogOffset,
    pub segment: SegmentSeq,
    /// The block's payload bytes.
    pub start: SegmentOffset,
    pub len: u64,
    /// The block's 4-byte checksum (it lives in a table at its frame's end,
    /// not adjacent to the payload). Without it a restored extent could not be
    /// read-verified short of re-decoding its whole frame.
    pub crc: SegmentOffset,
}

/// One bounded piece of a checkpoint. The checkpoint sequence is bound into
/// the record checksum, not serialized in the body, so a chunk from one
/// attempt can never be accepted inside another's range. Production code
/// encodes chunks only through [Checkpoint::new], the validating funnel; the
/// fields stay public for tests that build hostile streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CheckpointChunk {
    pub seq: CheckpointSeq,
    pub rows: Vec<CatalogRow>,
    pub extents: Vec<ExtentRow>,
    pub segments: Vec<SegmentSeq>,
    /// Minting floors as of this checkpoint.
    pub next_log: LogId,
    pub next_txn: TxnSeq,
}

impl CheckpointChunk {
    fn write_body(&self, body: &mut Vec<u8>) {
        UInt(self.rows.len() as u32).write(body);
        for row in &self.rows {
            UInt(row.log.0).write(body);
            UInt(row.generation).write(body);
            UInt(row.committed).write(body);
            debug_assert!(row.name.len() <= MAX_LOG_NAME_LEN);
            UInt(row.name.len() as u32).write(body);
            body.extend_from_slice(&row.name);
            body.extend_from_slice(&RESERVED_LOG_BYTES);
        }
        debug_assert!(self.extents.len() <= MAX_EXTENT_DELTAS);
        UInt(self.extents.len() as u32).write(body);
        for extent in &self.extents {
            UInt(extent.log.0).write(body);
            UInt(extent.at.0).write(body);
            UInt(extent.segment.0).write(body);
            UInt(extent.start.0).write(body);
            UInt(extent.len).write(body);
            UInt(extent.crc.0).write(body);
        }
        UInt(self.segments.len() as u32).write(body);
        for segment in &self.segments {
            UInt(segment.0).write(body);
        }
        UInt(self.next_log.0).write(body);
        UInt(self.next_txn.0).write(body);
    }
}

/// Terminates a checkpoint: a checkpoint without its end is incomplete. The
/// completeness hash is order-sensitive and its verification is load-bearing:
/// chunk order, duplication, and omission within an attempt are otherwise
/// unbound. Production code encodes ends only through [Checkpoint::new], the
/// validating funnel; the fields stay public for tests that build hostile
/// streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CheckpointEnd {
    pub seq: CheckpointSeq,
    /// Total encoded bytes of the checkpoint's chunk records (the end record
    /// itself excluded: its own size depends on this value).
    pub total_bytes: u64,
    pub rows: u64,
    pub extents: u64,
    pub segments: u64,
    /// Completeness hash over all chunks.
    pub hash: [u8; 32],
}

impl CheckpointEnd {
    fn write_body(&self, body: &mut Vec<u8>) {
        UInt(self.seq.0).write(body);
        UInt(self.total_bytes).write(body);
        UInt(self.rows).write(body);
        UInt(self.extents).write(body);
        UInt(self.segments).write(body);
        body.extend_from_slice(&self.hash);
    }
}

/// Catalog rows one chunk carries at most. With the extent and segment
/// limits below, packing bounds any single chunk record to a few MiB.
const CHUNK_ROWS: usize = 4096;
const CHUNK_EXTENTS: usize = 4096;
const CHUNK_SEGMENTS: usize = 65536;

// Every chunk must decode under the per-record caps, and each family cap must
// exceed its per-chunk packing limit so multi-chunk checkpoints are reachable.
const _: () = assert!(CHUNK_EXTENTS <= MAX_EXTENT_DELTAS);
const _: () = assert!(CHUNK_ROWS < MAX_CHECKPOINT_LOGS);
const _: () = assert!(CHUNK_EXTENTS < MAX_CHECKPOINT_EXTENTS);
const _: () = assert!(CHUNK_SEGMENTS < MAX_CHECKPOINT_SEGMENTS);

// Worst-case encoded sizes (every varint at its 10-byte maximum), proving a
// checkpoint that saturates every cap still fits MAX_CHECKPOINT_BYTES.
const CATALOG_ROW_MAX: u64 = 3 * 10 + 5 + MAX_LOG_NAME_LEN as u64 + 8;
const EXTENT_ROW_MAX: u64 = 6 * 10;
const SEGMENT_REF_MAX: u64 = 10;
/// Envelope (length prefix, kind, checksum) plus the three counts and the
/// two minting floors every chunk carries.
const CHUNK_OVERHEAD_MAX: u64 = (5 + 1 + 4) + 3 * 5 + 2 * 10;
const CHECKPOINT_CHUNKS_MAX: u64 = {
    let rows = (MAX_CHECKPOINT_LOGS as u64).div_ceil(CHUNK_ROWS as u64);
    let extents = (MAX_CHECKPOINT_EXTENTS as u64).div_ceil(CHUNK_EXTENTS as u64);
    let segments = (MAX_CHECKPOINT_SEGMENTS as u64).div_ceil(CHUNK_SEGMENTS as u64);
    let mut max = rows;
    if extents > max {
        max = extents;
    }
    if segments > max {
        max = segments;
    }
    max
};
/// Envelope plus the five counters and the completeness hash.
const CHECKPOINT_END_MAX: u64 = (5 + 1 + 4) + 5 * 10 + 32;
const _: () = assert!(
    MAX_CHECKPOINT_LOGS as u64 * CATALOG_ROW_MAX
        + MAX_CHECKPOINT_EXTENTS as u64 * EXTENT_ROW_MAX
        + MAX_CHECKPOINT_SEGMENTS as u64 * SEGMENT_REF_MAX
        + CHECKPOINT_CHUNKS_MAX * CHUNK_OVERHEAD_MAX
        + CHECKPOINT_END_MAX
        <= MAX_CHECKPOINT_BYTES
);

/// Upper bound on the encoded bytes of a checkpoint holding `logs` catalog
/// rows and `extents` extent rows (each extent conservatively in its own
/// referenced segment), from the same worst-case row constants the
/// [MAX_CHECKPOINT_BYTES] proof uses. Sizes the reserve a cleaner needs to
/// publish a checkpoint at any family fill level.
pub(super) const fn checkpoint_bytes_bound(logs: u64, extents: u64) -> u64 {
    let chunks = logs.div_ceil(CHUNK_ROWS as u64)
        + extents.div_ceil(CHUNK_EXTENTS as u64)
        + extents.div_ceil(CHUNK_SEGMENTS as u64)
        + 1;
    logs * CATALOG_ROW_MAX
        + extents * (EXTENT_ROW_MAX + SEGMENT_REF_MAX)
        + chunks * CHUNK_OVERHEAD_MAX
        + CHECKPOINT_END_MAX
}

/// Upper bound on the encoded bytes of a frame carrying `payload` bytes
/// across `logs` touched logs with names up to `name_len`, from the same
/// write path [ValidatedTxn::write_body] uses (every varint at its bound: a
/// descriptor is a verb byte plus four varints, a create adds its name and
/// reserved bytes, and each payload block adds a table entry and a checksum).
pub(super) const fn frame_bytes_bound(payload: u64, logs: u64, name_len: u64) -> u64 {
    let blocks = payload.div_ceil(MAX_BLOCK_BYTES as u64) + logs;
    let envelope = 5 + 1 + 4;
    let header = 10 + 10 + 5;
    let descriptors = logs * (2 * (1 + 4 * 10) + 5 + name_len + 8);
    let block_table = 5 + blocks * (10 + 10 + 5 + 4);
    envelope + header + descriptors + block_table + payload
}

/// Accumulates the order-sensitive completeness hash: each chunk body framed
/// by its length, so chunk boundaries can never shift or merge unnoticed.
struct CompletenessHash(Sha256);

impl CompletenessHash {
    fn new() -> Self {
        Self(Sha256::default())
    }

    fn chunk(&mut self, body: &[u8]) {
        let mut prefix = Vec::with_capacity(5);
        UInt(body.len() as u32).write(&mut prefix);
        self.0.update(&prefix);
        self.0.update(body);
    }

    fn finish(self) -> [u8; 32] {
        let (_, digest) = self.0.finalize();
        digest.0
    }
}

/// The encoded envelope size of a record with a `body_len`-byte body.
fn envelope_len(body_len: usize) -> u64 {
    let mut prefix = Vec::with_capacity(5);
    UInt(body_len as u32).write(&mut prefix);
    (prefix.len() + 1 + body_len + 4) as u64
}

/// A complete checkpoint: every committed log's catalog row and extent map,
/// the referenced segments, and the minting floors, as bounded chunks
/// terminated by the end that proves them whole.
///
/// [Checkpoint::new] is the only constructor (parallel to [ValidatedTxn]): it
/// validates every cap and computes the completeness hash, so encoding is
/// infallible, and [Checkpoint::decode] verifies the end against the chunks
/// it actually read, returning the same type live checkpointing produced.
#[derive(Debug)]
pub(super) struct Checkpoint {
    chunks: Vec<CheckpointChunk>,
    end: CheckpointEnd,
}

impl Checkpoint {
    /// Validates one checkpoint's contents and packs them into chunks. Rows
    /// must arrive in ascending log order and extents in ascending (log,
    /// offset) order (the semantic loader revalidates both).
    pub fn new(
        seq: CheckpointSeq,
        rows: Vec<CatalogRow>,
        extents: Vec<ExtentRow>,
        segments: Vec<SegmentSeq>,
        next_log: LogId,
        next_txn: TxnSeq,
    ) -> Result<Self, String> {
        if rows.len() > MAX_CHECKPOINT_LOGS {
            return Err(format!("{} rows exceeds {MAX_CHECKPOINT_LOGS}", rows.len()));
        }
        if extents.len() > MAX_CHECKPOINT_EXTENTS {
            return Err(format!(
                "{} extents exceeds {MAX_CHECKPOINT_EXTENTS}",
                extents.len()
            ));
        }
        if segments.len() > MAX_CHECKPOINT_SEGMENTS {
            return Err(format!(
                "{} segments exceeds {MAX_CHECKPOINT_SEGMENTS}",
                segments.len()
            ));
        }
        for row in &rows {
            if row.name.len() > MAX_LOG_NAME_LEN {
                return Err(format!(
                    "log name of {} bytes exceeds {MAX_LOG_NAME_LEN}",
                    row.name.len()
                ));
            }
        }
        let counts = (
            rows.len() as u64,
            extents.len() as u64,
            segments.len() as u64,
        );

        // Slice the categories across chunks in parallel. At least one chunk
        // always exists, so the minting floors are always present and decode
        // can demand agreement across chunks.
        fn slice<T: Clone>(source: &[T], i: usize, per: usize) -> Vec<T> {
            let start = (i * per).min(source.len());
            let end = ((i + 1) * per).min(source.len());
            source[start..end].to_vec()
        }
        let needed = [
            rows.len().div_ceil(CHUNK_ROWS),
            extents.len().div_ceil(CHUNK_EXTENTS),
            segments.len().div_ceil(CHUNK_SEGMENTS),
            1,
        ]
        .into_iter()
        .max()
        .unwrap();
        let chunks: Vec<CheckpointChunk> = (0..needed)
            .map(|i| CheckpointChunk {
                seq,
                rows: slice(&rows, i, CHUNK_ROWS),
                extents: slice(&extents, i, CHUNK_EXTENTS),
                segments: slice(&segments, i, CHUNK_SEGMENTS),
                next_log,
                next_txn,
            })
            .collect();

        let mut hash = CompletenessHash::new();
        let mut total_bytes = 0u64;
        let mut body = Vec::new();
        for chunk in &chunks {
            body.clear();
            chunk.write_body(&mut body);
            hash.chunk(&body);
            total_bytes += envelope_len(body.len());
        }
        let end = CheckpointEnd {
            seq,
            total_bytes,
            rows: counts.0,
            extents: counts.1,
            segments: counts.2,
            hash: hash.finish(),
        };
        Ok(Self { chunks, end })
    }

    /// Appends the checkpoint's records -- every chunk, then the end -- to
    /// `out`.
    pub fn encode(&self, ident: &Identity, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        for chunk in &self.chunks {
            body.clear();
            chunk.write_body(&mut body);
            write_envelope(out, ident, KIND_CHECKPOINT_CHUNK, self.end.seq.0, &body);
        }
        body.clear();
        self.end.write_body(&mut body);
        write_envelope(out, ident, KIND_CHECKPOINT_END, self.end.seq.0, &body);
    }

    /// Decodes and verifies a complete checkpoint from exactly the bytes its
    /// locator names. Within a located range every tear, clean end, cap
    /// breach, or leftover byte is hard corruption, never a fallback: a valid
    /// root proves its checkpoint was durably complete before the root was
    /// published. The end's counts and completeness hash are verified against
    /// the chunks actually read, so a reordered, duplicated, or omitted chunk
    /// cannot pass.
    pub fn decode(buf: &[u8], ident: &Identity, seq: CheckpointSeq) -> Result<Self, String> {
        let expect = Expect::Checkpoint(seq);
        let mut chunks: Vec<CheckpointChunk> = Vec::new();
        let mut hash = CompletenessHash::new();
        let (mut rows, mut extents, mut segments) = (0u64, 0u64, 0u64);
        let mut chunk_bytes = 0u64;
        let mut body = Vec::new();
        let mut pos = 0;
        loop {
            if pos == buf.len() {
                return Err("checkpoint ends without its end record".into());
            }
            match Record::decode(&buf[pos..], ident, expect) {
                Decoded::Record(Record::CheckpointChunk(chunk), consumed) => {
                    rows += chunk.rows.len() as u64;
                    extents += chunk.extents.len() as u64;
                    segments += chunk.segments.len() as u64;
                    if rows > MAX_CHECKPOINT_LOGS as u64
                        || extents > MAX_CHECKPOINT_EXTENTS as u64
                        || segments > MAX_CHECKPOINT_SEGMENTS as u64
                    {
                        return Err("checkpoint exceeds its caps".into());
                    }
                    if let Some(first) = chunks.first()
                        && (first.next_log != chunk.next_log || first.next_txn != chunk.next_txn)
                    {
                        return Err("checkpoint chunks disagree on the minting floors".into());
                    }
                    body.clear();
                    chunk.write_body(&mut body);
                    hash.chunk(&body);
                    chunk_bytes += consumed as u64;
                    pos += consumed;
                    chunks.push(chunk);
                }
                Decoded::Record(Record::CheckpointEnd(end), consumed) => {
                    pos += consumed;
                    if pos != buf.len() {
                        return Err("bytes after the checkpoint end".into());
                    }
                    if chunks.is_empty() {
                        return Err("checkpoint has no chunks".into());
                    }
                    if end.total_bytes != chunk_bytes
                        || end.rows != rows
                        || end.extents != extents
                        || end.segments != segments
                    {
                        return Err("checkpoint end counts do not match its chunks".into());
                    }
                    if end.hash != hash.finish() {
                        return Err("checkpoint completeness hash mismatch".into());
                    }
                    return Ok(Self { chunks, end });
                }
                // Expect::Checkpoint admits only the two checkpoint kinds.
                Decoded::Record(..) => {
                    unreachable!("non-checkpoint record under a checkpoint binding")
                }
                Decoded::CleanEnd | Decoded::TornTail => return Err("checkpoint is torn".into()),
                Decoded::Corrupt(reason) => return Err(reason),
            }
        }
    }

    pub const fn end(&self) -> &CheckpointEnd {
        &self.end
    }

    /// Catalog rows across all chunks, in written order.
    pub fn rows(&self) -> impl Iterator<Item = &CatalogRow> {
        self.chunks.iter().flat_map(|chunk| chunk.rows.iter())
    }

    /// Extent rows across all chunks, in written order.
    pub fn extents(&self) -> impl Iterator<Item = &ExtentRow> {
        self.chunks.iter().flat_map(|chunk| chunk.extents.iter())
    }

    /// Referenced segments across all chunks, in written order.
    pub fn segments(&self) -> impl Iterator<Item = &SegmentSeq> {
        self.chunks.iter().flat_map(|chunk| chunk.segments.iter())
    }

    /// The log id minting floor (every chunk agrees; decode enforces it).
    pub fn next_log(&self) -> LogId {
        self.chunks[0].next_log
    }

    /// The transaction sequence minting floor.
    pub fn next_txn(&self) -> TxnSeq {
        self.chunks[0].next_txn
    }
}

/// A live block copied to a new segment by cleaning. No transaction
/// semantics: authoritative only once a checkpoint references it. The
/// record's own (log, at) are self-supplied, so a reader must cross-check
/// them against the governing extent row before serving bytes --
/// [Expect::Relocated] carries that expectation, and the store's read path
/// enforces it structurally by verifying every block against the extent
/// row's own (log, at) binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RelocatedExtent {
    pub log: LogId,
    pub at: LogOffset,
    pub payload: Vec<u8>,
}

/// Where a [RelocatedExtent]'s verifiable bytes live, offsets relative to the
/// record's first byte (parallel to [BlockSite]).
#[derive(Clone, Copy, Debug)]
pub(super) struct RelocatedSite {
    /// Offset of the block's payload.
    pub payload: usize,
    /// Offset of the block's 4-byte checksum.
    pub crc: usize,
}

impl RelocatedExtent {
    /// Validates one relocated block. The only constructor, so encoding is
    /// infallible (parallel to [ValidatedTxn]).
    pub fn new(log: LogId, at: LogOffset, payload: Vec<u8>) -> Result<Self, String> {
        if payload.is_empty() || payload.len() > MAX_BLOCK_BYTES {
            return Err("invalid block length".into());
        }
        Ok(Self { log, at, payload })
    }

    /// Appends this record's envelope to `out` and returns where its payload
    /// and block checksum landed, relative to the record's first byte, so the
    /// extent row the cleaner emits can never diverge from the encoding.
    pub fn encode(&self, ident: &Identity, out: &mut Vec<u8>) -> RelocatedSite {
        let start = out.len();
        let mut body = Vec::with_capacity(32 + self.payload.len());
        self.write_body(&ident.salt, &mut body);
        write_envelope(out, ident, KIND_RELOCATED_EXTENT, 0, &body);
        // The record ends [payload][block crc 4][record crc 4].
        let end = out.len() - start;
        RelocatedSite {
            payload: end - 8 - self.payload.len(),
            crc: end - 8,
        }
    }

    fn write_body(&self, salt: &Salt, body: &mut Vec<u8>) {
        debug_assert!(!self.payload.is_empty() && self.payload.len() <= MAX_BLOCK_BYTES);
        UInt(self.log.0).write(body);
        UInt(self.at.0).write(body);
        UInt(self.payload.len() as u32).write(body);
        body.extend_from_slice(&self.payload);
        body.extend_from_slice(&block_crc(salt, self.log, self.at, &self.payload));
    }
}

/// Upper bound on the encoded bytes of a [RelocatedExtent] record carrying a
/// `payload`-byte block -- envelope, three varints at their bounds, block
/// checksum -- sibling of [frame_bytes_bound]: sizes the cleaner's copy work
/// in encoded output bytes.
pub(super) const fn relocated_bytes_bound(payload: u64) -> u64 {
    (5 + 1 + 4) + (10 + 10 + 5) + 4 + payload
}

const KIND_TRANSACTION_FRAME: u8 = 1;
const KIND_CHECKPOINT_CHUNK: u8 = 2;
const KIND_CHECKPOINT_END: u8 = 3;
const KIND_RELOCATED_EXTENT: u8 = 4;

const OP_CREATE: u8 = 1;
const OP_APPEND: u8 = 2;
const OP_REWIND: u8 = 3;
const OP_REMOVE: u8 = 4;

/// The identity a reader requires of the next record: which kinds it will
/// accept and the sequence their checksums must bind.
#[derive(Clone, Copy, Debug)]
pub(super) enum Expect {
    /// A transaction frame with exactly this sequence.
    Frame(TxnSeq),
    /// A chunk or end of exactly this checkpoint.
    Checkpoint(CheckpointSeq),
    /// A relocated extent serving exactly this block (no owning sequence;
    /// binds zero). The record's (log, at) are self-supplied, so the reader
    /// states the governing extent row's expectation here and decode
    /// cross-checks it.
    Relocated { log: LogId, at: LogOffset },
}

impl Expect {
    /// The sequence bound into the checksum.
    const fn seq(self) -> u64 {
        match self {
            Self::Frame(seq) => seq.0,
            Self::Checkpoint(seq) => seq.0,
            Self::Relocated { .. } => 0,
        }
    }
}

/// One record of a segment's stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Record {
    /// One atomic transaction: complete means apply everything, torn means
    /// apply nothing. The envelope checksum decides; per-block checksums serve
    /// random reads.
    TransactionFrame(ValidatedTxn),
    CheckpointChunk(CheckpointChunk),
    CheckpointEnd(CheckpointEnd),
    RelocatedExtent(RelocatedExtent),
}

/// Outcome of decoding one record from a segment's unread remainder.
#[derive(Debug)]
pub(super) enum Decoded {
    /// A valid record and the bytes it consumed.
    Record(Record, usize),
    /// Exact end of written data: nothing starts here (true end, or a zero
    /// hole left by a torn extension -- no record starts with a zero byte).
    CleanEnd,
    /// A write started and did not complete: short frame or checksum failure,
    /// including every identity mismatch. Replay stops here and ignores every
    /// later byte.
    TornTail,
    /// A checksummed record whose content is impossible. Tearing cannot
    /// produce this; it is always a hard error.
    Corrupt(String),
}

/// Appends a record envelope -- length, kind, body, checksum -- to `out`.
fn write_envelope(out: &mut Vec<u8>, ident: &Identity, kind: u8, seq: u64, body: &[u8]) {
    debug_assert!(!body.is_empty() && body.len() as u64 <= MAX_RECORD_BYTES);
    UInt(body.len() as u32).write(out);
    out.push(kind);
    out.extend_from_slice(body);
    out.extend_from_slice(&record_crc(ident, kind, seq, body));
}

impl Record {
    const fn kind(&self) -> u8 {
        match self {
            Self::TransactionFrame(_) => KIND_TRANSACTION_FRAME,
            Self::CheckpointChunk(_) => KIND_CHECKPOINT_CHUNK,
            Self::CheckpointEnd(_) => KIND_CHECKPOINT_END,
            Self::RelocatedExtent(_) => KIND_RELOCATED_EXTENT,
        }
    }

    /// The relevant sequence bound into this record's checksum.
    const fn seq(&self) -> u64 {
        match self {
            Self::TransactionFrame(txn) => txn.seq.0,
            Self::CheckpointChunk(chunk) => chunk.seq.0,
            Self::CheckpointEnd(end) => end.seq.0,
            Self::RelocatedExtent(_) => 0,
        }
    }

    /// Appends this record's envelope (length, kind, body, checksum) to `out`.
    ///
    /// The committer's vectored write path must derive its iovecs and checksum
    /// feed from the same run/block/descriptor iterators used here, so the two
    /// encodings can never diverge; until it lands, this contiguous encode
    /// serves tests and (later) checkpoint records.
    pub fn encode(&self, ident: &Identity, out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(64);
        match self {
            Self::TransactionFrame(txn) => return txn.encode_frame(ident, out),
            Self::CheckpointChunk(chunk) => chunk.write_body(&mut body),
            Self::CheckpointEnd(end) => end.write_body(&mut body),
            Self::RelocatedExtent(extent) => extent.write_body(&ident.salt, &mut body),
        }
        write_envelope(out, ident, self.kind(), self.seq(), &body);
    }

    /// Decodes one record from the start of `buf` (the unread remainder of the
    /// segment) under the identity the reader expects.
    pub fn decode(buf: &[u8], ident: &Identity, expect: Expect) -> Decoded {
        if buf.is_empty() || buf[0] == 0 {
            return Decoded::CleanEnd;
        }
        let mut cursor = buf;
        let Ok(len) = UInt::<u32>::read(&mut cursor) else {
            return Decoded::TornTail;
        };
        // Widened arithmetic: a hostile length near u32::MAX must not overflow
        // into a passing bounds check on 32-bit targets.
        let len = u64::from(len.0);
        if len > MAX_RECORD_BYTES || len + 5 > cursor.remaining() as u64 {
            return Decoded::TornTail;
        }
        let len = len as usize;
        let kind = cursor[0];
        let body = &cursor[1..1 + len];
        if record_crc(ident, kind, expect.seq(), body) != cursor[1 + len..1 + len + 4] {
            return Decoded::TornTail;
        }
        let consumed = (buf.len() - cursor.len()) + 1 + len + 4;
        match Self::decode_body(kind, body, ident, expect) {
            Ok(record) => Decoded::Record(record, consumed),
            Err(reason) => Decoded::Corrupt(reason),
        }
    }

    /// Decodes a checksummed body. Any failure here is corruption, not a torn
    /// tail.
    fn decode_body(
        kind: u8,
        mut body: &[u8],
        ident: &Identity,
        expect: Expect,
    ) -> Result<Self, String> {
        let body = &mut body;
        let record = match (kind, expect) {
            (KIND_TRANSACTION_FRAME, Expect::Frame(seq)) => {
                Self::TransactionFrame(decode_frame(body, &ident.salt, seq)?)
            }
            (KIND_CHECKPOINT_CHUNK, Expect::Checkpoint(seq)) => {
                Self::CheckpointChunk(decode_chunk(body, seq)?)
            }
            (KIND_CHECKPOINT_END, Expect::Checkpoint(seq)) => {
                Self::CheckpointEnd(decode_end(body, seq)?)
            }
            (KIND_RELOCATED_EXTENT, Expect::Relocated { log, at }) => {
                Self::RelocatedExtent(decode_relocated(body, &ident.salt, log, at)?)
            }
            _ => return Err(format!("record kind {kind} is not valid in this stream")),
        };
        if body.remaining() != 0 {
            return Err("trailing bytes in record body".into());
        }
        Ok(record)
    }
}

/// Probes a torn record for burial: walks successive claimed-length hops and
/// asks whether a valid successor frame -- carrying the sequence its hop
/// implies -- sits at any claimed end. A frame is written only after its
/// predecessor's barrier completed, so a valid successor proves every frame
/// before it was once durably complete: the tear is damage to acknowledged
/// history, never a crash artifact. Consecutive damaged frames are walked
/// through; each hop is bounded like a record decode and the walk by the
/// caller's replay range. Best-effort by design; the residual blindness is
/// damage to a length prefix (which hides every later successor), a
/// mid-stream zeroed first length byte (reads as a clean end), and damage
/// extending through the final acknowledged frame (no successor exists).
pub(super) fn buried_tear(buf: &[u8], ident: &Identity, torn: TxnSeq) -> bool {
    let mut buf = buf;
    let mut expect = torn;
    loop {
        let mut cursor = buf;
        let Ok(len) = UInt::<u32>::read(&mut cursor) else {
            return false;
        };
        let len = u64::from(len.0);
        if len > MAX_RECORD_BYTES || len + 5 > cursor.remaining() as u64 {
            return false;
        }
        buf = &cursor[(1 + len + 4) as usize..];
        expect = expect.next();
        match Record::decode(buf, ident, Expect::Frame(expect)) {
            Decoded::Record(..) => return true,
            // Torn as well: hop over it (consecutive damaged frames).
            Decoded::TornTail => {}
            // Corrupt means the successor's identity-bound checksum passed,
            // which proves the predecessor's barrier completed just as a
            // clean Record would: the tear is buried.
            Decoded::Corrupt(_) => return true,
            Decoded::CleanEnd => return false,
        }
    }
}

/// Decode-side allocation allowance, charged before every reservation so a
/// compact hostile record cannot expand into unbounded memory.
struct Budget(usize);

impl Budget {
    const fn new() -> Self {
        Self(MAX_DECODED_BYTES)
    }

    fn charge(&mut self, bytes: usize) -> Result<(), String> {
        if bytes > self.0 {
            return Err("decoded size exceeds MAX_DECODED_BYTES".into());
        }
        self.0 -= bytes;
        Ok(())
    }
}

fn read_u8(body: &mut &[u8]) -> Result<u8, String> {
    u8::read(body).map_err(|e| e.to_string())
}

fn read_u32(body: &mut &[u8]) -> Result<u32, String> {
    Ok(UInt::<u32>::read(body).map_err(|e| e.to_string())?.0)
}

fn read_u64(body: &mut &[u8]) -> Result<u64, String> {
    Ok(UInt::<u64>::read(body).map_err(|e| e.to_string())?.0)
}

fn read_array<const N: usize>(body: &mut &[u8]) -> Result<[u8; N], String> {
    if body.remaining() < N {
        return Err("record body is short".into());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&body[..N]);
    body.advance(N);
    Ok(out)
}

/// Reads a length-prefixed log name: arbitrary bytes, empty included, bounded
/// only by [MAX_LOG_NAME_LEN].
fn read_name(body: &mut &[u8], budget: &mut Budget) -> Result<Vec<u8>, String> {
    let len = read_u32(body)? as usize;
    if len > MAX_LOG_NAME_LEN {
        return Err(format!(
            "log name of {len} bytes exceeds {MAX_LOG_NAME_LEN}"
        ));
    }
    budget.charge(len)?;
    if len > body.remaining() {
        return Err("log name exceeds body".into());
    }
    let name = body[..len].to_vec();
    body.advance(len);
    Ok(name)
}

/// Decodes a frame body back into the validated transaction it was encoded
/// from, verifying every bound and per-block checksum.
fn decode_frame(body: &mut &[u8], salt: &Salt, seq: TxnSeq) -> Result<ValidatedTxn, String> {
    let mut budget = Budget::new();
    let epoch = read_u64(body)?;
    if epoch != salt.epoch {
        return Err("frame epoch does not match its binding".into());
    }
    if read_u64(body)? != seq.0 {
        return Err("frame sequence does not match its binding".into());
    }

    let descriptors = read_u32(body)? as usize;
    if descriptors > MAX_TRANSACTION_OPS {
        return Err(format!(
            "{descriptors} descriptors exceeds {MAX_TRANSACTION_OPS}"
        ));
    }
    budget.charge(descriptors.saturating_mul(size_of::<(LogId, NetOp)>()))?;
    let mut ops: Vec<(LogId, NetOp)> = Vec::with_capacity(descriptors);
    // (ops index, anchor, run length) for every append, in wire order.
    let mut appends: Vec<(usize, u64, u64)> = Vec::new();
    for _ in 0..descriptors {
        let verb = read_u8(body)?;
        let log = LogId(read_u64(body)?);
        let generation = read_u64(body)?;
        let committed = read_u64(body)?;
        match verb {
            OP_CREATE => {
                if generation != 0 || committed != 0 {
                    return Err("create expects an absent log".into());
                }
                let name = read_name(body, &mut budget)?;
                if read_array::<8>(body)? != RESERVED_LOG_BYTES {
                    return Err("reserved log bytes are not zero".into());
                }
                ops.push((
                    log,
                    NetOp::Create {
                        name,
                        run: Vec::new(),
                    },
                ));
            }
            OP_REWIND => {
                let to = read_u64(body)?;
                ops.push((
                    log,
                    NetOp::Mutate {
                        generation,
                        committed,
                        rewind_to: Some(to),
                        run: Vec::new(),
                    },
                ));
            }
            OP_APPEND => {
                let len = read_u64(body)?;
                if len == 0 {
                    return Err("append of zero bytes".into());
                }
                // An append may extend an immediately preceding create or
                // rewind of the same log; otherwise it stands alone (the
                // second clause stops an append from extending an op that
                // already received one).
                let extends = ops.last().is_some_and(|(prev, _)| *prev == log)
                    && appends.last().is_none_or(|&(i, _, _)| i + 1 != ops.len());
                let (index, anchor) = if extends {
                    let index = ops.len() - 1;
                    let anchor = match &ops[index].1 {
                        NetOp::Create { .. } if generation == 0 && committed == 0 => 0,
                        NetOp::Mutate {
                            generation: g,
                            committed: c,
                            rewind_to: Some(to),
                            ..
                        } if *g == generation && *c == committed => *to,
                        _ => return Err("append does not extend its predecessor".into()),
                    };
                    (index, anchor)
                } else {
                    ops.push((
                        log,
                        NetOp::Mutate {
                            generation,
                            committed,
                            rewind_to: None,
                            run: Vec::new(),
                        },
                    ));
                    (ops.len() - 1, committed)
                };
                if anchor.checked_add(len).is_none() {
                    return Err("append overflows the log length".into());
                }
                appends.push((index, anchor, len));
            }
            OP_REMOVE => ops.push((
                log,
                NetOp::Remove {
                    generation,
                    committed,
                },
            )),
            other => return Err(format!("unknown operation {other}")),
        }
    }

    let mut payload_len: u64 = 0;
    for &(_, _, len) in &appends {
        payload_len = payload_len
            .checked_add(len)
            .ok_or_else(|| "payload length overflows".to_string())?;
    }
    if payload_len > MAX_TRANSACTION_PAYLOAD {
        return Err(format!(
            "payload of {payload_len} bytes exceeds {MAX_TRANSACTION_PAYLOAD}"
        ));
    }
    budget.charge(payload_len as usize)?;

    let declared = read_u32(body)? as usize;
    if declared > MAX_PAYLOAD_BLOCKS {
        return Err(format!("{declared} blocks exceeds {MAX_PAYLOAD_BLOCKS}"));
    }
    budget.charge(declared.saturating_mul(size_of::<(LogId, u64, u32)>()))?;
    // A block descriptor is at least three encoded bytes.
    if declared > body.remaining() / 3 {
        return Err("block count exceeds body".into());
    }
    let mut blocks = Vec::with_capacity(declared);
    for _ in 0..declared {
        let log = LogId(read_u64(body)?);
        let at = read_u64(body)?;
        let len = read_u32(body)?;
        if len == 0 || len as usize > MAX_BLOCK_BYTES {
            return Err("invalid block length".into());
        }
        blocks.push((log, at, len));
    }
    // Blocks tile the append runs exactly, in wire order, at the canonical
    // size the encoder produces; any other tiling under a valid checksum is
    // corruption.
    let mut table = blocks.iter();
    for &(index, anchor, run_len) in &appends {
        let log = ops[index].0;
        let mut covered = 0u64;
        while covered < run_len {
            let Some(&(block_log, at, len)) = table.next() else {
                return Err("blocks do not tile the append runs".into());
            };
            let canonical = (run_len - covered).min(MAX_BLOCK_BYTES as u64);
            if block_log != log || at != anchor + covered || u64::from(len) != canonical {
                return Err("blocks do not tile the append runs".into());
            }
            covered += u64::from(len);
        }
    }
    if table.next().is_some() {
        return Err("blocks do not tile the append runs".into());
    }

    if (body.remaining() as u64) < payload_len {
        return Err("payload exceeds body".into());
    }
    let current = *body;
    let (payload, rest) = current.split_at(payload_len as usize);
    *body = rest;
    let mut at = 0usize;
    for &(index, _, run_len) in &appends {
        let run = payload[at..at + run_len as usize].to_vec();
        at += run_len as usize;
        match &mut ops[index].1 {
            NetOp::Create { run: slot, .. } | NetOp::Mutate { run: slot, .. } => *slot = run,
            // Append indices are minted only for Create and Mutate above.
            NetOp::Remove { .. } => unreachable!("append paired with a remove"),
        }
    }
    let mut at = 0usize;
    for &(log, offset, len) in &blocks {
        let stored = read_array::<4>(body)?;
        let block = &payload[at..at + len as usize];
        at += len as usize;
        if stored != block_crc(salt, log, LogOffset(offset), block) {
            return Err("per-block checksum mismatch".into());
        }
    }

    ValidatedTxn::new(epoch, seq, ops).map_err(|e| e.to_string())
}

fn decode_chunk(body: &mut &[u8], seq: CheckpointSeq) -> Result<CheckpointChunk, String> {
    let mut budget = Budget::new();

    let rows = read_u32(body)? as usize;
    if rows > MAX_CHECKPOINT_LOGS {
        return Err(format!("{rows} rows exceeds {MAX_CHECKPOINT_LOGS}"));
    }
    budget.charge(rows.saturating_mul(size_of::<CatalogRow>()))?;
    // A row is at least 12 encoded bytes; a larger claim cannot be complete.
    if rows > body.remaining() / 12 {
        return Err("row count exceeds body".into());
    }
    let mut catalog = Vec::with_capacity(rows);
    for _ in 0..rows {
        let log = LogId(read_u64(body)?);
        let generation = read_u64(body)?;
        let committed = read_u64(body)?;
        let name = read_name(body, &mut budget)?;
        if read_array::<8>(body)? != RESERVED_LOG_BYTES {
            return Err("reserved log bytes are not zero".into());
        }
        catalog.push(CatalogRow {
            log,
            generation,
            committed,
            name,
        });
    }

    let extents = read_u32(body)? as usize;
    if extents > MAX_EXTENT_DELTAS {
        return Err(format!("{extents} extents exceeds {MAX_EXTENT_DELTAS}"));
    }
    budget.charge(extents.saturating_mul(size_of::<ExtentRow>()))?;
    // An extent row is at least six encoded bytes.
    if extents > body.remaining() / 6 {
        return Err("extent count exceeds body".into());
    }
    let mut extent_rows = Vec::with_capacity(extents);
    for _ in 0..extents {
        extent_rows.push(ExtentRow {
            log: LogId(read_u64(body)?),
            at: LogOffset(read_u64(body)?),
            segment: SegmentSeq(read_u64(body)?),
            start: SegmentOffset(read_u64(body)?),
            len: read_u64(body)?,
            crc: SegmentOffset(read_u64(body)?),
        });
    }

    let segments = read_u32(body)? as usize;
    if segments > MAX_CHECKPOINT_SEGMENTS {
        return Err(format!(
            "{segments} segments exceeds {MAX_CHECKPOINT_SEGMENTS}"
        ));
    }
    budget.charge(segments.saturating_mul(size_of::<SegmentSeq>()))?;
    if segments > body.remaining() {
        return Err("segment count exceeds body".into());
    }
    let mut segment_ids = Vec::with_capacity(segments);
    for _ in 0..segments {
        segment_ids.push(SegmentSeq(read_u64(body)?));
    }

    Ok(CheckpointChunk {
        seq,
        rows: catalog,
        extents: extent_rows,
        segments: segment_ids,
        next_log: LogId(read_u64(body)?),
        next_txn: TxnSeq(read_u64(body)?),
    })
}

fn decode_end(body: &mut &[u8], seq: CheckpointSeq) -> Result<CheckpointEnd, String> {
    if read_u64(body)? != seq.0 {
        return Err("checkpoint end does not match its binding".into());
    }
    Ok(CheckpointEnd {
        seq,
        total_bytes: read_u64(body)?,
        rows: read_u64(body)?,
        extents: read_u64(body)?,
        segments: read_u64(body)?,
        hash: read_array::<32>(body)?,
    })
}

fn decode_relocated(
    body: &mut &[u8],
    salt: &Salt,
    expect_log: LogId,
    expect_at: LogOffset,
) -> Result<RelocatedExtent, String> {
    let mut budget = Budget::new();
    let log = LogId(read_u64(body)?);
    let at = LogOffset(read_u64(body)?);
    if log != expect_log || at != expect_at {
        return Err("relocated extent does not match the governing row".into());
    }
    let len = read_u32(body)? as usize;
    if len == 0 || len > MAX_BLOCK_BYTES {
        return Err("invalid block length".into());
    }
    budget.charge(len)?;
    if len > body.remaining() {
        return Err("payload exceeds body".into());
    }
    let payload = body[..len].to_vec();
    body.advance(len);
    if read_array::<4>(body)? != block_crc(salt, log, at, &payload) {
        return Err("per-block checksum mismatch".into());
    }
    Ok(RelocatedExtent { log, at, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INCARNATION: Incarnation = Incarnation(*b"0123456789abcdef");
    const EPOCH: u64 = 3;

    fn ident() -> Identity {
        Identity {
            salt: Salt::new(&INCARNATION, EPOCH),
            segment: SegmentSeq(7),
        }
    }

    fn sample_ops() -> Vec<(LogId, NetOp)> {
        vec![
            (
                LogId(1),
                NetOp::Create {
                    name: b"orders".to_vec(),
                    run: b"hello".to_vec(),
                },
            ),
            (
                LogId(2),
                NetOp::Mutate {
                    generation: 4,
                    committed: 100,
                    rewind_to: Some(40),
                    run: vec![7u8; 10],
                },
            ),
            (
                LogId(3),
                NetOp::Mutate {
                    generation: 0,
                    committed: 5,
                    rewind_to: None,
                    run: b"xyz".to_vec(),
                },
            ),
            (
                LogId(4),
                NetOp::Mutate {
                    generation: 1,
                    committed: 9,
                    rewind_to: Some(0),
                    run: Vec::new(),
                },
            ),
            (
                LogId(5),
                NetOp::Remove {
                    generation: 2,
                    committed: 33,
                },
            ),
        ]
    }

    fn frame(seq: u64, ops: Vec<(LogId, NetOp)>) -> Record {
        Record::TransactionFrame(ValidatedTxn::new(EPOCH, TxnSeq(seq), ops).unwrap())
    }

    fn encode(record: &Record, ident: &Identity) -> Vec<u8> {
        let mut out = Vec::new();
        record.encode(ident, &mut out);
        out
    }

    /// Hand-builds a valid envelope over an arbitrary body.
    fn envelope(ident: &Identity, kind: u8, seq: u64, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        UInt(body.len() as u32).write(&mut out);
        out.push(kind);
        out.extend_from_slice(body);
        out.extend_from_slice(&record_crc(ident, kind, seq, body));
        out
    }

    /// Recomputes a patched root page's checksum so decode reaches the body
    /// checks.
    fn reseal_root(page: &mut [u8]) {
        let sum = crc(ROOT_DOMAIN, &INCARNATION.0, &[], &page[..ROOT_BODY]);
        page[ROOT_BODY..ROOT_BODY + 4].copy_from_slice(&sum);
    }

    #[test]
    fn manifest_header_round_trip() {
        let header = ManifestHeader {
            incarnation: INCARNATION,
        };
        let page = header.encode();
        assert_eq!(page.len(), PAGE);
        assert_eq!(ManifestHeader::decode(&page).unwrap(), header);
    }

    #[test]
    fn manifest_header_damage_is_hard_error() {
        let header = ManifestHeader {
            incarnation: INCARNATION,
        };
        let mut page = header.encode();
        page[3] ^= 1;
        assert!(ManifestHeader::decode(&page).is_err());
        // Nonzero padding under a valid checksum is damage too.
        let mut page = header.encode();
        page[100] = 1;
        assert!(ManifestHeader::decode(&page).is_err());
        // All zeros (never written) is damage: creation is staged and renamed.
        assert!(ManifestHeader::decode(&vec![0u8; PAGE]).is_err());
    }

    #[test]
    fn segment_header_round_trip() {
        let header = SegmentHeader {
            incarnation: INCARNATION,
            seq: SegmentSeq(42),
        };
        let page = header.encode();
        assert_eq!(
            SegmentHeader::decode(&page, &INCARNATION, SegmentSeq(42)).unwrap(),
            header
        );
    }

    #[test]
    fn segment_header_wrong_identity_is_hard_error() {
        let page = SegmentHeader {
            incarnation: INCARNATION,
            seq: SegmentSeq(42),
        }
        .encode();
        let foreign = Incarnation(*b"ffffffffffffffff");
        assert!(SegmentHeader::decode(&page, &foreign, SegmentSeq(42)).is_err());
        assert!(SegmentHeader::decode(&page, &INCARNATION, SegmentSeq(41)).is_err());
        let mut damaged = page;
        damaged[3] ^= 1;
        assert!(SegmentHeader::decode(&damaged, &INCARNATION, SegmentSeq(42)).is_err());
    }

    fn sample_root(seq: u64) -> Root {
        Root {
            seq,
            epoch: 0,
            checkpoint: None,
            active_segment: SegmentSeq(1),
            replay_from: TxnSeq(1),
            replay_at: SEGMENT_RECORDS,
            next_log: LogId(1),
            next_txn: TxnSeq(1),
        }
    }

    #[test]
    fn root_round_trip_and_parity() {
        let empty = sample_root(6);
        let page = empty.encode(&INCARNATION);
        assert_eq!(Root::decode(&page, &INCARNATION, 0).unwrap(), Some(empty));
        // A valid root in the wrong slot is damage.
        assert!(Root::decode(&page, &INCARNATION, 1).is_err());

        let full = Root {
            seq: 7,
            epoch: 2,
            checkpoint: Some(CheckpointLocator {
                segment: SegmentSeq(3),
                start: SEGMENT_RECORDS,
                len: 512,
                seq: CheckpointSeq(9),
                hash: [0xAB; 32],
            }),
            active_segment: SegmentSeq(4),
            replay_from: TxnSeq(101),
            replay_at: SegmentOffset(70_000),
            next_log: LogId(55),
            next_txn: TxnSeq(120),
        };
        let page = full.encode(&INCARNATION);
        assert_eq!(Root::decode(&page, &INCARNATION, 1).unwrap(), Some(full));

        // A root under a different incarnation reads as never-written.
        let foreign = Incarnation(*b"ffffffffffffffff");
        assert_eq!(Root::decode(&page, &foreign, 1).unwrap(), None);
        // All zeros reads as never-written.
        assert_eq!(
            Root::decode(&vec![0u8; PAGE], &INCARNATION, 0).unwrap(),
            None
        );
    }

    #[test]
    fn root_malformed_is_hard_error() {
        // Nonzero locator bytes under an empty checkpoint flag.
        let mut page = sample_root(6).encode(&INCARNATION);
        page[ROOT_CHECKPOINT + 10] = 1;
        reseal_root(&mut page);
        assert!(Root::decode(&page, &INCARNATION, 0).is_err());

        // An invalid checkpoint flag.
        let mut page = sample_root(6).encode(&INCARNATION);
        page[ROOT_CHECKPOINT] = 2;
        reseal_root(&mut page);
        assert!(Root::decode(&page, &INCARNATION, 0).is_err());

        // An unknown format version.
        let mut page = sample_root(6).encode(&INCARNATION);
        page[ROOT_VERSION + 1] = 99;
        reseal_root(&mut page);
        assert!(Root::decode(&page, &INCARNATION, 0).is_err());

        // Nonzero padding beyond the checksum.
        let mut page = sample_root(6).encode(&INCARNATION);
        page[PAGE - 1] = 1;
        assert!(Root::decode(&page, &INCARNATION, 0).is_err());
    }

    #[test]
    fn root_fallback_only_on_invalid_root() {
        // The rule this pins: a torn slot falls back; the surviving valid root
        // governs regardless of age.
        let older = sample_root(6);
        let newer = sample_root(7);
        let slot0 = older.encode(&INCARNATION);
        let mut slot1 = newer.encode(&INCARNATION);
        slot1[ROOT_SEQ] ^= 1; // torn publication of the newer root

        let decoded0 = Root::decode(&slot0, &INCARNATION, 0).unwrap();
        let decoded1 = Root::decode(&slot1, &INCARNATION, 1).unwrap();
        assert_eq!(decoded1, None);
        let governing = [decoded0, decoded1]
            .into_iter()
            .flatten()
            .max_by_key(|r| r.seq);
        assert_eq!(governing, Some(older));
    }

    #[test]
    fn root_nonzero_epoch_round_trips_and_drives_record_salt() {
        let root = Root {
            epoch: EPOCH,
            ..sample_root(6)
        };
        let page = root.encode(&INCARNATION);
        let decoded = Root::decode(&page, &INCARNATION, 0).unwrap().unwrap();
        assert_eq!(decoded, root);

        // Recovery reconstructs the salt from the manifest incarnation and the
        // governing root's epoch: records written under that salt decode, and
        // a neighboring epoch's salt rejects them.
        let governing = Identity {
            salt: Salt::new(&INCARNATION, decoded.epoch),
            segment: SegmentSeq(7),
        };
        let buf = encode(&frame(9, sample_ops()), &governing);
        assert!(matches!(
            Record::decode(&buf, &governing, Expect::Frame(TxnSeq(9))),
            Decoded::Record(..)
        ));
        let stale = Identity {
            salt: Salt::new(&INCARNATION, decoded.epoch + 1),
            segment: SegmentSeq(7),
        };
        assert!(matches!(
            Record::decode(&buf, &stale, Expect::Frame(TxnSeq(9))),
            Decoded::TornTail
        ));
    }

    #[test]
    fn short_pages_are_damage() {
        let page = ManifestHeader {
            incarnation: INCARNATION,
        }
        .encode();
        assert!(ManifestHeader::decode(&page[..PAGE - 1]).is_err());
        let page = SegmentHeader {
            incarnation: INCARNATION,
            seq: SegmentSeq(1),
        }
        .encode();
        assert!(SegmentHeader::decode(&page[..PAGE - 1], &INCARNATION, SegmentSeq(1)).is_err());
        // A short root page reads as never-written, like a checksum failure.
        let page = sample_root(6).encode(&INCARNATION);
        assert_eq!(
            Root::decode(&page[..PAGE - 1], &INCARNATION, 0).unwrap(),
            None
        );
    }

    #[test]
    fn record_round_trip() {
        let ident = ident();
        let mut buf = Vec::new();
        for seq in 9..12 {
            frame(seq, sample_ops()).encode(&ident, &mut buf);
        }
        let mut remaining = &buf[..];
        for seq in 9..12 {
            match Record::decode(remaining, &ident, Expect::Frame(TxnSeq(seq))) {
                Decoded::Record(record, consumed) => {
                    assert_eq!(record, frame(seq, sample_ops()));
                    remaining = &remaining[consumed..];
                }
                other => panic!("expected record, got {other:?}"),
            }
        }
        assert!(matches!(
            Record::decode(remaining, &ident, Expect::Frame(TxnSeq(12))),
            Decoded::CleanEnd
        ));
    }

    #[test]
    fn block_sites_locate_payload_and_checksums() {
        let ident = ident();
        let two_blocks = vec![(
            LogId(1),
            NetOp::Mutate {
                generation: 1,
                committed: 10,
                rewind_to: Some(0),
                run: vec![3u8; MAX_BLOCK_BYTES + 1],
            },
        )];
        for ops in [sample_ops(), two_blocks] {
            let txn = ValidatedTxn::new(EPOCH, TxnSeq(9), ops).unwrap();
            let buf = encode(&Record::TransactionFrame(txn.clone()), &ident);
            let sites = txn.block_sites(buf.len());
            let blocks: Vec<_> = txn.blocks().collect();
            assert_eq!(sites.len(), blocks.len());
            for (site, (log, at, block)) in sites.iter().zip(blocks) {
                assert_eq!((site.log, site.at, site.len), (log, at, block.len() as u64));
                assert_eq!(&buf[site.payload..site.payload + block.len()], block);
                assert_eq!(
                    buf[site.crc..site.crc + 4],
                    block_crc(&ident.salt, log, at, block)
                );
            }
        }
    }

    #[test]
    fn checkpoint_round_trip() {
        let ident = ident();
        let seq = CheckpointSeq(5);
        let chunk = Record::CheckpointChunk(CheckpointChunk {
            seq,
            rows: vec![
                CatalogRow {
                    log: LogId(1),
                    generation: 2,
                    committed: 300,
                    name: b"orders".to_vec(),
                },
                CatalogRow {
                    log: LogId(9),
                    generation: 0,
                    committed: 0,
                    name: Vec::new(),
                },
            ],
            extents: vec![ExtentRow {
                log: LogId(1),
                at: LogOffset(100),
                segment: SegmentSeq(2),
                start: SegmentOffset(8192),
                len: 200,
                crc: SegmentOffset(8500),
            }],
            segments: vec![SegmentSeq(2), SegmentSeq(3)],
            next_log: LogId(10),
            next_txn: TxnSeq(77),
        });
        let end = Record::CheckpointEnd(CheckpointEnd {
            seq,
            total_bytes: 1024,
            rows: 2,
            extents: 1,
            segments: 2,
            hash: [0xCD; 32],
        });
        let mut buf = Vec::new();
        chunk.encode(&ident, &mut buf);
        end.encode(&ident, &mut buf);

        let expect = Expect::Checkpoint(seq);
        let Decoded::Record(decoded, consumed) = Record::decode(&buf, &ident, expect) else {
            panic!("expected chunk");
        };
        assert_eq!(decoded, chunk);
        let Decoded::Record(decoded, _) = Record::decode(&buf[consumed..], &ident, expect) else {
            panic!("expected end");
        };
        assert_eq!(decoded, end);
    }

    fn catalog_row(id: u64) -> CatalogRow {
        CatalogRow {
            log: LogId(id),
            generation: 0,
            committed: 0,
            name: vec![id as u8],
        }
    }

    fn checkpoint_chunk(seq: CheckpointSeq, rows: Vec<CatalogRow>) -> CheckpointChunk {
        CheckpointChunk {
            seq,
            rows,
            extents: Vec::new(),
            segments: Vec::new(),
            next_log: LogId(10),
            next_txn: TxnSeq(77),
        }
    }

    /// Encodes `chunks` followed by a truthfully computed end record.
    fn checkpoint_stream(
        ident: &Identity,
        seq: CheckpointSeq,
        chunks: &[CheckpointChunk],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut hash = CompletenessHash::new();
        let mut total_bytes = 0u64;
        let (mut rows, mut extents, mut segments) = (0u64, 0u64, 0u64);
        for chunk in chunks {
            let before = out.len();
            Record::CheckpointChunk(chunk.clone()).encode(ident, &mut out);
            total_bytes += (out.len() - before) as u64;
            let mut body = Vec::new();
            chunk.write_body(&mut body);
            hash.chunk(&body);
            rows += chunk.rows.len() as u64;
            extents += chunk.extents.len() as u64;
            segments += chunk.segments.len() as u64;
        }
        Record::CheckpointEnd(CheckpointEnd {
            seq,
            total_bytes,
            rows,
            extents,
            segments,
            hash: hash.finish(),
        })
        .encode(ident, &mut out);
        out
    }

    /// The constructor validates every cap; a valid checkpoint round-trips
    /// through encode and decode, splitting into bounded chunks as needed.
    #[test]
    fn checkpoint_constructor_and_round_trip() {
        let ident = ident();
        let seq = CheckpointSeq(3);

        // One row over the per-chunk packing limit forces a second chunk.
        let rows: Vec<CatalogRow> = (0..=CHUNK_ROWS as u64).map(catalog_row).collect();
        let extents = vec![ExtentRow {
            log: LogId(0),
            at: LogOffset(0),
            segment: SegmentSeq(1),
            start: SegmentOffset(8192),
            len: 100,
            crc: SegmentOffset(8300),
        }];
        let segments = vec![SegmentSeq(1)];
        let checkpoint = Checkpoint::new(
            seq,
            rows.clone(),
            extents.clone(),
            segments.clone(),
            LogId(9000),
            TxnSeq(42),
        )
        .unwrap();
        assert_eq!(checkpoint.chunks.len(), 2);

        let mut buf = Vec::new();
        checkpoint.encode(&ident, &mut buf);
        let decoded = Checkpoint::decode(&buf, &ident, seq).unwrap();
        assert_eq!(decoded.rows().cloned().collect::<Vec<_>>(), rows);
        assert_eq!(decoded.extents().cloned().collect::<Vec<_>>(), extents);
        assert_eq!(decoded.segments().cloned().collect::<Vec<_>>(), segments);
        assert_eq!(decoded.next_log(), LogId(9000));
        assert_eq!(decoded.next_txn(), TxnSeq(42));
        assert_eq!(decoded.end(), &checkpoint.end);

        // Caps are enforced at construction.
        assert!(
            Checkpoint::new(
                seq,
                Vec::new(),
                Vec::new(),
                vec![SegmentSeq(0); MAX_CHECKPOINT_SEGMENTS + 1],
                LogId(0),
                TxnSeq(0),
            )
            .is_err()
        );
        let long_name = CatalogRow {
            name: vec![b'n'; MAX_LOG_NAME_LEN + 1],
            ..catalog_row(0)
        };
        assert!(
            Checkpoint::new(
                seq,
                vec![long_name],
                Vec::new(),
                Vec::new(),
                LogId(1),
                TxnSeq(0)
            )
            .is_err()
        );
    }

    /// The end's verification is load-bearing: reordered, duplicated, or
    /// omitted chunks fail it even though every record's own checksum passes,
    /// and a stream that stops short of its end is hard corruption.
    #[test]
    fn checkpoint_end_verification_detects_tampering() {
        let ident = ident();
        let seq = CheckpointSeq(5);
        let c1 = checkpoint_chunk(seq, vec![catalog_row(1), catalog_row(2)]);
        let c2 = checkpoint_chunk(seq, vec![catalog_row(3)]);
        let good = checkpoint_stream(&ident, seq, &[c1.clone(), c2.clone()]);
        assert_eq!(
            Checkpoint::decode(&good, &ident, seq)
                .unwrap()
                .rows()
                .count(),
            3
        );

        // Splice tampered chunk orders under the original end record.
        let mut r1 = Vec::new();
        Record::CheckpointChunk(c1).encode(&ident, &mut r1);
        let mut r2 = Vec::new();
        Record::CheckpointChunk(c2).encode(&ident, &mut r2);
        let end = good[r1.len() + r2.len()..].to_vec();
        let reordered = [r2.clone(), r1.clone(), end.clone()].concat();
        let duplicated = [r1.clone(), r1.clone(), end.clone()].concat();
        let omitted = [r1.clone(), end.clone()].concat();
        let endless = [r1.clone(), r2.clone()].concat();
        let mut short = good.clone();
        short.truncate(good.len() - 1);
        let mut trailing = good;
        trailing.push(1);
        // A chunk of another attempt fails its identity binding outright.
        let mut foreign = Vec::new();
        Record::CheckpointChunk(checkpoint_chunk(CheckpointSeq(6), vec![catalog_row(1)]))
            .encode(&ident, &mut foreign);
        let foreign = [foreign, r2, end].concat();
        for tampered in [
            reordered, duplicated, omitted, endless, short, trailing, foreign,
        ] {
            assert!(Checkpoint::decode(&tampered, &ident, seq).is_err());
        }
    }

    /// A valid successor frame after a tear proves the torn frame was once
    /// durable, so the tear is damage; without a successor (or without a
    /// readable length prefix) the probe stays quiet.
    #[test]
    fn buried_tear_probe() {
        let ident = ident();
        let mut buf = Vec::new();
        let first = frame(9, sample_ops());
        first.encode(&ident, &mut buf);
        let first_len = buf.len();
        frame(10, sample_ops()).encode(&ident, &mut buf);

        // Damage a payload byte of the first frame: torn, but buried under a
        // valid frame 10.
        let Record::TransactionFrame(txn) = &first else {
            unreachable!()
        };
        let site = txn.block_sites(first_len)[0].payload;
        let mut damaged = buf.clone();
        damaged[site] ^= 1;
        assert!(matches!(
            Record::decode(&damaged, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::TornTail
        ));
        assert!(buried_tear(&damaged, &ident, TxnSeq(9)));

        // The same damage in the last frame has no successor: a legal tear.
        let mut tail = buf.clone();
        tail[first_len + site] ^= 1;
        assert!(!buried_tear(&tail[first_len..], &ident, TxnSeq(10)));

        // Damage to the length prefix hides the successor: the accepted
        // residual risk.
        let mut prefix = buf.clone();
        prefix[0] ^= 0x7F;
        assert!(!buried_tear(&prefix, &ident, TxnSeq(9)));

        // Two consecutive damaged frames under an intact acknowledged third:
        // the walk hops both tears and still finds the successor.
        let mut three = Vec::new();
        frame(9, sample_ops()).encode(&ident, &mut three);
        let second = three.len();
        frame(10, sample_ops()).encode(&ident, &mut three);
        let third = three.len();
        frame(11, sample_ops()).encode(&ident, &mut three);
        let mut damaged = three.clone();
        damaged[site] ^= 1; // frame 9's payload
        damaged[second + 6] ^= 1; // frame 10's body, past its length prefix
        assert!(matches!(
            Record::decode(&damaged[second..third], &ident, Expect::Frame(TxnSeq(10))),
            Decoded::TornTail
        ));
        assert!(buried_tear(&damaged, &ident, TxnSeq(9)));

        // A zeroed first length byte mid-stream reads as a clean end: the
        // named CleanEnd residual.
        let mut zeroed = three.clone();
        zeroed[site] ^= 1;
        zeroed[second] = 0;
        assert!(!buried_tear(&zeroed, &ident, TxnSeq(9)));
    }

    #[test]
    fn relocated_extent_round_trip() {
        let ident = ident();
        let extent = RelocatedExtent::new(LogId(4), LogOffset(9000), vec![0x5A; 100]).unwrap();
        let mut buf = Vec::new();
        let site = extent.encode(&ident, &mut buf);
        // The site locates the payload and its checksum inside the record.
        assert_eq!(&buf[site.payload..site.payload + 100], &[0x5A; 100]);
        assert_eq!(
            buf[site.crc..site.crc + 4],
            block_crc(&ident.salt, LogId(4), LogOffset(9000), &extent.payload)
        );
        let expect = Expect::Relocated {
            log: LogId(4),
            at: LogOffset(9000),
        };
        let Decoded::Record(decoded, consumed) = Record::decode(&buf, &ident, expect) else {
            panic!("expected record");
        };
        assert_eq!(decoded, Record::RelocatedExtent(extent));
        assert_eq!(consumed, buf.len());

        // A record whose self-supplied (log, at) do not match the governing
        // expectation is corrupt, not served.
        for expect in [
            Expect::Relocated {
                log: LogId(5),
                at: LogOffset(9000),
            },
            Expect::Relocated {
                log: LogId(4),
                at: LogOffset(9001),
            },
        ] {
            assert!(matches!(
                Record::decode(&buf, &ident, expect),
                Decoded::Corrupt(_)
            ));
        }

        // The validating constructor rejects impossible blocks.
        assert!(RelocatedExtent::new(LogId(0), LogOffset(0), Vec::new()).is_err());
        assert!(
            RelocatedExtent::new(LogId(0), LogOffset(0), vec![0; MAX_BLOCK_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn record_boundary_round_trip() {
        let ident = ident();
        let cases = vec![
            // An empty transaction.
            Vec::new(),
            // A name at exactly the cap.
            vec![(
                LogId(1),
                NetOp::Create {
                    name: vec![b'n'; MAX_LOG_NAME_LEN],
                    run: Vec::new(),
                },
            )],
            // A run at exactly one block, and one byte over.
            vec![(
                LogId(1),
                NetOp::Mutate {
                    generation: 1,
                    committed: 10,
                    rewind_to: None,
                    run: vec![1u8; MAX_BLOCK_BYTES],
                },
            )],
            vec![(
                LogId(1),
                NetOp::Mutate {
                    generation: 1,
                    committed: 10,
                    rewind_to: Some(0),
                    run: vec![2u8; MAX_BLOCK_BYTES + 1],
                },
            )],
        ];
        for ops in cases {
            let record = frame(9, ops);
            let buf = encode(&record, &ident);
            let Decoded::Record(decoded, consumed) =
                Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9)))
            else {
                panic!("expected record");
            };
            assert_eq!(decoded, record);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn record_clean_end_is_exact() {
        let ident = ident();
        let expect = Expect::Frame(TxnSeq(1));
        assert!(matches!(
            Record::decode(&[], &ident, expect),
            Decoded::CleanEnd
        ));
        assert!(matches!(
            Record::decode(&[0, 7, 7], &ident, expect),
            Decoded::CleanEnd
        ));
    }

    #[test]
    fn record_torn_tail_is_torn() {
        let ident = ident();
        let buf = encode(&frame(9, sample_ops()), &ident);
        // Truncation at every byte boundary: empty is a clean end, every other
        // strict prefix is a torn tail.
        for cut in 0..buf.len() {
            let outcome = Record::decode(&buf[..cut], &ident, Expect::Frame(TxnSeq(9)));
            if cut == 0 {
                assert!(matches!(outcome, Decoded::CleanEnd));
            } else {
                assert!(
                    matches!(outcome, Decoded::TornTail),
                    "prefix of {cut} bytes"
                );
            }
        }
    }

    #[test]
    fn record_bit_flips_never_validate() {
        let ident = ident();
        let buf = encode(&frame(9, sample_ops()), &ident);
        for at in 0..buf.len() {
            for bit in 0..8 {
                let mut flipped = buf.clone();
                flipped[at] ^= 1 << bit;
                match Record::decode(&flipped, &ident, Expect::Frame(TxnSeq(9))) {
                    Decoded::Record(..) => panic!("bit {bit} of byte {at} validated"),
                    // A leading zero is legitimately a clean end.
                    Decoded::CleanEnd => assert_eq!(flipped[0], 0),
                    Decoded::TornTail | Decoded::Corrupt(_) => {}
                }
            }
        }
    }

    #[test]
    fn record_binds_its_identity() {
        let ident = ident();
        let buf = encode(&frame(9, sample_ops()), &ident);

        // Wrong incarnation.
        let foreign = Identity {
            salt: Salt::new(&Incarnation(*b"ffffffffffffffff"), EPOCH),
            segment: SegmentSeq(7),
        };
        assert!(matches!(
            Record::decode(&buf, &foreign, Expect::Frame(TxnSeq(9))),
            Decoded::TornTail
        ));
        // Wrong epoch.
        let stale = Identity {
            salt: Salt::new(&INCARNATION, EPOCH + 1),
            segment: SegmentSeq(7),
        };
        assert!(matches!(
            Record::decode(&buf, &stale, Expect::Frame(TxnSeq(9))),
            Decoded::TornTail
        ));
        // Wrong segment.
        let moved = Identity {
            salt: Salt::new(&INCARNATION, EPOCH),
            segment: SegmentSeq(8),
        };
        assert!(matches!(
            Record::decode(&buf, &moved, Expect::Frame(TxnSeq(9))),
            Decoded::TornTail
        ));
        // Wrong transaction sequence.
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(10))),
            Decoded::TornTail
        ));
        // Wrong kind context: the checksum still binds (the kind byte is in
        // the domain), so this is a checksummed record that cannot belong to
        // the stream -- corruption, not a tear.
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Checkpoint(CheckpointSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn chunk_binds_its_checkpoint_attempt() {
        let ident = ident();
        let chunk = Record::CheckpointChunk(CheckpointChunk {
            seq: CheckpointSeq(5),
            rows: Vec::new(),
            extents: Vec::new(),
            segments: Vec::new(),
            next_log: LogId(1),
            next_txn: TxnSeq(1),
        });
        let buf = encode(&chunk, &ident);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Checkpoint(CheckpointSeq(5))),
            Decoded::Record(..)
        ));
        // Another attempt's range can never accept it.
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Checkpoint(CheckpointSeq(6))),
            Decoded::TornTail
        ));
        // Nor can a frame stream, even at the same numeric sequence.
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(5))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn record_unknown_kind_is_corrupt() {
        let ident = ident();
        let buf = envelope(&ident, 0xEE, 1, b"junk");
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(1))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn record_corruption_is_not_torn() {
        // A checksummed frame body with an unknown operation: tearing cannot
        // produce this.
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(1u32).write(&mut body);
        body.push(0xEE);
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn record_trailing_body_bytes_are_corrupt() {
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(0u32).write(&mut body); // no descriptors
        UInt(0u32).write(&mut body); // no blocks
        body.push(0xAB); // trailing garbage inside the checksummed body
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn record_binding_mismatch_in_body_is_corrupt() {
        // A body claiming one sequence under an envelope bound to another:
        // only a buggy writer can produce it, and it must not pass.
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(0u32).write(&mut body);
        UInt(0u32).write(&mut body);
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 10, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(10))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn frame_body_epoch_mismatch_is_corrupt() {
        // A body claiming another epoch under an envelope whose salt binds
        // this one: only a buggy writer can produce it.
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH + 1).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(0u32).write(&mut body);
        UInt(0u32).write(&mut body);
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn frame_non_canonical_tiling_is_corrupt() {
        // Three 1-byte blocks over a 3-byte run, every checksum correct: the
        // encoder produces one canonical block, so this is corruption.
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(1u32).write(&mut body);
        body.push(OP_APPEND);
        UInt(1u64).write(&mut body); // log
        UInt(0u64).write(&mut body); // generation
        UInt(0u64).write(&mut body); // committed
        UInt(3u64).write(&mut body); // run length
        UInt(3u32).write(&mut body); // three blocks
        for at in 0..3u64 {
            UInt(1u64).write(&mut body); // log
            UInt(at).write(&mut body);
            UInt(1u32).write(&mut body); // len
        }
        body.extend_from_slice(b"abc");
        for (at, byte) in b"abc".iter().enumerate() {
            let sum = block_crc(&ident.salt, LogId(1), LogOffset(at as u64), &[*byte]);
            body.extend_from_slice(&sum);
        }
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn record_hostile_length_is_torn() {
        let ident = ident();
        let mut buf = Vec::new();
        UInt(u32::MAX).write(&mut buf);
        buf.extend_from_slice(&[0xFF; 64]);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(1))),
            Decoded::TornTail
        ));
    }

    #[test]
    fn frame_hostile_ops_count_is_corrupt() {
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt((MAX_TRANSACTION_OPS + 1) as u32).write(&mut body);
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn frame_hostile_block_count_is_corrupt() {
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(0u32).write(&mut body); // no descriptors
        UInt((MAX_PAYLOAD_BLOCKS + 1) as u32).write(&mut body);
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn frame_hostile_payload_claim_is_corrupt() {
        // One compact append descriptor claiming a run over the payload cap.
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(1u32).write(&mut body);
        body.push(OP_APPEND);
        UInt(1u64).write(&mut body); // log
        UInt(0u64).write(&mut body); // generation
        UInt(0u64).write(&mut body); // committed
        UInt(MAX_TRANSACTION_PAYLOAD + 1).write(&mut body);
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn frame_hostile_name_is_corrupt() {
        let ident = ident();
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(1u32).write(&mut body);
        body.push(OP_CREATE);
        UInt(1u64).write(&mut body); // log
        UInt(0u64).write(&mut body); // generation
        UInt(0u64).write(&mut body); // committed
        UInt((MAX_LOG_NAME_LEN + 1) as u32).write(&mut body);
        let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn chunk_hostile_row_count_is_corrupt() {
        // A compact chunk claiming rows over the checkpoint cap: it must be
        // rejected before any allocation.
        let ident = ident();
        let mut body = Vec::new();
        UInt((MAX_CHECKPOINT_LOGS + 1) as u32).write(&mut body);
        let buf = envelope(&ident, KIND_CHECKPOINT_CHUNK, 5, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Checkpoint(CheckpointSeq(5))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn chunk_hostile_extent_count_is_corrupt() {
        let ident = ident();
        let mut body = Vec::new();
        UInt(0u32).write(&mut body); // no rows
        UInt((MAX_EXTENT_DELTAS + 1) as u32).write(&mut body);
        let buf = envelope(&ident, KIND_CHECKPOINT_CHUNK, 5, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Checkpoint(CheckpointSeq(5))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn chunk_hostile_segment_count_is_corrupt() {
        let ident = ident();
        let mut body = Vec::new();
        UInt(0u32).write(&mut body); // no rows
        UInt(0u32).write(&mut body); // no extents
        UInt((MAX_CHECKPOINT_SEGMENTS + 1) as u32).write(&mut body);
        let buf = envelope(&ident, KIND_CHECKPOINT_CHUNK, 5, &body);
        assert!(matches!(
            Record::decode(&buf, &ident, Expect::Checkpoint(CheckpointSeq(5))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn frame_envelope_vs_block_checksum() {
        let ident = ident();
        let ops = vec![(
            LogId(1),
            NetOp::Mutate {
                generation: 0,
                committed: 0,
                rewind_to: None,
                run: b"abc".to_vec(),
            },
        )];
        let buf = encode(&frame(9, ops), &ident);

        // A payload bit flip breaks the envelope checksum: a torn tail, and
        // the whole transaction applies nothing.
        let mut torn = buf.clone();
        let payload_at = buf.len() - 4 - 4 - 3; // block crc, envelope crc, run
        torn[payload_at] ^= 1;
        assert!(matches!(
            Record::decode(&torn, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::TornTail
        ));

        // A wrong per-block checksum under a valid envelope can only come from
        // a buggy writer: corruption.
        let mut body = Vec::new();
        UInt(EPOCH).write(&mut body);
        UInt(9u64).write(&mut body);
        UInt(1u32).write(&mut body);
        body.push(OP_APPEND);
        UInt(1u64).write(&mut body);
        UInt(0u64).write(&mut body);
        UInt(0u64).write(&mut body);
        UInt(3u64).write(&mut body);
        UInt(1u32).write(&mut body); // one block
        UInt(1u64).write(&mut body); // log
        UInt(0u64).write(&mut body); // at
        UInt(3u32).write(&mut body); // len
        body.extend_from_slice(b"abc");
        body.extend_from_slice(&[0u8; 4]); // wrong block checksum
        let forged = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
        assert!(matches!(
            Record::decode(&forged, &ident, Expect::Frame(TxnSeq(9))),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn frame_descriptor_violations_are_corrupt() {
        let ident = ident();
        // Each case is a hand-built descriptor section under a valid envelope.
        type Case = Box<dyn Fn(&mut Vec<u8>)>;
        let cases: Vec<Case> = vec![
            // Logs out of canonical order.
            Box::new(|body| {
                UInt(2u32).write(body);
                for log in [2u64, 1u64] {
                    body.push(OP_REMOVE);
                    UInt(log).write(body);
                    UInt(0u64).write(body);
                    UInt(0u64).write(body);
                }
                UInt(0u32).write(body);
            }),
            // Rewind not below the committed length.
            Box::new(|body| {
                UInt(1u32).write(body);
                body.push(OP_REWIND);
                UInt(1u64).write(body);
                UInt(0u64).write(body);
                UInt(5u64).write(body); // committed
                UInt(5u64).write(body); // to == committed
                UInt(0u32).write(body);
            }),
            // Create with a nonzero expected state.
            Box::new(|body| {
                UInt(1u32).write(body);
                body.push(OP_CREATE);
                UInt(1u64).write(body);
                UInt(1u64).write(body); // generation
                UInt(0u64).write(body);
                UInt(0u32).write(body); // empty name
                body.extend_from_slice(&RESERVED_LOG_BYTES);
                UInt(0u32).write(body);
            }),
            // Nonzero reserved log bytes.
            Box::new(|body| {
                UInt(1u32).write(body);
                body.push(OP_CREATE);
                UInt(1u64).write(body);
                UInt(0u64).write(body);
                UInt(0u64).write(body);
                UInt(0u32).write(body);
                body.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
                UInt(0u32).write(body);
            }),
            // An append whose gen/committed disagree with its rewind.
            Box::new(|body| {
                UInt(2u32).write(body);
                body.push(OP_REWIND);
                UInt(1u64).write(body);
                UInt(3u64).write(body);
                UInt(10u64).write(body);
                UInt(2u64).write(body);
                body.push(OP_APPEND);
                UInt(1u64).write(body);
                UInt(4u64).write(body); // generation mismatch
                UInt(10u64).write(body);
                UInt(1u64).write(body);
                UInt(0u32).write(body);
            }),
            // An append of zero bytes.
            Box::new(|body| {
                UInt(1u32).write(body);
                body.push(OP_APPEND);
                UInt(1u64).write(body);
                UInt(0u64).write(body);
                UInt(0u64).write(body);
                UInt(0u64).write(body);
                UInt(0u32).write(body);
            }),
            // Blocks that do not tile the append run.
            Box::new(|body| {
                UInt(1u32).write(body);
                body.push(OP_APPEND);
                UInt(1u64).write(body);
                UInt(0u64).write(body);
                UInt(0u64).write(body);
                UInt(3u64).write(body);
                UInt(1u32).write(body);
                UInt(1u64).write(body);
                UInt(1u64).write(body); // block starts past the anchor
                UInt(3u32).write(body);
                body.extend_from_slice(b"abc");
                body.extend_from_slice(&[0u8; 4]);
            }),
        ];
        for (i, write_rest) in cases.iter().enumerate() {
            let mut body = Vec::new();
            UInt(EPOCH).write(&mut body);
            UInt(9u64).write(&mut body);
            write_rest(&mut body);
            let buf = envelope(&ident, KIND_TRANSACTION_FRAME, 9, &body);
            assert!(
                matches!(
                    Record::decode(&buf, &ident, Expect::Frame(TxnSeq(9))),
                    Decoded::Corrupt(_)
                ),
                "case {i}"
            );
        }
    }

    #[test]
    fn block_crc_binds_log_and_offset() {
        let salt = Salt::new(&INCARNATION, EPOCH);
        let sum = block_crc(&salt, LogId(1), LogOffset(100), b"data");
        assert_ne!(sum, block_crc(&salt, LogId(2), LogOffset(100), b"data"));
        assert_ne!(sum, block_crc(&salt, LogId(1), LogOffset(101), b"data"));
        let other = Salt::new(&INCARNATION, EPOCH + 1);
        assert_ne!(sum, block_crc(&other, LogId(1), LogOffset(100), b"data"));
    }

    #[test]
    fn relocated_extent_wrong_block_checksum_is_corrupt() {
        let ident = ident();
        let mut body = Vec::new();
        UInt(4u64).write(&mut body);
        UInt(9000u64).write(&mut body);
        UInt(4u32).write(&mut body);
        body.extend_from_slice(b"data");
        body.extend_from_slice(&[0u8; 4]); // wrong block checksum
        let buf = envelope(&ident, KIND_RELOCATED_EXTENT, 0, &body);
        let expect = Expect::Relocated {
            log: LogId(4),
            at: LogOffset(9000),
        };
        assert!(matches!(
            Record::decode(&buf, &ident, expect),
            Decoded::Corrupt(_)
        ));
    }

    #[test]
    fn validated_txn_rejections() {
        let seq = TxnSeq(9);
        // Too many logs.
        let ops = (0..MAX_LOGS_TOUCHED as u64 + 1)
            .map(|i| {
                (
                    LogId(i),
                    NetOp::Remove {
                        generation: 0,
                        committed: 0,
                    },
                )
            })
            .collect();
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, ops),
            Err(Error::TransactionTooLarge(_))
        ));
        // Not in canonical order.
        let unsorted = vec![
            (
                LogId(2),
                NetOp::Remove {
                    generation: 0,
                    committed: 0,
                },
            ),
            (
                LogId(1),
                NetOp::Remove {
                    generation: 0,
                    committed: 0,
                },
            ),
        ];
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, unsorted),
            Err(Error::InvalidTransaction(_))
        ));
        // Duplicate log.
        let duplicated = vec![
            (
                LogId(1),
                NetOp::Remove {
                    generation: 0,
                    committed: 0,
                },
            ),
            (
                LogId(1),
                NetOp::Remove {
                    generation: 0,
                    committed: 0,
                },
            ),
        ];
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, duplicated),
            Err(Error::InvalidTransaction(_))
        ));
        // Oversized name.
        let named = vec![(
            LogId(1),
            NetOp::Create {
                name: vec![b'n'; MAX_LOG_NAME_LEN + 1],
                run: Vec::new(),
            },
        )];
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, named),
            Err(Error::InvalidTransaction(_))
        ));
        // Rewind not below the committed length.
        let rewound = vec![(
            LogId(1),
            NetOp::Mutate {
                generation: 0,
                committed: 5,
                rewind_to: Some(5),
                run: Vec::new(),
            },
        )];
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, rewound),
            Err(Error::InvalidTransaction(_))
        ));
        // A mutation with no effect.
        let noop = vec![(
            LogId(1),
            NetOp::Mutate {
                generation: 0,
                committed: 5,
                rewind_to: None,
                run: Vec::new(),
            },
        )];
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, noop),
            Err(Error::InvalidTransaction(_))
        ));
        // A run overflowing the log length.
        let overflowing = vec![(
            LogId(1),
            NetOp::Mutate {
                generation: 0,
                committed: u64::MAX,
                rewind_to: None,
                run: vec![0u8; 2],
            },
        )];
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, overflowing),
            Err(Error::InvalidTransaction(_))
        ));
        // Payload over the cap (zeroed pages, so cheap to allocate).
        let oversized = vec![(
            LogId(1),
            NetOp::Mutate {
                generation: 0,
                committed: 0,
                rewind_to: None,
                run: vec![0u8; MAX_TRANSACTION_PAYLOAD as usize + 1],
            },
        )];
        assert!(matches!(
            ValidatedTxn::new(EPOCH, seq, oversized),
            Err(Error::TransactionTooLarge(_))
        ));
    }
}
