//! On-disk formats for the volume: superblock and blob table.
//!
//! Layout of the volume file (offsets in the inner blob's logical space):
//!
//! ```text
//! +----------------+----------------+------------------------------------+
//! | superblock A   | superblock B   | block-aligned extents (data,       |
//! | (block 0)      | (block 1)      |  checksum blocks, shadows, tables) |
//! +----------------+----------------+------------------------------------+
//! ```
//!
//! Commits alternate superblock slots (never touching the slot that holds
//! the last confirmed commit) and shadow-write the entire table to a fresh
//! extent. The superblock binds the table by a CRC over its exact bytes;
//! this binding is load-bearing against recycled-extent aliasing, not just
//! bit rot (see the model docs).
//!
//! Checksums are stored OUT OF BAND: data extents hold pure blob content in
//! whole [`BLOCK`]-sized blocks at block-aligned offsets, and the CRCs
//! covering them live in separate checksum extents (below, [`ChecksumRef`]).
//! No per-block header or trailer widens the data stride, so a
//! block-aligned block-sized read maps to exactly one aligned block-sized
//! read of the volume file. An inline BLOCK+checksum stride would instead
//! straddle two physical blocks on every such read.
//!
//! All multi-byte integers are big-endian. Every structure is terminated by
//! a CRC32C over the preceding bytes.

use super::{
    alloc::{block_align, Extent},
    BLOCK,
};
use bytes::{Buf, BufMut};
use commonware_cryptography::Crc32;

/// Superblock layout (fixed size, one per slot):
///
/// ```text
/// | magic (4B) | version (2B) | seq (8B) | table_offset (8B)
/// | table_len (4B) | table_crc (4B) | crc (4B) |
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Superblock {
    /// Commit sequence number.
    pub seq: u64,
    /// Physical offset of the table extent.
    pub table_offset: u64,
    /// Exact byte length of the encoded table.
    pub table_len: u32,
    /// CRC32C over the table bytes (the content binding).
    pub table_crc: u32,
}

impl Superblock {
    pub const MAGIC: [u8; 4] = *b"CWVL";
    pub const FORMAT_VERSION: u16 = 0;
    pub const SIZE: usize = 4 + 2 + 8 + 8 + 4 + 4 + 4;

    /// Offset of superblock slot `slot` (0 or 1).
    pub fn slot_offset(slot: u8) -> u64 {
        debug_assert!(slot < 2);
        slot as u64 * BLOCK
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.put_slice(&Self::MAGIC);
        out.put_u16(Self::FORMAT_VERSION);
        out.put_u64(self.seq);
        out.put_u64(self.table_offset);
        out.put_u32(self.table_len);
        out.put_u32(self.table_crc);
        let crc = Crc32::checksum(&out);
        out.put_u32(crc);
        out
    }

    /// Decode and validate a superblock slot. Any deviation (bad magic,
    /// version, or CRC) yields `None`: an invalid slot, not an error — slot
    /// selection treats it as absent.
    pub fn decode(mut buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let crc = Crc32::checksum(&buf[..Self::SIZE - 4]);
        let mut magic = [0u8; 4];
        buf.copy_to_slice(&mut magic);
        if magic != Self::MAGIC {
            return None;
        }
        if buf.get_u16() != Self::FORMAT_VERSION {
            return None;
        }
        let decoded = Self {
            seq: buf.get_u64(),
            table_offset: buf.get_u64(),
            table_len: buf.get_u32(),
            table_crc: buf.get_u32(),
        };
        (buf.get_u32() == crc).then_some(decoded)
    }
}

/// A written run: `len` bytes of blob data at `logical` backed at `physical`.
///
/// Runs cover only WRITTEN ranges; logical gaps between runs are holes that
/// read as zeros. Physical ranges are block-aligned at both ends (writes
/// zero-fill block edges), except that `len` is exact for the final run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Run {
    pub logical: u64,
    pub physical: u64,
    pub len: u64,
}

impl Run {
    /// The extent backing this run: starts are block-aligned and the
    /// allocation covers the written length rounded up to whole blocks.
    pub const fn extent(&self) -> Extent {
        Extent {
            offset: self.physical,
            len: block_align(self.len),
        }
    }
}

/// A checksum extent: CRC32Cs for `count` consecutive chunks starting at
/// `first_chunk`, stored at `offset`, guarded by `crc` over its bytes.
///
/// An entry's refs are disjoint and contiguous from chunk 0, and together
/// cover every backed chunk below the frontier plus a FULL frontier chunk
/// (a partial frontier chunk is served by the entry's `tail_crc` instead).
/// Hole positions inside the covered range hold arbitrary values and are
/// never consulted. An append-shaped commit extends coverage by appending
/// one new ref and keeps the prior refs' extents untouched. Any other dirt
/// shape rewrites the whole array as a single ref (see the commit module).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ChecksumRef {
    pub first_chunk: u64,
    pub count: u32,
    pub offset: u64,
    pub crc: u32,
}

/// One blob's entry in the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    /// Volume-unique id, monotonic, never reused.
    pub id: u64,
    /// Index into the table's partition list.
    pub partition: u32,
    pub name: Vec<u8>,
    pub version: u16,
    /// Committed logical size in bytes.
    pub size: u64,
    /// Pruned floor: bytes below this offset were dropped and their reads
    /// fail. Byte-exact. Runs never start below its chunk, and checksum
    /// refs cover from at most its chunk.
    pub floor: u64,
    pub runs: Vec<Run>,
    pub checksums: Vec<ChecksumRef>,
    /// CRC over the written span of the final backed chunk, full or
    /// partial (0 when no chunk is backed). Hydration verifies the
    /// frontier against it without touching the checksum extents, and
    /// recovery consults it for partial frontier chunks, whose CRC the
    /// checksum refs do not cover.
    pub tail_crc: u32,
    /// Physical offset of the shadow block holding the committed bytes of
    /// the final BACKED chunk's span, when that span is partial (the last
    /// backed chunk may sit below trailing hole chunks after a sparse
    /// resize). Absent when no chunk is backed or the last backed chunk's
    /// span fills a whole block.
    pub shadow: Option<u64>,
}

/// The blob table: the complete durable state of a commit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Table {
    /// Commit seq (informational; the superblock CRC is the binding).
    pub seq: u64,
    /// Next blob id to allocate (ids are never reused).
    pub next_id: u64,
    /// All partitions, including empty ones (partition existence is
    /// first-class: scan of an empty partition succeeds).
    pub partitions: Vec<String>,
    pub blobs: Vec<Entry>,
    /// Chunks whose content changed in THIS commit — plus each captured
    /// blob's frontier chunk whenever the capture wrote a fresh shadow —
    /// as (blob id, chunk index). Recovery verifies exactly these to
    /// distinguish a fully-landed commit from a torn one; the manifested
    /// frontier makes it check the fresh shadow's content (recovery's
    /// splice is a raw byte copy and must never write an unverified
    /// shadow).
    pub manifest: Vec<(u64, u64)>,
}

impl Entry {
    /// The entry of a live blob that no commit has captured with content:
    /// empty, unresolved partition index. Table assembly and demotion must
    /// produce the identical entry for such a blob (assembly emits one for
    /// EVERY live blob, and a demoted blob's entry is served verbatim).
    pub const fn empty(id: u64, name: Vec<u8>, version: u16) -> Self {
        Self {
            id,
            partition: 0,
            name,
            version,
            size: 0,
            floor: 0,
            runs: Vec::new(),
            checksums: Vec::new(),
            tail_crc: 0,
            shadow: None,
        }
    }

    /// Encode this entry's byte run within a table.
    ///
    /// Entries encode independently so commits can reuse cached encodings
    /// for blobs they do not capture (table assembly is O(captured), not
    /// O(all blobs)). The concatenation of per-entry runs is byte-identical
    /// to the monolithic [`Table::encode`].
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.name.len() + self.runs.len() * 24);
        out.put_u64(self.id);
        out.put_u32(self.partition);
        out.put_u32(self.name.len() as u32);
        out.put_slice(&self.name);
        out.put_u16(self.version);
        out.put_u64(self.size);
        out.put_u64(self.floor);
        out.put_u32(self.runs.len() as u32);
        for r in &self.runs {
            out.put_u64(r.logical);
            out.put_u64(r.physical);
            out.put_u64(r.len);
        }
        out.put_u32(self.checksums.len() as u32);
        for c in &self.checksums {
            out.put_u64(c.first_chunk);
            out.put_u32(c.count);
            out.put_u64(c.offset);
            out.put_u32(c.crc);
        }
        out.put_u32(self.tail_crc);
        match self.shadow {
            Some(offset) => {
                out.put_u8(1);
                out.put_u64(offset);
            }
            None => out.put_u8(0),
        }
        out
    }
}

impl Table {
    /// Encode with a terminating CRC32C.
    pub fn encode(&self) -> Vec<u8> {
        Self::assemble(
            self.seq,
            self.next_id,
            &self.partitions,
            self.blobs.iter().map(Entry::encode).collect(),
            &self.manifest,
        )
    }

    /// Assemble a table's bytes from pre-encoded entry runs (in blob-id
    /// order). This is the single definition of the table format; the
    /// commit path feeds it cached entry encodings.
    pub fn assemble(
        seq: u64,
        next_id: u64,
        partitions: &[String],
        entries: Vec<impl AsRef<[u8]>>,
        manifest: &[(u64, u64)],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1024 + entries.iter().map(|e| e.as_ref().len()).sum::<usize>() + manifest.len() * 16,
        );
        out.put_u64(seq);
        out.put_u64(next_id);
        out.put_u32(partitions.len() as u32);
        for p in partitions {
            out.put_u32(p.len() as u32);
            out.put_slice(p.as_bytes());
        }
        out.put_u32(entries.len() as u32);
        for e in entries {
            out.put_slice(e.as_ref());
        }
        out.put_u32(manifest.len() as u32);
        for &(id, chunk) in manifest {
            out.put_u64(id);
            out.put_u64(chunk);
        }
        let crc = Crc32::checksum(&out);
        out.put_u32(crc);
        out
    }

    /// Decode a table whose bytes already passed the superblock's CRC
    /// binding. Returns `None` on any structural violation (which, given the
    /// binding, indicates corruption rather than a torn write).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let (body, crc_bytes) = bytes.split_at(bytes.len() - 4);
        let stored = u32::from_be_bytes(crc_bytes.try_into().ok()?);
        if Crc32::checksum(body) != stored {
            return None;
        }
        let mut buf = body;
        let take = |buf: &mut &[u8], n: usize| -> Option<Vec<u8>> {
            if buf.len() < n {
                return None;
            }
            let (head, rest) = buf.split_at(n);
            let out = head.to_vec();
            *buf = rest;
            Some(out)
        };
        let need = |buf: &&[u8], n: usize| -> Option<()> { (buf.len() >= n).then_some(()) };

        need(&buf, 20)?;
        let seq = buf.get_u64();
        let next_id = buf.get_u64();
        let n_partitions = buf.get_u32() as usize;
        let mut partitions = Vec::with_capacity(n_partitions.min(1024));
        for _ in 0..n_partitions {
            need(&buf, 4)?;
            let len = buf.get_u32() as usize;
            let bytes = take(&mut buf, len)?;
            partitions.push(String::from_utf8(bytes).ok()?);
        }
        need(&buf, 4)?;
        let n_blobs = buf.get_u32() as usize;
        let mut blobs = Vec::with_capacity(n_blobs.min(1024));
        for _ in 0..n_blobs {
            need(&buf, 16)?;
            let id = buf.get_u64();
            let partition = buf.get_u32();
            let name_len = buf.get_u32() as usize;
            let name = take(&mut buf, name_len)?;
            need(&buf, 22)?;
            let version = buf.get_u16();
            let size = buf.get_u64();
            let floor = buf.get_u64();
            let n_runs = buf.get_u32() as usize;
            let mut runs = Vec::with_capacity(n_runs.min(1024));
            for _ in 0..n_runs {
                need(&buf, 24)?;
                runs.push(Run {
                    logical: buf.get_u64(),
                    physical: buf.get_u64(),
                    len: buf.get_u64(),
                });
            }
            need(&buf, 4)?;
            let n_checksums = buf.get_u32() as usize;
            let mut checksums = Vec::with_capacity(n_checksums.min(1024));
            for _ in 0..n_checksums {
                need(&buf, 24)?;
                checksums.push(ChecksumRef {
                    first_chunk: buf.get_u64(),
                    count: buf.get_u32(),
                    offset: buf.get_u64(),
                    crc: buf.get_u32(),
                });
            }
            need(&buf, 5)?;
            let tail_crc = buf.get_u32();
            let shadow = match buf.get_u8() {
                0 => None,
                1 => {
                    need(&buf, 8)?;
                    Some(buf.get_u64())
                }
                _ => return None,
            };
            blobs.push(Entry {
                id,
                partition,
                name,
                version,
                size,
                floor,
                runs,
                checksums,
                tail_crc,
                shadow,
            });
        }
        need(&buf, 4)?;
        let n_manifest = buf.get_u32() as usize;
        let mut manifest = Vec::with_capacity(n_manifest.min(4096));
        for _ in 0..n_manifest {
            need(&buf, 16)?;
            manifest.push((buf.get_u64(), buf.get_u64()));
        }
        if !buf.is_empty() {
            return None;
        }
        Some(Self {
            seq,
            next_id,
            partitions,
            blobs,
            manifest,
        })
    }
}

#[cfg(kani)]
mod verification {
    //! Kani proofs that the layout decoders are total: for ANY input within
    //! the stated size bound they return `Some` or `None` without panicking,
    //! overflowing, or reading out of bounds. Recovery feeds these decoders
    //! raw disk bytes before any checksum has vouched for them.
    //!
    //! Scope: inputs are bounded by the harness constants below, and the
    //! proofs check only totality plus the stated postconditions. Nothing is
    //! claimed about inputs larger than the bound, and nothing is claimed
    //! about the semantic validity of accepted values beyond those
    //! postconditions.
    //!
    //! Every loop in [`Table::decode`] consumes at least 4 bytes of input
    //! per iteration (partitions: 4 plus the name, entries: at least 47,
    //! runs and checksum refs: 24, manifest: 16), so iteration counts are
    //! bounded by the input length and the unwind bounds below are sound.

    use super::{Superblock, Table};

    /// Replacement for [`commonware_cryptography::Crc32::checksum`] under
    /// verification. The real implementation dispatches into `crc_fast`
    /// (SIMD kernels behind runtime CPU-feature detection, which Kani
    /// cannot execute) and its result only gates acceptance. Returning an
    /// unconstrained value is sound for totality: the real function returns
    /// one specific u32 per input, so every real execution is contained in
    /// the behaviors explored with the stub.
    ///
    /// Referenced only through `kani::stub` attributes, which dead-code
    /// analysis does not see.
    #[allow(dead_code)]
    fn any_checksum(_data: &[u8]) -> u32 {
        kani::any()
    }

    /// Covers [`Superblock::SIZE`] (34 bytes) plus slack.
    const SUPERBLOCK_BOUND: usize = 40;

    /// [`Superblock::decode`] is total for any input of at most
    /// [`SUPERBLOCK_BOUND`] bytes, and every accepted superblock's fields
    /// equal the big-endian decoding of the corresponding input bytes.
    #[kani::proof]
    #[kani::stub(commonware_cryptography::Crc32::checksum, any_checksum)]
    fn superblock_decode_total() {
        let buf: [u8; SUPERBLOCK_BOUND] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= SUPERBLOCK_BOUND);
        let Some(sb) = Superblock::decode(&buf[..n]) else {
            return;
        };
        assert_eq!(sb.seq, u64::from_be_bytes(buf[6..14].try_into().unwrap()));
        assert_eq!(
            sb.table_offset,
            u64::from_be_bytes(buf[14..22].try_into().unwrap())
        );
        assert_eq!(
            sb.table_len,
            u32::from_be_bytes(buf[22..26].try_into().unwrap())
        );
        assert_eq!(
            sb.table_crc,
            u32::from_be_bytes(buf[26..30].try_into().unwrap())
        );
    }

    /// Replacement for [`core::str::from_utf8`] under verification that
    /// makes the validation VERDICT nondeterministic without running the
    /// validation loops (whose unrolling inside the unrolled partition-name
    /// loop makes the [`TABLE_BOUND`] harness intractable). Both variants
    /// are explored for every input: the `Ok` carries the input bytes
    /// unvalidated, and the `Err` is a real [`core::str::Utf8Error`]
    /// obtained by validating a concrete invalid byte through the sibling
    /// [`core::str::from_utf8_mut`], which this stub does not replace.
    /// [`String::from_utf8`] then builds its own error value around it, so
    /// decode's rejection path runs unmodified. This is sound for totality:
    /// the real function returns one of these two variants per input, so
    /// every real execution is contained in the behaviors explored here.
    ///
    /// Referenced only through `kani::stub` attributes, which dead-code
    /// analysis does not see.
    #[allow(dead_code)]
    fn any_utf8_verdict(v: &[u8]) -> Result<&str, core::str::Utf8Error> {
        if kani::any() {
            // SAFETY: the result is never read as UTF-8. Decode only wraps
            // it into a stored `String`, and the harness only takes its
            // byte length, so the invalid contents this branch can admit
            // are never observed as `str`.
            Ok(unsafe { core::str::from_utf8_unchecked(v) })
        } else {
            let mut invalid = [0xffu8];
            Err(core::str::from_utf8_mut(&mut invalid).unwrap_err())
        }
    }

    /// Replacement for [`Vec::with_capacity`] under verification. The
    /// capacity is a pure allocation hint, so deferring to [`Vec::new`]
    /// is observably identical (pushes reallocate on demand), and it is
    /// what makes the table harnesses tractable: decode preallocates
    /// `count.min(1024)` slots per vector, and bit-blasting materializes
    /// every such symbolic-size heap array at full width during SAT
    /// conversion, which exhausts memory.
    ///
    /// Referenced only through `kani::stub` attributes, which dead-code
    /// analysis does not see.
    #[allow(dead_code)]
    fn vec_no_capacity_hint<T>(_capacity: usize) -> Vec<T> {
        Vec::new()
    }

    /// The exact byte length [`Table::encode`] would produce for `table`.
    fn encoded_len(table: &Table) -> usize {
        let mut len = 8 + 8 + 4;
        for p in &table.partitions {
            len += 4 + p.len();
        }
        len += 4;
        for e in &table.blobs {
            len += 8 + 4 + 4 + e.name.len() + 2 + 8 + 8;
            len += 4 + e.runs.len() * 24;
            len += 4 + e.checksums.len() * 24;
            len += 4 + 1 + if e.shadow.is_some() { 8 } else { 0 };
        }
        len + 4 + table.manifest.len() * 16 + 4
    }

    /// Bound for the entry-focused harness. 87 bytes admit an accepted
    /// table holding one complete entry (79 bytes) or one entry with a
    /// present shadow (87), with every field inside the entry symbolic.
    /// The run and checksum loops execute their hostile-count and
    /// truncation paths here (a complete 24-byte iteration needs 94
    /// bytes), and their complete-iteration path is covered by
    /// [`table_decode_total_full_shape`]. Larger bounds do not fit: the
    /// formula for this harness at 111 bytes already exhausts a 64 GB
    /// machine during SAT solving under Kani 0.67.
    const TABLE_ENTRY_BOUND: usize = 87;

    /// [`Table::decode`] is total for any input of at most
    /// [`TABLE_ENTRY_BOUND`] bytes whose partition-count field holds zero
    /// and whose blob-count field holds one, with the UTF-8 validation
    /// verdict made nondeterministic by [`any_utf8_verdict`], and every
    /// accepted table re-encodes to exactly the input length (the
    /// exact-consumption contract). Everything inside the entry stays
    /// symbolic: name length, run and checksum counts, shadow flag, and
    /// the manifest count. Inputs that declare partitions are covered by
    /// [`table_decode_total_partitions`] up to its smaller bound, and the
    /// full-feature shape by [`table_decode_total_full_shape`].
    ///
    /// The count bytes are pinned by assignment rather than `assume` so
    /// constant propagation removes the partition loop and all but one
    /// blob iteration from the unrolled program (an assumed-equal
    /// symbolic count would still unroll every nest, which does not fit
    /// in memory).
    ///
    /// The unwind bound is set by the manifest loop: at most 3 complete
    /// 16-byte items fit in the bytes after the fixed header and counts,
    /// plus a failing iteration, plus the unwinding check.
    #[kani::proof]
    #[kani::unwind(5)]
    #[kani::solver(kissat)]
    #[kani::stub(commonware_cryptography::Crc32::checksum, any_checksum)]
    #[kani::stub(core::str::from_utf8, any_utf8_verdict)]
    #[kani::stub(std::vec::Vec::with_capacity, vec_no_capacity_hint)]
    fn table_decode_total_entries() {
        let mut buf: [u8; TABLE_ENTRY_BOUND] = kani::any();
        buf[16] = 0;
        buf[17] = 0;
        buf[18] = 0;
        buf[19] = 0;
        buf[20] = 0;
        buf[21] = 0;
        buf[22] = 0;
        buf[23] = 1;
        let n: usize = kani::any();
        kani::assume(n <= TABLE_ENTRY_BOUND);
        let Some(table) = Table::decode(&buf[..n]) else {
            return;
        };
        assert_eq!(encoded_len(&table), n);
    }

    /// The exact size of the one-of-everything encoding: one partition
    /// with a 1-byte name, one entry with a 1-byte name, one run, one
    /// checksum ref, a present shadow, and one manifest item.
    const TABLE_FULL_SHAPE_BOUND: usize = 157;

    /// [`Table::decode`] is total for any input of at most
    /// [`TABLE_FULL_SHAPE_BOUND`] bytes whose count, length, and flag
    /// fields hold the one-of-everything shape above (pinned by
    /// assignment, everything else symbolic: both names, ids, offsets,
    /// sizes, floors, CRCs, and the input length), and every accepted
    /// table re-encodes to exactly the input length. With every loop
    /// count concrete the unrolled program is nearly straight-line, so
    /// this covers the full-feature acceptance path that the bounded
    /// harnesses above cannot reach.
    #[kani::proof]
    #[kani::unwind(3)]
    #[kani::solver(kissat)]
    #[kani::stub(commonware_cryptography::Crc32::checksum, any_checksum)]
    #[kani::stub(core::str::from_utf8, any_utf8_verdict)]
    #[kani::stub(std::vec::Vec::with_capacity, vec_no_capacity_hint)]
    fn table_decode_total_full_shape() {
        let mut buf: [u8; TABLE_FULL_SHAPE_BOUND] = kani::any();
        // Partition count 1 at body bytes 16..20, then a 1-byte name.
        (buf[16], buf[17], buf[18], buf[19]) = (0, 0, 0, 1);
        (buf[20], buf[21], buf[22], buf[23]) = (0, 0, 0, 1);
        // Blob count 1 at 25..29 (the name occupies byte 24).
        (buf[25], buf[26], buf[27], buf[28]) = (0, 0, 0, 1);
        // Entry name length 1 at 41..45 (id 29..37, partition 37..41).
        (buf[41], buf[42], buf[43], buf[44]) = (0, 0, 0, 1);
        // Run count 1 at 64..68 (name 45, version 46..48, size 48..56,
        // floor 56..64), then one 24-byte run.
        (buf[64], buf[65], buf[66], buf[67]) = (0, 0, 0, 1);
        // Checksum-ref count 1 at 92..96, then one 24-byte ref.
        (buf[92], buf[93], buf[94], buf[95]) = (0, 0, 0, 1);
        // Shadow flag 1 at 124 (tail_crc 120..124), then the offset.
        buf[124] = 1;
        // Manifest count 1 at 133..137, then one 16-byte item and the CRC.
        (buf[133], buf[134], buf[135], buf[136]) = (0, 0, 0, 1);
        let n: usize = kani::any();
        kani::assume(n <= TABLE_FULL_SHAPE_BOUND);
        let Some(table) = Table::decode(&buf[..n]) else {
            return;
        };
        assert_eq!(encoded_len(&table), n);
    }

    /// Bound for the partition-focused harness: room for 3 complete
    /// partition-loop iterations with names up to 8 bytes (every UTF-8
    /// error class fits in 4), and a table with one empty-named partition
    /// is accepted at exactly this bound. Sized to the largest formula
    /// CBMC can bit-blast within this machine's memory.
    const TABLE_PARTITIONS_BOUND: usize = 36;

    /// Same statement as [`table_decode_total_entries`] for any input of
    /// at most [`TABLE_PARTITIONS_BOUND`] bytes with NO pinned fields: no
    /// count is constrained and the partition loop runs to its byte-driven
    /// limit of 3 complete iterations.
    #[kani::proof]
    #[kani::unwind(5)]
    #[kani::solver(kissat)]
    #[kani::stub(commonware_cryptography::Crc32::checksum, any_checksum)]
    #[kani::stub(core::str::from_utf8, any_utf8_verdict)]
    #[kani::stub(std::vec::Vec::with_capacity, vec_no_capacity_hint)]
    fn table_decode_total_partitions() {
        let buf: [u8; TABLE_PARTITIONS_BOUND] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= TABLE_PARTITIONS_BOUND);
        let Some(table) = Table::decode(&buf[..n]) else {
            return;
        };
        assert_eq!(encoded_len(&table), n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superblock_round_trip() {
        let sb = Superblock {
            seq: 42,
            table_offset: 8192,
            table_len: 517,
            table_crc: 0xdeadbeef,
        };
        let bytes = sb.encode();
        assert_eq!(bytes.len(), Superblock::SIZE);
        assert_eq!(Superblock::decode(&bytes), Some(sb.clone()));

        // Any flipped byte invalidates the slot.
        for i in 0..bytes.len() {
            let mut bad = sb.encode();
            bad[i] ^= 0xff;
            assert_eq!(Superblock::decode(&bad), None, "byte {i}");
        }
        // Short buffer is invalid.
        assert_eq!(Superblock::decode(&bytes[..Superblock::SIZE - 1]), None);
    }

    #[test]
    fn test_table_round_trip() {
        let table = Table {
            seq: 7,
            next_id: 3,
            partitions: vec!["wal".into(), "index".into()],
            blobs: vec![
                Entry {
                    id: 1,
                    partition: 0,
                    name: b"section-1".to_vec(),
                    version: 0,
                    size: 12345,
                    floor: 4096,
                    runs: vec![
                        Run {
                            logical: 0,
                            physical: 8192,
                            len: 8192,
                        },
                        Run {
                            logical: 8192,
                            physical: 65536,
                            len: 4153,
                        },
                    ],
                    checksums: vec![ChecksumRef {
                        first_chunk: 0,
                        count: 3,
                        offset: 4096 * 7,
                        crc: 99,
                    }],
                    tail_crc: 123,
                    shadow: Some(4096 * 9),
                },
                Entry {
                    id: 2,
                    partition: 1,
                    name: vec![],
                    version: 3,
                    size: 0,
                    floor: 0,
                    runs: vec![],
                    checksums: vec![],
                    tail_crc: 0,
                    shadow: None,
                },
            ],
            manifest: vec![(1, 0), (1, 3)],
        };
        let bytes = table.encode();
        assert_eq!(Table::decode(&bytes), Some(table.clone()));

        // Truncation and bit flips are rejected.
        assert_eq!(Table::decode(&bytes[..bytes.len() - 1]), None);
        for i in [0usize, 8, bytes.len() / 2, bytes.len() - 1] {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert_eq!(Table::decode(&bad), None, "byte {i}");
        }
        // Trailing garbage is rejected (exact-consumption contract).
        let mut padded = table.encode();
        let crc_start = padded.len() - 4;
        padded.insert(crc_start, 0);
        assert_eq!(Table::decode(&padded), None);
    }

    #[test]
    fn test_empty_table_round_trip() {
        let table = Table::default();
        assert_eq!(Table::decode(&table.encode()), Some(table));
    }
}
