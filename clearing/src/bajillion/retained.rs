//! Change-proof dealing: each proof slice is its span's share of the posted close plus the
//! slice witness, applied to a retained interval.
//!
//! A dealt slice is a subset of the close, not a re-materialized proof. Every assignee
//! retains its assigned span's live leaves across closes (an [Interval]), so the dealt form
//! ([DealtSlice]) ships exactly what the posted corpus ships for those rows plus what binds
//! the fragment to the certified roots. On the wire a dealt slice is one span-level witness
//! followed by one chunk per covered slice:
//!
//! - **The witness** ships once per span: the retained count, the span, the covered
//!   coverage boundaries, each covered slice's combined operator countersignature, the
//!   accumulator start states at the first boundary, the range openings, and the change
//!   and state guards.
//! - **A chunk** ships one slice's rows, its senders' outgoing entries, and its transpose
//!   range. Rows travel as the posted row wire: a rank-gap reference into the slice's
//!   retained leaves (or a full key for an account not yet live) and, for senders, the
//!   sequence number and payer signature. The first row's gap counts from the slice's first
//!   retained leaf rather than from the previous slice's last row, so a chunk's bytes do not
//!   depend on the span carrying it. Outgoing entries keep full recipient keys: they are
//!   the payer-signed leaf bytes, fixed before the close is ordered, so no row indexing can
//!   apply. The transpose range ships because recipient credit is proven by it and its
//!   entries originate from payers outside the span.
//!
//! The operator therefore encodes every chunk once per close ([Dealings]) and ships each
//! span as its witness followed by clones of the covered chunks ([Wire]), so dealing costs
//! one pass over the corpus however many spans overlap. Row, entry, and transpose counts
//! per chunk are pinned by the coverage boundary deltas, so decoding needs no per-chunk
//! framing.
//!
//! Sequence numbers, cumulative amounts, counts, and boundary positions and prefixes ride
//! as varints. The hash preimages they are checked against stay fixed-width.
//!
//! Hydration is reconstruction, not validation: [DealtSlice::hydrate] rebuilds the exact
//! [ProofSlice] the full pipeline deals, and the caller runs the unchanged
//! [validate_slice](crate::bajillion::transition::validate_slice) on it. A stale or
//! corrupted interval hydrates to an error or to a slice whose state openings miss the
//! certified roots and is rejected there. After validation, [Interval::advance] rolls the
//! interval forward.
//!
//! Retention is a protocol assumption, not a cache: an assignee that lost its interval or
//! is joining syncs it externally (from other assignees or the operator, checked against
//! the certified predecessor root) before participating. Dealing never carries catch-up
//! material.

use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    commitment::{self, RangeOpening},
    posted::{Reference, RowWire, derive_row, resolve_references, row_wire},
    state::{AccountRow, AccountState, ChangeGuard, StateLeaf},
    transition::{
        ChangeRange, CloseContext, CoverageRange, OperatorAggregate, ProofSlice, SliceCodecConfig,
        StateRange, TransitionError, account_slice, codec_invalid, max_proof_hashes, read_span,
        validate_row,
    },
    vector::{
        OutEntry, OutVector, TransposeEntry, read_transpose, transpose_encode_size, write_transpose,
    },
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{
    Decode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
    varint::UInt,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, lthash::LtHash};
use core::ops::Range;

/// One assigned span's live leaves at a certified close, retained across closes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interval<P: PublicKey> {
    leaves: Vec<StateLeaf<P>>,
}

impl<P: PublicKey> Interval<P> {
    /// Builds a retained interval from strictly key-sorted live leaves.
    ///
    /// Callers obtain the leaves from their own prior validation (the hydrated slice's
    /// predecessor interval) or from an external sync checked against the certified root.
    pub fn new(leaves: Vec<StateLeaf<P>>) -> Result<Self, TransitionError> {
        if leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(TransitionError::NonCanonicalStateOrder);
        }
        if leaves
            .iter()
            .any(|leaf| !leaf.state.active || leaf.state.balance == 0)
        {
            return Err(TransitionError::InactiveBalance);
        }
        Ok(Self { leaves })
    }

    /// The retained live leaves, key-sorted.
    pub fn leaves(&self) -> &[StateLeaf<P>] {
        &self.leaves
    }

    /// Rolls the interval forward over one validated slice's rows.
    ///
    /// Must be called with rows from a slice that passed full validation against this
    /// interval (see [DealtSlice::hydrate]); applying anything else desynchronizes the
    /// interval, which the next close's validation then rejects.
    ///
    /// # Panics
    ///
    /// Panics if a row's predecessor diverges from the retained leaf, which validation
    /// has already ruled out for the sequences this method documents.
    pub fn advance<D: Digest>(&mut self, slice: &ProofSlice<P, D>) {
        let mut advanced = Vec::with_capacity(self.leaves.len() + slice.changes.rows.len());
        let mut leaves = self.leaves.iter().peekable();
        for row in &slice.changes.rows {
            while leaves.peek().is_some_and(|leaf| leaf.account < row.account) {
                advanced.push((*leaves.peek().expect("peeked")).clone());
                leaves.next();
            }
            match leaves.peek() {
                Some(leaf) if leaf.account == row.account => {
                    assert!(
                        leaf.state == row.predecessor,
                        "row predecessor diverges from the retained interval"
                    );
                    leaves.next();
                }
                _ => assert!(
                    !row.predecessor.active,
                    "active predecessor missing from the retained interval"
                ),
            }
            if row.successor.active {
                advanced.push(StateLeaf {
                    account: row.account.clone(),
                    state: row.successor,
                });
            }
        }
        advanced.extend(leaves.cloned());
        self.leaves = advanced;
    }
}

/// The span-level part of a dealt slice, shipped once per span ahead of its chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Witness<P: PublicKey, D: Digest> {
    /// Live leaves the assignee's retained interval must supply, a decode bound pinned to
    /// the coverage: decoding rejects any count other than the predecessor position delta
    /// between the span's first and last boundaries.
    ///
    /// Untrusted wire input: a lying count fails decoding, and a lying coverage hydrates to
    /// an error or a slice whose openings miss the certified roots.
    pub(crate) retained: u32,
    pub(crate) span: Range<u16>,
    pub(crate) coverage: CoverageRange<D>,
    pub(crate) operator_aggregates: Vec<Option<OperatorAggregate>>,
    pub(crate) out_start: LtHash,
    pub(crate) in_start: LtHash,
    pub(crate) transpose_opening: Option<RangeOpening<D>>,
    pub(crate) withdrawal_opening: Option<RangeOpening<D>>,
    pub(crate) change_predecessor: Option<ChangeGuard<P, D>>,
    pub(crate) change_successor: Option<ChangeGuard<P, D>>,
    pub(crate) change_opening: RangeOpening<D>,
    pub(crate) predecessor: StateRange<P, D>,
    pub(crate) successor: StateRange<P, D>,
}

impl<P: PublicKey, D: Digest> Witness<P, D> {
    /// Binds this witness around its span's content as the full proof slice.
    pub(crate) fn slice(
        self,
        rows: Vec<AccountRow<P, D>>,
        out_vectors: Vec<OutVector<P>>,
        transpose: Vec<TransposeEntry<P>>,
        unchanged: Vec<StateLeaf<P>>,
    ) -> ProofSlice<P, D> {
        ProofSlice {
            span: self.span,
            coverage: self.coverage,
            changes: ChangeRange {
                predecessor: self.change_predecessor,
                rows,
                successor: self.change_successor,
                opening: self.change_opening,
            },
            out_vectors,
            transpose,
            out_start: self.out_start,
            operator_aggregates: self.operator_aggregates,
            in_start: self.in_start,
            transpose_opening: self.transpose_opening,
            withdrawal_opening: self.withdrawal_opening,
            unchanged,
            predecessor: self.predecessor,
            successor: self.successor,
        }
    }

    /// The witness bytes by component: everything but the chunk components.
    fn breakdown(&self) -> DealtBreakdown {
        DealtBreakdown {
            fixed: u32::SIZE + self.span.start.encode_size() + self.span.end.encode_size(),
            boundaries: self.coverage.boundaries_size(),
            aggregates: self.operator_aggregates.encode_size(),
            starts: LtHash::SIZE * 2,
            openings: self.coverage.opening.encode_size()
                + self.change_opening.encode_size()
                + self.predecessor.opening.encode_size()
                + self.successor.opening.encode_size()
                + self.transpose_opening.encode_size()
                + self.withdrawal_opening.encode_size(),
            guards: self.change_predecessor.encode_size()
                + self.change_successor.encode_size()
                + self.predecessor.predecessor.encode_size()
                + self.predecessor.successor.encode_size()
                + self.successor.predecessor.encode_size()
                + self.successor.successor.encode_size(),
            ..DealtBreakdown::default()
        }
    }

    /// Reads a witness under the decode limits, pinning every span-level count to its
    /// coverage boundaries.
    fn read(reader: &mut impl Buf, config: &SliceCodecConfig) -> Result<Self, CodecError> {
        let invalid = |reason| codec_invalid("DealtSlice", reason);
        let state_limit = config
            .close
            .max_states()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let retained = u32::read(reader)?;
        if u64::from(retained) > state_limit {
            return Err(invalid("retained interval exceeds the state bound"));
        }
        let span = read_span(reader, "DealtSlice")?;
        let intervals = usize::from(span.end - span.start);
        let coverage = CoverageRange::read_bounded(reader, intervals + 1, config.max_proof_hashes)?;
        let (start, end) = (coverage.start(), coverage.end());

        // The retained count is the predecessor position delta across the span, so a peer
        // cannot loosen the chunk and state-range decode bounds beyond its coverage.
        if end.predecessor.checked_sub(start.predecessor) != Some(retained) {
            return Err(invalid("retained count does not match the coverage"));
        }

        // The boundary deltas pin the exact row, transpose, and withdrawal counts.
        let row_count = end
            .change
            .checked_sub(start.change)
            .filter(|count| u64::from(*count) <= config.close.max_rows())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| invalid("row count is not canonical"))?;
        let retained_bound = usize::try_from(retained)
            .map_err(|_| invalid("retained bound is not representable"))?;
        let operator_aggregates =
            Vec::<Option<OperatorAggregate>>::read_cfg(reader, &(RangeCfg::exact(intervals), ()))?;
        let transpose_count = end
            .prefix
            .in_count
            .checked_sub(start.prefix.in_count)
            .filter(|count| *count <= config.close.max_total_entries())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| invalid("transpose entry count is not canonical"))?;
        let out_start = LtHash::read(reader)?;
        let in_start = LtHash::read(reader)?;
        let transpose_opening = match u8::read(reader)? {
            0 if transpose_count == 0 => None,
            1 if transpose_count != 0 => Some(RangeOpening::read_bounded(
                reader,
                transpose_count,
                config.max_proof_hashes,
            )?),
            0 | 1 => {
                return Err(invalid(
                    "transpose opening presence does not match the entry count",
                ));
            }
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let withdrawal_count = end
            .prefix
            .withdrawal_count
            .checked_sub(start.prefix.withdrawal_count)
            .and_then(|count| usize::try_from(count).ok())
            .filter(|count| *count <= row_count)
            .ok_or_else(|| invalid("withdrawal output count is not canonical"))?;
        let withdrawal_opening = match u8::read(reader)? {
            0 if withdrawal_count == 0 => None,
            1 if withdrawal_count != 0 => Some(RangeOpening::read_bounded(
                reader,
                withdrawal_count,
                config.max_proof_hashes,
            )?),
            0 | 1 => {
                return Err(invalid(
                    "withdrawal opening presence does not match the output count",
                ));
            }
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let change_predecessor = Option::<ChangeGuard<P, D>>::read(reader)?;
        let change_successor = Option::<ChangeGuard<P, D>>::read(reader)?;
        let change_opening = RangeOpening::read_bounded(
            reader,
            row_count.saturating_add(2),
            config.max_proof_hashes,
        )?;

        // State-range member bounds: the retained interval plus every row covers each
        // side's possible members. The retained count is pinned to the coverage above, and
        // hydration against a diverging interval fails slice validation.
        let members = retained_bound
            .checked_add(row_count)
            .ok_or_else(|| invalid("state member count overflows"))?;
        let predecessor = StateRange::read_bounded(reader, members, config.max_proof_hashes)?;
        let successor = StateRange::read_bounded(reader, members, config.max_proof_hashes)?;
        Ok(Self {
            retained,
            span,
            coverage,
            operator_aggregates,
            out_start,
            in_start,
            transpose_opening,
            withdrawal_opening,
            change_predecessor,
            change_successor,
            change_opening,
            predecessor,
            successor,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for Witness<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.retained.write(writer);
        self.span.start.write(writer);
        self.span.end.write(writer);
        self.coverage.write(writer);
        self.operator_aggregates.write(writer);
        self.out_start.write(writer);
        self.in_start.write(writer);
        self.transpose_opening.write(writer);
        self.withdrawal_opening.write(writer);
        self.change_predecessor.write(writer);
        self.change_successor.write(writer);
        self.change_opening.write(writer);
        self.predecessor.predecessor.write(writer);
        self.predecessor.successor.write(writer);
        self.predecessor.opening.write(writer);
        self.successor.predecessor.write(writer);
        self.successor.successor.write(writer);
        self.successor.opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Witness<P, D> {
    fn encode_size(&self) -> usize {
        self.breakdown().total()
    }
}

/// One covered slice's decoded content: its rows, their outgoing entries, and its
/// transpose range.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Chunk<P: PublicKey> {
    rows: Vec<RowWire<P>>,
    /// Outgoing entries aligned one-for-one with `rows`, empty for credit-only rows.
    entries: Vec<Vec<OutEntry<P>>>,
    transpose: Vec<TransposeEntry<P>>,
}

impl<P: PublicKey> Chunk<P> {
    /// Reads one chunk whose row, outgoing entry, and transpose counts the coverage
    /// boundaries pin, with rank gaps bounded by the retained count.
    fn read(
        reader: &mut impl Buf,
        rows: usize,
        entries: u64,
        transpose: usize,
        retained: usize,
        per_account: usize,
    ) -> Result<Self, CodecError> {
        let invalid = |reason| codec_invalid("DealtSlice", reason);

        // Counts are untrusted until the bytes arrive, so preallocation is capped by what the
        // buffer can still hold.
        let mut wires = Vec::with_capacity(rows.min(reader.remaining()));
        for _ in 0..rows {
            wires.push(RowWire::read(reader, retained)?);
        }
        let mut remaining = usize::try_from(entries)
            .map_err(|_| invalid("outgoing entry count is not representable"))?;
        let mut vectors = Vec::with_capacity(wires.len());
        for row in &wires {
            if row.outgoing.is_none() {
                vectors.push(Vec::new());
                continue;
            }
            let vector = read_entries::<P>(reader, per_account.min(remaining))?;
            remaining -= vector.len();
            vectors.push(vector);
        }
        if remaining != 0 {
            return Err(invalid("outgoing entry count is not canonical"));
        }
        let range = read_transpose::<P>(reader, transpose.max(1))?;
        if range.len() != transpose {
            return Err(invalid("transpose entry count is not canonical"));
        }
        Ok(Self {
            rows: wires,
            entries: vectors,
            transpose: range,
        })
    }

    /// Row, entry, and transpose bytes.
    fn sizes(&self) -> (usize, usize, usize) {
        chunk_sizes(
            &self.rows,
            self.entries.iter().map(Vec::as_slice),
            &self.transpose,
        )
    }

    fn write(&self, writer: &mut impl BufMut) {
        write_chunk(
            &self.rows,
            self.entries.iter().map(Vec::as_slice),
            &self.transpose,
            writer,
        );
    }
}

/// Writes one slice's content: its rows, then each sending row's entries, then its
/// transpose range. `entries` aligns one-for-one with `rows`.
fn write_chunk<'a, P: PublicKey + 'a>(
    rows: &[RowWire<P>],
    entries: impl IntoIterator<Item = &'a [OutEntry<P>]>,
    transpose: &[TransposeEntry<P>],
    writer: &mut impl BufMut,
) {
    for row in rows {
        row.write(writer);
    }
    for (row, entries) in rows.iter().zip(entries) {
        if row.outgoing.is_some() {
            write_entries(entries, writer);
        }
    }
    write_transpose(transpose, writer);
}

/// Row, entry, and transpose bytes of one slice's content.
fn chunk_sizes<'a, P: PublicKey + 'a>(
    rows: &[RowWire<P>],
    entries: impl IntoIterator<Item = &'a [OutEntry<P>]>,
    transpose: &[TransposeEntry<P>],
) -> (usize, usize, usize) {
    (
        rows.iter().map(RowWire::encode_size).sum(),
        rows.iter()
            .zip(entries)
            .filter(|(row, _)| row.outgoing.is_some())
            .map(|(_, entries)| entries_size(entries))
            .sum(),
        transpose_encode_size(transpose),
    )
}

/// Encodes one slice's chunk against its retained predecessor leaves: rows with rank gaps
/// counted from the slice's first leaf, each sending row's entries, and the slice's
/// transpose range.
pub(crate) fn encode_chunk<P: PublicKey, D: Digest>(
    rows: &[AccountRow<P, D>],
    out_vectors: &[OutVector<P>],
    transpose: &[TransposeEntry<P>],
    leaves: &[StateLeaf<P>],
) -> Bytes {
    let wires = rows
        .iter()
        .zip(resolve_references(
            rows,
            leaves.iter().map(|leaf| &leaf.account),
        ))
        .map(|(row, reference)| row_wire(row, reference))
        .collect::<Vec<_>>();
    let entries = || out_vectors.iter().map(OutVector::entries);
    let (row_bytes, entry_bytes, transpose_bytes) = chunk_sizes(&wires, entries(), transpose);
    let mut buf = BytesMut::with_capacity(row_bytes + entry_bytes + transpose_bytes);
    write_chunk(&wires, entries(), transpose, &mut buf);
    debug_assert_eq!(buf.len(), row_bytes + entry_bytes + transpose_bytes);
    buf.freeze()
}

/// The dealt form of one proof slice: the span witness and one chunk per covered slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealtSlice<P: PublicKey, D: Digest> {
    witness: Witness<P, D>,
    /// One chunk per covered slice, in slice order.
    chunks: Vec<Chunk<P>>,
}

impl<P: PublicKey, D: Digest> DealtSlice<P, D> {
    /// The deterministic slice indices covered, nonempty and contiguous.
    pub const fn span(&self) -> &Range<u16> {
        &self.witness.span
    }

    /// Strips a fully assembled slice down to its posted-style share.
    ///
    /// The stripped material (unchanged leaves, predecessor and successor states,
    /// prefixes, settlement outputs, acknowledgment bodies, vector payers) is exactly what
    /// [DealtSlice::hydrate] re-derives from the assignee's retained interval. Rows,
    /// leaves, and transpose entries are chunked by their account's slice under
    /// `slice_bits`, the close's assignment width.
    ///
    /// # Panics
    ///
    /// Panics if `slice_bits` exceeds the protocol bound or the slice carries content
    /// (rows, live leaves, or transpose recipients) before or past its span, neither of
    /// which an assembled slice does.
    pub fn strip(slice: ProofSlice<P, D>, slice_bits: u8) -> Self {
        let ProofSlice {
            span,
            coverage,
            changes,
            out_vectors,
            transpose,
            out_start,
            operator_aggregates,
            in_start,
            transpose_opening,
            withdrawal_opening,
            unchanged,
            predecessor,
            successor,
        } = slice;
        let ChangeRange {
            predecessor: change_predecessor,
            rows,
            successor: change_successor,
            opening: change_opening,
        } = changes;
        let slice_of = |account: &P| {
            account_slice(account, slice_bits).expect("slice bits are within the protocol bound")
        };

        // The assignee's retained interval is this slice's live predecessor set: the
        // unchanged leaves plus every row with a live predecessor, in key order.
        let mut interval: Vec<&P> = Vec::with_capacity(unchanged.len() + rows.len());
        {
            let mut unchanged = unchanged.iter().map(|leaf| &leaf.account).peekable();
            for row in &rows {
                while unchanged.peek().is_some_and(|leaf| **leaf < row.account) {
                    interval.push(unchanged.next().expect("peeked"));
                }
                if row.predecessor.active {
                    interval.push(&row.account);
                }
            }
            interval.extend(unchanged);
        }
        let retained = u32::try_from(interval.len()).expect("dealt slices fit the vector bound");

        // Each slice's rows resolve against that slice's leaves alone, so a chunk's bytes
        // do not depend on the span carrying it.
        let mut chunks = Vec::with_capacity(usize::from(span.end - span.start));
        let (mut row_end, mut leaf_end, mut entry_end) = (0_usize, 0_usize, 0_usize);
        for slice in span.clone() {
            let (row_start, leaf_start, entry_start) = (row_end, leaf_end, entry_end);
            while rows
                .get(row_end)
                .is_some_and(|row| slice_of(&row.account) <= slice)
            {
                row_end += 1;
            }
            while interval
                .get(leaf_end)
                .is_some_and(|key| slice_of(key) <= slice)
            {
                leaf_end += 1;
            }
            while transpose
                .get(entry_end)
                .is_some_and(|entry| slice_of(&entry.recipient) <= slice)
            {
                entry_end += 1;
            }
            let covered = &rows[row_start..row_end];
            let references =
                resolve_references(covered, interval[leaf_start..leaf_end].iter().copied());
            chunks.push(Chunk {
                rows: covered
                    .iter()
                    .zip(references)
                    .map(|(row, reference)| row_wire(row, reference))
                    .collect(),
                entries: out_vectors[row_start..row_end]
                    .iter()
                    .map(|vector| vector.entries().to_vec())
                    .collect(),
                transpose: transpose[entry_start..entry_end].to_vec(),
            });
        }

        // Rows, leaves, and transpose entries are key-sorted, so their first elements
        // detect content before the span and the exhausted cursors content past it.
        let within = |account: &P| slice_of(account) >= span.start;
        assert!(
            rows.first().is_none_or(|row| within(&row.account))
                && interval.first().is_none_or(|key| within(key))
                && transpose
                    .first()
                    .is_none_or(|entry| within(&entry.recipient))
                && row_end == rows.len()
                && leaf_end == interval.len()
                && entry_end == transpose.len(),
            "slice content outside its span"
        );
        Self {
            witness: Witness {
                retained,
                span,
                coverage,
                operator_aggregates,
                out_start,
                in_start,
                transpose_opening,
                withdrawal_opening,
                change_predecessor,
                change_successor,
                change_opening,
                predecessor,
                successor,
            },
            chunks,
        }
    }

    /// Rebuilds the exact full slice against the assignee's retained interval.
    ///
    /// Hydration is reconstruction, not validation: the caller MUST pass the result to
    /// [validate_slice](crate::bajillion::transition::validate_slice). A retained
    /// interval that diverges from the sealed close hydrates to an error or to a slice
    /// whose predecessor or successor openings miss the certified roots and is rejected
    /// there.
    pub fn hydrate<H>(
        self,
        interval: &Interval<P>,
        context: &CloseContext<P, D>,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
    ) -> Result<ProofSlice<P, D>, CodecError>
    where
        H: Hasher<Digest = D>,
    {
        let invalid = |reason| codec_invalid("DealtSlice", reason);
        let slice_bits = context.assignment().slice_bits();
        let slice_of = |account: &P| {
            account_slice(account, slice_bits).map_err(|_| invalid("account has no slice"))
        };
        let span = &self.witness.span;
        if self.chunks.len() != usize::from(span.end - span.start) {
            return Err(invalid("chunk count does not match the span"));
        }

        // Resolve every row reference against its slice's leaves in the retained interval.
        // The interval is the span's live predecessor set in key order, so each slice's
        // leaves are one contiguous run of it.
        let leaves = &interval.leaves;
        let row_count: usize = self.chunks.iter().map(|chunk| chunk.rows.len()).sum();
        let mut skeleton = Vec::with_capacity(row_count);
        let mut entries = Vec::with_capacity(row_count);
        let mut transpose =
            Vec::with_capacity(self.chunks.iter().map(|chunk| chunk.transpose.len()).sum());
        let mut position = 0_usize;
        for (slice, chunk) in span.clone().zip(self.chunks) {
            while leaves
                .get(position)
                .is_some_and(|leaf| slice_of(&leaf.account).is_ok_and(|member| member < slice))
            {
                position += 1;
            }
            let mut cursor = position;
            while leaves
                .get(position)
                .is_some_and(|leaf| slice_of(&leaf.account).is_ok_and(|member| member == slice))
            {
                position += 1;
            }
            let end = position;
            for row in chunk.rows {
                let (account, predecessor) = match row.reference {
                    Reference::Live(gap) => {
                        let index = cursor
                            .checked_add(gap)
                            .filter(|index| *index < end)
                            .ok_or_else(|| invalid("rank gap beyond the slice interval"))?;
                        cursor = index + 1;
                        (leaves[index].account.clone(), leaves[index].state)
                    }
                    Reference::Fresh(account) => {
                        if slice_of(&account)? != slice {
                            return Err(invalid("row outside its slice"));
                        }
                        (account, AccountState::default())
                    }
                };
                skeleton.push((account, predecessor, row.outgoing));
            }
            entries.extend(chunk.entries);
            transpose.extend(chunk.transpose);
        }
        if skeleton.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(invalid("rows are not strictly account-sorted"));
        }
        if skeleton.iter().any(|(account, predecessor, _)| {
            !predecessor.active
                && leaves
                    .binary_search_by(|leaf| leaf.account.cmp(account))
                    .is_ok()
        }) {
            return Err(invalid("live account carried as a full key"));
        }

        // Derive each row's successor, output, acknowledgment body, and prefix by walking
        // its incoming transpose range, exactly as posted decoding derives them globally.
        let epoch = context.payment().epoch();
        let mut rows = Vec::with_capacity(skeleton.len());
        let mut out_vectors = Vec::with_capacity(skeleton.len());
        let mut prefix = self.witness.coverage.start().prefix;
        let mut cursor = 0_usize;
        for ((account, predecessor, outgoing), entries) in skeleton.into_iter().zip(entries) {
            let vector = OutVector::new(epoch, account.clone(), entries)
                .map_err(|_| invalid("outgoing vector is not canonical"))?;
            let start = cursor;
            let mut credit = 0_u64;
            let mut receipts = 0_u64;
            while transpose
                .get(cursor)
                .is_some_and(|entry| entry.recipient == account)
            {
                let entry = &transpose[cursor];
                credit = credit
                    .checked_add(entry.cumulative)
                    .ok_or_else(|| invalid("credit totals overflow"))?;
                receipts = receipts
                    .checked_add(entry.count)
                    .ok_or_else(|| invalid("credit totals overflow"))?;
                cursor += 1;
            }
            let mut row = derive_row::<H, P, D>(
                context,
                deposits,
                withdrawals,
                account,
                predecessor,
                outgoing,
                &vector,
                credit,
                receipts,
            )?;
            let delta = validate_row::<H, P, D>(
                context,
                deposits,
                withdrawals,
                &row,
                &vector,
                &transpose[start..cursor],
            )
            .map_err(|_| invalid("derived row is not internally valid"))?;
            prefix = prefix
                .checked_extend(delta)
                .ok_or_else(|| invalid("prefix chain overflows"))?;
            row.prefix = prefix;
            rows.push(row);
            out_vectors.push(vector);
        }
        if cursor != transpose.len() {
            return Err(invalid("transpose entries without a credited row"));
        }

        // The unchanged leaves are the retained interval minus the rows.
        let mut consumed = rows.iter().map(|row| &row.account).peekable();
        let mut unchanged = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            while consumed.peek().is_some_and(|row| **row < leaf.account) {
                consumed.next();
            }
            if consumed.peek().is_some_and(|row| **row == leaf.account) {
                continue;
            }
            unchanged.push(leaf.clone());
        }
        Ok(self.witness.slice(rows, out_vectors, transpose, unchanged))
    }
}

/// Writes one sender's outgoing entries with varint amounts and counts.
fn write_entries<P: PublicKey>(entries: &[OutEntry<P>], writer: &mut impl BufMut) {
    entries.len().write(writer);
    for entry in entries {
        entry.recipient.write(writer);
        UInt(entry.cumulative).write(writer);
        UInt(entry.count).write(writer);
    }
}

/// Reads one sender's outgoing entries of at most `max` entries.
fn read_entries<P: PublicKey>(
    reader: &mut impl Buf,
    max: usize,
) -> Result<Vec<OutEntry<P>>, CodecError> {
    let len = usize::read_cfg(reader, &RangeCfg::new(..=max))?;
    let mut entries = Vec::with_capacity(len.min(reader.remaining()));
    for _ in 0..len {
        entries.push(OutEntry {
            recipient: P::read(reader)?,
            cumulative: UInt::read(reader)?.into(),
            count: UInt::read(reader)?.into(),
        });
    }
    Ok(entries)
}

fn entries_size<P: PublicKey>(entries: &[OutEntry<P>]) -> usize {
    entries.len().encode_size()
        + entries
            .iter()
            .map(|entry| {
                P::SIZE + UInt(entry.cumulative).encode_size() + UInt(entry.count).encode_size()
            })
            .sum::<usize>()
}

impl<P: PublicKey, D: Digest> Write for DealtSlice<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.witness.write(writer);
        for chunk in &self.chunks {
            chunk.write(writer);
        }
    }
}

/// The dealt wire by component, for byte accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DealtBreakdown {
    /// Retained count and span.
    pub fixed: usize,
    /// Covered coverage boundaries.
    pub boundaries: usize,
    /// Row tags, references, sequence numbers, and payer signatures.
    pub rows: usize,
    /// Outgoing entries with their per-sender counts.
    pub entries: usize,
    /// The recipient-grouped transpose ranges, one per covered slice.
    pub transpose: usize,
    /// Per-slice operator aggregates.
    pub aggregates: usize,
    /// Both accumulator start states.
    pub starts: usize,
    /// Coverage, change, state, transpose, and withdrawal range openings.
    pub openings: usize,
    /// Change and state guards.
    pub guards: usize,
}

impl DealtBreakdown {
    /// Total dealt bytes.
    pub const fn total(&self) -> usize {
        self.fixed
            + self.boundaries
            + self.rows
            + self.entries
            + self.transpose
            + self.aggregates
            + self.starts
            + self.openings
            + self.guards
    }

    /// Adds another slice's components.
    pub const fn add(&mut self, other: &Self) {
        self.fixed += other.fixed;
        self.boundaries += other.boundaries;
        self.rows += other.rows;
        self.entries += other.entries;
        self.transpose += other.transpose;
        self.aggregates += other.aggregates;
        self.starts += other.starts;
        self.openings += other.openings;
        self.guards += other.guards;
    }
}

impl<P: PublicKey, D: Digest> DealtSlice<P, D> {
    /// The encoded size of this slice by component.
    pub fn breakdown(&self) -> DealtBreakdown {
        let mut breakdown = self.witness.breakdown();
        for chunk in &self.chunks {
            let (rows, entries, transpose) = chunk.sizes();
            breakdown.rows += rows;
            breakdown.entries += entries;
            breakdown.transpose += transpose;
        }
        breakdown
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for DealtSlice<P, D> {
    fn encode_size(&self) -> usize {
        self.breakdown().total()
    }
}

impl<P: PublicKey, D: Digest> Read for DealtSlice<P, D> {
    /// Anchor-bound close limits and the maximum hashes accepted by each proof frontier.
    type Cfg = SliceCodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let invalid = |reason| codec_invalid("DealtSlice", reason);
        let witness = Witness::<P, D>::read(reader, config)?;
        let retained = usize::try_from(witness.retained)
            .map_err(|_| invalid("retained bound is not representable"))?;
        let per_account = usize::try_from(
            config
                .close
                .max_account_entries()
                .min(u64::from(commitment::MAX_VECTOR_LENGTH)),
        )
        .map_err(|_| invalid("outgoing entry bound is not representable"))?;
        let boundaries = &witness.coverage.boundaries;
        let (start, end) = (witness.coverage.start(), witness.coverage.end());
        if end
            .prefix
            .out_count
            .checked_sub(start.prefix.out_count)
            .is_none_or(|count| count > config.close.max_total_entries())
        {
            return Err(invalid("outgoing entry count is not canonical"));
        }

        // Each covered slice's boundary deltas pin its chunk's row, entry, and transpose
        // counts. The span totals were bounded with the witness and every delta is
        // nonnegative, so no chunk can claim more than the span.
        let mut chunks = Vec::with_capacity(boundaries.len() - 1);
        for window in boundaries.windows(2) {
            let rows = window[1]
                .change
                .checked_sub(window[0].change)
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| invalid("row count is not canonical"))?;
            let entries = window[1]
                .prefix
                .out_count
                .checked_sub(window[0].prefix.out_count)
                .ok_or_else(|| invalid("outgoing entry count is not canonical"))?;
            let transpose = window[1]
                .prefix
                .in_count
                .checked_sub(window[0].prefix.in_count)
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| invalid("transpose entry count is not canonical"))?;
            chunks.push(Chunk::read(
                reader,
                rows,
                entries,
                transpose,
                retained,
                per_account,
            )?);
        }
        Ok(Self { witness, chunks })
    }
}

/// Decodes one dealt slice only after enforcing a caller-selected byte limit.
pub fn decode_dealt_slice_bounded<P: PublicKey, D: Digest>(
    encoded: &[u8],
    limits: crate::bajillion::transition::CloseLimits,
    max_bytes: usize,
) -> Result<DealtSlice<P, D>, CodecError> {
    if encoded.len() > max_bytes {
        return Err(codec_invalid(
            "DealtSlice",
            "encoded slice exceeds configured byte limit",
        ));
    }
    let max_hashes = max_proof_hashes(D::SIZE, max_bytes)?;
    DealtSlice::decode_cfg(encoded, &SliceCodecConfig::new(limits, max_hashes))
}

/// The wire of one dealt slice: its span witness followed by one chunk per covered slice,
/// held as separately owned segments so every span ships without copying chunk bytes.
///
/// Writes exactly the bytes [DealtSlice] reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wire {
    segments: Vec<Bytes>,
}

impl Wire {
    /// The witness segment followed by the chunk segments in slice order, for vectored
    /// sends.
    pub fn segments(&self) -> &[Bytes] {
        &self.segments
    }
}

impl Write for Wire {
    fn write(&self, writer: &mut impl BufMut) {
        for segment in &self.segments {
            writer.put_slice(segment);
        }
    }
}

impl EncodeSize for Wire {
    fn encode_size(&self) -> usize {
        self.segments.iter().map(Bytes::len).sum()
    }
}

/// One close's dealt wire encoded once: every slice's chunk plus one witness per dealt
/// span, from which each span's [Wire] is assembled by cloning segments.
#[derive(Clone, Debug)]
pub struct Dealings {
    chunks: Vec<Bytes>,
    witnesses: Vec<(Range<u16>, Bytes)>,
}

impl Dealings {
    /// Pairs every slice's encoded chunk, in slice order, with the encoded witness of each
    /// dealt span.
    pub(crate) const fn new(chunks: Vec<Bytes>, witnesses: Vec<(Range<u16>, Bytes)>) -> Self {
        Self { chunks, witnesses }
    }

    fn witness(&self, span: &Range<u16>) -> &Bytes {
        self.witnesses
            .iter()
            .find(|(dealt, _)| dealt == span)
            .map(|(_, witness)| witness)
            .expect("span was dealt")
    }

    fn chunks(&self, span: &Range<u16>) -> &[Bytes] {
        &self.chunks[usize::from(span.start)..usize::from(span.end)]
    }

    /// The wire of one dealt span: its witness followed by its slices' chunks.
    ///
    /// # Panics
    ///
    /// Panics if `span` was not dealt.
    pub fn encode_span(&self, span: &Range<u16>) -> Wire {
        let chunks = self.chunks(span);
        let mut segments = Vec::with_capacity(chunks.len() + 1);
        segments.push(self.witness(span).clone());
        segments.extend(chunks.iter().cloned());
        Wire { segments }
    }

    /// The encoded size of one dealt span.
    ///
    /// # Panics
    ///
    /// Panics if `span` was not dealt.
    pub fn span_size(&self, span: &Range<u16>) -> usize {
        self.witness(span).len() + self.chunks(span).iter().map(Bytes::len).sum::<usize>()
    }
}
