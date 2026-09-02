//! Change-proof dealing: each proof slice is its span's share of the posted close plus the
//! slice witness, applied to a retained interval.
//!
//! A dealt slice is a subset of the close, not a re-materialized proof. Every assignee
//! retains its assigned span's live leaves across closes (an [Interval]), so the dealt form
//! ([DealtSlice]) ships exactly what the posted corpus ships for those rows plus what binds
//! the fragment to the certified roots:
//!
//! - **Rows** travel as the posted row wire: a rank-gap reference into the retained
//!   interval (or a full key for an account not yet live) and, for senders, the sequence
//!   number and payer signature. Predecessor states come from the interval, successor
//!   states and settlement outputs are equation-derived, prefixes chain from the opening
//!   boundary, and acknowledgment bodies are rebuilt from context and row material.
//! - **Outgoing entries** keep full recipient keys: they are the payer-signed leaf bytes,
//!   fixed before the close is ordered, so no row indexing can apply.
//! - **The transpose range** ships: recipient credit is proven by it, and its entries
//!   originate from payers outside the span.
//! - **The witness** ships once per span: the covered coverage boundaries, the accumulator
//!   start states at the first boundary, the range openings, the change and state guards,
//!   and each covered slice's combined operator countersignature.
//!
//! Sequence numbers, cumulative amounts, and counts ride as varints. The hash preimages
//! they are checked against stay fixed-width.
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
    posted::{Reference, RowWire, derive_row},
    state::{AccountState, ChangeGuard, StateLeaf},
    transition::{
        ChangeRange, CloseContext, CoverageRange, OperatorAggregate, ProofSlice, SliceCodecConfig,
        StateRange, TransitionError, codec_invalid, max_proof_hashes, read_span, validate_row,
    },
    vector::{OutEntry, OutVector, TransposeEntry, read_transpose, write_transpose},
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
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

/// The dealt form of one proof slice: the span's share of the posted close plus the
/// slice witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealtSlice<P: PublicKey, D: Digest> {
    /// Live leaves the assignee's retained interval must supply, bounding hydration decode.
    ///
    /// Untrusted wire input: a lying count either fails decode bounds or hydrates to an
    /// error or a slice whose state openings miss the certified roots.
    retained: u32,
    span: Range<u16>,
    coverage: CoverageRange<D>,
    rows: Vec<RowWire<P>>,
    /// Outgoing entries aligned one-for-one with `rows`, empty for credit-only rows.
    entries: Vec<Vec<OutEntry<P>>>,
    operator_aggregates: Vec<Option<OperatorAggregate>>,
    transpose: Vec<TransposeEntry<P>>,
    out_start: LtHash,
    in_start: LtHash,
    transpose_opening: Option<RangeOpening<D>>,
    withdrawal_opening: Option<RangeOpening<D>>,
    change_predecessor: Option<ChangeGuard<P, D>>,
    change_successor: Option<ChangeGuard<P, D>>,
    change_opening: RangeOpening<D>,
    predecessor: StateRange<P, D>,
    successor: StateRange<P, D>,
}

impl<P: PublicKey, D: Digest> DealtSlice<P, D> {
    /// The deterministic slice indices covered, nonempty and contiguous.
    pub const fn span(&self) -> &Range<u16> {
        &self.span
    }

    /// Strips a fully assembled slice down to its posted-style share.
    ///
    /// The stripped material (unchanged leaves, predecessor and successor states,
    /// prefixes, settlement outputs, acknowledgment bodies, vector payers) is exactly what
    /// [DealtSlice::hydrate] re-derives from the assignee's retained interval.
    pub fn strip(slice: ProofSlice<P, D>) -> Self {
        // The assignee's retained interval is this slice's live predecessor set: the
        // unchanged leaves plus every row with a live predecessor, in key order.
        let mut interval = Vec::with_capacity(slice.unchanged.len() + slice.changes.rows.len());
        {
            let mut unchanged = slice.unchanged.iter().map(|leaf| &leaf.account).peekable();
            for row in &slice.changes.rows {
                while unchanged.peek().is_some_and(|leaf| **leaf < row.account) {
                    interval.push((*unchanged.next().expect("peeked")).clone());
                }
                if row.predecessor.active {
                    interval.push(row.account.clone());
                }
            }
            interval.extend(unchanged.cloned());
        }
        let mut live = interval.iter().peekable();
        let rows = slice
            .changes
            .rows
            .iter()
            .map(|row| {
                let reference = if row.predecessor.active {
                    let mut gap = 0_usize;
                    while live.peek().is_some_and(|key| **key < row.account) {
                        live.next();
                        gap += 1;
                    }
                    assert!(
                        live.next().is_some_and(|key| *key == row.account),
                        "live row missing from the reconstructed interval"
                    );
                    Reference::Live(gap)
                } else {
                    Reference::Fresh(row.account.clone())
                };
                let outgoing = row
                    .outgoing
                    .as_ref()
                    .map(|send| (send.body().seq(), send.payer_signature().clone()));
                RowWire {
                    reference,
                    outgoing,
                }
            })
            .collect();
        let entries = slice
            .out_vectors
            .iter()
            .map(|vector| vector.entries().to_vec())
            .collect();
        Self {
            retained: u32::try_from(interval.len()).expect("dealt slices fit the vector bound"),
            span: slice.span,
            coverage: slice.coverage,
            rows,
            entries,
            operator_aggregates: slice.operator_aggregates,
            transpose: slice.transpose,
            out_start: slice.out_start,
            in_start: slice.in_start,
            transpose_opening: slice.transpose_opening,
            withdrawal_opening: slice.withdrawal_opening,
            change_predecessor: slice.changes.predecessor,
            change_successor: slice.changes.successor,
            change_opening: slice.changes.opening,
            predecessor: slice.predecessor,
            successor: slice.successor,
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

        // Resolve every row reference against the retained interval.
        let mut live = interval.leaves.iter().peekable();
        let mut skeleton = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let (account, predecessor) = match &row.reference {
                Reference::Live(gap) => {
                    for _ in 0..*gap {
                        live.next()
                            .ok_or_else(|| invalid("rank gap beyond the interval"))?;
                    }
                    let leaf = live
                        .next()
                        .ok_or_else(|| invalid("rank gap beyond the interval"))?;
                    (leaf.account.clone(), leaf.state)
                }
                Reference::Fresh(account) => (account.clone(), AccountState::default()),
            };
            skeleton.push((account, predecessor, row.outgoing.clone()));
        }
        if skeleton.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(invalid("rows are not strictly account-sorted"));
        }
        if skeleton.iter().zip(&self.rows).any(|((account, ..), row)| {
            matches!(row.reference, Reference::Fresh(_))
                && interval
                    .leaves
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
        let mut prefix = self.coverage.start().prefix;
        let mut cursor = 0_usize;
        for ((account, predecessor, outgoing), entries) in skeleton.into_iter().zip(self.entries) {
            let vector = OutVector::new(epoch, account.clone(), entries)
                .map_err(|_| invalid("outgoing vector is not canonical"))?;
            let start = cursor;
            let mut credit = 0_u64;
            let mut receipts = 0_u64;
            while self
                .transpose
                .get(cursor)
                .is_some_and(|entry| entry.recipient == account)
            {
                let entry = &self.transpose[cursor];
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
                &self.transpose[start..cursor],
            )
            .map_err(|_| invalid("derived row is not internally valid"))?;
            prefix = prefix
                .checked_extend(delta)
                .ok_or_else(|| invalid("prefix chain overflows"))?;
            row.prefix = prefix;
            rows.push(row);
            out_vectors.push(vector);
        }
        if cursor != self.transpose.len() {
            return Err(invalid("transpose entries without a credited row"));
        }

        // The unchanged leaves are the retained interval minus the rows.
        let mut consumed = rows.iter().map(|row| &row.account).peekable();
        let mut unchanged = Vec::with_capacity(interval.leaves.len());
        for leaf in &interval.leaves {
            while consumed.peek().is_some_and(|row| **row < leaf.account) {
                consumed.next();
            }
            if consumed.peek().is_some_and(|row| **row == leaf.account) {
                continue;
            }
            unchanged.push(leaf.clone());
        }

        Ok(ProofSlice {
            span: self.span,
            coverage: self.coverage,
            changes: ChangeRange {
                predecessor: self.change_predecessor,
                rows,
                successor: self.change_successor,
                opening: self.change_opening,
            },
            out_vectors,
            transpose: self.transpose,
            out_start: self.out_start,
            operator_aggregates: self.operator_aggregates,
            in_start: self.in_start,
            transpose_opening: self.transpose_opening,
            withdrawal_opening: self.withdrawal_opening,
            unchanged,
            predecessor: self.predecessor,
            successor: self.successor,
        })
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
        self.retained.write(writer);
        self.span.start.write(writer);
        self.span.end.write(writer);
        self.coverage.write(writer);
        for row in &self.rows {
            row.write(writer);
        }
        for (row, entries) in self.rows.iter().zip(&self.entries) {
            if row.outgoing.is_some() {
                write_entries(entries, writer);
            }
        }
        self.operator_aggregates.write(writer);
        write_transpose(&self.transpose, writer);
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
    /// The recipient-grouped transpose range.
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
        DealtBreakdown {
            fixed: u32::SIZE + self.span.start.encode_size() + self.span.end.encode_size(),
            boundaries: self.coverage.boundaries.encode_size(),
            rows: self.rows.iter().map(RowWire::encode_size).sum(),
            entries: self
                .rows
                .iter()
                .zip(&self.entries)
                .filter(|(row, _)| row.outgoing.is_some())
                .map(|(_, entries)| entries_size(entries))
                .sum(),
            transpose: crate::bajillion::vector::transpose_encode_size(&self.transpose),
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
        }
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

        // The boundary deltas pin the exact row, entry, transpose, and withdrawal counts.
        let row_count = end
            .change
            .checked_sub(start.change)
            .filter(|count| u64::from(*count) <= config.close.max_rows())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| invalid("row count is not canonical"))?;
        let retained_bound = usize::try_from(retained)
            .map_err(|_| invalid("retained bound is not representable"))?;
        // Counts are untrusted until the bytes arrive, so preallocation is capped by what the
        // buffer can still hold.
        let mut rows = Vec::with_capacity(row_count.min(reader.remaining()));
        for _ in 0..row_count {
            rows.push(RowWire::read(reader, retained_bound)?);
        }
        let entry_total = end
            .prefix
            .out_count
            .checked_sub(start.prefix.out_count)
            .filter(|count| *count <= config.close.max_total_entries())
            .ok_or_else(|| invalid("outgoing entry count is not canonical"))?;
        let mut remaining = usize::try_from(entry_total)
            .map_err(|_| invalid("outgoing entry count is not representable"))?;
        let per_account = usize::try_from(
            config
                .close
                .max_account_entries()
                .min(u64::from(commitment::MAX_VECTOR_LENGTH)),
        )
        .map_err(|_| invalid("outgoing entry bound is not representable"))?;
        let mut entries = Vec::with_capacity(row_count.min(reader.remaining()));
        for row in &rows {
            if row.outgoing.is_none() {
                entries.push(Vec::new());
                continue;
            }
            let vector = read_entries::<P>(reader, per_account.min(remaining))?;
            remaining -= vector.len();
            entries.push(vector);
        }
        if remaining != 0 {
            return Err(invalid("outgoing entry count is not canonical"));
        }
        let operator_aggregates =
            Vec::<Option<OperatorAggregate>>::read_cfg(reader, &(RangeCfg::exact(intervals), ()))?;
        let transpose_count = end
            .prefix
            .in_count
            .checked_sub(start.prefix.in_count)
            .filter(|count| *count <= config.close.max_total_entries())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| invalid("transpose entry count is not canonical"))?;
        let transpose = read_transpose::<P>(reader, transpose_count.max(1))?;
        if transpose.len() != transpose_count {
            return Err(invalid("transpose entry count is not canonical"));
        }
        let out_start = LtHash::read(reader)?;
        let in_start = LtHash::read(reader)?;
        let transpose_opening = match u8::read(reader)? {
            0 if transpose.is_empty() => None,
            1 if !transpose.is_empty() => Some(RangeOpening::read_bounded(
                reader,
                transpose.len(),
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
        // side's possible members. The claimed retained count is untrusted decode-bound
        // input. Hydration against a diverging interval fails slice validation.
        let members = retained_bound
            .checked_add(row_count)
            .ok_or_else(|| invalid("state member count overflows"))?;
        let predecessor = StateRange::read_bounded(reader, members, config.max_proof_hashes)?;
        let successor = StateRange::read_bounded(reader, members, config.max_proof_hashes)?;
        Ok(Self {
            retained,
            span,
            coverage,
            rows,
            entries,
            operator_aggregates,
            transpose,
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
