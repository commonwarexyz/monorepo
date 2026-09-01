//! Change-proof dealing: slices without the unchanged state, applied to retained intervals.
//!
//! The [ProofSlice] re-deals every unchanged leaf in
//! its interval each close, which is the one dealt term that scales with the economy
//! instead of the movers. This module deletes it. Every slice assignee retains its key
//! interval's live leaves across closes (an [Interval]), the dealt form drops the
//! unchanged vector (a [DealtSlice]), and the rows are the entire change proof: their
//! placement against the retained interval is implied by key order, so hydration and
//! advancement are deterministic.
//!
//! Validation is parity by construction: [DealtSlice::hydrate] rebuilds the exact
//! [ProofSlice] the full pipeline deals, and the
//! caller runs the unchanged
//! [validate_slice](crate::bajillion::transition::validate_slice) on it. A stale or corrupted
//! interval hydrates to a slice whose state openings miss the certified roots and is
//! rejected there. After validation, [Interval::advance] rolls the interval forward.
//!
//! Retention is a protocol assumption, not a cache: an assignee that lost its interval or
//! is joining syncs it externally (from other assignees or the operator, checked against
//! the certified predecessor root) before participating. Dealing never carries catch-up
//! material.

use crate::bajillion::{
    commitment::{self, RangeOpening},
    state::StateLeaf,
    transition::{
        ChangeRange, CoverageRange, ProofSlice, SliceCodecConfig, StateRange, TransitionError,
        codec_invalid, max_proof_hashes, read_out_vectors,
    },
    vector::{read_transpose, write_transpose},
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{Decode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, PublicKey, lthash::LtHash};

/// One slice interval's live leaves at a certified close, retained across closes.
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

    /// Returns the unchanged leaves for a close whose changed rows in this interval carry
    /// the given strictly key-sorted accounts: every retained leaf without a row.
    fn unchanged<D: Digest>(&self, slice: &DealtSlice<P, D>) -> Vec<StateLeaf<P>> {
        let mut rows = slice.changes.rows.iter().map(|row| &row.account).peekable();
        let mut unchanged = Vec::with_capacity(self.leaves.len());
        for leaf in &self.leaves {
            while rows.peek().is_some_and(|row| **row < leaf.account) {
                rows.next();
            }
            if rows.peek().is_some_and(|row| **row == leaf.account) {
                continue;
            }
            unchanged.push(leaf.clone());
        }
        unchanged
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

/// The dealt form of one proof slice: everything but the unchanged state vector.
///
/// Wire savings are exactly the unchanged leaves (65 B each), the one dealt term
/// proportional to the economy rather than the movers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealtSlice<P: PublicKey, D: Digest> {
    /// Live leaves the assignee's retained interval must supply, bounding hydration decode.
    ///
    /// Untrusted wire input: a lying count either fails decode bounds or hydrates to a slice
    /// whose state openings miss the certified roots.
    retained: u32,
    inner: ProofSlice<P, D>,
}

impl<P: PublicKey, D: Digest> DealtSlice<P, D> {
    /// Strips the unchanged state from a fully assembled slice.
    ///
    /// # Panics
    ///
    /// Panics if the slice's unchanged interval exceeds the protocol vector bound, which
    /// assembly has already ruled out for every slice it deals.
    pub fn strip(mut slice: ProofSlice<P, D>) -> Self {
        let retained =
            u32::try_from(slice.unchanged.len()).expect("dealt slices fit the vector bound");
        slice.unchanged = Vec::new();
        Self {
            retained,
            inner: slice,
        }
    }

    /// Returns the dealt wire size of this slice, excluding the retained-count prefix.
    pub fn encoded_size(&self) -> usize {
        self.inner.encoded_size()
    }

    /// Rebuilds the exact full slice by filling the unchanged state from the retained
    /// interval.
    ///
    /// Hydration is reconstruction, not validation: the caller MUST pass the result to
    /// [validate_slice](crate::bajillion::transition::validate_slice). A retained interval
    /// that diverges from the sealed close hydrates to a slice whose predecessor or
    /// successor openings miss the certified roots and is rejected there.
    pub fn hydrate(self, interval: &Interval<P>) -> ProofSlice<P, D> {
        let unchanged = interval.unchanged(&self);
        let mut slice = self.inner;
        slice.unchanged = unchanged;
        slice
    }
}

impl<P: PublicKey, D: Digest> core::ops::Deref for DealtSlice<P, D> {
    type Target = ProofSlice<P, D>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<P: PublicKey, D: Digest> Write for DealtSlice<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        let slice = &self.inner;
        debug_assert!(slice.unchanged.is_empty());
        self.retained.write(writer);
        slice.index.write(writer);
        slice.coverage.start.write(writer);
        slice.coverage.end.write(writer);
        slice.coverage.opening.write(writer);
        slice.changes.predecessor.write(writer);
        slice.changes.rows.write(writer);
        slice.changes.successor.write(writer);
        slice.changes.opening.write(writer);
        slice.out_vectors.write(writer);
        slice.operator_aggregate.write(writer);
        write_transpose(&slice.transpose, writer);
        slice.out_start.write(writer);
        slice.in_start.write(writer);
        slice.transpose_opening.write(writer);
        slice.withdrawal_opening.write(writer);
        slice.predecessor.predecessor.write(writer);
        slice.predecessor.successor.write(writer);
        slice.predecessor.opening.write(writer);
        slice.successor.predecessor.write(writer);
        slice.successor.successor.write(writer);
        slice.successor.opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for DealtSlice<P, D> {
    fn encode_size(&self) -> usize {
        // The wire replaces the empty unchanged vector (one length byte) with the
        // fixed-width retained count.
        u32::SIZE + self.encoded_size() - self.inner.unchanged.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for DealtSlice<P, D> {
    /// Anchor-bound close limits and the maximum hashes accepted by each proof frontier.
    type Cfg = SliceCodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let state_limit = config
            .close
            .max_states()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let retained = u32::read(reader)?;
        if u64::from(retained) > state_limit {
            return Err(codec_invalid(
                "DealtSlice",
                "retained interval exceeds the state bound",
            ));
        }
        let row_limit = config
            .close
            .max_rows()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let row_limit = usize::try_from(row_limit)
            .map_err(|_| codec_invalid("DealtSlice", "row limit is not representable"))?;
        let index = u16::read(reader)?;
        let coverage = CoverageRange::read_bounded(reader, config.max_proof_hashes)?;
        let changes = ChangeRange::read_bounded(reader, row_limit, config.max_proof_hashes)?;
        let out_vectors = read_out_vectors(reader, changes.rows.len(), &config.close)?;
        let operator_aggregate = Option::read(reader)?;
        let transpose_count = coverage
            .end
            .prefix
            .in_count
            .checked_sub(coverage.start.prefix.in_count)
            .filter(|count| *count <= config.close.max_total_entries())
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(codec_invalid(
                "DealtSlice",
                "transpose entry count is not canonical",
            ))?;
        let transpose = read_transpose::<P>(reader, transpose_count.max(1))?;
        if transpose.len() != transpose_count {
            return Err(codec_invalid(
                "DealtSlice",
                "transpose entry count is not canonical",
            ));
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
                return Err(codec_invalid(
                    "DealtSlice",
                    "transpose opening presence does not match the entry count",
                ));
            }
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let withdrawal_count = coverage
            .end
            .prefix
            .withdrawal_count
            .checked_sub(coverage.start.prefix.withdrawal_count)
            .and_then(|count| usize::try_from(count).ok())
            .filter(|count| *count <= changes.rows.len())
            .ok_or(codec_invalid(
                "DealtSlice",
                "withdrawal output count is not canonical",
            ))?;
        let withdrawal_opening = match u8::read(reader)? {
            0 if withdrawal_count == 0 => None,
            1 if withdrawal_count != 0 => Some(RangeOpening::read_bounded(
                reader,
                withdrawal_count,
                config.max_proof_hashes,
            )?),
            0 | 1 => {
                return Err(codec_invalid(
                    "DealtSlice",
                    "withdrawal opening presence does not match the output count",
                ));
            }
            tag => return Err(CodecError::InvalidEnum(tag)),
        };

        // The member counts hydration will fill: the retained interval plus each side's
        // active row states. The claimed retained count is untrusted decode-bound input;
        // hydration against a diverging interval fails slice validation.
        let retained_members = usize::try_from(retained)
            .map_err(|_| codec_invalid("DealtSlice", "retained bound is not representable"))?;
        let predecessor_members = retained_members
            .checked_add(
                changes
                    .rows
                    .iter()
                    .filter(|row| row.predecessor.active)
                    .count(),
            )
            .ok_or(codec_invalid(
                "DealtSlice",
                "predecessor member count overflows",
            ))?;
        let successor_members = retained_members
            .checked_add(
                changes
                    .rows
                    .iter()
                    .filter(|row| row.successor.active)
                    .count(),
            )
            .ok_or(codec_invalid(
                "DealtSlice",
                "successor member count overflows",
            ))?;
        let predecessor =
            StateRange::read_bounded(reader, predecessor_members, config.max_proof_hashes)?;
        let successor =
            StateRange::read_bounded(reader, successor_members, config.max_proof_hashes)?;
        Ok(Self {
            retained,
            inner: ProofSlice {
                index,
                coverage,
                changes,
                out_vectors,
                transpose,
                out_start,
                operator_aggregate,
                in_start,
                transpose_opening,
                withdrawal_opening,
                unchanged: Vec::new(),
                predecessor,
                successor,
            },
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

/// Convenience for sizing: the unchanged bytes a full slice deals that its dealt form
/// does not.
pub fn unchanged_bytes<P: PublicKey, D: Digest>(slice: &ProofSlice<P, D>) -> usize {
    slice.unchanged.encode_size()
}
