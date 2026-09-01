//! Stateless sender-vector close assembly and validation.
//!
//! The close carries one payer-signed vector endpoint per sending row, whose committed root
//! sums to the row's debit advance, and derives the operator's recipient-major transpose of
//! the same edge multiset. Coverage boundaries carry running lattice-hash accumulators over
//! both orderings, so each validator checks its slices' accumulator transitions and the
//! terminal boundary proves the transpose is a permutation of the union of payer vectors.

use crate::bajillion::{
    boundary::{
        BoundaryError, Deadline, DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
    },
    challenge::{StateAbsence, StateLookup, StateOpening, StateValueOpening},
    commitment::{self, RangeOpening, Tree, VectorKind, VectorRoot},
    payment::{AckError, PaymentContext, VECTOR_ACK_AGGREGATE_NAMESPACE, verify_ack_signatures},
    state::{
        AccountChange, AccountRow, AccountState, ChangeGuard, Prefix, SettlementOutput, StateLeaf,
    },
    vector::{
        self, OutEntry, OutVector, TransposeEntry, accumulate_edge, read_transpose,
        transpose_encode_size, write_transpose,
    },
};
use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Decode, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{
    BatchVerifier, Digest, Hasher, PublicKey,
    blake3::Digest as Checksum,
    bls12381::primitives::{
        ops::aggregate::{self, combine_messages, combine_signatures, verify_same_signer},
        variant::{MinSig, Variant},
    },
    lthash::LtHash,
};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::iter::NonEmpty;
use rand_core::CryptoRng;
use thiserror::Error;

/// Hash namespace for canonical close header identifiers.
pub const BATCH_ID_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BATCH_ID";
/// Hash namespace for contextual commitments to the close roots.
pub const HEADER_ROOT_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_HEADER_ROOT";
/// Hash namespace for canonical root-independent epoch payment anchors.
pub const EPOCH_ANCHOR_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_EPOCH_ANCHOR";
/// Maximum number of high-order account-key bits used for deterministic proof slices.
pub const MAX_SLICE_BITS: u8 = 8;

/// Returns the deterministic high-order-key interval containing an account.
pub fn account_slice<P: PublicKey>(account: &P, slice_bits: u8) -> Result<u16, TransitionError> {
    if slice_bits > MAX_SLICE_BITS {
        return Err(TransitionError::SliceBits);
    }
    if slice_bits == 0 {
        return Ok(0);
    }
    let first = account
        .as_ref()
        .first()
        .copied()
        .ok_or(TransitionError::EmptyAccountKey)?;
    Ok(u16::from(first >> (8 - slice_bits)))
}

/// Hash of one canonical close header.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BatchId<D: Digest>(D);

impl<D: Digest> BatchId<D> {
    /// Wraps a digest as a batch identifier.
    pub const fn new(digest: D) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    pub const fn digest(&self) -> &D {
        &self.0
    }

    /// Consumes the identifier and returns its digest.
    pub const fn into_digest(self) -> D {
        self.0
    }
}

impl<D: Digest> Write for BatchId<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl<D: Digest> FixedSize for BatchId<D> {
    const SIZE: usize = D::SIZE;
}

impl<D: Digest> Read for BatchId<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(D::read(reader)?))
    }
}

/// Chain-registered validator committee and deterministic corpus partition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Assignment<D: Digest> {
    committee: D,
    slice_bits: u8,
}

impl<D: Digest> Assignment<D> {
    /// Creates an assignment bound to one committee commitment.
    pub const fn new(committee: D, slice_bits: u8) -> Result<Self, TransitionError> {
        if slice_bits > MAX_SLICE_BITS {
            return Err(TransitionError::SliceBits);
        }
        Ok(Self {
            committee,
            slice_bits,
        })
    }

    /// Returns the commitment to the exact ordered validator committee.
    pub const fn committee(&self) -> &D {
        &self.committee
    }

    /// Returns the number of high-order account-key bits selecting a slice.
    pub const fn slice_bits(&self) -> u8 {
        self.slice_bits
    }

    /// Returns the exact number of deterministic slices.
    pub const fn slice_count(&self) -> u16 {
        1_u16 << self.slice_bits
    }
}

impl<D: Digest> Write for Assignment<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.committee.write(writer);
        self.slice_bits.write(writer);
    }
}

impl<D: Digest> FixedSize for Assignment<D> {
    const SIZE: usize = D::SIZE + u8::SIZE;
}

impl<D: Digest> Read for Assignment<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let committee = D::read(reader)?;
        let slice_bits = u8::read(reader)?;
        Self::new(committee, slice_bits)
            .map_err(|_| CodecError::Invalid("clearing::Assignment", "slice-bit bound exceeded"))
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for Assignment<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            committee: u.arbitrary()?,
            slice_bits: u.int_in_range(0..=MAX_SLICE_BITS)?,
        })
    }
}

/// Signature variant carrying the operator's aggregable close countersignatures.
///
/// The prototype pins the committee's MinSig variant rather than threading a second variant
/// parameter through every close structure.
pub type OperatorVariant = MinSig;
/// The operator's aggregable-acceptance public key.
///
/// Deployment-fixed and dedicated: never a committee member's consensus key, even though the
/// signing namespaces already separate the message spaces.
pub type OperatorKey = <OperatorVariant as Variant>::Public;
/// One per-acknowledgment aggregable countersignature.
pub type OperatorSignature = <OperatorVariant as Variant>::Signature;
/// One proof slice's combined operator countersignature.
pub type OperatorAggregate = aggregate::Signature<OperatorVariant>;

/// The change, withdrawal-output, successor-state, coverage, and transpose roots for one close.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RootBundle<D: Digest> {
    /// Exact sorted changed-account vector.
    pub change: VectorRoot<D>,
    /// Validator-derived withdrawal outputs in request order.
    pub withdrawal_outputs: VectorRoot<D>,
    /// Complete successor account-state vector.
    pub successor: VectorRoot<D>,
    /// Gap-free positional boundaries for every deterministic proof slice.
    pub coverage: VectorRoot<D>,
    /// Recipient-major collated edge terminals.
    pub transpose: VectorRoot<D>,
    /// Exact transpose leaf count.
    ///
    /// Slice range openings prove membership under `transpose` but cannot see past their own
    /// interval, so without a committed total a closer could seal a transpose tree carrying
    /// trailing leaves no slice opens, leaving a certified close every full validator
    /// rejects. Pinning the count restores seal and audit agreement.
    pub transpose_len: u32,
}

impl<D: Digest> Write for RootBundle<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.change.write(writer);
        self.withdrawal_outputs.write(writer);
        self.successor.write(writer);
        self.coverage.write(writer);
        self.transpose.write(writer);
        self.transpose_len.write(writer);
    }
}

impl<D: Digest> FixedSize for RootBundle<D> {
    const SIZE: usize = VectorRoot::<D>::SIZE * 5 + u32::SIZE;
}

impl<D: Digest> Read for RootBundle<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            change: VectorRoot::read(reader)?,
            withdrawal_outputs: VectorRoot::read(reader)?,
            successor: VectorRoot::read(reader)?,
            coverage: VectorRoot::read(reader)?,
            transpose: VectorRoot::read(reader)?,
            transpose_len: u32::read(reader)?,
        })
    }
}

/// Context-bound digest committing to one sender-vector [`RootBundle`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Header<D: Digest>(D);

impl<D: Digest> Header<D> {
    /// Commits to the close context and every root in its exact protocol role.
    pub fn new<H, P>(context: &CloseContext<P, D>, roots: &RootBundle<D>) -> Self
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
    {
        let payment = context.payment().encode();
        let transpose_len = roots.transpose_len.to_be_bytes();
        Self(H::hash(&[
            HEADER_ROOT_HASH_NAMESPACE,
            payment.as_ref(),
            context.predecessor_root().digest.as_ref(),
            roots.change.digest.as_ref(),
            roots.withdrawal_outputs.digest.as_ref(),
            roots.successor.digest.as_ref(),
            roots.coverage.digest.as_ref(),
            roots.transpose.digest.as_ref(),
            &transpose_len,
        ]))
    }

    /// Returns whether `context` and `roots` match this header's exact protocol roles.
    pub fn verify<H, P>(&self, context: &CloseContext<P, D>, roots: &RootBundle<D>) -> bool
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
    {
        *self == Self::new::<H, P>(context, roots)
    }

    /// Returns the underlying header digest.
    pub const fn digest(&self) -> &D {
        &self.0
    }

    /// Derives the canonical identifier of this contextual header.
    pub fn batch_id<H: Hasher<Digest = D>>(&self) -> BatchId<D> {
        BatchId::new(H::hash(&[BATCH_ID_HASH_NAMESPACE, self.0.as_ref()]))
    }
}

impl<D: Digest> Write for Header<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl<D: Digest> FixedSize for Header<D> {
    const SIZE: usize = D::SIZE;
}

impl<D: Digest> Read for Header<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(D::read(reader)?))
    }
}

/// Header-committed positions, cumulative prefix, and accumulator checksums before one slice.
///
/// The leaf commits only the succinct [LtHash] checksums. Each slice carries the full start
/// states as witness data, verified against the committed checksums before accumulation
/// resumes, so adjacent slices provably continue from identical states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SliceBoundary {
    /// Position in the predecessor live-state vector.
    pub predecessor: u32,
    /// Position in the changed-row vector.
    pub change: u32,
    /// Position in the successor live-state vector.
    pub successor: u32,
    /// Exact cumulative row prefix before `change`.
    pub prefix: Prefix,
    /// Checksum of the payer-vector edge accumulator before `change`.
    pub out_check: Checksum,
    /// Checksum of the transpose edge accumulator before `prefix.in_count`.
    pub in_check: Checksum,
}

impl SliceBoundary {
    /// Returns the canonical first boundary: zero positions, empty prefix, empty accumulators.
    pub fn origin() -> Self {
        let empty = LtHash::new().checksum();
        Self {
            predecessor: 0,
            change: 0,
            successor: 0,
            prefix: Prefix::default(),
            out_check: empty,
            in_check: empty,
        }
    }
}

impl Write for SliceBoundary {
    fn write(&self, writer: &mut impl BufMut) {
        self.predecessor.write(writer);
        self.change.write(writer);
        self.successor.write(writer);
        self.prefix.write(writer);
        self.out_check.write(writer);
        self.in_check.write(writer);
    }
}

impl FixedSize for SliceBoundary {
    const SIZE: usize = u32::SIZE * 3 + Prefix::SIZE + Checksum::SIZE * 2;
}

impl Read for SliceBoundary {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            predecessor: u32::read(reader)?,
            change: u32::read(reader)?,
            successor: u32::read(reader)?,
            prefix: Prefix::read(reader)?,
            out_check: Checksum::read(reader)?,
            in_check: Checksum::read(reader)?,
        })
    }
}

/// Two adjacent authenticated coverage boundaries defining one slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageRange<D: Digest> {
    /// Boundary before this slice.
    pub start: SliceBoundary,
    /// Boundary after this slice.
    pub end: SliceBoundary,
    /// Authentication of the two adjacent boundary values.
    pub opening: RangeOpening<D>,
}

impl<D: Digest> Write for CoverageRange<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.start.write(writer);
        self.end.write(writer);
        self.opening.write(writer);
    }
}

impl<D: Digest> EncodeSize for CoverageRange<D> {
    fn encode_size(&self) -> usize {
        SliceBoundary::SIZE * 2 + self.opening.encode_size()
    }
}

impl<D: Digest> Read for CoverageRange<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            start: SliceBoundary::read(reader)?,
            end: SliceBoundary::read(reader)?,
            opening: RangeOpening::read_bounded(reader, 2, usize::MAX)?,
        })
    }
}

/// Exact contiguous changed-row slice for one account-key interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeRange<P: PublicKey, D: Digest> {
    /// Immediate compact guard before this interval, when one exists.
    pub predecessor: Option<ChangeGuard<P, D>>,
    /// Every changed row whose account belongs to this interval.
    pub rows: Vec<AccountRow<P, D>>,
    /// Immediate compact guard after this interval, when one exists.
    pub successor: Option<ChangeGuard<P, D>>,
    /// Authentication of the contiguous guards derived from the disclosed rows and boundaries.
    pub opening: RangeOpening<D>,
}

/// Authentication of one exact live-state interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRange<P: PublicKey, D: Digest> {
    /// Immediate live-state predecessor, when one exists.
    pub predecessor: Option<StateLeaf<P>>,
    /// Immediate live-state successor, when one exists.
    pub successor: Option<StateLeaf<P>>,
    /// Authentication of the contiguous guard-and-member slice.
    pub opening: RangeOpening<D>,
}

/// One proof slice for independently authenticating an account interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSlice<P: PublicKey, D: Digest> {
    /// Deterministic interval index.
    pub index: u16,
    /// Header-bound positions, prefix, and accumulators for this interval.
    pub coverage: CoverageRange<D>,
    /// Exact changed rows in this interval.
    pub changes: ChangeRange<P, D>,
    /// Outgoing vectors aligned one-for-one with [`ChangeRange::rows`].
    pub out_vectors: Vec<OutVector<P>>,
    /// Transpose entries in this interval's exact positional range.
    pub transpose: Vec<TransposeEntry<P>>,
    /// Full payer-vector accumulator state at the start boundary.
    pub out_start: LtHash,
    /// Combined operator countersignature over this interval's acknowledged bodies, present
    /// exactly when the interval contains a sending row.
    pub operator_aggregate: Option<OperatorAggregate>,
    /// Full transpose accumulator state at the start boundary.
    pub in_start: LtHash,
    /// Range opening for `transpose`, present exactly when it is nonempty.
    pub transpose_opening: Option<RangeOpening<D>>,
    /// Range opening for the validator-derived withdrawal outputs in this interval.
    pub withdrawal_opening: Option<RangeOpening<D>>,
    /// Live leaves unchanged across both roots in this interval.
    pub unchanged: Vec<StateLeaf<P>>,
    /// Exact guarded predecessor-state interval.
    pub predecessor: StateRange<P, D>,
    /// Exact guarded successor-state interval.
    pub successor: StateRange<P, D>,
}

impl<P: PublicKey, D: Digest> ProofSlice<P, D> {
    /// Returns the encoded size of this slice.
    pub fn encoded_size(&self) -> usize {
        self.index.encode_size()
            + self.coverage.encode_size()
            + self.changes.predecessor.encode_size()
            + self.changes.rows.encode_size()
            + self.changes.successor.encode_size()
            + self.changes.opening.encode_size()
            + self.out_vectors.encode_size()
            + self.operator_aggregate.encode_size()
            + transpose_encode_size(&self.transpose)
            + LtHash::SIZE * 2
            + self.transpose_opening.encode_size()
            + self.withdrawal_opening.encode_size()
            + self.unchanged.encode_size()
            + self.predecessor.predecessor.encode_size()
            + self.predecessor.successor.encode_size()
            + self.predecessor.opening.encode_size()
            + self.successor.predecessor.encode_size()
            + self.successor.successor.encode_size()
            + self.successor.opening.encode_size()
    }
}

/// Complete public corpus needed to validate one stateless sender-vector close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Close<P: PublicKey, D: Digest> {
    /// Settlement header produced by this corpus.
    pub header: Header<D>,
    /// Root preimage authenticated by `header`.
    pub roots: RootBundle<D>,
    /// Strictly account-sorted live leaves unchanged across both state roots.
    pub unchanged: Vec<StateLeaf<P>>,
    /// Strictly account-sorted changed rows.
    pub rows: Vec<AccountRow<P, D>>,
    /// Outgoing vectors aligned one-for-one with `rows`.
    pub out_vectors: Vec<OutVector<P>>,
    /// Combined operator countersignatures, one per proof slice interval.
    ///
    /// Quorum-attested rather than header-committed: for a fixed key and body multiset
    /// exactly one subgroup element verifies, so the aggregates are self-authenticating and
    /// tampering with a posted copy can only make that copy fail verification.
    pub operator_aggregates: Vec<Option<OperatorAggregate>>,
}

impl<P: PublicKey, D: Digest> Close<P, D> {
    /// Returns the encoded size of this corpus.
    ///
    /// The transpose never ships in the posted corpus: it is a pure function of the posted
    /// out vectors (sort the union by recipient, payer), rebuilt by any full validator and
    /// carried per interval only inside dealt slices.
    pub fn encoded_size(&self) -> usize {
        Header::<D>::SIZE
            + RootBundle::<D>::SIZE
            + self.unchanged.encode_size()
            + self.rows.encode_size()
            + self.out_vectors.encode_size()
    }

    /// Rebuilds the canonical recipient-major transpose from the posted out vectors.
    pub fn rebuild_transpose(&self) -> Result<Vec<TransposeEntry<P>>, TransitionError> {
        rebuild_transpose(&self.rows, &self.out_vectors)
    }
}

/// Collates the canonical transpose from rows and their aligned out vectors.
fn rebuild_transpose<P: PublicKey, D: Digest>(
    rows: &[AccountRow<P, D>],
    out_vectors: &[OutVector<P>],
) -> Result<Vec<TransposeEntry<P>>, TransitionError> {
    if rows.len() != out_vectors.len() {
        return Err(TransitionError::VectorAlignment);
    }
    let total = out_vectors
        .iter()
        .map(|vector| vector.entries().len())
        .try_fold(0_usize, |sum, len| sum.checked_add(len))
        .ok_or(TransitionError::CloseLimit)?;
    let mut transpose = Vec::with_capacity(total);
    for (row, vector) in rows.iter().zip(out_vectors) {
        if vector.payer() != &row.account {
            return Err(TransitionError::VectorAlignment);
        }
        for entry in vector.entries() {
            transpose.push(TransposeEntry {
                recipient: entry.recipient.clone(),
                payer: row.account.clone(),
                cumulative: entry.cumulative,
                count: entry.count,
            });
        }
    }
    transpose.sort_unstable_by(|left, right| {
        (&left.recipient, &left.payer).cmp(&(&right.recipient, &right.payer))
    });
    Ok(transpose)
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for RootBundle<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            change: u.arbitrary()?,
            withdrawal_outputs: u.arbitrary()?,
            successor: u.arbitrary()?,
            coverage: u.arbitrary()?,
            transpose: u.arbitrary()?,
            transpose_len: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for Header<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for SliceBoundary {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            predecessor: u.arbitrary()?,
            change: u.arbitrary()?,
            successor: u.arbitrary()?,
            prefix: u.arbitrary()?,
            out_check: u.arbitrary()?,
            in_check: u.arbitrary()?,
        })
    }
}

/// Canonical resource limits for constructing, decoding, and validating one close.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseLimits {
    max_states: u64,
    max_rows: u64,
    max_withdrawals: u64,
    max_account_entries: u64,
    max_total_entries: u64,
    max_payment_total: u64,
    max_deposit_total: u64,
    max_withdrawal_total: u64,
}

impl CloseLimits {
    /// Creates explicit close resource limits.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        max_states: u64,
        max_rows: u64,
        max_withdrawals: u64,
        max_account_entries: u64,
        max_total_entries: u64,
        max_payment_total: u64,
        max_deposit_total: u64,
        max_withdrawal_total: u64,
    ) -> Self {
        Self {
            max_states,
            max_rows,
            max_withdrawals,
            max_account_entries,
            max_total_entries,
            max_payment_total,
            max_deposit_total,
            max_withdrawal_total,
        }
    }

    /// Permits every close representable by the protocol.
    pub const fn protocol_maximum() -> Self {
        let vector = commitment::MAX_VECTOR_LENGTH as u64;
        Self::new(
            vector,
            vector,
            vector,
            vector,
            vector * vector,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        )
    }

    /// Returns the maximum live leaves in either state root.
    pub const fn max_states(&self) -> u64 {
        self.max_states
    }

    /// Returns the changed-row limit.
    pub const fn max_rows(&self) -> u64 {
        self.max_rows
    }

    /// Returns the withdrawal-record limit.
    pub const fn max_withdrawals(&self) -> u64 {
        self.max_withdrawals
    }

    /// Returns the per-account edge-entry limit.
    pub const fn max_account_entries(&self) -> u64 {
        self.max_account_entries
    }

    /// Returns the aggregate edge-entry limit.
    pub const fn max_total_entries(&self) -> u64 {
        self.max_total_entries
    }

    /// Returns the gross payment limit applied independently to debit, credit, and payout.
    pub const fn max_payment_total(&self) -> u64 {
        self.max_payment_total
    }

    /// Returns the aggregate deposit limit.
    pub const fn max_deposit_total(&self) -> u64 {
        self.max_deposit_total
    }

    /// Returns the aggregate applied-withdrawal limit.
    pub const fn max_withdrawal_total(&self) -> u64 {
        self.max_withdrawal_total
    }
}

impl Write for CloseLimits {
    fn write(&self, writer: &mut impl BufMut) {
        self.max_states.write(writer);
        self.max_rows.write(writer);
        self.max_withdrawals.write(writer);
        self.max_account_entries.write(writer);
        self.max_total_entries.write(writer);
        self.max_payment_total.write(writer);
        self.max_deposit_total.write(writer);
        self.max_withdrawal_total.write(writer);
    }
}

impl FixedSize for CloseLimits {
    const SIZE: usize = u64::SIZE * 8;
}

impl Read for CloseLimits {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            max_states: u64::read(reader)?,
            max_rows: u64::read(reader)?,
            max_withdrawals: u64::read(reader)?,
            max_account_entries: u64::read(reader)?,
            max_total_entries: u64::read(reader)?,
            max_payment_total: u64::read(reader)?,
            max_deposit_total: u64::read(reader)?,
            max_withdrawal_total: u64::read(reader)?,
        })
    }
}

/// Predecessor-state-root-independent registration shared by every payment in one epoch.
///
/// The settlement chain binds this registration to exactly one predecessor state root when the
/// close is registered. An embedding must never reuse the registration after its ancestry is
/// invalidated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochContext<P: PublicKey, D: Digest> {
    payment: PaymentContext<P, D>,
    deployment: D,
    deposit_root: VectorRoot<D>,
    withdrawal_root: VectorRoot<D>,
    predecessor_liability: u64,
    admission_deadline: Deadline,
    challenge_deadline: Deadline,
    limits: CloseLimits,
    assignment: Assignment<D>,
}

impl<P: PublicKey, D: Digest> EpochContext<P, D> {
    /// Authenticates the immutable payment, boundary, and validation parameters for one epoch.
    ///
    /// Admission must precede the challenge deadline, and the challenge deadline must leave one
    /// representable later timestamp for finalization or expiry. The predecessor liability remains
    /// authenticated, but [`CloseContext`] adds its exact state root later so successor payments can
    /// begin while the predecessor close is constructed.
    ///
    /// This is the single verification point for the boundary batches. Every later validation
    /// pins its batch arguments to the roots committed here instead of re-verifying them.
    #[allow(clippy::too_many_arguments)]
    pub fn new<H: Hasher<Digest = D>>(
        deployment: D,
        epoch: u64,
        operator: P,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
        predecessor_liability: u64,
        admission_deadline: Deadline,
        challenge_deadline: Deadline,
        limits: CloseLimits,
        assignment: Assignment<D>,
    ) -> Result<Self, TransitionError> {
        if admission_deadline >= challenge_deadline || challenge_deadline == u64::MAX {
            return Err(TransitionError::DeadlineOrder);
        }
        validate_boundary_batches(&deployment, deposits, withdrawals, &limits)?;

        // A sealed boundary must leave a buildable close. Every account's
        // post-deposit holdings stay representable because the aggregate does.
        predecessor_liability
            .checked_add(deposits.total())
            .ok_or(TransitionError::LiabilityOverflow)?;

        let deposit_root = deposits.root::<H>()?;
        let withdrawal_root = withdrawals.root::<H>()?;
        let deposit_root_encoded = deposit_root.encode();
        let withdrawal_root_encoded = withdrawal_root.encode();
        let predecessor_liability_encoded = predecessor_liability.to_be_bytes();
        let epoch_encoded = epoch.to_be_bytes();
        let admission_deadline_encoded = admission_deadline.to_be_bytes();
        let challenge_deadline_encoded = challenge_deadline.to_be_bytes();
        let limits_encoded = limits.encode();
        let assignment_encoded = assignment.encode();
        let anchor = H::hash(&[
            EPOCH_ANCHOR_HASH_NAMESPACE,
            deployment.as_ref(),
            deposit_root_encoded.as_ref(),
            withdrawal_root_encoded.as_ref(),
            &predecessor_liability_encoded,
            &epoch_encoded,
            operator.as_ref(),
            &admission_deadline_encoded,
            &challenge_deadline_encoded,
            limits_encoded.as_ref(),
            assignment_encoded.as_ref(),
        ]);

        Ok(Self {
            payment: PaymentContext::new(anchor, epoch, operator),
            deployment,
            deposit_root,
            withdrawal_root,
            predecessor_liability,
            admission_deadline,
            challenge_deadline,
            limits,
            assignment,
        })
    }

    /// Binds this epoch registration to one exact predecessor state.
    pub fn bind<H: Hasher<Digest = D>>(
        self,
        cache: &StateCache<P, D>,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
    ) -> Result<CloseContext<P, D>, TransitionError> {
        if deposits.root::<H>()? != self.deposit_root
            || withdrawals.root::<H>()? != self.withdrawal_root
        {
            return Err(TransitionError::BoundaryRoot);
        }
        if cache.liability() != self.predecessor_liability {
            return Err(TransitionError::PredecessorLiability);
        }
        validate_sealed_boundaries(cache, deposits, withdrawals, &self.limits)?;
        Ok(CloseContext {
            epoch: self,
            predecessor_root: cache.root(),
        })
    }

    /// Binds the root already owned by the settlement state machine.
    ///
    /// Settlement intake establishes each request's start affordability, through safety openings
    /// when queueing and through one predecessor-root opening for operator-carried requests.
    /// Later epoch spending can still lower the tail, which certification settles with a zero
    /// release. Callers outside that owner must use [`Self::bind`] with the complete state cache.
    pub(crate) const fn bind_settlement_root(
        self,
        predecessor_root: VectorRoot<D>,
    ) -> CloseContext<P, D> {
        CloseContext {
            epoch: self,
            predecessor_root,
        }
    }

    /// Returns the anchored payment context.
    pub const fn payment(&self) -> &PaymentContext<P, D> {
        &self.payment
    }

    /// Returns the settlement deployment identifier.
    pub const fn deployment(&self) -> &D {
        &self.deployment
    }

    /// Returns the exact sealed deposit-vector root.
    pub const fn deposit_root(&self) -> &VectorRoot<D> {
        &self.deposit_root
    }

    /// Returns the exact sealed withdrawal-vector root.
    pub const fn withdrawal_root(&self) -> &VectorRoot<D> {
        &self.withdrawal_root
    }

    /// Returns the authenticated predecessor liability.
    pub const fn predecessor_liability(&self) -> u64 {
        self.predecessor_liability
    }

    /// Returns the last time at which this close may be admitted.
    pub const fn admission_deadline(&self) -> Deadline {
        self.admission_deadline
    }

    /// Returns the exact challenge deadline.
    pub const fn challenge_deadline(&self) -> Deadline {
        self.challenge_deadline
    }

    /// Returns the resource limits authenticated by the epoch anchor.
    pub const fn limits(&self) -> &CloseLimits {
        &self.limits
    }

    /// Returns the authenticated committee and deterministic slice partition.
    pub const fn assignment(&self) -> &Assignment<D> {
        &self.assignment
    }

    /// Reassembles a context from parts retained by an earlier construction.
    ///
    /// No boundary validation or anchor recomputation happens here, so the
    /// parts must come from an [`EpochContext`] that was constructed and
    /// authenticated through [`Self::new`] (for example one persisted by the
    /// settlement chain codec).
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_parts(
        payment: PaymentContext<P, D>,
        deployment: D,
        deposit_root: VectorRoot<D>,
        withdrawal_root: VectorRoot<D>,
        predecessor_liability: u64,
        admission_deadline: Deadline,
        challenge_deadline: Deadline,
        limits: CloseLimits,
        assignment: Assignment<D>,
    ) -> Self {
        Self {
            payment,
            deployment,
            deposit_root,
            withdrawal_root,
            predecessor_liability,
            admission_deadline,
            challenge_deadline,
            limits,
            assignment,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for EpochContext<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            payment: PaymentContext::new(u.arbitrary()?, u.arbitrary()?, u.arbitrary()?),
            deployment: u.arbitrary()?,
            deposit_root: u.arbitrary()?,
            withdrawal_root: u.arbitrary()?,
            predecessor_liability: u.arbitrary()?,
            admission_deadline: u.arbitrary()?,
            challenge_deadline: u.arbitrary()?,
            limits: u.arbitrary()?,
            assignment: u.arbitrary()?,
        })
    }
}

/// Chain-known epoch registration bound to one exact predecessor state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseContext<P: PublicKey, D: Digest> {
    epoch: EpochContext<P, D>,
    predecessor_root: VectorRoot<D>,
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for CloseContext<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            epoch: u.arbitrary()?,
            predecessor_root: u.arbitrary()?,
        })
    }
}

impl<P: PublicKey, D: Digest> CloseContext<P, D> {
    /// Returns the root-independent epoch registration.
    pub const fn epoch_context(&self) -> &EpochContext<P, D> {
        &self.epoch
    }

    /// Returns the anchored payment context.
    pub const fn payment(&self) -> &PaymentContext<P, D> {
        self.epoch.payment()
    }

    /// Returns the settlement deployment identifier.
    pub const fn deployment(&self) -> &D {
        self.epoch.deployment()
    }

    /// Returns the exact sealed deposit-vector root.
    pub const fn deposit_root(&self) -> &VectorRoot<D> {
        self.epoch.deposit_root()
    }

    /// Returns the exact sealed withdrawal-vector root.
    pub const fn withdrawal_root(&self) -> &VectorRoot<D> {
        self.epoch.withdrawal_root()
    }

    /// Returns the bound predecessor state root.
    pub const fn predecessor_root(&self) -> &VectorRoot<D> {
        &self.predecessor_root
    }

    /// Returns the authenticated predecessor liability.
    pub const fn predecessor_liability(&self) -> u64 {
        self.epoch.predecessor_liability()
    }

    /// Returns the last time at which this close may be admitted.
    pub const fn admission_deadline(&self) -> Deadline {
        self.epoch.admission_deadline()
    }

    /// Returns the exact challenge deadline.
    pub const fn challenge_deadline(&self) -> Deadline {
        self.epoch.challenge_deadline()
    }

    /// Returns the resource limits authenticated by the epoch anchor.
    pub const fn limits(&self) -> &CloseLimits {
        self.epoch.limits()
    }

    /// Returns the authenticated committee and deterministic slice partition.
    pub const fn assignment(&self) -> &Assignment<D> {
        self.epoch.assignment()
    }

    /// Reassembles a bound context from parts retained by an earlier binding.
    ///
    /// See [`EpochContext::from_parts`] for the provenance requirement.
    pub(crate) const fn from_parts(
        epoch: EpochContext<P, D>,
        predecessor_root: VectorRoot<D>,
    ) -> Self {
        Self {
            epoch,
            predecessor_root,
        }
    }
}

/// One external payout derived from a certified receive by an absent account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPayout<P: PublicKey> {
    /// Recipient account, interpreted by the embedding asset adapter.
    pub recipient: P,
    /// Exact value released to the recipient.
    pub amount: u64,
}

/// Validator-derived settlement output for one canonical withdrawal request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalOutput {
    destination: Bytes,
    amount: u64,
}

impl WithdrawalOutput {
    pub(crate) fn from_request<P: PublicKey, D: Digest>(
        request: &SignedWithdrawal<P, D>,
        amount: u64,
    ) -> Self {
        Self {
            destination: request.body().destination().clone(),
            amount,
        }
    }

    /// Returns the opaque asset-adapter destination.
    #[must_use]
    pub const fn destination(&self) -> &Bytes {
        &self.destination
    }

    /// Returns the exact amount released by the certified close.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }
}

impl Write for WithdrawalOutput {
    fn write(&self, writer: &mut impl BufMut) {
        self.destination.write(writer);
        self.amount.write(writer);
    }
}

impl EncodeSize for WithdrawalOutput {
    fn encode_size(&self) -> usize {
        self.destination.encode_size() + u64::SIZE
    }

    fn encode_inline_size(&self) -> usize {
        self.destination.encode_inline_size() + u64::SIZE
    }
}

impl Read for WithdrawalOutput {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(reader: &mut impl Buf, destination_cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            destination: Bytes::read_cfg(reader, destination_cfg)?,
            amount: u64::read(reader)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for WithdrawalOutput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = usize::from(u.arbitrary::<u8>()? % 65);
        Ok(Self {
            destination: Bytes::copy_from_slice(u.bytes(len)?),
            amount: u.arbitrary()?,
        })
    }
}

/// Constant-size settlement witness for the terminal counts and aggregate flows.
///
/// Individual external payouts and withdrawals are claimed later with bounded Merkle witnesses.
/// The operator therefore never publishes a recipient-sized payout list during admission or
/// finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProof<D: Digest> {
    terminal: SliceBoundary,
    terminal_opening: commitment::Opening<D>,
}

impl<D: Digest> TerminalProof<D> {
    /// Returns the authenticated terminal coverage boundary.
    #[must_use]
    pub const fn terminal(&self) -> &SliceBoundary {
        &self.terminal
    }

    /// Authenticates the terminal counts and aggregate flows against a complete root bundle.
    ///
    /// # Security
    ///
    /// The caller must establish that the header was certified by the epoch committee. This
    /// method verifies the header binding and terminal opening, not the certificate itself.
    pub fn verify<H, P>(
        &self,
        context: &CloseContext<P, D>,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
        header: &Header<D>,
        roots: &RootBundle<D>,
    ) -> Result<Prefix, TransitionError>
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
    {
        validate_header::<H, P, D>(context, header, roots)?;
        validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;
        verify_terminal_proof_after_header::<H, P, D>(context, deposits, withdrawals, roots, self)
            .map(|(prefix, _)| prefix)
    }
}

impl<D: Digest> Write for TerminalProof<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.terminal.write(writer);
        self.terminal_opening.write(writer);
    }
}

impl<D: Digest> EncodeSize for TerminalProof<D> {
    fn encode_size(&self) -> usize {
        self.terminal.encode_size() + self.terminal_opening.encode_size()
    }
}

impl<D: Digest> Read for TerminalProof<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            terminal: SliceBoundary::read(reader)?,
            terminal_opening: commitment::Opening::read(reader)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for TerminalProof<D>
where
    D: Digest,
    SliceBoundary: for<'a> arbitrary::Arbitrary<'a>,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            terminal: u.arbitrary()?,
            terminal_opening: u.arbitrary()?,
        })
    }
}

/// One claim for net credit classified as an external payout by a certified changed row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPayoutClaim<P: PublicKey, D: Digest> {
    leaf: AccountChange<P, D>,
    opening: commitment::Opening<D>,
}

impl<P: PublicKey, D: Digest> ExternalPayoutClaim<P, D> {
    /// Returns the claimed change-vector position.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.opening.position
    }

    /// Returns the payout recipient.
    #[must_use]
    pub const fn recipient(&self) -> &P {
        self.leaf.account()
    }

    /// Verifies this claim against an already authenticated finalized change root.
    ///
    /// Validators derive the compact output while validating the full changed row. This method
    /// therefore proves inclusion and classification, not the row relation independently.
    ///
    /// The embedding must bind `change_root` to the finalized batch and consume the tuple of that
    /// batch identifier and [`Self::position`] atomically with the payout.
    pub fn verify<H>(
        &self,
        change_root: &VectorRoot<D>,
    ) -> Result<ExternalPayout<P>, TransitionError>
    where
        H: Hasher<Digest = D>,
    {
        self.opening.verify::<H>(
            VectorKind::Change,
            change_root,
            self.leaf.guard::<H>().encode().as_ref(),
        )?;
        let SettlementOutput::ExternalPayout(amount) = self.leaf.output() else {
            return Err(TransitionError::PayoutClaim);
        };
        if amount == 0 {
            return Err(TransitionError::PayoutClaim);
        }
        Ok(ExternalPayout {
            recipient: self.leaf.account().clone(),
            amount,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for ExternalPayoutClaim<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.leaf.write(writer);
        self.opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ExternalPayoutClaim<P, D> {
    fn encode_size(&self) -> usize {
        self.leaf.encode_size() + self.opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for ExternalPayoutClaim<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            leaf: AccountChange::read(reader)?,
            opening: commitment::Opening::read(reader)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ExternalPayoutClaim<P, D>
where
    P: PublicKey,
    D: Digest,
    AccountChange<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            leaf: u.arbitrary()?,
            opening: u.arbitrary()?,
        })
    }
}

/// One claim for a validator-derived withdrawal output in a finalized close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalClaim<D: Digest> {
    output: WithdrawalOutput,
    output_opening: commitment::Opening<D>,
}

impl<D: Digest> WithdrawalClaim<D> {
    /// Returns the certified settlement output.
    #[must_use]
    pub const fn output(&self) -> &WithdrawalOutput {
        &self.output
    }

    /// Returns the request's canonical withdrawal-vector position.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.output_opening.position
    }

    /// Verifies and returns the exact certified settlement output.
    ///
    /// Every validator derives this output from the exact signed request assigned to the same
    /// position. The embedding must bind `output_root` to the finalized batch and consume the
    /// batch position atomically with the release.
    pub fn verify<H>(
        &self,
        output_root: &VectorRoot<D>,
    ) -> Result<WithdrawalOutput, TransitionError>
    where
        H: Hasher<Digest = D>,
    {
        self.output_opening.verify::<H>(
            VectorKind::WithdrawalOutput,
            output_root,
            self.output.encode().as_ref(),
        )?;
        Ok(self.output.clone())
    }
}

impl<D: Digest> Write for WithdrawalClaim<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.output.write(writer);
        self.output_opening.write(writer);
    }
}

impl<D: Digest> EncodeSize for WithdrawalClaim<D> {
    fn encode_size(&self) -> usize {
        self.output.encode_size() + self.output_opening.encode_size()
    }
}

impl<D: Digest> Read for WithdrawalClaim<D> {
    /// Maximum encoded destination length.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(reader: &mut impl Buf, destination_cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            output: WithdrawalOutput::read_cfg(reader, destination_cfg)?,
            output_opening: commitment::Opening::read(reader)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for WithdrawalClaim<D>
where
    D: Digest,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            output: u.arbitrary()?,
            output_opening: u.arbitrary()?,
        })
    }
}

/// One prepared sender-vector close with the Merkle state needed for dealing proof slices.
#[derive(Debug)]
pub struct PreparedClose<P: PublicKey, D: Digest> {
    close: Close<P, D>,
    transpose: Vec<TransposeEntry<P>>,
    predecessor_root: VectorRoot<D>,
    change_leaves: Vec<AccountChange<P, D>>,
    change_guards: Vec<ChangeGuard<P, D>>,
    changes: Tree<D>,
    withdrawal_outputs: Vec<WithdrawalOutput>,
    withdrawal_output_tree: Tree<D>,
    successor_leaves: Vec<StateLeaf<P>>,
    successor: Tree<D>,
    transpose_tree: Tree<D>,
    coverage_boundaries: Vec<SliceBoundary>,
    boundary_states: Vec<(LtHash, LtHash)>,
    coverage: Tree<D>,
}

impl<P: PublicKey, D: Digest> PreparedClose<P, D> {
    /// Returns the canonical prepared close.
    #[must_use]
    pub const fn close(&self) -> &Close<P, D> {
        &self.close
    }

    /// Discards the retained Merkle state and returns the canonical close.
    #[must_use]
    pub fn into_close(self) -> Close<P, D> {
        self.close
    }

    fn slice_bits(&self) -> u8 {
        let slice_count = self.coverage_boundaries.len() - 1;
        assert!(slice_count.is_power_of_two());
        u8::try_from(slice_count.ilog2()).expect("prepared slice count fits the supported width")
    }

    /// Validates the complete close relation without reconstructing any retained root.
    pub fn validate<H, B, R>(
        &self,
        context: &CloseContext<P, D>,
        operator: &OperatorKey,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> Result<(), TransitionError>
    where
        H: Hasher<Digest = D>,
        B: BatchVerifier<PublicKey = P>,
        R: CryptoRng,
    {
        let close = &self.close;
        validate_close_preamble::<H, P, D>(context, deposits, withdrawals, close)?;
        validate_operator_aggregates(operator, close, &self.coverage_boundaries, strategy)?;
        validate_close_rows::<H, P, D, B, R>(
            context,
            deposits,
            withdrawals,
            close,
            &self.transpose,
            rng,
            strategy,
        )?;
        let terminal = self
            .coverage_boundaries
            .last()
            .ok_or(TransitionError::SliceCoverage)?;
        let row_count =
            u32::try_from(close.rows.len()).map_err(|_| TransitionError::TooManyRows)?;
        validate_terminal_boundary::<H, P, D>(
            context,
            &close.roots,
            deposits,
            withdrawals,
            row_count,
            terminal,
        )?;
        Ok(())
    }

    /// Deals every deterministic proof slice from the retained Merkle state.
    pub fn assemble_slices(
        &self,
        cache: &StateCache<P, D>,
        strategy: &impl Strategy,
    ) -> Result<Vec<ProofSlice<P, D>>, TransitionError> {
        if cache.root() != self.predecessor_root {
            return Err(TransitionError::PredecessorRoot);
        }
        let slice_bits = self.slice_bits();
        let unchanged_boundaries = state_boundaries(&self.close.unchanged, slice_bits)?;
        let slice_count = 1_u16 << slice_bits;
        strategy.try_map_collect_vec(0..slice_count, |index| {
            let slice = usize::from(index);
            let start_boundary = self.coverage_boundaries[slice];
            let end_boundary = self.coverage_boundaries[slice + 1];
            let start = start_boundary.change as usize;
            let end = end_boundary.change as usize;
            let (predecessor, change_successor, opening) = self.changes.bracket(
                &self.change_guards,
                start_boundary.change..end_boundary.change,
            )?;
            let withdrawal_start = u32::try_from(start_boundary.prefix.withdrawal_count)
                .map_err(|_| TransitionError::SliceRange)?;
            let withdrawal_count = u32::try_from(
                end_boundary
                    .prefix
                    .withdrawal_count
                    .checked_sub(start_boundary.prefix.withdrawal_count)
                    .ok_or(TransitionError::SliceRange)?,
            )
            .map_err(|_| TransitionError::SliceRange)?;
            let transpose_start = u32::try_from(start_boundary.prefix.in_count)
                .map_err(|_| TransitionError::SliceRange)?;
            let transpose_count = u32::try_from(
                end_boundary
                    .prefix
                    .in_count
                    .checked_sub(start_boundary.prefix.in_count)
                    .ok_or(TransitionError::SliceRange)?,
            )
            .map_err(|_| TransitionError::SliceRange)?;
            Ok(ProofSlice {
                index,
                coverage: CoverageRange {
                    start: start_boundary,
                    end: end_boundary,
                    opening: self.coverage.range_opening(u32::from(index), 2)?,
                },
                changes: ChangeRange {
                    predecessor,
                    rows: self.close.rows[start..end].to_vec(),
                    successor: change_successor,
                    opening,
                },
                out_vectors: self.close.out_vectors[start..end].to_vec(),
                operator_aggregate: self.close.operator_aggregates[slice].clone(),
                transpose: self.transpose
                    [transpose_start as usize..(transpose_start + transpose_count) as usize]
                    .to_vec(),
                out_start: self.boundary_states[slice].0.clone(),
                in_start: self.boundary_states[slice].1.clone(),
                transpose_opening: (transpose_count != 0)
                    .then(|| {
                        self.transpose_tree
                            .range_opening(transpose_start, transpose_count)
                    })
                    .transpose()?,
                withdrawal_opening: (withdrawal_count != 0)
                    .then(|| {
                        self.withdrawal_output_tree
                            .range_opening(withdrawal_start, withdrawal_count)
                    })
                    .transpose()?,
                unchanged: self.close.unchanged[unchanged_boundaries[slice] as usize
                    ..unchanged_boundaries[slice + 1] as usize]
                    .to_vec(),
                predecessor: build_state_range(
                    cache.leaves(),
                    cache.tree(),
                    start_boundary.predecessor,
                    end_boundary.predecessor,
                )?,
                successor: build_state_range(
                    &self.successor_leaves,
                    &self.successor,
                    start_boundary.successor,
                    end_boundary.successor,
                )?,
            })
        })
    }

    /// Opens the terminal counts, flows, and accumulator equality for settlement admission.
    pub fn terminal_proof(&self) -> Result<TerminalProof<D>, TransitionError> {
        let position = u32::try_from(self.coverage_boundaries.len() - 1)
            .map_err(|_| TransitionError::SliceCoverage)?;
        Ok(TerminalProof {
            terminal: self.coverage_boundaries[position as usize],
            terminal_opening: self.coverage.opening(position)?,
        })
    }

    /// Opens one validator-derived withdrawal output and its membership proof.
    pub fn withdrawal_claim(
        &self,
        withdrawals: &WithdrawalBatch<P, D>,
        account: &P,
    ) -> Result<WithdrawalClaim<D>, TransitionError> {
        let position = withdrawals
            .requests()
            .binary_search_by(|request| request.account().cmp(account))
            .map_err(|_| TransitionError::WithdrawalClaim)?;
        let output = self
            .withdrawal_outputs
            .get(position)
            .cloned()
            .ok_or(TransitionError::WithdrawalClaim)?;
        Ok(WithdrawalClaim {
            output,
            output_opening: self
                .withdrawal_output_tree
                .opening(u32::try_from(position).map_err(|_| TransitionError::WithdrawalClaim)?)?,
        })
    }

    /// Opens one external payout by recipient for later claiming.
    pub fn external_payout_claim(
        &self,
        recipient: &P,
    ) -> Result<ExternalPayoutClaim<P, D>, TransitionError> {
        let position = self
            .close
            .rows
            .binary_search_by(|row| row.account.cmp(recipient))
            .map_err(|_| TransitionError::PayoutClaim)?;
        let position = u32::try_from(position).map_err(|_| TransitionError::TooManyRows)?;
        let leaf = self
            .change_leaves
            .get(position as usize)
            .cloned()
            .ok_or(TransitionError::PayoutClaim)?;
        if !matches!(leaf.output(), SettlementOutput::ExternalPayout(amount) if amount != 0) {
            return Err(TransitionError::PayoutClaim);
        }
        Ok(ExternalPayoutClaim {
            leaf,
            opening: self.changes.opening(position)?,
        })
    }
}

/// Assembles a sender-vector close and retains its Merkle material for later dealing.
///
/// `out_partials` carries one sender-maintained accumulator partial per row, aligned with
/// `out_vectors`. The closer lane-sums these into coverage boundaries instead of expanding
/// every edge itself. A wrong partial yields an invalid close that validators reject, so the
/// closer trusts them only with its own liveness.
#[allow(clippy::too_many_arguments)]
pub fn prepare_close_with_strategy<H, P, D>(
    cache: &StateCache<P, D>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    rows: Vec<AccountRow<P, D>>,
    out_vectors: Vec<OutVector<P>>,
    out_partials: &[LtHash],
    operator_signatures: &[Option<OperatorSignature>],
    transpose: Vec<TransposeEntry<P>>,
    strategy: &impl Strategy,
) -> Result<PreparedClose<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if cache.root() != *context.predecessor_root() {
        return Err(TransitionError::PredecessorRoot);
    }
    if out_partials.len() != rows.len() || operator_signatures.len() != rows.len() {
        return Err(TransitionError::VectorAlignment);
    }
    if rows
        .iter()
        .zip(operator_signatures)
        .any(|(row, signature)| row.outgoing.is_some() != signature.is_some())
    {
        return Err(TransitionError::VectorAlignment);
    }
    if cache.liability() != context.predecessor_liability() {
        return Err(TransitionError::PredecessorLiability);
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::NonCanonicalRows);
    }
    let totals = rows.last().map_or_else(Prefix::default, |row| row.prefix);
    validate_corpus_limits(context, &rows, &out_vectors, totals)?;
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;

    let unchanged = derive_unchanged(cache.leaves(), &rows)?;
    let successor_leaves = derive_successor(
        &unchanged,
        &rows,
        cache.leaves(),
        context.limits().max_states(),
    )?;

    let successor = state_tree_with_strategy::<H, P, D>(&successor_leaves, strategy)?;
    let (change_leaves, change_guards, changes) =
        change_material_with_strategy::<H, P, D>(&rows, &out_vectors, strategy)?;
    let (withdrawal_outputs, withdrawal_output_tree) =
        withdrawal_output_material_with_strategy::<H, P, D>(&rows, withdrawals, strategy)?;
    let transpose_tree = transpose_tree_with_strategy::<H, P, D>(&transpose, strategy)?;
    let (coverage_boundaries, boundary_states) = derive_coverage::<P, D>(
        &rows,
        &out_vectors,
        Some(out_partials),
        &transpose,
        cache.leaves(),
        &successor_leaves,
        context.assignment().slice_bits(),
        strategy,
    )?;
    let coverage = coverage_tree_with_strategy::<H, D>(&coverage_boundaries, strategy)?;
    let operator_aggregates = coverage_boundaries
        .windows(2)
        .map(|window| {
            let range = window[0].change as usize..window[1].change as usize;
            NonEmpty::try_new(operator_signatures[range].iter().flatten()).map(combine_signatures)
        })
        .collect::<Vec<_>>();
    let expected_liability = checked_successor_liability(
        cache.liability(),
        deposits.total(),
        totals.withdrawal,
        totals.payout,
    )?;
    if state_liability(&successor_leaves)? != expected_liability {
        return Err(TransitionError::LiabilityEquation);
    }
    let roots = RootBundle {
        change: changes.root(),
        withdrawal_outputs: withdrawal_output_tree.root(),
        successor: successor.root(),
        coverage: coverage.root(),
        transpose: transpose_tree.root(),
        transpose_len: u32::try_from(transpose.len()).map_err(|_| TransitionError::CloseLimit)?,
    };
    let close = Close {
        header: Header::new::<H, P>(context, &roots),
        roots,
        unchanged,
        rows,
        out_vectors,
        operator_aggregates,
    };
    Ok(PreparedClose {
        close,
        transpose,
        predecessor_root: cache.root(),
        change_leaves,
        change_guards,
        changes,
        withdrawal_outputs,
        withdrawal_output_tree,
        successor_leaves,
        successor,
        transpose_tree,
        coverage_boundaries,
        boundary_states,
        coverage,
    })
}

/// Reusable index for constructing bounded account lookups against one sender-vector close.
#[derive(Clone, Debug)]
pub struct ChallengeIndex<P: PublicKey, D: Digest> {
    predecessor_root: VectorRoot<D>,
    leaves: Vec<AccountChange<P, D>>,
    guards: Vec<ChangeGuard<P, D>>,
    tree: Tree<D>,
}

impl<P: PublicKey, D: Digest> ChallengeIndex<P, D> {
    /// Builds and authenticates the changed-row tree once for repeated challenge construction.
    pub fn new<H: Hasher<Digest = D>>(
        context: &CloseContext<P, D>,
        close: &Close<P, D>,
    ) -> Result<Self, TransitionError> {
        if !close.header.verify::<H, P>(context, &close.roots) {
            return Err(TransitionError::HeaderRoot);
        }
        if close
            .rows
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(TransitionError::NonCanonicalRows);
        }
        let (leaves, guards, tree) =
            change_material_with_strategy::<H, P, D>(&close.rows, &close.out_vectors, &Sequential)?;
        if tree.root() != close.roots.change {
            return Err(TransitionError::ChangeRoot);
        }
        Ok(Self {
            predecessor_root: *context.predecessor_root(),
            leaves,
            guards,
            tree,
        })
    }

    /// Returns the authenticated change-vector root committed by this index.
    #[must_use]
    pub const fn root(&self) -> VectorRoot<D> {
        self.tree.root()
    }

    /// Returns the compact leaf, membership opening, or ordered absence for one account.
    pub fn change_parts(&self, account: &P) -> Result<ChangeParts<P, D>, TransitionError> {
        match self
            .leaves
            .binary_search_by(|leaf| leaf.account().cmp(account))
        {
            Ok(position) => Ok(ChangeParts::Present {
                leaf: self.leaves[position].clone(),
                proof: self.tree.opening(position as u32)?,
            }),
            Err(insertion) => {
                let insertion =
                    u32::try_from(insertion).map_err(|_| TransitionError::SliceRange)?;
                let (predecessor, successor, opening) =
                    self.tree.bracket(&self.guards, insertion..insertion)?;
                Ok(ChangeParts::Absent {
                    predecessor,
                    successor,
                    opening,
                })
            }
        }
    }

    /// Returns the bound predecessor state root.
    #[must_use]
    pub const fn predecessor_root(&self) -> &VectorRoot<D> {
        &self.predecessor_root
    }
}

/// Raw change-vector lookup material for one account.
#[derive(Clone, Debug)]
pub enum ChangeParts<P: PublicKey, D: Digest> {
    /// The account changed.
    Present {
        /// Compact changed-account leaf.
        leaf: AccountChange<P, D>,
        /// Membership opening for its guard.
        proof: commitment::Opening<D>,
    },
    /// The account is absent from the change vector.
    Absent {
        /// Immediate predecessor guard, when one exists.
        predecessor: Option<ChangeGuard<P, D>>,
        /// Immediate successor guard, when one exists.
        successor: Option<ChangeGuard<P, D>>,
        /// One contiguous proof for the disclosed adjacent leaves.
        opening: RangeOpening<D>,
    },
}

/// Verifies the complete public close relation from a decoded corpus.
pub fn validate_close_with_strategy<H, P, D, B, R>(
    context: &CloseContext<P, D>,
    operator: &OperatorKey,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
    rng: &mut R,
    strategy: &impl Strategy,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
{
    validate_close_preamble::<H, P, D>(context, deposits, withdrawals, close)?;
    if change_material_with_strategy::<H, P, D>(&close.rows, &close.out_vectors, strategy)?
        .2
        .root()
        != close.roots.change
    {
        return Err(TransitionError::ChangeRoot);
    }
    if withdrawal_output_material_with_strategy::<H, P, D>(&close.rows, withdrawals, strategy)?
        .1
        .root()
        != close.roots.withdrawal_outputs
    {
        return Err(TransitionError::WithdrawalOutputRoot);
    }
    // The posted corpus never carries the transpose: rebuild the canonical collation from
    // the posted vectors and hold the committed root to it.
    let transpose = close.rebuild_transpose()?;
    if u32::try_from(transpose.len()).ok() != Some(close.roots.transpose_len)
        || transpose_tree_with_strategy::<H, P, D>(&transpose, strategy)?.root()
            != close.roots.transpose
    {
        return Err(TransitionError::TransposeRoot);
    }
    let (predecessor, successor) =
        derive_state_vectors(&close.unchanged, &close.rows, context.limits().max_states())?;
    let predecessor_tree = state_tree_with_strategy::<H, P, D>(&predecessor, strategy)?;
    let successor_tree = state_tree_with_strategy::<H, P, D>(&successor, strategy)?;
    if predecessor_tree.root() != *context.predecessor_root() {
        return Err(TransitionError::PredecessorRoot);
    }
    if successor_tree.root() != close.roots.successor {
        return Err(TransitionError::SuccessorRoot);
    }
    let (coverage, _) = derive_coverage::<P, D>(
        &close.rows,
        &close.out_vectors,
        None,
        &transpose,
        &predecessor,
        &successor,
        context.assignment().slice_bits(),
        strategy,
    )?;
    if coverage_tree_with_strategy::<H, D>(&coverage, strategy)?.root() != close.roots.coverage {
        return Err(TransitionError::SliceCoverage);
    }
    validate_operator_aggregates(operator, close, &coverage, strategy)?;
    validate_close_rows::<H, P, D, B, R>(
        context,
        deposits,
        withdrawals,
        close,
        &transpose,
        rng,
        strategy,
    )?;
    let terminal = coverage.last().ok_or(TransitionError::SliceCoverage)?;
    let row_count = u32::try_from(close.rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    validate_terminal_boundary::<H, P, D>(
        context,
        &close.roots,
        deposits,
        withdrawals,
        row_count,
        terminal,
    )?;
    Ok(())
}

fn validate_close_preamble<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if !close.header.verify::<H, P>(context, &close.roots) {
        return Err(TransitionError::HeaderRoot);
    }
    if close.rows.len() != close.out_vectors.len() {
        return Err(TransitionError::VectorAlignment);
    }
    if u32::try_from(close.rows.len()).map_err(|_| TransitionError::TooManyRows)?
        > commitment::MAX_VECTOR_LENGTH
    {
        return Err(TransitionError::TooManyRows);
    }
    if close
        .rows
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::NonCanonicalRows);
    }
    let totals = close
        .rows
        .last()
        .map_or_else(Prefix::default, |row| row.prefix);
    validate_corpus_limits(context, &close.rows, &close.out_vectors, totals)?;
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;
    for record in deposits.records() {
        if close
            .rows
            .binary_search_by(|row| row.account.cmp(record.account()))
            .is_err()
        {
            return Err(TransitionError::BoundaryAccountMissing);
        }
    }
    for request in withdrawals.requests() {
        if close
            .rows
            .binary_search_by(|row| row.account.cmp(request.account()))
            .is_err()
        {
            return Err(TransitionError::BoundaryAccountMissing);
        }
    }
    Ok(())
}

fn validate_close_rows<H, P, D, B, R>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
    transpose: &[TransposeEntry<P>],
    rng: &mut R,
    strategy: &impl Strategy,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
{
    // Group the transpose by row account once, so rows validate independently in parallel
    // against their exact contiguous incoming interval.
    let groups = transpose_groups(&close.rows, transpose)?;
    strategy.try_map_collect_vec(
        close
            .rows
            .iter()
            .zip(&close.out_vectors)
            .zip(&groups)
            .enumerate(),
        |(index, ((row, out_vector), group))| {
            let incoming = &transpose[group.0..group.1];
            let delta =
                validate_row::<H, P, D>(context, deposits, withdrawals, row, out_vector, incoming)?;
            let previous = index
                .checked_sub(1)
                .map_or_else(Prefix::default, |previous| close.rows[previous].prefix);
            let prefix = previous
                .checked_extend(delta)
                .ok_or(TransitionError::PrefixOverflow)?;
            if prefix != row.prefix {
                return Err(TransitionError::Prefix);
            }
            Ok(())
        },
    )?;
    let row_count = u32::try_from(close.rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    let totals = close
        .rows
        .last()
        .map_or_else(Prefix::default, |row| row.prefix);
    validate_terminal_prefix(context, deposits, withdrawals, row_count, totals)?;

    // Every distinct acknowledgment joins one randomized aggregate batch.
    let ack_count = close
        .rows
        .iter()
        .filter(|row| row.outgoing.is_some())
        .count();
    if !verify_ack_signatures::<P, D, B, R, _>(
        close.rows.iter().filter_map(|row| row.outgoing.as_ref()),
        ack_count,
        rng,
        strategy,
    ) {
        return Err(TransitionError::Ack(AckError::InvalidPayerSignature));
    }
    Ok(())
}

/// Verifies every slice interval's combined operator countersignature.
fn validate_operator_aggregates<P: PublicKey, D: Digest>(
    operator: &OperatorKey,
    close: &Close<P, D>,
    coverage: &[SliceBoundary],
    strategy: &impl Strategy,
) -> Result<(), TransitionError> {
    if close.operator_aggregates.len() + 1 != coverage.len() {
        return Err(TransitionError::VectorAlignment);
    }
    strategy.try_map_collect_vec(
        coverage.windows(2).zip(&close.operator_aggregates),
        |(window, aggregate)| {
            let range = window[0].change as usize..window[1].change as usize;
            verify_operator_aggregate(
                operator,
                &close.rows[range],
                aggregate.as_ref(),
                &Sequential,
            )
        },
    )?;
    Ok(())
}

/// Verifies one interval's combined operator countersignature over its acknowledged bodies.
///
/// An interval with no sending rows must carry no aggregate. The operator key is assumed
/// group-checked with a verified proof of possession, fixed by deployment configuration
/// exactly like the operator's receipt key.
fn verify_operator_aggregate<P: PublicKey, D: Digest>(
    operator: &OperatorKey,
    rows: &[AccountRow<P, D>],
    aggregate: Option<&OperatorAggregate>,
    strategy: &impl Strategy,
) -> Result<(), TransitionError> {
    let encoded = rows
        .iter()
        .filter_map(|row| row.outgoing.as_ref())
        .map(|send| send.body().encode())
        .collect::<Vec<_>>();
    let pairs = encoded
        .iter()
        .map(|body| (VECTOR_ACK_AGGREGATE_NAMESPACE, body.as_ref()))
        .collect::<Vec<_>>();
    match (NonEmpty::try_new(pairs.iter()), aggregate) {
        (None, None) => Ok(()),
        (Some(messages), Some(aggregate)) => {
            let message = combine_messages::<OperatorVariant, _>(messages, strategy);
            verify_same_signer::<OperatorVariant>(operator, &message, aggregate)
                .map_err(|_| TransitionError::Ack(AckError::InvalidOperatorSignature))
        }
        _ => Err(TransitionError::Ack(AckError::InvalidOperatorSignature)),
    }
}

/// Splits the transpose into one contiguous [start, end) group per row.
fn transpose_groups<P: PublicKey, D: Digest>(
    rows: &[AccountRow<P, D>],
    transpose: &[TransposeEntry<P>],
) -> Result<Vec<(usize, usize)>, TransitionError> {
    if transpose
        .windows(2)
        .any(|pair| (&pair[0].recipient, &pair[0].payer) >= (&pair[1].recipient, &pair[1].payer))
    {
        return Err(TransitionError::NonCanonicalTranspose);
    }
    let mut groups = Vec::with_capacity(rows.len());
    let mut cursor = 0_usize;
    for row in rows {
        // An entry crediting an account without a row can never satisfy conservation.
        if transpose
            .get(cursor)
            .is_some_and(|entry| entry.recipient < row.account)
        {
            return Err(TransitionError::TransposeAlignment);
        }
        let start = cursor;
        while transpose
            .get(cursor)
            .is_some_and(|entry| entry.recipient == row.account)
        {
            cursor += 1;
        }
        groups.push((start, cursor));
    }
    if cursor != transpose.len() {
        return Err(TransitionError::TransposeAlignment);
    }
    Ok(groups)
}

/// Validates one changed row against its outgoing vector and incoming transpose interval.
pub(crate) fn validate_row<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row: &AccountRow<P, D>,
    out_vector: &OutVector<P>,
    incoming: &[TransposeEntry<P>],
) -> Result<Prefix, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_row_state_sides(row)?;
    let (debit, credit, receipts) = row
        .checked_deltas()
        .ok_or(TransitionError::CounterRegression)?;
    let deposit = deposits.amount_for(&row.account);
    let withdrawal = withdrawals.request_for(&row.account);
    let withdrawal_amount = match withdrawal {
        Some(request) => {
            let available =
                u128::from(row.predecessor.balance) + u128::from(deposit) + u128::from(credit);
            let tail = available
                .checked_sub(u128::from(debit))
                .ok_or(TransitionError::BalanceEquation)?;
            match request.body().action() {
                WithdrawalAction::Amount(amount) if u128::from(amount.get()) <= tail => {
                    amount.get()
                }
                WithdrawalAction::Amount(_) => 0,
                WithdrawalAction::Close => {
                    u64::try_from(tail).map_err(|_| TransitionError::PrefixOverflow)?
                }
            }
        }
        None => 0,
    };

    let registered = row.predecessor.active || deposit != 0;
    let payout = if registered { 0 } else { credit };
    if !registered && (credit == 0 || withdrawal.is_some()) {
        return Err(TransitionError::AccountActivity);
    }
    if !row.is_changed() && row.predecessor.active {
        return Err(TransitionError::UnchangedRow);
    }
    if u128::from(row.successor.balance)
        + u128::from(debit)
        + u128::from(withdrawal_amount)
        + u128::from(payout)
        != u128::from(row.predecessor.balance) + u128::from(credit) + u128::from(deposit)
    {
        return Err(TransitionError::BalanceEquation);
    }

    let expected_output = match withdrawal {
        Some(_) => SettlementOutput::Withdrawal(withdrawal_amount),
        None if payout != 0 => SettlementOutput::ExternalPayout(payout),
        None => SettlementOutput::None,
    };
    if row.output != expected_output {
        return Err(TransitionError::SettlementOutput);
    }

    // The outgoing side: the dual-signed endpoint must commit this exact vector, and the
    // vector's checked sum must equal the row's debit advance.
    if out_vector.payer() != &row.account || out_vector.epoch() != context.payment().epoch() {
        return Err(TransitionError::VectorAlignment);
    }
    let (out_total, _) = out_vector.totals()?;
    match (&row.outgoing, debit) {
        (None, 0) => {
            if !out_vector.entries().is_empty() {
                return Err(TransitionError::VectorAlignment);
            }
        }
        (Some(ack), debit) if debit != 0 => {
            // The signed body must bind this exact anchor and epoch, matching the base
            // protocol's terminal-structure binding, so a foreign or stale-context ack can
            // never be committed even when its debit and root line up.
            ack.body().validate_context(context.payment())?;
            if ack.body().payer() != &row.account
                || ack.body().cumulative_debit() != row.successor.cumulative_debit
                || out_total != debit
            {
                return Err(TransitionError::OutgoingEndpoint);
            }
            let send_root = out_vector.root::<H, D>()?;
            if send_root != ack.body().send_root() {
                return Err(TransitionError::OutgoingEndpoint);
            }
        }
        _ => return Err(TransitionError::OutgoingPresence),
    }

    // The incoming side: the row's exact contiguous transpose interval must sum to the credit
    // and receipt-count advances.
    let mut in_credit = 0_u64;
    let mut in_count = 0_u64;
    for entry in incoming {
        if entry.recipient != row.account {
            return Err(TransitionError::TransposeAlignment);
        }
        entry.validate()?;
        in_credit = in_credit
            .checked_add(entry.cumulative)
            .ok_or(TransitionError::PrefixOverflow)?;
        in_count = in_count
            .checked_add(entry.count)
            .ok_or(TransitionError::PrefixOverflow)?;
    }
    if in_credit != credit || in_count != receipts {
        return Err(TransitionError::CreditTotals);
    }

    let limits = context.limits();
    let out_count =
        u64::try_from(out_vector.entries().len()).map_err(|_| TransitionError::PrefixOverflow)?;
    let in_entries = u64::try_from(incoming.len()).map_err(|_| TransitionError::PrefixOverflow)?;
    if out_count > limits.max_account_entries() || in_entries > limits.max_account_entries() {
        return Err(TransitionError::CloseLimit);
    }

    Ok(Prefix {
        debit,
        credit,
        payout,
        deposit,
        withdrawal: withdrawal_amount,
        withdrawal_count: u64::from(withdrawal.is_some()),
        out_count,
        in_count: in_entries,
    })
}

fn validate_row_state_sides<P: PublicKey, D: Digest>(
    row: &AccountRow<P, D>,
) -> Result<(), TransitionError> {
    if row.predecessor.active {
        if row.predecessor.balance == 0 {
            return Err(TransitionError::InactiveBalance);
        }
    } else if row.predecessor != AccountState::default() {
        return Err(TransitionError::NonCanonicalPredecessorAbsence);
    }
    if row.successor.active != (row.successor.balance > 0) {
        return Err(TransitionError::InactiveBalance);
    }
    Ok(())
}

fn validate_corpus_limits<P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    rows: &[AccountRow<P, D>],
    out_vectors: &[OutVector<P>],
    totals: Prefix,
) -> Result<(), TransitionError> {
    let limits = context.limits();
    let row_count = u64::try_from(rows.len()).map_err(|_| TransitionError::CloseLimit)?;
    if row_count > limits.max_rows()
        || totals.withdrawal_count > limits.max_withdrawals()
        || totals.debit > limits.max_payment_total()
        || totals.credit > limits.max_payment_total()
        || totals.payout > limits.max_payment_total()
        || totals.deposit > limits.max_deposit_total()
        || totals.withdrawal > limits.max_withdrawal_total()
        || totals.in_count > limits.max_total_entries()
        || totals.out_count > limits.max_total_entries()
    {
        return Err(TransitionError::CloseLimit);
    }
    let mut total_out = 0_u64;
    for out_vector in out_vectors {
        let count =
            u64::try_from(out_vector.entries().len()).map_err(|_| TransitionError::CloseLimit)?;
        if count > limits.max_account_entries() {
            return Err(TransitionError::CloseLimit);
        }
        total_out = total_out
            .checked_add(count)
            .filter(|total| *total <= limits.max_total_entries())
            .ok_or(TransitionError::CloseLimit)?;
    }
    Ok(())
}

pub(crate) fn validate_boundary_roots<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if deposits
        .root::<H>()
        .map_err(|_| TransitionError::BoundaryRoot)?
        != *context.deposit_root()
        || withdrawals
            .root::<H>()
            .map_err(|_| TransitionError::BoundaryRoot)?
            != *context.withdrawal_root()
    {
        return Err(TransitionError::BoundaryRoot);
    }
    Ok(())
}

fn validate_terminal_prefix<P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row_count: u32,
    totals: Prefix,
) -> Result<u64, TransitionError> {
    let withdrawal_count =
        u64::try_from(withdrawals.len()).map_err(|_| TransitionError::BoundaryTotals)?;
    if totals.deposit != deposits.total() || totals.withdrawal_count != withdrawal_count {
        return Err(TransitionError::BoundaryTotals);
    }
    let limits = context.limits();
    if u64::from(row_count) > limits.max_rows()
        || totals.withdrawal_count > limits.max_withdrawals()
        || totals.out_count > limits.max_total_entries()
        || totals.in_count > limits.max_total_entries()
        || totals.debit > limits.max_payment_total()
        || totals.credit > limits.max_payment_total()
        || totals.payout > limits.max_payment_total()
        || totals.deposit > limits.max_deposit_total()
        || totals.withdrawal > limits.max_withdrawal_total()
    {
        return Err(TransitionError::CloseLimit);
    }
    if totals.debit != totals.credit {
        return Err(TransitionError::PaymentConservation);
    }

    // Every edge appears once on each side, so the counts and the accumulators must agree.
    if totals.out_count != totals.in_count {
        return Err(TransitionError::MultisetMismatch);
    }
    checked_successor_liability(
        context.predecessor_liability(),
        totals.deposit,
        totals.withdrawal,
        totals.payout,
    )
}

fn validate_terminal_boundary<H, P, D>(
    context: &CloseContext<P, D>,
    roots: &RootBundle<D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row_count: u32,
    terminal: &SliceBoundary,
) -> Result<u64, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if terminal.out_check != terminal.in_check {
        return Err(TransitionError::MultisetMismatch);
    }
    if u64::from(roots.transpose_len) != terminal.prefix.in_count {
        return Err(TransitionError::TransposeRoot);
    }
    // Zero-count trees have no opening anywhere on the seal path, so their committed roots
    // are pinned here to the canonical empty root instead.
    if roots.transpose_len == 0
        && roots.transpose != commitment::empty_root::<H>(VectorKind::Transpose)
    {
        return Err(TransitionError::TransposeRoot);
    }
    if terminal.prefix.withdrawal_count == 0
        && roots.withdrawal_outputs != commitment::empty_root::<H>(VectorKind::WithdrawalOutput)
    {
        return Err(TransitionError::WithdrawalOutputRoot);
    }
    validate_terminal_prefix(context, deposits, withdrawals, row_count, terminal.prefix)
}

pub(crate) fn checked_successor_liability(
    predecessor: u64,
    deposits: u64,
    withdrawals: u64,
    payouts: u64,
) -> Result<u64, TransitionError> {
    let available = u128::from(predecessor) + u128::from(deposits);
    let successor = available
        .checked_sub(u128::from(withdrawals))
        .and_then(|remaining| remaining.checked_sub(u128::from(payouts)))
        .ok_or(TransitionError::LiabilityEquation)?;
    u64::try_from(successor).map_err(|_| TransitionError::LiabilityOverflow)
}

type ChangeMaterial<P, D> = (Vec<AccountChange<P, D>>, Vec<ChangeGuard<P, D>>, Tree<D>);

fn change_material_with_strategy<H, P, D>(
    rows: &[AccountRow<P, D>],
    out_vectors: &[OutVector<P>],
    strategy: &impl Strategy,
) -> Result<ChangeMaterial<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if rows.len() != out_vectors.len() {
        return Err(TransitionError::VectorAlignment);
    }
    let len = u32::try_from(rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    let leaves = strategy.try_map_collect_vec(
        rows.iter().zip(out_vectors),
        |(row, out_vector)| -> Result<AccountChange<P, D>, TransitionError> {
            if out_vector.payer() != &row.account {
                return Err(TransitionError::VectorAlignment);
            }
            let send_root = out_vector.root::<H, D>()?;
            Ok(AccountChange::from_row::<H>(row, send_root))
        },
    )?;
    let guards = strategy.map_collect_vec(leaves.iter(), |leaf| leaf.guard::<H>());
    let mut builder = commitment::Builder::<H>::new(VectorKind::Change, len)?;
    builder.add_values(&guards, strategy)?;
    Ok((leaves, guards, builder.build(strategy)?))
}

type WithdrawalOutputMaterial<D> = (Vec<WithdrawalOutput>, Tree<D>);

fn withdrawal_output_material_with_strategy<H, P, D>(
    rows: &[AccountRow<P, D>],
    withdrawals: &WithdrawalBatch<P, D>,
    strategy: &impl Strategy,
) -> Result<WithdrawalOutputMaterial<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = u32::try_from(withdrawals.len()).map_err(|_| TransitionError::CloseLimit)?;
    let mut outputs = Vec::with_capacity(withdrawals.len());
    let mut row_index = 0_usize;
    for request in withdrawals.requests() {
        while rows
            .get(row_index)
            .is_some_and(|row| row.account < *request.account())
        {
            row_index += 1;
        }
        let row = rows
            .get(row_index)
            .filter(|row| row.account == *request.account())
            .ok_or(TransitionError::SettlementOutput)?;
        let SettlementOutput::Withdrawal(amount) = row.output else {
            return Err(TransitionError::SettlementOutput);
        };
        outputs.push(WithdrawalOutput::from_request(request, amount));
        row_index += 1;
    }
    let mut builder = commitment::Builder::<H>::new(VectorKind::WithdrawalOutput, len)?;
    builder.add_values(&outputs, strategy)?;
    Ok((outputs, builder.build(strategy)?))
}

fn transpose_tree_with_strategy<H, P, D>(
    transpose: &[TransposeEntry<P>],
    strategy: &impl Strategy,
) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = u32::try_from(transpose.len()).map_err(|_| TransitionError::CloseLimit)?;
    let mut builder = commitment::Builder::<H>::new(VectorKind::Transpose, len)?;
    builder.add_values(transpose, strategy)?;
    Ok(builder.build(strategy)?)
}

fn state_tree_with_strategy<H, P, D>(
    leaves: &[StateLeaf<P>],
    strategy: &impl Strategy,
) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = u32::try_from(leaves.len()).map_err(|_| TransitionError::TooManyStates)?;
    let mut builder = commitment::Builder::<H>::new(VectorKind::State, len)?;
    builder.add_values(leaves, strategy)?;
    Ok(builder.build(strategy)?)
}

const fn is_live_state(state: &AccountState) -> bool {
    state.active && state.balance > 0
}

fn state_liability<P: PublicKey>(leaves: &[StateLeaf<P>]) -> Result<u64, TransitionError> {
    leaves.iter().try_fold(0_u64, |total, leaf| {
        total
            .checked_add(leaf.state.balance)
            .ok_or(TransitionError::LiabilityOverflow)
    })
}

fn derive_unchanged<P: PublicKey, D: Digest>(
    predecessor: &[StateLeaf<P>],
    rows: &[AccountRow<P, D>],
) -> Result<Vec<StateLeaf<P>>, TransitionError> {
    let mut unchanged = Vec::with_capacity(predecessor.len().saturating_sub(rows.len()));
    let mut state = 0_usize;
    for row in rows {
        while predecessor
            .get(state)
            .is_some_and(|leaf| leaf.account < row.account)
        {
            unchanged.push(predecessor[state].clone());
            state += 1;
        }
        match predecessor.get(state) {
            Some(leaf) if leaf.account == row.account => {
                if leaf.state != row.predecessor {
                    return Err(TransitionError::PredecessorLinkage);
                }
                state += 1;
            }
            _ if row.predecessor == AccountState::default() => {}
            _ => return Err(TransitionError::PredecessorLinkage),
        }
    }
    unchanged.extend_from_slice(&predecessor[state..]);
    Ok(unchanged)
}

fn merge_state_vectors<P: PublicKey, D: Digest>(
    unchanged: &[StateLeaf<P>],
    rows: &[AccountRow<P, D>],
    max_states: u64,
    mut predecessor: impl FnMut(&P, &AccountState) -> Result<(), TransitionError>,
) -> Result<Vec<StateLeaf<P>>, TransitionError> {
    if unchanged
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
        || unchanged.iter().any(|leaf| !is_live_state(&leaf.state))
    {
        return Err(TransitionError::NonCanonicalStateOrder);
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::NonCanonicalRows);
    }
    let mut predecessor_len = unchanged.len();
    let mut successor_len = unchanged.len();
    for row in rows {
        validate_row_state_sides(row)?;
        if row.predecessor.active {
            predecessor_len = predecessor_len
                .checked_add(1)
                .ok_or(TransitionError::TooManyStates)?;
        }
        if row.successor.active {
            successor_len = successor_len
                .checked_add(1)
                .ok_or(TransitionError::TooManyStates)?;
        }
    }

    let protocol_max = u64::from(commitment::MAX_VECTOR_LENGTH);
    let predecessor_len =
        u64::try_from(predecessor_len).map_err(|_| TransitionError::TooManyStates)?;
    let successor_len = u64::try_from(successor_len).map_err(|_| TransitionError::TooManyStates)?;
    if predecessor_len > max_states
        || successor_len > max_states
        || predecessor_len > protocol_max
        || successor_len > protocol_max
    {
        return Err(TransitionError::TooManyStates);
    }

    let mut successor = Vec::with_capacity(successor_len as usize);
    let mut unchanged_index = 0_usize;
    let mut row_index = 0_usize;
    while unchanged_index < unchanged.len() || row_index < rows.len() {
        match (unchanged.get(unchanged_index), rows.get(row_index)) {
            (Some(leaf), Some(row)) if leaf.account == row.account => {
                return Err(TransitionError::StateRowOverlap);
            }
            (Some(leaf), Some(row)) if leaf.account < row.account => {
                predecessor(&leaf.account, &leaf.state)?;
                successor.push(leaf.clone());
                unchanged_index += 1;
            }
            (Some(leaf), None) => {
                predecessor(&leaf.account, &leaf.state)?;
                successor.push(leaf.clone());
                unchanged_index += 1;
            }
            (_, Some(row)) => {
                if row.predecessor.active {
                    predecessor(&row.account, &row.predecessor)?;
                }
                if row.successor.active {
                    successor.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.successor,
                    });
                }
                row_index += 1;
            }
            (None, None) => break,
        }
    }
    Ok(successor)
}

type StateVectors<P> = (Vec<StateLeaf<P>>, Vec<StateLeaf<P>>);

fn derive_state_vectors<P: PublicKey, D: Digest>(
    unchanged: &[StateLeaf<P>],
    rows: &[AccountRow<P, D>],
    max_states: u64,
) -> Result<StateVectors<P>, TransitionError> {
    let mut predecessor = Vec::with_capacity(unchanged.len().saturating_add(rows.len()));
    let successor = merge_state_vectors(unchanged, rows, max_states, |account, state| {
        predecessor.push(StateLeaf {
            account: account.clone(),
            state: *state,
        });
        Ok(())
    })?;
    Ok((predecessor, successor))
}

fn derive_successor<P: PublicKey, D: Digest>(
    unchanged: &[StateLeaf<P>],
    rows: &[AccountRow<P, D>],
    expected: &[StateLeaf<P>],
    max_states: u64,
) -> Result<Vec<StateLeaf<P>>, TransitionError> {
    let mut position = 0_usize;
    let successor = merge_state_vectors(unchanged, rows, max_states, |account, state| {
        let leaf = expected
            .get(position)
            .ok_or(TransitionError::PredecessorLinkage)?;
        if leaf.account != *account || leaf.state != *state {
            return Err(TransitionError::PredecessorLinkage);
        }
        position += 1;
        Ok(())
    })?;
    if position != expected.len() {
        return Err(TransitionError::PredecessorLinkage);
    }
    Ok(successor)
}

fn boundaries<P: PublicKey, T>(
    items: &[T],
    account: impl Fn(&T) -> &P,
    slice_bits: u8,
) -> Result<Vec<u32>, TransitionError> {
    if slice_bits > MAX_SLICE_BITS {
        return Err(TransitionError::SliceBits);
    }
    let slice_count = 1_u16 << slice_bits;
    let mut boundaries = Vec::with_capacity(usize::from(slice_count) + 1);
    boundaries.push(0);
    let mut cursor = 0_usize;
    for index in 0..slice_count {
        while let Some(item) = items.get(cursor) {
            let member =
                account_slice(account(item), slice_bits).map_err(|_| TransitionError::SliceBits)?;
            if member < index {
                return Err(TransitionError::NonCanonicalSliceOrder);
            }
            if member != index {
                break;
            }
            cursor += 1;
        }
        boundaries.push(u32::try_from(cursor).map_err(|_| TransitionError::TooManyStates)?);
    }
    if cursor != items.len() {
        return Err(TransitionError::NonCanonicalSliceOrder);
    }
    Ok(boundaries)
}

fn state_boundaries<P: PublicKey>(
    leaves: &[StateLeaf<P>],
    slice_bits: u8,
) -> Result<Vec<u32>, TransitionError> {
    boundaries(leaves, |leaf| &leaf.account, slice_bits)
}

/// Coverage boundaries paired with the full accumulator state at each boundary.
type CoverageMaterial = (Vec<SliceBoundary>, Vec<(LtHash, LtHash)>);

#[allow(clippy::too_many_arguments)]
fn derive_coverage<P, D>(
    rows: &[AccountRow<P, D>],
    out_vectors: &[OutVector<P>],
    out_partials: Option<&[LtHash]>,
    transpose: &[TransposeEntry<P>],
    predecessor: &[StateLeaf<P>],
    successor: &[StateLeaf<P>],
    slice_bits: u8,
    strategy: &impl Strategy,
) -> Result<CoverageMaterial, TransitionError>
where
    P: PublicKey,
    D: Digest,
{
    if rows.len() != out_vectors.len() {
        return Err(TransitionError::VectorAlignment);
    }
    if out_partials.is_some_and(|partials| partials.len() != rows.len()) {
        return Err(TransitionError::VectorAlignment);
    }
    let predecessor = state_boundaries(predecessor, slice_bits)?;
    let changes = boundaries(rows, |row| &row.account, slice_bits)?;
    let successor = state_boundaries(successor, slice_bits)?;

    // The accumulator is associative, so fold each slice interval's contribution in parallel
    // and prefix-combine the partials into running boundary values afterward.
    let in_count_at = |change: u32| -> Result<usize, TransitionError> {
        if change == 0 {
            Ok(0)
        } else {
            usize::try_from(rows[change as usize - 1].prefix.in_count)
                .map_err(|_| TransitionError::PrefixOverflow)
        }
    };
    let partials = strategy.try_map_collect_vec(
        changes.windows(2),
        |window| -> Result<(LtHash, LtHash), TransitionError> {
            let (start, end) = (window[0] as usize, window[1] as usize);
            // The closer lane-sums sender-maintained per-payer partials. Validators pass no
            // partials and fold raw entries: their own fold is what certification attests.
            let mut out_acc = LtHash::new();
            if let Some(partials) = out_partials {
                for partial in &partials[start..end] {
                    out_acc.combine(partial);
                }
            } else {
                for (row, out_vector) in rows[start..end].iter().zip(&out_vectors[start..end]) {
                    for entry in out_vector.entries() {
                        accumulate_edge(
                            &mut out_acc,
                            &row.account,
                            &entry.recipient,
                            entry.cumulative,
                            entry.count,
                        );
                    }
                }
            }
            let in_start = in_count_at(window[0])?;
            let in_end = in_count_at(window[1])?;
            if in_start > in_end || in_end > transpose.len() {
                return Err(TransitionError::TransposeAlignment);
            }
            let mut in_acc = LtHash::new();
            for entry in &transpose[in_start..in_end] {
                accumulate_edge(
                    &mut in_acc,
                    &entry.payer,
                    &entry.recipient,
                    entry.cumulative,
                    entry.count,
                );
            }
            Ok((out_acc, in_acc))
        },
    )?;
    if in_count_at(*changes.last().expect("boundaries are nonempty"))? != transpose.len() {
        return Err(TransitionError::TransposeAlignment);
    }

    let mut coverage = Vec::with_capacity(changes.len());
    let mut states = Vec::with_capacity(changes.len());
    let mut out_acc = LtHash::new();
    let mut in_acc = LtHash::new();
    for (index, ((predecessor, change), successor)) in predecessor
        .into_iter()
        .zip(changes.iter().copied())
        .zip(successor)
        .enumerate()
    {
        if let Some(previous) = index.checked_sub(1) {
            out_acc.combine(&partials[previous].0);
            in_acc.combine(&partials[previous].1);
        }
        let prefix = if change == 0 {
            Prefix::default()
        } else {
            rows[change as usize - 1].prefix
        };
        coverage.push(SliceBoundary {
            predecessor,
            change,
            successor,
            prefix,
            out_check: out_acc.checksum(),
            in_check: in_acc.checksum(),
        });
        states.push((out_acc.clone(), in_acc.clone()));
    }
    Ok((coverage, states))
}

fn coverage_tree_with_strategy<H, D>(
    coverage: &[SliceBoundary],
    strategy: &impl Strategy,
) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let len = u32::try_from(coverage.len()).map_err(|_| TransitionError::SliceCoverage)?;
    let mut builder = commitment::Builder::<H>::new(VectorKind::Coverage, len)?;
    builder.add_values(coverage, strategy)?;
    Ok(builder.build(strategy)?)
}

fn build_state_range<P: PublicKey, D: Digest>(
    leaves: &[StateLeaf<P>],
    tree: &Tree<D>,
    start: u32,
    end: u32,
) -> Result<StateRange<P, D>, TransitionError> {
    let (predecessor, successor, opening) = tree.bracket(leaves, start..end)?;
    Ok(StateRange {
        predecessor,
        successor,
        opening,
    })
}

/// Authenticates one proof slice against its registered header and boundaries.
#[allow(clippy::too_many_arguments)]
pub fn validate_slice<H, P, D, B, R>(
    context: &CloseContext<P, D>,
    operator: &OperatorKey,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
    slice: &ProofSlice<P, D>,
    rng: &mut R,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
{
    if !header.verify::<H, P>(context, roots) {
        return Err(TransitionError::HeaderRoot);
    }
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;
    validate_slice_after_header::<H, P, D>(context, operator, deposits, withdrawals, roots, slice)?;
    // Both authorization halves are quorum-attested per slice: the operator's through its
    // combined countersignature, the payers' through this batch.
    let authorization_count = slice
        .changes
        .rows
        .iter()
        .filter(|row| row.outgoing.is_some())
        .count();
    if !verify_ack_signatures::<P, D, B, R, _>(
        slice
            .changes
            .rows
            .iter()
            .filter_map(|row| row.outgoing.as_ref()),
        authorization_count,
        rng,
        &Sequential,
    ) {
        return Err(TransitionError::Ack(AckError::InvalidPayerSignature));
    }
    Ok(())
}

pub(crate) fn validate_slice_after_header<H, P, D>(
    context: &CloseContext<P, D>,
    operator: &OperatorKey,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    roots: &RootBundle<D>,
    slice: &ProofSlice<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let assignment = context.assignment();
    if slice.index >= assignment.slice_count() {
        return Err(TransitionError::SliceIndex);
    }
    validate_coverage_range::<H, D>(assignment, slice.index, &roots.coverage, &slice.coverage)?;
    validate_change_range::<H, P, D>(
        assignment,
        slice.index,
        &roots.change,
        &slice.changes,
        &slice.out_vectors,
        slice.coverage.start.change,
        slice.coverage.end.change,
    )?;
    // Runs after the change range pins strict row order, so the combined message never folds
    // duplicate bodies, per the aggregation primitive's distinct-messages precondition.
    verify_operator_aggregate(
        operator,
        &slice.changes.rows,
        slice.operator_aggregate.as_ref(),
        &Sequential,
    )?;

    let (predecessor, successor) = derive_state_vectors(
        &slice.unchanged,
        &slice.changes.rows,
        context.limits().max_states(),
    )?;
    validate_state_range::<H, P, D>(
        assignment,
        slice.index,
        context.predecessor_root(),
        &slice.predecessor,
        &predecessor,
        context.limits().max_states(),
        slice.coverage.start.predecessor..slice.coverage.end.predecessor,
    )?;
    validate_state_range::<H, P, D>(
        assignment,
        slice.index,
        &roots.successor,
        &slice.successor,
        &successor,
        context.limits().max_states(),
        slice.coverage.start.successor..slice.coverage.end.successor,
    )?;

    // The transpose interval is positionally pinned by the boundary in-counts and must
    // authenticate under the transpose root.
    let transpose_start = u32::try_from(slice.coverage.start.prefix.in_count)
        .map_err(|_| TransitionError::SliceRange)?;
    let transpose_count = u32::try_from(
        slice
            .coverage
            .end
            .prefix
            .in_count
            .checked_sub(slice.coverage.start.prefix.in_count)
            .ok_or(TransitionError::SliceRange)?,
    )
    .map_err(|_| TransitionError::SliceRange)?;
    if usize::try_from(transpose_count).ok() != Some(slice.transpose.len()) {
        return Err(TransitionError::SliceRange);
    }
    match (&slice.transpose_opening, slice.transpose.is_empty()) {
        (None, true) => {}
        (Some(opening), false)
            if opening.start == transpose_start
                && opening.proof.leaf_count == roots.transpose_len =>
        {
            let encoded = slice
                .transpose
                .iter()
                .map(Encode::encode)
                .collect::<Vec<_>>();
            opening.verify::<H, _>(VectorKind::Transpose, &roots.transpose, &encoded)?;
        }
        _ => return Err(TransitionError::SliceRange),
    }

    // The witness start states must hash to the committed boundary checksums before any
    // accumulation resumes from them.
    if slice.out_start.checksum() != slice.coverage.start.out_check
        || slice.in_start.checksum() != slice.coverage.start.in_check
    {
        return Err(TransitionError::SliceCoverage);
    }

    // Row equations advance the prefix and both accumulators through the interval.
    let groups = transpose_groups(&slice.changes.rows, &slice.transpose)?;
    let mut prefix = slice.coverage.start.prefix;
    let mut out_acc = slice.out_start.clone();
    let mut in_acc = slice.in_start.clone();
    let mut withdrawal_outputs = Vec::new();
    for ((row, out_vector), group) in slice
        .changes
        .rows
        .iter()
        .zip(&slice.out_vectors)
        .zip(&groups)
    {
        let incoming = &slice.transpose[group.0..group.1];
        let delta =
            validate_row::<H, P, D>(context, deposits, withdrawals, row, out_vector, incoming)?;
        prefix = prefix
            .checked_extend(delta)
            .ok_or(TransitionError::PrefixOverflow)?;
        if prefix != row.prefix {
            return Err(TransitionError::Prefix);
        }
        for entry in out_vector.entries() {
            accumulate_edge(
                &mut out_acc,
                &row.account,
                &entry.recipient,
                entry.cumulative,
                entry.count,
            );
        }
        for entry in incoming {
            accumulate_edge(
                &mut in_acc,
                &entry.payer,
                &entry.recipient,
                entry.cumulative,
                entry.count,
            );
        }
        if let Some(request) = withdrawals.request_for(&row.account) {
            let SettlementOutput::Withdrawal(amount) = row.output else {
                return Err(TransitionError::SettlementOutput);
            };
            withdrawal_outputs.push(WithdrawalOutput::from_request(request, amount));
        }
    }
    if prefix != slice.coverage.end.prefix
        || out_acc.checksum() != slice.coverage.end.out_check
        || in_acc.checksum() != slice.coverage.end.in_check
    {
        return Err(TransitionError::Prefix);
    }
    validate_withdrawal_output_range::<H, D>(
        &roots.withdrawal_outputs,
        &slice.withdrawal_opening,
        slice.coverage.start.prefix.withdrawal_count,
        slice.coverage.end.prefix.withdrawal_count,
        withdrawals.len(),
        &withdrawal_outputs,
    )?;

    // The final authenticated boundary binds all vector lengths, corpus totals, and the
    // multiset equality between the two edge orderings.
    let change_len = slice.changes.opening.proof.leaf_count;
    if slice.index + 1 == assignment.slice_count() {
        if slice.coverage.end.predecessor != slice.predecessor.opening.proof.leaf_count
            || slice.coverage.end.change != change_len
            || slice.coverage.end.successor != slice.successor.opening.proof.leaf_count
        {
            return Err(TransitionError::SliceCoverage);
        }
        validate_terminal_boundary::<H, P, D>(
            context,
            roots,
            deposits,
            withdrawals,
            change_len,
            &slice.coverage.end,
        )?;
    }
    Ok(())
}

fn validate_coverage_range<H, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &VectorRoot<D>,
    range: &CoverageRange<D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let expected_len = u32::from(assignment.slice_count()) + 1;
    if range.opening.start != u32::from(index)
        || range.opening.proof.leaf_count != expected_len
        || range.start.predecessor > range.end.predecessor
        || range.start.change > range.end.change
        || range.start.successor > range.end.successor
        || (index == 0 && range.start != SliceBoundary::origin())
    {
        return Err(TransitionError::SliceCoverage);
    }
    range.opening.verify::<H, _>(
        VectorKind::Coverage,
        root,
        &[range.start.encode(), range.end.encode()],
    )?;
    Ok(())
}

fn validate_change_range<H, P, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &VectorRoot<D>,
    range: &ChangeRange<P, D>,
    out_vectors: &[OutVector<P>],
    start: u32,
    end: u32,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if range.rows.len() != out_vectors.len() {
        return Err(TransitionError::VectorAlignment);
    }
    let members = u32::try_from(range.rows.len()).map_err(|_| TransitionError::SliceRange)?;
    let positions = range
        .opening
        .bracket(
            range.predecessor.is_some(),
            members,
            range.successor.is_some(),
        )
        .ok_or(TransitionError::SliceRange)?;
    if positions != (start..end)
        || range
            .predecessor
            .iter()
            .map(ChangeGuard::account)
            .chain(range.rows.iter().map(|row| &row.account))
            .chain(range.successor.iter().map(ChangeGuard::account))
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(TransitionError::SliceRange);
    }
    for row in &range.rows {
        if account_slice(&row.account, assignment.slice_bits())
            .map_err(|_| TransitionError::SliceBits)?
            != index
        {
            return Err(TransitionError::SliceRange);
        }
    }
    if let Some(predecessor) = &range.predecessor
        && account_slice(predecessor.account(), assignment.slice_bits())
            .map_err(|_| TransitionError::SliceBits)?
            >= index
    {
        return Err(TransitionError::SliceRange);
    }
    if let Some(successor) = &range.successor
        && account_slice(successor.account(), assignment.slice_bits())
            .map_err(|_| TransitionError::SliceBits)?
            <= index
    {
        return Err(TransitionError::SliceRange);
    }
    let member_guards = range
        .rows
        .iter()
        .zip(out_vectors)
        .map(
            |(row, out_vector)| -> Result<ChangeGuard<P, D>, TransitionError> {
                if out_vector.payer() != &row.account {
                    return Err(TransitionError::VectorAlignment);
                }
                let send_root = out_vector.root::<H, D>()?;
                Ok(AccountChange::from_row::<H>(row, send_root).guard::<H>())
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    let encoded = range
        .predecessor
        .iter()
        .map(Encode::encode)
        .chain(member_guards.iter().map(Encode::encode))
        .chain(range.successor.iter().map(Encode::encode))
        .collect::<Vec<_>>();
    range
        .opening
        .verify::<H, _>(VectorKind::Change, root, &encoded)?;
    Ok(())
}

fn validate_withdrawal_output_range<H, D>(
    root: &VectorRoot<D>,
    opening: &Option<RangeOpening<D>>,
    start: u64,
    end: u64,
    total: usize,
    outputs: &[WithdrawalOutput],
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let start = u32::try_from(start).map_err(|_| TransitionError::SliceRange)?;
    let end = u32::try_from(end).map_err(|_| TransitionError::SliceRange)?;
    let total = u32::try_from(total).map_err(|_| TransitionError::CloseLimit)?;
    let count = end.checked_sub(start).ok_or(TransitionError::SliceRange)?;
    if usize::try_from(count).ok() != Some(outputs.len()) {
        return Err(TransitionError::SliceRange);
    }
    match (opening, outputs.is_empty()) {
        (None, true) => {
            if total == 0 && *root != commitment::empty_root::<H>(VectorKind::WithdrawalOutput) {
                return Err(TransitionError::WithdrawalOutputRoot);
            }
        }
        (Some(opening), false) if opening.start == start && opening.proof.leaf_count == total => {
            let encoded = outputs.iter().map(Encode::encode).collect::<Vec<_>>();
            opening.verify::<H, _>(VectorKind::WithdrawalOutput, root, &encoded)?;
        }
        _ => return Err(TransitionError::SliceRange),
    }
    Ok(())
}

fn validate_state_range<H, P, D>(
    assignment: &Assignment<D>,
    index: u16,
    root: &VectorRoot<D>,
    range: &StateRange<P, D>,
    members: &[StateLeaf<P>],
    max_states: u64,
    positions: core::ops::Range<u32>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = range.opening.proof.leaf_count;
    if u64::from(len) > max_states || len > commitment::MAX_VECTOR_LENGTH {
        return Err(TransitionError::SliceStateRange);
    }
    let count = u32::try_from(members.len()).map_err(|_| TransitionError::SliceStateRange)?;
    if range
        .opening
        .bracket(
            range.predecessor.is_some(),
            count,
            range.successor.is_some(),
        )
        .ok_or(TransitionError::SliceStateRange)?
        != positions
    {
        return Err(TransitionError::SliceStateRange);
    }

    let leaves = range
        .predecessor
        .iter()
        .chain(members)
        .chain(range.successor.iter())
        .collect::<Vec<_>>();
    if leaves.iter().any(|leaf| !is_live_state(&leaf.state))
        || leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::SliceStateRange);
    }
    for leaf in members {
        if account_slice(&leaf.account, assignment.slice_bits())
            .map_err(|_| TransitionError::SliceBits)?
            != index
        {
            return Err(TransitionError::SliceStateRange);
        }
    }
    if let Some(predecessor) = &range.predecessor
        && account_slice(&predecessor.account, assignment.slice_bits())
            .map_err(|_| TransitionError::SliceBits)?
            >= index
    {
        return Err(TransitionError::SliceStateRange);
    }
    if let Some(successor) = &range.successor
        && account_slice(&successor.account, assignment.slice_bits())
            .map_err(|_| TransitionError::SliceBits)?
            <= index
    {
        return Err(TransitionError::SliceStateRange);
    }
    let encoded = leaves.into_iter().map(Encode::encode).collect::<Vec<_>>();
    range
        .opening
        .verify::<H, _>(VectorKind::State, root, &encoded)?;
    Ok(())
}

pub(crate) const fn codec_invalid(name: &'static str, reason: &'static str) -> CodecError {
    CodecError::Invalid(name, reason)
}

/// Complete live-state vector and its retained Merkle tree.
#[derive(Clone, Debug)]
pub struct StateCache<P: PublicKey, D: Digest> {
    leaves: Vec<StateLeaf<P>>,
    tree: Tree<D>,
    liability: u64,
}

impl<P: PublicKey, D: Digest> StateCache<P, D> {
    /// Validates and commits a complete, strictly account-sorted live-state vector.
    pub fn new<H: Hasher<Digest = D>>(leaves: Vec<StateLeaf<P>>) -> Result<Self, TransitionError> {
        Self::new_with_strategy::<H>(leaves, &Sequential)
    }

    /// Validates and commits a complete live-state vector using the supplied execution strategy.
    pub fn new_with_strategy<H: Hasher<Digest = D>>(
        leaves: Vec<StateLeaf<P>>,
        strategy: &impl Strategy,
    ) -> Result<Self, TransitionError> {
        if leaves
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(TransitionError::NonCanonicalStateOrder);
        }
        if leaves.iter().any(|leaf| !is_live_state(&leaf.state)) {
            return Err(TransitionError::InactiveBalance);
        }

        let mut previous_prefix = None;
        for leaf in &leaves {
            let prefix = leaf
                .account
                .as_ref()
                .first()
                .copied()
                .ok_or(TransitionError::EmptyAccountKey)?;
            if previous_prefix.is_some_and(|previous| previous > prefix) {
                return Err(TransitionError::NonCanonicalSliceOrder);
            }
            previous_prefix = Some(prefix);
        }

        let liability = state_liability(&leaves)?;
        let tree = state_tree_with_strategy::<H, P, D>(&leaves, strategy)?;
        Ok(Self {
            leaves,
            tree,
            liability,
        })
    }

    /// Returns the complete canonical live-state leaves.
    pub fn leaves(&self) -> &[StateLeaf<P>] {
        &self.leaves
    }

    /// Returns the number of live accounts.
    pub const fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Returns whether the live state is empty.
    pub const fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Returns the cached state root.
    pub const fn root(&self) -> VectorRoot<D> {
        self.tree.root()
    }

    /// Returns the retained live-state tree for range openings.
    pub(crate) const fn tree(&self) -> &Tree<D> {
        &self.tree
    }

    /// Returns the checked sum of live-state balances.
    pub const fn liability(&self) -> u64 {
        self.liability
    }

    /// Opens one authenticated account from the cached state tree.
    pub fn opening(&self, account: &P) -> Result<StateOpening<P, D>, TransitionError> {
        let (position, leaf) = self
            .locate(account)
            .ok_or(TransitionError::UnknownAccount)?;
        Ok(StateOpening {
            leaf: leaf.clone(),
            proof: self.tree.opening(position)?,
        })
    }

    /// Opens membership or ordered nonmembership for one account.
    pub fn lookup(&self, account: &P) -> Result<StateLookup<P, D>, TransitionError> {
        match self
            .leaves
            .binary_search_by(|leaf| leaf.account.cmp(account))
        {
            Ok(position) => Ok(StateLookup::Present(Box::new(StateValueOpening {
                state: self.leaves[position].state,
                proof: self.tree.opening(position as u32)?,
            }))),
            Err(insertion) => {
                let insertion =
                    u32::try_from(insertion).map_err(|_| TransitionError::TooManyStates)?;
                let (predecessor, successor, opening) =
                    self.tree.bracket(&self.leaves, insertion..insertion)?;
                Ok(StateLookup::Absent(StateAbsence {
                    predecessor,
                    successor,
                    opening,
                }))
            }
        }
    }

    fn locate(&self, account: &P) -> Option<(u32, &StateLeaf<P>)> {
        self.leaves
            .binary_search_by(|leaf| leaf.account.cmp(account))
            .ok()
            .and_then(|position| {
                u32::try_from(position)
                    .ok()
                    .map(|position| (position, &self.leaves[position as usize]))
            })
    }
}

fn boundary_accounts<'a, P: PublicKey, D: Digest>(
    deposits: &'a DepositBatch<P>,
    withdrawals: &'a WithdrawalBatch<P, D>,
) -> BTreeSet<&'a P> {
    let mut accounts = BTreeSet::new();
    accounts.extend(deposits.records().iter().map(|record| record.account()));
    accounts.extend(
        withdrawals
            .requests()
            .iter()
            .map(|request| request.account()),
    );
    accounts
}

fn validate_boundary_batches<P: PublicKey, D: Digest>(
    deployment: &D,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    limits: &CloseLimits,
) -> Result<(), TransitionError> {
    withdrawals.verify_deployment(deployment)?;
    let accounts = boundary_accounts(deposits, withdrawals);
    let account_count = u64::try_from(accounts.len()).map_err(|_| TransitionError::CloseLimit)?;
    let withdrawal_count =
        u64::try_from(withdrawals.len()).map_err(|_| TransitionError::CloseLimit)?;
    if account_count > limits.max_rows
        || withdrawal_count > limits.max_withdrawals
        || deposits.total() > limits.max_deposit_total
    {
        return Err(TransitionError::CloseLimit);
    }
    Ok(())
}

fn validate_sealed_boundaries<P: PublicKey, D: Digest>(
    cache: &StateCache<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    limits: &CloseLimits,
) -> Result<(), TransitionError> {
    // The bound roots pin these batches byte-identical to the ones the epoch
    // registration validated, so only the cache-relative rules run here.
    let accounts = boundary_accounts(deposits, withdrawals);
    if u64::try_from(cache.len()).map_err(|_| TransitionError::CloseLimit)? > limits.max_states {
        return Err(TransitionError::CloseLimit);
    }

    for account in accounts {
        let predecessor = cache
            .locate(account)
            .map_or_else(AccountState::default, |(_, leaf)| leaf.state);
        let deposit = deposits.amount_for(account);
        let Some(withdrawal) = withdrawals.request_for(account) else {
            continue;
        };
        let body = withdrawal.body();
        match body.action() {
            WithdrawalAction::Amount(amount) => {
                let amount = amount.get();
                let available = u128::from(predecessor.balance) + u128::from(deposit);
                if u128::from(amount) > available {
                    return Err(TransitionError::WithdrawalCoverage);
                }
                if predecessor.active && deposit != 0 && deposit == amount {
                    return Err(TransitionError::BoundaryNoStateChange);
                }
            }
            WithdrawalAction::Close if !(predecessor.active || deposit != 0) => {
                return Err(TransitionError::BoundaryNoStateChange);
            }
            WithdrawalAction::Close => {}
        }
    }
    Ok(())
}

/// Verifies that a header commits exactly this context and root bundle.
pub fn validate_header<H, P, D>(
    context: &CloseContext<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if !header.verify::<H, P>(context, roots) {
        return Err(TransitionError::HeaderRoot);
    }
    Ok(())
}

/// Verifies a terminal proof whose header and boundary roots are already authenticated.
///
/// Returns the terminal prefix and the exact successor liability it certifies.
pub fn verify_terminal_proof_after_header<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    roots: &RootBundle<D>,
    proof: &TerminalProof<D>,
) -> Result<(Prefix, u64), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let terminal_position = u32::from(context.assignment().slice_count());
    let coverage_len = terminal_position
        .checked_add(1)
        .ok_or(TransitionError::TerminalProof)?;
    if proof.terminal_opening.position != terminal_position
        || proof.terminal_opening.proof.leaf_count != coverage_len
        || u64::from(proof.terminal.predecessor) > context.limits().max_states()
        || u64::from(proof.terminal.successor) > context.limits().max_states()
    {
        return Err(TransitionError::TerminalProof);
    }
    proof.terminal_opening.verify::<H>(
        VectorKind::Coverage,
        &roots.coverage,
        &proof.terminal.encode(),
    )?;
    let successor_liability = validate_terminal_boundary::<H, P, D>(
        context,
        roots,
        deposits,
        withdrawals,
        proof.terminal.change,
        &proof.terminal,
    )?;
    Ok((proof.terminal.prefix, successor_liability))
}

/// Verifies the complete public close relation from a decoded corpus.
#[allow(clippy::too_many_arguments)]
pub fn validate_close<H, P, D, B, R>(
    context: &CloseContext<P, D>,
    operator: &OperatorKey,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
    rng: &mut R,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
{
    validate_close_with_strategy::<H, P, D, B, R>(
        context,
        operator,
        deposits,
        withdrawals,
        close,
        rng,
        &Sequential,
    )
}

/// Adversarial decode limits for one proof slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SliceCodecConfig {
    /// Anchor-bound close limits.
    pub close: CloseLimits,
    /// Maximum proof hashes accepted within the outer byte bound.
    pub max_proof_hashes: usize,
}

impl SliceCodecConfig {
    /// Creates slice decode limits.
    pub const fn new(close: CloseLimits, max_proof_hashes: usize) -> Self {
        Self {
            close,
            max_proof_hashes,
        }
    }
}

impl<D: Digest> CoverageRange<D> {
    pub(crate) fn read_bounded(
        reader: &mut impl Buf,
        max_hashes: usize,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            start: SliceBoundary::read(reader)?,
            end: SliceBoundary::read(reader)?,
            opening: RangeOpening::read_bounded(reader, 2, max_hashes)?,
        })
    }
}

impl<P: PublicKey, D: Digest> ChangeRange<P, D> {
    pub(crate) fn read_bounded(
        reader: &mut impl Buf,
        maximum: usize,
        max_hashes: usize,
    ) -> Result<Self, CodecError> {
        let predecessor = Option::<ChangeGuard<P, D>>::read(reader)?;
        let rows = Vec::<AccountRow<P, D>>::read_cfg(reader, &(RangeCfg::new(..=maximum), ()))?;
        let successor = Option::<ChangeGuard<P, D>>::read(reader)?;
        let values = rows
            .len()
            .saturating_add(usize::from(predecessor.is_some()))
            .saturating_add(usize::from(successor.is_some()));
        let opening = RangeOpening::read_bounded(reader, values, max_hashes)?;
        Ok(Self {
            predecessor,
            rows,
            successor,
            opening,
        })
    }
}

impl<P: PublicKey, D: Digest> StateRange<P, D> {
    pub(crate) fn read_bounded(
        reader: &mut impl Buf,
        members: usize,
        max_hashes: usize,
    ) -> Result<Self, CodecError> {
        let predecessor = Option::<StateLeaf<P>>::read(reader)?;
        let successor = Option::<StateLeaf<P>>::read(reader)?;
        let values = members
            .checked_add(usize::from(predecessor.is_some()))
            .and_then(|values| values.checked_add(usize::from(successor.is_some())))
            .ok_or(CodecError::Invalid(
                "StateRange",
                "range value count overflows",
            ))?;
        Ok(Self {
            predecessor,
            successor,
            opening: RangeOpening::read_bounded(reader, values, max_hashes)?,
        })
    }
}

pub(crate) fn read_out_vectors<P: PublicKey>(
    reader: &mut impl Buf,
    rows: usize,
    limits: &CloseLimits,
) -> Result<Vec<OutVector<P>>, CodecError> {
    let count = usize::read_cfg(reader, &RangeCfg::exact(rows))?;
    let mut vectors = Vec::new();
    let mut total = 0_u64;
    for _ in 0..count {
        let epoch = u64::read(reader)?;
        let payer = P::read(reader)?;
        let remaining = limits.max_total_entries.saturating_sub(total);
        let entry_limit = limits
            .max_account_entries
            .min(remaining)
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let entry_limit = usize::try_from(entry_limit).map_err(|_| {
            codec_invalid("ProofSlice", "outgoing entry bound is not representable")
        })?;
        let entries = Vec::<OutEntry<P>>::read_cfg(reader, &(RangeCfg::new(..=entry_limit), ()))?;
        total = total
            .checked_add(u64::try_from(entries.len()).map_err(|_| {
                codec_invalid("ProofSlice", "outgoing entry count is not representable")
            })?)
            .filter(|total| *total <= limits.max_total_entries)
            .ok_or_else(|| {
                codec_invalid(
                    "ProofSlice",
                    "aggregate outgoing entry count exceeds configured bound",
                )
            })?;
        vectors.push(
            OutVector::new(epoch, payer, entries)
                .map_err(|_| codec_invalid("ProofSlice", "outgoing vector is not canonical"))?,
        );
    }
    Ok(vectors)
}

impl<P: PublicKey, D: Digest> Write for ProofSlice<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.index.write(writer);
        self.coverage.start.write(writer);
        self.coverage.end.write(writer);
        self.coverage.opening.write(writer);
        self.changes.predecessor.write(writer);
        self.changes.rows.write(writer);
        self.changes.successor.write(writer);
        self.changes.opening.write(writer);
        self.out_vectors.write(writer);
        self.operator_aggregate.write(writer);
        write_transpose(&self.transpose, writer);
        self.out_start.write(writer);
        self.in_start.write(writer);
        self.transpose_opening.write(writer);
        self.withdrawal_opening.write(writer);
        self.unchanged.write(writer);
        self.predecessor.predecessor.write(writer);
        self.predecessor.successor.write(writer);
        self.predecessor.opening.write(writer);
        self.successor.predecessor.write(writer);
        self.successor.successor.write(writer);
        self.successor.opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ProofSlice<P, D> {
    fn encode_size(&self) -> usize {
        self.encoded_size()
    }
}

impl<P: PublicKey, D: Digest> Read for ProofSlice<P, D> {
    /// Anchor-bound close limits and the maximum hashes accepted by each proof frontier.
    type Cfg = SliceCodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let row_limit = config
            .close
            .max_rows()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let row_limit = usize::try_from(row_limit)
            .map_err(|_| CodecError::Invalid("ProofSlice", "row limit is not representable"))?;
        let index = u16::read(reader)?;
        let coverage = CoverageRange::read_bounded(reader, config.max_proof_hashes)?;
        let changes = ChangeRange::read_bounded(reader, row_limit, config.max_proof_hashes)?;
        let out_vectors = read_out_vectors(reader, changes.rows.len(), &config.close)?;
        let operator_aggregate = Option::<OperatorAggregate>::read(reader)?;
        let transpose_count = coverage
            .end
            .prefix
            .in_count
            .checked_sub(coverage.start.prefix.in_count)
            .filter(|count| *count <= config.close.max_total_entries)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(CodecError::Invalid(
                "ProofSlice",
                "transpose entry count is not canonical",
            ))?;
        let transpose = read_transpose::<P>(reader, transpose_count.max(1))?;
        if transpose.len() != transpose_count {
            return Err(CodecError::Invalid(
                "ProofSlice",
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
                return Err(CodecError::Invalid(
                    "ProofSlice",
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
            .ok_or(CodecError::Invalid(
                "ProofSlice",
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
                return Err(CodecError::Invalid(
                    "ProofSlice",
                    "withdrawal opening presence does not match the output count",
                ));
            }
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let state_limit = config
            .close
            .max_states()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let state_limit = usize::try_from(state_limit)
            .map_err(|_| CodecError::Invalid("ProofSlice", "state limit is not representable"))?;
        let unchanged =
            Vec::<StateLeaf<P>>::read_cfg(reader, &(RangeCfg::new(..=state_limit), ()))?;
        let predecessor_members = unchanged
            .len()
            .checked_add(
                changes
                    .rows
                    .iter()
                    .filter(|row| row.predecessor.active)
                    .count(),
            )
            .ok_or(CodecError::Invalid(
                "ProofSlice",
                "predecessor member count overflows",
            ))?;
        let successor_members = unchanged
            .len()
            .checked_add(
                changes
                    .rows
                    .iter()
                    .filter(|row| row.successor.active)
                    .count(),
            )
            .ok_or(CodecError::Invalid(
                "ProofSlice",
                "successor member count overflows",
            ))?;
        let predecessor =
            StateRange::read_bounded(reader, predecessor_members, config.max_proof_hashes)?;
        let successor =
            StateRange::read_bounded(reader, successor_members, config.max_proof_hashes)?;
        Ok(Self {
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
            unchanged,
            predecessor,
            successor,
        })
    }
}

/// Decodes one slice only after enforcing a caller-selected byte limit.
pub fn decode_slice_bounded<P: PublicKey, D: Digest>(
    encoded: &[u8],
    limits: CloseLimits,
    max_bytes: usize,
) -> Result<ProofSlice<P, D>, CodecError> {
    if encoded.len() > max_bytes {
        return Err(CodecError::Invalid(
            "ProofSlice",
            "encoded slice exceeds configured byte limit",
        ));
    }
    let max_hashes = max_proof_hashes(D::SIZE, max_bytes)?;
    ProofSlice::decode_cfg(encoded, &SliceCodecConfig::new(limits, max_hashes))
}

pub(crate) const fn max_proof_hashes(
    digest_size: usize,
    max_bytes: usize,
) -> Result<usize, CodecError> {
    if digest_size == 0 {
        return Err(CodecError::Invalid(
            "ProofSlice",
            "digest encoded size is zero",
        ));
    }
    Ok(max_bytes / digest_size)
}

#[cfg(feature = "arbitrary")]
mod slice_arbitrary_impls {
    use super::*;

    impl<'a, D> arbitrary::Arbitrary<'a> for CoverageRange<D>
    where
        D: Digest,
        RangeOpening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                start: u.arbitrary()?,
                end: u.arbitrary()?,
                opening: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for ChangeRange<P, D>
    where
        P: PublicKey,
        D: Digest,
        AccountRow<P, D>: arbitrary::Arbitrary<'a>,
        ChangeGuard<P, D>: arbitrary::Arbitrary<'a>,
        RangeOpening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                predecessor: u.arbitrary()?,
                rows: u.arbitrary()?,
                successor: u.arbitrary()?,
                opening: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for StateRange<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest,
        RangeOpening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                predecessor: u.arbitrary()?,
                successor: u.arbitrary()?,
                opening: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for ProofSlice<P, D>
    where
        P: PublicKey,
        D: Digest,
        CoverageRange<D>: arbitrary::Arbitrary<'a>,
        ChangeRange<P, D>: arbitrary::Arbitrary<'a>,
        OutVector<P>: arbitrary::Arbitrary<'a>,
        TransposeEntry<P>: arbitrary::Arbitrary<'a>,
        OperatorAggregate: arbitrary::Arbitrary<'a>,
        StateLeaf<P>: arbitrary::Arbitrary<'a>,
        StateRange<P, D>: arbitrary::Arbitrary<'a>,
        RangeOpening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                index: u.arbitrary()?,
                coverage: u.arbitrary()?,
                changes: u.arbitrary()?,
                out_vectors: u.arbitrary()?,
                transpose: u.arbitrary()?,
                out_start: u.arbitrary()?,
                operator_aggregate: u.arbitrary()?,
                in_start: u.arbitrary()?,
                transpose_opening: u.arbitrary()?,
                withdrawal_opening: u.arbitrary()?,
                unchanged: u.arbitrary()?,
                predecessor: u.arbitrary()?,
                successor: u.arbitrary()?,
            })
        }
    }
}

/// Close construction or validation failure.
#[derive(Debug, Error)]
pub enum TransitionError {
    /// The header does not commit the context and roots.
    #[error("header does not commit the context and roots")]
    HeaderRoot,
    /// The predecessor state root does not match the bound context.
    #[error("predecessor state root does not match the bound context")]
    PredecessorRoot,
    /// The predecessor liability does not match the bound context.
    #[error("predecessor liability does not match the bound context")]
    PredecessorLiability,
    /// A row's predecessor state disagrees with the predecessor vector.
    #[error("row predecessor state disagrees with the predecessor vector")]
    PredecessorLinkage,
    /// Rows are not strictly account-sorted and unique.
    #[error("rows are not strictly account-sorted and unique")]
    NonCanonicalRows,
    /// The transpose is not strictly sorted by recipient and payer.
    #[error("transpose is not strictly sorted by recipient and payer")]
    NonCanonicalTranspose,
    /// A transpose entry credits an account with no changed row.
    #[error("transpose entry does not align with a changed row")]
    TransposeAlignment,
    /// Rows and outgoing vectors are not aligned one-for-one.
    #[error("rows and outgoing vectors are not aligned")]
    VectorAlignment,
    /// State leaves are not strictly sorted, live, and positive.
    #[error("state leaves are not canonical")]
    NonCanonicalStateOrder,
    /// Items are not sorted by their deterministic slice interval.
    #[error("items are not sorted by slice interval")]
    NonCanonicalSliceOrder,
    /// A public-key representation has no high-order byte for account partitioning.
    #[error("account public key has an empty canonical representation")]
    EmptyAccountKey,
    /// A requested account is absent from the committed live state.
    #[error("account is absent from the committed live state")]
    UnknownAccount,
    /// Admission does not precede a challenge deadline with a representable resolution time.
    #[error("admission must precede a challenge deadline below the maximum timestamp")]
    DeadlineOrder,
    /// The slice-bit bound is exceeded.
    #[error("slice-bit bound exceeded")]
    SliceBits,
    /// A slice index is outside the deterministic partition.
    #[error("slice index is outside the partition")]
    SliceIndex,
    /// A slice coverage opening is not canonical.
    #[error("slice coverage opening is not canonical")]
    SliceCoverage,
    /// A slice range opening is not canonical.
    #[error("slice range opening is not canonical")]
    SliceRange,
    /// A slice state range opening is not canonical.
    #[error("slice state range opening is not canonical")]
    SliceStateRange,
    /// An account appears in both the unchanged vector and a row.
    #[error("account appears in both the unchanged vector and a row")]
    StateRowOverlap,
    /// A predecessor row side is not canonical for an absent account.
    #[error("predecessor row side is not canonical for an absent account")]
    NonCanonicalPredecessorAbsence,
    /// A live leaf or row side violates the active-positive rule.
    #[error("live state must be active with positive balance")]
    InactiveBalance,
    /// A close exceeds a configured or protocol resource limit.
    #[error("close exceeds a configured resource limit")]
    CloseLimit,
    /// The state vector exceeds the protocol bound.
    #[error("state vector exceeds the protocol bound")]
    TooManyStates,
    /// The row vector exceeds the protocol bound.
    #[error("row vector exceeds the protocol bound")]
    TooManyRows,
    /// A cumulative counter regressed.
    #[error("cumulative counter regressed")]
    CounterRegression,
    /// A row balance equation does not hold.
    #[error("row balance equation does not hold")]
    BalanceEquation,
    /// A row's settlement output is not the derived classification.
    #[error("row settlement output is not the derived classification")]
    SettlementOutput,
    /// An unregistered row retains activity it cannot have.
    #[error("unregistered row retains impossible activity")]
    AccountActivity,
    /// An active row does not change authenticated state.
    #[error("active row does not change authenticated state")]
    UnchangedRow,
    /// A terminal outgoing endpoint disagrees with its row.
    #[error("terminal outgoing endpoint disagrees with its row")]
    OutgoingEndpoint,
    /// Outgoing presence does not match the debit advance.
    #[error("outgoing presence does not match the debit advance")]
    OutgoingPresence,
    /// A row's credit totals disagree with its transpose interval.
    #[error("row credit totals disagree with the transpose interval")]
    CreditTotals,
    /// A running prefix does not extend its predecessor exactly.
    #[error("running prefix does not extend its predecessor exactly")]
    Prefix,
    /// Prefix arithmetic overflowed.
    #[error("prefix arithmetic overflowed")]
    PrefixOverflow,
    /// Gross debit and credit are not equal.
    #[error("gross debit and credit are not equal")]
    PaymentConservation,
    /// The two edge-ordering accumulators are not equal.
    #[error("edge multiset accumulators are not equal")]
    MultisetMismatch,
    /// Boundary totals disagree with the sealed batches.
    #[error("boundary totals disagree with the sealed batches")]
    BoundaryTotals,
    /// A sealed boundary batch root does not match the context.
    #[error("sealed boundary batch root does not match the context")]
    BoundaryRoot,
    /// A boundary account has no changed row.
    #[error("boundary account has no changed row")]
    BoundaryAccountMissing,
    /// A sealed boundary cannot produce an exact payment-free state transition.
    #[error("sealed boundary can leave an account's authenticated state unchanged")]
    BoundaryNoStateChange,
    /// A withdrawal is not affordable from the sealed predecessor state and deposit.
    #[error("withdrawal is not covered by the sealed predecessor state and deposit")]
    WithdrawalCoverage,
    /// The successor liability equation does not hold.
    #[error("successor liability equation does not hold")]
    LiabilityEquation,
    /// Liability arithmetic overflowed.
    #[error("liability arithmetic overflowed")]
    LiabilityOverflow,
    /// The change root does not commit the disclosed rows.
    #[error("change root does not commit the disclosed rows")]
    ChangeRoot,
    /// The successor root does not commit the derived vector.
    #[error("successor root does not commit the derived vector")]
    SuccessorRoot,
    /// The withdrawal-output root does not commit the derived outputs.
    #[error("withdrawal-output root does not commit the derived outputs")]
    WithdrawalOutputRoot,
    /// The transpose root does not commit the disclosed entries.
    #[error("transpose root does not commit the disclosed entries")]
    TransposeRoot,
    /// The terminal proof is not canonical.
    #[error("terminal proof is not canonical")]
    TerminalProof,
    /// A withdrawal claim does not identify a certified output.
    #[error("withdrawal claim does not identify a certified output")]
    WithdrawalClaim,
    /// An external payout claim does not identify certified credit.
    #[error("external payout claim does not identify certified credit")]
    PayoutClaim,
    /// A chain-sealed boundary is malformed or unauthenticated.
    #[error("invalid boundary: {0}")]
    Boundary(#[from] BoundaryError),
    /// An acknowledgment failed verification.
    #[error("invalid acknowledgment: {0}")]
    Ack(#[from] AckError),
    /// An outgoing vector or transpose entry is invalid.
    #[error("invalid edge vector: {0}")]
    Vector(#[from] vector::Error),
    /// The generic vector commitment is invalid.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
}
