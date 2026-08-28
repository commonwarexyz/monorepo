//! Stateless close assembly and validation.

use crate::bajillion::{
    boundary::{
        BoundaryError, Deadline, DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
    },
    challenge::{
        AccountLookup, ChangeAbsence, ChangeLookup, ChangeOpening, HigherShardTipLookup,
        StateAbsence, StateLookup, StateOpening, StateValueOpening,
    },
    commitment::{self, Tree, VectorKind, VectorRoot},
    credit::{self, ShardHead, ShardSet},
    payment::{PaymentContext, PaymentError},
    state::{
        AccountChange, AccountRow, AccountState, ChangeGuard, Prefix, SettlementOutput, StateLeaf,
    },
};
use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use thiserror::Error;

mod slice;
pub use slice::{
    ChangeRange, CoverageRange, ProofSlice, SliceBoundary, SliceCodecConfig, StateRange,
    WithdrawalOutputRange, assemble_slices, decode_slice_bounded, validate_slice,
};
pub(crate) use slice::{validate_slice_header, validate_slice_structure_after_header};

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

/// The change, withdrawal-output, successor-state, and coverage roots for one close.
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
        })
    }
}

impl<D: Digest> Write for RootBundle<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.change.write(writer);
        self.withdrawal_outputs.write(writer);
        self.successor.write(writer);
        self.coverage.write(writer);
    }
}

impl<D: Digest> FixedSize for RootBundle<D> {
    const SIZE: usize = VectorRoot::<D>::SIZE * 4;
}

impl<D: Digest> Read for RootBundle<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            change: VectorRoot::read(reader)?,
            withdrawal_outputs: VectorRoot::read(reader)?,
            successor: VectorRoot::read(reader)?,
            coverage: VectorRoot::read(reader)?,
        })
    }
}

/// Context-bound digest committing to one [`RootBundle`].
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
        Self(H::hash(&[
            HEADER_ROOT_HASH_NAMESPACE,
            payment.as_ref(),
            context.predecessor_root().digest.as_ref(),
            roots.change.digest.as_ref(),
            roots.withdrawal_outputs.digest.as_ref(),
            roots.successor.digest.as_ref(),
            roots.coverage.digest.as_ref(),
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
        BatchId(H::hash(&[BATCH_ID_HASH_NAMESPACE, self.0.as_ref()]))
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

/// Canonical resource limits for constructing, decoding, and validating one close.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseLimits {
    max_states: u64,
    max_rows: u64,
    max_withdrawals: u64,
    max_shards_per_account: u64,
    max_total_shards: u64,
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
        max_shards_per_account: u64,
        max_total_shards: u64,
        max_payment_total: u64,
        max_deposit_total: u64,
        max_withdrawal_total: u64,
    ) -> Self {
        Self {
            max_states,
            max_rows,
            max_withdrawals,
            max_shards_per_account,
            max_total_shards,
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

    /// Returns the per-account terminal-shard limit.
    pub const fn max_shards_per_account(&self) -> u64 {
        self.max_shards_per_account
    }

    /// Returns the aggregate terminal-shard limit.
    pub const fn max_total_shards(&self) -> u64 {
        self.max_total_shards
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
        self.max_shards_per_account.write(writer);
        self.max_total_shards.write(writer);
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
            max_shards_per_account: u64::read(reader)?,
            max_total_shards: u64::read(reader)?,
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
}

/// Chain-known epoch registration bound to one exact predecessor state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseContext<P: PublicKey, D: Digest> {
    epoch: EpochContext<P, D>,
    predecessor_root: VectorRoot<D>,
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
}

/// Complete public corpus needed to validate one stateless close.
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
    /// Terminal shard sets aligned one-for-one with `rows`.
    pub shard_sets: Vec<ShardSet<P, D>>,
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

/// One prepared close with the Merkle state needed for dealing proof slices.
///
/// This transient value is not encoded. It retains the change, withdrawal-output,
/// successor-state, and coverage trees so repeated dealing and claim construction reuse them.
#[derive(Debug)]
pub struct PreparedClose<P: PublicKey, D: Digest> {
    close: Close<P, D>,
    predecessor_root: VectorRoot<D>,
    change_leaves: Vec<AccountChange<P, D>>,
    change_guards: Vec<ChangeGuard<P, D>>,
    changes: Tree<D>,
    withdrawal_outputs: Vec<WithdrawalOutput>,
    withdrawal_output_tree: Tree<D>,
    successor_leaves: Vec<StateLeaf<P>>,
    successor: Tree<D>,
    coverage_boundaries: Vec<SliceBoundary>,
    coverage: Tree<D>,
}

type ChangeMaterial<P, D> = (Vec<AccountChange<P, D>>, Vec<ChangeGuard<P, D>>, Tree<D>);
type WithdrawalOutputMaterial<D> = (Vec<WithdrawalOutput>, Tree<D>);

impl<P: PublicKey, D: Digest> PreparedClose<P, D> {
    pub(super) fn slice_bits(&self) -> u8 {
        let slice_count = self.coverage_boundaries.len() - 1;
        assert!(slice_count.is_power_of_two());
        u8::try_from(slice_count.ilog2()).expect("prepared slice count fits the supported width")
    }

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

    /// Validates the complete close relation without reconstructing any retained root.
    pub fn validate<H>(
        &self,
        context: &CloseContext<P, D>,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
    ) -> Result<(), TransitionError>
    where
        H: Hasher<Digest = D>,
    {
        validate_prepared_close::<H, P, D>(context, deposits, withdrawals, self)
    }

    /// Deals every deterministic proof slice from the retained Merkle state.
    pub fn assemble_slices(
        &self,
        cache: &StateCache<P, D>,
        strategy: &impl Strategy,
    ) -> Result<Vec<ProofSlice<P, D>>, TransitionError> {
        slice::assemble_prepared_slices(cache, self, strategy)
    }

    /// Opens one account-relative compact value from the retained change tree.
    pub fn change_opening(&self, position: u32) -> Result<ChangeOpening<D>, TransitionError> {
        let leaf = self
            .change_leaves
            .get(position as usize)
            .ok_or(TransitionError::SliceRange)?;
        Ok(ChangeOpening {
            value: leaf.value(),
            proof: self.changes.opening(position)?,
        })
    }

    /// Opens the terminal counts and aggregate flows needed for settlement admission.
    pub fn terminal_proof(&self) -> Result<TerminalProof<D>, TransitionError> {
        build_terminal_proof(&self.coverage_boundaries, &self.coverage)
    }

    /// Opens one external payout by recipient for later claiming.
    pub fn external_payout_claim(
        &self,
        recipient: &P,
    ) -> Result<ExternalPayoutClaim<P, D>, TransitionError> {
        build_external_payout_claim(&self.close, &self.change_leaves, &self.changes, recipient)
    }

    /// Opens one validator-derived withdrawal output and its membership proof.
    pub fn withdrawal_claim<H>(
        &self,
        withdrawals: &WithdrawalBatch<P, D>,
        account: &P,
    ) -> Result<WithdrawalClaim<D>, TransitionError>
    where
        H: Hasher<Digest = D>,
    {
        build_withdrawal_claim(
            &self.withdrawal_outputs,
            &self.withdrawal_output_tree,
            withdrawals,
            account,
        )
    }
}

fn build_terminal_proof<D: Digest>(
    coverage_boundaries: &[SliceBoundary],
    coverage: &Tree<D>,
) -> Result<TerminalProof<D>, TransitionError> {
    let position =
        u32::try_from(coverage_boundaries.len() - 1).map_err(|_| TransitionError::SliceCoverage)?;
    Ok(TerminalProof {
        terminal: coverage_boundaries[position as usize],
        terminal_opening: coverage.opening(position)?,
    })
}

fn build_external_payout_claim<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
    leaves: &[AccountChange<P, D>],
    changes: &Tree<D>,
    recipient: &P,
) -> Result<ExternalPayoutClaim<P, D>, TransitionError> {
    let position = close
        .rows
        .binary_search_by(|row| row.account.cmp(recipient))
        .map_err(|_| TransitionError::PayoutClaim)?;
    let position = u32::try_from(position).map_err(|_| TransitionError::TooManyRows)?;
    let leaf = leaves
        .get(position as usize)
        .cloned()
        .ok_or(TransitionError::PayoutClaim)?;
    if !matches!(leaf.output(), SettlementOutput::ExternalPayout(amount) if amount != 0) {
        return Err(TransitionError::PayoutClaim);
    }
    Ok(ExternalPayoutClaim {
        leaf,
        opening: changes.opening(position)?,
    })
}

fn build_withdrawal_claim<P: PublicKey, D: Digest>(
    outputs: &[WithdrawalOutput],
    output_tree: &Tree<D>,
    withdrawals: &WithdrawalBatch<P, D>,
    account: &P,
) -> Result<WithdrawalClaim<D>, TransitionError> {
    let withdrawal_position = withdrawals
        .requests()
        .binary_search_by(|request| request.account().cmp(account))
        .map_err(|_| TransitionError::WithdrawalClaim)?;
    let output = outputs
        .get(withdrawal_position)
        .cloned()
        .ok_or(TransitionError::WithdrawalClaim)?;
    Ok(WithdrawalClaim {
        output,
        output_opening: output_tree.opening(
            u32::try_from(withdrawal_position).map_err(|_| TransitionError::WithdrawalClaim)?,
        )?,
    })
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for Close<P, D>
where
    P: PublicKey,
    D: Digest,
    Header<D>: for<'a> arbitrary::Arbitrary<'a>,
    RootBundle<D>: for<'a> arbitrary::Arbitrary<'a>,
    AccountRow<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    StateLeaf<P>: for<'a> arbitrary::Arbitrary<'a>,
    ShardSet<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = usize::from(u.arbitrary::<u8>()? % 33);
        let mut rows = Vec::with_capacity(len);
        let mut shard_sets = Vec::with_capacity(len);
        for _ in 0..len {
            rows.push(u.arbitrary()?);
            shard_sets.push(u.arbitrary()?);
        }
        Ok(Self {
            header: u.arbitrary()?,
            roots: u.arbitrary()?,
            unchanged: u.arbitrary()?,
            rows,
            shard_sets,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for Close<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.header.write(writer);
        self.roots.write(writer);
        self.unchanged.write(writer);
        self.rows.write(writer);
        self.shard_sets.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Close<P, D> {
    fn encode_size(&self) -> usize {
        self.header.encode_size()
            + self.roots.encode_size()
            + self.unchanged.encode_size()
            + self.rows.encode_size()
            + self.shard_sets.encode_size()
    }
}

const fn codec_invalid(name: &'static str, reason: &'static str) -> CodecError {
    CodecError::Invalid(name, reason)
}

fn read_shard_sets<P: PublicKey, D: Digest>(
    reader: &mut impl Buf,
    rows: usize,
    limits: &CloseLimits,
) -> Result<Vec<ShardSet<P, D>>, CodecError> {
    let count = usize::read_cfg(reader, &RangeCfg::exact(rows))?;
    let mut sets = Vec::new();
    let mut total = 0_u64;
    for _ in 0..count {
        let epoch = u64::read(reader)?;
        let recipient = P::read(reader)?;
        let remaining = limits.max_total_shards.saturating_sub(total);
        let head_limit = limits
            .max_shards_per_account
            .min(remaining)
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let head_limit = usize::try_from(head_limit).map_err(|_| {
            codec_invalid(
                "clearing::Close",
                "terminal shard bound is not representable",
            )
        })?;
        let head_count = usize::read_cfg(reader, &RangeCfg::new(..=head_limit))?;
        let mut heads = Vec::with_capacity(head_count.min(reader.remaining()));
        for _ in 0..head_count {
            heads.push(ShardHead::read(reader)?);
        }
        total = total
            .checked_add(u64::try_from(heads.len()).map_err(|_| {
                codec_invalid(
                    "clearing::Close",
                    "terminal shard count is not representable",
                )
            })?)
            .filter(|total| *total <= limits.max_total_shards)
            .ok_or_else(|| {
                codec_invalid(
                    "clearing::Close",
                    "aggregate terminal shard count exceeds configured bound",
                )
            })?;
        sets.push(ShardSet::new(epoch, recipient, heads).map_err(|_| {
            codec_invalid("clearing::Close", "terminal shard set is not canonical")
        })?);
    }
    Ok(sets)
}

impl<P: PublicKey, D: Digest> Read for Close<P, D> {
    type Cfg = CloseLimits;

    fn read_cfg(reader: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let header = Header::read(reader)?;
        let roots = RootBundle::read(reader)?;
        let state_limit = limits
            .max_states
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let state_limit = usize::try_from(state_limit)
            .map_err(|_| codec_invalid("clearing::Close", "state bound is not representable"))?;
        let unchanged =
            Vec::<StateLeaf<P>>::read_cfg(reader, &(RangeCfg::new(..=state_limit), ()))?;
        let row_limit = limits
            .max_rows
            .min(u64::from(commitment::MAX_VECTOR_LENGTH));
        let row_limit = usize::try_from(row_limit)
            .map_err(|_| codec_invalid("clearing::Close", "row bound is not representable"))?;
        let rows = Vec::<AccountRow<P, D>>::read_cfg(reader, &(RangeCfg::new(..=row_limit), ()))?;
        let shard_sets = read_shard_sets(reader, rows.len(), limits)?;
        Ok(Self {
            header,
            roots,
            unchanged,
            rows,
            shard_sets,
        })
    }
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

const fn is_live_state(state: &AccountState) -> bool {
    state.active && state.balance > 0
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

/// Derives the unchanged live-state suffix of a close.
///
/// The caller must supply strictly account-sorted inputs: `predecessor` comes
/// from a validated [`StateCache`] and `rows` must already have passed the
/// canonical-order scan.
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

type StateVectors<P> = (Vec<StateLeaf<P>>, Vec<StateLeaf<P>>);

fn derive_state_vectors<P: PublicKey, D: Digest>(
    unchanged: &[StateLeaf<P>],
    rows: &[AccountRow<P, D>],
    max_states: u64,
) -> Result<StateVectors<P>, TransitionError> {
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
    for row in rows {
        validate_row_state_sides(row)?;
    }

    let capacity = unchanged.len().saturating_add(rows.len());
    let mut predecessor = Vec::with_capacity(capacity);
    let mut successor = Vec::with_capacity(capacity);
    let mut unchanged_index = 0_usize;
    let mut row_index = 0_usize;
    while unchanged_index < unchanged.len() || row_index < rows.len() {
        match (unchanged.get(unchanged_index), rows.get(row_index)) {
            (Some(leaf), Some(row)) if leaf.account < row.account => {
                predecessor.push(leaf.clone());
                successor.push(leaf.clone());
                unchanged_index += 1;
            }
            (Some(leaf), Some(row)) if row.account < leaf.account => {
                if row.predecessor.active {
                    predecessor.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.predecessor,
                    });
                }
                if row.successor.active {
                    successor.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.successor,
                    });
                }
                row_index += 1;
            }
            (Some(_), Some(_)) => return Err(TransitionError::StateRowOverlap),
            (Some(leaf), None) => {
                predecessor.push(leaf.clone());
                successor.push(leaf.clone());
                unchanged_index += 1;
            }
            (None, Some(row)) => {
                if row.predecessor.active {
                    predecessor.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.predecessor,
                    });
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

    let protocol_max = u64::from(commitment::MAX_VECTOR_LENGTH);
    let predecessor_len =
        u64::try_from(predecessor.len()).map_err(|_| TransitionError::TooManyStates)?;
    let successor_len =
        u64::try_from(successor.len()).map_err(|_| TransitionError::TooManyStates)?;
    if predecessor_len > max_states
        || successor_len > max_states
        || predecessor_len > protocol_max
        || successor_len > protocol_max
    {
        return Err(TransitionError::TooManyStates);
    }
    Ok((predecessor, successor))
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

fn validate_corpus_limits<P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    rows: &[AccountRow<P, D>],
    shard_sets: &[ShardSet<P, D>],
    totals: Prefix,
) -> Result<(), TransitionError> {
    let limits = context.limits();
    let row_count = u64::try_from(rows.len()).map_err(|_| TransitionError::CloseLimit)?;
    if row_count > limits.max_rows
        || totals.withdrawal_count > limits.max_withdrawals
        || totals.debit > limits.max_payment_total
        || totals.credit > limits.max_payment_total
        || totals.payout > limits.max_payment_total
        || totals.deposit > limits.max_deposit_total
        || totals.withdrawal > limits.max_withdrawal_total
    {
        return Err(TransitionError::CloseLimit);
    }

    let mut total_shards = 0_u64;
    for shards in shard_sets {
        let count = u64::try_from(shards.heads().len()).map_err(|_| TransitionError::CloseLimit)?;
        if count > limits.max_shards_per_account {
            return Err(TransitionError::CloseLimit);
        }
        total_shards = total_shards
            .checked_add(count)
            .ok_or(TransitionError::CloseLimit)?;
    }
    if total_shards > limits.max_total_shards || totals.shard_count > limits.max_total_shards {
        return Err(TransitionError::CloseLimit);
    }
    Ok(())
}

/// Reusable index for constructing bounded account lookups against one close.
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
        validate_header::<H, P, D>(context, &close.header, &close.roots)?;
        if close
            .rows
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(TransitionError::NonCanonicalRows);
        }
        let (leaves, guards, tree) =
            change_material_with_strategy::<H, P, D>(&close.rows, &close.shard_sets, &Sequential)?;
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

    /// Constructs membership or adjacent ordered-absence evidence for `account`.
    pub fn account_lookup(
        &self,
        state: &StateCache<P, D>,
        account: &P,
    ) -> Result<AccountLookup<P, D>, TransitionError> {
        if state.root() != self.predecessor_root {
            return Err(TransitionError::PredecessorRoot);
        }
        match self.change_lookup(account)? {
            ChangeLookup::Present(opening) => Ok(AccountLookup::Present(opening)),
            ChangeLookup::Absent(change) => Ok(AccountLookup::Absent {
                state: Box::new(state.lookup(account)?),
                change,
            }),
        }
    }

    /// Constructs compact membership or shared adjacent-absence evidence for `account`.
    pub fn change_lookup(&self, account: &P) -> Result<ChangeLookup<P, D>, TransitionError> {
        match self
            .leaves
            .binary_search_by(|leaf| leaf.account().cmp(account))
        {
            Ok(position) => Ok(ChangeLookup::Present(Box::new(ChangeOpening {
                value: self.leaves[position].value(),
                proof: self.tree.opening(position as u32)?,
            }))),
            Err(insertion) => {
                let insertion =
                    u32::try_from(insertion).map_err(|_| TransitionError::SliceRange)?;
                let (predecessor, successor, opening) =
                    self.tree.bracket(&self.guards, insertion..insertion)?;
                Ok(ChangeLookup::Absent(ChangeAbsence {
                    predecessor,
                    successor,
                    opening,
                }))
            }
        }
    }

    /// Constructs the composed recipient and shard lookup for a higher-tip challenge.
    pub fn higher_shard_tip_lookup<H: Hasher<Digest = D>>(
        &self,
        account: &P,
        shards: Option<&ShardSet<P, D>>,
        shard: u64,
    ) -> Result<HigherShardTipLookup<P, D>, TransitionError> {
        match self.change_lookup(account)? {
            ChangeLookup::Present(opening) => {
                let shards = shards.ok_or(TransitionError::ShardAlignment)?;
                if shards.recipient() != account {
                    return Err(TransitionError::ShardAlignment);
                }
                let tip = shards.lookup::<H>(shard)?;
                let (credit_tip_root, _) = tip.reconstruct::<H>(shard)?;
                if credit_tip_root != opening.value.credit_tip_root() {
                    return Err(TransitionError::ShardAlignment);
                }
                Ok(HigherShardTipLookup::Present {
                    value: opening.value.core(),
                    proof: opening.proof,
                    tip,
                })
            }
            ChangeLookup::Absent(absence) => {
                if shards.is_some() {
                    return Err(TransitionError::ShardAlignment);
                }
                Ok(HigherShardTipLookup::Absent(absence))
            }
        }
    }
}

fn checked_successor_liability(
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

#[cfg(test)]
fn change_tree<H, P, D>(
    rows: &[AccountRow<P, D>],
    shard_sets: &[ShardSet<P, D>],
) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    change_tree_with_strategy::<H, P, D>(rows, shard_sets, &Sequential)
}

fn change_tree_with_strategy<H, P, D>(
    rows: &[AccountRow<P, D>],
    shard_sets: &[ShardSet<P, D>],
    strategy: &impl Strategy,
) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let (_, _, tree) = change_material_with_strategy::<H, P, D>(rows, shard_sets, strategy)?;
    Ok(tree)
}

fn change_material_with_strategy<H, P, D>(
    rows: &[AccountRow<P, D>],
    shard_sets: &[ShardSet<P, D>],
    strategy: &impl Strategy,
) -> Result<ChangeMaterial<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if rows.len() != shard_sets.len() {
        return Err(TransitionError::ShardAlignment);
    }
    let len = u32::try_from(rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    let leaves = strategy.try_map_collect_vec(rows.iter().zip(shard_sets), |(row, shards)| {
        AccountChange::<P, D>::from_row::<H>(row, shards).map_err(TransitionError::from)
    })?;
    let guards = strategy.map_collect_vec(leaves.iter(), |leaf| leaf.guard::<H>());
    let mut builder = commitment::Builder::<H>::new(VectorKind::Change, len)?;
    builder.add_values(&guards, strategy)?;
    Ok((leaves, guards, builder.build(strategy)?))
}

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
    let outputs = derive_withdrawal_outputs::<P, D>(rows, withdrawals)?;
    let mut builder = commitment::Builder::<H>::new(VectorKind::WithdrawalOutput, len)?;
    builder.add_values(&outputs, strategy)?;
    Ok((outputs, builder.build(strategy)?))
}

fn derive_withdrawal_outputs<P, D>(
    rows: &[AccountRow<P, D>],
    withdrawals: &WithdrawalBatch<P, D>,
) -> Result<Vec<WithdrawalOutput>, TransitionError>
where
    P: PublicKey,
    D: Digest,
{
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
    Ok(outputs)
}

fn state_liability<P: PublicKey>(leaves: &[StateLeaf<P>]) -> Result<u64, TransitionError> {
    leaves.iter().try_fold(0_u64, |total, leaf| {
        total
            .checked_add(leaf.state.balance)
            .ok_or(TransitionError::LiabilityOverflow)
    })
}

/// Builds one close from the complete live predecessor state, then validates it fully.
pub fn build_close<H, P, D>(
    cache: &StateCache<P, D>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    rows: Vec<AccountRow<P, D>>,
    shard_sets: Vec<ShardSet<P, D>>,
) -> Result<Close<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    build_close_with_strategy::<H, P, D>(
        cache,
        context,
        deposits,
        withdrawals,
        rows,
        shard_sets,
        &Sequential,
    )
}

/// Builds one close with the supplied execution strategy, then validates it fully.
pub fn build_close_with_strategy<H, P, D>(
    cache: &StateCache<P, D>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    rows: Vec<AccountRow<P, D>>,
    shard_sets: Vec<ShardSet<P, D>>,
    strategy: &impl Strategy,
) -> Result<Close<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let prepared = prepare_close_with_strategy::<H, P, D>(
        cache,
        context,
        deposits,
        withdrawals,
        rows,
        shard_sets,
        strategy,
    )?;
    prepared.validate::<H>(context, deposits, withdrawals)?;
    Ok(prepared.into_close())
}

/// Assembles a close and retains its Merkle material for later dealing.
///
/// This validates canonical shape, authenticated context, boundary roots, and exact predecessor-state
/// linkage. Call [`PreparedClose::validate`] before relying on row equations or signatures when
/// the corpus was not assembled from already accepted local payments.
pub fn prepare_close_with_strategy<H, P, D>(
    cache: &StateCache<P, D>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    rows: Vec<AccountRow<P, D>>,
    shard_sets: Vec<ShardSet<P, D>>,
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
    if cache.liability != context.predecessor_liability() {
        return Err(TransitionError::PredecessorLiability);
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::NonCanonicalRows);
    }
    let totals = rows.last().map_or_else(Prefix::default, |row| row.prefix);
    validate_corpus_limits(context, &rows, &shard_sets, totals)?;
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;

    let unchanged = derive_unchanged(cache.leaves(), &rows)?;
    let (predecessor_leaves, successor_leaves) =
        derive_state_vectors(&unchanged, &rows, context.limits().max_states())?;
    if predecessor_leaves != cache.leaves {
        return Err(TransitionError::PredecessorLinkage);
    }

    let successor = state_tree_with_strategy::<H, P, D>(&successor_leaves, strategy)?;
    let (change_leaves, change_guards, changes) =
        change_material_with_strategy::<H, P, D>(&rows, &shard_sets, strategy)?;
    let (withdrawal_outputs, withdrawal_output_tree) =
        withdrawal_output_material_with_strategy::<H, P, D>(&rows, withdrawals, strategy)?;
    let coverage_boundaries = slice::derive_coverage(
        &rows,
        &predecessor_leaves,
        &successor_leaves,
        context.assignment().slice_bits(),
    )?;
    let coverage = slice::coverage_tree_with_strategy::<H, D>(&coverage_boundaries, strategy)?;
    let expected_liability = checked_successor_liability(
        cache.liability,
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
    };
    let close = Close {
        header: Header::new::<H, P>(context, &roots),
        roots,
        unchanged,
        rows,
        shard_sets,
    };
    Ok(PreparedClose {
        close,
        predecessor_root: cache.root(),
        change_leaves,
        change_guards,
        changes,
        withdrawal_outputs,
        withdrawal_output_tree,
        successor_leaves,
        successor,
        coverage_boundaries,
        coverage,
    })
}

/// Assembles the terminal settlement witness from a decoded close.
///
/// Close producers should prefer [`PreparedClose::terminal_proof`], which reuses the retained
/// coverage tree. This convenience path reconstructs that tree from the public corpus.
pub fn assemble_terminal_proof<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
    strategy: &impl Strategy,
) -> Result<TerminalProof<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_close_preamble::<H, P, D>(context, deposits, withdrawals, close)?;
    let (predecessor, successor) =
        derive_state_vectors(&close.unchanged, &close.rows, context.limits().max_states())?;
    let coverage_boundaries = slice::derive_coverage(
        &close.rows,
        &predecessor,
        &successor,
        context.assignment().slice_bits(),
    )?;
    let coverage = slice::coverage_tree_with_strategy::<H, D>(&coverage_boundaries, strategy)?;
    if coverage.root() != close.roots.coverage {
        return Err(TransitionError::SliceCoverage);
    }
    build_terminal_proof(&coverage_boundaries, &coverage)
}

/// Opens one external payout from a decoded close.
pub fn assemble_external_payout_claim<H, P, D>(
    close: &Close<P, D>,
    recipient: &P,
    strategy: &impl Strategy,
) -> Result<ExternalPayoutClaim<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let (leaves, _, changes) =
        change_material_with_strategy::<H, P, D>(&close.rows, &close.shard_sets, strategy)?;
    if changes.root() != close.roots.change {
        return Err(TransitionError::ChangeRoot);
    }
    build_external_payout_claim(close, &leaves, &changes, recipient)
}

/// Opens one validator-derived withdrawal output from a decoded close.
pub fn assemble_withdrawal_claim<H, P, D>(
    close: &Close<P, D>,
    withdrawals: &WithdrawalBatch<P, D>,
    account: &P,
    strategy: &impl Strategy,
) -> Result<WithdrawalClaim<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let (outputs, output_tree) =
        withdrawal_output_material_with_strategy::<H, P, D>(&close.rows, withdrawals, strategy)?;
    if output_tree.root() != close.roots.withdrawal_outputs {
        return Err(TransitionError::WithdrawalOutputRoot);
    }
    build_withdrawal_claim(&outputs, &output_tree, withdrawals, account)
}

/// Validates the contextual root commitment and predecessor-state ancestry.
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

fn validate_corpus_shape<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
) -> Result<(), TransitionError> {
    let rows = u32::try_from(close.rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    if rows > commitment::MAX_VECTOR_LENGTH {
        return Err(TransitionError::RowCount);
    }
    if close.rows.len() != close.shard_sets.len() {
        return Err(TransitionError::ShardAlignment);
    }
    Ok(())
}

fn validate_boundaries<P: PublicKey, D: Digest>(
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
) -> Result<(), TransitionError> {
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

/// Validates one terminal prefix and returns the successor liability it settles to.
pub(crate) fn validate_terminal_prefix<P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row_count: u32,
    totals: Prefix,
) -> Result<u64, TransitionError> {
    let withdrawal_count =
        u64::try_from(withdrawals.len()).map_err(|_| TransitionError::BoundaryTotals)?;
    // The released withdrawal total is certified row-derived and may fall below
    // the batch's requested sum because uncovered amounts release zero. Over-
    // release fails the custody subtraction at admission.
    if totals.deposit != deposits.total() || totals.withdrawal_count != withdrawal_count {
        return Err(TransitionError::BoundaryTotals);
    }

    let limits = context.limits();
    if u64::from(row_count) > limits.max_rows()
        || totals.withdrawal_count > limits.max_withdrawals()
        || totals.shard_count > limits.max_total_shards()
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
    checked_successor_liability(
        context.predecessor_liability(),
        totals.deposit,
        totals.withdrawal,
        totals.payout,
    )
}

pub(crate) fn verify_terminal_proof_after_header<H, P, D>(
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
    let successor_liability = validate_terminal_prefix(
        context,
        deposits,
        withdrawals,
        proof.terminal.change,
        proof.terminal.prefix,
    )?;
    Ok((proof.terminal.prefix, successor_liability))
}

fn validate_boundary_roots<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if deposits.root::<H>()? != *context.deposit_root()
        || withdrawals.root::<H>()? != *context.withdrawal_root()
    {
        return Err(TransitionError::BoundaryRoot);
    }
    Ok(())
}

fn validate_row_inner<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row: &AccountRow<P, D>,
    shards: &ShardSet<P, D>,
    verify_signatures: bool,
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
                // Coverage is all-or-nothing. An amount the account can no
                // longer cover at the epoch tail settles with a zero release,
                // so a payer spending after authorizing a withdrawal cannot
                // leave the operator without a buildable close.
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

    // An unregistered row may only route credits out as an external payout.
    // The balance equation below rejects any residual state it would retain.
    if !registered && (credit == 0 || withdrawal.is_some()) {
        return Err(TransitionError::AccountActivity);
    }

    // An unchanged active row is stuffing. An unchanged absent row survives
    // only when it carries an effect, such as a deposit consumed exactly by
    // its own withdrawal, because the activity guard rejects the rest.
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

    match (&row.outgoing, debit) {
        (None, 0) => {}
        (Some(payment), debit) if debit != 0 => {
            // The whole terminal batch clears inside this epoch, so its total must fit in the
            // epoch's debit advance even though only one entry's receipt accompanies the send.
            let total = payment.send().body().total();
            if payment.payer() != &row.account
                || payment.send().body().cumulative_debit() != row.successor.cumulative_debit
                || total.is_none_or(|total| total > debit)
            {
                return Err(TransitionError::OutgoingEndpoint);
            }
            if verify_signatures {
                payment.verify_terminal::<H>(context.payment())?;
            } else {
                payment.validate_terminal_structure::<H>(context.payment())?;
            }
        }
        _ => return Err(TransitionError::OutgoingPresence),
    }

    if shards.epoch() != context.payment().epoch() || shards.recipient() != &row.account {
        return Err(TransitionError::ShardAlignment);
    }
    let (total_credit, total_receipts) = shards.totals()?;
    if total_credit != credit || total_receipts != receipts {
        return Err(TransitionError::CreditTotals);
    }
    for head in shards.heads() {
        if verify_signatures {
            head.payment.verify_terminal::<H>(context.payment())?;
        } else {
            head.payment
                .validate_terminal_structure::<H>(context.payment())?;
        }
    }

    Ok(Prefix {
        debit,
        credit,
        payout,
        deposit,
        withdrawal: withdrawal_amount,
        withdrawal_count: u64::from(withdrawal.is_some()),
        shard_count: u64::try_from(shards.heads().len())
            .map_err(|_| TransitionError::PrefixOverflow)?,
    })
}

fn validate_row<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row: &AccountRow<P, D>,
    shards: &ShardSet<P, D>,
) -> Result<Prefix, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_row_inner::<H, P, D>(context, deposits, withdrawals, row, shards, true)
}

pub(crate) fn validate_row_structure<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row: &AccountRow<P, D>,
    shards: &ShardSet<P, D>,
) -> Result<Prefix, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_row_inner::<H, P, D>(context, deposits, withdrawals, row, shards, false)
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
    validate_header::<H, P, D>(context, &close.header, &close.roots)?;
    validate_corpus_shape(close)?;
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
    validate_corpus_limits(context, &close.rows, &close.shard_sets, totals)?;
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;
    validate_boundaries(deposits, withdrawals, close)
}

fn validate_close_rows<H, P, D>(
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
    let mut prefix = Prefix::default();
    for (row, shards) in close.rows.iter().zip(&close.shard_sets) {
        let delta = validate_row::<H, P, D>(context, deposits, withdrawals, row, shards)?;
        prefix = prefix
            .checked_extend(delta)
            .ok_or(TransitionError::PrefixOverflow)?;
        if prefix != row.prefix {
            return Err(TransitionError::Prefix);
        }
    }
    let row_count = u32::try_from(close.rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    validate_terminal_prefix(context, deposits, withdrawals, row_count, prefix)?;
    Ok(())
}

fn validate_prepared_close<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    prepared: &PreparedClose<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    // Every retained tree and derived vector was fixed at the single
    // construction site from these same inputs, and the header pins the
    // context, so only the public close relation needs validation.
    let close = prepared.close();
    validate_close_preamble::<H, P, D>(context, deposits, withdrawals, close)?;
    validate_close_rows::<H, P, D>(context, deposits, withdrawals, close)
}

/// Verifies the complete public close relation.
pub fn validate_close<H, P, D>(
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
    validate_close_with_strategy::<H, P, D>(context, deposits, withdrawals, close, &Sequential)
}

/// Verifies the complete public close relation using the supplied execution strategy.
pub fn validate_close_with_strategy<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
    strategy: &impl Strategy,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    validate_close_preamble::<H, P, D>(context, deposits, withdrawals, close)?;
    if change_tree_with_strategy::<H, P, D>(&close.rows, &close.shard_sets, strategy)?.root()
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
    let coverage = slice::derive_coverage(
        &close.rows,
        &predecessor,
        &successor,
        context.assignment().slice_bits(),
    )?;
    if slice::coverage_tree_with_strategy::<H, D>(&coverage, strategy)?.root()
        != close.roots.coverage
    {
        return Err(TransitionError::SliceCoverage);
    }
    let totals = close
        .rows
        .last()
        .map_or_else(Prefix::default, |row| row.prefix);
    let expected_liability = checked_successor_liability(
        context.predecessor_liability(),
        deposits.total(),
        totals.withdrawal,
        totals.payout,
    )?;
    if state_liability(&successor)? != expected_liability {
        return Err(TransitionError::LiabilityEquation);
    }
    validate_close_rows::<H, P, D>(context, deposits, withdrawals, close)
}

/// Close construction or public validation failure.
#[derive(Debug, Error)]
pub enum TransitionError {
    /// The deterministic account partition exceeds the supported prefix width.
    #[error("slice bits exceed the supported bound")]
    SliceBits,
    /// A public-key representation has no high-order byte for account partitioning.
    #[error("account public key has an empty canonical representation")]
    EmptyAccountKey,
    /// Canonically ordered accounts do not form monotone high-order-key intervals.
    #[error("account ordering is incompatible with deterministic slice intervals")]
    NonCanonicalSliceOrder,
    /// A proof-slice index is outside the anchor-bound partition.
    #[error("proof-slice index is outside the authenticated partition")]
    SliceIndex,
    /// A slice does not authenticate the exact changed-row interval assigned to it.
    #[error("proof-slice changed-row range is not canonical")]
    SliceRange,
    /// A slice does not authenticate one exact state interval assigned to it.
    #[error("proof-slice state range is not canonical")]
    SliceStateRange,
    /// A slice does not authenticate its exact gap-free vector coverage.
    #[error("proof-slice coverage boundaries are not canonical")]
    SliceCoverage,
    /// The terminal settlement opening is malformed or out of bounds.
    #[error("terminal settlement proof is not canonical")]
    TerminalProof,
    /// A compact change opening does not classify an external payout.
    #[error("change opening does not classify an external payout")]
    PayoutClaim,
    /// A derived withdrawal output and opening do not form one finalized claim.
    #[error("withdrawal claim is not canonical")]
    WithdrawalClaim,
    /// A state vector exceeds its length bound.
    #[error("state vector exceeds its length bound")]
    TooManyStates,
    /// State accounts are not strictly sorted and unique.
    #[error("state accounts are not strictly sorted and unique")]
    NonCanonicalStateOrder,
    /// A committed leaf or projected row side is not active with positive balance.
    #[error("live state must be active with positive balance")]
    InactiveBalance,
    /// Changed rows exceed the protocol bound.
    #[error("changed rows exceed the protocol bound")]
    TooManyRows,
    /// Changed rows are not strictly sorted and unique.
    #[error("changed rows are not strictly sorted and unique")]
    NonCanonicalRows,
    /// A requested account is absent from the committed live state.
    #[error("account is absent from the committed live state")]
    UnknownAccount,
    /// A row's predecessor state does not match its cached account.
    #[error("row does not match the cached predecessor account state")]
    PredecessorLinkage,
    /// An absent predecessor row side is not the canonical default state.
    #[error("an absent predecessor row side must be the canonical default state")]
    NonCanonicalPredecessorAbsence,
    /// One account appears in both the unchanged vector and changed rows.
    #[error("unchanged leaves and changed rows must have disjoint accounts")]
    StateRowOverlap,
    /// A header does not authenticate its roots under the registered close context.
    #[error("header does not authenticate the supplied roots and close context")]
    HeaderRoot,
    /// The derived predecessor state root differs from the root owned by the close context.
    #[error("predecessor state root does not match the close context")]
    PredecessorRoot,
    /// Cached and expected predecessor liabilities differ.
    #[error("cached predecessor liability does not match the expected liability")]
    PredecessorLiability,
    /// Admission does not precede a challenge deadline with a representable resolution time.
    #[error("admission must precede a challenge deadline below the maximum timestamp")]
    DeadlineOrder,
    /// Changed-row or unchanged-state counts exceed their bounds.
    #[error("close row or unchanged-state counts exceed their bounds")]
    RowCount,
    /// Rows and receive-shard sets are not aligned one-for-one.
    #[error("changed rows and terminal shard sets are not aligned")]
    ShardAlignment,
    /// The committed change root does not match the exact semantic projections derived from rows.
    #[error("change root does not commit the derived row projections")]
    ChangeRoot,
    /// The committed withdrawal-output root does not match the exact derived outputs.
    #[error("withdrawal-output root does not commit the derived outputs")]
    WithdrawalOutputRoot,
    /// The committed successor-state root does not match the exact derived live state.
    #[error("successor-state root does not commit the derived live state")]
    SuccessorRoot,
    /// A close or sealed boundary exceeds its anchor-bound resource limits.
    #[error("close exceeds an anchor-bound resource limit")]
    CloseLimit,
    /// Supplied boundary batches do not match the roots sealed into the epoch anchor.
    #[error("boundary batches do not match the sealed epoch anchor")]
    BoundaryRoot,
    /// A sealed boundary cannot produce an exact payment-free state transition.
    #[error("sealed boundary can leave an account's authenticated state unchanged")]
    BoundaryNoStateChange,
    /// A boundary account has no changed row.
    #[error("a boundary account is missing its changed row")]
    BoundaryAccountMissing,
    /// Terminal prefix boundary totals or record count do not match the sealed batches.
    #[error("terminal prefix does not match the sealed boundary")]
    BoundaryTotals,
    /// A withdrawal is not affordable from the sealed predecessor state and deposit.
    #[error("withdrawal is not covered by the sealed predecessor state and deposit")]
    WithdrawalCoverage,
    /// A disclosed row does not change authenticated state.
    #[error("a disclosed changed-account row is unchanged")]
    UnchangedRow,
    /// Debit, credit, or receipt counters regressed.
    #[error("an account cumulative counter regressed")]
    CounterRegression,
    /// An inactive account changed without activation, or activity closed incorrectly.
    #[error("account activity transition is invalid")]
    AccountActivity,
    /// An account does not satisfy the exact widened balance equation.
    #[error("account balance equation is invalid")]
    BalanceEquation,
    /// A row's settlement output does not match its authenticated local effect.
    #[error("changed row settlement output is invalid")]
    SettlementOutput,
    /// Terminal outgoing evidence is not present exactly when debit advanced.
    #[error("terminal outgoing evidence presence does not match debit activity")]
    OutgoingPresence,
    /// Terminal outgoing evidence names another payer or debit endpoint, or its batch total
    /// exceeds the epoch debit advance.
    #[error("terminal outgoing evidence does not match the terminal debit endpoint")]
    OutgoingEndpoint,
    /// Receive-shard totals do not match the account credit and receipt deltas.
    #[error("terminal receive-shard totals do not match account deltas")]
    CreditTotals,
    /// Extending a running prefix overflowed.
    #[error("running close prefix overflowed")]
    PrefixOverflow,
    /// A row does not carry the exact next running prefix.
    #[error("changed row prefix is not continuous")]
    Prefix,
    /// Gross payment debit and credit differ.
    #[error("gross payment debit and credit are not conserved")]
    PaymentConservation,
    /// Predecessor and successor liabilities do not satisfy boundary flow conservation.
    #[error("predecessor and successor liabilities violate boundary flow conservation")]
    LiabilityEquation,
    /// A liability cannot be represented as a `u64`.
    #[error("aggregate account liability overflows u64")]
    LiabilityOverflow,
    /// A chain-sealed boundary is malformed or unauthenticated.
    #[error("invalid boundary: {0}")]
    Boundary(#[from] BoundaryError),
    /// A terminal payment is malformed or unauthenticated.
    #[error("invalid terminal payment: {0}")]
    Payment(#[from] PaymentError),
    /// A terminal receive-shard commitment is invalid.
    #[error("invalid terminal receive-shard set: {0}")]
    Credit(#[from] credit::Error),
    /// A typed vector commitment or opening is invalid.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        boundary::{DepositRecord, SignedWithdrawal},
        credit::ShardHead,
        payment::{Entry, Payment, SignedReceipt, SignedSend},
        state::AccountState,
    };
    use bytes::{Bytes, BytesMut};
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Sha256, Signer as _, sha256::Digest as ShaDigest};
    use commonware_cryptography_curve25519::signing::{
        Signature, SigningKey, StrictVerifyingKey as VerifyingKey,
    };
    use commonware_parallel::{Rayon, Sequential};
    use core::{
        fmt,
        num::NonZeroU64,
        ops::Deref,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use std::num::NonZeroUsize;

    type TestClose = Close<VerifyingKey, ShaDigest>;
    type TestContext = CloseContext<VerifyingKey, ShaDigest>;
    type TestDeposits = DepositBatch<VerifyingKey>;
    type TestWithdrawals = WithdrawalBatch<VerifyingKey, ShaDigest>;
    type TestPair = (
        AccountRow<VerifyingKey, ShaDigest>,
        ShardSet<VerifyingKey, ShaDigest>,
    );

    #[allow(clippy::too_many_arguments)]
    fn close_context<H, P, D>(
        deployment: D,
        epoch: u64,
        operator: P,
        cache: &StateCache<P, D>,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
        admission_deadline: Deadline,
        challenge_deadline: Deadline,
        limits: CloseLimits,
        assignment: Assignment<D>,
    ) -> Result<CloseContext<P, D>, TransitionError>
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
        D: Digest,
    {
        EpochContext::new::<H>(
            deployment,
            epoch,
            operator,
            deposits,
            withdrawals,
            cache.liability(),
            admission_deadline,
            challenge_deadline,
            limits,
            assignment,
        )
        .and_then(|epoch| epoch.bind::<H>(cache, deposits, withdrawals))
    }

    static HASH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static KEY_DECODES: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct CountingKey(VerifyingKey);

    impl fmt::Display for CountingKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&self.0, formatter)
        }
    }

    impl Deref for CountingKey {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }

    impl AsRef<[u8]> for CountingKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl Write for CountingKey {
        fn write(&self, writer: &mut impl BufMut) {
            self.0.write(writer);
        }
    }

    impl FixedSize for CountingKey {
        const SIZE: usize = VerifyingKey::SIZE;
    }

    impl Read for CountingKey {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            KEY_DECODES.fetch_add(1, Ordering::Relaxed);
            VerifyingKey::read_cfg(reader, &()).map(Self)
        }
    }

    impl commonware_utils::Span for CountingKey {}
    impl commonware_utils::Array for CountingKey {}

    impl commonware_cryptography::Verifier for CountingKey {
        type Signature = Signature;

        fn verify(&self, namespace: &[u8], message: &[u8], signature: &Signature) -> bool {
            commonware_cryptography::Verifier::verify(&self.0, namespace, message, signature)
        }
    }

    impl PublicKey for CountingKey {}

    #[derive(Default)]
    struct CountingHasher(Sha256);

    impl commonware_cryptography::Hasher for CountingHasher {
        type Digest = ShaDigest;

        fn hash(parts: &[&[u8]]) -> Self::Digest {
            HASH_CALLS.fetch_add(1, Ordering::Relaxed);
            Sha256::hash(parts)
        }

        fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
            HASH_CALLS.fetch_add(2, Ordering::Relaxed);
            Sha256::hash_pair(left, right)
        }

        fn update(&mut self, bytes: &[u8]) -> &mut Self {
            self.0.update(bytes);
            self
        }

        fn finalize(self) -> (Self, Self::Digest) {
            HASH_CALLS.fetch_add(1, Ordering::Relaxed);
            let (inner, digest) = self.0.finalize();
            (Self(inner), digest)
        }
    }

    struct PaymentFixture {
        cache: StateCache<VerifyingKey, ShaDigest>,
        context: TestContext,
        deposits: TestDeposits,
        withdrawals: TestWithdrawals,
        close: TestClose,
        operator: SigningKey,
        payer: SigningKey,
        payment: Payment<VerifyingKey, ShaDigest>,
    }

    fn state(balance: u64) -> AccountState {
        AccountState {
            balance,
            active: true,
            ..AccountState::default()
        }
    }

    fn amount(value: u64) -> WithdrawalAction {
        WithdrawalAction::Amount(NonZeroU64::new(value).unwrap())
    }

    fn withdrawal_output(destination: &'static [u8], amount: u64) -> WithdrawalOutput {
        WithdrawalOutput {
            destination: Bytes::from_static(destination),
            amount,
        }
    }

    const fn limits(rows: u64, per_account_shards: u64, total_shards: u64) -> CloseLimits {
        CloseLimits::new(
            commitment::MAX_VECTOR_LENGTH as u64,
            rows,
            rows,
            per_account_shards,
            total_shards,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        )
    }

    fn assignment(slice_bits: u8) -> Assignment<ShaDigest> {
        Assignment::new(Sha256::hash(&[b"test-validator-committee"]), slice_bits).unwrap()
    }

    fn payment(
        context: &PaymentContext<VerifyingKey, ShaDigest>,
        operator: &SigningKey,
        payer: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
    ) -> Payment<VerifyingKey, ShaDigest> {
        let send =
            SignedSend::sign_next(context, payer, recipient.public_key(), amount, 0).unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            context,
            &send,
            &recipient.public_key(),
            0,
            0,
            0,
            operator,
        )
        .unwrap();
        Payment::new::<Sha256>(context, send, receipt).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn linked_payment(
        context: &PaymentContext<VerifyingKey, ShaDigest>,
        operator: &SigningKey,
        payer: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
        previous_debit: u64,
        shard: u64,
        previous_credit: u64,
        previous_index: u64,
    ) -> Payment<VerifyingKey, ShaDigest> {
        let send = SignedSend::sign_next(
            context,
            payer,
            recipient.public_key(),
            amount,
            previous_debit,
        )
        .unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            context,
            &send,
            &recipient.public_key(),
            shard,
            previous_credit,
            previous_index,
            operator,
        )
        .unwrap();
        Payment::new::<Sha256>(context, send, receipt).unwrap()
    }

    fn assign_prefixes(
        pairs: &mut [TestPair],
        deposits: &TestDeposits,
        withdrawals: &TestWithdrawals,
    ) {
        let mut prefix = Prefix::default();
        for (row, shards) in pairs {
            let (debit, credit, _) = row.checked_deltas().unwrap();
            let deposit = deposits.amount_for(&row.account);
            let withdrawal = withdrawals.request_for(&row.account);
            let amount = withdrawal.map_or(0, |request| {
                let available =
                    u128::from(row.predecessor.balance) + u128::from(deposit) + u128::from(credit);
                let tail = available.checked_sub(u128::from(debit)).unwrap();
                match request.body().action() {
                    WithdrawalAction::Amount(amount) if u128::from(amount.get()) <= tail => {
                        amount.get()
                    }
                    WithdrawalAction::Amount(_) => 0,
                    WithdrawalAction::Close => u64::try_from(tail).unwrap(),
                }
            });
            let payout = if row.predecessor.active || deposit != 0 {
                0
            } else {
                credit
            };
            row.output = match withdrawal {
                Some(_) => SettlementOutput::Withdrawal(amount),
                None if payout != 0 => SettlementOutput::ExternalPayout(payout),
                None => SettlementOutput::None,
            };
            prefix = prefix
                .checked_extend(Prefix {
                    debit,
                    credit,
                    payout,
                    deposit,
                    withdrawal: amount,
                    withdrawal_count: u64::from(withdrawal.is_some()),
                    shard_count: shards.heads().len() as u64,
                })
                .unwrap();
            row.prefix = prefix;
        }
    }

    fn payment_fixture_with_slice_bits(slice_bits: u8) -> PaymentFixture {
        let operator = SigningKey::from_seed(1);
        let payer = SigningKey::from_seed(2);
        let recipient = SigningKey::from_seed(3);
        let payer_opening = state(100);
        let recipient_opening = state(40);
        let mut leaves = vec![
            StateLeaf {
                account: payer.public_key(),
                state: payer_opening,
            },
            StateLeaf {
                account: recipient.public_key(),
                state: recipient_opening,
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"deployment"]),
            7,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            98,
            99,
            CloseLimits::protocol_maximum(),
            assignment(slice_bits),
        )
        .unwrap();
        let payment_context = context.payment().clone();
        let payment = payment(&payment_context, &operator, &payer, &recipient, 20);

        let payer_shards = ShardSet::empty(payment_context.epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            payment_context.epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment.clone())],
        )
        .unwrap();
        let mut pairs = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    predecessor: payer_opening,
                    successor: AccountState {
                        balance: 80,
                        cumulative_debit: 20,
                        ..payer_opening
                    },
                    outgoing: Some(payment.clone()),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    predecessor: recipient_opening,
                    successor: AccountState {
                        balance: 60,
                        cumulative_credit: 20,
                        receipt_count: 1,
                        ..recipient_opening
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
        )
        .unwrap();
        PaymentFixture {
            cache,
            context,
            deposits,
            withdrawals,
            close,
            operator,
            payer,
            payment,
        }
    }

    fn payment_fixture() -> PaymentFixture {
        payment_fixture_with_slice_bits(0)
    }

    #[test]
    fn batched_terminal_send_validates_and_bounds_its_total() {
        let operator = SigningKey::from_seed(1);
        let payer = SigningKey::from_seed(2);
        let first = SigningKey::from_seed(3);
        let second = SigningKey::from_seed(4);
        let payer_opening = state(100);
        let first_opening = state(40);
        let second_opening = state(10);
        let mut leaves = vec![
            StateLeaf {
                account: payer.public_key(),
                state: payer_opening,
            },
            StateLeaf {
                account: first.public_key(),
                state: first_opening,
            },
            StateLeaf {
                account: second.public_key(),
                state: second_opening,
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"deployment"]),
            7,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            98,
            99,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let payment_context = context.payment().clone();
        let send = SignedSend::sign_next_batch(
            &payment_context,
            &payer,
            vec![
                Entry::new(first.public_key(), 15).unwrap(),
                Entry::new(second.public_key(), 5).unwrap(),
            ],
            0,
        )
        .unwrap();
        let first_payment = Payment::new::<Sha256>(
            &payment_context,
            send.clone(),
            SignedReceipt::issue_next::<Sha256, _>(
                &payment_context,
                &send,
                &first.public_key(),
                0,
                0,
                0,
                &operator,
            )
            .unwrap(),
        )
        .unwrap();
        let second_payment = Payment::new::<Sha256>(
            &payment_context,
            send.clone(),
            SignedReceipt::issue_next::<Sha256, _>(
                &payment_context,
                &send,
                &second.public_key(),
                0,
                0,
                0,
                &operator,
            )
            .unwrap(),
        )
        .unwrap();

        let mut pairs = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    predecessor: payer_opening,
                    successor: AccountState {
                        balance: 80,
                        cumulative_debit: 20,
                        ..payer_opening
                    },
                    outgoing: Some(second_payment.clone()),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                ShardSet::empty(payment_context.epoch(), payer.public_key()),
            ),
            (
                AccountRow {
                    account: first.public_key(),
                    predecessor: first_opening,
                    successor: AccountState {
                        balance: 55,
                        cumulative_credit: 15,
                        receipt_count: 1,
                        ..first_opening
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                ShardSet::new(
                    payment_context.epoch(),
                    first.public_key(),
                    vec![ShardHead::new(0, first_payment)],
                )
                .unwrap(),
            ),
            (
                AccountRow {
                    account: second.public_key(),
                    predecessor: second_opening,
                    successor: AccountState {
                        balance: 15,
                        cumulative_credit: 5,
                        receipt_count: 1,
                        ..second_opening
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                ShardSet::new(
                    payment_context.epoch(),
                    second.public_key(),
                    vec![ShardHead::new(0, second_payment.clone())],
                )
                .unwrap(),
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
        )
        .unwrap();
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();

        // A terminal batch whose total exceeds the epoch debit advance is rejected even though
        // its endpoint matches the successor debit.
        let row = AccountRow {
            account: payer.public_key(),
            predecessor: AccountState {
                balance: 95,
                cumulative_debit: 5,
                ..payer_opening
            },
            successor: AccountState {
                balance: 80,
                cumulative_debit: 20,
                ..payer_opening
            },
            outgoing: Some(second_payment),
            output: SettlementOutput::None,
            prefix: Prefix::default(),
        };
        let shards = ShardSet::empty(payment_context.epoch(), payer.public_key());
        assert!(matches!(
            validate_row_structure::<Sha256, _, _>(
                &context,
                &deposits,
                &withdrawals,
                &row,
                &shards
            ),
            Err(TransitionError::OutgoingEndpoint)
        ));
    }

    fn empty_fixture() -> (TestContext, TestDeposits, TestWithdrawals, TestClose) {
        let operator = SigningKey::from_seed(20);
        let account = SigningKey::from_seed(21).public_key();
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account,
            state: state(3),
        }])
        .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"deployment"]),
            8,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            49,
            50,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        (context, deposits, withdrawals, close)
    }

    #[test]
    fn state_opening_uses_cached_membership_and_rejects_unknown_accounts() {
        let mut leaves = (100..104)
            .map(|seed| StateLeaf {
                account: SigningKey::from_seed(seed).public_key(),
                state: state(seed),
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<CountingHasher>(leaves).unwrap();
        let account = cache.leaves()[2].account.clone();

        HASH_CALLS.store(0, Ordering::Relaxed);
        let opening = cache.opening(&account).unwrap();
        assert_eq!(HASH_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(opening.leaf, cache.leaves()[2]);
        opening
            .proof
            .verify::<Sha256>(
                VectorKind::State,
                &cache.root(),
                opening.leaf.encode().as_ref(),
            )
            .unwrap();

        let unknown = SigningKey::from_seed(999).public_key();
        assert!(matches!(
            cache.opening(&unknown),
            Err(TransitionError::UnknownAccount)
        ));
        assert_eq!(HASH_CALLS.load(Ordering::Relaxed), 0);
    }

    fn rebind_state(context: &TestContext, close: &mut TestClose) {
        close.roots.change = change_tree::<Sha256, _, _>(&close.rows, &close.shard_sets)
            .unwrap()
            .root();
        let (predecessor, successor) = derive_state_vectors(
            &close.unchanged,
            &close.rows,
            u64::from(commitment::MAX_VECTOR_LENGTH),
        )
        .unwrap();
        close.roots.successor = state_tree_with_strategy::<Sha256, _, _>(&successor, &Sequential)
            .unwrap()
            .root();
        let coverage = slice::derive_coverage(
            &close.rows,
            &predecessor,
            &successor,
            context.assignment().slice_bits(),
        )
        .unwrap();
        close.roots.coverage =
            slice::coverage_tree_with_strategy::<Sha256, _>(&coverage, &Sequential)
                .unwrap()
                .root();
        close.header = Header::new::<Sha256, _>(context, &close.roots);
    }

    #[test]
    fn payment_close_is_valid_and_codec_is_bounded() {
        let fixture = payment_fixture();
        validate_close::<Sha256, _, _>(
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
        )
        .unwrap();
        let encoded = fixture.close.encode();
        assert!(TestClose::decode_cfg(encoded.clone(), &limits(1, 1, 1)).is_err());
        let decoded = TestClose::decode_cfg(encoded, &limits(2, 1, 1)).unwrap();
        validate_close::<Sha256, _, _>(
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &decoded,
        )
        .unwrap();
    }

    #[test]
    fn close_decode_reads_each_key_occurrence_across_segments() {
        const HEAD_COUNT: usize = 32;

        let operator = SigningKey::from_seed(30);
        let payer = SigningKey::from_seed(31);
        let recipient = SigningKey::from_seed(32);
        let context = PaymentContext::new(
            Sha256::hash(&[b"counted-key-anchor"]),
            9,
            operator.public_key(),
        );
        let heads = (0..HEAD_COUNT as u64)
            .map(|shard| {
                ShardHead::new(
                    shard,
                    linked_payment(
                        &context, &operator, &payer, &recipient, 1, shard, shard, 0, 0,
                    ),
                )
            })
            .collect();
        let set = ShardSet::new(context.epoch(), recipient.public_key(), heads).unwrap();
        let encoded = vec![set].encode();
        let split = 1_usize.encode_size() + u64::SIZE + 7;

        KEY_DECODES.store(0, Ordering::Relaxed);
        let mut segmented = Bytes::copy_from_slice(&encoded[..split])
            .chain(Bytes::copy_from_slice(&encoded[split..]));
        let decoded = read_shard_sets::<CountingKey, ShaDigest>(
            &mut segmented,
            1,
            &limits(1, HEAD_COUNT as u64, HEAD_COUNT as u64),
        )
        .unwrap();
        assert_eq!(segmented.remaining(), 0);
        assert_eq!(decoded[0].heads().len(), HEAD_COUNT);
        assert_eq!(KEY_DECODES.load(Ordering::Relaxed), 1 + 3 * HEAD_COUNT);

        let head_start =
            1_usize.encode_size() + u64::SIZE + VerifyingKey::SIZE + HEAD_COUNT.encode_size();
        let truncated_at =
            head_start + u64::SIZE + ShaDigest::SIZE + u64::SIZE + VerifyingKey::SIZE - 1;
        KEY_DECODES.store(0, Ordering::Relaxed);
        let mut truncated = Bytes::copy_from_slice(&encoded[..split])
            .chain(Bytes::copy_from_slice(&encoded[split..truncated_at]));
        assert!(matches!(
            read_shard_sets::<CountingKey, ShaDigest>(
                &mut truncated,
                1,
                &limits(1, HEAD_COUNT as u64, HEAD_COUNT as u64),
            ),
            Err(CodecError::EndOfBuffer)
        ));
        assert_eq!(KEY_DECODES.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn header_is_one_context_bound_root_of_ordered_roots() {
        let fixture = payment_fixture();
        let header = &fixture.close.header;
        assert_eq!(Header::<ShaDigest>::SIZE, ShaDigest::SIZE);
        assert_eq!(RootBundle::<ShaDigest>::SIZE, ShaDigest::SIZE * 4);
        assert_eq!(header.encode().len(), ShaDigest::SIZE);
        validate_header::<Sha256, _, _>(&fixture.context, header, &fixture.close.roots).unwrap();

        let mut reordered = fixture.close.roots;
        core::mem::swap(&mut reordered.change, &mut reordered.successor);
        assert!(matches!(
            validate_header::<Sha256, _, _>(&fixture.context, header, &reordered),
            Err(TransitionError::HeaderRoot)
        ));

        let other_context = empty_fixture().0;
        assert!(!header.verify::<Sha256, _>(&other_context, &fixture.close.roots));
        let rebound = Header::new::<Sha256, _>(&other_context, &fixture.close.roots);
        assert!(matches!(
            validate_header::<Sha256, _, _>(&fixture.context, &rebound, &fixture.close.roots),
            Err(TransitionError::HeaderRoot)
        ));
    }

    #[test]
    fn successor_liability_uses_widened_checked_arithmetic() {
        assert_eq!(
            checked_successor_liability(u64::MAX, 1, 1, 0).unwrap(),
            u64::MAX
        );
        assert!(matches!(
            checked_successor_liability(u64::MAX, 1, 0, 0),
            Err(TransitionError::LiabilityOverflow)
        ));
        assert!(matches!(
            checked_successor_liability(0, 0, 1, 0),
            Err(TransitionError::LiabilityEquation)
        ));
    }

    #[test]
    fn sealed_boundary_requires_representable_holdings() {
        let operator = SigningKey::from_seed(104);
        let account = SigningKey::from_seed(105).public_key();
        let deposits = DepositBatch::new(vec![DepositRecord::new(account, 1).unwrap()]).unwrap();

        // A deposit-only boundary on a saturated ledger has no buildable close,
        // so registration must reject it before it can wedge the epoch.
        assert!(matches!(
            EpochContext::<VerifyingKey, ShaDigest>::new::<Sha256>(
                Sha256::hash(&[b"deployment"]),
                15,
                operator.public_key(),
                &deposits,
                &WithdrawalBatch::empty(),
                u64::MAX,
                9,
                10,
                CloseLimits::protocol_maximum(),
                assignment(0),
            ),
            Err(TransitionError::LiabilityOverflow)
        ));
    }

    #[test]
    fn row_stuffing_is_rejected() {
        let operator = SigningKey::from_seed(106);
        let mut accounts = [SigningKey::from_seed(107), SigningKey::from_seed(108)];
        accounts.sort_by_key(SigningKey::public_key);
        let registered = accounts[0].public_key();
        let absent = accounts[1].public_key();
        let opening = state(100);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: registered.clone(),
            state: opening,
        }])
        .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"row-stuffing"]),
            4,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();

        // An unchanged active row is stuffing.
        let unchanged = AccountRow {
            account: registered.clone(),
            predecessor: opening,
            successor: opening,
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix::default(),
        };
        let shards = ShardSet::empty(context.payment().epoch(), registered);
        assert!(matches!(
            validate_row::<Sha256, _, _>(&context, &deposits, &withdrawals, &unchanged, &shards),
            Err(TransitionError::UnchangedRow)
        ));

        // An absent row with no effects is unregistered inactivity.
        let inactive = AccountRow {
            account: absent.clone(),
            predecessor: AccountState::default(),
            successor: AccountState::default(),
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix::default(),
        };
        let shards = ShardSet::empty(context.payment().epoch(), absent.clone());
        assert!(matches!(
            validate_row::<Sha256, _, _>(&context, &deposits, &withdrawals, &inactive, &shards),
            Err(TransitionError::AccountActivity)
        ));

        // An unregistered credit may only route out as an external payout, so
        // retained successor state fails the balance equation.
        let retained = AccountRow {
            account: absent.clone(),
            predecessor: AccountState::default(),
            successor: AccountState {
                balance: 30,
                cumulative_credit: 30,
                active: true,
                ..AccountState::default()
            },
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix::default(),
        };
        let shards = ShardSet::empty(context.payment().epoch(), absent);
        assert!(matches!(
            validate_row::<Sha256, _, _>(&context, &deposits, &withdrawals, &retained, &shards),
            Err(TransitionError::BalanceEquation)
        ));
    }

    #[test]
    fn close_row_with_retained_successor_fails_the_balance_equation() {
        let operator = SigningKey::from_seed(109);
        let payer = SigningKey::from_seed(110);
        let opening = state(100);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: payer.public_key(),
            state: opening,
        }])
        .unwrap();
        let deployment = Sha256::hash(&[b"close-balance"]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            cache.root().digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            &payer,
        )])
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            4,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let row = AccountRow {
            account: payer.public_key(),
            predecessor: opening,
            successor: state(50),
            outgoing: None,
            output: SettlementOutput::Withdrawal(100),
            prefix: Prefix::default(),
        };
        let shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        assert!(matches!(
            validate_row::<Sha256, _, _>(&context, &deposits, &withdrawals, &row, &shards),
            Err(TransitionError::BalanceEquation)
        ));
    }

    #[test]
    fn proof_slices_authenticate_every_exhaustive_interval() {
        let fixture = payment_fixture_with_slice_bits(4);
        validate_close::<Sha256, _, _>(
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
        )
        .unwrap();
        let slices = assemble_slices::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
            &Sequential,
        )
        .unwrap();
        assert_eq!(slices.len(), 16);
        assert!(slices.iter().any(|slice| slice.changes.rows.is_empty()));
        assert_eq!(
            slices
                .iter()
                .flat_map(|slice| slice.changes.rows.clone())
                .collect::<Vec<_>>(),
            fixture.close.rows
        );
        assert_eq!(
            slices
                .iter()
                .flat_map(|slice| slice.shard_sets.clone())
                .collect::<Vec<_>>(),
            fixture.close.shard_sets
        );

        for slice in &slices {
            validate_slice::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close.header,
                &fixture.close.roots,
                slice,
            )
            .unwrap();
            let encoded = slice.encode();
            let decoded = decode_slice_bounded::<VerifyingKey, ShaDigest>(
                encoded.as_ref(),
                CloseLimits::protocol_maximum(),
                encoded.len(),
            )
            .unwrap();
            assert_eq!(&decoded, slice);
        }
    }

    #[test]
    fn maximum_partition_decodes_middle_coverage_opening() {
        let operator = SigningKey::from_seed(188);
        let cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(Vec::new()).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"maximum-coverage-partition"]),
            1,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(MAX_SLICE_BITS),
        )
        .unwrap();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let slices = assemble_slices::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();

        assert_eq!(slices.len(), 256);
        let middle = &slices[128];
        assert_eq!(middle.coverage.opening.proof.leaf_count, 257);
        let encoded = middle.encode();
        assert!(
            ProofSlice::<VerifyingKey, ShaDigest>::decode_cfg(
                encoded.as_ref(),
                &SliceCodecConfig::new(CloseLimits::protocol_maximum(), 0),
            )
            .is_err()
        );
        let decoded = decode_slice_bounded::<VerifyingKey, ShaDigest>(
            encoded.as_ref(),
            CloseLimits::protocol_maximum(),
            encoded.len(),
        )
        .unwrap();
        assert_eq!(&decoded, middle);
        validate_slice::<Sha256, _, _>(
            &context,
            &deposits,
            &withdrawals,
            &close.header,
            &close.roots,
            &decoded,
        )
        .unwrap();
    }

    #[test]
    fn slice_codec_hash_limit_bounds_frontiers_not_members() {
        let fixture = payment_fixture_with_slice_bits(0);
        let slice = assemble_slices::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
            &Sequential,
        )
        .unwrap()
        .pop()
        .unwrap();
        assert!(slice.coverage.opening.proof.siblings.is_empty());
        assert!(slice.changes.opening.proof.siblings.is_empty());
        assert!(slice.predecessor.opening.proof.siblings.is_empty());
        assert!(slice.successor.opening.proof.siblings.is_empty());

        let encoded = slice.encode();
        assert_eq!(
            ProofSlice::<VerifyingKey, ShaDigest>::decode_cfg(
                encoded.as_ref(),
                &SliceCodecConfig::new(CloseLimits::protocol_maximum(), 0),
            )
            .unwrap(),
            slice
        );

        let siblings = vec![Sha256::hash(&[b"oversized-frontier"]); 3];
        let mut coverage = slice.clone();
        coverage.coverage.opening.proof.siblings = siblings.clone();
        let mut changes = slice.clone();
        changes.changes.opening.proof.siblings = siblings.clone();
        let mut predecessor = slice.clone();
        predecessor.predecessor.opening.proof.siblings = siblings.clone();
        let mut successor = slice;
        successor.successor.opening.proof.siblings = siblings;
        for oversized in [coverage, changes, predecessor, successor] {
            assert!(
                ProofSlice::<VerifyingKey, ShaDigest>::decode_cfg(
                    oversized.encode().as_ref(),
                    &SliceCodecConfig::new(CloseLimits::protocol_maximum(), 2),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn absent_recipient_credit_is_committed_as_external_payout() {
        let operator = SigningKey::from_seed(189);
        let mut accounts = [SigningKey::from_seed(190), SigningKey::from_seed(191)];
        accounts.sort_by_key(SigningKey::public_key);
        let recipient = &accounts[0];
        let payer = &accounts[1];
        let payer_opening = state(100);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: payer.public_key(),
            state: payer_opening,
        }])
        .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"external-payout"]),
            4,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let empty_terminal_size = prepare_close_with_strategy::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
            &Sequential,
        )
        .unwrap()
        .terminal_proof()
        .unwrap()
        .encode_size();
        let payment = payment(context.payment(), &operator, payer, recipient, 20);
        let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment.clone())],
        )
        .unwrap();
        let mut pairs = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    predecessor: payer_opening,
                    successor: AccountState {
                        balance: 80,
                        cumulative_debit: 20,
                        ..payer_opening
                    },
                    outgoing: Some(payment),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    predecessor: AccountState::default(),
                    successor: AccountState {
                        cumulative_credit: 20,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
            &Sequential,
        )
        .unwrap();
        prepared
            .validate::<Sha256>(&context, &deposits, &withdrawals)
            .unwrap();
        let terminal = prepared.terminal_proof().unwrap();
        assert_eq!(terminal.encode_size(), empty_terminal_size);
        assert_eq!(
            terminal
                .verify::<Sha256, _>(
                    &context,
                    &deposits,
                    &withdrawals,
                    &prepared.close().header,
                    &prepared.close().roots,
                )
                .unwrap()
                .payout,
            20
        );
        let decoded = TerminalProof::<ShaDigest>::decode_cfg(terminal.encode(), &()).unwrap();
        assert_eq!(decoded, terminal);

        let claim = prepared
            .external_payout_claim(&recipient.public_key())
            .unwrap();
        assert_eq!(claim.position(), 0);
        assert_eq!(claim.recipient(), &recipient.public_key());
        assert_eq!(
            claim
                .verify::<Sha256>(&prepared.close().roots.change)
                .unwrap(),
            ExternalPayout {
                recipient: recipient.public_key(),
                amount: 20,
            }
        );
        let decoded =
            ExternalPayoutClaim::<VerifyingKey, ShaDigest>::decode_cfg(claim.encode(), &())
                .unwrap();
        assert_eq!(decoded, claim);
        let mut wrong_kind_row = prepared.close().rows[0].clone();
        wrong_kind_row.output = SettlementOutput::Withdrawal(20);
        let wrong_kind_leaf =
            AccountChange::from_row::<Sha256>(&wrong_kind_row, &prepared.close().shard_sets[0])
                .unwrap();
        let mut wrong_kind_builder =
            commitment::Builder::<Sha256>::new(VectorKind::Change, 1).unwrap();
        wrong_kind_builder
            .add_values(
                std::slice::from_ref(&wrong_kind_leaf.guard::<Sha256>()),
                &Sequential,
            )
            .unwrap();
        let wrong_kind_tree = wrong_kind_builder.build(&Sequential).unwrap();
        let wrong_kind = ExternalPayoutClaim {
            leaf: wrong_kind_leaf,
            opening: wrong_kind_tree.opening(0).unwrap(),
        };
        assert!(matches!(
            wrong_kind.verify::<Sha256>(&wrong_kind_tree.root()),
            Err(TransitionError::PayoutClaim)
        ));

        let close = prepared.close();

        assert_eq!(close.rows.last().unwrap().prefix.payout, 20);
        let (_, successor) = derive_state_vectors(
            &close.unchanged,
            &close.rows,
            u64::from(commitment::MAX_VECTOR_LENGTH),
        )
        .unwrap();
        assert_eq!(successor.len(), 1);
        assert_eq!(successor[0].account, payer.public_key());
        assert_eq!(successor[0].state.balance, 80);
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, close).unwrap();
    }

    fn amount_withdrawal_close(
        seed_base: u8,
        spend: u64,
        requested: u64,
        released: u64,
        residual: u64,
    ) {
        let operator = SigningKey::from_seed(u64::from(seed_base));
        let mut accounts = [
            SigningKey::from_seed(u64::from(seed_base) + 1),
            SigningKey::from_seed(u64::from(seed_base) + 2),
        ];
        accounts.sort_by_key(SigningKey::public_key);
        let payer = &accounts[0];
        let recipient = &accounts[1];
        let mut leaves = vec![
            StateLeaf {
                account: payer.public_key(),
                state: state(100),
            },
            StateLeaf {
                account: recipient.public_key(),
                state: state(40),
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deployment = Sha256::hash(&[b"amount-withdrawal-coverage"]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            cache.root().digest,
            Bytes::from_static(b"destination"),
            amount(requested),
            100,
            payer,
        )])
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            4,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let spent = payment(context.payment(), &operator, payer, recipient, spend);
        let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, spent.clone())],
        )
        .unwrap();
        let mut pairs = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    predecessor: state(100),
                    successor: AccountState {
                        balance: residual,
                        active: residual > 0,
                        cumulative_debit: spend,
                        ..state(100)
                    },
                    outgoing: Some(spent),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    predecessor: state(40),
                    successor: AccountState {
                        balance: 40 + spend,
                        cumulative_credit: spend,
                        receipt_count: 1,
                        ..state(40)
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
            &Sequential,
        )
        .unwrap();
        let close = prepared.close();
        let position = close
            .rows
            .binary_search_by(|row| row.account.cmp(&payer.public_key()))
            .unwrap();
        assert_eq!(
            close.rows[position].output,
            SettlementOutput::Withdrawal(released)
        );
        assert_eq!(close.rows[position].successor.balance, residual);
        let terminal = prepared
            .terminal_proof()
            .unwrap()
            .verify::<Sha256, _>(
                &context,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
            )
            .unwrap();
        assert_eq!(terminal.withdrawal, released);
        assert_eq!(
            prepared
                .withdrawal_claim::<Sha256>(&withdrawals, &payer.public_key())
                .unwrap()
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap(),
            withdrawal_output(b"destination", released)
        );
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, close).unwrap();
    }

    #[test]
    fn uncovered_amount_withdrawal_releases_nothing() {
        // The payer spends its whole balance before the queued withdrawal
        // reaches the close. The close must remain buildable: the uncovered
        // request settles with a zero release instead of wedging the operator
        // between an unbuildable balance equation and the withdrawal deadline.
        amount_withdrawal_close(240, 100, 100, 0, 0);
    }

    #[test]
    fn amount_withdrawal_coverage_is_all_or_nothing() {
        // One unit of tail shortfall voids the whole release.
        amount_withdrawal_close(244, 51, 50, 0, 49);
        // An exactly covered request still releases the full amount.
        amount_withdrawal_close(248, 50, 50, 50, 0);
        // A covered request with residual balance releases the full amount.
        amount_withdrawal_close(252, 40, 50, 50, 10);
    }

    #[test]
    fn external_payout_claim_rejects_credit_classified_as_close_withdrawal() {
        let operator = SigningKey::from_seed(192);
        let mut accounts = [
            SigningKey::from_seed(193),
            SigningKey::from_seed(194),
            SigningKey::from_seed(195),
            SigningKey::from_seed(196),
        ];
        accounts.sort_by_key(SigningKey::public_key);
        let close_payer = &accounts[0];
        let close_recipient = &accounts[1];
        let external_payer = &accounts[2];
        let external_recipient = &accounts[3];
        let predecessor = state(100);
        let mut leaves = vec![
            StateLeaf {
                account: close_payer.public_key(),
                state: predecessor,
            },
            StateLeaf {
                account: external_payer.public_key(),
                state: predecessor,
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deployment = Sha256::hash(&[b"close-withdrawal-is-not-payout"]);
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(close_recipient.public_key(), 5).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            cache.root().digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            close_recipient,
        )])
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            4,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let close_payment = payment(
            context.payment(),
            &operator,
            close_payer,
            close_recipient,
            7,
        );
        let external_payment = payment(
            context.payment(),
            &operator,
            external_payer,
            external_recipient,
            7,
        );
        let close_payer_shards =
            ShardSet::empty(context.payment().epoch(), close_payer.public_key());
        let close_recipient_shards = ShardSet::new(
            context.payment().epoch(),
            close_recipient.public_key(),
            vec![ShardHead::new(0, close_payment.clone())],
        )
        .unwrap();
        let external_payer_shards =
            ShardSet::empty(context.payment().epoch(), external_payer.public_key());
        let external_recipient_shards = ShardSet::new(
            context.payment().epoch(),
            external_recipient.public_key(),
            vec![ShardHead::new(0, external_payment.clone())],
        )
        .unwrap();
        let mut pairs = vec![
            (
                AccountRow {
                    account: close_payer.public_key(),
                    predecessor,
                    successor: AccountState {
                        balance: 93,
                        cumulative_debit: 7,
                        ..predecessor
                    },
                    outgoing: Some(close_payment),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                close_payer_shards,
            ),
            (
                AccountRow {
                    account: close_recipient.public_key(),
                    predecessor: AccountState::default(),
                    successor: AccountState {
                        cumulative_credit: 7,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                close_recipient_shards,
            ),
            (
                AccountRow {
                    account: external_payer.public_key(),
                    predecessor,
                    successor: AccountState {
                        balance: 93,
                        cumulative_debit: 7,
                        ..predecessor
                    },
                    outgoing: Some(external_payment),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                external_payer_shards,
            ),
            (
                AccountRow {
                    account: external_recipient.public_key(),
                    predecessor: AccountState::default(),
                    successor: AccountState {
                        cumulative_credit: 7,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                external_recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
            &Sequential,
        )
        .unwrap();
        let terminal = prepared
            .terminal_proof()
            .unwrap()
            .verify::<Sha256, _>(
                &context,
                &deposits,
                &withdrawals,
                &prepared.close().header,
                &prepared.close().roots,
            )
            .unwrap();
        assert_eq!(terminal.deposit, 5);
        assert_eq!(terminal.withdrawal, 12);
        assert_eq!(terminal.payout, 7);
        assert_eq!(
            prepared
                .withdrawal_claim::<Sha256>(&withdrawals, &close_recipient.public_key())
                .unwrap()
                .verify::<Sha256>(&prepared.close().roots.withdrawal_outputs)
                .unwrap(),
            withdrawal_output(b"destination", 12)
        );
        assert!(matches!(
            prepared.external_payout_claim(&close_recipient.public_key()),
            Err(TransitionError::PayoutClaim)
        ));

        let position = prepared
            .close()
            .rows
            .binary_search_by(|row| row.account.cmp(&close_recipient.public_key()))
            .unwrap() as u32;
        let forged = ExternalPayoutClaim {
            leaf: prepared.change_leaves[position as usize].clone(),
            opening: prepared.changes.opening(position).unwrap(),
        };
        assert!(matches!(
            forged.verify::<Sha256>(&prepared.close().roots.change),
            Err(TransitionError::PayoutClaim)
        ));
        assert_eq!(
            ExternalPayoutClaim::<VerifyingKey, ShaDigest>::decode_cfg(forged.encode(), &())
                .unwrap(),
            forged
        );

        let genuine = prepared
            .external_payout_claim(&external_recipient.public_key())
            .unwrap();
        assert_eq!(
            genuine
                .verify::<Sha256>(&prepared.close().roots.change)
                .unwrap(),
            ExternalPayout {
                recipient: external_recipient.public_key(),
                amount: 7,
            }
        );
        let mut wrong_opening = genuine;
        wrong_opening.opening.position = position;
        assert!(matches!(
            wrong_opening.verify::<Sha256>(&prepared.close().roots.change),
            Err(TransitionError::Commitment(_))
        ));
    }

    #[test]
    fn proof_slice_assembly_is_strategy_independent() {
        let fixture = payment_fixture_with_slice_bits(4);
        validate_close::<Sha256, _, _>(
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
        )
        .unwrap();
        let sequential = assemble_slices::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
            &Sequential,
        )
        .unwrap();
        let parallel = assemble_slices::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
            &Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap(),
        )
        .unwrap();

        assert_eq!(parallel, sequential);
    }

    #[test]
    fn prepared_close_reuses_roots_across_proof_assemblies() {
        let fixture = payment_fixture_with_slice_bits(4);
        let parallel = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();
        let expected = assemble_slices::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
            &Sequential,
        )
        .unwrap();

        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.close.rows.clone(),
            fixture.close.shard_sets.clone(),
            &parallel,
        )
        .unwrap();
        prepared
            .validate::<Sha256>(&fixture.context, &fixture.deposits, &fixture.withdrawals)
            .unwrap();
        assert_eq!(prepared.close(), &fixture.close);
        assert_eq!(
            prepared
                .assemble_slices(&fixture.cache, &Sequential)
                .unwrap(),
            expected
        );
        assert_eq!(
            prepared.assemble_slices(&fixture.cache, &parallel).unwrap(),
            expected
        );
    }

    #[test]
    fn prepared_slice_assembly_does_not_rehash_roots() {
        let fixture = payment_fixture_with_slice_bits(4);
        let prepared = prepare_close_with_strategy::<CountingHasher, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.close.rows.clone(),
            fixture.close.shard_sets.clone(),
            &Sequential,
        )
        .unwrap();

        HASH_CALLS.store(0, Ordering::Relaxed);
        let slices = prepared
            .assemble_slices(&fixture.cache, &Sequential)
            .unwrap();
        assert!(!slices.is_empty());
        assert_eq!(HASH_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn proof_slice_rejects_omission_shifted_bounds_and_wrong_index() {
        let fixture = payment_fixture_with_slice_bits(4);
        validate_close::<Sha256, _, _>(
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
        )
        .unwrap();
        let slices = assemble_slices::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            &fixture.close,
            &Sequential,
        )
        .unwrap();
        let member = slices
            .iter()
            .find(|slice| !slice.changes.rows.is_empty())
            .unwrap();

        let mut omitted = member.clone();
        omitted.changes.rows.remove(0);
        omitted.shard_sets.remove(0);
        assert!(
            validate_slice::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close.header,
                &fixture.close.roots,
                &omitted,
            )
            .is_err()
        );

        let mut shifted = member.clone();
        shifted.predecessor.opening.start = shifted.predecessor.opening.start.saturating_add(1);
        assert!(
            validate_slice::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close.header,
                &fixture.close.roots,
                &shifted,
            )
            .is_err()
        );

        let mut wrong_index = member.clone();
        wrong_index.index = (wrong_index.index + 1) % fixture.context.assignment().slice_count();
        assert!(
            validate_slice::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close.header,
                &fixture.close.roots,
                &wrong_index,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_state_has_every_canonical_empty_slice() {
        let operator = SigningKey::from_seed(23);
        let cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(Vec::new()).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"deployment"]),
            1,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(3),
        )
        .unwrap();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
        let slices = assemble_slices::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        assert_eq!(slices.len(), 8);
        for slice in &slices {
            assert!(slice.changes.rows.is_empty());
            assert!(slice.unchanged.is_empty());
            validate_slice::<Sha256, _, _>(
                &context,
                &deposits,
                &withdrawals,
                &close.header,
                &close.roots,
                slice,
            )
            .unwrap();
        }
    }

    #[test]
    fn admission_enforces_configured_public_close_caps() {
        let fixture = payment_fixture();
        let caps = limits(1, 0, 0);
        assert!(TestClose::decode_cfg(fixture.close.encode(), &caps).is_err());
        let restricted = close_context::<Sha256, _, _>(
            *fixture.context.deployment(),
            fixture.context.payment().epoch(),
            fixture.operator.public_key(),
            &fixture.cache,
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.context.admission_deadline(),
            fixture.context.challenge_deadline(),
            caps,
            *fixture.context.assignment(),
        )
        .unwrap();
        assert!(matches!(
            build_close::<Sha256, _, _>(
                &fixture.cache,
                &restricted,
                &fixture.deposits,
                &fixture.withdrawals,
                fixture.close.rows.clone(),
                fixture.close.shard_sets.clone(),
            ),
            Err(TransitionError::CloseLimit)
        ));
    }

    #[test]
    fn epoch_anchor_binds_committee_and_slice_assignment() {
        let operator = SigningKey::from_seed(69);
        let cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(Vec::new()).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let deployment = Sha256::hash(&[b"assignment-deployment"]);
        let first = close_context::<Sha256, _, _>(
            deployment,
            12,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            99,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"committee-a"]), 8).unwrap(),
        )
        .unwrap();
        let different_committee = close_context::<Sha256, _, _>(
            deployment,
            12,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            99,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"committee-b"]), 8).unwrap(),
        )
        .unwrap();
        let different_partition = close_context::<Sha256, _, _>(
            deployment,
            12,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            99,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"committee-a"]), 7).unwrap(),
        )
        .unwrap();
        let different_admission = close_context::<Sha256, _, _>(
            deployment,
            12,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            98,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"committee-a"]), 8).unwrap(),
        )
        .unwrap();

        assert_ne!(
            first.payment().anchor(),
            different_committee.payment().anchor()
        );
        assert_ne!(
            first.payment().anchor(),
            different_partition.payment().anchor()
        );
        assert_ne!(
            first.payment().anchor(),
            different_admission.payment().anchor()
        );
        assert!(matches!(
            close_context::<Sha256, _, _>(
                deployment,
                12,
                operator.public_key(),
                &cache,
                &deposits,
                &withdrawals,
                100,
                100,
                CloseLimits::protocol_maximum(),
                Assignment::new(Sha256::hash(&[b"committee-a"]), 8).unwrap(),
            ),
            Err(TransitionError::DeadlineOrder)
        ));
        assert!(matches!(
            close_context::<Sha256, _, _>(
                deployment,
                12,
                operator.public_key(),
                &cache,
                &deposits,
                &withdrawals,
                u64::MAX - 1,
                u64::MAX,
                CloseLimits::protocol_maximum(),
                Assignment::new(Sha256::hash(&[b"committee-a"]), 8).unwrap(),
            ),
            Err(TransitionError::DeadlineOrder)
        ));
    }

    #[test]
    fn epoch_anchor_binds_liability_but_not_predecessor_root() {
        let operator = SigningKey::from_seed(70);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let epoch = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"root-independent-anchor"]),
            12,
            operator.public_key(),
            &deposits,
            &withdrawals,
            10,
            99,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"committee"]), 8).unwrap(),
        )
        .unwrap();
        let payment = epoch.payment().clone();
        let wrong_liability = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"root-independent-anchor"]),
            12,
            operator.public_key(),
            &deposits,
            &withdrawals,
            11,
            99,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"committee"]), 8).unwrap(),
        )
        .unwrap();
        assert_ne!(wrong_liability.payment().anchor(), payment.anchor());
        let first_account = SigningKey::from_seed(71).public_key();
        let second_account = SigningKey::from_seed(72).public_key();
        let state = AccountState {
            balance: 10,
            active: true,
            ..AccountState::default()
        };
        let first_cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(vec![StateLeaf {
            account: first_account,
            state,
        }])
        .unwrap();
        let second_cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(vec![StateLeaf {
            account: second_account,
            state,
        }])
        .unwrap();
        assert!(matches!(
            wrong_liability.bind::<Sha256>(&first_cache, &deposits, &withdrawals),
            Err(TransitionError::PredecessorLiability)
        ));
        let first = epoch
            .clone()
            .bind::<Sha256>(&first_cache, &deposits, &withdrawals)
            .unwrap();
        let second = epoch
            .bind::<Sha256>(&second_cache, &deposits, &withdrawals)
            .unwrap();

        assert_ne!(first.predecessor_root(), second.predecessor_root());
        assert_eq!(first.payment(), &payment);
        assert_eq!(second.payment(), &payment);
    }

    #[test]
    fn close_decode_checks_remaining_aggregate_shards_before_reading_next_vector() {
        let fixture = payment_fixture();
        let position = fixture
            .close
            .shard_sets
            .iter()
            .position(|set| !set.heads().is_empty())
            .unwrap();
        let set = &fixture.close.shard_sets[position];
        let encoded_head = set.heads()[0].encode();

        let mut wire = BytesMut::new();
        fixture.close.header.write(&mut wire);
        fixture.close.roots.write(&mut wire);
        Vec::<StateLeaf<VerifyingKey>>::new().write(&mut wire);
        vec![fixture.close.rows[position].clone()].write(&mut wire);
        1_usize.write(&mut wire);
        set.epoch().write(&mut wire);
        set.recipient().write(&mut wire);
        1_usize.write(&mut wire);
        wire.extend_from_slice(&encoded_head);
        wire.extend_from_slice(b"after-over-budget-head");

        let mut reader = wire.freeze();
        assert!(TestClose::read_cfg(&mut reader, &limits(1, 1, 0)).is_err());
        assert!(
            reader.as_ref().starts_with(encoded_head.as_ref()),
            "decoder consumed an over-budget shard-head vector before rejecting its length"
        );
    }

    #[test]
    fn substituted_boundary_batches_do_not_validate_against_other_roots() {
        let operator = SigningKey::from_seed(70);
        let account = SigningKey::from_seed(71);
        let deployment = Sha256::hash(&[b"boundary-deployment"]);
        let authorization_root = Sha256::hash(&[b"boundary-authorization"]);
        let sealed_deposits = DepositBatch::new(vec![
            crate::bajillion::boundary::DepositRecord::new(account.public_key(), 7).unwrap(),
        ])
        .unwrap();
        let sealed_withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            authorization_root,
            Bytes::from_static(b"sealed-destination"),
            amount(2),
            100,
            &account,
        )])
        .unwrap();
        let sealed_deposit_root = sealed_deposits.root::<Sha256>().unwrap();
        let sealed_withdrawal_root = sealed_withdrawals.root::<Sha256>().unwrap();
        let deposits = DepositBatch::new(vec![
            crate::bajillion::boundary::DepositRecord::new(account.public_key(), 9).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            authorization_root,
            Bytes::from_static(b"substituted-destination"),
            amount(4),
            100,
            &account,
        )])
        .unwrap();
        assert_ne!(deposits.root::<Sha256>().unwrap(), sealed_deposit_root);
        assert_ne!(
            withdrawals.root::<Sha256>().unwrap(),
            sealed_withdrawal_root
        );

        let predecessor = state(10);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: predecessor,
        }])
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            13,
            operator.public_key(),
            &cache,
            &sealed_deposits,
            &sealed_withdrawals,
            99,
            100,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
        let mut pairs = vec![(
            AccountRow {
                account: account.public_key(),
                predecessor,
                successor: state(15),
                outgoing: None,
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            shards,
        )];
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets) = pairs.into_iter().unzip();
        assert!(matches!(
            build_close::<Sha256, _, _>(
                &cache,
                &context,
                &deposits,
                &withdrawals,
                rows,
                shard_sets,
            ),
            Err(TransitionError::BoundaryRoot)
        ));
    }

    #[test]
    fn sealed_withdrawals_may_bind_distinct_authorization_roots() {
        let operator = SigningKey::from_seed(74);
        let first = SigningKey::from_seed(75);
        let second = SigningKey::from_seed(76);
        let deployment = Sha256::hash(&[b"mixed-root-deployment"]);
        let mut leaves = vec![
            StateLeaf {
                account: first.public_key(),
                state: state(10),
            },
            StateLeaf {
                account: second.public_key(),
                state: state(10),
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![
            SignedWithdrawal::sign(
                deployment,
                Sha256::hash(&[b"first-finalized-root"]),
                Bytes::from_static(b"first"),
                amount(1),
                100,
                &first,
            ),
            SignedWithdrawal::sign(
                deployment,
                Sha256::hash(&[b"second-finalized-root"]),
                Bytes::from_static(b"second"),
                amount(1),
                100,
                &second,
            ),
        ])
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            16,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            99,
            100,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();

        assert_eq!(
            context.withdrawal_root(),
            &withdrawals.root::<Sha256>().unwrap()
        );
    }

    #[test]
    fn sealing_rejects_zero_net_boundary_without_state_change() {
        let operator = SigningKey::from_seed(72);
        let account = SigningKey::from_seed(73);
        let predecessor = state(10);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: predecessor,
        }])
        .unwrap();
        let deployment = Sha256::hash(&[b"equal-flow-deployment"]);
        let authorization_root = Sha256::hash(&[b"equal-flow-authorization"]);
        let deposits = DepositBatch::new(vec![
            crate::bajillion::boundary::DepositRecord::new(account.public_key(), 5).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            authorization_root,
            Bytes::new(),
            amount(5),
            100,
            &account,
        )])
        .unwrap();
        assert!(matches!(
            close_context::<Sha256, _, _>(
                deployment,
                14,
                operator.public_key(),
                &cache,
                &deposits,
                &withdrawals,
                99,
                100,
                CloseLimits::protocol_maximum(),
                assignment(0),
            ),
            Err(TransitionError::BoundaryNoStateChange)
        ));
    }

    #[test]
    fn sealing_checks_exact_withdrawal_coverage() {
        let operator = SigningKey::from_seed(77);
        let account = SigningKey::from_seed(78);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: state(10),
        }])
        .unwrap();
        let deployment = Sha256::hash(&[b"exact-withdrawal-coverage"]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            cache.root().digest,
            Bytes::new(),
            amount(11),
            100,
            &account,
        )])
        .unwrap();

        assert!(matches!(
            close_context::<Sha256, _, _>(
                deployment,
                17,
                operator.public_key(),
                &cache,
                &deposits,
                &withdrawals,
                99,
                100,
                CloseLimits::protocol_maximum(),
                assignment(0),
            ),
            Err(TransitionError::WithdrawalCoverage)
        ));
    }

    #[test]
    fn challenge_index_builds_present_and_absent_account_evidence() {
        let fixture = payment_fixture();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, &fixture.close).unwrap();
        assert_eq!(index.root(), fixture.close.roots.change);
        let payer = fixture.payment.payer();
        let present = index.account_lookup(&fixture.cache, payer).unwrap();
        let resolved = present
            .resolve::<Sha256>(
                fixture.context.predecessor_root(),
                &fixture.close.roots.change,
                payer,
            )
            .unwrap();
        let payer_row = fixture
            .close
            .rows
            .iter()
            .find(|row| &row.account == payer)
            .unwrap();
        assert_eq!(
            resolved.terminal_debit,
            payer_row.successor.cumulative_debit
        );
        assert_eq!(
            resolved.leaf.as_ref().map(AccountChange::account),
            Some(payer)
        );

        let recipient = fixture.payment.recipient();
        let recipient_position = fixture
            .close
            .rows
            .binary_search_by(|row| row.account.cmp(recipient))
            .unwrap();
        let receipt = fixture.payment.receipt().body();
        let recipient_lookup = index
            .higher_shard_tip_lookup::<Sha256>(
                recipient,
                Some(&fixture.close.shard_sets[recipient_position]),
                receipt.shard(),
            )
            .unwrap();
        let tip = recipient_lookup
            .resolve::<Sha256>(&fixture.close.roots.change, recipient, receipt.shard())
            .unwrap()
            .unwrap();
        assert_eq!(tip.cumulative_credit, receipt.cumulative_shard_credit());
        assert_eq!(tip.index, receipt.index());

        let operator = SigningKey::from_seed(19);
        let dormant = SigningKey::from_seed(20).public_key();
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: dormant.clone(),
            state: state(5),
        }])
        .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"deployment"]),
            3,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            9,
            10,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let index = ChallengeIndex::new::<Sha256>(&context, &close).unwrap();
        let absent = index.account_lookup(&cache, &dormant).unwrap();
        let resolved = absent
            .resolve::<Sha256>(context.predecessor_root(), &close.roots.change, &dormant)
            .unwrap();
        assert_eq!(
            resolved.terminal_debit,
            cache.leaves()[0].state.cumulative_debit
        );
        assert!(resolved.leaf.is_none());
        let absent = index
            .higher_shard_tip_lookup::<Sha256>(&dormant, None, 0)
            .unwrap();
        assert!(
            absent
                .resolve::<Sha256>(&close.roots.change, &dormant, 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unchanged_live_state_close_is_canonical() {
        let (context, deposits, withdrawals, close) = empty_fixture();
        assert!(close.rows.is_empty());
        assert!(close.shard_sets.is_empty());
        assert_eq!(close.unchanged.len(), 1);
        assert_eq!(*context.predecessor_root(), close.roots.successor);
        assert_eq!(close.rows.last().map(|row| row.prefix), None);
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
    }

    #[test]
    fn empty_close_requires_an_unchanged_state_root() {
        let (context, deposits, withdrawals, mut close) = empty_fixture();
        validate_header::<Sha256, _, _>(&context, &close.header, &close.roots).unwrap();

        close.roots.successor.digest = Sha256::hash(&[b"hidden-empty-change"]);
        close.header = Header::new::<Sha256, _>(&context, &close.roots);
        assert!(matches!(
            validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close),
            Err(TransitionError::SuccessorRoot)
        ));
    }

    #[test]
    fn empty_state_has_one_canonical_empty_close() {
        let operator = SigningKey::from_seed(22);
        let cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(Vec::new()).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"deployment"]),
            1,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            8,
            9,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            *context.predecessor_root(),
            commitment::empty_root::<Sha256>(VectorKind::State)
        );
        assert_eq!(*context.predecessor_root(), close.roots.successor);
        assert_eq!(
            close.roots.change,
            commitment::empty_root::<Sha256>(VectorKind::Change)
        );
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
    }

    #[test]
    fn close_rebuilds_complete_live_state_vectors() {
        let operator = SigningKey::from_seed(24);
        let mut leaves = (0..1_024_u64)
            .map(|seed| StateLeaf {
                account: SigningKey::from_seed(1_000 + seed).public_key(),
                state: state(1),
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        HASH_CALLS.store(0, Ordering::Relaxed);
        let cache = StateCache::new::<CountingHasher>(leaves).unwrap();
        let cache_hashes = HASH_CALLS.swap(0, Ordering::Relaxed);

        let account = cache.leaves()[cache.len() / 2].account.clone();
        let deployment = CountingHasher::hash(&[b"deployment"]);
        let deposits = DepositBatch::new(vec![
            crate::bajillion::boundary::DepositRecord::new(account.clone(), 1).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<CountingHasher, _, _>(
            deployment,
            8,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            49,
            50,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let shards = ShardSet::empty(context.payment().epoch(), account.clone());
        let row = AccountRow {
            account,
            predecessor: state(1),
            successor: AccountState {
                balance: 2,
                active: true,
                ..AccountState::default()
            },
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix {
                deposit: 1,
                ..Prefix::default()
            },
        };
        HASH_CALLS.store(0, Ordering::Relaxed);
        let close = build_close::<CountingHasher, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            vec![row],
            vec![shards],
        )
        .unwrap();
        let close_hashes = HASH_CALLS.load(Ordering::Relaxed);
        validate_close::<CountingHasher, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
        HASH_CALLS.store(0, Ordering::Relaxed);
        let slices = assemble_slices::<CountingHasher, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap();
        let slice_hashes = HASH_CALLS.load(Ordering::Relaxed);

        assert!(cache_hashes > 1_024);
        assert!(
            close_hashes > cache_hashes,
            "fresh close used only {close_hashes} hashes after a {cache_hashes}-hash cache build"
        );
        assert_eq!(close.unchanged.len(), 1_023);
        assert_eq!(slices.len(), 1);
        assert!(
            slice_hashes > 1_024,
            "slice assembly did not rebuild the {slice_hashes}-hash successor tree"
        );
    }

    #[test]
    fn zero_balance_payment_removes_account_from_successor_state() {
        let operator = SigningKey::from_seed(25);
        let payer = SigningKey::from_seed(26);
        let recipient = SigningKey::from_seed(27);
        let payer_opening = state(20);
        let recipient_opening = state(5);
        let mut leaves = vec![
            StateLeaf {
                account: payer.public_key(),
                state: payer_opening,
            },
            StateLeaf {
                account: recipient.public_key(),
                state: recipient_opening,
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"zero-balance-payment"]),
            8,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            59,
            60,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let payment = payment(context.payment(), &operator, &payer, &recipient, 20);
        let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment.clone())],
        )
        .unwrap();
        let recipient_successor = AccountState {
            balance: 25,
            cumulative_credit: 20,
            receipt_count: 1,
            active: true,
            ..AccountState::default()
        };
        let mut pairs = vec![
            (
                AccountRow {
                    account: payer.public_key(),
                    predecessor: payer_opening,
                    successor: AccountState {
                        cumulative_debit: 20,
                        ..AccountState::default()
                    },
                    outgoing: Some(payment),
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    predecessor: recipient_opening,
                    successor: recipient_successor,
                    outgoing: None,
                    output: SettlementOutput::None,
                    prefix: Prefix::default(),
                },
                recipient_shards,
            ),
        ];
        pairs.sort_unstable_by(|left, right| left.0.account.cmp(&right.0.account));
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets) = pairs.into_iter().unzip();
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
            &Sequential,
        )
        .unwrap();
        prepared
            .validate::<Sha256>(&context, &deposits, &withdrawals)
            .unwrap();

        assert_eq!(prepared.successor_leaves.len(), 1);
        assert_eq!(prepared.successor_leaves[0].account, recipient.public_key());
        assert_eq!(prepared.successor_leaves[0].state, recipient_successor);
        assert!(
            prepared
                .successor_leaves
                .iter()
                .all(|leaf| leaf.state.balance > 0)
        );
    }

    #[test]
    fn close_sweeps_predecessor_balance_and_deactivates() {
        let operator = SigningKey::from_seed(30);
        let account = SigningKey::from_seed(31);
        let predecessor = state(10);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: predecessor,
        }])
        .unwrap();
        let deployment = Sha256::hash(&[b"deployment"]);
        let withdrawal_root = Sha256::hash(&[b"finalized-withdrawal-root"]);
        let deposits = DepositBatch::empty();
        let request = SignedWithdrawal::sign(
            deployment,
            withdrawal_root,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            &account,
        );
        let withdrawals = WithdrawalBatch::new(vec![request]).unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            9,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            79,
            80,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
        let mut pairs = vec![(
            AccountRow {
                account: account.public_key(),
                predecessor,
                successor: AccountState {
                    balance: 0,
                    active: false,
                    ..predecessor
                },
                outgoing: None,
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            shards,
        )];
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets) = pairs.into_iter().unzip();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
        )
        .unwrap();

        let mut restricted_limits = CloseLimits::protocol_maximum();
        restricted_limits.max_withdrawal_total = 9;
        let restricted_context = close_context::<Sha256, _, _>(
            deployment,
            9,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            79,
            80,
            restricted_limits,
            assignment(0),
        )
        .unwrap();
        assert!(matches!(
            build_close::<Sha256, _, _>(
                &cache,
                &restricted_context,
                &deposits,
                &withdrawals,
                close.rows.clone(),
                close.shard_sets.clone(),
            ),
            Err(TransitionError::CloseLimit)
        ));

        assert_eq!(withdrawals.total(), 0);
        assert_eq!(close.rows.last().unwrap().prefix.withdrawal, 10);
        assert_eq!(
            checked_successor_liability(context.predecessor_liability(), 0, 10, 0).unwrap(),
            0
        );
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &account.public_key(),
            &Sequential,
        )
        .unwrap();
        let expected = withdrawal_output(b"destination", 10);
        assert_eq!(claim.output(), &expected);
        assert_eq!(claim.position(), 0);
        assert_eq!(
            claim
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap(),
            expected
        );

        let mut wrong_destination = claim.clone();
        wrong_destination.output.destination = Bytes::from_static(b"wrong-destination");
        assert!(matches!(
            wrong_destination.verify::<Sha256>(&close.roots.withdrawal_outputs),
            Err(TransitionError::Commitment(_))
        ));

        let mut wrong_amount = claim.clone();
        wrong_amount.output.amount = 9;
        assert!(matches!(
            wrong_amount.verify::<Sha256>(&close.roots.withdrawal_outputs),
            Err(TransitionError::Commitment(_))
        ));

        let mut wrong_root = close.roots.withdrawal_outputs;
        wrong_root.digest = Sha256::hash(&[b"wrong-withdrawal-output-root"]);
        assert!(matches!(
            claim.verify::<Sha256>(&wrong_root),
            Err(TransitionError::Commitment(_))
        ));

        let amount_request = SignedWithdrawal::sign(
            deployment,
            withdrawal_root,
            Bytes::from_static(b"destination"),
            amount(10),
            100,
            &account,
        );
        assert_eq!(
            WithdrawalOutput::from_request(&amount_request, 10),
            claim.output().clone()
        );

        let decoded =
            WithdrawalClaim::<ShaDigest>::decode_cfg(claim.encode(), &(..=usize::MAX).into())
                .unwrap();
        assert_eq!(decoded, claim);
    }

    #[test]
    fn withdrawal_claim_opens_compact_epoch_tail_output() {
        let operator = SigningKey::from_seed(34);
        let mut accounts = [SigningKey::from_seed(35), SigningKey::from_seed(36)];
        accounts.sort_by_key(SigningKey::public_key);
        let cache = StateCache::new::<Sha256>(
            accounts
                .iter()
                .enumerate()
                .map(|(index, account)| StateLeaf {
                    account: account.public_key(),
                    state: state(10 + index as u64),
                })
                .collect(),
        )
        .unwrap();
        let deployment = Sha256::hash(&[b"withdrawal-claim-compact-output"]);
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(accounts[1].public_key(), 7).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::new(
            accounts
                .iter()
                .map(|account| {
                    SignedWithdrawal::sign(
                        deployment,
                        cache.root().digest,
                        Bytes::from_static(b"destination"),
                        WithdrawalAction::Close,
                        100,
                        account,
                    )
                })
                .collect(),
        )
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            10,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            79,
            80,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let mut pairs = cache
            .leaves()
            .iter()
            .map(|leaf| {
                let shards = ShardSet::empty(context.payment().epoch(), leaf.account.clone());
                (
                    AccountRow {
                        account: leaf.account.clone(),
                        predecessor: leaf.state,
                        successor: AccountState {
                            balance: 0,
                            active: false,
                            ..leaf.state
                        },
                        outgoing: None,
                        output: SettlementOutput::None,
                        prefix: Prefix::default(),
                    },
                    shards,
                )
            })
            .collect::<Vec<_>>();
        assign_prefixes(&mut pairs, &deposits, &withdrawals);
        let (rows, shard_sets) = pairs.into_iter().unzip();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            rows,
            shard_sets,
        )
        .unwrap();

        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &accounts[1].public_key(),
            &Sequential,
        )
        .unwrap();
        let one_opening = claim.output_opening.encode_size();
        let expected = withdrawal_output(b"destination", 18);
        assert_eq!(claim.output(), &expected);
        assert_eq!(claim.position(), 1);
        assert_eq!(
            claim.encode_size(),
            claim.output.encode_size() + one_opening
        );
        assert_eq!(
            claim
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap(),
            expected
        );
        let mut wrong_position = claim;
        wrong_position.output_opening.position = 0;
        assert!(matches!(
            wrong_position.verify::<Sha256>(&close.roots.withdrawal_outputs),
            Err(TransitionError::Commitment(_))
        ));

        let mut slice = assemble_slices::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            &close,
            &Sequential,
        )
        .unwrap()
        .pop()
        .unwrap();
        let mut outputs = derive_withdrawal_outputs(&close.rows, &withdrawals).unwrap();
        outputs.push(outputs[0].clone());
        let mut builder = commitment::Builder::<Sha256>::new(
            VectorKind::WithdrawalOutput,
            u32::try_from(outputs.len()).unwrap(),
        )
        .unwrap();
        builder.add_values(&outputs, &Sequential).unwrap();
        let extended = builder.build(&Sequential).unwrap();
        let mut roots = close.roots;
        roots.withdrawal_outputs = extended.root();
        let header = Header::new::<Sha256, _>(&context, &roots);
        slice.withdrawal_outputs.opening = Some(extended.range_opening(0, 2).unwrap());
        assert!(matches!(
            validate_slice::<Sha256, _, _>(
                &context,
                &deposits,
                &withdrawals,
                &header,
                &roots,
                &slice,
            ),
            Err(TransitionError::SliceRange)
        ));
    }

    #[test]
    fn amount_and_close_have_the_same_compact_withdrawal_output_shape() {
        let account = SigningKey::from_seed(39);
        let deployment = Sha256::hash(&[b"compact-withdrawal-action-shape"]);
        let state_root = Sha256::hash(&[b"compact-withdrawal-action-state"]);
        let amount_request = SignedWithdrawal::sign(
            deployment,
            state_root,
            Bytes::from_static(b"destination"),
            amount(7),
            100,
            &account,
        );
        let close_request = SignedWithdrawal::sign(
            deployment,
            state_root,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            &account,
        );

        let amount_output = WithdrawalOutput::from_request(&amount_request, 7);
        let close_output = WithdrawalOutput::from_request(&close_request, 7);
        assert_eq!(amount_output, close_output);
        assert_eq!(amount_output.encode(), close_output.encode());
    }

    #[test]
    fn withdrawal_claim_encoding_grows_logarithmically() {
        let output = withdrawal_output(b"opaque-destination-21", 7);
        assert_eq!(output.destination().len(), 21);
        let mut previous_size = None;

        for exponent in 0..=10 {
            let count = 1_u32 << exponent;
            let outputs = vec![output.clone(); usize::try_from(count).unwrap()];
            let mut builder =
                commitment::Builder::<Sha256>::new(VectorKind::WithdrawalOutput, count).unwrap();
            builder.add_values(&outputs, &Sequential).unwrap();
            let tree = builder.build(&Sequential).unwrap();
            let claim = WithdrawalClaim {
                output: output.clone(),
                output_opening: tree.opening(count - 1).unwrap(),
            };

            assert_eq!(claim.position(), count - 1);
            assert_eq!(
                claim.verify::<Sha256>(&tree.root()).unwrap(),
                output.clone()
            );
            if exponent == 0 {
                assert_eq!(claim.encode_size(), 39);
            }
            if let Some(previous_size) = previous_size {
                assert_eq!(claim.encode_size() - previous_size, ShaDigest::SIZE);
            }
            previous_size = Some(claim.encode_size());
        }
    }

    #[test]
    fn withdrawal_claim_supports_deposit_funded_absent_account() {
        let operator = SigningKey::from_seed(37);
        let account = SigningKey::from_seed(38);
        let cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(Vec::new()).unwrap();
        let deployment = Sha256::hash(&[b"deposit-funded-withdrawal-claim"]);
        let deposits =
            DepositBatch::new(vec![DepositRecord::new(account.public_key(), 9).unwrap()]).unwrap();
        let request = SignedWithdrawal::sign(
            deployment,
            cache.root().digest,
            Bytes::from_static(b"destination"),
            amount(4),
            100,
            &account,
        );
        let withdrawals = WithdrawalBatch::new(vec![request]).unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            11,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            79,
            80,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            vec![AccountRow {
                account: account.public_key(),
                predecessor: AccountState::default(),
                successor: state(5),
                outgoing: None,
                output: SettlementOutput::Withdrawal(4),
                prefix: Prefix {
                    deposit: 9,
                    withdrawal: 4,
                    withdrawal_count: 1,
                    ..Prefix::default()
                },
            }],
            vec![shards],
        )
        .unwrap();
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &account.public_key(),
            &Sequential,
        )
        .unwrap();
        let expected = withdrawal_output(b"destination", 4);
        assert_eq!(claim.output(), &expected);
        assert_eq!(
            claim
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap(),
            expected
        );
        assert_eq!(
            claim.encode_size(),
            claim.output.encode_size() + claim.output_opening.encode_size()
        );
    }

    #[test]
    fn deposit_activation_and_zero_balance_close_are_exact_changes() {
        let operator = SigningKey::from_seed(32);
        let account = SigningKey::from_seed(33);
        let cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(Vec::new()).unwrap();
        let deployment = Sha256::hash(&[b"deployment"]);
        let deposits = DepositBatch::new(vec![
            crate::bajillion::boundary::DepositRecord::new(account.public_key(), 5).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            deployment,
            12,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            89,
            90,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
        let row = AccountRow {
            account: account.public_key(),
            predecessor: AccountState::default(),
            successor: AccountState {
                balance: 5,
                active: true,
                ..AccountState::default()
            },
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix {
                deposit: 5,
                ..Prefix::default()
            },
        };
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            vec![row],
            vec![shards],
        )
        .unwrap();
        assert!(close.rows[0].successor.active);
        assert!(close.unchanged.is_empty());
        assert_ne!(*context.predecessor_root(), close.roots.successor);
        assert_eq!(
            checked_successor_liability(context.predecessor_liability(), 5, 0, 0).unwrap(),
            5
        );

        let predecessor = state(5);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: predecessor,
        }])
        .unwrap();
        let authorization_root = Sha256::hash(&[b"finalized"]);
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            authorization_root,
            Bytes::new(),
            WithdrawalAction::Close,
            100,
            &account,
        )])
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            deployment,
            12,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            89,
            90,
            CloseLimits::protocol_maximum(),
            assignment(0),
        )
        .unwrap();
        let shards = ShardSet::empty(context.payment().epoch(), account.public_key());
        let row = AccountRow {
            account: account.public_key(),
            predecessor,
            successor: AccountState::default(),
            outgoing: None,
            output: SettlementOutput::Withdrawal(5),
            prefix: Prefix {
                withdrawal: 5,
                withdrawal_count: 1,
                ..Prefix::default()
            },
        };
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            vec![row],
            vec![shards],
        )
        .unwrap();
        assert!(!close.rows[0].successor.active);
        assert!(close.rows[0].is_changed());
        assert!(close.unchanged.is_empty());
        assert_eq!(
            close.roots.successor,
            commitment::empty_root::<Sha256>(VectorKind::State)
        );
    }

    #[test]
    fn close_sweeps_the_tail_after_payment_activity() {
        let mut fixture = payment_fixture();
        let authorization_root = Sha256::hash(&[b"close-authorization"]);
        let recipient_account = SigningKey::from_seed(3);
        let withdrawals = WithdrawalBatch::new(
            [&fixture.payer, &recipient_account]
                .into_iter()
                .map(|account| {
                    SignedWithdrawal::sign(
                        *fixture.context.deployment(),
                        authorization_root,
                        Bytes::from_static(b"destination"),
                        WithdrawalAction::Close,
                        100,
                        account,
                    )
                })
                .collect(),
        )
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            *fixture.context.deployment(),
            7,
            fixture.operator.public_key(),
            &fixture.cache,
            &fixture.deposits,
            &withdrawals,
            98,
            99,
            CloseLimits::protocol_maximum(),
            *fixture.context.assignment(),
        )
        .unwrap();
        let payment = payment(
            context.payment(),
            &fixture.operator,
            &fixture.payer,
            &recipient_account,
            20,
        );
        let payer_position = fixture
            .close
            .rows
            .binary_search_by(|row| row.account.cmp(&fixture.payer.public_key()))
            .unwrap();
        fixture.close.rows[payer_position].outgoing = Some(payment.clone());
        fixture.close.rows[payer_position].successor.balance = 0;
        fixture.close.rows[payer_position].successor.active = false;
        let recipient_position = fixture
            .close
            .rows
            .binary_search_by(|row| row.account.cmp(&recipient_account.public_key()))
            .unwrap();
        fixture.close.shard_sets[recipient_position] = ShardSet::new(
            context.payment().epoch(),
            fixture.close.rows[recipient_position].account.clone(),
            vec![ShardHead::new(0, payment)],
        )
        .unwrap();
        fixture.close.rows[recipient_position].successor.balance = 0;
        fixture.close.rows[recipient_position].successor.active = false;
        let mut pairs = fixture
            .close
            .rows
            .clone()
            .into_iter()
            .zip(fixture.close.shard_sets)
            .collect::<Vec<_>>();
        assign_prefixes(&mut pairs, &fixture.deposits, &withdrawals);
        let (rows, shard_sets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();

        let close = build_close::<Sha256, _, _>(
            &fixture.cache,
            &context,
            &fixture.deposits,
            &withdrawals,
            rows,
            shard_sets,
        )
        .unwrap();
        assert_eq!(close.rows.last().unwrap().prefix.withdrawal, 140);
        assert_eq!(close.rows.last().unwrap().prefix.debit, 20);
        assert_eq!(close.rows.last().unwrap().prefix.credit, 20);
        assert_eq!(
            close.roots.successor,
            commitment::empty_root::<Sha256>(VectorKind::State)
        );

        let payer_claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &fixture.payer.public_key(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(
            payer_claim
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap(),
            withdrawal_output(b"destination", 80)
        );
        let recipient_claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &recipient_account.public_key(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(
            recipient_claim
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap(),
            withdrawal_output(b"destination", 60)
        );
    }

    #[test]
    fn close_may_release_zero_after_exact_debit() {
        let mut fixture = payment_fixture();
        let recipient = SigningKey::from_seed(3);
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            *fixture.context.deployment(),
            Sha256::hash(&[b"zero-tail-authorization"]),
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            &fixture.payer,
        )])
        .unwrap();
        let context = close_context::<Sha256, _, _>(
            *fixture.context.deployment(),
            7,
            fixture.operator.public_key(),
            &fixture.cache,
            &fixture.deposits,
            &withdrawals,
            98,
            99,
            CloseLimits::protocol_maximum(),
            *fixture.context.assignment(),
        )
        .unwrap();
        let payment = payment(
            context.payment(),
            &fixture.operator,
            &fixture.payer,
            &recipient,
            100,
        );
        let payer_position = fixture
            .close
            .rows
            .binary_search_by(|row| row.account.cmp(&fixture.payer.public_key()))
            .unwrap();
        fixture.close.rows[payer_position].successor.balance = 0;
        fixture.close.rows[payer_position]
            .successor
            .cumulative_debit = 100;
        fixture.close.rows[payer_position].successor.active = false;
        fixture.close.rows[payer_position].outgoing = Some(payment.clone());
        let recipient_position = fixture
            .close
            .rows
            .binary_search_by(|row| row.account.cmp(&recipient.public_key()))
            .unwrap();
        fixture.close.rows[recipient_position].successor.balance = 140;
        fixture.close.rows[recipient_position]
            .successor
            .cumulative_credit = 100;
        fixture.close.rows[recipient_position]
            .successor
            .receipt_count = 1;
        fixture.close.shard_sets[recipient_position] = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment)],
        )
        .unwrap();
        let mut pairs = fixture
            .close
            .rows
            .into_iter()
            .zip(fixture.close.shard_sets)
            .collect::<Vec<_>>();
        assign_prefixes(&mut pairs, &fixture.deposits, &withdrawals);
        let (rows, shard_sets) = pairs.into_iter().unzip();
        let close = build_close::<Sha256, _, _>(
            &fixture.cache,
            &context,
            &fixture.deposits,
            &withdrawals,
            rows,
            shard_sets,
        )
        .unwrap();

        assert_eq!(close.rows.last().unwrap().prefix.withdrawal, 0);
        assert_eq!(close.rows.last().unwrap().prefix.withdrawal_count, 1);
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &fixture.payer.public_key(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(
            claim
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap(),
            withdrawal_output(b"destination", 0)
        );
    }

    #[test]
    fn mismatched_successor_root_is_rejected() {
        let (context, deposits, withdrawals, mut close) = empty_fixture();
        close.roots.successor.digest = Sha256::hash(&[b"hidden"]);
        close.header = Header::new::<Sha256, _>(&context, &close.roots);
        assert!(matches!(
            validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close),
            Err(TransitionError::SuccessorRoot)
        ));
    }

    #[test]
    fn broken_prefix_and_balance_equation_are_rejected() {
        let mut fixture = payment_fixture();
        fixture.close.rows[0].prefix.debit =
            fixture.close.rows[0].prefix.debit.checked_add(1).unwrap();
        rebind_state(&fixture.context, &mut fixture.close);
        assert!(matches!(
            validate_close::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close,
            ),
            Err(TransitionError::Prefix)
        ));

        let mut fixture = payment_fixture();
        fixture.close.rows[0].successor.balance += 1;
        assert!(matches!(
            validate_row::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close.rows[0],
                &fixture.close.shard_sets[0],
            ),
            Err(TransitionError::BalanceEquation)
        ));
        rebind_state(&fixture.context, &mut fixture.close);
        assert!(
            validate_close::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close,
            )
            .is_err()
        );
    }

    #[test]
    fn settlement_output_is_derived_from_the_validated_row() {
        let fixture = payment_fixture();
        let mut rows = fixture.close.rows.clone();
        rows[0].output = SettlementOutput::Withdrawal(1);
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &fixture.cache,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            rows,
            fixture.close.shard_sets.clone(),
            &Sequential,
        )
        .unwrap();

        assert!(matches!(
            prepared.validate::<Sha256>(&fixture.context, &fixture.deposits, &fixture.withdrawals,),
            Err(TransitionError::SettlementOutput)
        ));
    }

    #[test]
    fn broken_signature_and_row_order_are_rejected() {
        let mut fixture = payment_fixture();
        let payer = fixture
            .close
            .rows
            .iter()
            .position(|row| row.outgoing.is_some())
            .unwrap();
        let original = fixture.close.rows[payer].outgoing.as_ref().unwrap();
        let invalid_send = SignedSend::sign_body_by_authority(
            original.send().body().clone(),
            &SigningKey::from_seed(999),
        );
        fixture.close.rows[payer].outgoing = Some(Payment::from_parts_unchecked(
            invalid_send,
            original.receipt().clone(),
        ));
        rebind_state(&fixture.context, &mut fixture.close);
        assert!(matches!(
            validate_close::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close,
            ),
            Err(TransitionError::Payment(
                PaymentError::InvalidPayerSignature
            ))
        ));

        let mut fixture = payment_fixture();
        fixture.close.rows.swap(0, 1);
        fixture.close.shard_sets.swap(0, 1);
        assert!(matches!(
            validate_close::<Sha256, _, _>(
                &fixture.context,
                &fixture.deposits,
                &fixture.withdrawals,
                &fixture.close,
            ),
            Err(TransitionError::NonCanonicalRows)
        ));
    }

    #[test]
    fn liability_overflow_is_rejected_at_cache_construction() {
        let a = SigningKey::from_seed(40).public_key();
        let b = SigningKey::from_seed(41).public_key();
        let mut leaves = vec![
            StateLeaf {
                account: a,
                state: state(u64::MAX),
            },
            StateLeaf {
                account: b,
                state: state(1),
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        assert!(matches!(
            StateCache::new::<Sha256>(leaves),
            Err(TransitionError::LiabilityOverflow)
        ));

        assert!(matches!(
            StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(vec![StateLeaf {
                account: SigningKey::from_seed(42).public_key(),
                state: AccountState {
                    balance: 1,
                    ..AccountState::default()
                },
            }]),
            Err(TransitionError::InactiveBalance)
        ));
    }

    #[test]
    fn live_state_merge_supports_creation_and_destruction() {
        let mut accounts = (100..103)
            .map(|seed| SigningKey::from_seed(seed).public_key())
            .collect::<Vec<_>>();
        accounts.sort_unstable();

        let predecessor = vec![
            StateLeaf {
                account: accounts[0].clone(),
                state: state(10),
            },
            StateLeaf {
                account: accounts[1].clone(),
                state: state(20),
            },
        ];
        let row = |account: VerifyingKey,
                   predecessor,
                   successor|
         -> AccountRow<VerifyingKey, ShaDigest> {
            AccountRow {
                account,
                predecessor,
                successor,
                outgoing: None,
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            }
        };
        let rows = vec![
            row(accounts[0].clone(), state(10), AccountState::default()),
            row(accounts[2].clone(), AccountState::default(), state(30)),
        ];

        let unchanged = derive_unchanged(&predecessor, &rows).unwrap();
        assert_eq!(unchanged, vec![predecessor[1].clone()]);
        let (derived_predecessor, successor) = derive_state_vectors(&unchanged, &rows, 3).unwrap();
        assert_eq!(derived_predecessor, predecessor);
        assert_eq!(
            successor,
            vec![
                StateLeaf {
                    account: accounts[1].clone(),
                    state: state(20),
                },
                StateLeaf {
                    account: accounts[2].clone(),
                    state: state(30),
                },
            ]
        );
    }
}
