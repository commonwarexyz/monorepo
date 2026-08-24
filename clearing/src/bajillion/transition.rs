//! Stateless close assembly and validation.

use crate::bajillion::{
    boundary::{
        BoundaryError, Deadline, DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
    },
    challenge::{AccountLookup, RowOpening, StateLookup, StateOpening},
    commitment::{self, Tree, VectorKind, VectorRoot},
    credit::{self, ShardHead, ShardSet},
    payment::{PaymentContext, PaymentError},
    state::{AccountRow, Prefix, StateLeaf},
};
use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use thiserror::Error;

mod slice;
pub use slice::{
    ChangeRange, LayoutRange, ProofSlice, SliceBoundary, SliceCodecConfig, StateRange,
    assemble_slices, decode_slice_bounded, validate_slice,
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

/// The state, change, and slice-layout roots authenticated by one close header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RootBundle<D: Digest> {
    /// Complete opening account-state vector.
    pub opening: VectorRoot<D>,
    /// Exact sorted changed-account vector.
    pub change: VectorRoot<D>,
    /// Complete closing account-state vector.
    pub closing: VectorRoot<D>,
    /// Gap-free positional boundaries for every deterministic proof slice.
    pub layout: VectorRoot<D>,
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for RootBundle<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            opening: u.arbitrary()?,
            change: u.arbitrary()?,
            closing: u.arbitrary()?,
            layout: u.arbitrary()?,
        })
    }
}

impl<D: Digest> Write for RootBundle<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.opening.write(writer);
        self.change.write(writer);
        self.closing.write(writer);
        self.layout.write(writer);
    }
}

impl<D: Digest> FixedSize for RootBundle<D> {
    const SIZE: usize = VectorRoot::<D>::SIZE * 4;
}

impl<D: Digest> Read for RootBundle<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            opening: VectorRoot::read(reader)?,
            change: VectorRoot::read(reader)?,
            closing: VectorRoot::read(reader)?,
            layout: VectorRoot::read(reader)?,
        })
    }
}

/// Context-bound digest committing to one [`RootBundle`].
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Header<D: Digest>(D);

impl<D: Digest> Header<D> {
    /// Commits to the exact root roles under one authenticated payment context.
    pub fn new<H, P>(context: &PaymentContext<P, D>, roots: &RootBundle<D>) -> Self
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
    {
        let context = context.encode();
        Self(H::hash(&[
            HEADER_ROOT_HASH_NAMESPACE,
            context.as_ref(),
            roots.opening.digest.as_ref(),
            roots.change.digest.as_ref(),
            roots.closing.digest.as_ref(),
            roots.layout.digest.as_ref(),
        ]))
    }

    /// Returns whether `roots` are the unique contextual opening of this header.
    pub fn verify<H, P>(&self, context: &PaymentContext<P, D>, roots: &RootBundle<D>) -> bool
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

    /// Returns the gross payment limit applied independently to debit and credit.
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

/// Root-independent registration shared by every payment in one epoch.
///
/// The settlement chain binds this registration to exactly one opening state when the close is
/// registered. An embedding must never reuse the registration after its ancestry is invalidated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochContext<P: PublicKey, D: Digest> {
    payment: PaymentContext<P, D>,
    deployment: D,
    deposit_root: VectorRoot<D>,
    withdrawal_root: VectorRoot<D>,
    opening_liability: u64,
    admission_deadline: Deadline,
    challenge_deadline: Deadline,
    limits: CloseLimits,
    assignment: Assignment<D>,
}

impl<P: PublicKey, D: Digest> EpochContext<P, D> {
    /// Authenticates the immutable payment, boundary, and validation parameters for one epoch.
    ///
    /// Admission must precede the challenge deadline, and the challenge deadline must leave one
    /// representable later timestamp for finalization or expiry. The opening liability remains
    /// authenticated, but the exact opening root is excluded so successor payments can begin while
    /// the predecessor state root is constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn new<H: Hasher<Digest = D>>(
        deployment: D,
        epoch: u64,
        operator: P,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
        opening_liability: u64,
        admission_deadline: Deadline,
        challenge_deadline: Deadline,
        limits: CloseLimits,
        assignment: Assignment<D>,
    ) -> Result<Self, TransitionError> {
        if admission_deadline >= challenge_deadline || challenge_deadline == u64::MAX {
            return Err(TransitionError::DeadlineOrder);
        }
        validated_boundary_accounts(&deployment, deposits, withdrawals, &limits)?;

        let deposit_root = deposits.root::<H>()?;
        let withdrawal_root = withdrawals.root::<H>()?;
        let deposit_root_encoded = deposit_root.encode();
        let withdrawal_root_encoded = withdrawal_root.encode();
        let opening_liability_encoded = opening_liability.to_be_bytes();
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
            &opening_liability_encoded,
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
            opening_liability,
            admission_deadline,
            challenge_deadline,
            limits,
            assignment,
        })
    }

    /// Binds this epoch registration to one exact opening state.
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
        if cache.liability() != self.opening_liability {
            return Err(TransitionError::OpeningLiability);
        }
        validate_sealed_boundaries(cache, &self.deployment, deposits, withdrawals, &self.limits)?;
        Ok(CloseContext {
            epoch: self,
            opening_root: cache.root(),
        })
    }

    /// Binds the root already owned by the settlement state machine.
    ///
    /// Boundary affordability is established when deposits and withdrawals enter settlement
    /// state. Callers outside that owner must use [`Self::bind`] with the complete state cache.
    pub(crate) const fn bind_settlement_root(
        self,
        opening_root: VectorRoot<D>,
    ) -> CloseContext<P, D> {
        CloseContext {
            epoch: self,
            opening_root,
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

    /// Returns the authenticated opening liability.
    pub const fn opening_liability(&self) -> u64 {
        self.opening_liability
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

/// Chain-known epoch registration bound to one exact opening state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseContext<P: PublicKey, D: Digest> {
    epoch: EpochContext<P, D>,
    opening_root: VectorRoot<D>,
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

    /// Returns the bound opening state root.
    pub const fn opening_root(&self) -> &VectorRoot<D> {
        &self.opening_root
    }

    /// Returns the authenticated opening liability.
    pub const fn opening_liability(&self) -> u64 {
        self.epoch.opening_liability()
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
    /// Returns the authenticated terminal layout boundary.
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

/// One claim for net credit classified as an external payout by adjacent cumulative prefixes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPayoutClaim<P: PublicKey, D: Digest> {
    predecessor: Option<AccountRow<P, D>>,
    row: AccountRow<P, D>,
    change_opening: commitment::MultiOpening<D>,
}

impl<P: PublicKey, D: Digest> ExternalPayoutClaim<P, D> {
    /// Returns the claimed change-vector position.
    #[must_use]
    pub fn position(&self) -> u32 {
        self.change_opening
            .positions
            .last()
            .copied()
            .unwrap_or_default()
    }

    /// Returns the authenticated changed-account row.
    #[must_use]
    pub const fn row(&self) -> &AccountRow<P, D> {
        &self.row
    }

    /// Verifies this claim against an already authenticated finalized change root.
    ///
    /// The row and its predecessor, when present, must authenticate an exact positive payout
    /// prefix delta. Credit assigned to a deposit or withdrawal cannot satisfy this claim.
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
        let previous_prefix = adjacent_change_prefix(
            self.predecessor.as_ref(),
            &self.row,
            &self.change_opening.positions,
        )
        .ok_or(TransitionError::PayoutClaim)?;
        match &self.predecessor {
            Some(predecessor) => {
                let predecessor_encoded = predecessor.encode();
                let row_encoded = self.row.encode();
                self.change_opening.verify::<H, _>(
                    VectorKind::Change,
                    change_root,
                    &[predecessor_encoded.as_ref(), row_encoded.as_ref()],
                )?;
            }
            None => self.change_opening.verify::<H, _>(
                VectorKind::Change,
                change_root,
                &[self.row.encode()],
            )?,
        }

        validate_row_state_sides(&self.row)?;
        let amount = external_payout_amount(&self.row, previous_prefix)
            .ok_or(TransitionError::PayoutClaim)?;
        Ok(ExternalPayout {
            recipient: self.row.account.clone(),
            amount,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for ExternalPayoutClaim<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.predecessor.write(writer);
        self.row.write(writer);
        self.change_opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ExternalPayoutClaim<P, D> {
    fn encode_size(&self) -> usize {
        self.predecessor.encode_size() + self.row.encode_size() + self.change_opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for ExternalPayoutClaim<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let claim = Self {
            predecessor: Option::<AccountRow<P, D>>::read(reader)?,
            row: AccountRow::read(reader)?,
            change_opening: commitment::MultiOpening::read_bounded(reader, 2)?,
        };
        adjacent_change_prefix(
            claim.predecessor.as_ref(),
            &claim.row,
            &claim.change_opening.positions,
        )
        .ok_or(CodecError::Invalid(
            "ExternalPayoutClaim",
            "change rows and positions are not adjacent",
        ))?;
        Ok(claim)
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ExternalPayoutClaim<P, D>
where
    P: PublicKey,
    D: Digest,
    AccountRow<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::MultiOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            predecessor: u.arbitrary()?,
            row: u.arbitrary()?,
            change_opening: u.arbitrary()?,
        })
    }
}

/// One claim for a signed withdrawal included in a finalized close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalClaim<P: PublicKey, D: Digest> {
    request: SignedWithdrawal<P, D>,
    withdrawal_opening: commitment::Opening<D>,
    predecessor: Option<AccountRow<P, D>>,
    row: AccountRow<P, D>,
    change_opening: commitment::MultiOpening<D>,
}

impl<P: PublicKey, D: Digest> WithdrawalClaim<P, D> {
    /// Returns the signed withdrawal authorization.
    #[must_use]
    pub const fn request(&self) -> &SignedWithdrawal<P, D> {
        &self.request
    }

    /// Returns the request's canonical withdrawal-vector position.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.withdrawal_opening.position
    }

    /// Verifies the request and derives its exact release from finalized vector openings.
    pub fn verify<H>(
        &self,
        deployment: &D,
        withdrawal_root: &VectorRoot<D>,
        change_root: &VectorRoot<D>,
    ) -> Result<u64, TransitionError>
    where
        H: Hasher<Digest = D>,
    {
        self.request.verify_deployment(deployment)?;
        if self.request.account() != &self.row.account {
            return Err(TransitionError::WithdrawalClaim);
        }
        self.withdrawal_opening.verify::<H>(
            VectorKind::Withdrawal,
            withdrawal_root,
            self.request.encode().as_ref(),
        )?;

        let previous_prefix = adjacent_change_prefix(
            self.predecessor.as_ref(),
            &self.row,
            &self.change_opening.positions,
        )
        .ok_or(TransitionError::WithdrawalClaim)?;
        match &self.predecessor {
            Some(predecessor) => {
                let predecessor_encoded = predecessor.encode();
                let row_encoded = self.row.encode();
                self.change_opening.verify::<H, _>(
                    VectorKind::Change,
                    change_root,
                    &[predecessor_encoded.as_ref(), row_encoded.as_ref()],
                )?;
            }
            None => {
                self.change_opening.verify::<H, _>(
                    VectorKind::Change,
                    change_root,
                    &[self.row.encode()],
                )?;
            }
        }

        validate_row_state_sides(&self.row)?;
        let delta = checked_prefix_delta(self.row.prefix, previous_prefix)
            .ok_or(TransitionError::WithdrawalClaim)?;
        let (debit, credit, receipts) = self
            .row
            .checked_deltas()
            .ok_or(TransitionError::WithdrawalClaim)?;
        let amount = delta.withdrawal;
        if (!self.row.opening.active && delta.deposit == 0)
            || delta.debit != debit
            || delta.credit != credit
            || delta.payout != 0
            || delta.withdrawals != 1
            || delta.shards != u64::from(self.row.credit_root.len)
            || self.row.credit_root.total_credit != credit
            || self.row.credit_root.total_receipts != receipts
        {
            return Err(TransitionError::WithdrawalClaim);
        }
        match self.request.body().action() {
            WithdrawalAction::Amount(expected) if amount != expected.get() => {
                return Err(TransitionError::WithdrawalClaim);
            }
            WithdrawalAction::Close if self.row.closing.active || self.row.closing.balance != 0 => {
                return Err(TransitionError::WithdrawalClaim);
            }
            WithdrawalAction::Amount(_) | WithdrawalAction::Close => {}
        }
        if u128::from(self.row.closing.balance) + u128::from(debit) + u128::from(amount)
            != u128::from(self.row.opening.balance) + u128::from(credit) + u128::from(delta.deposit)
        {
            return Err(TransitionError::WithdrawalClaim);
        }
        Ok(amount)
    }
}

impl<P: PublicKey, D: Digest> Write for WithdrawalClaim<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.request.write(writer);
        self.withdrawal_opening.write(writer);
        self.predecessor.write(writer);
        self.row.write(writer);
        self.change_opening.write(writer);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for WithdrawalClaim<P, D> {
    fn encode_size(&self) -> usize {
        self.request.encode_size()
            + self.withdrawal_opening.encode_size()
            + self.predecessor.encode_size()
            + self.row.encode_size()
            + self.change_opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for WithdrawalClaim<P, D> {
    /// Maximum encoded destination length.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(reader: &mut impl Buf, destination_cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            request: SignedWithdrawal::read_cfg(reader, destination_cfg)?,
            withdrawal_opening: commitment::Opening::read(reader)?,
            predecessor: Option::<AccountRow<P, D>>::read(reader)?,
            row: AccountRow::read(reader)?,
            change_opening: commitment::MultiOpening::read_bounded(reader, 2)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for WithdrawalClaim<P, D>
where
    P: PublicKey,
    D: Digest,
    SignedWithdrawal<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    AccountRow<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::MultiOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            request: u.arbitrary()?,
            withdrawal_opening: u.arbitrary()?,
            predecessor: u.arbitrary()?,
            row: u.arbitrary()?,
            change_opening: u.arbitrary()?,
        })
    }
}

/// One prepared close with the Merkle state needed for dealing proof slices.
///
/// This transient value is not encoded. It retains the change, closing-state, and layout trees so
/// repeated dealing does not rebuild their roots.
#[derive(Debug)]
pub struct PreparedClose<P: PublicKey, D: Digest> {
    close: Close<P, D>,
    changes: Tree<D>,
    closing_leaves: Vec<StateLeaf<P>>,
    closing: Tree<D>,
    layout_boundaries: Vec<SliceBoundary>,
    layout: Tree<D>,
}

impl<P: PublicKey, D: Digest> PreparedClose<P, D> {
    pub(super) fn slice_bits(&self) -> u8 {
        let slice_count = self.layout_boundaries.len() - 1;
        debug_assert!(slice_count.is_power_of_two());
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

    /// Opens one changed row from the retained change tree.
    pub fn row_opening(&self, position: u32) -> Result<RowOpening<P, D>, TransitionError> {
        let row = self
            .close
            .rows
            .get(position as usize)
            .cloned()
            .ok_or(TransitionError::SliceRange)?;
        Ok(RowOpening {
            row,
            proof: self.changes.opening(position)?,
        })
    }

    /// Opens the terminal counts and aggregate flows needed for settlement admission.
    pub fn terminal_proof(&self) -> Result<TerminalProof<D>, TransitionError> {
        build_terminal_proof(&self.layout_boundaries, &self.layout)
    }

    /// Opens one external payout by recipient for later claiming.
    pub fn external_payout_claim(
        &self,
        recipient: &P,
    ) -> Result<ExternalPayoutClaim<P, D>, TransitionError> {
        build_external_payout_claim(&self.close, &self.changes, recipient)
    }

    /// Opens one finalized withdrawal request and its changed row for later claiming.
    pub fn withdrawal_claim<H>(
        &self,
        withdrawals: &WithdrawalBatch<P, D>,
        account: &P,
    ) -> Result<WithdrawalClaim<P, D>, TransitionError>
    where
        H: Hasher<Digest = D>,
    {
        let withdrawal_tree = withdrawal_tree::<H, P, D>(withdrawals)?;
        build_withdrawal_claim(
            &self.close,
            &self.changes,
            withdrawals,
            &withdrawal_tree,
            account,
        )
    }
}

fn build_terminal_proof<D: Digest>(
    layout_boundaries: &[SliceBoundary],
    layout: &Tree<D>,
) -> Result<TerminalProof<D>, TransitionError> {
    let position =
        u32::try_from(layout_boundaries.len() - 1).map_err(|_| TransitionError::SliceLayout)?;
    Ok(TerminalProof {
        terminal: layout_boundaries[position as usize],
        terminal_opening: layout.opening(position)?,
    })
}

fn build_external_payout_claim<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
    changes: &Tree<D>,
    recipient: &P,
) -> Result<ExternalPayoutClaim<P, D>, TransitionError> {
    let position = close
        .rows
        .binary_search_by(|row| row.account.cmp(recipient))
        .map_err(|_| TransitionError::PayoutClaim)?;
    let position = u32::try_from(position).map_err(|_| TransitionError::TooManyRows)?;
    let change_positions = if position == 0 {
        vec![position]
    } else {
        vec![position - 1, position]
    };
    let predecessor = position
        .checked_sub(1)
        .map(|position| close.rows[position as usize].clone());
    let row = close.rows[position as usize].clone();
    let previous_prefix = adjacent_change_prefix(predecessor.as_ref(), &row, &change_positions)
        .ok_or(TransitionError::PayoutClaim)?;
    external_payout_amount(&row, previous_prefix).ok_or(TransitionError::PayoutClaim)?;
    Ok(ExternalPayoutClaim {
        predecessor,
        row,
        change_opening: changes.multi_opening(&change_positions)?,
    })
}

fn build_withdrawal_claim<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
    changes: &Tree<D>,
    withdrawals: &WithdrawalBatch<P, D>,
    withdrawal_tree: &Tree<D>,
    account: &P,
) -> Result<WithdrawalClaim<P, D>, TransitionError> {
    let withdrawal_position = withdrawals
        .requests()
        .binary_search_by(|request| request.account().cmp(account))
        .map_err(|_| TransitionError::WithdrawalClaim)?;
    let change_position = close
        .rows
        .binary_search_by(|row| row.account.cmp(account))
        .map_err(|_| TransitionError::WithdrawalClaim)?;
    let change_position =
        u32::try_from(change_position).map_err(|_| TransitionError::TooManyRows)?;
    let change_positions = if change_position == 0 {
        vec![change_position]
    } else {
        vec![change_position - 1, change_position]
    };
    Ok(WithdrawalClaim {
        request: withdrawals.requests()[withdrawal_position].clone(),
        withdrawal_opening: withdrawal_tree.opening(
            u32::try_from(withdrawal_position).map_err(|_| TransitionError::WithdrawalClaim)?,
        )?,
        predecessor: change_position
            .checked_sub(1)
            .map(|position| close.rows[position as usize].clone()),
        row: close.rows[change_position as usize].clone(),
        change_opening: changes.multi_opening(&change_positions)?,
    })
}

fn withdrawal_tree<H, P, D>(withdrawals: &WithdrawalBatch<P, D>) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = u32::try_from(withdrawals.len()).map_err(|_| TransitionError::CloseLimit)?;
    let mut builder = commitment::Builder::<H>::new(VectorKind::Withdrawal, len)?;
    for request in withdrawals.requests() {
        builder.add_encoded(request.encode().as_ref())?;
    }
    Ok(builder.build(&Sequential)?)
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

/// Complete live opening vector and its retained Merkle tree.
#[derive(Clone, Debug)]
pub struct StateCache<P: PublicKey, D: Digest> {
    leaves: Vec<StateLeaf<P>>,
    tree: Tree<D>,
    liability: u64,
}

impl<P: PublicKey, D: Digest> StateCache<P, D> {
    /// Validates and commits a complete, strictly account-sorted opening vector.
    pub fn new<H: Hasher<Digest = D>>(leaves: Vec<StateLeaf<P>>) -> Result<Self, TransitionError> {
        Self::new_with_strategy::<H>(leaves, &Sequential)
    }

    /// Validates and commits a complete opening vector using the supplied execution strategy.
    pub fn new_with_strategy<H: Hasher<Digest = D>>(
        leaves: Vec<StateLeaf<P>>,
        strategy: &impl Strategy,
    ) -> Result<Self, TransitionError> {
        let len = u32::try_from(leaves.len()).map_err(|_| TransitionError::TooManyStates)?;
        if len > commitment::MAX_VECTOR_LENGTH {
            return Err(TransitionError::TooManyStates);
        }
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

        let mut liability = 0_u64;
        for leaf in &leaves {
            liability = liability
                .checked_add(leaf.state.balance)
                .ok_or(TransitionError::LiabilityOverflow)?;
        }
        let tree = state_tree_with_strategy::<H, P, D>(&leaves, strategy)?;
        Ok(Self {
            leaves,
            tree,
            liability,
        })
    }

    /// Returns the complete canonical opening leaves.
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

    /// Returns the cached opening state root.
    pub const fn root(&self) -> VectorRoot<D> {
        self.tree.root()
    }

    /// Returns the checked sum of opening balances.
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
            Ok(position) => Ok(StateLookup::Present(Box::new(StateOpening {
                leaf: self.leaves[position].clone(),
                proof: self.tree.opening(position as u32)?,
            }))),
            Err(insertion) => {
                let opening = |position: usize| -> Result<_, TransitionError> {
                    Ok(Box::new(StateOpening {
                        leaf: self.leaves[position].clone(),
                        proof: self.tree.opening(position as u32)?,
                    }))
                };
                Ok(StateLookup::Absent {
                    predecessor: insertion.checked_sub(1).map(opening).transpose()?,
                    successor: (insertion < self.leaves.len())
                        .then(|| opening(insertion))
                        .transpose()?,
                })
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

const fn is_live_state(state: &crate::bajillion::state::AccountState) -> bool {
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

fn derive_unchanged<P: PublicKey, D: Digest>(
    opening: &[StateLeaf<P>],
    rows: &[AccountRow<P, D>],
) -> Result<Vec<StateLeaf<P>>, TransitionError> {
    if opening
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
        || opening.iter().any(|leaf| !is_live_state(&leaf.state))
    {
        return Err(TransitionError::NonCanonicalStateOrder);
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::NonCanonicalRows);
    }

    let mut unchanged = Vec::with_capacity(opening.len().saturating_sub(rows.len()));
    let mut state = 0_usize;
    for row in rows {
        while opening
            .get(state)
            .is_some_and(|leaf| leaf.account < row.account)
        {
            unchanged.push(opening[state].clone());
            state += 1;
        }
        match opening.get(state) {
            Some(leaf) if leaf.account == row.account => {
                if leaf.state != row.opening {
                    return Err(TransitionError::OpeningLinkage);
                }
                state += 1;
            }
            _ if row.opening == crate::bajillion::state::AccountState::default() => {}
            _ => return Err(TransitionError::OpeningLinkage),
        }
    }
    unchanged.extend_from_slice(&opening[state..]);
    Ok(unchanged)
}

fn validate_row_state_sides<P: PublicKey, D: Digest>(
    row: &AccountRow<P, D>,
) -> Result<(), TransitionError> {
    if row.opening.active {
        if row.opening.balance == 0 {
            return Err(TransitionError::InactiveBalance);
        }
    } else if row.opening != crate::bajillion::state::AccountState::default() {
        return Err(TransitionError::NonCanonicalOpeningAbsence);
    }
    if row.closing.active != (row.closing.balance > 0) {
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
    let mut opening = Vec::with_capacity(capacity);
    let mut closing = Vec::with_capacity(capacity);
    let mut unchanged_index = 0_usize;
    let mut row_index = 0_usize;
    while unchanged_index < unchanged.len() || row_index < rows.len() {
        match (unchanged.get(unchanged_index), rows.get(row_index)) {
            (Some(leaf), Some(row)) if leaf.account < row.account => {
                opening.push(leaf.clone());
                closing.push(leaf.clone());
                unchanged_index += 1;
            }
            (Some(leaf), Some(row)) if row.account < leaf.account => {
                if row.opening.active {
                    opening.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.opening,
                    });
                }
                if row.closing.active {
                    closing.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.closing,
                    });
                }
                row_index += 1;
            }
            (Some(_), Some(_)) => return Err(TransitionError::StateRowOverlap),
            (Some(leaf), None) => {
                opening.push(leaf.clone());
                closing.push(leaf.clone());
                unchanged_index += 1;
            }
            (None, Some(row)) => {
                if row.opening.active {
                    opening.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.opening,
                    });
                }
                if row.closing.active {
                    closing.push(StateLeaf {
                        account: row.account.clone(),
                        state: row.closing,
                    });
                }
                row_index += 1;
            }
            (None, None) => break,
        }
    }

    let protocol_max = u64::from(commitment::MAX_VECTOR_LENGTH);
    let opening_len = u64::try_from(opening.len()).map_err(|_| TransitionError::TooManyStates)?;
    let closing_len = u64::try_from(closing.len()).map_err(|_| TransitionError::TooManyStates)?;
    if opening_len > max_states
        || closing_len > max_states
        || opening_len > protocol_max
        || closing_len > protocol_max
    {
        return Err(TransitionError::TooManyStates);
    }
    Ok((opening, closing))
}

fn validated_boundary_accounts<'a, P: PublicKey, D: Digest>(
    deployment: &D,
    deposits: &'a DepositBatch<P>,
    withdrawals: &'a WithdrawalBatch<P, D>,
    limits: &CloseLimits,
) -> Result<BTreeSet<&'a P>, TransitionError> {
    withdrawals.verify_deployment(deployment)?;
    let mut accounts = BTreeSet::new();
    accounts.extend(deposits.records().iter().map(|record| record.account()));
    accounts.extend(
        withdrawals
            .requests()
            .iter()
            .map(|request| request.account()),
    );
    let account_count = u64::try_from(accounts.len()).map_err(|_| TransitionError::CloseLimit)?;
    let withdrawal_count =
        u64::try_from(withdrawals.len()).map_err(|_| TransitionError::CloseLimit)?;
    if account_count > limits.max_rows
        || withdrawal_count > limits.max_withdrawals
        || deposits.total() > limits.max_deposit_total
    {
        return Err(TransitionError::CloseLimit);
    }
    Ok(accounts)
}

fn validate_sealed_boundaries<P: PublicKey, D: Digest>(
    cache: &StateCache<P, D>,
    deployment: &D,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    limits: &CloseLimits,
) -> Result<(), TransitionError> {
    let accounts = validated_boundary_accounts(deployment, deposits, withdrawals, limits)?;
    if u64::try_from(cache.len()).map_err(|_| TransitionError::CloseLimit)? > limits.max_states {
        return Err(TransitionError::CloseLimit);
    }

    for account in accounts {
        let opening = cache.locate(account).map_or_else(
            crate::bajillion::state::AccountState::default,
            |(_, leaf)| leaf.state,
        );
        let deposit = deposits.amount_for(account);
        let Some(withdrawal) = withdrawals.request_for(account) else {
            continue;
        };
        let body = withdrawal.body();
        match body.action() {
            WithdrawalAction::Amount(amount) => {
                let amount = amount.get();
                let available = u128::from(opening.balance) + u128::from(deposit);
                if u128::from(amount) > available {
                    return Err(TransitionError::WithdrawalCoverage);
                }
                if opening.active && deposit != 0 && deposit == amount {
                    return Err(TransitionError::BoundaryNoStateChange);
                }
            }
            WithdrawalAction::Close if !(opening.active || deposit != 0) => {
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
        || totals.withdrawals > limits.max_withdrawals
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
    if total_shards > limits.max_total_shards || totals.shards > limits.max_total_shards {
        return Err(TransitionError::CloseLimit);
    }
    Ok(())
}

/// Reusable index for constructing bounded account lookups against one close.
#[derive(Clone, Debug)]
pub struct ChallengeIndex<P: PublicKey, D: Digest> {
    opening_root: VectorRoot<D>,
    rows: Vec<AccountRow<P, D>>,
    tree: Tree<D>,
}

impl<P: PublicKey, D: Digest> ChallengeIndex<P, D> {
    /// Builds and authenticates the changed-row tree once for repeated challenge construction.
    pub fn new<H: Hasher<Digest = D>>(close: &Close<P, D>) -> Result<Self, TransitionError> {
        if close
            .rows
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(TransitionError::NonCanonicalRows);
        }
        let tree = change_tree::<H, P, D>(&close.rows)?;
        if tree.root() != close.roots.change {
            return Err(TransitionError::ChangeRoot);
        }
        Ok(Self {
            opening_root: close.roots.opening,
            rows: close.rows.clone(),
            tree,
        })
    }

    /// Returns the authenticated change-vector root indexed by this cache.
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
        if state.root() != self.opening_root {
            return Err(TransitionError::OpeningRoot);
        }
        match self.rows.binary_search_by(|row| row.account.cmp(account)) {
            Ok(position) => Ok(AccountLookup::Present(Box::new(RowOpening {
                row: self.rows[position].clone(),
                proof: self.tree.opening(position as u32)?,
            }))),
            Err(insertion) => {
                let state = state.lookup(account)?;
                let row_opening = |position: usize| -> Result<_, TransitionError> {
                    Ok(Box::new(RowOpening {
                        row: self.rows[position].clone(),
                        proof: self.tree.opening(position as u32)?,
                    }))
                };
                Ok(AccountLookup::Absent {
                    state: Box::new(state),
                    predecessor: insertion.checked_sub(1).map(row_opening).transpose()?,
                    successor: (insertion < self.rows.len())
                        .then(|| row_opening(insertion))
                        .transpose()?,
                })
            }
        }
    }
}

fn checked_closing_liability(
    opening: u64,
    deposits: u64,
    withdrawals: u64,
    payouts: u64,
) -> Result<u64, TransitionError> {
    let available = u128::from(opening) + u128::from(deposits);
    let closing = available
        .checked_sub(u128::from(withdrawals))
        .and_then(|remaining| remaining.checked_sub(u128::from(payouts)))
        .ok_or(TransitionError::LiabilityEquation)?;
    u64::try_from(closing).map_err(|_| TransitionError::LiabilityOverflow)
}

fn change_tree<H, P, D>(rows: &[AccountRow<P, D>]) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    change_tree_with_strategy::<H, P, D>(rows, &Sequential)
}

fn change_tree_with_strategy<H, P, D>(
    rows: &[AccountRow<P, D>],
    strategy: &impl Strategy,
) -> Result<Tree<D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let len = u32::try_from(rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    let mut builder = commitment::Builder::<H>::new(VectorKind::Change, len)?;
    builder.add_values(rows, strategy)?;
    Ok(builder.build(strategy)?)
}

fn state_liability<P: PublicKey>(leaves: &[StateLeaf<P>]) -> Result<u64, TransitionError> {
    leaves.iter().try_fold(0_u64, |total, leaf| {
        total
            .checked_add(leaf.state.balance)
            .ok_or(TransitionError::LiabilityOverflow)
    })
}

/// Builds one close from the complete live opening state, then validates it fully.
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
/// This validates canonical shape, authenticated context, boundary roots, and exact opening-state
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
    if cache.root() != *context.opening_root() {
        return Err(TransitionError::OpeningRoot);
    }
    if cache.liability != context.opening_liability() {
        return Err(TransitionError::OpeningLiability);
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].account >= pair[1].account)
    {
        return Err(TransitionError::NonCanonicalRows);
    }
    if rows.len() != shard_sets.len() {
        return Err(TransitionError::ShardAlignment);
    }
    let totals = rows.last().map_or_else(Prefix::default, |row| row.prefix);
    validate_corpus_limits(context, &rows, &shard_sets, totals)?;
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;

    let unchanged = derive_unchanged(cache.leaves(), &rows)?;
    let (opening_leaves, closing_leaves) =
        derive_state_vectors(&unchanged, &rows, context.limits().max_states())?;
    if opening_leaves != cache.leaves {
        return Err(TransitionError::OpeningLinkage);
    }

    let closing = state_tree_with_strategy::<H, P, D>(&closing_leaves, strategy)?;
    let changes = change_tree_with_strategy::<H, P, D>(&rows, strategy)?;
    let layout_boundaries = slice::derive_layout(
        &rows,
        &opening_leaves,
        &closing_leaves,
        context.assignment().slice_bits(),
    )?;
    let layout = slice::layout_tree_with_strategy::<H, D>(&layout_boundaries, strategy)?;
    let expected_liability = checked_closing_liability(
        cache.liability,
        deposits.total(),
        totals.withdrawal,
        totals.payout,
    )?;
    if state_liability(&closing_leaves)? != expected_liability {
        return Err(TransitionError::LiabilityEquation);
    }
    let roots = RootBundle {
        opening: cache.root(),
        change: changes.root(),
        closing: closing.root(),
        layout: layout.root(),
    };
    let close = Close {
        header: Header::new::<H, P>(context.payment(), &roots),
        roots,
        unchanged,
        rows,
        shard_sets,
    };
    Ok(PreparedClose {
        close,
        changes,
        closing_leaves,
        closing,
        layout_boundaries,
        layout,
    })
}

/// Assembles the terminal settlement witness from a decoded close.
///
/// Close producers should prefer [`PreparedClose::terminal_proof`], which reuses the retained
/// layout tree. This convenience path reconstructs that tree from the public corpus.
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
    let (opening, closing) =
        derive_state_vectors(&close.unchanged, &close.rows, context.limits().max_states())?;
    let layout_boundaries = slice::derive_layout(
        &close.rows,
        &opening,
        &closing,
        context.assignment().slice_bits(),
    )?;
    let layout = slice::layout_tree_with_strategy::<H, D>(&layout_boundaries, strategy)?;
    if layout.root() != close.roots.layout {
        return Err(TransitionError::SliceLayout);
    }
    build_terminal_proof(&layout_boundaries, &layout)
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
    let changes = change_tree_with_strategy::<H, P, D>(&close.rows, strategy)?;
    if changes.root() != close.roots.change {
        return Err(TransitionError::ChangeRoot);
    }
    build_external_payout_claim(close, &changes, recipient)
}

/// Opens one withdrawal request and its changed row from a decoded close.
pub fn assemble_withdrawal_claim<H, P, D>(
    close: &Close<P, D>,
    withdrawals: &WithdrawalBatch<P, D>,
    account: &P,
    strategy: &impl Strategy,
) -> Result<WithdrawalClaim<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let changes = change_tree_with_strategy::<H, P, D>(&close.rows, strategy)?;
    if changes.root() != close.roots.change {
        return Err(TransitionError::ChangeRoot);
    }
    let withdrawal_tree = withdrawal_tree::<H, P, D>(withdrawals)?;
    build_withdrawal_claim(close, &changes, withdrawals, &withdrawal_tree, account)
}

/// Validates the contextual root commitment and opening-state ancestry.
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
    if !header.verify::<H, P>(context.payment(), roots) {
        return Err(TransitionError::HeaderRoot);
    }
    if roots.opening != *context.opening_root() {
        return Err(TransitionError::OpeningRoot);
    }
    Ok(())
}

fn validate_corpus_shape<P: PublicKey, D: Digest>(
    close: &Close<P, D>,
    limits: &CloseLimits,
) -> Result<(), TransitionError> {
    let rows = u32::try_from(close.rows.len()).map_err(|_| TransitionError::TooManyRows)?;
    let unchanged =
        u64::try_from(close.unchanged.len()).map_err(|_| TransitionError::TooManyStates)?;
    if rows > commitment::MAX_VECTOR_LENGTH
        || u64::from(rows) > limits.max_rows()
        || unchanged > limits.max_states()
    {
        return Err(TransitionError::RowCount);
    }
    if close.rows.len() != close.shard_sets.len() {
        return Err(TransitionError::ShardAlignment);
    }
    Ok(())
}

fn validate_boundaries<P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    close: &Close<P, D>,
) -> Result<(), TransitionError> {
    withdrawals.verify_deployment(context.deployment())?;
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

pub(crate) fn validate_terminal_prefix<P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    row_count: u32,
    totals: Prefix,
) -> Result<(), TransitionError> {
    let withdrawal_count =
        u64::try_from(withdrawals.len()).map_err(|_| TransitionError::BoundaryTotals)?;
    if totals.deposit != deposits.total()
        || totals.withdrawal < withdrawals.total()
        || totals.withdrawals != withdrawal_count
    {
        return Err(TransitionError::BoundaryTotals);
    }

    let limits = context.limits();
    if u64::from(row_count) > limits.max_rows()
        || totals.withdrawals > limits.max_withdrawals()
        || totals.shards > limits.max_total_shards()
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
    checked_closing_liability(
        context.opening_liability(),
        totals.deposit,
        totals.withdrawal,
        totals.payout,
    )?;
    Ok(())
}

fn adjacent_change_prefix<P: PublicKey, D: Digest>(
    predecessor: Option<&AccountRow<P, D>>,
    row: &AccountRow<P, D>,
    positions: &[u32],
) -> Option<Prefix> {
    match predecessor {
        Some(predecessor) => {
            let position = positions.last().copied()?;
            if predecessor.account >= row.account
                || positions != [position.checked_sub(1)?, position]
            {
                return None;
            }
            Some(predecessor.prefix)
        }
        None => (positions == [0]).then_some(Prefix::default()),
    }
}

fn external_payout_amount<P: PublicKey, D: Digest>(
    row: &AccountRow<P, D>,
    previous_prefix: Prefix,
) -> Option<u64> {
    if row.opening != crate::bajillion::state::AccountState::default()
        || row.closing.active
        || row.closing.balance != 0
        || row.outgoing.is_some()
    {
        return None;
    }
    let (debit, credit, receipts) = row.checked_deltas()?;
    let delta = checked_prefix_delta(row.prefix, previous_prefix)?;
    (debit == 0
        && credit > 0
        && receipts > 0
        && row.credit_root.len > 0
        && row.credit_root.total_credit == credit
        && row.credit_root.total_receipts == receipts
        && delta.debit == debit
        && delta.credit == credit
        && delta.payout == credit
        && delta.deposit == 0
        && delta.withdrawal == 0
        && delta.withdrawals == 0
        && delta.shards == u64::from(row.credit_root.len))
    .then_some(credit)
}

fn checked_prefix_delta(current: Prefix, previous: Prefix) -> Option<Prefix> {
    Some(Prefix {
        debit: current.debit.checked_sub(previous.debit)?,
        credit: current.credit.checked_sub(previous.credit)?,
        payout: current.payout.checked_sub(previous.payout)?,
        deposit: current.deposit.checked_sub(previous.deposit)?,
        withdrawal: current.withdrawal.checked_sub(previous.withdrawal)?,
        withdrawals: current.withdrawals.checked_sub(previous.withdrawals)?,
        shards: current.shards.checked_sub(previous.shards)?,
    })
}

pub(crate) fn verify_terminal_proof_after_header<H, P, D>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    roots: &RootBundle<D>,
    proof: &TerminalProof<D>,
) -> Result<Prefix, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let terminal_position = u32::from(context.assignment().slice_count());
    let layout_len = terminal_position
        .checked_add(1)
        .ok_or(TransitionError::TerminalProof)?;
    if proof.terminal_opening.position != terminal_position
        || proof.terminal_opening.proof.leaf_count != layout_len
        || u64::from(proof.terminal.opening) > context.limits().max_states()
        || u64::from(proof.terminal.change) > context.limits().max_rows()
        || u64::from(proof.terminal.closing) > context.limits().max_states()
    {
        return Err(TransitionError::TerminalProof);
    }
    proof.terminal_opening.verify::<H>(
        VectorKind::Layout,
        &roots.layout,
        &proof.terminal.encode(),
    )?;
    validate_terminal_prefix(
        context,
        deposits,
        withdrawals,
        proof.terminal.change,
        proof.terminal.prefix,
    )?;
    Ok(proof.terminal.prefix)
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
        Some(request) => match request.body().action() {
            WithdrawalAction::Amount(amount) => amount.get(),
            WithdrawalAction::Close => {
                let available =
                    u128::from(row.opening.balance) + u128::from(deposit) + u128::from(credit);
                let tail = available
                    .checked_sub(u128::from(debit))
                    .ok_or(TransitionError::BalanceEquation)?;
                u64::try_from(tail).map_err(|_| TransitionError::PrefixOverflow)?
            }
        },
        None => 0,
    };

    let registered = row.opening.active || deposit != 0;
    let payout = if registered { 0 } else { credit };
    if !registered && (row.closing.active || debit != 0 || credit == 0 || withdrawal.is_some()) {
        return Err(TransitionError::AccountActivity);
    }
    let has_effect =
        debit != 0 || credit != 0 || receipts != 0 || deposit != 0 || withdrawal.is_some();
    if (!row.is_changed() && !(has_effect && !row.opening.active && !row.closing.active))
        || (!row.opening.active && !row.closing.active && !has_effect)
    {
        return Err(TransitionError::UnchangedRow);
    }
    if withdrawal.is_some_and(|request| matches!(request.body().action(), WithdrawalAction::Close))
        && (row.closing.balance != 0 || row.closing.active)
    {
        return Err(TransitionError::AccountActivity);
    }
    if u128::from(row.closing.balance)
        + u128::from(debit)
        + u128::from(withdrawal_amount)
        + u128::from(payout)
        != u128::from(row.opening.balance) + u128::from(credit) + u128::from(deposit)
    {
        return Err(TransitionError::BalanceEquation);
    }

    match (&row.outgoing, debit) {
        (None, 0) => {}
        (Some(payment), debit) if debit != 0 => {
            if payment.payer() != &row.account
                || payment.send().body().cumulative_debit() != row.closing.cumulative_debit
                || payment.amount() > debit
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
    shards.verify_root::<H>(&row.credit_root)?;
    if row.credit_root.total_credit != credit
        || row.credit_root.total_receipts != receipts
        || usize::try_from(row.credit_root.len).ok() != Some(shards.heads().len())
    {
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
        withdrawals: u64::from(withdrawal.is_some()),
        shards: u64::try_from(shards.heads().len()).map_err(|_| TransitionError::PrefixOverflow)?,
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
    validate_corpus_shape(close, context.limits())?;
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
    validate_boundaries(context, deposits, withdrawals, close)
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
    validate_terminal_prefix(context, deposits, withdrawals, row_count, prefix)
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
    let close = prepared.close();
    validate_close_preamble::<H, P, D>(context, deposits, withdrawals, close)?;
    let slice_bits = prepared.slice_bits();
    if slice_bits != context.assignment().slice_bits() {
        return Err(TransitionError::SliceBits);
    }
    if prepared.changes.root() != close.roots.change {
        return Err(TransitionError::ChangeRoot);
    }
    let (opening, closing) =
        derive_state_vectors(&close.unchanged, &close.rows, context.limits().max_states())?;
    if prepared.closing_leaves != closing || prepared.closing.root() != close.roots.closing {
        return Err(TransitionError::ClosingRoot);
    }
    let layout = slice::derive_layout(&close.rows, &opening, &closing, slice_bits)?;
    if prepared.layout_boundaries != layout || prepared.layout.root() != close.roots.layout {
        return Err(TransitionError::SliceLayout);
    }
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
    if change_tree_with_strategy::<H, P, D>(&close.rows, strategy)?.root() != close.roots.change {
        return Err(TransitionError::ChangeRoot);
    }
    let (opening, closing) =
        derive_state_vectors(&close.unchanged, &close.rows, context.limits().max_states())?;
    let opening_tree = state_tree_with_strategy::<H, P, D>(&opening, strategy)?;
    let closing_tree = state_tree_with_strategy::<H, P, D>(&closing, strategy)?;
    if opening_tree.root() != close.roots.opening {
        return Err(TransitionError::OpeningRoot);
    }
    if closing_tree.root() != close.roots.closing {
        return Err(TransitionError::ClosingRoot);
    }
    let layout = slice::derive_layout(
        &close.rows,
        &opening,
        &closing,
        context.assignment().slice_bits(),
    )?;
    if slice::layout_tree_with_strategy::<H, D>(&layout, strategy)?.root() != close.roots.layout {
        return Err(TransitionError::SliceLayout);
    }
    let expected_liability = checked_closing_liability(
        context.opening_liability(),
        deposits.total(),
        close
            .rows
            .last()
            .map_or_else(Prefix::default, |row| row.prefix)
            .withdrawal,
        close
            .rows
            .last()
            .map_or_else(Prefix::default, |row| row.prefix)
            .payout,
    )?;
    if state_liability(&closing)? != expected_liability {
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
    /// A slice does not authenticate its exact gap-free vector boundaries.
    #[error("proof-slice layout boundaries are not canonical")]
    SliceLayout,
    /// The terminal settlement opening is malformed or out of bounds.
    #[error("terminal settlement proof is not canonical")]
    TerminalProof,
    /// A changed row is not a valid external payout claim.
    #[error("changed row is not a valid external payout claim")]
    PayoutClaim,
    /// A signed withdrawal and changed row do not form one finalized claim.
    #[error("withdrawal claim is not canonical")]
    WithdrawalClaim,
    /// The opening state vector exceeds the protocol bound.
    #[error("opening state vector exceeds the protocol bound")]
    TooManyStates,
    /// Opening accounts are not strictly sorted and unique.
    #[error("opening state accounts are not strictly sorted and unique")]
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
    /// A row's opening state does not match its cached account.
    #[error("row does not match the cached opening account state")]
    OpeningLinkage,
    /// An opening-absent row side is not the canonical default state.
    #[error("an absent opening row side must be the canonical default state")]
    NonCanonicalOpeningAbsence,
    /// One account appears in both the unchanged vector and changed rows.
    #[error("unchanged leaves and changed rows must have disjoint accounts")]
    StateRowOverlap,
    /// A header does not authenticate its roots under the registered payment context.
    #[error("header does not authenticate the supplied roots and payment context")]
    HeaderRoot,
    /// Root bundle and expected opening roots differ.
    #[error("root bundle opening root does not match the expected root")]
    OpeningRoot,
    /// Cached and expected opening liabilities differ.
    #[error("cached opening liability does not match the expected liability")]
    OpeningLiability,
    /// Admission does not precede a challenge deadline with a representable resolution time.
    #[error("admission must precede a challenge deadline below the maximum timestamp")]
    DeadlineOrder,
    /// Change-root, unchanged-state, or row counts exceed their bounds.
    #[error("close row counts are inconsistent")]
    RowCount,
    /// Rows and receive-shard sets are not aligned one-for-one.
    #[error("changed rows and terminal shard sets are not aligned")]
    ShardAlignment,
    /// The committed change root does not match the exact rows.
    #[error("change root does not commit the supplied rows")]
    ChangeRoot,
    /// The committed closing root does not match the exact derived live state.
    #[error("closing root does not commit the derived live state")]
    ClosingRoot,
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
    /// A withdrawal is not affordable from the sealed opening state and deposit.
    #[error("withdrawal is not covered by the sealed opening state and deposit")]
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
    /// Terminal outgoing evidence is not present exactly when debit advanced.
    #[error("terminal outgoing evidence presence does not match debit activity")]
    OutgoingPresence,
    /// Terminal outgoing evidence names another payer or debit endpoint.
    #[error("terminal outgoing evidence does not match the closing debit endpoint")]
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
    /// Opening and closing liabilities do not satisfy boundary flow conservation.
    #[error("opening and closing liabilities violate boundary flow conservation")]
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
        payment::{Payment, SignedReceipt, SignedSend},
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
        let receipt =
            SignedReceipt::issue_next::<Sha256, _>(context, &send, 0, 0, 0, operator).unwrap();
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
            let amount = withdrawal.map_or(0, |request| match request.body().action() {
                WithdrawalAction::Amount(amount) => amount.get(),
                WithdrawalAction::Close => {
                    let available =
                        u128::from(row.opening.balance) + u128::from(deposit) + u128::from(credit);
                    u64::try_from(available.checked_sub(u128::from(debit)).unwrap()).unwrap()
                }
            });
            prefix = prefix
                .checked_extend(Prefix {
                    debit,
                    credit,
                    payout: if row.opening.active || deposit != 0 {
                        0
                    } else {
                        credit
                    },
                    deposit,
                    withdrawal: amount,
                    withdrawals: u64::from(withdrawal.is_some()),
                    shards: shards.heads().len() as u64,
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
                    opening: payer_opening,
                    closing: AccountState {
                        balance: 80,
                        cumulative_debit: 20,
                        ..payer_opening
                    },
                    outgoing: Some(payment.clone()),
                    credit_root: payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    opening: recipient_opening,
                    closing: AccountState {
                        balance: 60,
                        cumulative_credit: 20,
                        receipt_count: 1,
                        ..recipient_opening
                    },
                    outgoing: None,
                    credit_root: recipient_shards.root::<Sha256>().unwrap(),
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
        close.roots.change = change_tree::<Sha256, _, _>(&close.rows).unwrap().root();
        let (opening, closing) = derive_state_vectors(
            &close.unchanged,
            &close.rows,
            u64::from(commitment::MAX_VECTOR_LENGTH),
        )
        .unwrap();
        close.roots.opening = state_tree_with_strategy::<Sha256, _, _>(&opening, &Sequential)
            .unwrap()
            .root();
        close.roots.closing = state_tree_with_strategy::<Sha256, _, _>(&closing, &Sequential)
            .unwrap()
            .root();
        let layout = slice::derive_layout(
            &close.rows,
            &opening,
            &closing,
            context.assignment().slice_bits(),
        )
        .unwrap();
        close.roots.layout = slice::layout_tree_with_strategy::<Sha256, _>(&layout, &Sequential)
            .unwrap()
            .root();
        close.header = Header::new::<Sha256, _>(context.payment(), &close.roots);
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
        assert_eq!(header.encode().len(), ShaDigest::SIZE);
        validate_header::<Sha256, _, _>(&fixture.context, header, &fixture.close.roots).unwrap();

        let mut reordered = fixture.close.roots;
        core::mem::swap(&mut reordered.opening, &mut reordered.closing);
        assert!(matches!(
            validate_header::<Sha256, _, _>(&fixture.context, header, &reordered),
            Err(TransitionError::HeaderRoot)
        ));

        let other_context = empty_fixture().0;
        assert!(!header.verify::<Sha256, _>(other_context.payment(), &fixture.close.roots));

        let mut other_opening = fixture.close.roots;
        other_opening.opening.digest = Sha256::hash(&[b"other-opening"]);
        let rebound = Header::new::<Sha256, _>(fixture.context.payment(), &other_opening);
        assert!(matches!(
            validate_header::<Sha256, _, _>(&fixture.context, &rebound, &other_opening),
            Err(TransitionError::OpeningRoot)
        ));
    }

    #[test]
    fn terminal_prefix_liability_uses_widened_checked_arithmetic() {
        let operator = SigningKey::from_seed(104);
        let account = SigningKey::from_seed(105).public_key();
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: state(u64::MAX),
        }])
        .unwrap();
        let deposits = DepositBatch::new(vec![DepositRecord::new(account, 1).unwrap()]).unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"deployment"]),
            15,
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
        let mut totals = Prefix {
            deposit: 1,
            withdrawal: 1,
            ..Prefix::default()
        };
        validate_terminal_prefix(&context, &deposits, &withdrawals, 1, totals).unwrap();

        totals.withdrawal = 0;
        assert!(matches!(
            validate_terminal_prefix(&context, &deposits, &withdrawals, 1, totals),
            Err(TransitionError::LiabilityOverflow)
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
    fn maximum_partition_decodes_middle_layout_opening() {
        let operator = SigningKey::from_seed(188);
        let cache = StateCache::<VerifyingKey, ShaDigest>::new::<Sha256>(Vec::new()).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = close_context::<Sha256, _, _>(
            Sha256::hash(&[b"maximum-layout-partition"]),
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
        assert_eq!(middle.layout.opening.proof.leaf_count, 257);
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
        assert!(slice.layout.opening.proof.siblings.is_empty());
        assert!(slice.changes.opening.proof.siblings.is_empty());
        assert!(slice.opening.opening.proof.siblings.is_empty());
        assert!(slice.closing.opening.proof.siblings.is_empty());

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
        let mut layout = slice.clone();
        layout.layout.opening.proof.siblings = siblings.clone();
        let mut changes = slice.clone();
        changes.changes.opening.proof.siblings = siblings.clone();
        let mut opening = slice.clone();
        opening.opening.opening.proof.siblings = siblings.clone();
        let mut closing = slice;
        closing.closing.opening.proof.siblings = siblings;
        for oversized in [layout, changes, opening, closing] {
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
                    opening: payer_opening,
                    closing: AccountState {
                        balance: 80,
                        cumulative_debit: 20,
                        ..payer_opening
                    },
                    outgoing: Some(payment),
                    credit_root: payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    opening: AccountState::default(),
                    closing: AccountState {
                        cumulative_credit: 20,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    credit_root: recipient_shards.root::<Sha256>().unwrap(),
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
        assert!(claim.predecessor.is_none());
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
        let mut unexpected_predecessor = claim.clone();
        unexpected_predecessor.predecessor = Some(claim.row);
        assert!(matches!(
            unexpected_predecessor.verify::<Sha256>(&prepared.close().roots.change),
            Err(TransitionError::PayoutClaim)
        ));
        assert!(
            ExternalPayoutClaim::<VerifyingKey, ShaDigest>::decode_cfg(
                unexpected_predecessor.encode(),
                &(),
            )
            .is_err()
        );

        let close = prepared.close();

        assert_eq!(close.rows.last().unwrap().prefix.payout, 20);
        let (_, closing) = derive_state_vectors(
            &close.unchanged,
            &close.rows,
            u64::from(commitment::MAX_VECTOR_LENGTH),
        )
        .unwrap();
        assert_eq!(closing.len(), 1);
        assert_eq!(closing[0].account, payer.public_key());
        assert_eq!(closing[0].state.balance, 80);
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, close).unwrap();
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
        let closing_payer = &accounts[0];
        let closing_recipient = &accounts[1];
        let external_payer = &accounts[2];
        let external_recipient = &accounts[3];
        let opening = state(100);
        let mut leaves = vec![
            StateLeaf {
                account: closing_payer.public_key(),
                state: opening,
            },
            StateLeaf {
                account: external_payer.public_key(),
                state: opening,
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let deployment = Sha256::hash(&[b"close-withdrawal-is-not-payout"]);
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(closing_recipient.public_key(), 5).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            deployment,
            cache.root().digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            closing_recipient,
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
        let closing_payment = payment(
            context.payment(),
            &operator,
            closing_payer,
            closing_recipient,
            7,
        );
        let external_payment = payment(
            context.payment(),
            &operator,
            external_payer,
            external_recipient,
            7,
        );
        let closing_payer_shards =
            ShardSet::empty(context.payment().epoch(), closing_payer.public_key());
        let closing_recipient_shards = ShardSet::new(
            context.payment().epoch(),
            closing_recipient.public_key(),
            vec![ShardHead::new(0, closing_payment.clone())],
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
                    account: closing_payer.public_key(),
                    opening,
                    closing: AccountState {
                        balance: 93,
                        cumulative_debit: 7,
                        ..opening
                    },
                    outgoing: Some(closing_payment),
                    credit_root: closing_payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                closing_payer_shards,
            ),
            (
                AccountRow {
                    account: closing_recipient.public_key(),
                    opening: AccountState::default(),
                    closing: AccountState {
                        cumulative_credit: 7,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    credit_root: closing_recipient_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                closing_recipient_shards,
            ),
            (
                AccountRow {
                    account: external_payer.public_key(),
                    opening,
                    closing: AccountState {
                        balance: 93,
                        cumulative_debit: 7,
                        ..opening
                    },
                    outgoing: Some(external_payment),
                    credit_root: external_payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                external_payer_shards,
            ),
            (
                AccountRow {
                    account: external_recipient.public_key(),
                    opening: AccountState::default(),
                    closing: AccountState {
                        cumulative_credit: 7,
                        receipt_count: 1,
                        ..AccountState::default()
                    },
                    outgoing: None,
                    credit_root: external_recipient_shards.root::<Sha256>().unwrap(),
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
                .withdrawal_claim::<Sha256>(&withdrawals, &closing_recipient.public_key())
                .unwrap()
                .verify::<Sha256>(
                    context.deployment(),
                    context.withdrawal_root(),
                    &prepared.close().roots.change,
                )
                .unwrap(),
            12
        );
        assert!(matches!(
            prepared.external_payout_claim(&closing_recipient.public_key()),
            Err(TransitionError::PayoutClaim)
        ));

        let position = prepared
            .close()
            .rows
            .binary_search_by(|row| row.account.cmp(&closing_recipient.public_key()))
            .unwrap() as u32;
        let positions = if position == 0 {
            vec![position]
        } else {
            vec![position - 1, position]
        };
        let forged = ExternalPayoutClaim {
            predecessor: position
                .checked_sub(1)
                .map(|position| prepared.close().rows[position as usize].clone()),
            row: prepared.close().rows[position as usize].clone(),
            change_opening: prepared.changes.multi_opening(&positions).unwrap(),
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
        assert!(genuine.predecessor.is_some());
        assert_eq!(
            genuine
                .verify::<Sha256>(&prepared.close().roots.change)
                .unwrap(),
            ExternalPayout {
                recipient: external_recipient.public_key(),
                amount: 7,
            }
        );
        let mut missing_predecessor = genuine;
        missing_predecessor.predecessor = None;
        assert!(matches!(
            missing_predecessor.verify::<Sha256>(&prepared.close().roots.change),
            Err(TransitionError::PayoutClaim)
        ));
        assert!(
            ExternalPayoutClaim::<VerifyingKey, ShaDigest>::decode_cfg(
                missing_predecessor.encode(),
                &(),
            )
            .is_err()
        );
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
        shifted.opening.opening.start = shifted.opening.opening.start.saturating_add(1);
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
    fn epoch_anchor_binds_liability_but_not_opening_root() {
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
            Err(TransitionError::OpeningLiability)
        ));
        let first = epoch
            .clone()
            .bind::<Sha256>(&first_cache, &deposits, &withdrawals)
            .unwrap();
        let second = epoch
            .bind::<Sha256>(&second_cache, &deposits, &withdrawals)
            .unwrap();

        assert_ne!(first.opening_root(), second.opening_root());
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

        let opening = state(10);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: opening,
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
                opening,
                closing: state(15),
                outgoing: None,
                credit_root: shards.root::<Sha256>().unwrap(),
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
        let opening = state(10);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: opening,
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
        let index = ChallengeIndex::new::<Sha256>(&fixture.close).unwrap();
        assert_eq!(index.root(), fixture.close.roots.change);
        let payer = fixture.payment.payer();
        let present = index.account_lookup(&fixture.cache, payer).unwrap();
        let resolved = present
            .resolve::<Sha256>(
                &fixture.close.roots.opening,
                &fixture.close.roots.change,
                payer,
            )
            .unwrap();
        assert!(resolved.row.is_some());

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
        let index = ChallengeIndex::new::<Sha256>(&close).unwrap();
        let absent = index.account_lookup(&cache, &dormant).unwrap();
        let resolved = absent
            .resolve::<Sha256>(&close.roots.opening, &close.roots.change, &dormant)
            .unwrap();
        assert!(resolved.row.is_none());
        assert_eq!(resolved.opening, resolved.closing);
    }

    #[test]
    fn unchanged_live_state_close_is_canonical() {
        let (context, deposits, withdrawals, close) = empty_fixture();
        assert!(close.rows.is_empty());
        assert!(close.shard_sets.is_empty());
        assert_eq!(close.unchanged.len(), 1);
        assert_eq!(close.roots.opening, close.roots.closing);
        assert_eq!(close.rows.last().map(|row| row.prefix), None);
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
    }

    #[test]
    fn empty_close_requires_an_unchanged_state_root() {
        let (context, deposits, withdrawals, mut close) = empty_fixture();
        validate_header::<Sha256, _, _>(&context, &close.header, &close.roots).unwrap();

        close.roots.closing.digest = Sha256::hash(&[b"hidden-empty-change"]);
        close.header = Header::new::<Sha256, _>(context.payment(), &close.roots);
        assert!(matches!(
            validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close),
            Err(TransitionError::ClosingRoot)
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
            close.roots.opening,
            commitment::empty_root::<Sha256>(VectorKind::State)
        );
        assert_eq!(close.roots.opening, close.roots.closing);
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
            opening: state(1),
            closing: AccountState {
                balance: 2,
                active: true,
                ..AccountState::default()
            },
            outgoing: None,
            credit_root: shards.root::<CountingHasher>().unwrap(),
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
            "slice assembly did not rebuild the {slice_hashes}-hash closing tree"
        );
    }

    #[test]
    fn zero_balance_payment_removes_account_from_closing_state() {
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
        let recipient_closing = AccountState {
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
                    opening: payer_opening,
                    closing: AccountState {
                        cumulative_debit: 20,
                        ..AccountState::default()
                    },
                    outgoing: Some(payment),
                    credit_root: payer_shards.root::<Sha256>().unwrap(),
                    prefix: Prefix::default(),
                },
                payer_shards,
            ),
            (
                AccountRow {
                    account: recipient.public_key(),
                    opening: recipient_opening,
                    closing: recipient_closing,
                    outgoing: None,
                    credit_root: recipient_shards.root::<Sha256>().unwrap(),
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

        assert_eq!(prepared.closing_leaves.len(), 1);
        assert_eq!(prepared.closing_leaves[0].account, recipient.public_key());
        assert_eq!(prepared.closing_leaves[0].state, recipient_closing);
        assert!(
            prepared
                .closing_leaves
                .iter()
                .all(|leaf| leaf.state.balance > 0)
        );
    }

    #[test]
    fn close_sweeps_opening_balance_and_deactivates() {
        let operator = SigningKey::from_seed(30);
        let account = SigningKey::from_seed(31);
        let opening = state(10);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: opening,
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
                opening,
                closing: AccountState {
                    balance: 0,
                    active: false,
                    ..opening
                },
                outgoing: None,
                credit_root: shards.root::<Sha256>().unwrap(),
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
            checked_closing_liability(context.opening_liability(), 0, 10, 0).unwrap(),
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
        assert_eq!(
            claim
                .verify::<Sha256>(
                    context.deployment(),
                    context.withdrawal_root(),
                    &close.roots.change,
                )
                .unwrap(),
            10
        );

        let mut wrong_prefix = claim.clone();
        wrong_prefix.row.prefix.withdrawal = 9;
        let wrong_prefix_tree = change_tree::<Sha256, _, _>(&[wrong_prefix.row.clone()]).unwrap();
        wrong_prefix.change_opening = wrong_prefix_tree.multi_opening(&[0]).unwrap();
        assert!(matches!(
            wrong_prefix.verify::<Sha256>(
                context.deployment(),
                context.withdrawal_root(),
                &wrong_prefix_tree.root(),
            ),
            Err(TransitionError::WithdrawalClaim)
        ));

        let mut wrong_tail = claim.clone();
        wrong_tail.row.closing.balance = 1;
        wrong_tail.row.closing.active = true;
        wrong_tail.row.prefix.withdrawal = 9;
        let wrong_tail_tree = change_tree::<Sha256, _, _>(&[wrong_tail.row.clone()]).unwrap();
        wrong_tail.change_opening = wrong_tail_tree.multi_opening(&[0]).unwrap();
        assert!(matches!(
            wrong_tail.verify::<Sha256>(
                context.deployment(),
                context.withdrawal_root(),
                &wrong_tail_tree.root(),
            ),
            Err(TransitionError::WithdrawalClaim)
        ));

        let decoded = WithdrawalClaim::<VerifyingKey, ShaDigest>::decode_cfg(
            claim.encode(),
            &(..=usize::MAX).into(),
        )
        .unwrap();
        assert_eq!(decoded, claim);
    }

    #[test]
    fn withdrawal_claim_derives_epoch_tail_balance_from_adjacent_prefixes() {
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
        let deployment = Sha256::hash(&[b"withdrawal-claim-adjacent-prefix"]);
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
                        opening: leaf.state,
                        closing: AccountState {
                            balance: 0,
                            active: false,
                            ..leaf.state
                        },
                        outgoing: None,
                        credit_root: shards.root::<Sha256>().unwrap(),
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
        assert!(claim.predecessor.is_some());
        assert_eq!(
            claim
                .verify::<Sha256>(
                    context.deployment(),
                    context.withdrawal_root(),
                    &close.roots.change,
                )
                .unwrap(),
            18
        );

        let mut missing_predecessor = claim;
        missing_predecessor.predecessor = None;
        assert!(matches!(
            missing_predecessor.verify::<Sha256>(
                context.deployment(),
                context.withdrawal_root(),
                &close.roots.change,
            ),
            Err(TransitionError::WithdrawalClaim)
        ));
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
                opening: AccountState::default(),
                closing: state(5),
                outgoing: None,
                credit_root: shards.root::<Sha256>().unwrap(),
                prefix: Prefix {
                    deposit: 9,
                    withdrawal: 4,
                    withdrawals: 1,
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
        assert_eq!(
            claim
                .verify::<Sha256>(
                    context.deployment(),
                    context.withdrawal_root(),
                    &close.roots.change,
                )
                .unwrap(),
            4
        );

        let mut inexact = claim;
        inexact.row.closing.balance = 4;
        inexact.row.prefix.withdrawal = 5;
        let inexact_tree = change_tree::<Sha256, _, _>(&[inexact.row.clone()]).unwrap();
        inexact.change_opening = inexact_tree.multi_opening(&[0]).unwrap();
        assert!(matches!(
            inexact.verify::<Sha256>(
                context.deployment(),
                context.withdrawal_root(),
                &inexact_tree.root(),
            ),
            Err(TransitionError::WithdrawalClaim)
        ));
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
            opening: AccountState::default(),
            closing: AccountState {
                balance: 5,
                active: true,
                ..AccountState::default()
            },
            outgoing: None,
            credit_root: shards.root::<Sha256>().unwrap(),
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
        assert!(close.rows[0].closing.active);
        assert!(close.unchanged.is_empty());
        assert_ne!(close.roots.opening, close.roots.closing);
        assert_eq!(
            checked_closing_liability(context.opening_liability(), 5, 0, 0).unwrap(),
            5
        );

        let opening = state(5);
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.public_key(),
            state: opening,
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
            opening,
            closing: AccountState::default(),
            outgoing: None,
            credit_root: shards.root::<Sha256>().unwrap(),
            prefix: Prefix {
                withdrawal: 5,
                withdrawals: 1,
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
        assert!(!close.rows[0].closing.active);
        assert!(close.rows[0].is_changed());
        assert!(close.unchanged.is_empty());
        assert_eq!(
            close.roots.closing,
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
        fixture.close.rows[payer_position].closing.balance = 0;
        fixture.close.rows[payer_position].closing.active = false;
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
        fixture.close.rows[recipient_position].credit_root = fixture.close.shard_sets
            [recipient_position]
            .root::<Sha256>()
            .unwrap();
        fixture.close.rows[recipient_position].closing.balance = 0;
        fixture.close.rows[recipient_position].closing.active = false;
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
            close.roots.closing,
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
                .verify::<Sha256>(
                    context.deployment(),
                    context.withdrawal_root(),
                    &close.roots.change,
                )
                .unwrap(),
            80
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
                .verify::<Sha256>(
                    context.deployment(),
                    context.withdrawal_root(),
                    &close.roots.change,
                )
                .unwrap(),
            60
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
        fixture.close.rows[payer_position].closing.balance = 0;
        fixture.close.rows[payer_position].closing.cumulative_debit = 100;
        fixture.close.rows[payer_position].closing.active = false;
        fixture.close.rows[payer_position].outgoing = Some(payment.clone());
        let recipient_position = fixture
            .close
            .rows
            .binary_search_by(|row| row.account.cmp(&recipient.public_key()))
            .unwrap();
        fixture.close.rows[recipient_position].closing.balance = 140;
        fixture.close.rows[recipient_position]
            .closing
            .cumulative_credit = 100;
        fixture.close.rows[recipient_position].closing.receipt_count = 1;
        fixture.close.shard_sets[recipient_position] = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, payment)],
        )
        .unwrap();
        fixture.close.rows[recipient_position].credit_root = fixture.close.shard_sets
            [recipient_position]
            .root::<Sha256>()
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
        assert_eq!(close.rows.last().unwrap().prefix.withdrawals, 1);
        let claim = assemble_withdrawal_claim::<Sha256, _, _>(
            &close,
            &withdrawals,
            &fixture.payer.public_key(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(
            claim
                .verify::<Sha256>(
                    context.deployment(),
                    context.withdrawal_root(),
                    &close.roots.change,
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn mismatched_closing_root_is_rejected() {
        let (context, deposits, withdrawals, mut close) = empty_fixture();
        close.roots.closing.digest = Sha256::hash(&[b"hidden"]);
        close.header = Header::new::<Sha256, _>(context.payment(), &close.roots);
        assert!(matches!(
            validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close),
            Err(TransitionError::ClosingRoot)
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
        fixture.close.rows[0].closing.balance += 1;
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

        let opening = vec![
            StateLeaf {
                account: accounts[0].clone(),
                state: state(10),
            },
            StateLeaf {
                account: accounts[1].clone(),
                state: state(20),
            },
        ];
        let row = |account: VerifyingKey, opening, closing| {
            let shards = ShardSet::empty(0, account.clone());
            AccountRow {
                account,
                opening,
                closing,
                outgoing: None,
                credit_root: shards.root::<Sha256>().unwrap(),
                prefix: Prefix::default(),
            }
        };
        let rows = vec![
            row(accounts[0].clone(), state(10), AccountState::default()),
            row(accounts[2].clone(), AccountState::default(), state(30)),
        ];

        let unchanged = derive_unchanged(&opening, &rows).unwrap();
        assert_eq!(unchanged, vec![opening[1].clone()]);
        let (derived_opening, closing) = derive_state_vectors(&unchanged, &rows, 3).unwrap();
        assert_eq!(derived_opening, opening);
        assert_eq!(
            closing,
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
