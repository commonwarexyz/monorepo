//! Full-replica close construction, validation, and retained claim evidence.

use crate::bajillion::{
    boundary::{
        BoundaryError, Deadline, DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch,
    },
    commitment::{self, RangeOpening, Tree, VectorKind, VectorRoot},
    payment::{
        AckError, PaymentContext, SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE,
        VectorSendBody, verify_ack_signatures,
    },
    posted::{self, Dealing},
    qmdb::{self, PreparedState, State, StateRoot, account_key},
    state::{AccountChange, AccountRow, ChangeGuard, SettlementOutput},
    vector::{self, OutVector},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{
    BatchVerifier, Digest, Hasher, PublicKey,
    bls12381::primitives::{
        ops::aggregate::{self, combine_messages, combine_signatures, verify_same_signer},
        variant::{MinSig, Variant},
    },
};
use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::Spawner;
use commonware_storage::Context;
use commonware_utils::iter::NonEmpty;
use core::num::NonZeroU64;
use rand_core::CryptoRng;
use thiserror::Error;

/// Hash namespace for canonical close identifiers.
pub const BATCH_ID_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BATCH_ID";
/// Hash namespace for the certified close descriptor.
pub const HEADER_ROOT_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_HEADER_ROOT";
/// Hash namespace for immutable epoch payment anchors.
pub const EPOCH_ANCHOR_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_EPOCH_ANCHOR";

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
/// Combined acceptance of every terminal payer body in a close.
pub type OperatorAggregate = aggregate::Signature<OperatorVariant>;

/// The activity, withdrawal-output, and successor balance commitments.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RootBundle<D: Digest> {
    /// Account activity, including participants with unchanged balances.
    pub change: VectorRoot<D>,
    /// One output per registered withdrawal, in request order.
    pub withdrawal_outputs: VectorRoot<D>,
    /// Current Ordered balance state after this epoch's canonical batch.
    pub successor: StateRoot<D>,
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
        })
    }
}
impl<D: Digest> Write for RootBundle<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.change.write(writer);
        self.withdrawal_outputs.write(writer);
        self.successor.write(writer);
    }
}
impl<D: Digest> FixedSize for RootBundle<D> {
    const SIZE: usize = D::SIZE * 3;
}
impl<D: Digest> Read for RootBundle<D> {
    type Cfg = ();
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            change: VectorRoot::read(reader)?,
            withdrawal_outputs: VectorRoot::read(reader)?,
            successor: StateRoot::read(reader)?,
        })
    }
}

/// Separate reserves that settlement cannot derive from the registered request amounts.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct CloseAmounts {
    /// Actual releases to registered withdrawal destinations.
    pub withdrawal: u64,
    /// Credits released directly to external recipients.
    pub payout: u64,
}
impl Write for CloseAmounts {
    fn write(&self, writer: &mut impl BufMut) {
        self.withdrawal.write(writer);
        self.payout.write(writer);
    }
}
impl FixedSize for CloseAmounts {
    const SIZE: usize = 16;
}
impl Read for CloseAmounts {
    type Cfg = ();
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            withdrawal: u64::read(reader)?,
            payout: u64::read(reader)?,
        })
    }
}

/// Digest of the exact registered context, predecessor, roots, and release amounts.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Header<D: Digest>(D);
impl<D: Digest> Header<D> {
    /// Commits every value settlement needs to interpret this close.
    pub fn new<H: Hasher<Digest = D>, P: PublicKey>(
        context: &CloseContext<P, D>,
        roots: &RootBundle<D>,
        amounts: &CloseAmounts,
    ) -> Self {
        Self(H::hash(&[
            HEADER_ROOT_HASH_NAMESPACE,
            context.payment().encode().as_ref(),
            context.predecessor_root().digest.as_ref(),
            roots.change.digest.as_ref(),
            roots.withdrawal_outputs.digest.as_ref(),
            roots.successor.digest.as_ref(),
            amounts.encode().as_ref(),
        ]))
    }
    /// Checks the complete close descriptor against this digest.
    pub fn verify<H: Hasher<Digest = D>, P: PublicKey>(
        &self,
        context: &CloseContext<P, D>,
        roots: &RootBundle<D>,
        amounts: &CloseAmounts,
    ) -> bool {
        context.epoch.verify_anchor::<H>() && *self == Self::new::<H, P>(context, roots, amounts)
    }
    /// Returns the underlying digest.
    pub const fn digest(&self) -> &D {
        &self.0
    }
    /// Derives the canonical batch identity.
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
    committee: D,
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
        committee: D,
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
        let mut context = Self {
            payment: PaymentContext::new(deployment, epoch, operator.clone()),
            deployment,
            deposit_root,
            withdrawal_root,
            predecessor_liability,
            admission_deadline,
            challenge_deadline,
            limits,
            committee,
        };
        context.payment = PaymentContext::new(context.compute_anchor::<H>(), epoch, operator);
        Ok(context)
    }

    fn compute_anchor<H: Hasher<Digest = D>>(&self) -> D {
        H::hash(&[
            EPOCH_ANCHOR_HASH_NAMESPACE,
            self.deployment.as_ref(),
            self.deposit_root.encode().as_ref(),
            self.withdrawal_root.encode().as_ref(),
            &self.predecessor_liability.to_be_bytes(),
            &self.payment.epoch().to_be_bytes(),
            self.payment.operator().as_ref(),
            &self.admission_deadline.to_be_bytes(),
            &self.challenge_deadline.to_be_bytes(),
            self.limits.encode().as_ref(),
            self.committee.encode().as_ref(),
        ])
    }

    /// Checks that the payment anchor binds every registered parameter and valid deadlines.
    ///
    /// Registration provenance must still be authenticated by the settlement owner.
    pub fn verify_anchor<H: Hasher<Digest = D>>(&self) -> bool {
        self.admission_deadline < self.challenge_deadline
            && self.challenge_deadline < u64::MAX
            && self.compute_anchor::<H>() == *self.payment.anchor()
    }

    /// Binds registration to the locally validated predecessor and its boundary eligibility.
    pub async fn bind<H, E, S>(
        self,
        state: &State<E, H, S>,
        deposits: &DepositBatch<P>,
        withdrawals: &WithdrawalBatch<P, D>,
    ) -> Result<CloseContext<P, D>, TransitionError>
    where
        H: Hasher<Digest = D>,
        E: Context + Spawner,
        S: Strategy,
    {
        let context = CloseContext {
            epoch: self,
            predecessor_root: state.root(),
        };
        validate_predecessor::<H, P, D, E, S>(state, &context, deposits, withdrawals).await?;
        Ok(context)
    }

    /// Binds the root already owned by the settlement state machine.
    ///
    /// Settlement intake establishes each request's start affordability, through safety openings
    /// when queueing and through one predecessor-root opening for operator-carried requests.
    /// Later epoch spending can still lower the tail, which certification settles with a zero
    /// release. Callers outside that owner must use [`Self::bind`] with the complete balance database.
    pub(crate) const fn bind_settlement_root(
        self,
        predecessor_root: StateRoot<D>,
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

    /// Returns the authenticated validator committee.
    pub const fn committee(&self) -> &D {
        &self.committee
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
        committee: D,
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
            committee,
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
            committee: u.arbitrary()?,
        })
    }
}

/// Chain-known epoch registration bound to one exact predecessor state root.
///
/// Decoding checks structure. Header and full-close validation recompute the epoch anchor;
/// the embedding authenticates this exact registration and predecessor through settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseContext<P: PublicKey, D: Digest> {
    epoch: EpochContext<P, D>,
    predecessor_root: StateRoot<D>,
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
    pub const fn predecessor_root(&self) -> &StateRoot<D> {
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

    /// Returns the authenticated validator committee.
    pub const fn committee(&self) -> &D {
        self.epoch.committee()
    }

    /// Reassembles a bound context from parts retained by an earlier binding.
    ///
    /// See [`EpochContext::from_parts`] for the provenance requirement.
    pub(crate) const fn from_parts(
        epoch: EpochContext<P, D>,
        predecessor_root: StateRoot<D>,
    ) -> Self {
        Self {
            epoch,
            predecessor_root,
        }
    }
}

impl<P: PublicKey, D: Digest> Write for CloseContext<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.epoch.payment.write(writer);
        self.epoch.deployment.write(writer);
        self.epoch.deposit_root.write(writer);
        self.epoch.withdrawal_root.write(writer);
        self.epoch.predecessor_liability.write(writer);
        self.epoch.admission_deadline.write(writer);
        self.epoch.challenge_deadline.write(writer);
        self.epoch.limits.write(writer);
        self.epoch.committee.write(writer);
        self.predecessor_root.write(writer);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for CloseContext<P, D> {
    const SIZE: usize = PaymentContext::<P, D>::SIZE
        + D::SIZE
        + VectorRoot::<D>::SIZE * 2
        + StateRoot::<D>::SIZE
        + u64::SIZE * 3
        + CloseLimits::SIZE
        + D::SIZE;
}

impl<P: PublicKey, D: Digest> Read for CloseContext<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let payment = PaymentContext::read(reader)?;
        let deployment = D::read(reader)?;
        let deposit_root = VectorRoot::read(reader)?;
        let withdrawal_root = VectorRoot::read(reader)?;
        let predecessor_liability = u64::read(reader)?;
        let admission_deadline = u64::read(reader)?;
        let challenge_deadline = u64::read(reader)?;
        let limits = CloseLimits::read(reader)?;
        let committee = D::read(reader)?;
        let predecessor_root = StateRoot::read(reader)?;
        Ok(Self::from_parts(
            EpochContext::from_parts(
                payment,
                deployment,
                deposit_root,
                withdrawal_root,
                predecessor_liability,
                admission_deadline,
                challenge_deadline,
                limits,
                committee,
            ),
            predecessor_root,
        ))
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

/// Membership claim for one external payout in the activity tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPayoutClaim<P: PublicKey, D: Digest> {
    leaf: AccountChange<P, D>,
    opening: commitment::Opening<D>,
}

impl<P: PublicKey, D: Digest> ExternalPayoutClaim<P, D> {
    pub(crate) const fn new(leaf: AccountChange<P, D>, opening: commitment::Opening<D>) -> Self {
        Self { leaf, opening }
    }

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
    pub(crate) const fn new(
        output: WithdrawalOutput,
        output_opening: commitment::Opening<D>,
    ) -> Self {
        Self {
            output,
            output_opening,
        }
    }

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

/// One accepted terminal payer vector supplied by the close producer.
#[derive(Clone, Debug)]
pub struct Terminal<P: PublicKey, D: Digest> {
    /// Payer authorization over the complete epoch vector.
    pub authorization: SendAuthorization<P, D>,
    /// Entries authenticated by that authorization.
    pub vector: OutVector<P>,
    /// Operator acceptance in the aggregate-signature domain.
    pub operator_signature: OperatorSignature,
}

/// Complete derived activity and reusable proof material for one close.
#[derive(Clone, Debug)]
pub struct Close<P: PublicKey, D: Digest> {
    /// Certified proposal identifier.
    pub header: Header<D>,
    /// State and claim commitments.
    pub roots: RootBundle<D>,
    /// Certified settlement reserves.
    pub amounts: CloseAmounts,
    /// Canonical account activity; balances are transient derivation results.
    pub rows: Vec<AccountRow<P, D>>,
    /// Terminal vectors aligned with activity rows.
    pub out_vectors: Vec<OutVector<P>>,
    encoded: Bytes,
    pub(crate) changes: Arc<ChallengeIndex<P, D>>,
    withdrawals: Vec<WithdrawalOutput>,
    withdrawal_rows: Vec<usize>,
    withdrawal_tree: Tree<D>,
}
impl<P: PublicKey, D: Digest> Close<P, D> {
    /// Encodes retained claim evidence for later service without replaying the balance database.
    ///
    /// Transient row balances are local metadata. This artifact does not authorize a state
    /// transition; only full dealing validation can produce an applicable state candidate.
    pub fn encode_evidence(&self) -> Bytes {
        let mut writer = bytes::BytesMut::new();
        self.roots.write(&mut writer);
        self.amounts.write(&mut writer);
        self.encoded.write(&mut writer);
        for row in &self.rows {
            row.predecessor.write(&mut writer);
            row.successor.write(&mut writer);
            row.output.write(&mut writer);
        }
        self.withdrawals.write(&mut writer);
        writer.freeze()
    }

    /// Restores bounded claim evidence against an independently authenticated header.
    ///
    /// This reconstructs and verifies every activity/vector/output commitment. The caller
    /// authenticates `expected` through settlement. It does not validate the balance transition
    /// or certify the stored transient row balances, and returns no applicable state batch.
    pub fn decode_evidence<H: Hasher<Digest = D>>(
        mut encoded: Bytes,
        context: &CloseContext<P, D>,
        expected: &Header<D>,
    ) -> Result<Self, TransitionError> {
        let roots = RootBundle::read(&mut encoded)?;
        let amounts = CloseAmounts::read(&mut encoded)?;
        validate_header::<H, P, D>(context, expected, &roots, &amounts)?;
        if amounts.withdrawal > context.limits().max_withdrawal_total()
            || amounts.payout > context.limits().max_payment_total()
        {
            return Err(TransitionError::CloseLimit);
        }
        let available = encoded.remaining();
        let wire = Bytes::read_cfg(&mut encoded, &RangeCfg::new(..=available))?;
        let dealing = posted::decode(wire, context)?;
        if dealing.header != *expected {
            return Err(TransitionError::HeaderRoot);
        }
        if dealing.rows.len() > encoded.remaining() / 17 {
            return Err(TransitionError::Codec(CodecError::Invalid(
                "clearing::Evidence",
                "truncated activity",
            )));
        }
        let mut rows = Vec::with_capacity(dealing.rows.len());
        let mut vectors = Vec::with_capacity(dealing.rows.len());
        let mut leaves = Vec::with_capacity(dealing.rows.len());
        let mut payout = 0_u64;
        let mut withdrawal_amounts = Vec::new();
        let mut withdrawal_rows = Vec::new();
        for input in dealing.rows {
            let predecessor = u64::read(&mut encoded)?;
            let successor = u64::read(&mut encoded)?;
            let output = SettlementOutput::read(&mut encoded)?;
            match output {
                SettlementOutput::ExternalPayout(amount) => {
                    payout = payout
                        .checked_add(amount)
                        .ok_or(TransitionError::Arithmetic)?;
                }
                SettlementOutput::Withdrawal(amount) => {
                    withdrawal_rows.push(rows.len());
                    withdrawal_amounts.push(amount);
                }
                SettlementOutput::None => {}
            }
            let root = input.vector.root::<H, D>()?;
            let debit = input.vector.totals()?.0;
            let outgoing = input.outgoing.map(|(seq, signature)| {
                SendAuthorization::from_raw_unchecked(
                    VectorSendBody::new(context.payment(), input.account.clone(), seq, debit, root),
                    signature,
                )
            });
            let row = AccountRow {
                account: input.account,
                predecessor,
                successor,
                outgoing,
                output,
            };
            leaves.push(AccountChange::from_row(&row, root));
            rows.push(row);
            vectors.push(input.vector);
        }
        if payout != amounts.payout {
            return Err(TransitionError::SettlementOutput);
        }
        let bound = context
            .limits()
            .max_withdrawals()
            .min(u64::from(commitment::MAX_VECTOR_LENGTH))
            .min((encoded.remaining() / 9) as u64) as usize;
        let count = usize::read_cfg(&mut encoded, &RangeCfg::new(..=bound))?;
        if count != withdrawal_amounts.len() {
            return Err(TransitionError::WithdrawalOutputRoot);
        }
        let mut outputs = Vec::with_capacity(count);
        let mut withdrawal = 0_u64;
        for amount in withdrawal_amounts {
            let available = encoded.remaining();
            let output = WithdrawalOutput::read_cfg(&mut encoded, &RangeCfg::new(..=available))?;
            if output.amount() != amount {
                return Err(TransitionError::WithdrawalOutputRoot);
            }
            withdrawal = withdrawal
                .checked_add(amount)
                .ok_or(TransitionError::Arithmetic)?;
            outputs.push(output);
        }
        if withdrawal != amounts.withdrawal || encoded.has_remaining() {
            return Err(TransitionError::SettlementOutput);
        }
        let guards = leaves
            .iter()
            .map(AccountChange::guard::<H>)
            .collect::<Vec<_>>();
        let mut builder = commitment::Builder::<H>::new(VectorKind::Change, leaves.len() as u32)?;
        builder.add_values(&guards, &Sequential)?;
        let changes = Arc::new(ChallengeIndex {
            leaves: Arc::new(leaves),
            guards: Arc::new(guards),
            tree: Arc::new(builder.build(&Sequential)?),
        });
        let mut builder =
            commitment::Builder::<H>::new(VectorKind::WithdrawalOutput, count as u32)?;
        builder.add_values(&outputs, &Sequential)?;
        let withdrawal_tree = builder.build(&Sequential)?;
        if changes.root() != roots.change || withdrawal_tree.root() != roots.withdrawal_outputs {
            return Err(TransitionError::ChangeRoot);
        }
        Ok(Self {
            header: *expected,
            roots,
            amounts,
            rows,
            out_vectors: vectors,
            encoded: dealing.encoded,
            changes,
            withdrawals: outputs,
            withdrawal_rows,
            withdrawal_tree,
        })
    }
    /// Shares the single full-validator dealing.
    pub const fn encoded(&self) -> &Bytes {
        &self.encoded
    }
    /// Returns retained activity values and their guard tree.
    pub fn change_evidence(&self) -> (&[AccountChange<P, D>], &Tree<D>) {
        (&self.changes.leaves, &self.changes.tree)
    }
    /// Returns the registered withdrawal outputs and their tree.
    pub fn withdrawal_evidence(&self) -> (&[WithdrawalOutput], &Tree<D>) {
        (&self.withdrawals, &self.withdrawal_tree)
    }
    /// Opens a registered withdrawal, including a zero release.
    pub fn withdrawal_claim(&self, account: &P) -> Result<WithdrawalClaim<D>, TransitionError> {
        let row = self
            .changes
            .leaves
            .binary_search_by(|leaf| leaf.account().as_ref().cmp(account.as_ref()))
            .map_err(|_| TransitionError::WithdrawalClaim)?;
        let index = self
            .withdrawal_rows
            .binary_search(&row)
            .map_err(|_| TransitionError::WithdrawalClaim)?;
        Ok(WithdrawalClaim::new(
            self.withdrawals[index].clone(),
            self.withdrawal_tree.opening(index as u32)?,
        ))
    }
    /// Opens a positive external payout.
    pub fn external_payout_claim(
        &self,
        account: &P,
    ) -> Result<ExternalPayoutClaim<P, D>, TransitionError> {
        match self.changes.change_parts(account)? {
            ChangeParts::Present { leaf, proof } if matches!(leaf.output(),SettlementOutput::ExternalPayout(amount) if amount>0) => {
                Ok(ExternalPayoutClaim::new(leaf, proof))
            }
            _ => Err(TransitionError::PayoutClaim),
        }
    }
}

/// A derived close and a predecessor-bound, unapplied Current batch.
pub struct PreparedClose<P: PublicKey, D: Digest, S: Strategy = Sequential> {
    close: Close<P, D>,
    state: PreparedState<D, S>,
}
impl<P: PublicKey, D: Digest, S: Strategy> PreparedClose<P, D, S> {
    /// Returns the retained close evidence.
    pub const fn close(&self) -> &Close<P, D> {
        &self.close
    }
    /// Returns the shared encoded dealing.
    pub const fn encoded(&self) -> &Bytes {
        &self.close.encoded
    }
    /// Returns the prepared successor state.
    pub const fn state(&self) -> &PreparedState<D, S> {
        &self.state
    }
    /// Separates retained close evidence from its state candidate.
    pub fn into_parts(self) -> (Close<P, D>, PreparedState<D, S>) {
        (self.close, self.state)
    }
    /// Applies the candidate while retaining the close's claim evidence.
    pub async fn apply<E, H>(
        self,
        state: State<E, H, S>,
    ) -> Result<(State<E, H, S>, Close<P, D>), TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
    {
        Ok((state.apply(self.state).await?, self.close))
    }
    /// Opens a registered withdrawal from the retained close.
    pub fn withdrawal_claim(&self, account: &P) -> Result<WithdrawalClaim<D>, TransitionError> {
        self.close.withdrawal_claim(account)
    }
    /// Opens an external payout from the retained close.
    pub fn external_payout_claim(
        &self,
        account: &P,
    ) -> Result<ExternalPayoutClaim<P, D>, TransitionError> {
        self.close.external_payout_claim(account)
    }
}

/// Whole activity-tree lookup material, shared by prepared and validated closes.
#[derive(Clone, Debug)]
pub struct ChallengeIndex<P: PublicKey, D: Digest> {
    leaves: Arc<Vec<AccountChange<P, D>>>,
    guards: Arc<Vec<ChangeGuard<P, D>>>,
    tree: Arc<Tree<D>>,
}
impl<P: PublicKey, D: Digest> ChallengeIndex<P, D> {
    /// Authenticates and shares the close's retained activity tree.
    pub fn new<H: Hasher<Digest = D>>(
        context: &CloseContext<P, D>,
        close: &Close<P, D>,
    ) -> Result<Self, TransitionError> {
        validate_header::<H, P, D>(context, &close.header, &close.roots, &close.amounts)?;
        if close.changes.tree.root() != close.roots.change {
            return Err(TransitionError::ChangeRoot);
        }
        Ok((*close.changes).clone())
    }
    /// Returns the activity root.
    pub fn root(&self) -> VectorRoot<D> {
        self.tree.root()
    }
    /// Opens membership or the exact adjacent-key absence bracket.
    pub fn change_parts(&self, account: &P) -> Result<ChangeParts<P, D>, TransitionError> {
        match self
            .leaves
            .binary_search_by(|leaf| leaf.account().as_ref().cmp(account.as_ref()))
        {
            Ok(position) => Ok(ChangeParts::Present {
                leaf: self.leaves[position].clone(),
                proof: self.tree.opening(position as u32)?,
            }),
            Err(position) => {
                let (predecessor, successor, opening) = self
                    .tree
                    .bracket(&self.guards, position as u32..position as u32)?;
                Ok(ChangeParts::Absent {
                    predecessor,
                    successor,
                    opening,
                })
            }
        }
    }
}
/// Activity membership or a compact ordered absence witness.
#[derive(Clone, Debug)]
pub enum ChangeParts<P: PublicKey, D: Digest> {
    /// Account participated in this epoch.
    Present {
        /// Committed activity projection.
        leaf: AccountChange<P, D>,
        /// Membership opening of its guard.
        proof: commitment::Opening<D>,
    },
    /// Account did not participate in this epoch.
    Absent {
        /// Immediate previous guard.
        predecessor: Option<ChangeGuard<P, D>>,
        /// Immediate following guard.
        successor: Option<ChangeGuard<P, D>>,
        /// Authentication of the adjacent bracket.
        opening: RangeOpening<D>,
    },
}

/// Constructs one canonical dealing and its incremental state candidate.
///
/// Preparation checks body/vector consistency. Signature authentication belongs to validation.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_close_with_strategy<H, P, D, E, S>(
    state: &State<E, H, S>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    terminals: Vec<Terminal<P, D>>,
    strategy: &S,
) -> Result<PreparedClose<P, D, S>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    E: Context + Spawner,
    S: Strategy,
{
    let limits = context.limits();
    if terminals.len() as u64 > limits.max_rows()
        || terminals.windows(2).any(|pair| {
            pair[0].authorization.body().payer().as_ref()
                >= pair[1].authorization.body().payer().as_ref()
        })
    {
        return Err(TransitionError::NonCanonicalRows);
    }

    // Activity and recipient indices share the Current account key ordering.
    let mut accounts = BTreeMap::new();
    let mut total_entries = 0_u64;
    for terminal in &terminals {
        let body = terminal.authorization.body();
        body.validate_context(context.payment())?;
        if terminal.vector.payer() != body.payer()
            || terminal.vector.epoch() != context.payment().epoch()
            || terminal.vector.entries().is_empty()
            || terminal.vector.root::<H, D>()? != body.send_root()
            || terminal.vector.totals()?.0 != body.cumulative_debit()
        {
            return Err(TransitionError::OutgoingEndpoint);
        }
        accounts.insert(account_key(body.payer())?, body.payer().clone());
        total_entries = total_entries
            .checked_add(terminal.vector.entries().len() as u64)
            .filter(|n| *n <= limits.max_total_entries())
            .ok_or(TransitionError::CloseLimit)?;
        for entry in terminal.vector.entries() {
            accounts.insert(account_key(&entry.recipient)?, entry.recipient.clone());
        }
        if accounts.len() as u64 > limits.max_rows()
            || accounts.len() > commitment::MAX_VECTOR_LENGTH as usize
        {
            return Err(TransitionError::CloseLimit);
        }
    }
    for account in deposits
        .records()
        .iter()
        .map(|record| record.account())
        .chain(
            withdrawals
                .requests()
                .iter()
                .map(|request| request.account()),
        )
    {
        accounts.insert(account_key(account)?, account.clone());
    }
    if accounts.len() as u64 > limits.max_rows()
        || accounts.len() > commitment::MAX_VECTOR_LENGTH as usize
    {
        return Err(TransitionError::CloseLimit);
    }
    let mut rows = Vec::with_capacity(accounts.len());
    let mut signatures = Vec::with_capacity(terminals.len());
    let mut terminal = terminals.into_iter().peekable();
    for account in accounts.into_values() {
        let (outgoing, vector) = match terminal.peek() {
            Some(next) if next.authorization.body().payer() == &account => {
                let next = terminal.next().expect("peeked terminal");
                signatures.push(next.operator_signature);
                (
                    Some((
                        next.authorization.body().seq(),
                        next.authorization.payer_signature().clone(),
                    )),
                    next.vector,
                )
            }
            _ => (
                None,
                OutVector::empty(context.payment().epoch(), account.clone()),
            ),
        };
        rows.push(posted::Row {
            account,
            outgoing,
            vector,
        });
    }
    if terminal.next().is_some() {
        return Err(TransitionError::NonCanonicalRows);
    }
    let aggregate = NonEmpty::try_new(signatures.iter()).map(combine_signatures);
    derive::<H, P, D, E, S>(
        state,
        context,
        deposits,
        withdrawals,
        rows,
        aggregate,
        None,
        strategy,
    )
    .await
}

/// Authenticates the full dealing against the retained predecessor before any state installation.
#[allow(clippy::too_many_arguments)]
pub async fn validate_close_with_strategy<H, P, D, E, S, B, R>(
    state: &State<E, H, S>,
    context: &CloseContext<P, D>,
    operator: &OperatorKey,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    dealing: Dealing<P, D>,
    rng: &mut R,
    strategy: &S,
) -> Result<PreparedClose<P, D, S>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    E: Context + Spawner,
    S: Strategy,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
{
    let expected = dealing.header;
    let aggregate = dealing.aggregate;
    let prepared = derive::<H, P, D, E, S>(
        state,
        context,
        deposits,
        withdrawals,
        dealing.rows,
        aggregate.clone(),
        Some(dealing.encoded),
        strategy,
    )
    .await?;
    if expected != prepared.close.header {
        return Err(TransitionError::HeaderRoot);
    }
    if !verify_ack_signatures::<P, D, B, R, _>(
        prepared
            .close
            .rows
            .iter()
            .filter_map(|row| row.outgoing.as_ref()),
        rng,
        strategy,
    ) {
        return Err(TransitionError::Ack(AckError::InvalidPayerSignature));
    }
    verify_operator_aggregate(operator, &prepared.close.rows, aggregate.as_ref(), strategy)?;
    Ok(prepared)
}

#[allow(clippy::too_many_arguments)]
async fn derive<H, P, D, E, S>(
    state: &State<E, H, S>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    input: Vec<posted::Row<P>>,
    aggregate: Option<OperatorAggregate>,
    encoded: Option<Bytes>,
    strategy: &S,
) -> Result<PreparedClose<P, D, S>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    E: Context + Spawner,
    S: Strategy,
{
    validate_predecessor::<H, P, D, E, S>(state, context, deposits, withdrawals).await?;
    let limits = context.limits();
    if input.len() as u64 > limits.max_rows()
        || input.len() > commitment::MAX_VECTOR_LENGTH as usize
    {
        return Err(TransitionError::CloseLimit);
    }
    if input
        .windows(2)
        .any(|pair| pair[0].account.as_ref() >= pair[1].account.as_ref())
    {
        return Err(TransitionError::NonCanonicalRows);
    }
    for account in deposits
        .records()
        .iter()
        .map(|r| r.account().as_ref())
        .chain(withdrawals.requests().iter().map(|r| r.account().as_ref()))
    {
        if input
            .binary_search_by(|row| row.account.as_ref().cmp(account.as_ref()))
            .is_err()
        {
            return Err(TransitionError::BoundaryAccountMissing);
        }
    }
    let keys = input
        .iter()
        .map(|row| account_key(&row.account))
        .collect::<Result<Vec<_>, _>>()?;
    let balances = state.get_many(&keys.iter().collect::<Vec<_>>()).await?;
    let mut incoming = vec![(0_u64, 0_u64); input.len()];
    let mut edge_count = 0_u64;
    let mut gross = 0_u64;
    for row in &input {
        if row.vector.payer() != &row.account || row.vector.epoch() != context.payment().epoch() {
            return Err(TransitionError::VectorAlignment);
        }
        let entries = row.vector.entries();
        if entries.len() as u64 > limits.max_account_entries() {
            return Err(TransitionError::CloseLimit);
        }
        let (debit, _) = row.vector.totals()?;
        if row.outgoing.is_some() != !entries.is_empty() {
            return Err(TransitionError::OutgoingPresence);
        }
        edge_count = edge_count
            .checked_add(entries.len() as u64)
            .filter(|n| *n <= limits.max_total_entries())
            .ok_or(TransitionError::CloseLimit)?;
        gross = gross
            .checked_add(debit)
            .filter(|n| *n <= limits.max_payment_total())
            .ok_or(TransitionError::CloseLimit)?;
        for entry in entries {
            let index = input
                .binary_search_by(|row| row.account.as_ref().cmp(entry.recipient.as_ref()))
                .map_err(|_| TransitionError::UnknownAccount)?;
            let slot = &mut incoming[index];
            slot.0 = slot
                .0
                .checked_add(entry.cumulative)
                .ok_or(TransitionError::Arithmetic)?;
            slot.1 = slot
                .1
                .checked_add(1)
                .filter(|n| *n <= limits.max_account_entries())
                .ok_or(TransitionError::CloseLimit)?;
        }
    }
    let mut amounts = CloseAmounts::default();
    let mut rows = Vec::with_capacity(input.len());
    let mut vectors = Vec::with_capacity(input.len());
    let mut updates = Vec::new();
    let mut leaves = Vec::with_capacity(input.len());
    for (((input, old), key), (credit, in_count)) in
        input.into_iter().zip(balances).zip(keys).zip(incoming)
    {
        let predecessor = old.map_or(0, NonZeroU64::get);
        let deposit = deposits.amount_for(&input.account);
        let request = withdrawals.request_for(&input.account);
        let debit = input.vector.totals()?.0;
        if input.outgoing.is_none() && in_count == 0 && deposit == 0 && request.is_none() {
            return Err(TransitionError::AccountActivity);
        }
        let registered = predecessor != 0 || deposit != 0;
        if !registered && (credit == 0 || request.is_some() || debit != 0) {
            return Err(TransitionError::AccountActivity);
        }
        let tail = (u128::from(predecessor) + u128::from(deposit) + u128::from(credit))
            .checked_sub(u128::from(debit))
            .ok_or(TransitionError::BalanceEquation)?;
        let withdrawal = match request.map(|request| request.body().action()) {
            Some(WithdrawalAction::Amount(amount)) if u128::from(amount.get()) <= tail => {
                amount.get()
            }
            Some(WithdrawalAction::Close) => {
                u64::try_from(tail).map_err(|_| TransitionError::Arithmetic)?
            }
            _ => 0,
        };
        let payout = if registered { 0 } else { credit };
        let successor = tail
            .checked_sub(u128::from(withdrawal))
            .and_then(|n| n.checked_sub(u128::from(payout)))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(TransitionError::BalanceEquation)?;
        let output = if request.is_some() {
            SettlementOutput::Withdrawal(withdrawal)
        } else if payout > 0 {
            SettlementOutput::ExternalPayout(payout)
        } else {
            SettlementOutput::None
        };
        amounts.withdrawal = amounts
            .withdrawal
            .checked_add(withdrawal)
            .ok_or(TransitionError::Arithmetic)?;
        amounts.payout = amounts
            .payout
            .checked_add(payout)
            .ok_or(TransitionError::Arithmetic)?;
        let send_root = input.vector.root::<H, D>()?;
        let outgoing = input.outgoing.map(|(seq, signature)| {
            SendAuthorization::from_raw_unchecked(
                VectorSendBody::new(
                    context.payment(),
                    input.account.clone(),
                    seq,
                    debit,
                    send_root,
                ),
                signature,
            )
        });
        let row = AccountRow {
            account: input.account,
            predecessor,
            successor,
            outgoing,
            output,
        };
        leaves.push(AccountChange::from_row(&row, send_root));
        if predecessor != successor {
            updates.push((key, NonZeroU64::new(successor)));
        }
        rows.push(row);
        vectors.push(input.vector);
    }
    let guards = strategy.map_collect_vec(leaves.iter(), |leaf| leaf.guard::<H>());
    let mut builder = commitment::Builder::<H>::new(VectorKind::Change, leaves.len() as u32)?;
    builder.add_values(&guards, strategy)?;
    let changes = Arc::new(ChallengeIndex {
        leaves: Arc::new(leaves),
        guards: Arc::new(guards),
        tree: Arc::new(builder.build(strategy)?),
    });
    let mut outputs = Vec::with_capacity(withdrawals.len());
    let mut withdrawal_rows = Vec::with_capacity(withdrawals.len());
    for request in withdrawals.requests() {
        let index = rows
            .binary_search_by(|row| row.account.as_ref().cmp(request.account().as_ref()))
            .map_err(|_| TransitionError::BoundaryAccountMissing)?;
        let SettlementOutput::Withdrawal(amount) = rows[index].output else {
            return Err(TransitionError::SettlementOutput);
        };
        outputs.push(WithdrawalOutput::from_request(request, amount));
        withdrawal_rows.push(index);
    }
    let mut builder = commitment::Builder::<H>::new(
        VectorKind::WithdrawalOutput,
        u32::try_from(outputs.len()).map_err(|_| TransitionError::CloseLimit)?,
    )?;
    builder.add_values(&outputs, strategy)?;
    let withdrawal_tree = builder.build(strategy)?;
    let candidate = state.prepare(state.head(), updates).await?;
    if candidate.head().live_accounts() > limits.max_states() {
        return Err(TransitionError::CloseLimit);
    }
    let roots = RootBundle {
        change: changes.root(),
        withdrawal_outputs: withdrawal_tree.root(),
        successor: candidate.root(),
    };
    let liability =
        validate_close_amounts::<H, P, D>(context, deposits, withdrawals, &roots, &amounts)?;
    if candidate.head().liability() != liability {
        return Err(TransitionError::LiabilityEquation);
    }
    let header = Header::new::<H, P>(context, &roots, &amounts);
    let encoded = match encoded {
        Some(encoded) => encoded,
        None => posted::encode(&header, &rows, &vectors, aggregate.as_ref())?,
    };
    Ok(PreparedClose {
        close: Close {
            header,
            roots,
            amounts,
            rows,
            out_vectors: vectors,
            encoded,
            changes,
            withdrawals: outputs,
            withdrawal_rows,
            withdrawal_tree,
        },
        state: candidate,
    })
}

async fn validate_predecessor<H, P, D, E, S>(
    state: &State<E, H, S>,
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
) -> Result<(), TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    E: Context + Spawner,
    S: Strategy,
{
    if state.root() != *context.predecessor_root() {
        return Err(TransitionError::PredecessorRoot);
    }
    if state.liability() != context.predecessor_liability() {
        return Err(TransitionError::PredecessorLiability);
    }
    if state.live_accounts() > context.limits().max_states() {
        return Err(TransitionError::CloseLimit);
    }
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;
    let keys = withdrawals
        .requests()
        .iter()
        .map(|request| account_key(request.account()))
        .collect::<Result<Vec<_>, _>>()?;
    let balances = state.get_many(&keys.iter().collect::<Vec<_>>()).await?;
    for (request, balance) in withdrawals.requests().iter().zip(balances) {
        let balance = balance.map_or(0, NonZeroU64::get);
        let deposit = deposits.amount_for(request.account());
        match request.body().action() {
            WithdrawalAction::Amount(amount)
                if u128::from(amount.get()) > u128::from(balance) + u128::from(deposit) =>
            {
                return Err(TransitionError::WithdrawalCoverage);
            }
            WithdrawalAction::Close if balance == 0 && deposit == 0 => {
                return Err(TransitionError::BoundaryNoStateChange);
            }
            _ => {}
        }
    }
    Ok(())
}

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
        (Some(messages), Some(signature)) => verify_same_signer::<OperatorVariant>(
            operator,
            &combine_messages::<OperatorVariant, _>(messages, strategy),
            signature,
        )
        .map_err(|_| TransitionError::Ack(AckError::InvalidOperatorSignature)),
        _ => Err(TransitionError::Ack(AckError::InvalidOperatorSignature)),
    }
}

/// Checks that the complete descriptor reconstructs the claimed header.
pub fn validate_header<H: Hasher<Digest = D>, P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
    amounts: &CloseAmounts,
) -> Result<(), TransitionError> {
    if header.verify::<H, P>(context, roots, amounts) {
        Ok(())
    } else {
        Err(TransitionError::HeaderRoot)
    }
}
/// Checks settlement-visible bounds and derives successor liability from registered deposits.
pub fn validate_close_amounts<H: Hasher<Digest = D>, P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    roots: &RootBundle<D>,
    amounts: &CloseAmounts,
) -> Result<u64, TransitionError> {
    validate_boundary_roots::<H, P, D>(context, deposits, withdrawals)?;
    let limits = context.limits();
    if amounts.withdrawal > limits.max_withdrawal_total()
        || amounts.payout > limits.max_payment_total()
    {
        return Err(TransitionError::CloseLimit);
    }
    if withdrawals.is_empty()
        && (amounts.withdrawal != 0
            || roots.withdrawal_outputs
                != commitment::empty_root::<H>(VectorKind::WithdrawalOutput))
    {
        return Err(TransitionError::WithdrawalOutputRoot);
    }
    checked_successor_liability(
        context.predecessor_liability(),
        deposits.total(),
        amounts.withdrawal,
        amounts.payout,
    )
}
pub(crate) fn validate_boundary_roots<H: Hasher<Digest = D>, P: PublicKey, D: Digest>(
    context: &CloseContext<P, D>,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
) -> Result<(), TransitionError> {
    if !context.epoch.verify_anchor::<H>() {
        return Err(TransitionError::EpochAnchor);
    }
    if deposits.root::<H>()? != *context.deposit_root()
        || withdrawals.root::<H>()? != *context.withdrawal_root()
    {
        return Err(TransitionError::BoundaryRoot);
    }
    Ok(())
}
fn validate_boundary_batches<P: PublicKey, D: Digest>(
    deployment: &D,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    limits: &CloseLimits,
) -> Result<(), TransitionError> {
    withdrawals.verify_deployment(deployment)?;
    let accounts = deposits
        .records()
        .iter()
        .map(|r| r.account().as_ref())
        .chain(withdrawals.requests().iter().map(|r| r.account().as_ref()))
        .collect::<BTreeSet<_>>();
    if accounts.len() as u64 > limits.max_rows()
        || withdrawals.len() as u64 > limits.max_withdrawals()
        || deposits.total() > limits.max_deposit_total()
    {
        return Err(TransitionError::CloseLimit);
    }
    Ok(())
}
pub(crate) fn checked_successor_liability(
    predecessor: u64,
    deposits: u64,
    withdrawals: u64,
    payouts: u64,
) -> Result<u64, TransitionError> {
    let value = (u128::from(predecessor) + u128::from(deposits))
        .checked_sub(u128::from(withdrawals))
        .and_then(|n| n.checked_sub(u128::from(payouts)))
        .ok_or(TransitionError::LiabilityEquation)?;
    u64::try_from(value).map_err(|_| TransitionError::LiabilityOverflow)
}

/// Invalid close data, context, authentication, or state operation.
#[derive(Debug, Error)]
pub enum TransitionError {
    /// The payment anchor does not authenticate the supplied epoch parameters.
    #[error("epoch parameters do not match the payment anchor")]
    EpochAnchor,

    /// Header/context mismatch.
    #[error("invalid close header")]
    HeaderRoot,
    /// A different predecessor was supplied.
    #[error("wrong predecessor root")]
    PredecessorRoot,
    /// Registered liability differs from retained state.
    #[error("wrong predecessor liability")]
    PredecessorLiability,
    /// Accounts must be uniquely sorted by canonical key bytes.
    #[error("noncanonical account order")]
    NonCanonicalRows,
    /// A vector is not aligned with its account/epoch.
    #[error("vector alignment mismatch")]
    VectorAlignment,
    /// An entry references no activity account.
    #[error("unknown recipient")]
    UnknownAccount,
    /// A close exceeds a registered or representation bound.
    #[error("close limit exceeded")]
    CloseLimit,
    /// An activity projection exceeds the BMT bound.
    #[error("too many activity rows")]
    TooManyRows,
    /// A body does not authorize the disclosed vector.
    #[error("terminal endpoint mismatch")]
    OutgoingEndpoint,
    /// Sender signature presence must match a nonempty vector.
    #[error("outgoing presence mismatch")]
    OutgoingPresence,
    /// An account has no disclosed activity or cannot perform that activity.
    #[error("invalid account activity")]
    AccountActivity,
    /// Balances do not satisfy the authorized equation.
    #[error("invalid balance equation")]
    BalanceEquation,
    /// Checked close arithmetic overflowed.
    #[error("close arithmetic overflow")]
    Arithmetic,
    /// A boundary root differs from registration.
    #[error("wrong boundary root")]
    BoundaryRoot,
    /// A registered participant was omitted.
    #[error("missing boundary participant")]
    BoundaryAccountMissing,
    /// An absent account cannot request closure without a deposit.
    #[error("withdrawal has no eligible account")]
    BoundaryNoStateChange,
    /// Initial funds do not cover a requested amount.
    #[error("uncovered withdrawal")]
    WithdrawalCoverage,
    /// The derived output has the wrong action.
    #[error("invalid settlement output")]
    SettlementOutput,
    /// Live balances do not equal the derived liability.
    #[error("invalid liability equation")]
    LiabilityEquation,
    /// Liability cannot be represented.
    #[error("liability overflow")]
    LiabilityOverflow,
    /// Activity values do not match their committed root.
    #[error("wrong activity root")]
    ChangeRoot,
    /// Withdrawal outputs do not match their committed root.
    #[error("wrong withdrawal output root")]
    WithdrawalOutputRoot,
    /// No valid withdrawal claim exists for the account.
    #[error("invalid withdrawal claim")]
    WithdrawalClaim,
    /// No positive external payout exists for the account.
    #[error("invalid external payout claim")]
    PayoutClaim,
    /// Registration deadlines are not ordered.
    #[error("invalid deadline order")]
    DeadlineOrder,
    /// Boundary construction or authentication failed.
    #[error(transparent)]
    Boundary(#[from] BoundaryError),
    /// Payer or operator authentication failed.
    #[error(transparent)]
    Ack(#[from] AckError),
    /// Vector validation failed.
    #[error(transparent)]
    Vector(#[from] vector::Error),
    /// BMT construction or proof verification failed.
    #[error(transparent)]
    Commitment(#[from] commitment::Error),
    /// Keyed dealing decoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Current state operation failed.
    #[error(transparent)]
    State(#[from] qmdb::Error),
}
