//! Settlement transactions carried by chain blocks, and their request bodies.
//!
//! Each [`SettlementTx`] variant carries one bounded request struct. The
//! request codecs live here with the transaction enum: they are the chain's
//! settlement input surface, shared by execution ([`crate::chain::state`]),
//! the query server ([`crate::chain::query`]), and the wallet and operator
//! clients ([`crate::chain::client`]).
//!
//! # Routing, authorization, and replay
//!
//! Deployment requests name their target explicitly; execution verifies every header, batch,
//! signature, and opening against that target's state. Native transfers and deployment creation
//! use the chain domain. Claim-deposit composition names both its source claim and destination
//! deposit. Routing provides scheduling information, never authorization.
//!
//! Every native debit binds the complete signed intent to the immutable chain identity.
//! Deposit IDs, transfer IDs scoped to the signing account, deployment configuration IDs,
//! epoch sequence, and claim positions own replay protection. There is no shared wallet nonce.
//! Any peer may relay signed requests or proof-authenticated claims; all authoritative checks
//! run during block execution. Fees are exact signed operator costs fixed by genesis policy.
//!
//! | Variant | Who may land it | Enforced by (at execution) | Replay guard |
//! |---|---|---|---|
//! | `RegisterDeployment` | operator | signed complete configuration, native fee and resource bounds | configuration-derived deployment ID |
//! | `NativeTransfer` | debit owner | signature and native balance | (sender, transfer ID) |
//! | `Deposit` | account holder | signature, native debit and clearing custody intake | consumed deposit ID |
//! | `ClaimDeposit` | native credit recipient | finalized claim and signed destination deposit applied atomically | source claim position and destination deposit ID |
//! | `QueueWithdrawal` | the account holder | the account signature inside [`SignedWithdrawal`], verified with its deployment and root context | account queue slot and withdrawal replay id (`WithdrawalConflict`) |
//! | `RegisterEpoch` | the operator | the operator signature over exact boundary material and native fee | registration record and epoch sequence (`RegistrationConflict`, `EpochSequence`) |
//! | `Admit` | anyone holding a genuine certificate | the committee certificate over the exact header (exact quorum, verified aggregate) against the chain's own registration | registration admitted mark and admitted record (`AdmissionConflict`) |
//! | `ClaimWithdrawal` | anyone holding bound evidence | the claim opening against the finalized batch's withdrawal-outputs root; funds go to the certified destination | consumed (batch, position) and its release record |
//! | `ClaimExternalPayout` | anyone holding bound evidence | the claim opening against the finalized batch's change root; funds go to the certified receiver | consumed (batch, position) and its release record |
//! | `Challenge` | any holder of contradiction evidence (bearer, by design) | challenge adjudication over the admitted close | one proven challenge per batch (`ChallengeConflict`) |
//! | `BeginHardFaultSettlement` | anyone, once a real deadline expired or a challenge proved | the chain's own hard-fault flag (block production observes every deadline) | idempotent snapshot, then `HardFaultAlreadySettled` |
//! | `ClaimHardFault` | anyone holding the account's frozen-root opening; funds go to the opened account and its signed withdrawal | the state opening against the frozen root | consumed opening position and its release record (`PositionConflict`) |
//! | `ClaimPendingDeposit` | anyone (the refund is fixed to the account) | the chain's own staged-deposit record after a fault | consumed staged deposit and its refund record |

use crate::{
    chain::native::{NativeGenesis, RegistryEntry},
    protocol::{
        Account, Deployment, DepositEvent, Key, MAX_ACCOUNTS, MAX_DESTINATION_BYTES,
        SettlementResult,
    },
};
use bytes::{Buf, BufMut, Bytes};
use commonware_clearing::bajillion::{
    admission::bls12381::Certificate,
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalBatch},
    commitment::VectorRoot,
    qmdb::StateOpening,
    transition::{
        BatchId, CloseAmounts, ExternalPayoutClaim, Header, OperatorKey, RootBundle,
        WithdrawalClaim,
    },
};
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519, sha256::Digest};
use commonware_cryptography_curve25519::signing::{Signature, SigningKey};

const NATIVE_TRANSFER_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_NATIVE_TRANSFER";
const DEPOSIT_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_NATIVE_DEPOSIT";
const DEPLOYMENT_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_NATIVE_REGISTER";
const DEPLOYMENT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_NATIVE_DEPLOYMENT";

/// Signed creation of an immutable operator deployment with zero initial custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisterDeploymentRequest {
    pub(crate) chain_id: Digest,
    pub(crate) registration_id: Digest,
    pub(crate) operator: Key,
    pub(crate) operator_ack: OperatorKey,
    pub(crate) network_key: ed25519::PublicKey,
    pub(crate) accounts: Vec<Key>,
    pub(crate) max_dealing_bytes: u32,
    pub(crate) fee: u64,
    pub(crate) signature: Signature,
}

#[allow(clippy::too_many_arguments)]
fn registration_message(
    chain_id: Digest,
    registration_id: Digest,
    operator: &Key,
    operator_ack: OperatorKey,
    network_key: &ed25519::PublicKey,
    accounts: &[Key],
    max_dealing_bytes: u32,
    fee: u64,
) -> Bytes {
    (
        chain_id,
        registration_id,
        operator.clone(),
        operator_ack,
        network_key.clone(),
        accounts,
        max_dealing_bytes,
        fee,
    )
        .encode()
}

impl RegisterDeploymentRequest {
    /// Signs the deployment configuration and its exact native registration cost.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        chain_id: Digest,
        registration_id: Digest,
        operator_ack: OperatorKey,
        network_key: ed25519::PublicKey,
        accounts: Vec<Key>,
        max_dealing_bytes: u32,
        fee: u64,
        signer: &SigningKey,
    ) -> Self {
        let operator = signer.public_key();
        let message = registration_message(
            chain_id,
            registration_id,
            &operator,
            operator_ack,
            &network_key,
            &accounts,
            max_dealing_bytes,
            fee,
        );
        Self {
            chain_id,
            registration_id,
            operator,
            operator_ack,
            network_key,
            accounts,
            max_dealing_bytes,
            fee,
            signature: signer.sign(DEPLOYMENT_SIGNATURE_NAMESPACE, &message),
        }
    }

    fn message(&self) -> Bytes {
        registration_message(
            self.chain_id,
            self.registration_id,
            &self.operator,
            self.operator_ack,
            &self.network_key,
            &self.accounts,
            self.max_dealing_bytes,
            self.fee,
        )
    }

    /// Replay domain committing to the complete unsigned deployment configuration.
    pub(crate) fn deployment_id(&self) -> Digest {
        Sha256::hash(&[DEPLOYMENT_ID_NAMESPACE, &self.message()])
    }

    /// Derives the canonical zero-custody entry. Admission validates its authorization and bounds.
    pub(crate) fn entry(&self, native: &NativeGenesis) -> anyhow::Result<RegistryEntry> {
        let mut accounts = self
            .accounts
            .iter()
            .cloned()
            .map(|key| Account { key, balance: 0 })
            .collect::<Vec<_>>();
        accounts.sort_unstable_by(|left, right| left.key.cmp(&right.key));
        Ok(RegistryEntry {
            deployment: Deployment::configured(
                self.deployment_id(),
                self.operator.clone(),
                self.operator_ack,
                accounts,
                native.empty_root,
                native.empty_operations,
            )?,
            network_key: self.network_key.clone(),
            max_dealing_bytes: self.max_dealing_bytes,
        })
    }

    /// Authenticates every mutable registration field under its native chain domain.
    pub(crate) fn verify(&self, chain_id: &Digest) -> bool {
        self.chain_id == *chain_id
            && self.operator.verify(
                DEPLOYMENT_SIGNATURE_NAMESPACE,
                &self.message(),
                &self.signature,
            )
    }
}

impl Write for RegisterDeploymentRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.chain_id.write(buf);
        self.registration_id.write(buf);
        self.operator.write(buf);
        self.operator_ack.write(buf);
        self.network_key.write(buf);
        self.accounts.write(buf);
        self.max_dealing_bytes.write(buf);
        self.fee.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for RegisterDeploymentRequest {
    fn encode_size(&self) -> usize {
        self.chain_id.encode_size()
            + self.registration_id.encode_size()
            + self.operator.encode_size()
            + self.operator_ack.encode_size()
            + self.network_key.encode_size()
            + self.accounts.encode_size()
            + self.max_dealing_bytes.encode_size()
            + self.fee.encode_size()
            + self.signature.encode_size()
    }
}

impl Read for RegisterDeploymentRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: Digest::read(buf)?,
            registration_id: Digest::read(buf)?,
            operator: Key::read(buf)?,
            operator_ack: OperatorKey::read(buf)?,
            network_key: ed25519::PublicKey::read(buf)?,
            accounts: Vec::<Key>::read_cfg(buf, &(RangeCfg::new(0..=MAX_ACCOUNTS), ()))?,
            max_dealing_bytes: u32::read(buf)?,
            fee: u64::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

/// Signed transfer between native accounts, independent of clearing deployments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeTransferRequest {
    pub(crate) chain_id: Digest,
    pub(crate) id: Digest,
    pub(crate) from: Key,
    pub(crate) to: Key,
    pub(crate) amount: u64,
    pub(crate) signature: Signature,
}

impl NativeTransferRequest {
    pub(crate) fn sign(
        chain_id: Digest,
        id: Digest,
        to: Key,
        amount: u64,
        signer: &SigningKey,
    ) -> Self {
        let from = signer.public_key();
        let signature = signer.sign(
            NATIVE_TRANSFER_NAMESPACE,
            &(chain_id, id, from.clone(), to.clone(), amount).encode(),
        );
        Self {
            chain_id,
            id,
            from,
            to,
            amount,
            signature,
        }
    }

    pub(crate) fn verify(&self, chain_id: &Digest) -> bool {
        self.chain_id == *chain_id
            && self.from.verify(
                NATIVE_TRANSFER_NAMESPACE,
                &(
                    self.chain_id,
                    self.id,
                    self.from.clone(),
                    self.to.clone(),
                    self.amount,
                )
                    .encode(),
                &self.signature,
            )
    }
}

impl Write for NativeTransferRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.chain_id.write(buf);
        self.id.write(buf);
        self.from.write(buf);
        self.to.write(buf);
        self.amount.write(buf);
        self.signature.write(buf);
    }
}
impl EncodeSize for NativeTransferRequest {
    fn encode_size(&self) -> usize {
        self.chain_id.encode_size()
            + self.id.encode_size()
            + self.from.encode_size()
            + self.to.encode_size()
            + self.amount.encode_size()
            + self.signature.encode_size()
    }
}
impl Read for NativeTransferRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: Digest::read(buf)?,
            id: Digest::read(buf)?,
            from: Key::read(buf)?,
            to: Key::read(buf)?,
            amount: u64::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

/// Maximum entries accepted in one deposit or withdrawal batch.
const MAX_BATCH_ITEMS: usize = 1_024;

/// Maximum predecessor-root openings accepted alongside one queued withdrawal.
const MAX_STATE_OPENINGS: usize = 5;

/// Certificate participant-bitmap length for the fixed clearing committee.
const CERTIFICATE_PARTICIPANTS: usize = 4;

/// Bounds one encoded challenge. The largest canonical challenge is a higher acknowledged
/// entry: one fixed-size acknowledgment witness with its retained entry opening, plus a
/// composed sender lookup carrying two more openings (the change-vector membership proof
/// and the entry lookup under the reconstructed vector root). 32 KiB covers that maximum
/// with generous headroom and stays far below the 4 MiB frame budget.
///
/// No challenge size depends on the operator's account count. The fork family carries two
/// fixed-size acknowledgment witnesses and no openings at all, and the opening-carrying
/// families are depth-bounded structurally: every opening decodes at most `bmt::MAX_LEVELS`
/// sibling hashes per position, and their lookup leaves are fixed size.
pub(crate) const MAX_CHALLENGE_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChallengeRequest {
    pub(crate) deployment: Digest,
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) evidence: Bytes,
}

impl Write for ChallengeRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.batch_id.write(buf);
        self.evidence.write(buf);
    }
}

impl EncodeSize for ChallengeRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size() + self.batch_id.encode_size() + self.evidence.encode_size()
    }
}

impl Read for ChallengeRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            batch_id: BatchId::read(buf)?,
            evidence: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_CHALLENGE_BYTES))?,
        })
    }
}

/// Begins one deployment's terminal hard-fault settlement. The deployment is
/// named explicitly: the transition carries no other identifying field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BeginHardFaultSettlementRequest {
    pub(crate) deployment: Digest,
}

impl Write for BeginHardFaultSettlementRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
    }
}

impl EncodeSize for BeginHardFaultSettlementRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
    }
}

impl Read for BeginHardFaultSettlementRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
        })
    }
}

/// Claims one account's hard-fault release. The deployment is named
/// explicitly: deployments may configure the same accounts at the same
/// balances, so the opening's frozen-root proof alone cannot select one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimHardFaultRequest {
    pub(crate) deployment: Digest,
    pub(crate) opening: StateOpening<Key, Digest>,
}

impl Write for ClaimHardFaultRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.opening.write(buf);
    }
}

impl EncodeSize for ClaimHardFaultRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size() + self.opening.encode_size()
    }
}

impl Read for ClaimHardFaultRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let deployment = Digest::read(buf)?;
        let opening = StateOpening::read_cfg(buf, &super::query::MAX_PROOF_DIGESTS)?;
        Ok(Self {
            deployment,
            opening,
        })
    }
}

/// Refunds one account's stranded deposits after a fault. The deployment is
/// named explicitly: the account may hold staged deposits in several
/// deployments at once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimPendingDepositRequest {
    pub(crate) deployment: Digest,
    pub(crate) account: Key,
}

impl Write for ClaimPendingDepositRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.account.write(buf);
    }
}

impl EncodeSize for ClaimPendingDepositRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size() + self.account.encode_size()
    }
}

impl Read for ClaimPendingDepositRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            account: Key::read(buf)?,
        })
    }
}

/// A native-account debit funding the same account in one clearing deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DepositRequest {
    pub(crate) chain_id: Digest,
    pub(crate) deployment: Digest,
    pub(crate) event: DepositEvent,
    pub(crate) signature: Signature,
}

impl DepositRequest {
    /// Signs the complete deposit intent. The event identifier owns replay protection.
    pub(crate) fn sign(
        chain_id: Digest,
        deployment: Digest,
        event: DepositEvent,
        signer: &SigningKey,
    ) -> Self {
        let message = (chain_id, deployment, event.clone()).encode();
        Self {
            chain_id,
            deployment,
            event,
            signature: signer.sign(DEPOSIT_SIGNATURE_NAMESPACE, &message),
        }
    }

    /// Authenticates the native debit owner and immutable chain replay domain.
    pub(crate) fn verify(&self, chain_id: &Digest) -> bool {
        self.chain_id == *chain_id
            && self.event.account.verify(
                DEPOSIT_SIGNATURE_NAMESPACE,
                &(self.chain_id, self.deployment, self.event.clone()).encode(),
                &self.signature,
            )
    }
}

impl Write for DepositRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.chain_id.write(buf);
        self.deployment.write(buf);
        self.event.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for DepositRequest {
    fn encode_size(&self) -> usize {
        self.chain_id.encode_size()
            + self.deployment.encode_size()
            + self.event.encode_size()
            + self.signature.encode_size()
    }
}

impl Read for DepositRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: Digest::read(buf)?,
            deployment: Digest::read(buf)?,
            event: DepositEvent::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QueueWithdrawalRequest {
    pub(crate) request: SignedWithdrawal<Key, Digest>,
    pub(crate) openings: Vec<StateOpening<Key, Digest>>,
}

impl Write for QueueWithdrawalRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request.write(buf);
        self.openings.write(buf);
    }
}

impl EncodeSize for QueueWithdrawalRequest {
    fn encode_size(&self) -> usize {
        self.request.encode_size() + self.openings.encode_size()
    }
}

impl Read for QueueWithdrawalRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            request: SignedWithdrawal::read_cfg(buf, &RangeCfg::new(0..=MAX_DESTINATION_BYTES))?,
            openings: Vec::<StateOpening<Key, Digest>>::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_STATE_OPENINGS),
                    super::query::MAX_PROOF_DIGESTS,
                ),
            )?,
        })
    }
}

/// One epoch registration: exactly the boundary material the operator
/// legitimately chooses, covered by its signature.
///
/// The deposit boundary travels as the signed root of the batch the operator built its
/// context from. Execution derives the exact records from the chain's own custody state,
/// so a diverging deposit view is rejected at registration without consuming the slot.
///
/// The registration carries no timing: execution assigns the admission and
/// challenge deadlines from the inclusion height under the chain-wide
/// genesis policy and derives the payment anchor itself, so the operator
/// learns both from the certified registration record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisterEpochRequest {
    /// The deployment the epoch registers under, covered by the signature.
    pub(crate) deployment: Digest,
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) deposits_root: VectorRoot<Digest>,
    /// Root of the operator's full staged deposit set, deferred aggregates included, so a
    /// deposit view divergence a deferral hides from the boundary is still rejected.
    pub(crate) staged_root: VectorRoot<Digest>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    /// One predecessor-root opening per withdrawal in batch order. Execution selects the
    /// ones proving its operator-carried extras certifiable.
    pub(crate) openings: Vec<StateOpening<Key, Digest>>,
    pub(crate) fee: u64,
    pub(crate) signature: Signature,
}

impl Write for RegisterEpochRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.epoch.write(buf);
        self.predecessor_liability.write(buf);
        self.deposits_root.write(buf);
        self.staged_root.write(buf);
        self.withdrawals.write(buf);
        self.openings.write(buf);
        self.fee.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for RegisterEpochRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + self.epoch.encode_size()
            + self.predecessor_liability.encode_size()
            + self.deposits_root.encode_size()
            + self.staged_root.encode_size()
            + self.withdrawals.encode_size()
            + self.openings.encode_size()
            + self.fee.encode_size()
            + self.signature.encode_size()
    }
}

impl Read for RegisterEpochRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            epoch: u64::read(buf)?,
            predecessor_liability: u64::read(buf)?,
            deposits_root: VectorRoot::read(buf)?,
            staged_root: VectorRoot::read(buf)?,
            withdrawals: WithdrawalBatch::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_BATCH_ITEMS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            openings: Vec::<StateOpening<Key, Digest>>::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_BATCH_ITEMS),
                    super::query::MAX_PROOF_DIGESTS,
                ),
            )?,
            fee: u64::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmitRequest {
    /// Routing field naming the deployment whose registration the close
    /// admits against. Unsigned by design: the committee certificate over
    /// the header is the sole authorization, and every check runs against
    /// the named deployment's own records, so naming the wrong deployment
    /// only earns a typed rejection there.
    pub(crate) deployment: Digest,
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) amounts: CloseAmounts,
    pub(crate) certificate: Certificate,
}

impl From<&SettlementResult> for AdmitRequest {
    fn from(result: &SettlementResult) -> Self {
        Self {
            deployment: *result.epoch_context.deployment(),
            epoch: result.epoch,
            predecessor_liability: result.epoch_context.predecessor_liability(),
            deposits: result.deposits.clone(),
            withdrawals: result.withdrawals.clone(),
            header: result.header,
            roots: result.roots,
            amounts: result.amounts,
            certificate: result.certificate.clone(),
        }
    }
}

impl Write for AdmitRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.epoch.write(buf);
        self.predecessor_liability.write(buf);
        self.deposits.write(buf);
        self.withdrawals.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.amounts.write(buf);
        self.certificate.write(buf);
    }
}

impl EncodeSize for AdmitRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + self.epoch.encode_size()
            + self.predecessor_liability.encode_size()
            + self.deposits.encode_size()
            + self.withdrawals.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.amounts.encode_size()
            + self.certificate.encode_size()
    }
}

impl Read for AdmitRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let request = Self {
            deployment: Digest::read(buf)?,
            epoch: u64::read(buf)?,
            predecessor_liability: u64::read(buf)?,
            deposits: DepositBatch::read_cfg(buf, &RangeCfg::new(0..=MAX_BATCH_ITEMS))?,
            withdrawals: WithdrawalBatch::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_BATCH_ITEMS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            amounts: CloseAmounts::read(buf)?,
            certificate: Certificate::read_cfg(buf, &CERTIFICATE_PARTICIPANTS)?,
        };
        if request.certificate.signers.len() != CERTIFICATE_PARTICIPANTS {
            return Err(CodecError::Invalid(
                "clearing_terminal::AdmitRequest",
                "certificate participant bitmap must have length four",
            ));
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalClaimRequest {
    pub(crate) deployment: Digest,
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) claim: WithdrawalClaim<Digest>,
}

impl Write for WithdrawalClaimRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.batch_id.write(buf);
        self.claim.write(buf);
    }
}

impl EncodeSize for WithdrawalClaimRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size() + self.batch_id.encode_size() + self.claim.encode_size()
    }
}

impl Read for WithdrawalClaimRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            batch_id: BatchId::read(buf)?,
            claim: WithdrawalClaim::read_cfg(buf, &RangeCfg::new(0..=MAX_DESTINATION_BYTES))?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalPayoutClaimRequest {
    pub(crate) deployment: Digest,
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) claim: ExternalPayoutClaim<Key, Digest>,
}

impl Write for ExternalPayoutClaimRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.batch_id.write(buf);
        self.claim.write(buf);
    }
}

impl EncodeSize for ExternalPayoutClaimRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size() + self.batch_id.encode_size() + self.claim.encode_size()
    }
}

impl Read for ExternalPayoutClaimRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            batch_id: BatchId::read(buf)?,
            claim: ExternalPayoutClaim::read(buf)?,
        })
    }
}

/// A finalized output eligible for atomic native credit and redeposit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum FinalizedClaim {
    Withdrawal(WithdrawalClaimRequest),
    ExternalPayout(ExternalPayoutClaimRequest),
}
impl Write for FinalizedClaim {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Withdrawal(claim) => {
                0u8.write(buf);
                claim.write(buf);
            }
            Self::ExternalPayout(claim) => {
                1u8.write(buf);
                claim.write(buf);
            }
        }
    }
}
impl EncodeSize for FinalizedClaim {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Withdrawal(claim) => claim.encode_size(),
            Self::ExternalPayout(claim) => claim.encode_size(),
        }
    }
}
impl Read for FinalizedClaim {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Withdrawal(WithdrawalClaimRequest::read(buf)?)),
            1 => Ok(Self::ExternalPayout(ExternalPayoutClaimRequest::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One atomic finalized claim and signed native deposit into another deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimDepositRequest {
    pub(crate) claim: FinalizedClaim,
    pub(crate) deposit: DepositRequest,
}
impl Write for ClaimDepositRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.claim.write(buf);
        self.deposit.write(buf);
    }
}
impl EncodeSize for ClaimDepositRequest {
    fn encode_size(&self) -> usize {
        self.claim.encode_size() + self.deposit.encode_size()
    }
}
impl Read for ClaimDepositRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            claim: FinalizedClaim::read(buf)?,
            deposit: DepositRequest::read(buf)?,
        })
    }
}

/// One settlement-chain transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SettlementTx {
    RegisterDeployment(RegisterDeploymentRequest),
    NativeTransfer(NativeTransferRequest),
    ClaimDeposit(ClaimDepositRequest),
    Deposit(DepositRequest),
    QueueWithdrawal(QueueWithdrawalRequest),
    RegisterEpoch(RegisterEpochRequest),
    Admit(AdmitRequest),
    ClaimWithdrawal(WithdrawalClaimRequest),
    ClaimExternalPayout(ExternalPayoutClaimRequest),
    Challenge(ChallengeRequest),
    BeginHardFaultSettlement(BeginHardFaultSettlementRequest),
    ClaimHardFault(ClaimHardFaultRequest),
    ClaimPendingDeposit(ClaimPendingDepositRequest),
}

impl SettlementTx {
    /// The claimed deployment route. Execution authenticates the referenced state.
    pub(crate) const fn deployment(&self) -> Option<Digest> {
        Some(match self {
            Self::RegisterDeployment(_) | Self::NativeTransfer(_) => return None,
            Self::ClaimDeposit(request) => request.deposit.deployment,
            Self::Deposit(request) => request.deployment,
            Self::QueueWithdrawal(request) => *request.request.body().deployment(),
            Self::RegisterEpoch(request) => request.deployment,
            Self::Admit(request) => request.deployment,
            Self::ClaimWithdrawal(request) => request.deployment,
            Self::ClaimExternalPayout(request) => request.deployment,
            Self::Challenge(request) => request.deployment,
            Self::BeginHardFaultSettlement(request) => request.deployment,
            Self::ClaimHardFault(request) => request.deployment,
            Self::ClaimPendingDeposit(request) => request.deployment,
        })
    }

    /// Identity of this transaction: the digest of its encoding.
    ///
    /// The mempool keys dedupe, leasing, and retirement by it. It proves
    /// nothing about outcomes: acceptance is proven by the transaction's
    /// effect record in certified state, and a rejection is effect-free, so
    /// it leaves nothing provable against the state root.
    pub(crate) fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl Write for SettlementTx {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::RegisterDeployment(r) => {
                10u8.write(buf);
                r.write(buf);
            }
            Self::NativeTransfer(r) => {
                11u8.write(buf);
                r.write(buf);
            }
            Self::ClaimDeposit(r) => {
                12u8.write(buf);
                r.write(buf);
            }
            Self::Deposit(request) => {
                0_u8.write(buf);
                request.write(buf);
            }
            Self::QueueWithdrawal(request) => {
                1_u8.write(buf);
                request.write(buf);
            }
            Self::RegisterEpoch(request) => {
                2_u8.write(buf);
                request.write(buf);
            }
            Self::Admit(request) => {
                3_u8.write(buf);
                request.write(buf);
            }
            Self::ClaimWithdrawal(request) => {
                4_u8.write(buf);
                request.write(buf);
            }
            Self::ClaimExternalPayout(request) => {
                5_u8.write(buf);
                request.write(buf);
            }
            Self::Challenge(request) => {
                6_u8.write(buf);
                request.write(buf);
            }
            Self::BeginHardFaultSettlement(request) => {
                7_u8.write(buf);
                request.write(buf);
            }
            Self::ClaimHardFault(request) => {
                8_u8.write(buf);
                request.write(buf);
            }
            Self::ClaimPendingDeposit(request) => {
                9_u8.write(buf);
                request.write(buf);
            }
        }
    }
}

impl EncodeSize for SettlementTx {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::RegisterDeployment(r) => r.encode_size(),
            Self::NativeTransfer(r) => r.encode_size(),
            Self::ClaimDeposit(r) => r.encode_size(),
            Self::Deposit(request) => request.encode_size(),
            Self::QueueWithdrawal(request) => request.encode_size(),
            Self::RegisterEpoch(request) => request.encode_size(),
            Self::Admit(request) => request.encode_size(),
            Self::ClaimWithdrawal(request) => request.encode_size(),
            Self::ClaimExternalPayout(request) => request.encode_size(),
            Self::Challenge(request) => request.encode_size(),
            Self::BeginHardFaultSettlement(request) => request.encode_size(),
            Self::ClaimHardFault(request) => request.encode_size(),
            Self::ClaimPendingDeposit(request) => request.encode_size(),
        }
    }
}

impl Read for SettlementTx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            10 => Ok(Self::RegisterDeployment(RegisterDeploymentRequest::read(
                buf,
            )?)),
            11 => Ok(Self::NativeTransfer(NativeTransferRequest::read(buf)?)),
            12 => Ok(Self::ClaimDeposit(ClaimDepositRequest::read(buf)?)),
            0 => Ok(Self::Deposit(DepositRequest::read(buf)?)),
            1 => Ok(Self::QueueWithdrawal(QueueWithdrawalRequest::read(buf)?)),
            2 => Ok(Self::RegisterEpoch(RegisterEpochRequest::read(buf)?)),
            3 => Ok(Self::Admit(AdmitRequest::read(buf)?)),
            4 => Ok(Self::ClaimWithdrawal(WithdrawalClaimRequest::read(buf)?)),
            5 => Ok(Self::ClaimExternalPayout(ExternalPayoutClaimRequest::read(
                buf,
            )?)),
            6 => Ok(Self::Challenge(ChallengeRequest::read(buf)?)),
            7 => Ok(Self::BeginHardFaultSettlement(
                BeginHardFaultSettlementRequest::read(buf)?,
            )),
            8 => Ok(Self::ClaimHardFault(ClaimHardFaultRequest::read(buf)?)),
            9 => Ok(Self::ClaimPendingDeposit(ClaimPendingDepositRequest::read(
                buf,
            )?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{MAX_ENTRIES, Protocol, Wallet, omitting_close, wallets},
        rpc,
    };
    use bytes::BytesMut;
    use commonware_clearing::bajillion::{
        challenge::{AckWitness, Challenge, EntryWitness},
        payment::{VectorAck, VectorSendBody},
        vector::{OutEntry, OutTipLookup, OutVector},
    };
    use commonware_codec::DecodeExt as _;
    use commonware_utils::TestRng;
    use std::num::NonZeroUsize;

    #[test]
    fn deployment_identity_binds_the_complete_registration() {
        let signer = crate::protocol::operator_signer(0);
        let chain = Sha256::hash(&[b"registration-chain"]);
        let request = RegisterDeploymentRequest::sign(
            chain,
            Sha256::hash(&[b"registration-id"]),
            crate::protocol::operator_ack_key(0),
            ed25519::PrivateKey::from_seed(50).public_key(),
            wallets().iter().map(Wallet::public_key).collect(),
            4096,
            10,
            &signer,
        );
        assert!(request.verify(&chain));
        assert_eq!(
            RegisterDeploymentRequest::decode(request.encode()).unwrap(),
            request
        );
        for field in 0..8 {
            let mut changed = request.clone();
            match field {
                0 => changed.chain_id = Sha256::hash(&[b"another-chain"]),
                1 => changed.registration_id = Sha256::hash(&[b"another-id"]),
                2 => changed.operator = wallets()[0].public_key(),
                3 => changed.operator_ack = crate::protocol::operator_ack_key(1),
                4 => changed.network_key = ed25519::PrivateKey::from_seed(51).public_key(),
                5 => {
                    changed.accounts.pop();
                }
                6 => changed.max_dealing_bytes += 1,
                _ => changed.fee += 1,
            }
            assert_ne!(request.deployment_id(), changed.deployment_id());
            assert!(!changed.verify(&chain));
        }
    }

    #[test]
    fn native_deposit_authenticates_every_debit_field() {
        let wallet = wallets().remove(0);
        let chain = Sha256::hash(&[b"native-deposit-chain"]);
        let event = DepositEvent {
            id: Sha256::hash(&[b"deposit-id"]),
            account: wallet.public_key(),
            amount: 7,
        };
        let request =
            DepositRequest::sign(chain, crate::protocol::deployment(), event, wallet.signer());
        assert!(request.verify(&chain));
        assert_eq!(DepositRequest::decode(request.encode()).unwrap(), request);
        assert!(!request.verify(&Sha256::hash(&[b"another-chain"])));
        for field in 0..4 {
            let mut changed = request.clone();
            match field {
                0 => changed.deployment = Sha256::hash(&[b"another-deployment"]),
                1 => changed.event.id = Sha256::hash(&[b"another-id"]),
                2 => changed.event.amount += 1,
                _ => changed.event.account = wallets()[1].public_key(),
            }
            assert!(!changed.verify(&chain));
        }
    }

    #[test]
    fn native_transfer_authenticates_recipient_amount_and_replay_domain() {
        let wallet = wallets().remove(0);
        let chain = Sha256::hash(&[b"native-transfer-chain"]);
        let request = NativeTransferRequest::sign(
            chain,
            Sha256::hash(&[b"transfer-id"]),
            wallets()[1].public_key(),
            9,
            wallet.signer(),
        );
        assert!(request.verify(&chain));
        assert_eq!(
            NativeTransferRequest::decode(request.encode()).unwrap(),
            request
        );
        for field in 0..5 {
            let mut changed = request.clone();
            match field {
                0 => changed.chain_id = Sha256::hash(&[b"other-chain"]),
                1 => changed.id = Sha256::hash(&[b"other-id"]),
                2 => changed.to = wallets()[2].public_key(),
                3 => changed.from = wallets()[2].public_key(),
                _ => changed.amount += 1,
            }
            assert!(!changed.verify(&chain));
        }
    }

    #[test]
    fn challenge_request_enforces_its_nested_evidence_bound() {
        let batch_id = BatchId::new(Sha256::hash(&[b"bounded-challenge"]));
        let bounded = ChallengeRequest {
            deployment: crate::protocol::deployment(),
            batch_id,
            evidence: Bytes::from(vec![7; MAX_CHALLENGE_BYTES]),
        };
        assert!(bounded.encode_size() <= rpc::MAX_BODY_SIZE);
        assert_eq!(ChallengeRequest::decode(bounded.encode()).unwrap(), bounded);

        let mut oversized = BytesMut::new();
        crate::protocol::deployment().write(&mut oversized);
        batch_id.write(&mut oversized);
        (MAX_CHALLENGE_BYTES + 1).write(&mut oversized);
        let error = ChallengeRequest::decode(oversized.freeze()).unwrap_err();
        assert!(matches!(error, CodecError::InvalidLength(_)));

        let mut trailing = ChallengeRequest {
            deployment: crate::protocol::deployment(),
            batch_id,
            evidence: Bytes::from_static(&[0]),
        }
        .encode()
        .to_vec();
        trailing.push(0);
        assert!(matches!(
            ChallengeRequest::decode(Bytes::from(trailing)),
            Err(CodecError::ExtraData(_))
        ));
    }

    #[test]
    fn challenge_bound_admits_the_maximal_canonical_proof() {
        // A genuine higher-entry challenge over a committed close: the
        // retained acknowledgment witness with its entry opening plus the
        // composed sender lookup, the family the bound is sized for.
        let fraud = commonware_runtime::Runner::start(
            commonware_runtime::deterministic::Runner::default(),
            |context| async move {
                let strategy = commonware_parallel::Rayon::new(NonZeroUsize::MIN).unwrap();
                let config = crate::protocol::state_config("bound-proof", &context, strategy);
                let state = commonware_clearing::bajillion::qmdb::State::<_, Sha256, _>::init(
                    context,
                    config,
                    crate::protocol::genesis_balances(&crate::protocol::deployments()[0]).unwrap(),
                )
                .await
                .unwrap();
                Box::pin(omitting_close(state, &mut TestRng::new(41), 11, 12))
                    .await
                    .unwrap()
            },
        );
        let context = fraud.result.payment_context.clone();
        let held = &fraud.held_receipt;
        let genuine: Challenge<Key, Digest> = Challenge::HigherAckEntry {
            entry: Box::new(EntryWitness {
                ack: AckWitness::from_ack(&held.ack),
                recipient: held.recipient.clone(),
                cumulative: held.cumulative,
                count: held.count,
                opening: held.opening.clone(),
            }),
            sender: Box::new(fraud.held_lookup.clone()),
        };
        let evidence = genuine.encode();
        assert!(evidence.len() <= MAX_CHALLENGE_BYTES);
        assert_eq!(
            Challenge::<Key, Digest>::decode(evidence.clone()).unwrap(),
            genuine
        );

        // The deepest canonical entry witness: an acknowledged vector at the
        // protocol entry limit opens one entry at full depth, and the
        // composed challenge still clears the bound.
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let payer = wallets().remove(0);
        let mut entries = (0..MAX_ENTRIES)
            .map(|index| {
                let seed = 20_000 + u64::try_from(index).unwrap();
                OutEntry {
                    recipient: Wallet::from_seed("receiver", seed).public_key(),
                    cumulative: 1,
                    count: 1,
                }
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
        let recipient = entries[0].recipient.clone();
        let vector = OutVector::new(context.epoch(), payer.public_key(), entries).unwrap();
        let ack = VectorAck::sign_by_authorities(
            VectorSendBody::new(
                &context,
                payer.public_key(),
                0,
                MAX_ENTRIES as u64,
                vector.root::<Sha256, Digest>().unwrap(),
            ),
            payer.signer(),
            protocol.operator(),
        );
        let OutTipLookup::Present {
            cumulative,
            count,
            opening,
        } = vector.lookup::<Sha256, Digest>(&recipient).unwrap()
        else {
            panic!("the entry-limit vector holds its first entry");
        };
        let widest: Challenge<Key, Digest> = Challenge::HigherAckEntry {
            entry: Box::new(EntryWitness {
                ack: AckWitness::from_ack(&ack),
                recipient,
                cumulative,
                count,
                opening,
            }),
            sender: Box::new(fraud.held_lookup.clone()),
        };
        let widest = widest.encode();
        assert!(widest.len() <= MAX_CHALLENGE_BYTES);

        // The fork family carries two fixed-size witnesses and no openings,
        // so it stays under the deepest entry challenge.
        let fork: Challenge<Key, Digest> = Challenge::AckFork {
            left: Box::new(AckWitness::from_ack(&held.ack)),
            right: Box::new(AckWitness::from_ack(&ack)),
        };
        assert!(fork.encode().len() <= widest.len());

        // The genuine proof clears the request decode bound and the frame budget.
        let request = ChallengeRequest {
            deployment: crate::protocol::deployment(),
            batch_id: BatchId::new(Sha256::hash(&[b"maximal-challenge-batch"])),
            evidence,
        };
        assert!(request.encode_size() <= rpc::MAX_BODY_SIZE);
        assert_eq!(ChallengeRequest::decode(request.encode()).unwrap(), request);
    }

    #[test]
    fn request_codecs_enforce_their_nested_bounds() {
        // A withdrawal destination beyond the shared bound is refused at decode.
        let wallet = wallets().remove(0);
        let root = Sha256::hash(&[b"request-bound-root"]);
        let oversized_destination = SignedWithdrawal::sign(
            Sha256::hash(&[b"request-bound-deployment"]),
            root,
            Bytes::from(vec![0; MAX_DESTINATION_BYTES + 1]),
            commonware_clearing::bajillion::boundary::WithdrawalAction::Amount(
                std::num::NonZeroU64::MIN,
            ),
            100,
            wallet.signer(),
        );
        let request = QueueWithdrawalRequest {
            request: oversized_destination,
            openings: Vec::new(),
        };
        assert!(matches!(
            QueueWithdrawalRequest::decode(request.encode()),
            Err(CodecError::InvalidLength(_))
        ));

        // An openings count beyond the bound is refused before materializing.
        let bounded = SignedWithdrawal::sign(
            Sha256::hash(&[b"request-bound-deployment"]),
            root,
            Bytes::from_static(b"destination"),
            commonware_clearing::bajillion::boundary::WithdrawalAction::Amount(
                std::num::NonZeroU64::MIN,
            ),
            100,
            wallet.signer(),
        );
        let mut oversized_openings = BytesMut::new();
        bounded.write(&mut oversized_openings);
        (MAX_STATE_OPENINGS + 1).write(&mut oversized_openings);
        assert!(matches!(
            QueueWithdrawalRequest::decode(oversized_openings.freeze()),
            Err(CodecError::InvalidLength(_))
        ));

        // A registration batch beyond the bound is refused before materializing.
        let mut oversized_batch = BytesMut::new();
        Sha256::hash(&[b"request-bound-deployment"]).write(&mut oversized_batch);
        0_u64.write(&mut oversized_batch);
        400_u64.write(&mut oversized_batch);
        let oversized_root = VectorRoot {
            digest: Sha256::hash(&[b"oversized-batch-root"]),
        };
        oversized_root.write(&mut oversized_batch);
        oversized_root.write(&mut oversized_batch);
        (MAX_BATCH_ITEMS + 1).write(&mut oversized_batch);
        assert!(matches!(
            RegisterEpochRequest::decode(oversized_batch.freeze()),
            Err(CodecError::InvalidLength(_))
        ));
    }
}
