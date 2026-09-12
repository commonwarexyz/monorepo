//! Native balances, operator registration, and clearing execution over QMDB.
//!
//! Genesis fixes the native supply, resource prices, timing policy, and initial deployments.
//! The certified registry authorizes later deployments with immutable operator identities,
//! account enrollment, peer identities, and dealing limits. Registry and native-account keys
//! use the immutable chain domain; clearing records use their deployment domain.
//! A bounded digest directory enumerates immutable registration point records. Deadline work
//! uses deployment IDs and machines; routed transactions load their complete account rosters.
//!
//! Native deposits debit their signing account and credit clearing custody atomically. A
//! finalized clearing output creates a claim reserve; claiming it consumes the proof position
//! and credits its authenticated native destination in the same state transition. Refunds
//! and frozen-state claims follow the same rule. Fees transfer native value from the operator
//! to the genesis treasury, preserving the sum of native balances, active custody, and reserves.
//! [`SettlementTx::ClaimDeposit`] combines a finalized claim and a signed deposit without
//! exposing either half if the destination rejects the operation.
//!
//! # Deadlines and faults
//!
//! Block height is the only deadline clock. Execution observes each machine's liveness
//! deadlines before processing transactions, retaining those observations even if a subsequent
//! request is rejected. Registration assigns deadlines from genesis policy and enables a
//! successor registration after admission. Finalization consumes the FIFO front strictly after
//! its challenge window. A hard fault permanently fences its deployment while preserving the
//! valid pending prefix, finalized reserves, and independent terminal claims.
//!
//! # Persistence and replay
//!
//! Every machine, native balance, registry entry, and consumed transfer or claim record lives
//! in the same forked QMDB batch. The batch commits only after execution finishes. Deposit IDs,
//! signed transfer IDs scoped to their debit owner, deployment identities, epoch sequence, and
//! claim positions own replay protection; no global wallet nonce is required. Native transfer
//! records and the clearing primitive's lifetime replay records remain available for exact
//! retry resolution. Certified granular records expose each applied effect to clients.
//!
//! [`execute`] loads the registry and machines, observes clocks, applies transactions, and
//! merkleizes the complete result. [`preflight`] trials canonical application at one applied tip;
//! execution repeats every authoritative check at inclusion.

use crate::{
    chain::{
        app::Finalized,
        native::{MAX_DEPLOYMENTS, NativeGenesis, RegistryEntry},
        tx::{
            AdmitRequest, ChallengeRequest, ClaimHardFaultRequest, ClaimPendingDepositRequest,
            ExternalPayoutClaimRequest, FinalizedClaim, NativeTransferRequest,
            QueueWithdrawalRequest, RegisterEpochRequest, SettlementTx, WithdrawalClaimRequest,
        },
        types::{Batch, Database, KEY_BYTES, Qmdb, Sealed, StateKey},
    },
    protocol::{
        Deployment, DepositEvent, Key, MAX_DESTINATION_BYTES, SQLITE_U64_MAX, Timing, committee,
        epoch_context_at, settlement_config, verify_chain_registration_signature,
    },
};
use bytes::{Buf, BufMut, Bytes};
use commonware_clearing::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalBatch},
    challenge::{ChallengeKind, Verdict},
    commitment::VectorRoot,
    qmdb::StateRoot,
    settlement::{
        Bounds, ClaimError, DepositRefund, HardFaultReason, HardFaultRelease, HardFaultSettlement,
        Registered, SettlementChain, SettlementError,
    },
    transition::{BatchId, ExternalPayout, RootBundle, WithdrawalOutput},
};
use commonware_codec::{
    Decode, DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read,
    ReadExt as _, Write,
};
use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_glue::stateful::db::Unmerkleized as _;
use commonware_macros::boxed;
use commonware_runtime::Spawner;
use commonware_storage::{Context as StorageContext, mmr, qmdb::Error as QmdbError};
use std::collections::BTreeMap;
use tracing::debug;

/// Decode bounds for the persisted settlement machine.
///
/// The machine record is only decoded from state this node wrote or state
/// synced under a certified root, so these bounds are a structural backstop
/// sized generously above the demo deployment's configured limits.
const MACHINE_BOUNDS: Bounds = Bounds {
    committee: 16,
    items: 1 << 20,
    destination: MAX_DESTINATION_BYTES,
};

/// Maximum encoded bytes accepted for the persisted machine record.
const MAX_MACHINE_BYTES: usize = 1 << 24;

/// Native withdrawals require a canonical public key with a stable credit destination.
fn eligible(destination: &Bytes) -> bool {
    Key::decode(destination.clone()).is_ok()
}

/// Key domains. The discriminant is the trailing key byte.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum Domain {
    Status = 0,
    Anchor = 1,
    Admitted = 2,
    ClaimRoots = 3,
    Deposit = 4,
    Withdrawal = 5,
    Registration = 6,
    WithdrawalRelease = 7,
    PayoutRelease = 8,
    HardFault = 9,
    Refund = 10,
    Fault = 11,
    Machine = 12,
    Registry = 13,
    NativeBalance = 14,
    NativeTransfer = 15,
    RegistryEntry = 16,
}

/// Derives one state key: the domain-tagged digest of the deployment digest
/// and `payload`, entropy bytes first, domain tag last. Folding the
/// deployment into the hashed payload keeps entropy-first keying while
/// scoping every domain per deployment.
fn derive(deployment: &Digest, domain: Domain, payload: &[u8]) -> StateKey {
    let tag = [domain as u8];
    let digest = Sha256::hash(&[&tag[..], deployment.as_ref(), payload]);
    let mut bytes = [0u8; KEY_BYTES];
    bytes[..KEY_BYTES - 1].copy_from_slice(digest.as_ref());
    bytes[KEY_BYTES - 1] = domain as u8;
    StateKey::new(bytes)
}

/// Key of one deployment's status singleton.
pub(crate) fn status_key(deployment: &Digest) -> StateKey {
    derive(deployment, Domain::Status, &[])
}

/// Key of one deployment's registered payment anchor for `epoch`.
pub(crate) fn anchor_key(deployment: &Digest, epoch: u64) -> StateKey {
    derive(deployment, Domain::Anchor, &epoch.to_be_bytes())
}

/// Key of one deployment's admitted close record for `epoch`.
pub(crate) fn admitted_key(deployment: &Digest, epoch: u64) -> StateKey {
    derive(deployment, Domain::Admitted, &epoch.to_be_bytes())
}

/// Key of one deployment's claim roots record for one finalized batch.
pub(crate) fn claim_roots_key(deployment: &Digest, batch_id: &BatchId<Digest>) -> StateKey {
    derive(deployment, Domain::ClaimRoots, &batch_id.encode())
}

/// Key of one deployment's custody record for one deposit id.
pub(crate) fn deposit_key(deployment: &Digest, id: &Digest) -> StateKey {
    derive(deployment, Domain::Deposit, id.as_ref())
}

/// Key of one deployment's queued withdrawal for `account`.
pub(crate) fn withdrawal_key(deployment: &Digest, account: &Key) -> StateKey {
    derive(deployment, Domain::Withdrawal, &account.encode())
}

/// Key of one deployment's registration singleton.
pub(crate) fn registration_key(deployment: &Digest) -> StateKey {
    derive(deployment, Domain::Registration, &[])
}

/// Key of one deployment's released withdrawal by (batch, position).
pub(crate) fn withdrawal_release_key(
    deployment: &Digest,
    batch_id: &BatchId<Digest>,
    position: u32,
) -> StateKey {
    let mut payload = batch_id.encode().to_vec();
    payload.extend_from_slice(&position.to_be_bytes());
    derive(deployment, Domain::WithdrawalRelease, &payload)
}

/// Key of one deployment's released external payout by (batch, position).
pub(crate) fn payout_release_key(
    deployment: &Digest,
    batch_id: &BatchId<Digest>,
    position: u32,
) -> StateKey {
    let mut payload = batch_id.encode().to_vec();
    payload.extend_from_slice(&position.to_be_bytes());
    derive(deployment, Domain::PayoutRelease, &payload)
}

/// Key of one deployment's hard-fault release by account.
pub(crate) fn hard_fault_key(deployment: &Digest, account: &Key) -> StateKey {
    derive(deployment, Domain::HardFault, &account.encode())
}

/// Key of one deployment's deposit refund by account.
pub(crate) fn refund_key(deployment: &Digest, account: &Key) -> StateKey {
    derive(deployment, Domain::Refund, &account.encode())
}

/// Key of one deployment's fault singleton.
pub(crate) fn fault_key(deployment: &Digest) -> StateKey {
    derive(deployment, Domain::Fault, &[])
}

/// Key of one deployment's machine singleton.
pub(crate) fn machine_key(deployment: &Digest) -> StateKey {
    derive(deployment, Domain::Machine, &[])
}

/// Key of the chain's bounded authenticated operator registry.
pub(crate) fn registry_key(chain: &Digest) -> StateKey {
    derive(chain, Domain::Registry, &[])
}

/// Key of an account's spendable native balance.
pub(crate) fn native_balance_key(chain: &Digest, account: &Key) -> StateKey {
    derive(chain, Domain::NativeBalance, account.as_ref())
}

/// Key consuming one signed native transfer identifier under its debit owner.
pub(crate) fn native_transfer_key(chain: &Digest, from: &Key, id: &Digest) -> StateKey {
    derive(chain, Domain::NativeTransfer, &(from.clone(), *id).encode())
}

/// Key of one immutable deployment registration under the chain domain.
pub(crate) fn registry_entry_key(chain: &Digest, deployment: &Digest) -> StateKey {
    derive(chain, Domain::RegistryEntry, deployment.as_ref())
}

/// Reads the bounded deployment directory, using genesis before its first block.
#[cfg(test)]
pub(crate) async fn registry<E>(
    db: &Database<E>,
    native: &NativeGenesis,
) -> Result<Vec<Digest>, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    Ok(
        match db
            .read()
            .await
            .get(&registry_key(&native.chain_id()))
            .await?
        {
            Some(Record::Registry(ids)) => ids,
            None => native
                .deployments
                .iter()
                .map(|entry| *entry.deployment.digest())
                .collect(),
            Some(_) => unreachable!("registry key has a directory record"),
        },
    )
}

/// Reads one complete immutable registration without loading unrelated account rosters.
#[cfg(test)]
pub(crate) async fn registry_entry<E>(
    db: &Database<E>,
    native: &NativeGenesis,
    deployment: &Digest,
) -> Result<Option<RegistryEntry>, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    let chain_id = native.chain_id();
    let guard = db.read().await;
    match guard
        .get(&registry_entry_key(&chain_id, deployment))
        .await?
    {
        Some(Record::RegistryEntry(entry)) => {
            assert_eq!(
                entry.deployment.digest(),
                deployment,
                "registration key binds its deployment"
            );
            Ok(Some(entry))
        }
        None => Ok(native
            .deployments
            .iter()
            .find(|entry| entry.deployment.digest() == deployment)
            .cloned()),
        Some(_) => unreachable!("registration entry key holds a registration"),
    }
}

/// Reads a native account balance, including the allocation before the first block.
#[cfg(test)]
pub(crate) async fn native_balance<E>(
    db: &Database<E>,
    native: &NativeGenesis,
    account: &Key,
) -> Result<u64, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    Ok(
        match db
            .read()
            .await
            .get(&native_balance_key(&native.chain_id(), account))
            .await?
        {
            Some(Record::NativeBalance(balance)) => balance,
            None => native
                .balances
                .iter()
                .find(|entry| &entry.key == account)
                .map_or(0, |entry| entry.balance),
            Some(_) => unreachable!("native balance key has a balance record"),
        },
    )
}

/// The status singleton: the chain's one coherent settlement fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StatusRecord {
    /// Block height of the state this record is part of.
    pub(crate) height: u64,
    /// Timestamp of the block this record is part of, in milliseconds since
    /// the Unix epoch. Recency/display-grade: never a deadline input.
    pub(crate) timestamp: u64,
    pub(crate) deployment: Digest,
    /// Clearing state root (the settlement chain's account commitment).
    pub(crate) state_root: StateRoot<Digest>,
    /// Highest finalized epoch. Epochs finalize in order, so the state root
    /// covers every epoch at or below it.
    pub(crate) last_finalized: Option<u64>,
    pub(crate) custody: u64,
    pub(crate) claimable: u64,
    pub(crate) hard_faulted: bool,
}

impl Write for StatusRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.timestamp.write(buf);
        self.deployment.write(buf);
        self.state_root.write(buf);
        self.last_finalized.write(buf);
        self.custody.write(buf);
        self.claimable.write(buf);
        self.hard_faulted.write(buf);
    }
}

impl EncodeSize for StatusRecord {
    fn encode_size(&self) -> usize {
        self.height.encode_size()
            + self.timestamp.encode_size()
            + self.deployment.encode_size()
            + self.state_root.encode_size()
            + self.last_finalized.encode_size()
            + self.custody.encode_size()
            + self.claimable.encode_size()
            + self.hard_faulted.encode_size()
    }
}

impl Read for StatusRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            height: u64::read(buf)?,
            timestamp: u64::read(buf)?,
            deployment: Digest::read(buf)?,
            state_root: StateRoot::read(buf)?,
            last_finalized: Option::<u64>::read(buf)?,
            custody: u64::read(buf)?,
            claimable: u64::read(buf)?,
            hard_faulted: bool::read(buf)?,
        })
    }
}

/// The registration singleton: the live payment context's commitments,
/// including the chain-assigned deadlines and anchor the operator reads back
/// before issuing any receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegistrationRecord {
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) anchor: Digest,
    /// Chain-assigned last height at which the epoch's close may be admitted.
    pub(crate) admission_deadline: u64,
    /// Chain-assigned last height at which the admitted close may be
    /// challenged.
    pub(crate) challenge_deadline: u64,
    /// Root of the derived deposit boundary.
    pub(crate) deposits_root: VectorRoot<Digest>,
    /// Root of the full staged deposit view.
    pub(crate) staged_root: VectorRoot<Digest>,
    /// Root of the registered withdrawal batch.
    pub(crate) withdrawals_root: VectorRoot<Digest>,
    /// The admitted close, once one is admitted for this registration.
    pub(crate) admitted: Option<BatchId<Digest>>,
}

impl Write for RegistrationRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.predecessor_liability.write(buf);
        self.anchor.write(buf);
        self.admission_deadline.write(buf);
        self.challenge_deadline.write(buf);
        self.deposits_root.write(buf);
        self.staged_root.write(buf);
        self.withdrawals_root.write(buf);
        self.admitted.write(buf);
    }
}

impl EncodeSize for RegistrationRecord {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.predecessor_liability.encode_size()
            + self.anchor.encode_size()
            + self.admission_deadline.encode_size()
            + self.challenge_deadline.encode_size()
            + self.deposits_root.encode_size()
            + self.staged_root.encode_size()
            + self.withdrawals_root.encode_size()
            + self.admitted.encode_size()
    }
}

impl Read for RegistrationRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            predecessor_liability: u64::read(buf)?,
            anchor: Digest::read(buf)?,
            admission_deadline: u64::read(buf)?,
            challenge_deadline: u64::read(buf)?,
            deposits_root: VectorRoot::read(buf)?,
            staged_root: VectorRoot::read(buf)?,
            withdrawals_root: VectorRoot::read(buf)?,
            admitted: Option::<BatchId<Digest>>::read(buf)?,
        })
    }
}

/// The claim roots of one finalized batch, against which claimants verify
/// operator-served evidence locally before caching it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClaimRootsResponse {
    pub(crate) withdrawal_outputs: VectorRoot<Digest>,
    pub(crate) change: VectorRoot<Digest>,
}

impl Write for ClaimRootsResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.withdrawal_outputs.write(buf);
        self.change.write(buf);
    }
}

impl EncodeSize for ClaimRootsResponse {
    fn encode_size(&self) -> usize {
        self.withdrawal_outputs.encode_size() + self.change.encode_size()
    }
}

impl Read for ClaimRootsResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            withdrawal_outputs: VectorRoot::read(buf)?,
            change: VectorRoot::read(buf)?,
        })
    }
}

/// The identity and roots of the close admitted for one epoch.
///
/// Receivers anchor reconciliation against this record, so operator-served
/// or validator-served committed-side evidence is trusted only when it
/// verifies under these roots: the change root for challenge lookups and
/// claims, the successor root for state openings, the withdrawal-output
/// root for withdrawal claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedRootsResponse {
    pub(crate) batch_id: BatchId<Digest>,
    /// The full root bundle the admitted header commits.
    pub(crate) roots: RootBundle<Digest>,
    /// Whether FIFO settlement finalized the close.
    pub(crate) finalized: bool,
}

impl AdmittedRootsResponse {
    pub(crate) const fn new(
        batch_id: BatchId<Digest>,
        roots: RootBundle<Digest>,
        finalized: bool,
    ) -> Self {
        Self {
            batch_id,
            roots,
            finalized,
        }
    }
}

impl Write for AdmittedRootsResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.roots.write(buf);
        self.finalized.write(buf);
    }
}

impl EncodeSize for AdmittedRootsResponse {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size() + self.roots.encode_size() + self.finalized.encode_size()
    }
}

impl Read for AdmittedRootsResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            BatchId::read(buf)?,
            RootBundle::read(buf)?,
            bool::read(buf)?,
        ))
    }
}

/// One released withdrawal output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalResponse {
    pub(crate) amount: u64,
    pub(crate) destination: Bytes,
}

impl From<WithdrawalOutput> for WithdrawalResponse {
    fn from(output: WithdrawalOutput) -> Self {
        Self {
            amount: output.amount(),
            destination: output.destination().clone(),
        }
    }
}

impl Write for WithdrawalResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.amount.write(buf);
        self.destination.write(buf);
    }
}

impl EncodeSize for WithdrawalResponse {
    fn encode_size(&self) -> usize {
        self.amount.encode_size() + self.destination.encode_size()
    }
}

impl Read for WithdrawalResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            amount: u64::read(buf)?,
            destination: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_DESTINATION_BYTES))?,
        })
    }
}

/// One released external payout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalPayoutResponse {
    pub(crate) receiver: Key,
    pub(crate) amount: u64,
}

impl From<ExternalPayout<Key>> for ExternalPayoutResponse {
    fn from(payout: ExternalPayout<Key>) -> Self {
        Self {
            receiver: payout.recipient,
            amount: payout.amount,
        }
    }
}

impl Write for ExternalPayoutResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.receiver.write(buf);
        self.amount.write(buf);
    }
}

impl EncodeSize for ExternalPayoutResponse {
    fn encode_size(&self) -> usize {
        self.receiver.encode_size() + self.amount.encode_size()
    }
}

impl Read for ExternalPayoutResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            receiver: Key::read(buf)?,
            amount: u64::read(buf)?,
        })
    }
}

const fn challenge_kind_tag(kind: ChallengeKind) -> u8 {
    match kind {
        ChallengeKind::HigherAckDebit => 0,
        ChallengeKind::HigherAckEntry => 1,
        ChallengeKind::AckFork => 2,
    }
}

const fn challenge_kind_from_tag(tag: u8) -> Result<ChallengeKind, CodecError> {
    match tag {
        0 => Ok(ChallengeKind::HigherAckDebit),
        1 => Ok(ChallengeKind::HigherAckEntry),
        2 => Ok(ChallengeKind::AckFork),
        _ => Err(CodecError::Invalid(
            "clearing_terminal::ChallengeKind",
            "unknown challenge kind tag",
        )),
    }
}

fn read_challenge_kind(buf: &mut impl Buf) -> Result<ChallengeKind, CodecError> {
    challenge_kind_from_tag(u8::read(buf)?)
}

/// Why the deployment permanently hard-faulted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HardFaultReasonResponse {
    ProvenChallenge {
        batch_id: BatchId<Digest>,
        kind: ChallengeKind,
    },
    ExpiredDeposit {
        account: Key,
        expired_at: u64,
    },
    ExpiredWithdrawal {
        account: Key,
        expired_at: u64,
    },
    ExpiredRegistration {
        anchor: Digest,
        epoch: u64,
        expired_at: u64,
    },
}

impl From<HardFaultReason<Key, Digest>> for HardFaultReasonResponse {
    fn from(reason: HardFaultReason<Key, Digest>) -> Self {
        match reason {
            HardFaultReason::ProvenChallenge { batch_id, kind } => {
                Self::ProvenChallenge { batch_id, kind }
            }
            HardFaultReason::ExpiredDeposit {
                account,
                expired_at,
            } => Self::ExpiredDeposit {
                account,
                expired_at,
            },
            HardFaultReason::ExpiredWithdrawal {
                account,
                expired_at,
            } => Self::ExpiredWithdrawal {
                account,
                expired_at,
            },
            HardFaultReason::ExpiredRegistration {
                anchor,
                epoch,
                expired_at,
            } => Self::ExpiredRegistration {
                anchor,
                epoch,
                expired_at,
            },
        }
    }
}

impl Write for HardFaultReasonResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::ProvenChallenge { batch_id, kind } => {
                0_u8.write(buf);
                batch_id.write(buf);
                challenge_kind_tag(*kind).write(buf);
            }
            Self::ExpiredDeposit {
                account,
                expired_at,
            } => {
                1_u8.write(buf);
                account.write(buf);
                expired_at.write(buf);
            }
            Self::ExpiredWithdrawal {
                account,
                expired_at,
            } => {
                2_u8.write(buf);
                account.write(buf);
                expired_at.write(buf);
            }
            Self::ExpiredRegistration {
                anchor,
                epoch,
                expired_at,
            } => {
                3_u8.write(buf);
                anchor.write(buf);
                epoch.write(buf);
                expired_at.write(buf);
            }
        }
    }
}

impl EncodeSize for HardFaultReasonResponse {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::ProvenChallenge { batch_id, .. } => batch_id.encode_size() + 1,
            Self::ExpiredDeposit {
                account,
                expired_at,
            }
            | Self::ExpiredWithdrawal {
                account,
                expired_at,
            } => account.encode_size() + expired_at.encode_size(),
            Self::ExpiredRegistration {
                anchor,
                epoch,
                expired_at,
            } => anchor.encode_size() + epoch.encode_size() + expired_at.encode_size(),
        }
    }
}

impl Read for HardFaultReasonResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::ProvenChallenge {
                batch_id: BatchId::read(buf)?,
                kind: read_challenge_kind(buf)?,
            }),
            1 => Ok(Self::ExpiredDeposit {
                account: Key::read(buf)?,
                expired_at: u64::read(buf)?,
            }),
            2 => Ok(Self::ExpiredWithdrawal {
                account: Key::read(buf)?,
                expired_at: u64::read(buf)?,
            }),
            3 => Ok(Self::ExpiredRegistration {
                anchor: Digest::read(buf)?,
                epoch: u64::read(buf)?,
                expired_at: u64::read(buf)?,
            }),
            _ => Err(CodecError::Invalid(
                "clearing_terminal::HardFaultReasonResponse",
                "unknown hard-fault reason tag",
            )),
        }
    }
}

/// The frozen snapshot terminal settlement began from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BeginHardFaultSettlementResponse {
    pub(crate) reason: HardFaultReasonResponse,
    pub(crate) admission_fence_epoch: u64,
    pub(crate) invalid_from: Option<BatchId<Digest>>,
    pub(crate) frozen_state_root: StateRoot<Digest>,
    pub(crate) state_liability: u64,
    pub(crate) unfinalized_deposit_total: u64,
    pub(crate) custody_balance: u64,
}

impl From<HardFaultSettlement<Key, Digest>> for BeginHardFaultSettlementResponse {
    fn from(settlement: HardFaultSettlement<Key, Digest>) -> Self {
        Self {
            reason: settlement.reason.into(),
            admission_fence_epoch: settlement.admission_fence_epoch,
            invalid_from: settlement.invalid_from,
            frozen_state_root: settlement.frozen_state_root,
            state_liability: settlement.state_liability,
            unfinalized_deposit_total: settlement.unfinalized_deposit_total,
            custody_balance: settlement.custody_balance,
        }
    }
}

impl Write for BeginHardFaultSettlementResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.reason.write(buf);
        self.admission_fence_epoch.write(buf);
        self.invalid_from.write(buf);
        self.frozen_state_root.write(buf);
        self.state_liability.write(buf);
        self.unfinalized_deposit_total.write(buf);
        self.custody_balance.write(buf);
    }
}

impl EncodeSize for BeginHardFaultSettlementResponse {
    fn encode_size(&self) -> usize {
        self.reason.encode_size()
            + self.admission_fence_epoch.encode_size()
            + self.invalid_from.encode_size()
            + self.frozen_state_root.encode_size()
            + self.state_liability.encode_size()
            + self.unfinalized_deposit_total.encode_size()
            + self.custody_balance.encode_size()
    }
}

impl Read for BeginHardFaultSettlementResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            reason: HardFaultReasonResponse::read(buf)?,
            admission_fence_epoch: u64::read(buf)?,
            invalid_from: Option::<BatchId<Digest>>::read(buf)?,
            frozen_state_root: StateRoot::read(buf)?,
            state_liability: u64::read(buf)?,
            unfinalized_deposit_total: u64::read(buf)?,
            custody_balance: u64::read(buf)?,
        })
    }
}

/// One released hard-fault claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimHardFaultResponse {
    pub(crate) account: Key,
    pub(crate) withdrawal: Option<WithdrawalOutput>,
    pub(crate) residual: u64,
    pub(crate) released_custody: u64,
}

impl From<HardFaultRelease<Key>> for ClaimHardFaultResponse {
    fn from(release: HardFaultRelease<Key>) -> Self {
        Self {
            account: release.account,
            withdrawal: release.withdrawal,
            residual: release.residual,
            released_custody: release.released_custody,
        }
    }
}

impl Write for ClaimHardFaultResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.withdrawal.write(buf);
        self.residual.write(buf);
        self.released_custody.write(buf);
    }
}

impl EncodeSize for ClaimHardFaultResponse {
    fn encode_size(&self) -> usize {
        self.account.encode_size()
            + self.withdrawal.encode_size()
            + self.residual.encode_size()
            + self.released_custody.encode_size()
    }
}

impl Read for ClaimHardFaultResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: Key::read(buf)?,
            withdrawal: Option::<WithdrawalOutput>::read_cfg(
                buf,
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )?,
            residual: u64::read(buf)?,
            released_custody: u64::read(buf)?,
        })
    }
}

/// One refunded stranded deposit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimPendingDepositResponse {
    pub(crate) account: Key,
    pub(crate) amount: u64,
}

impl From<DepositRefund<Key>> for ClaimPendingDepositResponse {
    fn from(refund: DepositRefund<Key>) -> Self {
        Self {
            account: refund.account,
            amount: refund.amount,
        }
    }
}

impl Write for ClaimPendingDepositResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.amount.write(buf);
    }
}

impl EncodeSize for ClaimPendingDepositResponse {
    fn encode_size(&self) -> usize {
        self.account.encode_size() + self.amount.encode_size()
    }
}

impl Read for ClaimPendingDepositResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: Key::read(buf)?,
            amount: u64::read(buf)?,
        })
    }
}

/// The fault singleton: the permanent fault, then the terminal snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FaultRecord {
    /// The deployment hard-faulted for this reason.
    Faulted(HardFaultReasonResponse),
    /// Terminal settlement began with this frozen snapshot.
    Settling(BeginHardFaultSettlementResponse),
}

impl Write for FaultRecord {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Faulted(reason) => {
                0_u8.write(buf);
                reason.write(buf);
            }
            Self::Settling(settlement) => {
                1_u8.write(buf);
                settlement.write(buf);
            }
        }
    }
}

impl EncodeSize for FaultRecord {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Faulted(reason) => reason.encode_size(),
            Self::Settling(settlement) => settlement.encode_size(),
        }
    }
}

impl Read for FaultRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Faulted(HardFaultReasonResponse::read(buf)?)),
            1 => Ok(Self::Settling(BeginHardFaultSettlementResponse::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One released withdrawal, keyed by (batch, position).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalReleaseRecord {
    /// Digest of the exact claim that consumed the position.
    pub(crate) claim: Digest,
    pub(crate) released: WithdrawalResponse,
}

impl Write for WithdrawalReleaseRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.claim.write(buf);
        self.released.write(buf);
    }
}

impl EncodeSize for WithdrawalReleaseRecord {
    fn encode_size(&self) -> usize {
        self.claim.encode_size() + self.released.encode_size()
    }
}

impl Read for WithdrawalReleaseRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            claim: Digest::read(buf)?,
            released: WithdrawalResponse::read(buf)?,
        })
    }
}

/// One released external payout, keyed by (batch, position).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PayoutReleaseRecord {
    /// Digest of the exact claim that consumed the position.
    pub(crate) claim: Digest,
    pub(crate) released: ExternalPayoutResponse,
}

impl Write for PayoutReleaseRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.claim.write(buf);
        self.released.write(buf);
    }
}

impl EncodeSize for PayoutReleaseRecord {
    fn encode_size(&self) -> usize {
        self.claim.encode_size() + self.released.encode_size()
    }
}

impl Read for PayoutReleaseRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            claim: Digest::read(buf)?,
            released: ExternalPayoutResponse::read(buf)?,
        })
    }
}

/// One hard-fault release, keyed by account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HardFaultReleaseRecord {
    /// Frozen balance root authenticated by this account release.
    pub(crate) root: StateRoot<Digest>,
    pub(crate) released: ClaimHardFaultResponse,
}

impl Write for HardFaultReleaseRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.released.write(buf);
    }
}

impl EncodeSize for HardFaultReleaseRecord {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.released.encode_size()
    }
}

impl Read for HardFaultReleaseRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            root: StateRoot::read(buf)?,
            released: ClaimHardFaultResponse::read(buf)?,
        })
    }
}

/// One authenticated state value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Record {
    Registry(Vec<Digest>),
    RegistryEntry(RegistryEntry),
    NativeBalance(u64),
    NativeTransfer(NativeTransferRequest),
    Status(StatusRecord),
    Anchor(Digest),
    Admitted(AdmittedRootsResponse),
    ClaimRoots(ClaimRootsResponse),
    Deposit(DepositEvent),
    Withdrawal(SignedWithdrawal<Key, Digest>),
    Registration(RegistrationRecord),
    WithdrawalRelease(WithdrawalReleaseRecord),
    PayoutRelease(PayoutReleaseRecord),
    HardFault(HardFaultReleaseRecord),
    Refund(ClaimPendingDepositResponse),
    Fault(FaultRecord),
    /// The encoded settlement [`Machine`]. Held as bytes so the record stays
    /// cheap to clone and compare. [`execute`] decodes it explicitly.
    Machine(Bytes),
}

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Registry(r) => {
                13u8.write(buf);
                r.write(buf);
            }
            Self::RegistryEntry(entry) => {
                16u8.write(buf);
                entry.write(buf);
            }
            Self::NativeBalance(r) => {
                14u8.write(buf);
                r.write(buf);
            }
            Self::NativeTransfer(r) => {
                15u8.write(buf);
                r.write(buf);
            }
            Self::Status(record) => {
                0_u8.write(buf);
                record.write(buf);
            }
            Self::Anchor(anchor) => {
                1_u8.write(buf);
                anchor.write(buf);
            }
            Self::Admitted(record) => {
                2_u8.write(buf);
                record.write(buf);
            }
            Self::ClaimRoots(record) => {
                3_u8.write(buf);
                record.write(buf);
            }
            Self::Deposit(record) => {
                4_u8.write(buf);
                record.write(buf);
            }
            Self::Withdrawal(record) => {
                5_u8.write(buf);
                record.write(buf);
            }
            Self::Registration(record) => {
                6_u8.write(buf);
                record.write(buf);
            }
            Self::WithdrawalRelease(record) => {
                7_u8.write(buf);
                record.write(buf);
            }
            Self::PayoutRelease(record) => {
                8_u8.write(buf);
                record.write(buf);
            }
            Self::HardFault(record) => {
                9_u8.write(buf);
                record.write(buf);
            }
            Self::Refund(record) => {
                10_u8.write(buf);
                record.write(buf);
            }
            Self::Fault(record) => {
                11_u8.write(buf);
                record.write(buf);
            }
            Self::Machine(encoded) => {
                12_u8.write(buf);
                encoded.write(buf);
            }
        }
    }
}

impl EncodeSize for Record {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Registry(r) => r.encode_size(),
            Self::RegistryEntry(entry) => entry.encode_size(),
            Self::NativeBalance(r) => r.encode_size(),
            Self::NativeTransfer(r) => r.encode_size(),
            Self::Status(record) => record.encode_size(),
            Self::Anchor(anchor) => anchor.encode_size(),
            Self::Admitted(record) => record.encode_size(),
            Self::ClaimRoots(record) => record.encode_size(),
            Self::Deposit(record) => record.encode_size(),
            Self::Withdrawal(record) => record.encode_size(),
            Self::Registration(record) => record.encode_size(),
            Self::WithdrawalRelease(record) => record.encode_size(),
            Self::PayoutRelease(record) => record.encode_size(),
            Self::HardFault(record) => record.encode_size(),
            Self::Refund(record) => record.encode_size(),
            Self::Fault(record) => record.encode_size(),
            Self::Machine(encoded) => encoded.encode_size(),
        }
    }
}

impl Read for Record {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            13 => {
                let ids = Vec::<Digest>::read_cfg(buf, &(RangeCfg::new(0..=MAX_DEPLOYMENTS), ()))?;
                if ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len() {
                    return Err(CodecError::Invalid("Registry", "duplicate deployment"));
                }
                Ok(Self::Registry(ids))
            }
            16 => Ok(Self::RegistryEntry(RegistryEntry::read(buf)?)),
            14 => Ok(Self::NativeBalance(u64::read(buf)?)),
            15 => Ok(Self::NativeTransfer(NativeTransferRequest::read(buf)?)),
            0 => Ok(Self::Status(StatusRecord::read(buf)?)),
            1 => Ok(Self::Anchor(Digest::read(buf)?)),
            2 => Ok(Self::Admitted(AdmittedRootsResponse::read(buf)?)),
            3 => Ok(Self::ClaimRoots(ClaimRootsResponse::read(buf)?)),
            4 => Ok(Self::Deposit(DepositEvent::read(buf)?)),
            5 => Ok(Self::Withdrawal(SignedWithdrawal::read_cfg(
                buf,
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )?)),
            6 => Ok(Self::Registration(RegistrationRecord::read(buf)?)),
            7 => Ok(Self::WithdrawalRelease(WithdrawalReleaseRecord::read(buf)?)),
            8 => Ok(Self::PayoutRelease(PayoutReleaseRecord::read(buf)?)),
            9 => Ok(Self::HardFault(HardFaultReleaseRecord::read(buf)?)),
            10 => Ok(Self::Refund(ClaimPendingDepositResponse::read(buf)?)),
            11 => Ok(Self::Fault(FaultRecord::read(buf)?)),
            12 => Ok(Self::Machine(Bytes::read_cfg(
                buf,
                &RangeCfg::new(0..=MAX_MACHINE_BYTES),
            )?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// The internal outcome of applying one transaction.
///
/// Never persisted: acceptance is provable through the variant's effect
/// record and a rejection is effect-free, so the typed reason exists only
/// for execution tracing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TxOutcome {
    /// The transaction mutated settlement state.
    Applied,
    /// A challenge adjudicated with no contradiction.
    NoContradiction,
    /// The claimed batch is not claimable now. The exact claim may succeed
    /// later and must not be discarded.
    Unavailable,
    /// The transaction was rejected for a typed reason.
    Rejected(Reject),
}

/// Typed rejection reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reject {
    /// The account is not enrolled in the target deployment.
    UnknownAccount,
    /// A deposit id was reused for another event.
    DepositConflict,
    /// An account already queued another withdrawal.
    WithdrawalConflict,
    /// An epoch registration changed after it was accepted.
    RegistrationConflict,
    /// Another close was admitted or finalized for the epoch.
    AdmissionConflict,
    /// Challenge evidence changed after it was proven.
    ChallengeConflict,
    /// A terminal state claim position was reused.
    PositionConflict,
    /// The next settlement epoch is already registered.
    Fenced,
    /// A deadline-bearing transition landed outside its window, or the
    /// assigned epoch deadlines exceed the block clock.
    Deadline,
    /// The value exceeds the operator storage domain.
    Domain,
    /// The epoch is not the consecutive boundary or its replay expired.
    EpochSequence,
    /// The settlement epoch was not registered.
    NotRegistered,
    /// The close does not match the registered settlement epoch.
    SubmissionMismatch,
    /// The operator staged deposits differ from settlement.
    StagedDivergence,
    /// The operator deposit boundary differs from settlement.
    BoundaryDivergence,
    /// The registration omits a queued settlement withdrawal.
    MissingQueuedWithdrawal,
    /// The registration is missing an opening for a carried withdrawal.
    MissingOpening,
    /// The registration signature failed authentication.
    Signature,
    /// The claim was adjudicated against an immutable finalized batch and
    /// rejected. The verdict can never change.
    ClaimInvalid,
    /// Terminal hard-fault settlement has not begun.
    FaultUnavailable,
    /// The deployment is permanently hard-faulted.
    Faulted,
    /// The settlement chain rejected the transition.
    Chain,
    /// The transaction names an unregistered deployment.
    UnknownDeployment,
    /// Native account cannot cover the authorized debit.
    InsufficientBalance,
    /// The signed resource price differs from genesis policy.
    Fee,
    /// The registry is full or the requested resource budget exceeds policy.
    RegistryLimit,
    /// An immutable registration or native transfer identifier was already consumed.
    NativeConflict,
}

/// The result of applying one transaction: its outcome plus the granular
/// records it derives.
struct Step {
    outcome: TxOutcome,
    /// Derived record writes for an applied transaction.
    writes: Vec<(StateKey, Option<Record>)>,
}

impl Step {
    const fn rejected(reject: Reject) -> Self {
        Self {
            outcome: TxOutcome::Rejected(reject),
            writes: Vec::new(),
        }
    }

    const fn outcome(outcome: TxOutcome) -> Self {
        Self {
            outcome,
            writes: Vec::new(),
        }
    }

    const fn applied(writes: Vec<(StateKey, Option<Record>)>) -> Self {
        Self {
            outcome: TxOutcome::Applied,
            writes,
        }
    }
}

/// One deadline observation that changed machine state.
enum Fired {
    /// The admitted close finalized.
    Finalized {
        epoch: u64,
        batch_id: BatchId<Digest>,
        roots: RootBundle<Digest>,
    },
    /// The deployment hard-faulted.
    Faulted { reason: HardFaultReasonResponse },
}

/// Maps one chain claim rejection onto the retry contract: an unavailable
/// batch is the only state-dependent answer, and every adjudicated rejection
/// is final for the exact claim.
const fn claim_rejection(error: &ClaimError) -> TxOutcome {
    match error {
        ClaimError::Unavailable => TxOutcome::Unavailable,
        ClaimError::Consumed | ClaimError::Reserve | ClaimError::Proof(_) => {
            TxOutcome::Rejected(Reject::ClaimInvalid)
        }
    }
}

/// Maps one settlement chain error onto a typed rejection.
///
/// The clearing chain's own replay protection is the durable authority for
/// conflicting reuse, so its duplicate and consumption errors map onto the
/// conflict taxonomy directly.
const fn chain_rejection(error: &SettlementError) -> Reject {
    match error {
        SettlementError::OperatorHardFaulted => Reject::Faulted,
        SettlementError::EpochAlreadyActive => Reject::Fenced,
        SettlementError::DuplicateDeposit => Reject::DepositConflict,
        SettlementError::DuplicateWithdrawal
        | SettlementError::DuplicateWithdrawalAuthorization => Reject::WithdrawalConflict,
        SettlementError::AlreadyChallenged => Reject::ChallengeConflict,
        SettlementError::ClaimAlreadyConsumed => Reject::PositionConflict,
        SettlementError::AdmissionAfterDeadline
        | SettlementError::EpochAdmissionDeadlineTooLate
        | SettlementError::EpochAdmissionDeadlineNotMonotonic
        | SettlementError::EpochChallengeDuration => Reject::Deadline,
        SettlementError::OperatorNotHardFaulted
        | SettlementError::HardFaultSettlementNotStarted => Reject::FaultUnavailable,
        _ => Reject::Chain,
    }
}

/// Pending writes for one block, deduplicated by key. Iteration order (and
/// therefore the operation order in the batch) is the canonical key order.
type Writes = BTreeMap<StateKey, Option<Record>>;

/// Canonical source beneath the transaction's pending writes.
enum Source<'a, E>
where
    E: StorageContext + Spawner,
{
    Batch(&'a Batch<E>),
    Applied(&'a Qmdb<E>),
}

/// Pending writes over a parent batch or one pinned applied database snapshot.
struct View<'a, E>
where
    E: StorageContext + Spawner,
{
    writes: &'a Writes,
    source: Source<'a, E>,
}

impl<E> View<'_, E>
where
    E: StorageContext + Spawner,
{
    async fn get(&self, key: &StateKey) -> Result<Option<Record>, QmdbError<mmr::Family>> {
        if let Some(record) = self.writes.get(key) {
            return Ok(record.clone());
        }
        match self.source {
            Source::Batch(batch) => batch.get(key).await,
            Source::Applied(db) => db.get(key).await,
        }
    }

    async fn balance(&self, chain: &Digest, account: &Key) -> Result<u64, QmdbError<mmr::Family>> {
        Ok(match self.get(&native_balance_key(chain, account)).await? {
            Some(Record::NativeBalance(balance)) => balance,
            None => 0,
            Some(_) => unreachable!("native balance key has a balance record"),
        })
    }

    /// Reads one deployment's live registration record.
    async fn registration(
        &self,
        deployment: &Digest,
    ) -> Result<Option<RegistrationRecord>, QmdbError<mmr::Family>> {
        match self.get(&registration_key(deployment)).await? {
            None => Ok(None),
            Some(Record::Registration(record)) => Ok(Some(record)),
            Some(_) => unreachable!("the registration key holds a registration record"),
        }
    }

    /// Reads one deployment's admitted close record for `epoch`.
    async fn admitted(
        &self,
        deployment: &Digest,
        epoch: u64,
    ) -> Result<Option<AdmittedRootsResponse>, QmdbError<mmr::Family>> {
        match self.get(&admitted_key(deployment, epoch)).await? {
            None => Ok(None),
            Some(Record::Admitted(record)) => Ok(Some(record)),
            Some(_) => unreachable!("the admitted key holds an admitted record"),
        }
    }
}

/// The settlement machine: the clearing chain plus the last advanced height,
/// persisted whole in the machine record and mutated by block execution.
///
/// Block height is the clock and QMDB is the store. There are no bounded
/// replay caches and no digest-keyed history: replays land on the clearing
/// chain's own replay protection and the granular records, so every replayed
/// transaction is a harmless no-op or a typed conflict.
pub(crate) struct Machine {
    chain: SettlementChain<Sha256, Key>,
    /// Last advanced block height.
    height: u64,
    /// Last advanced block timestamp (milliseconds since the Unix epoch).
    ///
    /// Retained only to re-check strict timestamp monotonicity on replay:
    /// consensus verification already rejected any block whose timestamp
    /// does not exceed its parent's.
    timestamp: u64,
}

impl Write for Machine {
    fn write(&self, buf: &mut impl BufMut) {
        self.chain.write(buf);
        self.height.write(buf);
        self.timestamp.write(buf);
    }
}

impl EncodeSize for Machine {
    fn encode_size(&self) -> usize {
        self.chain.encode_size() + self.height.encode_size() + self.timestamp.encode_size()
    }
}

impl Read for Machine {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            chain: SettlementChain::read_cfg(buf, &MACHINE_BOUNDS)?,
            height: u64::read(buf)?,
            timestamp: u64::read(buf)?,
        })
    }
}

impl Machine {
    /// One configured deployment's genesis machine, constructed from its
    /// configured accounts under the chain-wide genesis `timing` policy.
    pub(crate) fn genesis(config: &Deployment, timing: &Timing) -> Self {
        let chain = SettlementChain::new(
            *config.digest(),
            config.operator.clone(),
            committee().expect("the demo committee is statically valid"),
            config.genesis(),
            0,
            settlement_config(timing),
        )
        .expect("the genesis settlement configuration is valid");
        Self {
            chain,
            height: 0,
            timestamp: 0,
        }
    }

    /// Returns the live registered close: the bound context with the exact
    /// boundary batches the chain committed at registration.
    ///
    /// This is the sealing surface: a validator seals a disseminated dealing
    /// against exactly this chain-authenticated registration, never against
    /// operator-supplied context material.
    pub(crate) fn registered(&self) -> Option<Registered<'_, Key, Digest>> {
        self.chain.registered()
    }

    /// Observes every liveness deadline exactly once for the block at
    /// `height` with `timestamp`, returning the state changes the
    /// observations made so the caller can derive records from them.
    fn advance(&mut self, height: u64, timestamp: u64) -> Vec<Fired> {
        assert!(
            height >= self.height,
            "settlement blocks advance monotonically"
        );
        assert!(
            timestamp > self.timestamp,
            "settlement block timestamps advance strictly"
        );
        self.height = height;
        self.timestamp = timestamp;
        let mut fired = Vec::new();
        let faulted_before = self.chain.hard_fault().is_some();

        // Finalize the admitted pipeline front once its inclusive challenge
        // window has passed. The claim roots must be captured before
        // finalization consumes the front.
        let front = self.chain.pending().map(|batch| batch.roots);
        match self.chain.finalize(height) {
            Ok(finalized) => {
                let roots = front.expect("finalization consumes the pipeline front");
                fired.push(Fired::Finalized {
                    epoch: finalized.epoch,
                    batch_id: finalized.batch_id,
                    roots,
                });
            }

            // No admitted close is ready to finalize at this height.
            Err(
                SettlementError::NoPendingBatch
                | SettlementError::ChallengeWindowOpen
                | SettlementError::BatchInvalidated
                | SettlementError::HardFaultAlreadySettled,
            ) => {}

            // Finalization past the window fails otherwise only on an
            // invariant breach: the pipeline front backing an admitted close
            // is pending, and the intake gates bound every arithmetic arm.
            Err(error) => unreachable!("admitted close must finalize past its window: {error}"),
        }

        // Finalization observed the liveness deadlines for this height on the
        // way in. Repeat the observation explicitly in case it declined
        // before doing so.
        if self.chain.hard_fault().is_none() {
            match self.chain.fault_expired(height) {
                Ok(_) | Err(SettlementError::DeadlineNotReached) => {}

                // `fault_expired` fails otherwise only through its operating
                // gate, and the fault check above proved that gate passing.
                Err(error) => unreachable!("liveness observation failed: {error}"),
            }
        }
        if !faulted_before && let Some(reason) = self.chain.hard_fault() {
            fired.push(Fired::Faulted {
                reason: reason.clone().into(),
            });
        }
        fired
    }

    /// Applies one transaction routed to this machine's deployment `config`
    /// at `height` under the chain-wide genesis `timing` policy. The block's
    /// [`Self::advance`] observation must already have run for that height.
    /// Replayed inputs re-execute and land on their variant's domain guard.
    async fn apply<E>(
        &mut self,
        config: &Deployment,
        height: u64,
        timing: &Timing,
        tx: &SettlementTx,
        view: &View<'_, E>,
    ) -> Result<Step, QmdbError<mmr::Family>>
    where
        E: StorageContext + Spawner,
    {
        Ok(match tx {
            SettlementTx::RegisterDeployment(_)
            | SettlementTx::NativeTransfer(_)
            | SettlementTx::ClaimDeposit(_) => {
                unreachable!("native transaction is executed by the native ledger")
            }
            SettlementTx::Deposit(request) => self.deposit(config, height, &request.event),
            SettlementTx::QueueWithdrawal(request) => {
                self.queue_withdrawal(config, height, request)
            }
            SettlementTx::RegisterEpoch(request) => {
                self.register_epoch(config, height, timing, request, view)
                    .await?
            }
            SettlementTx::Admit(request) => self.admit(config, height, request, view).await?,
            SettlementTx::ClaimWithdrawal(request) => self.claim_withdrawal(config, request),
            SettlementTx::ClaimExternalPayout(request) => {
                self.claim_external_payout(config, request)
            }
            SettlementTx::Challenge(request) => {
                self.challenge(config, height, request, view).await?
            }
            SettlementTx::BeginHardFaultSettlement(_) => {
                self.begin_hard_fault_settlement(config, view).await?
            }
            SettlementTx::ClaimHardFault(request) => self.claim_hard_fault(config, request),
            SettlementTx::ClaimPendingDeposit(request) => {
                self.claim_pending_deposit(config, height, request)
            }
        })
    }

    fn deposit(&mut self, config: &Deployment, height: u64, event: &DepositEvent) -> Step {
        if !config
            .accounts
            .iter()
            .any(|account| account.key == event.account)
        {
            return Step::rejected(Reject::UnknownAccount);
        }

        // The example operator persists monetary values in SQLite INTEGER
        // columns. Apply that deployment-wide domain before settlement takes
        // custody so operator credit cannot fail.
        let holdings = self
            .chain
            .custody_balance()
            .checked_add(self.chain.claimable_balance())
            .and_then(|balance| balance.checked_add(event.amount));
        match holdings {
            Some(holdings) if holdings <= SQLITE_U64_MAX => {}
            _ => return Step::rejected(Reject::Domain),
        }
        if let Err(error) =
            self.chain
                .record_deposit(height, event.id, event.account.clone(), event.amount)
        {
            return Step::rejected(chain_rejection(&error));
        }
        Step::applied(vec![(
            deposit_key(config.digest(), &event.id),
            Some(Record::Deposit(event.clone())),
        )])
    }

    fn queue_withdrawal(
        &mut self,
        config: &Deployment,
        height: u64,
        request: &QueueWithdrawalRequest,
    ) -> Step {
        if let Err(error) = self.chain.queue_withdrawal(
            height,
            request.request.clone(),
            &request.openings,
            eligible,
        ) {
            return Step::rejected(chain_rejection(&error));
        }
        Step::applied(vec![(
            withdrawal_key(config.digest(), request.request.account()),
            Some(Record::Withdrawal(request.request.clone())),
        )])
    }

    async fn register_epoch<E>(
        &mut self,
        config: &Deployment,
        height: u64,
        timing: &Timing,
        request: &RegisterEpochRequest,
        view: &View<'_, E>,
    ) -> Result<Step, QmdbError<mmr::Family>>
    where
        E: StorageContext + Spawner,
    {
        if !verify_chain_registration_signature(
            config,
            request.epoch,
            request.predecessor_liability,
            &request.deposits_root,
            &request.staged_root,
            &request.withdrawals,
            request.fee,
            &request.signature,
        ) {
            return Ok(Step::rejected(Reject::Signature));
        }

        // A second registration for an already-registered epoch conflicts:
        // the record guard makes an exact replay a harmless no-op and any
        // different material a typed conflict.
        if let Some(existing) = view.registration(config.digest()).await?
            && existing.epoch == request.epoch
        {
            return Ok(Step::rejected(Reject::RegistrationConflict));
        }

        // The successor's registration window opens at admission: the next
        // admissible epoch extends the pipeline head, so a registration is
        // acceptable as soon as its predecessor's close is admitted, while
        // that close's challenge window is still open.
        let pending = u64::try_from(self.chain.pending_epoch_count())
            .expect("the admission pipeline is bounded");
        if Some(request.epoch) != self.chain.expected_epoch().checked_add(pending) {
            return Ok(Step::rejected(Reject::EpochSequence));
        }

        // Execution assigns the epoch's absolute deadlines from the inclusion
        // height under the chain-wide genesis policy: the operator chooses
        // nothing about timing.
        let assigned = height
            .checked_add(timing.admission_offset)
            .and_then(|admission_deadline| {
                admission_deadline
                    .checked_add(timing.challenge_duration)
                    .map(|challenge_deadline| (admission_deadline, challenge_deadline))
            });
        let Some((admission_deadline, challenge_deadline)) = assigned else {
            return Ok(Step::rejected(Reject::Deadline));
        };

        // The full staged view must agree before the boundary is derived: a
        // deferral hides its account from both derived boundaries, so root
        // equality alone cannot see a deposit the operator never credited.
        let staged = self.chain.boundary_deposits(&WithdrawalBatch::empty());
        let Ok(staged_root) = staged.root::<Sha256>() else {
            return Ok(Step::rejected(Reject::Chain));
        };
        if staged_root != request.staged_root {
            return Ok(Step::rejected(Reject::StagedDivergence));
        }

        // The canonical boundary is settlement's own custody record with the
        // chain's deferral rule applied. The operator commits the root of the
        // boundary it built its context from, so a diverging deposit view is
        // rejected here without consuming the registration slot.
        let deposits = self.chain.boundary_deposits(&request.withdrawals);
        let Ok(derived_root) = deposits.root::<Sha256>() else {
            return Ok(Step::rejected(Reject::Chain));
        };
        if derived_root != request.deposits_root {
            return Ok(Step::rejected(Reject::BoundaryDivergence));
        }
        let Ok(withdrawals_root) = request.withdrawals.root::<Sha256>() else {
            return Ok(Step::rejected(Reject::Chain));
        };

        // The submitted batch may carry operator-collected requests beyond
        // the queued set, but every queued request must still appear
        // verbatim.
        let pending = self.chain.pending_withdrawals();
        for queued in pending.requests() {
            if request.withdrawals.request_for(queued.account()) != Some(queued) {
                return Ok(Step::rejected(Reject::MissingQueuedWithdrawal));
            }
        }

        // A registration is an immutable admission obligation, so the chain
        // proves every carried extra certifiable with one predecessor-root
        // opening in batch order.
        let mut extra_openings = Vec::new();
        for carried in request
            .withdrawals
            .requests()
            .iter()
            .filter(|entry| pending.request_for(entry.account()).is_none())
        {
            let Some(opening) = request
                .openings
                .iter()
                .find(|opening| &opening.account == carried.account())
            else {
                return Ok(Step::rejected(Reject::MissingOpening));
            };
            extra_openings.push(opening.clone());
        }
        let Ok(context) = epoch_context_at(
            *config.digest(),
            config.operator.clone(),
            request.epoch,
            &deposits,
            &request.withdrawals,
            request.predecessor_liability,
            admission_deadline,
            challenge_deadline,
        ) else {
            return Ok(Step::rejected(Reject::Chain));
        };
        let anchor = *context.payment().anchor();
        if let Err(error) = self.chain.register_epoch(
            height,
            context,
            request.withdrawals.clone(),
            &extra_openings,
            eligible,
        ) {
            return Ok(Step::rejected(chain_rejection(&error)));
        }
        let record = RegistrationRecord {
            epoch: request.epoch,
            predecessor_liability: request.predecessor_liability,
            anchor,
            admission_deadline,
            challenge_deadline,
            deposits_root: request.deposits_root,
            staged_root: request.staged_root,
            withdrawals_root,
            admitted: None,
        };
        Ok(Step::applied(vec![
            (
                anchor_key(config.digest(), request.epoch),
                Some(Record::Anchor(anchor)),
            ),
            (
                registration_key(config.digest()),
                Some(Record::Registration(record)),
            ),
        ]))
    }

    /// Admits one certified close.
    ///
    /// The committee certificate is the sole authorization: execution has no
    /// submitter concept (a transaction is bytes in a block), the request
    /// carries no submitter identity, and every field is checked against the
    /// chain's own registration record and the certificate over the exact
    /// header. A third party relaying a genuine certificate lands the close
    /// identically by design.
    async fn admit<E>(
        &mut self,
        config: &Deployment,
        height: u64,
        request: &AdmitRequest,
        view: &View<'_, E>,
    ) -> Result<Step, QmdbError<mmr::Family>>
    where
        E: StorageContext + Spawner,
    {
        // A close already finalized for this epoch conflicts permanently with
        // any admission that is not an exact replay.
        if let Some(admitted) = view.admitted(config.digest(), request.epoch).await?
            && admitted.finalized
        {
            return Ok(Step::rejected(Reject::AdmissionConflict));
        }
        if request.epoch < self.chain.expected_epoch() {
            return Ok(Step::rejected(Reject::EpochSequence));
        }
        let Some(registration) = view.registration(config.digest()).await? else {
            return Ok(Step::rejected(Reject::NotRegistered));
        };
        if registration.admitted.is_some() {
            return Ok(Step::rejected(Reject::AdmissionConflict));
        }
        let (Ok(deposits_root), Ok(withdrawals_root)) = (
            request.deposits.root::<Sha256>(),
            request.withdrawals.root::<Sha256>(),
        ) else {
            return Ok(Step::rejected(Reject::Chain));
        };
        if registration.epoch != request.epoch
            || registration.predecessor_liability != request.predecessor_liability
            || registration.deposits_root != deposits_root
            || registration.withdrawals_root != withdrawals_root
        {
            return Ok(Step::rejected(Reject::SubmissionMismatch));
        }
        let batch_id = match self.chain.admit(
            height,
            request.header,
            request.roots,
            request.amounts,
            request.certificate.clone(),
        ) {
            Ok(batch_id) => batch_id,
            Err(error) => return Ok(Step::rejected(chain_rejection(&error))),
        };
        let mut record = registration;
        record.admitted = Some(batch_id);
        Ok(Step::applied(vec![
            (
                admitted_key(config.digest(), request.epoch),
                Some(Record::Admitted(AdmittedRootsResponse::new(
                    batch_id,
                    request.roots,
                    false,
                ))),
            ),
            (
                registration_key(config.digest()),
                Some(Record::Registration(record)),
            ),
        ]))
    }

    async fn challenge<E>(
        &mut self,
        config: &Deployment,
        height: u64,
        request: &ChallengeRequest,
        view: &View<'_, E>,
    ) -> Result<Step, QmdbError<mmr::Family>>
    where
        E: StorageContext + Spawner,
    {
        // The evidence length was already bounded by the transaction codec,
        // so the bounded decode inside the chain uses it directly. The chain
        // adjudicates with the sequential strategy.
        let verdict = match self.chain.challenge_encoded(
            height,
            request.batch_id,
            &request.evidence,
            request.evidence.len(),
        ) {
            Ok(verdict) => verdict,
            Err(error) => return Ok(Step::rejected(chain_rejection(&error))),
        };
        match verdict {
            Verdict::NoContradiction => Ok(Step::outcome(TxOutcome::NoContradiction)),
            Verdict::Proven(_) => {
                let reason: HardFaultReasonResponse = self
                    .chain
                    .hard_fault()
                    .cloned()
                    .expect("a proven challenge hard-faults the deployment")
                    .into();
                let mut writes = vec![(
                    fault_key(config.digest()),
                    Some(Record::Fault(FaultRecord::Faulted(reason))),
                )];

                // A proven challenge invalidates the admitted close and
                // clears the live registration slot with it.
                if view.registration(config.digest()).await?.is_some() {
                    writes.push((registration_key(config.digest()), None));
                }
                Ok(Step {
                    outcome: TxOutcome::Applied,
                    writes,
                })
            }
        }
    }

    async fn begin_hard_fault_settlement<E>(
        &mut self,
        config: &Deployment,
        view: &View<'_, E>,
    ) -> Result<Step, QmdbError<mmr::Family>>
    where
        E: StorageContext + Spawner,
    {
        if matches!(
            view.get(&fault_key(config.digest())).await?,
            Some(Record::Fault(FaultRecord::Settling(_)))
        ) {
            return Ok(Step::outcome(TxOutcome::Unavailable));
        }
        let settlement = match self.chain.begin_hard_fault_settlement() {
            Ok(settlement) => settlement,
            Err(error) => return Ok(Step::rejected(chain_rejection(&error))),
        };
        Ok(Step::applied(vec![(
            fault_key(config.digest()),
            Some(Record::Fault(FaultRecord::Settling(settlement.into()))),
        )]))
    }

    fn claim_hard_fault(&mut self, config: &Deployment, request: &ClaimHardFaultRequest) -> Step {
        let root = self.chain.current_state_root();
        let release = match self.chain.claim_hard_fault(&request.opening) {
            Ok(release) => release,
            Err(error) => return Step::rejected(chain_rejection(&error)),
        };
        Step::applied(vec![(
            hard_fault_key(config.digest(), &request.opening.account),
            Some(Record::HardFault(HardFaultReleaseRecord {
                root,
                released: release.into(),
            })),
        )])
    }

    fn claim_pending_deposit(
        &mut self,
        config: &Deployment,
        height: u64,
        request: &ClaimPendingDepositRequest,
    ) -> Step {
        let refund = match self.chain.claim_pending_deposit(height, &request.account) {
            Ok(refund) => refund,
            Err(error) => return Step::rejected(chain_rejection(&error)),
        };
        Step::applied(vec![(
            refund_key(config.digest(), &request.account),
            Some(Record::Refund(refund.into())),
        )])
    }

    fn claim_withdrawal(&mut self, config: &Deployment, request: &WithdrawalClaimRequest) -> Step {
        let release = match self
            .chain
            .claim_withdrawal(request.batch_id, &request.claim)
        {
            Ok(release) => release,
            Err(error) => return Step::outcome(claim_rejection(&error)),
        };
        Step::applied(vec![(
            withdrawal_release_key(config.digest(), &request.batch_id, request.claim.position()),
            Some(Record::WithdrawalRelease(WithdrawalReleaseRecord {
                claim: Sha256::hash(&[&request.claim.encode()]),
                released: release.into(),
            })),
        )])
    }

    fn claim_external_payout(
        &mut self,
        config: &Deployment,
        request: &ExternalPayoutClaimRequest,
    ) -> Step {
        let payout = match self
            .chain
            .claim_external_payout(request.batch_id, &request.claim)
        {
            Ok(payout) => payout,
            Err(error) => return Step::outcome(claim_rejection(&error)),
        };
        Step::applied(vec![(
            payout_release_key(config.digest(), &request.batch_id, request.claim.position()),
            Some(Record::PayoutRelease(PayoutReleaseRecord {
                claim: Sha256::hash(&[&request.claim.encode()]),
                released: payout.into(),
            })),
        )])
    }

    /// The status record for a block at `height` with `timestamp`.
    const fn status(&self, deployment: Digest, height: u64, timestamp: u64) -> StatusRecord {
        StatusRecord {
            height,
            timestamp,
            deployment,
            state_root: self.chain.current_state_root(),
            last_finalized: self.chain.expected_epoch().checked_sub(1),
            custody: self.chain.custody_balance(),
            claimable: self.chain.claimable_balance(),
            hard_faulted: self.chain.hard_fault().is_some(),
        }
    }
}

/// Builds checked native account updates without committing any clearing or replay effect.
async fn balance_changes<E>(
    view: &View<'_, E>,
    chain: &Digest,
    changes: &[(Key, i128)],
) -> Result<Result<Vec<(StateKey, Option<Record>)>, Reject>, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    let mut totals = BTreeMap::<Key, i128>::new();
    for (account, amount) in changes {
        *totals.entry(account.clone()).or_default() += amount;
    }
    let mut writes = Vec::with_capacity(totals.len());
    for (account, change) in totals {
        let balance = i128::from(view.balance(chain, &account).await?) + change;
        let Ok(balance) = u64::try_from(balance) else {
            return Ok(Err(if balance < 0 {
                Reject::InsufficientBalance
            } else {
                Reject::Domain
            }));
        };
        writes.push((
            native_balance_key(chain, &account),
            Some(Record::NativeBalance(balance)),
        ));
    }
    Ok(Ok(writes))
}

/// Native credits are derived only from successful, proof-authenticated clearing releases.
fn released_credits(step: &Step) -> Vec<(Key, i128)> {
    let mut credits = Vec::new();
    for (_, record) in &step.writes {
        match record {
            Some(Record::WithdrawalRelease(record)) => {
                let account = Key::decode(record.released.destination.clone())
                    .expect("accepted destination is a canonical account key");
                credits.push((account, i128::from(record.released.amount)));
            }
            Some(Record::PayoutRelease(record)) => credits.push((
                record.released.receiver.clone(),
                i128::from(record.released.amount),
            )),
            Some(Record::Refund(record)) => {
                credits.push((record.account.clone(), i128::from(record.amount)))
            }
            Some(Record::HardFault(record)) => {
                let release = &record.released;
                credits.push((release.account.clone(), i128::from(release.residual)));
                if let Some(withdrawal) = &release.withdrawal {
                    let account = Key::decode(withdrawal.destination().clone())
                        .expect("accepted destination is a canonical account key");
                    credits.push((account, i128::from(withdrawal.amount())));
                }
            }
            _ => {}
        }
    }
    credits
}

/// Loads each routed registration and machine once from the transaction's exact view.
async fn load_deployments<E>(
    view: &View<'_, E>,
    chain: &Digest,
    deployments: &[Digest],
    entries: &mut [Option<RegistryEntry>],
    machines: &mut [Option<Machine>],
    indices: &[usize],
) -> Result<(), QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    for &index in indices {
        if entries[index].is_none() {
            let Some(Record::RegistryEntry(entry)) = view
                .get(&registry_entry_key(chain, &deployments[index]))
                .await?
            else {
                unreachable!(
                    "directory membership and immutable registration are written atomically"
                );
            };
            assert_eq!(
                entry.deployment.digest(),
                &deployments[index],
                "registration key binds its deployment"
            );
            entries[index] = Some(entry);
        }
        if machines[index].is_none() {
            let Some(Record::Machine(encoded)) =
                view.get(&machine_key(&deployments[index])).await?
            else {
                unreachable!("every registered deployment has a machine");
            };
            machines[index] = Some(Machine::decode(encoded).expect("machine encoding is valid"));
        }
    }
    Ok(())
}

/// Applies native ownership and clearing effects within the same uncommitted block view.
#[allow(clippy::too_many_arguments)]
async fn apply_native<E>(
    native: &NativeGenesis,
    chain_id: &Digest,
    entries: &mut Vec<Option<RegistryEntry>>,
    deployments: &mut Vec<Digest>,
    machines: &mut Vec<Option<Machine>>,
    height: u64,
    timestamp: u64,
    timing: &Timing,
    tx: &SettlementTx,
    view: &View<'_, E>,
) -> Result<Step, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    if let SettlementTx::NativeTransfer(request) = tx {
        if !request.verify(chain_id) {
            return Ok(Step::rejected(Reject::Signature));
        }
        if request.amount == 0 {
            return Ok(Step::rejected(Reject::Domain));
        }
        let key = native_transfer_key(chain_id, &request.from, &request.id);
        if view.get(&key).await?.is_some() {
            return Ok(Step::rejected(Reject::NativeConflict));
        }
        if view.balance(chain_id, &request.from).await? < request.amount {
            return Ok(Step::rejected(Reject::InsufficientBalance));
        }
        let changes = [
            (request.from.clone(), -i128::from(request.amount)),
            (request.to.clone(), i128::from(request.amount)),
        ];
        let mut writes = match balance_changes(view, chain_id, &changes).await? {
            Ok(writes) => writes,
            Err(error) => return Ok(Step::rejected(error)),
        };
        writes.push((key, Some(Record::NativeTransfer(request.clone()))));
        return Ok(Step::applied(writes));
    }
    if let SettlementTx::RegisterDeployment(request) = tx {
        if !request.verify(chain_id) {
            return Ok(Step::rejected(Reject::Signature));
        }
        if request.fee != native.registration_fee {
            return Ok(Step::rejected(Reject::Fee));
        }
        let Ok(entry) = request.entry(native) else {
            return Ok(Step::rejected(Reject::Domain));
        };
        let digest = *entry.deployment.digest();
        if deployments.contains(&digest) {
            return Ok(Step::rejected(Reject::NativeConflict));
        }
        if entries.len() >= native.max_deployments as usize
            || request.max_dealing_bytes == 0
            || request.max_dealing_bytes > native.max_dealing_bytes
            || request.accounts.len() > crate::protocol::MAX_ACCOUNTS
        {
            return Ok(Step::rejected(Reject::RegistryLimit));
        }
        let changes = [
            (request.operator.clone(), -i128::from(request.fee)),
            (native.fee_recipient.clone(), i128::from(request.fee)),
        ];
        if view.balance(chain_id, &request.operator).await? < request.fee {
            return Ok(Step::rejected(Reject::InsufficientBalance));
        }
        let mut writes = match balance_changes(view, chain_id, &changes).await? {
            Ok(writes) => writes,
            Err(error) => return Ok(Step::rejected(error)),
        };
        let mut machine = Machine::genesis(&entry.deployment, timing);
        machine.height = height;
        machine.timestamp = timestamp;
        writes.push((
            registry_entry_key(chain_id, &digest),
            Some(Record::RegistryEntry(entry.clone())),
        ));
        entries.push(Some(entry));
        deployments.push(digest);
        machines.push(Some(machine));
        writes.push((
            registry_key(chain_id),
            Some(Record::Registry(deployments.clone())),
        ));
        return Ok(Step::applied(writes));
    }
    if let SettlementTx::ClaimDeposit(request) = tx {
        if !request.deposit.verify(chain_id) {
            return Ok(Step::rejected(Reject::Signature));
        }
        let claim_tx = match &request.claim {
            FinalizedClaim::Withdrawal(claim) => SettlementTx::ClaimWithdrawal(claim.clone()),
            FinalizedClaim::ExternalPayout(claim) => {
                SettlementTx::ClaimExternalPayout(claim.clone())
            }
        };
        let source = match route(deployments, &claim_tx) {
            Ok(index) => index,
            Err(outcome) => return Ok(Step::outcome(outcome)),
        };
        let target = match route(deployments, tx) {
            Ok(index) => index,
            Err(outcome) => return Ok(Step::outcome(outcome)),
        };
        load_deployments(
            view,
            chain_id,
            deployments,
            entries,
            machines,
            &[source, target],
        )
        .await?;
        let source_config = &entries[source]
            .as_ref()
            .expect("source registration loaded")
            .deployment;
        let target_config = &entries[target]
            .as_ref()
            .expect("target registration loaded")
            .deployment;

        // Trial machines own the entire compound operation. Block deadline observations already
        // belong to the originals and remain durable when either trial rejects.
        let mut source_trial = Machine::decode(
            machines[source]
                .as_ref()
                .expect("source machine loaded")
                .encode(),
        )
        .expect("machine encoding is valid");
        let mut step = source_trial
            .apply(source_config, height, timing, &claim_tx, view)
            .await?;
        if step.outcome != TxOutcome::Applied {
            return Ok(step);
        }
        let mut credits = released_credits(&step);
        if credits.len() != 1 || credits[0].0 != request.deposit.event.account {
            return Ok(Step::rejected(Reject::Signature));
        }
        let mut target_trial = if target == source {
            None
        } else {
            Some(
                Machine::decode(
                    machines[target]
                        .as_ref()
                        .expect("target machine loaded")
                        .encode(),
                )
                .expect("machine encoding is valid"),
            )
        };
        let target_machine = target_trial.as_mut().unwrap_or(&mut source_trial);
        let deposit = target_machine.deposit(target_config, height, &request.deposit.event);
        if deposit.outcome != TxOutcome::Applied {
            return Ok(Step::outcome(deposit.outcome));
        }
        credits.push((
            request.deposit.event.account.clone(),
            -i128::from(request.deposit.event.amount),
        ));
        let balances = match balance_changes(view, chain_id, &credits).await? {
            Ok(writes) => writes,
            Err(error) => return Ok(Step::rejected(error)),
        };
        step.writes.extend(deposit.writes);
        step.writes.extend(balances);
        machines[source] = Some(source_trial);
        if let Some(target_trial) = target_trial {
            machines[target] = Some(target_trial);
        }
        return Ok(step);
    }
    let index = match route(deployments, tx) {
        Ok(index) => index,
        Err(outcome) => return Ok(Step::outcome(outcome)),
    };
    load_deployments(view, chain_id, deployments, entries, machines, &[index]).await?;
    let entry = entries[index].as_ref().expect("routed registration loaded");
    let config = &entry.deployment;
    let mut changes = Vec::new();
    match tx {
        SettlementTx::Deposit(request) => {
            if !request.verify(chain_id) {
                return Ok(Step::rejected(Reject::Signature));
            }
            changes.push((
                request.event.account.clone(),
                -i128::from(request.event.amount),
            ));
        }
        SettlementTx::RegisterEpoch(request) => {
            let fee = u64::from(entry.max_dealing_bytes).div_ceil(1024) * native.epoch_fee;
            if request.fee != fee {
                return Ok(Step::rejected(Reject::Fee));
            }
            if view.balance(chain_id, &config.operator).await? < fee {
                return Ok(Step::rejected(Reject::InsufficientBalance));
            }
            changes.push((config.operator.clone(), -i128::from(fee)));
            changes.push((native.fee_recipient.clone(), i128::from(fee)));
        }
        _ => {}
    }
    let balances = match balance_changes(view, chain_id, &changes).await? {
        Ok(writes) => writes,
        Err(error) => return Ok(Step::rejected(error)),
    };
    let mut step = machines[index]
        .as_mut()
        .expect("routed machine loaded")
        .apply(config, height, timing, tx, view)
        .await?;
    if step.outcome == TxOutcome::Applied {
        step.writes.extend(balances);

        // A release reduces clearing custody by the same value it credits. Genesis bounds
        // total native and clearing supply by u64, so a successful release cannot overflow.
        let credits = released_credits(&step);
        step.writes.extend(
            balance_changes(view, chain_id, &credits)
                .await?
                .expect("conserved native supply bounds release credits"),
        );
    }
    Ok(step)
}

/// Resolves a claimed deployment route. Each machine verifies its own batch and context bindings.
fn route(deployments: &[Digest], tx: &SettlementTx) -> Result<usize, TxOutcome> {
    let digest = tx
        .deployment()
        .ok_or(TxOutcome::Rejected(Reject::UnknownDeployment))?;
    deployments
        .iter()
        .position(|deployment| *deployment == digest)
        .ok_or(TxOutcome::Rejected(Reject::UnknownDeployment))
}

/// One proof-authorized effect with multiple valid transaction representations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProofAction {
    Effect(StateKey),
    Challenge {
        deployment: Digest,
        batch_id: BatchId<Digest>,
    },
}

/// Eligibility for bounded ingress at one coherent applied snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Preflight {
    Eligible { action: Option<ProofAction> },
    Unavailable,
}

/// Tests canonical execution without changing state or advancing its clock.
///
/// The applied read guard pins all trial reads to the finalized tip. It is released before
/// returning: eligibility is advisory and execution rechecks every condition at inclusion.
pub(crate) async fn preflight<E>(
    db: &Database<E>,
    finalized: &Finalized,
    native: &NativeGenesis,
    timing: &Timing,
    tx: &SettlementTx,
) -> Result<Preflight, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    let guard = db.read().await;
    let Some(tip) = finalized.latest() else {
        return Ok(Preflight::Unavailable);
    };
    if guard.root() != tip.root {
        return Ok(Preflight::Unavailable);
    }
    let chain_id = native.chain_id();
    let mut deployments = match guard.get(&registry_key(&chain_id)).await? {
        Some(Record::Registry(deployments)) => deployments,
        None => return Ok(Preflight::Unavailable),
        Some(_) => unreachable!("registry key has a directory record"),
    };
    let mut entries = vec![None; deployments.len()];
    let mut machines = (0..deployments.len()).map(|_| None).collect();
    let writes = Writes::new();
    let view = View {
        writes: &writes,
        source: Source::Applied(&guard),
    };
    let step = apply_native(
        native,
        &chain_id,
        &mut entries,
        &mut deployments,
        &mut machines,
        tip.height,
        tip.timestamp,
        timing,
        tx,
        &view,
    )
    .await?;
    if step.outcome != TxOutcome::Applied {
        return Ok(Preflight::Unavailable);
    }
    let action = match tx {
        SettlementTx::Admit(request) => Some(ProofAction::Effect(admitted_key(
            &request.deployment,
            request.epoch,
        ))),
        SettlementTx::Challenge(request) => Some(ProofAction::Challenge {
            deployment: request.deployment,
            batch_id: request.batch_id,
        }),
        SettlementTx::ClaimWithdrawal(request) => {
            Some(ProofAction::Effect(withdrawal_release_key(
                &request.deployment,
                &request.batch_id,
                request.claim.position(),
            )))
        }
        SettlementTx::ClaimExternalPayout(request) => {
            Some(ProofAction::Effect(payout_release_key(
                &request.deployment,
                &request.batch_id,
                request.claim.position(),
            )))
        }
        SettlementTx::ClaimDeposit(request) => Some(ProofAction::Effect(match &request.claim {
            FinalizedClaim::Withdrawal(claim) => {
                withdrawal_release_key(&claim.deployment, &claim.batch_id, claim.claim.position())
            }
            FinalizedClaim::ExternalPayout(claim) => {
                payout_release_key(&claim.deployment, &claim.batch_id, claim.claim.position())
            }
        })),
        _ => None,
    };
    Ok(Preflight::Eligible { action })
}

/// Executes native transfers and clearing transitions in one deterministic state fork.
///
/// The immutable genesis config supplies the chain domain and initial allocations. The
/// parent state's registry supplies every currently registered deployment. Block height is
/// the clock; the certified timestamp supplies recency metadata only.
///
/// The execution future is heap-owned so proposal and replay call chains do not accumulate
/// its state machine's stack footprint.
#[boxed]
pub(crate) async fn execute<E>(
    batch: Batch<E>,
    height: Height,
    timestamp: u64,
    timing: &Timing,
    native: &NativeGenesis,
    transactions: &[SettlementTx],
) -> Result<Sealed<E>, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    let chain_id = native.chain_id();
    let mut writes = Writes::new();
    let (mut deployments, mut entries) = match batch.get(&registry_key(&chain_id)).await? {
        Some(Record::Registry(ids)) => {
            let entries = vec![None; ids.len()];
            (ids, entries)
        }
        None => {
            assert!(native.validate(), "genesis supply and policy are valid");
            for account in &native.balances {
                writes.insert(
                    native_balance_key(&chain_id, &account.key),
                    Some(Record::NativeBalance(account.balance)),
                );
            }
            for entry in &native.deployments {
                writes.insert(
                    registry_entry_key(&chain_id, entry.deployment.digest()),
                    Some(Record::RegistryEntry(entry.clone())),
                );
            }
            let deployments = native
                .deployments
                .iter()
                .map(|entry| *entry.deployment.digest())
                .collect::<Vec<_>>();
            writes.insert(
                registry_key(&chain_id),
                Some(Record::Registry(deployments.clone())),
            );
            (
                deployments,
                native.deployments.iter().cloned().map(Some).collect(),
            )
        }
        Some(_) => unreachable!("registry key has a directory record"),
    };

    // Every registered machine advances, including deployments without transactions in this block.
    let mut machines = Vec::with_capacity(deployments.len());
    for (index, deployment) in deployments.iter().enumerate() {
        let machine = match batch.get(&machine_key(deployment)).await? {
            None => Machine::genesis(
                &entries[index]
                    .as_ref()
                    .expect("only genesis machines are absent")
                    .deployment,
                timing,
            ),
            Some(Record::Machine(encoded)) => {
                Machine::decode_cfg(encoded, &()).expect("the persisted machine decodes")
            }
            Some(_) => unreachable!("the machine key holds a machine record"),
        };
        machines.push(Some(machine));
    }

    // Observe each machine's deadlines exactly once for this block, deriving
    // records from every observation that changed machine state.
    for (deployment, machine) in deployments.iter().zip(machines.iter_mut()) {
        let machine = machine.as_mut().expect("all block machines loaded");
        for fired in machine.advance(height.get(), timestamp) {
            let view = View {
                writes: &writes,
                source: Source::Batch(&batch),
            };
            let emitted = match &fired {
                Fired::Finalized {
                    epoch,
                    batch_id,
                    roots,
                } => {
                    let mut emitted = vec![
                        (
                            claim_roots_key(deployment, batch_id),
                            Some(Record::ClaimRoots(ClaimRootsResponse {
                                withdrawal_outputs: roots.withdrawal_outputs,
                                change: roots.change,
                            })),
                        ),
                        (
                            admitted_key(deployment, *epoch),
                            Some(Record::Admitted(AdmittedRootsResponse::new(
                                *batch_id, *roots, true,
                            ))),
                        ),
                    ];

                    // Finalization retires the slot only when the singleton
                    // still belongs to the finalized epoch: a successor
                    // registered at admission has already taken it over and
                    // stays live.
                    if let Some(registration) = view.registration(deployment).await?
                        && registration.epoch == *epoch
                    {
                        emitted.push((registration_key(deployment), None));
                    }
                    emitted
                }
                Fired::Faulted { reason } => {
                    let mut emitted = vec![(
                        fault_key(deployment),
                        Some(Record::Fault(FaultRecord::Faulted(reason.clone()))),
                    )];

                    // The fault drops an unadmitted registration. An admitted
                    // close survives for FIFO finalization, which retires its
                    // record itself.
                    if let Some(registration) = view.registration(deployment).await?
                        && registration.admitted.is_none()
                    {
                        emitted.push((registration_key(deployment), None));
                    }
                    emitted
                }
            };
            for (key, value) in emitted {
                writes.insert(key, value);
            }
        }
    }

    for tx in transactions {
        let view = View {
            writes: &writes,
            source: Source::Batch(&batch),
        };
        let step = apply_native(
            native,
            &chain_id,
            &mut entries,
            &mut deployments,
            &mut machines,
            height.get(),
            timestamp,
            timing,
            tx,
            &view,
        )
        .await?;
        if step.outcome != TxOutcome::Applied {
            debug!(outcome = ?step.outcome, digest = ?tx.digest(), "transaction left no effect");
        }
        for (key, value) in step.writes {
            writes.insert(key, value);
        }
    }
    for (deployment, machine) in deployments.iter().zip(machines.iter()) {
        let machine = machine.as_ref().expect("all block machines loaded");
        writes.insert(
            status_key(deployment),
            Some(Record::Status(machine.status(
                *deployment,
                height.get(),
                timestamp,
            ))),
        );
        writes.insert(
            machine_key(deployment),
            Some(Record::Machine(machine.encode())),
        );
    }
    let mut batch = batch;
    for (key, value) in writes {
        batch = batch.write(key, value);
    }
    batch.merkleize().await
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use crate::protocol::identities;
    use bytes::BytesMut;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn applied_trial_reads_finish_with_a_queued_writer() {
        deterministic::Runner::default().start(|context| async move {
            let db = crate::chain::tests::open(context, "trial-writer").await;
            let guard = db.read().await;
            let writes = Writes::new();
            let view = View {
                writes: &writes,
                source: Source::Applied(&guard),
            };
            let chain = Sha256::hash(&[b"trial-writer-chain"]);
            assert_eq!(view.get(&registry_key(&chain)).await.unwrap(), None);
            let mut writer = Box::pin(db.write());
            assert!(futures::poll!(writer.as_mut()).is_pending());
            assert_eq!(
                view.get(&native_balance_key(&chain, &identities()[0].key))
                    .await
                    .unwrap(),
                None
            );
            drop(guard);
            let (slot, state) = writer.await;
            slot.put(state);
            assert_eq!(
                db.read().await.get(&registry_key(&chain)).await.unwrap(),
                None
            );
        });
    }

    #[test]
    fn registry_directory_is_bounded_unique_and_independent_of_rosters() {
        for count in [0, 1, MAX_DEPLOYMENTS] {
            let ids = (0..count)
                .map(|index| Sha256::hash(&[&index.to_le_bytes()]))
                .collect::<Vec<_>>();
            let record = Record::Registry(ids);
            let encoded = record.encode();
            assert!(encoded.len() <= 2 + MAX_DEPLOYMENTS * 32);
            assert_eq!(Record::decode(encoded.clone()).unwrap(), record);
            for end in 0..encoded.len() {
                assert!(Record::decode(encoded.slice(..end)).is_err());
            }
        }
        let id = Sha256::hash(&[b"duplicate-deployment"]);
        assert!(Record::decode(Record::Registry(vec![id; 2]).encode()).is_err());
        assert!(Record::decode(Record::Registry(vec![id; MAX_DEPLOYMENTS + 1]).encode()).is_err());
    }

    #[test]
    fn anchored_record_codecs_round_trip() {
        let batch_id = BatchId::new(Sha256::hash(&[b"anchored-record-batch"]));
        let change = VectorRoot {
            digest: Sha256::hash(&[b"anchored-record-change"]),
        };
        let root = |name: &[u8]| VectorRoot {
            digest: Sha256::hash(&[name]),
        };
        let roots = RootBundle {
            change,
            withdrawal_outputs: root(b"anchored-record-outputs"),
            successor: StateRoot::new(Sha256::hash(&[b"anchored-record-successor"])),
        };
        for admitted in [
            AdmittedRootsResponse::new(batch_id, roots, false),
            AdmittedRootsResponse::new(batch_id, roots, true),
        ] {
            let mut expected = Vec::new();
            batch_id.write(&mut expected);
            roots.write(&mut expected);
            admitted.finalized.write(&mut expected);
            assert_eq!(admitted.encode().as_ref(), expected);
            let decoded = AdmittedRootsResponse::decode(admitted.encode()).unwrap();
            assert_eq!(decoded, admitted);
        }
        let roots = ClaimRootsResponse {
            withdrawal_outputs: VectorRoot {
                digest: Sha256::hash(&[b"anchored-record-outputs"]),
            },
            change,
        };
        assert_eq!(ClaimRootsResponse::decode(roots.encode()).unwrap(), roots);
        let mut trailing = roots.encode().to_vec();
        trailing.push(0xff);
        assert!(ClaimRootsResponse::decode(Bytes::from(trailing)).is_err());
    }

    #[test]
    fn recovery_record_codecs_preserve_fault_metadata_and_optional_withdrawal() {
        let batch_id = BatchId::new(Sha256::hash(&[b"fault-metadata-batch"]));
        let account = identities()[0].key.clone();
        for reason in [
            HardFaultReasonResponse::ProvenChallenge {
                batch_id,
                kind: ChallengeKind::HigherAckEntry,
            },
            HardFaultReasonResponse::ExpiredDeposit {
                account: account.clone(),
                expired_at: 11,
            },
            HardFaultReasonResponse::ExpiredWithdrawal {
                account: account.clone(),
                expired_at: 13,
            },
            HardFaultReasonResponse::ExpiredRegistration {
                anchor: Sha256::hash(&[b"expired-registration-anchor"]),
                epoch: 17,
                expired_at: 19,
            },
        ] {
            assert_eq!(
                HardFaultReasonResponse::decode(reason.encode()).unwrap(),
                reason
            );
        }
        assert!(HardFaultReasonResponse::decode(Bytes::from_static(&[4])).is_err());

        let mut encoded = BytesMut::new();
        account.write(&mut encoded);
        true.write(&mut encoded);
        Bytes::from_static(b"recovery-destination").write(&mut encoded);
        7_u64.write(&mut encoded);
        93_u64.write(&mut encoded);
        100_u64.write(&mut encoded);
        let response = ClaimHardFaultResponse::decode(encoded.freeze()).unwrap();
        let withdrawal = response.withdrawal.as_ref().unwrap();
        assert_eq!(withdrawal.destination().as_ref(), b"recovery-destination");
        assert_eq!(withdrawal.amount(), 7);
        assert_eq!(
            ClaimHardFaultResponse::decode(response.encode()).unwrap(),
            response
        );
    }
}
