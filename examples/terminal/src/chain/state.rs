//! Settlement state layout and block execution over QMDB.
//!
//! # State shape
//!
//! One chain hosts several deployments, and every key domain carries the
//! deployment dimension. Every key is 32 entropy bytes (a domain-tagged
//! digest of the deployment digest and the record's identity) followed by
//! one domain tag byte, so the prefix-indexing translator sees high-entropy
//! prefixes and the domain stays explicit in the key. All domains live
//! forever. The value is the [`Record`] enum, one variant per domain:
//!
//! - machine singleton (per deployment): the codec-encoded settlement
//!   machine (the clearing [`SettlementChain`] plus the last advanced
//!   height)
//! - status singleton (per deployment): height, block timestamp,
//!   deployment, clearing state root, last finalized epoch, custody,
//!   claimable, hard fault flag
//! - epoch anchor by epoch, admitted roots by epoch, claim roots by batch id
//! - deposit records by id, withdrawal queue by account, registration
//!   singleton (per deployment), fault singleton (per deployment)
//! - release records: withdrawal by (batch, position), payout by (batch,
//!   position), hard fault by account, deposit refund by account
//!
//! The machine record is state, never a query target: every certified read
//! goes through the granular domains, which remain derived write-only
//! projections of the machine. The stateful determinism contract holds
//! trivially because the machines themselves live in the batch: given the
//! same parent state and inputs, execution reads, mutates, and rewrites the
//! same values on every fork.
//!
//! # Deployment isolation
//!
//! Execution routes every transaction to exactly one configured deployment's
//! machine (see [`crate::chain::tx`] for how each variant names or derives
//! its deployment) and applies it there alone. The isolation invariant: no
//! transaction reads or writes another deployment's records. Every key a
//! transaction's handler touches derives from its routed deployment's
//! digest, the machine it mutates is that deployment's, and a transaction
//! naming an unconfigured deployment is rejected effect-free with the typed
//! [`Reject::UnknownDeployment`] reason. Deadline observations likewise run
//! per machine, and each deployment's derived records are written under its
//! own digest.
//!
//! # Block-height deadlines
//!
//! Block height is the clock, and every deadline is an absolute block height
//! opened by the chain at the inclusion of the operator submission that
//! triggers it. A registration carries no timing: execution assigns its
//! admission deadline (the inclusion height plus the genesis admission
//! offset) and its challenge deadline (the admission deadline plus the
//! genesis challenge duration), and an admission opens the challenge window
//! and the successor epoch's registration eligibility while that window is
//! still running. Deposits and withdrawals carry their signed absolute
//! deadlines in height units. The deployment fixes the policy, the chain
//! assigns the instance, and the operator chooses nothing about timing, only
//! when to submit. An idle deployment has no live obligations and can never
//! fault by idling. There is no admission fast-forward: finalization waits
//! for real heights past the challenge deadline.
//!
//! Block timestamps are threaded through execution only for the status
//! record (query recency and display). No deadline ever reads a timestamp.
//!
//! # Replay protection
//!
//! Replay protection is domain state, never a history of transaction hashes:
//! every transaction carries a natural idempotence key, so no account nonces
//! and no digest-keyed outcome map are needed and the guard set is O(live
//! state). A duplicate inclusion of already-applied bytes re-executes and
//! lands on its variant's own guard as a harmless no-op or a typed conflict:
//! a deposit on its consumed id, a withdrawal on its account slot and replay
//! id, a registration on the registration record and the epoch sequence, an
//! admission on the registration's admitted mark and the admitted record, a
//! claim on its consumed (batch, position) or account release, a challenge
//! on the one-proven-per-batch rule, and the hard-fault transitions on the
//! fault records. Rejected transactions write nothing: acceptance is provable
//! through the variant's effect record, and a rejection is effect-free.
//!
//! # Execution shape
//!
//! [`execute`] runs one block: decode the machine record (or start from
//! genesis), observe deadlines exactly once for the block height, apply each
//! transaction to a typed outcome (never a panic for data-dependent
//! rejections), then write the derived records, the status singleton, and
//! the re-encoded machine, and merkleize. The typed outcome is internal:
//! only an applied transaction's derived records reach state.

use crate::{
    chain::{
        tx::{
            AdmitRequest, ChallengeRequest, ClaimHardFaultRequest, ClaimPendingDepositRequest,
            ExternalPayoutClaimRequest, QueueWithdrawalRequest, RegisterEpochRequest, SettlementTx,
            WithdrawalClaimRequest,
        },
        types::{Batch, Database, KEY_BYTES, Sealed, StateKey},
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
    settlement::{
        Bounds, ClaimError, DepositRefund, HardFaultReason, HardFaultRelease, HardFaultSettlement,
        Registered, SettlementChain, SettlementError,
    },
    state::{AccountState, StateLeaf},
    transition::{BatchId, ExternalPayout, StateCache, WithdrawalOutput},
};
use commonware_codec::{
    Decode, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_glue::stateful::db::Unmerkleized as _;
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

/// The demo asset adapter admits any non-empty destination within the
/// operator bound.
const fn eligible(destination: &Bytes) -> bool {
    !destination.is_empty() && destination.len() <= MAX_DESTINATION_BYTES
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
    pub(crate) state_root: VectorRoot<Digest>,
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
            state_root: VectorRoot::read(buf)?,
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

/// The identity and change root of the close admitted for one epoch.
///
/// Receivers anchor reconciliation against this record, so operator-served
/// committed-side evidence is trusted only when it matches it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedRootsResponse {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) change: VectorRoot<Digest>,
    /// Whether the close finalized. While false, its inclusive challenge window is open.
    pub(crate) finalized: bool,
}

impl Write for AdmittedRootsResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.change.write(buf);
        self.finalized.write(buf);
    }
}

impl EncodeSize for AdmittedRootsResponse {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size() + self.change.encode_size() + self.finalized.encode_size()
    }
}

impl Read for AdmittedRootsResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            batch_id: BatchId::read(buf)?,
            change: VectorRoot::read(buf)?,
            finalized: bool::read(buf)?,
        })
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
        ChallengeKind::LatestAcknowledgedSend => 0,
        ChallengeKind::HigherShardTip => 1,
        ChallengeKind::InconsistentReceiptRange => 2,
        ChallengeKind::ReceiptFork => 3,
    }
}

const fn challenge_kind_from_tag(tag: u8) -> Result<ChallengeKind, CodecError> {
    match tag {
        0 => Ok(ChallengeKind::LatestAcknowledgedSend),
        1 => Ok(ChallengeKind::HigherShardTip),
        2 => Ok(ChallengeKind::InconsistentReceiptRange),
        3 => Ok(ChallengeKind::ReceiptFork),
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
    pub(crate) frozen_state_root: VectorRoot<Digest>,
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
            frozen_state_root: VectorRoot::read(buf)?,
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
    /// Digest of the exact opening that consumed the position.
    pub(crate) opening: Digest,
    pub(crate) released: ClaimHardFaultResponse,
}

impl Write for HardFaultReleaseRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.opening.write(buf);
        self.released.write(buf);
    }
}

impl EncodeSize for HardFaultReleaseRecord {
    fn encode_size(&self) -> usize {
        self.opening.encode_size() + self.released.encode_size()
    }
}

impl Read for HardFaultReleaseRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            opening: Digest::read(buf)?,
            released: ClaimHardFaultResponse::read(buf)?,
        })
    }
}

/// One state value. Every domain stores exactly one variant.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Record {
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
/// for execution tracing and the advisory dry-run taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TxOutcome {
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
#[repr(u8)]
pub(crate) enum Reject {
    /// The account is not a configured terminal agent.
    UnknownAccount = 0,
    /// A deposit id was reused for another event.
    DepositConflict = 1,
    /// An account already queued another withdrawal.
    WithdrawalConflict = 2,
    /// An epoch registration changed after it was accepted.
    RegistrationConflict = 3,
    /// Another close was admitted or finalized for the epoch.
    AdmissionConflict = 4,
    /// Challenge evidence changed after it was proven.
    ChallengeConflict = 5,
    /// A terminal state claim position was reused.
    PositionConflict = 6,
    /// The next settlement epoch is already registered.
    Fenced = 7,
    /// A deadline-bearing transition landed outside its window, or the
    /// assigned epoch deadlines exceed the block clock.
    Deadline = 8,
    /// The value exceeds the operator storage domain.
    Domain = 9,
    /// The epoch is not the consecutive boundary or its replay expired.
    EpochSequence = 10,
    /// The settlement epoch was not registered.
    NotRegistered = 11,
    /// The close does not match the registered settlement epoch.
    SubmissionMismatch = 12,
    /// The operator staged deposits differ from settlement.
    StagedDivergence = 13,
    /// The operator deposit boundary differs from settlement.
    BoundaryDivergence = 14,
    /// The registration omits a queued settlement withdrawal.
    MissingQueuedWithdrawal = 15,
    /// The registration is missing an opening for a carried withdrawal.
    MissingOpening = 16,
    /// The registration signature failed authentication.
    Signature = 17,
    /// The claim was adjudicated against an immutable finalized batch and
    /// rejected. The verdict can never change.
    ClaimInvalid = 18,
    /// Terminal hard-fault settlement has not begun.
    FaultUnavailable = 19,
    /// The deployment is permanently hard-faulted.
    Faulted = 20,
    /// The settlement chain rejected the transition.
    Chain = 21,
    /// The transaction names a deployment this chain does not configure.
    UnknownDeployment = 22,
}

impl Reject {
    const fn from_tag(tag: u8) -> Result<Self, CodecError> {
        Ok(match tag {
            0 => Self::UnknownAccount,
            1 => Self::DepositConflict,
            2 => Self::WithdrawalConflict,
            3 => Self::RegistrationConflict,
            4 => Self::AdmissionConflict,
            5 => Self::ChallengeConflict,
            6 => Self::PositionConflict,
            7 => Self::Fenced,
            8 => Self::Deadline,
            9 => Self::Domain,
            10 => Self::EpochSequence,
            11 => Self::NotRegistered,
            12 => Self::SubmissionMismatch,
            13 => Self::StagedDivergence,
            14 => Self::BoundaryDivergence,
            15 => Self::MissingQueuedWithdrawal,
            16 => Self::MissingOpening,
            17 => Self::Signature,
            18 => Self::ClaimInvalid,
            19 => Self::FaultUnavailable,
            20 => Self::Faulted,
            21 => Self::Chain,
            22 => Self::UnknownDeployment,
            tag => return Err(CodecError::InvalidEnum(tag)),
        })
    }
}

/// Advisory dry-run verdict for one submitted transaction, answered by the
/// serving validator against its latest applied state.
///
/// Unauthenticated UX advice for submitters, never authorization or
/// evidence: execution re-checks everything at inclusion, and a `Doomed`
/// answer can go stale the moment state advances. It exists because
/// rejections are effect-free, so this is the only typed diagnosis a
/// submitter gets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Advice {
    /// The latest applied state already holds the transaction's effect.
    Applied,
    /// The checked subset (stateless checks plus a read-only feasibility
    /// peek at the domain records the transaction would consume) shows no
    /// contradiction. Deeper data-dependent checks still run at inclusion.
    Plausible,
    /// The transaction would be rejected as of the latest applied state.
    Doomed(Reject),
}

impl Write for Advice {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Applied => 0_u8.write(buf),
            Self::Plausible => 1_u8.write(buf),
            Self::Doomed(reject) => {
                2_u8.write(buf);
                (*reject as u8).write(buf);
            }
        }
    }
}

impl EncodeSize for Advice {
    fn encode_size(&self) -> usize {
        match self {
            Self::Doomed(_) => 2,
            _ => 1,
        }
    }
}

impl Read for Advice {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Applied),
            1 => Ok(Self::Plausible),
            2 => Ok(Self::Doomed(Reject::from_tag(u8::read(buf)?)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// The result of applying one transaction: its outcome plus the granular
/// records it derives.
pub(crate) struct Step {
    pub(crate) outcome: TxOutcome,
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
        withdrawal_outputs: VectorRoot<Digest>,
        change: VectorRoot<Digest>,
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

/// Read view over the block's pending writes with fall-through to the parent
/// batch, so a transaction observes records written earlier in its own block.
struct View<'a, E>
where
    E: StorageContext + Spawner,
{
    writes: &'a Writes,
    batch: &'a Batch<E>,
}

impl<E> View<'_, E>
where
    E: StorageContext + Spawner,
{
    async fn get(&self, key: &StateKey) -> Result<Option<Record>, QmdbError<mmr::Family>> {
        if let Some(record) = self.writes.get(key) {
            return Ok(record.clone());
        }
        self.batch.get(key).await
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
        let mut leaves = config
            .accounts
            .iter()
            .map(|account| StateLeaf {
                account: account.key.clone(),
                state: AccountState {
                    balance: account.balance,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let state =
            StateCache::new::<Sha256>(leaves).expect("the genesis account state is well formed");
        let chain = SettlementChain::new(
            *config.digest(),
            config.operator.clone(),
            committee().expect("the demo committee is statically valid"),
            &state,
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
                    withdrawal_outputs: roots.withdrawal_outputs,
                    change: roots.change,
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
            SettlementTx::BeginHardFaultSettlement(_) => self.begin_hard_fault_settlement(config),
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
                .find(|opening| &opening.leaf.account == carried.account())
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
            request.terminal_proof.clone(),
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
                Some(Record::Admitted(AdmittedRootsResponse {
                    batch_id,
                    change: request.roots.change,
                    finalized: false,
                })),
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

    fn begin_hard_fault_settlement(&mut self, config: &Deployment) -> Step {
        let settlement = match self.chain.begin_hard_fault_settlement() {
            Ok(settlement) => settlement,
            Err(error) => return Step::rejected(chain_rejection(&error)),
        };
        Step::applied(vec![(
            fault_key(config.digest()),
            Some(Record::Fault(FaultRecord::Settling(settlement.into()))),
        )])
    }

    fn claim_hard_fault(&mut self, config: &Deployment, request: &ClaimHardFaultRequest) -> Step {
        let release = match self.chain.claim_hard_fault(&request.opening) {
            Ok(release) => release,
            Err(error) => return Step::rejected(chain_rejection(&error)),
        };
        Step::applied(vec![(
            hard_fault_key(config.digest(), &request.opening.leaf.account),
            Some(Record::HardFault(HardFaultReleaseRecord {
                opening: Sha256::hash(&[&request.opening.encode()]),
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
    const fn status(&self, config: &Deployment, height: u64, timestamp: u64) -> StatusRecord {
        StatusRecord {
            height,
            timestamp,
            deployment: *config.digest(),
            state_root: self.chain.current_state_root(),
            last_finalized: self.chain.expected_epoch().checked_sub(1),
            custody: self.chain.custody_balance(),
            claimable: self.chain.claimable_balance(),
            hard_faulted: self.chain.hard_fault().is_some(),
        }
    }
}

/// Resolves the deployment index one transaction routes to, or the final
/// outcome when no configured deployment matches.
///
/// Naming variants resolve by their explicit or signed deployment digest and
/// fail typed on an unconfigured one. Batch-keyed variants resolve by their
/// batch id, which is deployment-unique by construction: a claim's batch
/// routes by the deployment holding its claim roots record (absent
/// everywhere means not claimable anywhere yet, the retryable
/// [`TxOutcome::Unavailable`]), and a challenge's batch routes by the
/// deployment whose admitted pipeline holds it (absent everywhere mirrors
/// the chain's own `NoPendingBatch` rejection).
async fn route<E>(
    deployments: &[Deployment],
    machines: &[Machine],
    view: &View<'_, E>,
    tx: &SettlementTx,
) -> Result<Result<usize, TxOutcome>, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    let named = |digest: &Digest| {
        deployments
            .iter()
            .position(|deployment| deployment.digest() == digest)
            .ok_or(TxOutcome::Rejected(Reject::UnknownDeployment))
    };
    Ok(match tx {
        SettlementTx::Deposit(request) => named(&request.deployment),
        SettlementTx::QueueWithdrawal(request) => named(request.request.body().deployment()),
        SettlementTx::RegisterEpoch(request) => named(&request.deployment),
        SettlementTx::Admit(request) => named(&request.deployment),
        SettlementTx::BeginHardFaultSettlement(request) => named(&request.deployment),
        SettlementTx::ClaimHardFault(request) => named(&request.deployment),
        SettlementTx::ClaimPendingDeposit(request) => named(&request.deployment),
        SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest { batch_id, .. })
        | SettlementTx::ClaimExternalPayout(ExternalPayoutClaimRequest { batch_id, .. }) => {
            let mut routed = Err(TxOutcome::Unavailable);
            for (index, deployment) in deployments.iter().enumerate() {
                if view
                    .get(&claim_roots_key(deployment.digest(), batch_id))
                    .await?
                    .is_some()
                {
                    routed = Ok(index);
                    break;
                }
            }
            routed
        }
        SettlementTx::Challenge(request) => machines
            .iter()
            .position(|machine| {
                machine
                    .chain
                    .pending_batches()
                    .any(|batch| batch.header.batch_id::<Sha256>() == request.batch_id)
            })
            .ok_or(TxOutcome::Rejected(Reject::Chain)),
    })
}

/// Executes one block against a forked batch: decode every configured
/// deployment's machine record (or start it from genesis), observe each
/// machine's deadlines exactly once for `height`, route and apply every
/// transaction to its deployment's machine, then write the derived records,
/// each status singleton, and each re-encoded machine, and merkleize.
///
/// `timestamp` is the block's certified timestamp, `timing` is the
/// chain-wide genesis epoch timing policy applied to every deployment, and
/// `deployments` is the configured deployment set from the shared genesis:
/// all are identical on every validator, so determinism holds. Every other
/// result-affecting value lives in the batch (the machine records are part
/// of the forked state), so given the same parent state and inputs, every
/// call produces the same writes and therefore the same roots.
pub(crate) async fn execute<E>(
    batch: Batch<E>,
    height: Height,
    timestamp: u64,
    timing: &Timing,
    deployments: &[Deployment],
    transactions: &[SettlementTx],
) -> Result<Sealed<E>, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    assert!(
        !deployments.is_empty(),
        "the chain configures at least one deployment"
    );

    // Load each deployment's machine from the parent state, or start it at
    // genesis.
    let mut machines = Vec::with_capacity(deployments.len());
    for config in deployments {
        let machine = match batch.get(&machine_key(config.digest())).await? {
            None => Machine::genesis(config, timing),

            // The machine record is written only by execution and otherwise
            // arrives only through state sync verified against a certified
            // root, so it always decodes.
            Some(Record::Machine(encoded)) => {
                Machine::decode_cfg(encoded, &()).expect("the persisted machine decodes")
            }
            Some(_) => unreachable!("the machine key holds a machine record"),
        };
        machines.push(machine);
    }

    // Observe each machine's deadlines exactly once for this block, deriving
    // records from every observation that changed machine state.
    let mut writes = Writes::new();
    for (config, machine) in deployments.iter().zip(machines.iter_mut()) {
        let deployment = config.digest();
        for fired in machine.advance(height.get(), timestamp) {
            let view = View {
                writes: &writes,
                batch: &batch,
            };
            let emitted = match &fired {
                Fired::Finalized {
                    epoch,
                    batch_id,
                    withdrawal_outputs,
                    change,
                } => {
                    let mut emitted = vec![
                        (
                            claim_roots_key(deployment, batch_id),
                            Some(Record::ClaimRoots(ClaimRootsResponse {
                                withdrawal_outputs: *withdrawal_outputs,
                                change: *change,
                            })),
                        ),
                        (
                            admitted_key(deployment, *epoch),
                            Some(Record::Admitted(AdmittedRootsResponse {
                                batch_id: *batch_id,
                                change: *change,
                                finalized: true,
                            })),
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

    // Route each transaction to its deployment's machine and apply it there
    // alone, to a typed outcome. Only applied transactions write records: a
    // rejection is effect-free, and a replay re-executes into its variant's
    // domain guard.
    for tx in transactions {
        let view = View {
            writes: &writes,
            batch: &batch,
        };
        let step = match route(deployments, &machines, &view, tx).await? {
            Ok(index) => {
                machines[index]
                    .apply(&deployments[index], height.get(), timing, tx, &view)
                    .await?
            }
            Err(outcome) => Step::outcome(outcome),
        };
        if step.outcome != TxOutcome::Applied {
            debug!(outcome = ?step.outcome, digest = ?tx.digest(), "transaction left no effect");
        }
        for (key, value) in step.writes {
            writes.insert(key, value);
        }
    }
    for (config, machine) in deployments.iter().zip(machines.iter()) {
        writes.insert(
            status_key(config.digest()),
            Some(Record::Status(machine.status(
                config,
                height.get(),
                timestamp,
            ))),
        );
        writes.insert(
            machine_key(config.digest()),
            Some(Record::Machine(machine.encode())),
        );
    }

    let mut batch = batch;
    for (key, value) in writes {
        batch = batch.write(key, value);
    }
    batch.merkleize().await
}

/// Advisory dry-run of one submitted transaction: the stateless checks plus
/// a read-only feasibility peek at the domain records the transaction would
/// consume, against the latest applied state.
///
/// Unauthenticated UX advice for submitters, never authorization or
/// evidence. Rejections are effect-free, so this is the only typed
/// diagnosis a submitter gets: execution re-checks everything at inclusion,
/// the peek deliberately skips the expensive arms (certificate verification,
/// terminal proofs, challenge adjudication, machine-internal gates), and
/// any answer can go stale the moment state advances.
pub(crate) async fn advise<E>(
    db: &Database<E>,
    deployments: &[Deployment],
    tx: &SettlementTx,
) -> Result<Advice, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    let named = |digest: &Digest| {
        deployments
            .iter()
            .find(|deployment| deployment.digest() == digest)
    };
    let guard = db.read().await;
    Ok(match tx {
        SettlementTx::Deposit(request) => {
            let Some(config) = named(&request.deployment) else {
                return Ok(Advice::Doomed(Reject::UnknownDeployment));
            };
            let deployment = config.digest();
            let event = &request.event;
            if !config
                .accounts
                .iter()
                .any(|account| account.key == event.account)
            {
                Advice::Doomed(Reject::UnknownAccount)
            } else if let Some(Record::Deposit(recorded)) =
                guard.get(&deposit_key(deployment, &event.id)).await?
            {
                if &recorded == event {
                    Advice::Applied
                } else {
                    Advice::Doomed(Reject::DepositConflict)
                }
            } else if let Some(Record::Status(status)) = guard.get(&status_key(deployment)).await?
                && status
                    .custody
                    .checked_add(status.claimable)
                    .and_then(|held| held.checked_add(event.amount))
                    .is_none_or(|holdings| holdings > SQLITE_U64_MAX)
            {
                Advice::Doomed(Reject::Domain)
            } else {
                Advice::Plausible
            }
        }
        SettlementTx::QueueWithdrawal(request) => {
            let Some(config) = named(request.request.body().deployment()) else {
                return Ok(Advice::Doomed(Reject::UnknownDeployment));
            };
            if request.request.verify_signature().is_err() {
                Advice::Doomed(Reject::Signature)
            } else if let Some(Record::Withdrawal(recorded)) = guard
                .get(&withdrawal_key(config.digest(), request.request.account()))
                .await?
                && recorded == request.request
            {
                Advice::Applied
            } else {
                Advice::Plausible
            }
        }
        SettlementTx::RegisterEpoch(request) => {
            let Some(config) = named(&request.deployment) else {
                return Ok(Advice::Doomed(Reject::UnknownDeployment));
            };
            if !verify_chain_registration_signature(
                config,
                request.epoch,
                request.predecessor_liability,
                &request.deposits_root,
                &request.staged_root,
                &request.withdrawals,
                &request.signature,
            ) {
                Advice::Doomed(Reject::Signature)
            } else if let Some(Record::Registration(record)) =
                guard.get(&registration_key(config.digest())).await?
                && record.epoch == request.epoch
            {
                let same = record.predecessor_liability == request.predecessor_liability
                    && record.deposits_root == request.deposits_root
                    && record.staged_root == request.staged_root
                    && request
                        .withdrawals
                        .root::<Sha256>()
                        .is_ok_and(|root| root == record.withdrawals_root);
                if same {
                    Advice::Applied
                } else {
                    Advice::Doomed(Reject::RegistrationConflict)
                }
            } else {
                Advice::Plausible
            }
        }
        SettlementTx::Admit(request) => {
            let Some(config) = named(&request.deployment) else {
                return Ok(Advice::Doomed(Reject::UnknownDeployment));
            };
            let deployment = config.digest();
            let batch_id = request.header.batch_id::<Sha256>();
            if let Some(Record::Admitted(admitted)) =
                guard.get(&admitted_key(deployment, request.epoch)).await?
            {
                if admitted.batch_id == batch_id {
                    Advice::Applied
                } else {
                    Advice::Doomed(Reject::AdmissionConflict)
                }
            } else {
                match guard.get(&registration_key(deployment)).await? {
                    None => Advice::Doomed(Reject::NotRegistered),
                    Some(Record::Registration(record)) if record.epoch != request.epoch => {
                        Advice::Doomed(Reject::SubmissionMismatch)
                    }
                    _ => Advice::Plausible,
                }
            }
        }
        SettlementTx::ClaimWithdrawal(request) => {
            let mut advice = Advice::Plausible;
            for config in deployments {
                let key = withdrawal_release_key(
                    config.digest(),
                    &request.batch_id,
                    request.claim.position(),
                );
                if let Some(Record::WithdrawalRelease(release)) = guard.get(&key).await? {
                    advice = if release.claim == Sha256::hash(&[&request.claim.encode()]) {
                        Advice::Applied
                    } else {
                        Advice::Doomed(Reject::PositionConflict)
                    };
                    break;
                }
            }
            advice
        }
        SettlementTx::ClaimExternalPayout(request) => {
            let mut advice = Advice::Plausible;
            for config in deployments {
                let key = payout_release_key(
                    config.digest(),
                    &request.batch_id,
                    request.claim.position(),
                );
                if let Some(Record::PayoutRelease(release)) = guard.get(&key).await? {
                    advice = if release.claim == Sha256::hash(&[&request.claim.encode()]) {
                        Advice::Applied
                    } else {
                        Advice::Doomed(Reject::PositionConflict)
                    };
                    break;
                }
            }
            advice
        }
        SettlementTx::Challenge(request) => {
            let mut advice = Advice::Plausible;
            for config in deployments {
                if let Some(Record::Fault(FaultRecord::Faulted(
                    HardFaultReasonResponse::ProvenChallenge { batch_id, .. },
                ))) = guard.get(&fault_key(config.digest())).await?
                    && batch_id == request.batch_id
                {
                    advice = Advice::Applied;
                    break;
                }
            }
            advice
        }
        SettlementTx::BeginHardFaultSettlement(request) => {
            let Some(config) = named(&request.deployment) else {
                return Ok(Advice::Doomed(Reject::UnknownDeployment));
            };
            match guard.get(&fault_key(config.digest())).await? {
                None => Advice::Doomed(Reject::FaultUnavailable),
                Some(Record::Fault(FaultRecord::Settling(_))) => Advice::Applied,
                _ => Advice::Plausible,
            }
        }
        SettlementTx::ClaimHardFault(request) => {
            let Some(config) = named(&request.deployment) else {
                return Ok(Advice::Doomed(Reject::UnknownDeployment));
            };
            let deployment = config.digest();
            if let Some(Record::HardFault(release)) = guard
                .get(&hard_fault_key(deployment, &request.opening.leaf.account))
                .await?
            {
                if release.opening == Sha256::hash(&[&request.opening.encode()]) {
                    Advice::Applied
                } else {
                    Advice::Doomed(Reject::PositionConflict)
                }
            } else {
                match guard.get(&fault_key(deployment)).await? {
                    Some(Record::Fault(FaultRecord::Settling(_))) => Advice::Plausible,
                    _ => Advice::Doomed(Reject::FaultUnavailable),
                }
            }
        }
        SettlementTx::ClaimPendingDeposit(request) => {
            let Some(config) = named(&request.deployment) else {
                return Ok(Advice::Doomed(Reject::UnknownDeployment));
            };
            let deployment = config.digest();
            if let Some(Record::Refund(_)) =
                guard.get(&refund_key(deployment, &request.account)).await?
            {
                Advice::Applied
            } else if guard.get(&fault_key(deployment)).await?.is_none() {
                Advice::Doomed(Reject::FaultUnavailable)
            } else {
                Advice::Plausible
            }
        }
    })
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use crate::protocol::identities;
    use bytes::BytesMut;
    use commonware_codec::DecodeExt as _;

    #[test]
    fn advice_codecs_round_trip_and_reject_unknown_tags() {
        for advice in [
            Advice::Applied,
            Advice::Plausible,
            Advice::Doomed(Reject::DepositConflict),
            Advice::Doomed(Reject::Chain),
            Advice::Doomed(Reject::UnknownDeployment),
        ] {
            assert_eq!(Advice::decode(advice.encode()).unwrap(), advice);
        }
        assert!(Advice::decode(Bytes::from_static(&[3])).is_err());
        assert!(Advice::decode(Bytes::from_static(&[2, 23])).is_err());
    }

    #[test]
    fn anchored_record_codecs_round_trip() {
        let batch_id = BatchId::new(Sha256::hash(&[b"anchored-record-batch"]));
        let change = VectorRoot {
            digest: Sha256::hash(&[b"anchored-record-change"]),
        };
        for admitted in [
            AdmittedRootsResponse {
                batch_id,
                change,
                finalized: false,
            },
            AdmittedRootsResponse {
                batch_id,
                change,
                finalized: true,
            },
        ] {
            assert_eq!(
                AdmittedRootsResponse::decode(admitted.encode()).unwrap(),
                admitted
            );
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
                kind: ChallengeKind::HigherShardTip,
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
