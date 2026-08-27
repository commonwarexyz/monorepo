//! Bounded settlement-chain RPC bodies and dispatch.

use crate::{
    protocol::{DepositEvent, Key, verify_registration_signature},
    rpc,
    settlement::{AdmissionOutcome, Settlement, SettlementStatus, SettlementSubmission},
};
use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, BufMut, Bytes};
use commonware_clearing::bajillion::{
    admission::bls12381::Certificate,
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalBatch},
    challenge::{ChallengeKind, StateOpening, Verdict},
    commitment::VectorRoot,
    settlement::{
        DepositRefund, FinalizedBatch, HardFaultReason, HardFaultRelease, HardFaultSettlement,
    },
    transition::{
        BatchId, ExternalPayout, ExternalPayoutClaim, Header, RootBundle, TerminalProof,
        WithdrawalClaim, WithdrawalOutput,
    },
};
use commonware_codec::{
    Decode as _, DecodeExt as _, Encode, EncodeSize, Error as CodecError, RangeCfg, Read,
    ReadExt as _, Write,
};
use commonware_cryptography::sha256::Digest;
use commonware_cryptography_curve25519::signing::Signature;
use commonware_runtime::{Network, Runner as _, tokio};
use std::{net::SocketAddr, time::Duration};

pub(crate) const METHOD_STATUS: u8 = 0;
pub(crate) const METHOD_DEPOSIT: u8 = 1;
pub(crate) const METHOD_QUEUE_WITHDRAWAL: u8 = 2;
pub(crate) const METHOD_REGISTER_EPOCH: u8 = 3;
pub(crate) const METHOD_ADMIT: u8 = 4;
pub(crate) const METHOD_CLAIM_WITHDRAWAL: u8 = 5;
pub(crate) const METHOD_CLAIM_EXTERNAL_PAYOUT: u8 = 6;
pub(crate) const METHOD_CONFIRM_DEPOSIT: u8 = 7;
pub(crate) const METHOD_CONFIRM_WITHDRAWAL: u8 = 8;
pub(crate) const METHOD_CHALLENGE: u8 = 9;
pub(crate) const METHOD_BEGIN_HARD_FAULT_SETTLEMENT: u8 = 10;
pub(crate) const METHOD_CLAIM_HARD_FAULT: u8 = 11;
pub(crate) const METHOD_CLAIM_PENDING_DEPOSIT: u8 = 12;
pub(crate) const METHOD_CONFIRM_REGISTRATION: u8 = 13;

const MAX_BATCH_ITEMS: usize = 1_024;
const MAX_DESTINATION_BYTES: usize = 256;
const MAX_STATE_OPENINGS: usize = 5;
const CERTIFICATE_PARTICIPANTS: usize = 4;
const MAX_ERROR_BYTES: usize = 1_024;
const MAX_CHALLENGE_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdmitError {
    #[error("settlement admission is pending through its challenge window")]
    Pending,
    #[error("settlement admission outcome is unknown: {0}")]
    Unknown(anyhow::Error),
    #[error("settlement rejected admission: {0}")]
    Rejected(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatusRequest;

impl Write for StatusRequest {
    fn write(&self, _: &mut impl BufMut) {}
}

impl EncodeSize for StatusRequest {
    fn encode_size(&self) -> usize {
        0
    }
}

impl Read for StatusRequest {
    type Cfg = ();

    fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistrationQuery {
    pub(crate) epoch: u64,
    pub(crate) anchor: Digest,
    pub(crate) state_root: VectorRoot<Digest>,
}

impl Write for RegistrationQuery {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.anchor.write(buf);
        self.state_root.write(buf);
    }
}

impl EncodeSize for RegistrationQuery {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.anchor.encode_size() + self.state_root.encode_size()
    }
}

impl Read for RegistrationQuery {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            anchor: Digest::read(buf)?,
            state_root: VectorRoot::read(buf)?,
        })
    }
}

pub(crate) type DepositRequest = DepositEvent;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChallengeRequest {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) evidence: Bytes,
}

impl Write for ChallengeRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.evidence.write(buf);
    }
}

impl EncodeSize for ChallengeRequest {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size() + self.evidence.encode_size()
    }
}

impl Read for ChallengeRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            batch_id: BatchId::read(buf)?,
            evidence: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_CHALLENGE_BYTES))?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BeginHardFaultSettlementRequest;

impl Write for BeginHardFaultSettlementRequest {
    fn write(&self, _: &mut impl BufMut) {}
}

impl EncodeSize for BeginHardFaultSettlementRequest {
    fn encode_size(&self) -> usize {
        0
    }
}

impl Read for BeginHardFaultSettlementRequest {
    type Cfg = ();

    fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimHardFaultRequest {
    pub(crate) opening: StateOpening<Key, Digest>,
}

impl Write for ClaimHardFaultRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.opening.write(buf);
    }
}

impl EncodeSize for ClaimHardFaultRequest {
    fn encode_size(&self) -> usize {
        self.opening.encode_size()
    }
}

impl Read for ClaimHardFaultRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let opening = StateOpening::read(buf)?;
        if opening.proof.proof.leaf_count > MAX_BATCH_ITEMS as u32 {
            return Err(CodecError::Invalid(
                "clearing_terminal::ClaimHardFaultRequest",
                "state opening exceeds the terminal account bound",
            ));
        }
        Ok(Self { opening })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimPendingDepositRequest {
    pub(crate) account: Key,
}

impl Write for ClaimPendingDepositRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
    }
}

impl EncodeSize for ClaimPendingDepositRequest {
    fn encode_size(&self) -> usize {
        self.account.encode_size()
    }
}

impl Read for ClaimPendingDepositRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: Key::read(buf)?,
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
                &(RangeCfg::new(0..=MAX_STATE_OPENINGS), ()),
            )?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisterEpochRequest {
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) signature: Signature,
}

impl Write for RegisterEpochRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.predecessor_liability.write(buf);
        self.deposits.write(buf);
        self.withdrawals.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for RegisterEpochRequest {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.predecessor_liability.encode_size()
            + self.deposits.encode_size()
            + self.withdrawals.encode_size()
            + self.signature.encode_size()
    }
}

impl Read for RegisterEpochRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
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
            signature: Signature::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmitRequest {
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) terminal_proof: TerminalProof<Digest>,
    pub(crate) certificate: Certificate,
}

impl Write for AdmitRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.predecessor_liability.write(buf);
        self.deposits.write(buf);
        self.withdrawals.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.terminal_proof.write(buf);
        self.certificate.write(buf);
    }
}

impl EncodeSize for AdmitRequest {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.predecessor_liability.encode_size()
            + self.deposits.encode_size()
            + self.withdrawals.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.terminal_proof.encode_size()
            + self.certificate.encode_size()
    }
}

impl Read for AdmitRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let request = Self {
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
            terminal_proof: TerminalProof::read(buf)?,
            certificate: Certificate::read_cfg(buf, &CERTIFICATE_PARTICIPANTS)?,
        };
        if request.certificate.signers.len() != CERTIFICATE_PARTICIPANTS {
            return Err(CodecError::Invalid(
                "clearing_operator::AdmitRequest",
                "certificate participant bitmap must have length four",
            ));
        }
        Ok(request)
    }
}

impl From<AdmitRequest> for SettlementSubmission {
    fn from(request: AdmitRequest) -> Self {
        Self {
            epoch: request.epoch,
            predecessor_liability: request.predecessor_liability,
            deposits: request.deposits,
            withdrawals: request.withdrawals,
            header: request.header,
            roots: request.roots,
            terminal_proof: request.terminal_proof,
            certificate: request.certificate,
        }
    }
}

impl From<&SettlementSubmission> for AdmitRequest {
    fn from(submission: &SettlementSubmission) -> Self {
        Self {
            epoch: submission.epoch,
            predecessor_liability: submission.predecessor_liability,
            deposits: submission.deposits.clone(),
            withdrawals: submission.withdrawals.clone(),
            header: submission.header,
            roots: submission.roots,
            terminal_proof: submission.terminal_proof.clone(),
            certificate: submission.certificate.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalClaimRequest {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) claim: WithdrawalClaim<Digest>,
}

impl Write for WithdrawalClaimRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.claim.write(buf);
    }
}

impl EncodeSize for WithdrawalClaimRequest {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size() + self.claim.encode_size()
    }
}

impl Read for WithdrawalClaimRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            batch_id: BatchId::read(buf)?,
            claim: WithdrawalClaim::read_cfg(buf, &RangeCfg::new(0..=MAX_DESTINATION_BYTES))?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalPayoutClaimRequest {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) claim: ExternalPayoutClaim<Key, Digest>,
}

impl Write for ExternalPayoutClaimRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.claim.write(buf);
    }
}

impl EncodeSize for ExternalPayoutClaimRequest {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size() + self.claim.encode_size()
    }
}

impl Read for ExternalPayoutClaimRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            batch_id: BatchId::read(buf)?,
            claim: ExternalPayoutClaim::read(buf)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatusResponse {
    pub(crate) now: u64,
    pub(crate) deployment: Digest,
    pub(crate) state_root: VectorRoot<Digest>,
    pub(crate) custody_balance: u64,
    pub(crate) claimable_balance: u64,
    pub(crate) hard_faulted: bool,
}

impl From<SettlementStatus> for StatusResponse {
    fn from(status: SettlementStatus) -> Self {
        Self {
            now: status.now,
            deployment: status.deployment,
            state_root: status.state_root,
            custody_balance: status.custody_balance,
            claimable_balance: status.claimable_balance,
            hard_faulted: status.hard_faulted,
        }
    }
}

impl Write for StatusResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.now.write(buf);
        self.deployment.write(buf);
        self.state_root.write(buf);
        self.custody_balance.write(buf);
        self.claimable_balance.write(buf);
        self.hard_faulted.write(buf);
    }
}

impl EncodeSize for StatusResponse {
    fn encode_size(&self) -> usize {
        self.now.encode_size()
            + self.deployment.encode_size()
            + self.state_root.encode_size()
            + self.custody_balance.encode_size()
            + self.claimable_balance.encode_size()
            + self.hard_faulted.encode_size()
    }
}

impl Read for StatusResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            now: u64::read(buf)?,
            deployment: Digest::read(buf)?,
            state_root: VectorRoot::read(buf)?,
            custody_balance: u64::read(buf)?,
            claimable_balance: u64::read(buf)?,
            hard_faulted: bool::read(buf)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalizedBatchResponse {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) epoch: u64,
    pub(crate) successor_root: VectorRoot<Digest>,
    pub(crate) withdrawal_total: u64,
    pub(crate) payout_total: u64,
    pub(crate) custody_balance: u64,
}

impl From<FinalizedBatch<Digest>> for FinalizedBatchResponse {
    fn from(finalized: FinalizedBatch<Digest>) -> Self {
        Self {
            batch_id: finalized.batch_id,
            epoch: finalized.epoch,
            successor_root: finalized.successor_root,
            withdrawal_total: finalized.withdrawal_total,
            payout_total: finalized.payout_total,
            custody_balance: finalized.custody_balance,
        }
    }
}

impl Write for FinalizedBatchResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.epoch.write(buf);
        self.successor_root.write(buf);
        self.withdrawal_total.write(buf);
        self.payout_total.write(buf);
        self.custody_balance.write(buf);
    }
}

impl EncodeSize for FinalizedBatchResponse {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size()
            + self.epoch.encode_size()
            + self.successor_root.encode_size()
            + self.withdrawal_total.encode_size()
            + self.payout_total.encode_size()
            + self.custody_balance.encode_size()
    }
}

impl Read for FinalizedBatchResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            batch_id: BatchId::read(buf)?,
            epoch: u64::read(buf)?,
            successor_root: VectorRoot::read(buf)?,
            withdrawal_total: u64::read(buf)?,
            payout_total: u64::read(buf)?,
            custody_balance: u64::read(buf)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmitResponse {
    Pending,
    Finalized(FinalizedBatchResponse),
}

impl Write for AdmitResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Pending => 0_u8.write(buf),
            Self::Finalized(finalized) => {
                1_u8.write(buf);
                finalized.write(buf);
            }
        }
    }
}

impl EncodeSize for AdmitResponse {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Pending => 0,
            Self::Finalized(finalized) => finalized.encode_size(),
        }
    }
}

impl Read for AdmitResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Finalized(FinalizedBatchResponse::read(buf)?)),
            _ => Err(CodecError::Invalid(
                "clearing_terminal::AdmitResponse",
                "unknown admission response tag",
            )),
        }
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalPayoutResponse {
    pub(crate) recipient: Key,
    pub(crate) amount: u64,
}

impl From<ExternalPayout<Key>> for ExternalPayoutResponse {
    fn from(payout: ExternalPayout<Key>) -> Self {
        Self {
            recipient: payout.recipient,
            amount: payout.amount,
        }
    }
}

impl Write for ExternalPayoutResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.amount.write(buf);
    }
}

impl EncodeSize for ExternalPayoutResponse {
    fn encode_size(&self) -> usize {
        self.recipient.encode_size() + self.amount.encode_size()
    }
}

impl Read for ExternalPayoutResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            recipient: Key::read(buf)?,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChallengeVerdict {
    NoContradiction,
    Proven(ChallengeKind),
}

impl From<Verdict> for ChallengeVerdict {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::NoContradiction => Self::NoContradiction,
            Verdict::Proven(kind) => Self::Proven(kind),
        }
    }
}

impl Write for ChallengeVerdict {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::NoContradiction => 0_u8.write(buf),
            Self::Proven(kind) => (challenge_kind_tag(*kind) + 1).write(buf),
        }
    }
}

impl EncodeSize for ChallengeVerdict {
    fn encode_size(&self) -> usize {
        1
    }
}

impl Read for ChallengeVerdict {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::NoContradiction),
            tag @ 1..=4 => Ok(Self::Proven(challenge_kind_from_tag(tag - 1)?)),
            _ => Err(CodecError::Invalid(
                "clearing_terminal::ChallengeVerdict",
                "unknown challenge verdict tag",
            )),
        }
    }
}

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

fn dispatch(settlement: &mut Settlement, request: rpc::Request) -> anyhow::Result<Bytes> {
    match request.method {
        METHOD_STATUS => {
            StatusRequest::decode(request.body).context("decode status request")?;
            Ok(StatusResponse::from(settlement.status()?).encode())
        }
        METHOD_DEPOSIT => {
            let request = DepositRequest::decode(request.body).context("decode deposit request")?;
            settlement
                .deposit(request)
                .context("apply deposit request")?;
            Ok(Bytes::new())
        }
        METHOD_QUEUE_WITHDRAWAL => {
            let request = QueueWithdrawalRequest::decode(request.body)
                .context("decode queue-withdrawal request")?;
            settlement
                .queue_withdrawal(request.request, request.openings)
                .context("apply queue-withdrawal request")?;
            Ok(Bytes::new())
        }
        METHOD_REGISTER_EPOCH => {
            let request = RegisterEpochRequest::decode(request.body)
                .context("decode epoch-registration request")?;
            ensure!(
                verify_registration_signature(
                    request.epoch,
                    request.predecessor_liability,
                    &request.deposits,
                    &request.withdrawals,
                    &request.signature,
                ),
                "authenticate settlement boundary"
            );
            settlement
                .register_epoch(
                    request.epoch,
                    request.predecessor_liability,
                    request.deposits,
                    request.withdrawals,
                )
                .context("apply epoch-registration request")?;
            Ok(Bytes::new())
        }
        METHOD_ADMIT => {
            let request = AdmitRequest::decode(request.body).context("decode admit request")?;
            let outcome = settlement
                .admit_submission(request.into())
                .context("apply admit request")?;
            Ok(match outcome {
                AdmissionOutcome::Pending => AdmitResponse::Pending,
                AdmissionOutcome::Finalized(finalized) => {
                    AdmitResponse::Finalized(FinalizedBatchResponse::from(finalized))
                }
            }
            .encode())
        }
        METHOD_CLAIM_WITHDRAWAL => {
            let request = WithdrawalClaimRequest::decode(request.body)
                .context("decode withdrawal-claim request")?;
            let release = settlement
                .claim_withdrawal(request.batch_id, &request.claim)
                .context("apply withdrawal-claim request")?;
            Ok(WithdrawalResponse::from(release).encode())
        }
        METHOD_CLAIM_EXTERNAL_PAYOUT => {
            let request = ExternalPayoutClaimRequest::decode(request.body)
                .context("decode external-payout-claim request")?;
            let payout = settlement
                .claim_external_payout(request.batch_id, &request.claim)
                .context("apply external-payout-claim request")?;
            Ok(ExternalPayoutResponse::from(payout).encode())
        }
        METHOD_CONFIRM_DEPOSIT => {
            let request = DepositRequest::decode(request.body)
                .context("decode deposit-confirmation request")?;
            settlement
                .confirm_deposit(&request)
                .context("confirm settlement deposit")?;
            Ok(Bytes::new())
        }
        METHOD_CONFIRM_WITHDRAWAL => {
            let request = SignedWithdrawal::decode_cfg(
                request.body,
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )
            .context("decode withdrawal-confirmation request")?;
            settlement
                .confirm_withdrawal(&request)
                .context("confirm settlement withdrawal")?;
            Ok(Bytes::new())
        }
        METHOD_CONFIRM_REGISTRATION => {
            let request =
                RegistrationQuery::decode(request.body).context("decode registration query")?;
            settlement
                .confirm_registration(request.epoch, &request.anchor, &request.state_root)
                .context("confirm payment registration")?;
            Ok(Bytes::new())
        }
        METHOD_CHALLENGE => {
            let request =
                ChallengeRequest::decode(request.body).context("decode challenge request")?;
            let verdict = settlement
                .challenge_encoded(request.batch_id, request.evidence, MAX_CHALLENGE_BYTES)
                .context("apply challenge request")?;
            Ok(ChallengeVerdict::from(verdict).encode())
        }
        METHOD_BEGIN_HARD_FAULT_SETTLEMENT => {
            BeginHardFaultSettlementRequest::decode(request.body)
                .context("decode begin-hard-fault-settlement request")?;
            let settlement = settlement
                .begin_hard_fault_settlement()
                .context("apply begin-hard-fault-settlement request")?;
            Ok(BeginHardFaultSettlementResponse::from(settlement).encode())
        }
        METHOD_CLAIM_HARD_FAULT => {
            let request = ClaimHardFaultRequest::decode(request.body)
                .context("decode hard-fault-claim request")?;
            let release = settlement
                .claim_hard_fault(&request.opening)
                .context("apply hard-fault-claim request")?;
            Ok(ClaimHardFaultResponse::from(release).encode())
        }
        METHOD_CLAIM_PENDING_DEPOSIT => {
            let request = ClaimPendingDepositRequest::decode(request.body)
                .context("decode pending-deposit-claim request")?;
            let refund = settlement
                .claim_pending_deposit(&request.account)
                .context("apply pending-deposit-claim request")?;
            Ok(ClaimPendingDepositResponse::from(refund).encode())
        }
        method => bail!("unknown settlement RPC method {method}"),
    }
}

fn error_response(mut error: String) -> rpc::Response {
    if error.len() > MAX_ERROR_BYTES {
        let mut end = MAX_ERROR_BYTES;
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
    }
    rpc::Response::Error {
        error: Bytes::from(error),
    }
}

pub(crate) fn handle(settlement: &mut Settlement, request: rpc::Request) -> rpc::Response {
    match dispatch(settlement, request) {
        Ok(body) => rpc::Response::Success { body },
        Err(error) => error_response(format!("{error:#}")),
    }
}

async fn invoke<E: Network>(
    network: &E,
    address: SocketAddr,
    method: u8,
    body: Bytes,
) -> Result<Bytes> {
    let response = rpc::call(network, address, &rpc::Request { method, body })
        .await
        .context("call settlement")?;
    match response {
        rpc::Response::Success { body } => Ok(body),
        rpc::Response::Error { error } => {
            bail!(
                "settlement rejected request: {}",
                String::from_utf8_lossy(&error)
            )
        }
    }
}

async fn invoke_empty<E: Network>(
    network: &E,
    address: SocketAddr,
    method: u8,
    body: Bytes,
) -> Result<()> {
    let response = invoke(network, address, method, body).await?;
    ensure!(
        response.is_empty(),
        "settlement returned an unexpected body"
    );
    Ok(())
}

pub(crate) async fn status<E: Network>(network: &E, address: SocketAddr) -> Result<StatusResponse> {
    StatusResponse::decode(invoke(network, address, METHOD_STATUS, StatusRequest.encode()).await?)
        .context("decode settlement status")
}

pub(crate) async fn deposit<E: Network>(
    network: &E,
    address: SocketAddr,
    request: DepositRequest,
) -> Result<()> {
    invoke_empty(network, address, METHOD_DEPOSIT, request.encode()).await
}

pub(crate) async fn confirm_deposit<E: Network>(
    network: &E,
    address: SocketAddr,
    request: DepositRequest,
) -> Result<()> {
    invoke_empty(network, address, METHOD_CONFIRM_DEPOSIT, request.encode()).await
}

pub(crate) async fn confirm_withdrawal<E: Network>(
    network: &E,
    address: SocketAddr,
    request: &SignedWithdrawal<Key, Digest>,
) -> Result<()> {
    invoke_empty(
        network,
        address,
        METHOD_CONFIRM_WITHDRAWAL,
        request.encode(),
    )
    .await
}

pub(crate) async fn confirm_registration<E: Network>(
    network: &E,
    address: SocketAddr,
    request: RegistrationQuery,
) -> Result<()> {
    invoke_empty(
        network,
        address,
        METHOD_CONFIRM_REGISTRATION,
        request.encode(),
    )
    .await
}

pub(crate) async fn queue_withdrawal<E: Network>(
    network: &E,
    address: SocketAddr,
    request: QueueWithdrawalRequest,
) -> Result<()> {
    invoke_empty(network, address, METHOD_QUEUE_WITHDRAWAL, request.encode()).await
}

pub(crate) async fn register_epoch<E: Network>(
    network: &E,
    address: SocketAddr,
    request: RegisterEpochRequest,
) -> Result<()> {
    invoke_empty(network, address, METHOD_REGISTER_EPOCH, request.encode()).await
}

async fn admit_once<E: Network>(
    network: &E,
    address: SocketAddr,
    request: AdmitRequest,
) -> std::result::Result<FinalizedBatchResponse, AdmitError> {
    let response = rpc::call(
        network,
        address,
        &rpc::Request {
            method: METHOD_ADMIT,
            body: request.encode(),
        },
    )
    .await
    .context("call settlement admission")
    .map_err(AdmitError::Unknown)?;
    match response {
        rpc::Response::Success { body } => match AdmitResponse::decode(body)
            .context("decode admission response")
            .map_err(AdmitError::Unknown)?
        {
            AdmitResponse::Pending => Err(AdmitError::Pending),
            AdmitResponse::Finalized(finalized) => Ok(finalized),
        },
        rpc::Response::Error { error } => Err(AdmitError::Rejected(
            String::from_utf8_lossy(&error).into_owned(),
        )),
    }
}

pub(crate) async fn claim_withdrawal<E: Network>(
    network: &E,
    address: SocketAddr,
    request: WithdrawalClaimRequest,
) -> Result<WithdrawalResponse> {
    WithdrawalResponse::decode(
        invoke(network, address, METHOD_CLAIM_WITHDRAWAL, request.encode()).await?,
    )
    .context("decode withdrawal response")
}

pub(crate) async fn claim_external_payout<E: Network>(
    network: &E,
    address: SocketAddr,
    request: ExternalPayoutClaimRequest,
) -> Result<ExternalPayoutResponse> {
    ExternalPayoutResponse::decode(
        invoke(
            network,
            address,
            METHOD_CLAIM_EXTERNAL_PAYOUT,
            request.encode(),
        )
        .await?,
    )
    .context("decode external payout")
}

#[allow(dead_code, reason = "the recovery client is an integration surface")]
pub(crate) async fn challenge_encoded<E: Network>(
    network: &E,
    address: SocketAddr,
    request: ChallengeRequest,
) -> Result<ChallengeVerdict> {
    ChallengeVerdict::decode(invoke(network, address, METHOD_CHALLENGE, request.encode()).await?)
        .context("decode challenge verdict")
}

#[allow(dead_code, reason = "the recovery client is an integration surface")]
pub(crate) async fn begin_hard_fault_settlement<E: Network>(
    network: &E,
    address: SocketAddr,
) -> Result<BeginHardFaultSettlementResponse> {
    BeginHardFaultSettlementResponse::decode(
        invoke(
            network,
            address,
            METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
            BeginHardFaultSettlementRequest.encode(),
        )
        .await?,
    )
    .context("decode hard-fault settlement")
}

#[allow(dead_code, reason = "the recovery client is an integration surface")]
pub(crate) async fn claim_hard_fault<E: Network>(
    network: &E,
    address: SocketAddr,
    request: ClaimHardFaultRequest,
) -> Result<ClaimHardFaultResponse> {
    ClaimHardFaultResponse::decode(
        invoke(network, address, METHOD_CLAIM_HARD_FAULT, request.encode()).await?,
    )
    .context("decode hard-fault release")
}

#[allow(dead_code, reason = "the recovery client is an integration surface")]
pub(crate) async fn claim_pending_deposit<E: Network>(
    network: &E,
    address: SocketAddr,
    request: ClaimPendingDepositRequest,
) -> Result<ClaimPendingDepositResponse> {
    ClaimPendingDepositResponse::decode(
        invoke(
            network,
            address,
            METHOD_CLAIM_PENDING_DEPOSIT,
            request.encode(),
        )
        .await?,
    )
    .context("decode pending-deposit refund")
}

/// Submits a completed close from its CPU worker without coupling proof construction to an
/// asynchronous runtime. The fresh runtime owns only this bounded network exchange.
pub(crate) fn admit_blocking(
    address: SocketAddr,
    submission: &SettlementSubmission,
) -> std::result::Result<FinalizedBatchResponse, AdmitError> {
    let request = AdmitRequest::from(submission);
    let config = tokio::Config::new()
        .with_worker_threads(1)
        .with_connect_timeout(Duration::from_secs(5))
        .with_read_write_timeout(Duration::from_secs(5));
    tokio::Runner::new(config)
        .start(move |context| async move { admit_once(&context, address, request).await })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Protocol, identities, wallets};
    use bytes::BytesMut;
    use commonware_clearing::bajillion::{
        boundary::{DepositRecord, SignedWithdrawal, WithdrawalAction},
        state::{AccountState, StateLeaf},
        transition::StateCache,
    };
    use commonware_cryptography::{Hasher, Sha256};
    use std::num::NonZeroU64;

    fn request(method: u8, body: impl Into<Bytes>) -> rpc::Request {
        rpc::Request {
            method,
            body: body.into(),
        }
    }

    fn success_body(response: rpc::Response) -> Bytes {
        match response {
            rpc::Response::Success { body } => body,
            rpc::Response::Error { error } => {
                panic!("unexpected RPC error: {}", String::from_utf8_lossy(&error))
            }
        }
    }

    fn error_text(response: rpc::Response) -> String {
        match response {
            rpc::Response::Success { .. } => panic!("expected RPC error"),
            rpc::Response::Error { error } => String::from_utf8(error.to_vec()).unwrap(),
        }
    }

    fn signed_registration(
        epoch: u64,
        predecessor_liability: u64,
        deposits: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
    ) -> RegisterEpochRequest {
        let protocol = Protocol::new(std::num::NonZeroUsize::MIN).unwrap();
        let signature =
            protocol.sign_registration(epoch, predecessor_liability, &deposits, &withdrawals);
        RegisterEpochRequest {
            epoch,
            predecessor_liability,
            deposits,
            withdrawals,
            signature,
        }
    }

    #[test]
    fn admission_response_round_trips_finalization() {
        let digest = Sha256::hash(&[b"admission-response"]);
        let finalized = FinalizedBatchResponse {
            batch_id: BatchId::new(digest),
            epoch: 7,
            successor_root: VectorRoot { digest },
            withdrawal_total: 11,
            payout_total: 13,
            custody_balance: 17,
        };
        assert_eq!(
            FinalizedBatchResponse::decode(finalized.encode()).unwrap(),
            finalized
        );
        assert!(FinalizedBatchResponse::decode(Bytes::from_static(&[2])).is_err());
        for response in [AdmitResponse::Pending, AdmitResponse::Finalized(finalized)] {
            assert_eq!(AdmitResponse::decode(response.encode()).unwrap(), response);
        }
        assert!(AdmitResponse::decode(Bytes::from_static(&[2])).is_err());
    }

    #[test]
    fn challenge_request_enforces_its_nested_evidence_bound() {
        let batch_id = BatchId::new(Sha256::hash(&[b"bounded-challenge"]));
        let bounded = ChallengeRequest {
            batch_id,
            evidence: Bytes::from(vec![7; MAX_CHALLENGE_BYTES]),
        };
        assert!(bounded.encode_size() <= rpc::MAX_BODY_SIZE);
        assert_eq!(ChallengeRequest::decode(bounded.encode()).unwrap(), bounded);

        let mut oversized = BytesMut::new();
        batch_id.write(&mut oversized);
        (MAX_CHALLENGE_BYTES + 1).write(&mut oversized);
        let error = ChallengeRequest::decode(oversized.freeze()).unwrap_err();
        assert!(matches!(error, CodecError::InvalidLength(_)));

        let mut trailing = ChallengeRequest {
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

        let mut settlement = Settlement::new().unwrap();
        let error = error_text(handle(
            &mut settlement,
            request(
                METHOD_CHALLENGE,
                ChallengeRequest {
                    batch_id,
                    evidence: Bytes::from_static(&[u8::MAX]),
                }
                .encode(),
            ),
        ));
        assert!(error.contains("decode challenge") || error.contains("invalid challenge"));
    }

    #[test]
    fn recovery_response_codecs_preserve_fault_metadata_and_optional_withdrawal() {
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
        for verdict in [
            ChallengeVerdict::NoContradiction,
            ChallengeVerdict::Proven(ChallengeKind::LatestAcknowledgedSend),
            ChallengeVerdict::Proven(ChallengeKind::HigherShardTip),
            ChallengeVerdict::Proven(ChallengeKind::InconsistentReceiptRange),
            ChallengeVerdict::Proven(ChallengeKind::ReceiptFork),
        ] {
            assert_eq!(ChallengeVerdict::decode(verdict.encode()).unwrap(), verdict);
        }
        assert!(ChallengeVerdict::decode(Bytes::from_static(&[5])).is_err());

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

    #[test]
    fn unknown_method_is_rejected() {
        let mut settlement = Settlement::new().unwrap();
        let error = error_text(handle(&mut settlement, request(u8::MAX, Bytes::new())));
        assert!(error.contains("unknown settlement RPC method 255"));
    }

    #[test]
    fn malformed_trailing_and_oversized_bodies_are_rejected() {
        let mut settlement = Settlement::new().unwrap();
        assert!(
            !error_text(handle(
                &mut settlement,
                request(METHOD_DEPOSIT, Bytes::from_static(&[0])),
            ))
            .is_empty()
        );

        let error = error_text(handle(
            &mut settlement,
            request(METHOD_STATUS, Bytes::from_static(&[0])),
        ));
        assert!(error.contains("Extra Data"));

        let deposit = DepositRequest {
            id: Sha256::hash(&[b"trailing-deposit"]),
            account: identities()[0].key.clone(),
            amount: 7,
        };
        let mut trailing = deposit.encode().to_vec();
        trailing.push(0xff);
        let error = error_text(handle(&mut settlement, request(METHOD_DEPOSIT, trailing)));
        assert!(error.contains("Extra Data"));

        let wallet = wallets().remove(0);
        let status = settlement.status().unwrap();
        let oversized_destination = SignedWithdrawal::sign(
            status.deployment,
            status.state_root.digest,
            Bytes::from(vec![0; MAX_DESTINATION_BYTES + 1]),
            WithdrawalAction::Amount(NonZeroU64::MIN),
            100,
            wallet.signer(),
        );
        let oversized_destination = QueueWithdrawalRequest {
            request: oversized_destination,
            openings: Vec::new(),
        };
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_QUEUE_WITHDRAWAL, oversized_destination.encode()),
        ));
        assert!(error.contains("Invalid Length"));

        let bounded_destination = SignedWithdrawal::sign(
            status.deployment,
            status.state_root.digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Amount(NonZeroU64::MIN),
            100,
            wallet.signer(),
        );
        let mut oversized_openings = bounded_destination.encode_mut();
        (MAX_STATE_OPENINGS + 1).write(&mut oversized_openings);
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_QUEUE_WITHDRAWAL, oversized_openings.freeze()),
        ));
        assert!(error.contains("Invalid Length"));

        let mut oversized_batch = BytesMut::new();
        0_u64.write(&mut oversized_batch);
        400_u64.write(&mut oversized_batch);
        (MAX_BATCH_ITEMS + 1).write(&mut oversized_batch);
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_REGISTER_EPOCH, oversized_batch.freeze()),
        ));
        assert!(error.contains("Invalid Length"));

        let status_body = success_body(handle(
            &mut settlement,
            request(METHOD_STATUS, Bytes::new()),
        ));
        let status = StatusResponse::decode(status_body).unwrap();
        assert_eq!(status.custody_balance, 400);
    }

    #[test]
    fn deposit_dispatch_is_idempotent() {
        let mut settlement = Settlement::new().unwrap();
        let deposit = DepositRequest {
            id: Sha256::hash(&[b"idempotent-deposit"]),
            account: identities()[0].key.clone(),
            amount: 7,
        };
        for _ in 0..2 {
            assert!(
                success_body(handle(
                    &mut settlement,
                    request(METHOD_DEPOSIT, deposit.encode()),
                ))
                .is_empty()
            );
        }

        let conflict = DepositRequest {
            amount: 8,
            ..deposit
        };
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_DEPOSIT, conflict.encode()),
        ));
        assert!(error.contains("deposit id was reused"));

        let status_body = success_body(handle(
            &mut settlement,
            request(METHOD_STATUS, Bytes::new()),
        ));
        let status = StatusResponse::decode(status_body).unwrap();
        assert_eq!(status.custody_balance, 407);
        assert_eq!(status.claimable_balance, 0);
    }

    #[test]
    fn hard_fault_rpc_retries_survive_full_settlement_and_reject_conflicts() {
        let mut settlement = Settlement::new().unwrap();
        let mut leaves = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: crate::protocol::INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let state = StateCache::new::<Sha256>(leaves).unwrap();
        let account = state.leaves()[0].account.clone();
        let deposit = DepositRequest {
            id: Sha256::hash(&[b"rpc-hard-fault-deposit"]),
            account: account.clone(),
            amount: 1,
        };
        success_body(handle(
            &mut settlement,
            request(METHOD_DEPOSIT, deposit.encode()),
        ));
        let deposits =
            DepositBatch::new(vec![DepositRecord::new(account.clone(), 1).unwrap()]).unwrap();
        let registration = signed_registration(0, 400, deposits.clone(), WithdrawalBatch::empty());
        success_body(handle(
            &mut settlement,
            request(METHOD_REGISTER_EPOCH, registration.encode()),
        ));
        let deadline = crate::protocol::epoch_context(0, &deposits, &WithdrawalBatch::empty(), 400)
            .unwrap()
            .admission_deadline();
        settlement.advance_logical_time(deadline + 1).unwrap();

        let begin_request = BeginHardFaultSettlementRequest.encode();
        let begin = BeginHardFaultSettlementResponse::decode(success_body(handle(
            &mut settlement,
            request(METHOD_BEGIN_HARD_FAULT_SETTLEMENT, begin_request.clone()),
        )))
        .unwrap();
        assert!(matches!(
            begin.reason,
            HardFaultReasonResponse::ExpiredRegistration {
                epoch: 0,
                expired_at,
                ..
            } if expired_at == deadline
        ));
        assert_eq!(begin.state_liability, 400);
        assert_eq!(begin.unfinalized_deposit_total, 1);
        assert_eq!(
            BeginHardFaultSettlementResponse::decode(success_body(handle(
                &mut settlement,
                request(METHOD_BEGIN_HARD_FAULT_SETTLEMENT, begin_request.clone()),
            )))
            .unwrap(),
            begin
        );

        let openings = state
            .leaves()
            .iter()
            .map(|leaf| state.opening(&leaf.account).unwrap())
            .collect::<Vec<_>>();
        let first_request = ClaimHardFaultRequest {
            opening: openings[0].clone(),
        };
        let first = ClaimHardFaultResponse::decode(success_body(handle(
            &mut settlement,
            request(METHOD_CLAIM_HARD_FAULT, first_request.encode()),
        )))
        .unwrap();
        assert_eq!(first.account, openings[0].leaf.account);
        assert_eq!(first.released_custody, crate::protocol::INITIAL_BALANCE);
        assert_eq!(
            ClaimHardFaultResponse::decode(success_body(handle(
                &mut settlement,
                request(METHOD_CLAIM_HARD_FAULT, first_request.encode()),
            )))
            .unwrap(),
            first
        );

        let mut conflicting = openings[0].clone();
        conflicting.leaf.state.balance -= 1;
        let error = error_text(handle(
            &mut settlement,
            request(
                METHOD_CLAIM_HARD_FAULT,
                ClaimHardFaultRequest {
                    opening: conflicting,
                }
                .encode(),
            ),
        ));
        assert!(error.contains("position was reused"));
        for opening in &openings[1..] {
            success_body(handle(
                &mut settlement,
                request(
                    METHOD_CLAIM_HARD_FAULT,
                    ClaimHardFaultRequest {
                        opening: opening.clone(),
                    }
                    .encode(),
                ),
            ));
        }

        let refund_request = ClaimPendingDepositRequest {
            account: account.clone(),
        };
        let refund = ClaimPendingDepositResponse::decode(success_body(handle(
            &mut settlement,
            request(METHOD_CLAIM_PENDING_DEPOSIT, refund_request.encode()),
        )))
        .unwrap();
        assert_eq!(refund.account, account);
        assert_eq!(refund.amount, 1);
        assert_eq!(settlement.status().unwrap().custody_balance, 0);

        assert_eq!(
            BeginHardFaultSettlementResponse::decode(success_body(handle(
                &mut settlement,
                request(METHOD_BEGIN_HARD_FAULT_SETTLEMENT, begin_request),
            )))
            .unwrap(),
            begin
        );
        assert_eq!(
            ClaimHardFaultResponse::decode(success_body(handle(
                &mut settlement,
                request(METHOD_CLAIM_HARD_FAULT, first_request.encode()),
            )))
            .unwrap(),
            first
        );
        assert_eq!(
            ClaimPendingDepositResponse::decode(success_body(handle(
                &mut settlement,
                request(METHOD_CLAIM_PENDING_DEPOSIT, refund_request.encode()),
            )))
            .unwrap(),
            refund
        );
    }

    #[test]
    fn epoch_registration_rpc_rejects_a_gap_without_consuming_the_slot() {
        let mut settlement = Settlement::new().unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let skipped = signed_registration(1, 400, deposits.clone(), withdrawals.clone());

        let error = error_text(handle(
            &mut settlement,
            request(METHOD_REGISTER_EPOCH, skipped.encode()),
        ));
        assert!(error.contains("settlement boundary epoch is not consecutive"));

        let first = signed_registration(0, 400, deposits, withdrawals);
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_REGISTER_EPOCH, first.encode()),
            ))
            .is_empty()
        );
    }

    #[test]
    fn registration_query_rpc_is_exact_and_retryable() {
        let mut settlement = Settlement::new().unwrap();
        let predecessor_state_root = settlement.status().unwrap().state_root;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = crate::protocol::epoch_context(0, &deposits, &withdrawals, 400).unwrap();
        let confirmation = RegistrationQuery {
            epoch: context.payment().epoch(),
            anchor: *context.payment().anchor(),
            state_root: predecessor_state_root,
        };
        assert_eq!(
            RegistrationQuery::decode(confirmation.encode()).unwrap(),
            confirmation
        );

        let error = error_text(handle(
            &mut settlement,
            request(METHOD_CONFIRM_REGISTRATION, confirmation.encode()),
        ));
        assert!(error.contains("payment registration is no longer live"));

        let registration = signed_registration(0, 400, deposits, withdrawals);
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_REGISTER_EPOCH, registration.encode()),
            ))
            .is_empty()
        );
        for _ in 0..2 {
            assert!(
                success_body(handle(
                    &mut settlement,
                    request(METHOD_CONFIRM_REGISTRATION, confirmation.encode()),
                ))
                .is_empty()
            );
        }

        let conflicting = RegistrationQuery {
            state_root: VectorRoot {
                digest: Sha256::hash(&[b"conflicting-confirmation-root"]),
            },
            ..confirmation
        };
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_CONFIRM_REGISTRATION, conflicting.encode()),
        ));
        assert!(error.contains("payment registration does not match"));

        let mut trailing = confirmation.encode().to_vec();
        trailing.push(0);
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_CONFIRM_REGISTRATION, trailing),
        ));
        assert!(error.contains("Extra Data"));
    }

    #[test]
    fn accepted_deposit_retry_survives_epoch_registration() {
        let mut settlement = Settlement::new().unwrap();
        let deposit = DepositRequest {
            id: Sha256::hash(&[b"registered-idempotent-deposit"]),
            account: identities()[0].key.clone(),
            amount: 7,
        };
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_DEPOSIT, deposit.encode()),
            ))
            .is_empty()
        );
        let registration = signed_registration(
            0,
            400,
            DepositBatch::new(vec![
                DepositRecord::new(deposit.account.clone(), deposit.amount).unwrap(),
            ])
            .unwrap(),
            WithdrawalBatch::empty(),
        );
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_REGISTER_EPOCH, registration.encode()),
            ))
            .is_empty()
        );

        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_DEPOSIT, deposit.encode()),
            ))
            .is_empty()
        );
    }

    #[test]
    fn accepted_withdrawal_retry_survives_epoch_registration() {
        let mut settlement = Settlement::new().unwrap();
        let operator = crate::operator::Operator::open(
            std::path::Path::new(":memory:"),
            std::num::NonZeroUsize::MIN,
        )
        .unwrap();
        let wallet = wallets().remove(0);
        let opening = operator.withdrawal_opening(&wallet.public_key()).unwrap();
        let status = settlement.status().unwrap();
        let withdrawal = SignedWithdrawal::sign(
            status.deployment,
            status.state_root.digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            100,
            wallet.signer(),
        );
        let queued = QueueWithdrawalRequest {
            request: withdrawal.clone(),
            openings: vec![opening.opening],
        };
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_QUEUE_WITHDRAWAL, queued.encode()),
            ))
            .is_empty()
        );
        let registration = signed_registration(
            0,
            400,
            DepositBatch::empty(),
            WithdrawalBatch::new(vec![withdrawal]).unwrap(),
        );
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_REGISTER_EPOCH, registration.encode()),
            ))
            .is_empty()
        );

        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_QUEUE_WITHDRAWAL, queued.encode()),
            ))
            .is_empty()
        );
    }

    #[test]
    fn epoch_registration_is_idempotent_and_fences_deposits() {
        let mut settlement = Settlement::new().unwrap();
        let registration =
            signed_registration(0, 400, DepositBatch::empty(), WithdrawalBatch::empty());
        for _ in 0..2 {
            assert!(
                success_body(handle(
                    &mut settlement,
                    request(METHOD_REGISTER_EPOCH, registration.encode()),
                ))
                .is_empty()
            );
        }

        let late = DepositRequest {
            id: Sha256::hash(&[b"late-rpc-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_DEPOSIT, late.encode()),
        ));
        assert!(error.contains("epoch is already registered"));
    }

    #[test]
    fn epoch_registration_rejects_an_unauthenticated_boundary() {
        let mut settlement = Settlement::new().unwrap();
        let mut registration =
            signed_registration(1, 400, DepositBatch::empty(), WithdrawalBatch::empty());
        registration.epoch = 0;

        let error = error_text(handle(
            &mut settlement,
            request(METHOD_REGISTER_EPOCH, registration.encode()),
        ));
        assert!(error.contains("authenticate settlement boundary"));

        let mut registration =
            signed_registration(0, 400, DepositBatch::empty(), WithdrawalBatch::empty());
        registration.predecessor_liability = 399;
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_REGISTER_EPOCH, registration.encode()),
        ));
        assert!(error.contains("authenticate settlement boundary"));
    }

    #[test]
    fn errors_are_utf8_and_truncated_on_a_character_boundary() {
        let response = error_response("é".repeat(MAX_ERROR_BYTES));
        let rpc::Response::Error { error } = response else {
            unreachable!();
        };
        assert_eq!(error.len(), MAX_ERROR_BYTES);
        assert!(core::str::from_utf8(&error).is_ok());
    }
}
