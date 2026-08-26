//! Bounded settlement-chain RPC bodies and dispatch.

use crate::{
    protocol::{DepositEvent, Key, verify_freeze_signature},
    rpc,
    settlement::{Settlement, SettlementStatus, SettlementSubmission},
};
use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, BufMut, Bytes};
use commonware_clearing::bajillion::{
    admission::bls12381::Certificate,
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalBatch},
    challenge::StateOpening,
    commitment::VectorRoot,
    settlement::{FinalizedBatch, WithdrawalRelease},
    transition::{
        BatchId, ExternalPayout, ExternalPayoutClaim, Header, RootBundle, TerminalProof,
        WithdrawalClaim,
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
pub(crate) const METHOD_FREEZE: u8 = 3;
pub(crate) const METHOD_ADMIT: u8 = 4;
pub(crate) const METHOD_CLAIM_WITHDRAWAL: u8 = 5;
pub(crate) const METHOD_CLAIM_EXTERNAL_PAYOUT: u8 = 6;
pub(crate) const METHOD_CONFIRM_DEPOSIT: u8 = 7;
pub(crate) const METHOD_CONFIRM_WITHDRAWAL: u8 = 8;

const MAX_BATCH_ITEMS: usize = 1_024;
const MAX_DESTINATION_BYTES: usize = 256;
const MAX_STATE_OPENINGS: usize = 5;
const CERTIFICATE_PARTICIPANTS: usize = 4;
const MAX_ERROR_BYTES: usize = 1_024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdmitError {
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

pub(crate) type DepositRequest = DepositEvent;

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
pub(crate) struct FreezeRequest {
    pub(crate) epoch: u64,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) signature: Signature,
}

impl Write for FreezeRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.deposits.write(buf);
        self.withdrawals.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for FreezeRequest {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.deposits.encode_size()
            + self.withdrawals.encode_size()
            + self.signature.encode_size()
    }
}

impl Read for FreezeRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
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
    pub(crate) opening_liability: u64,
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
        self.opening_liability.write(buf);
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
            + self.opening_liability.encode_size()
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
            opening_liability: u64::read(buf)?,
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
            opening_liability: request.opening_liability,
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
            opening_liability: submission.opening_liability,
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
    pub(crate) claim: WithdrawalClaim<Key, Digest>,
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
}

impl From<SettlementStatus> for StatusResponse {
    fn from(status: SettlementStatus) -> Self {
        Self {
            now: status.now,
            deployment: status.deployment,
            state_root: status.state_root,
            custody_balance: status.custody_balance,
            claimable_balance: status.claimable_balance,
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
    }
}

impl EncodeSize for StatusResponse {
    fn encode_size(&self) -> usize {
        self.now.encode_size()
            + self.deployment.encode_size()
            + self.state_root.encode_size()
            + self.custody_balance.encode_size()
            + self.claimable_balance.encode_size()
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
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalizedBatchResponse {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) epoch: u64,
    pub(crate) closing_state_root: VectorRoot<Digest>,
    pub(crate) withdrawal_total: u64,
    pub(crate) payout_total: u64,
    pub(crate) custody_balance: u64,
}

impl From<FinalizedBatch<Digest>> for FinalizedBatchResponse {
    fn from(finalized: FinalizedBatch<Digest>) -> Self {
        Self {
            batch_id: finalized.batch_id,
            epoch: finalized.epoch,
            closing_state_root: finalized.closing_state_root,
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
        self.closing_state_root.write(buf);
        self.withdrawal_total.write(buf);
        self.payout_total.write(buf);
        self.custody_balance.write(buf);
    }
}

impl EncodeSize for FinalizedBatchResponse {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size()
            + self.epoch.encode_size()
            + self.closing_state_root.encode_size()
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
            closing_state_root: VectorRoot::read(buf)?,
            withdrawal_total: u64::read(buf)?,
            payout_total: u64::read(buf)?,
            custody_balance: u64::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalResponse {
    pub(crate) amount: u64,
    pub(crate) destination: Bytes,
}

impl From<WithdrawalRelease<Key, Digest>> for WithdrawalResponse {
    fn from(release: WithdrawalRelease<Key, Digest>) -> Self {
        Self {
            amount: release.amount,
            destination: release.request.body().destination().clone(),
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

fn dispatch(settlement: &mut Settlement, request: rpc::Request) -> anyhow::Result<Bytes> {
    match request.method {
        METHOD_STATUS => {
            StatusRequest::decode(request.body).context("decode status request")?;
            Ok(StatusResponse::from(settlement.status()).encode())
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
        METHOD_FREEZE => {
            let request = FreezeRequest::decode(request.body).context("decode freeze request")?;
            ensure!(
                verify_freeze_signature(
                    request.epoch,
                    &request.deposits,
                    &request.withdrawals,
                    &request.signature,
                ),
                "authenticate settlement boundary"
            );
            settlement
                .freeze(request.epoch, request.deposits, request.withdrawals)
                .context("apply freeze request")?;
            Ok(Bytes::new())
        }
        METHOD_ADMIT => {
            let request = AdmitRequest::decode(request.body).context("decode admit request")?;
            let finalized = settlement
                .admit(request.into())
                .context("apply admit request")?;
            Ok(FinalizedBatchResponse::from(finalized).encode())
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

pub(crate) async fn queue_withdrawal<E: Network>(
    network: &E,
    address: SocketAddr,
    request: QueueWithdrawalRequest,
) -> Result<()> {
    invoke_empty(network, address, METHOD_QUEUE_WITHDRAWAL, request.encode()).await
}

pub(crate) async fn freeze<E: Network>(
    network: &E,
    address: SocketAddr,
    request: FreezeRequest,
) -> Result<()> {
    invoke_empty(network, address, METHOD_FREEZE, request.encode()).await
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
        rpc::Response::Success { body } => FinalizedBatchResponse::decode(body)
            .context("decode admission response")
            .map_err(AdmitError::Unknown),
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
    .context("decode withdrawal release")
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
    use commonware_clearing::bajillion::boundary::{
        DepositRecord, SignedWithdrawal, WithdrawalAction,
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

    fn signed_freeze(
        epoch: u64,
        deposits: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
    ) -> FreezeRequest {
        let protocol = Protocol::new(std::num::NonZeroUsize::MIN).unwrap();
        let signature = protocol.sign_freeze(epoch, &deposits, &withdrawals);
        FreezeRequest {
            epoch,
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
            closing_state_root: VectorRoot { digest },
            withdrawal_total: 11,
            payout_total: 13,
            custody_balance: 17,
        };
        assert_eq!(
            FinalizedBatchResponse::decode(finalized.encode()).unwrap(),
            finalized
        );
        assert!(FinalizedBatchResponse::decode(Bytes::from_static(&[2])).is_err());
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
        let status = settlement.status();
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
        (MAX_BATCH_ITEMS + 1).write(&mut oversized_batch);
        let error = error_text(handle(
            &mut settlement,
            request(METHOD_FREEZE, oversized_batch.freeze()),
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
    fn accepted_deposit_retry_survives_boundary_freeze() {
        let mut settlement = Settlement::new().unwrap();
        let deposit = DepositRequest {
            id: Sha256::hash(&[b"frozen-idempotent-deposit"]),
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
        let freeze = signed_freeze(
            0,
            DepositBatch::new(vec![
                DepositRecord::new(deposit.account.clone(), deposit.amount).unwrap(),
            ])
            .unwrap(),
            WithdrawalBatch::empty(),
        );
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_FREEZE, freeze.encode()),
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
    fn accepted_withdrawal_retry_survives_boundary_freeze() {
        let mut settlement = Settlement::new().unwrap();
        let operator = crate::operator::Operator::open(
            std::path::Path::new(":memory:"),
            std::num::NonZeroUsize::MIN,
        )
        .unwrap();
        let wallet = wallets().remove(0);
        let opening = operator.withdrawal_opening(&wallet.public_key()).unwrap();
        let status = settlement.status();
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
        let freeze = signed_freeze(
            0,
            DepositBatch::empty(),
            WithdrawalBatch::new(vec![withdrawal]).unwrap(),
        );
        assert!(
            success_body(handle(
                &mut settlement,
                request(METHOD_FREEZE, freeze.encode()),
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
    fn freeze_dispatch_is_idempotent_and_fences_deposits() {
        let mut settlement = Settlement::new().unwrap();
        let freeze = signed_freeze(0, DepositBatch::empty(), WithdrawalBatch::empty());
        for _ in 0..2 {
            assert!(
                success_body(handle(
                    &mut settlement,
                    request(METHOD_FREEZE, freeze.encode()),
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
        assert!(error.contains("boundary is already frozen"));
    }

    #[test]
    fn freeze_dispatch_rejects_an_unauthenticated_boundary() {
        let mut settlement = Settlement::new().unwrap();
        let mut freeze = signed_freeze(1, DepositBatch::empty(), WithdrawalBatch::empty());
        freeze.epoch = 0;

        let error = error_text(handle(
            &mut settlement,
            request(METHOD_FREEZE, freeze.encode()),
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
