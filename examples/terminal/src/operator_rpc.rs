//! Bounded operator RPC bodies and synchronous dispatch.

use crate::{
    operator::{CloseEvent, Operator},
    protocol::{Acceptance, DepositEvent, Key, MAX_ACCOUNTS},
    rpc,
    store::MAX_DESTINATION_BYTES,
};
use anyhow::{Context, Result, bail};
use bytes::{Buf, BufMut, Bytes};
#[cfg(test)]
use commonware_clearing::bajillion::boundary::WithdrawalAction;
use commonware_clearing::bajillion::{
    boundary::SignedWithdrawal,
    challenge::StateOpening,
    commitment::VectorRoot,
    payment::{PaymentContext, SignedSend},
    state::AccountState,
    transition::{BatchId, ExternalPayoutClaim, WithdrawalClaim},
};
use commonware_codec::{
    DecodeExt as _, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_runtime::Network;
use std::net::SocketAddr;

pub(crate) const METHOD_STATUS: u8 = 0;
pub(crate) const METHOD_PAYMENT_QUOTE: u8 = 1;
pub(crate) const METHOD_ACCEPT_SEND: u8 = 2;
pub(crate) const METHOD_APPLY_DEPOSIT: u8 = 3;
pub(crate) const METHOD_WITHDRAWAL_OPENING: u8 = 4;
pub(crate) const METHOD_APPLY_WITHDRAWAL: u8 = 5;
pub(crate) const METHOD_START_CLOSE: u8 = 6;
pub(crate) const METHOD_POLL_CLOSE: u8 = 7;
pub(crate) const METHOD_WITHDRAWAL_EVIDENCE: u8 = 8;
pub(crate) const METHOD_ACKNOWLEDGE_WITHDRAWAL: u8 = 9;
pub(crate) const METHOD_EXTERNAL_PAYOUT_EVIDENCE: u8 = 10;
pub(crate) const METHOD_ACKNOWLEDGE_EXTERNAL_PAYOUT: u8 = 11;

const MAX_CLOSE_HEADER_BYTES: usize = 64;
const MAX_CLOSE_ERROR_BYTES: usize = 1_024;
const MAX_ERROR_BYTES: usize = 1_024;
const WITHDRAWAL_ACK_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_APPLIED_WITHDRAWAL_REQUEST";

macro_rules! empty_request {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) struct $name;

        impl Write for $name {
            fn write(&self, _: &mut impl BufMut) {}
        }

        impl EncodeSize for $name {
            fn encode_size(&self) -> usize {
                0
            }
        }

        impl Read for $name {
            type Cfg = ();

            fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                Ok(Self)
            }
        }
    };
}

macro_rules! key_request {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub(crate) struct $name {
            pub(crate) account: Key,
        }

        impl Write for $name {
            fn write(&self, buf: &mut impl BufMut) {
                self.account.write(buf);
            }
        }

        impl EncodeSize for $name {
            fn encode_size(&self) -> usize {
                self.account.encode_size()
            }
        }

        impl Read for $name {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                Ok(Self {
                    account: Key::read(buf)?,
                })
            }
        }
    };
}

empty_request!(StatusRequest);

/// Idempotent request to cut one specific active epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartCloseRequest {
    /// Epoch that the caller observed before beginning the request.
    pub(crate) expected_epoch: u64,
}

impl Write for StartCloseRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.expected_epoch.write(buf);
    }
}

impl EncodeSize for StartCloseRequest {
    fn encode_size(&self) -> usize {
        self.expected_epoch.encode_size()
    }
}

impl Read for StartCloseRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            expected_epoch: u64::read(buf)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PollCloseRequest {
    pub(crate) epoch: u64,
}

impl Write for PollCloseRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
    }
}

impl EncodeSize for PollCloseRequest {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
    }
}

impl Read for PollCloseRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
        })
    }
}

key_request!(PaymentQuoteRequest);
key_request!(WithdrawalOpeningRequest);
key_request!(WithdrawalEvidenceRequest);
key_request!(ExternalPayoutEvidenceRequest);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptSendRequest {
    pub(crate) send: SignedSend<Key, Digest>,
}

impl Write for AcceptSendRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.send.write(buf);
    }
}

impl EncodeSize for AcceptSendRequest {
    fn encode_size(&self) -> usize {
        self.send.encode_size()
    }
}

impl Read for AcceptSendRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            send: SignedSend::read(buf)?,
        })
    }
}

pub(crate) type ApplyDepositRequest = DepositEvent;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyWithdrawalRequest {
    pub(crate) request: SignedWithdrawal<Key, Digest>,
}

impl Write for ApplyWithdrawalRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.request.write(buf);
    }
}

impl EncodeSize for ApplyWithdrawalRequest {
    fn encode_size(&self) -> usize {
        self.request.encode_size()
    }
}

impl Read for ApplyWithdrawalRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            request: SignedWithdrawal::read_cfg(buf, &RangeCfg::new(0..=MAX_DESTINATION_BYTES))?,
        })
    }
}

/// A compact operator snapshot without database-owned display strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatusResponse {
    pub(crate) epoch: u64,
    pub(crate) accounts: u64,
    pub(crate) present_accounts: u64,
    pub(crate) recent_payments: u64,
    pub(crate) reserved_payout_value: u64,
    pub(crate) close_in_progress: bool,
    pub(crate) faulted: bool,
}

impl Write for StatusResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.accounts.write(buf);
        self.present_accounts.write(buf);
        self.recent_payments.write(buf);
        self.reserved_payout_value.write(buf);
        self.close_in_progress.write(buf);
        self.faulted.write(buf);
    }
}

impl EncodeSize for StatusResponse {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.accounts.encode_size()
            + self.present_accounts.encode_size()
            + self.recent_payments.encode_size()
            + self.reserved_payout_value.encode_size()
            + self.close_in_progress.encode_size()
            + self.faulted.encode_size()
    }
}

impl Read for StatusResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            accounts: u64::read(buf)?,
            present_accounts: u64::read(buf)?,
            recent_payments: u64::read(buf)?,
            reserved_payout_value: u64::read(buf)?,
            close_in_progress: bool::read(buf)?,
            faulted: bool::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PaymentQuoteResponse {
    pub(crate) context: PaymentContext<Key, Digest>,
    pub(crate) state: AccountState,
    pub(crate) root: VectorRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

impl Write for PaymentQuoteResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.state.write(buf);
        self.root.write(buf);
        self.opening.write(buf);
    }
}

impl EncodeSize for PaymentQuoteResponse {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.state.encode_size()
            + self.root.encode_size()
            + self.opening.encode_size()
    }
}

impl Read for PaymentQuoteResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let response = Self {
            context: PaymentContext::read(buf)?,
            state: AccountState::read(buf)?,
            root: VectorRoot::read(buf)?,
            opening: StateOpening::read(buf)?,
        };
        if response.opening.proof.proof.leaf_count > MAX_ACCOUNTS as u32 {
            return Err(CodecError::Invalid(
                "clearing_terminal::PaymentQuoteResponse",
                "payer opening exceeds the terminal account bound",
            ));
        }
        Ok(response)
    }
}

/// One accepted send: the shared batch send and one receipt per entry, in entry order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedBatchResponse {
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) total: u64,
    pub(crate) acceptance: Acceptance,
}

impl Write for AcceptedBatchResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.sequence.write(buf);
        self.total.write(buf);
        self.acceptance.write(buf);
    }
}

impl EncodeSize for AcceptedBatchResponse {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.sequence.encode_size()
            + self.total.encode_size()
            + self.acceptance.encode_size()
    }
}

impl Read for AcceptedBatchResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            sequence: u64::read(buf)?,
            total: u64::read(buf)?,
            acceptance: Acceptance::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DepositAck {
    pub(crate) epoch: u64,
    pub(crate) id: Digest,
    pub(crate) account: Key,
    pub(crate) amount: u64,
}

impl Write for DepositAck {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.id.write(buf);
        self.account.write(buf);
        self.amount.write(buf);
    }
}

impl EncodeSize for DepositAck {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.id.encode_size()
            + self.account.encode_size()
            + self.amount.encode_size()
    }
}

impl Read for DepositAck {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            id: Digest::read(buf)?,
            account: Key::read(buf)?,
            amount: u64::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalOpeningResponse {
    pub(crate) root: VectorRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

impl Write for WithdrawalOpeningResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.opening.write(buf);
    }
}

impl EncodeSize for WithdrawalOpeningResponse {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.opening.encode_size()
    }
}

impl Read for WithdrawalOpeningResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            root: VectorRoot::read(buf)?,
            opening: StateOpening::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalAck {
    pub(crate) epoch: u64,
    pub(crate) digest: Digest,
}

impl Write for WithdrawalAck {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.digest.write(buf);
    }
}

impl EncodeSize for WithdrawalAck {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.digest.encode_size()
    }
}

impl Read for WithdrawalAck {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            digest: Digest::read(buf)?,
        })
    }
}

pub(crate) fn withdrawal_digest(request: &SignedWithdrawal<Key, Digest>) -> Digest {
    let encoded = request.encode();
    Sha256::hash(&[WITHDRAWAL_ACK_NAMESPACE, encoded.as_ref()])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalEvidenceResponse {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) account: Key,
    pub(crate) claim: WithdrawalClaim<Digest>,
}

impl Write for WithdrawalEvidenceResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.account.write(buf);
        self.claim.write(buf);
    }
}

impl EncodeSize for WithdrawalEvidenceResponse {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size() + self.account.encode_size() + self.claim.encode_size()
    }
}

impl Read for WithdrawalEvidenceResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            batch_id: BatchId::read(buf)?,
            account: Key::read(buf)?,
            claim: WithdrawalClaim::read_cfg(buf, &RangeCfg::new(0..=MAX_DESTINATION_BYTES))?,
        })
    }
}

pub(crate) type AcknowledgeWithdrawalRequest = WithdrawalEvidenceResponse;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalPayoutEvidenceResponse {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) claim: ExternalPayoutClaim<Key, Digest>,
}

impl Write for ExternalPayoutEvidenceResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.batch_id.write(buf);
        self.claim.write(buf);
    }
}

impl EncodeSize for ExternalPayoutEvidenceResponse {
    fn encode_size(&self) -> usize {
        self.batch_id.encode_size() + self.claim.encode_size()
    }
}

impl Read for ExternalPayoutEvidenceResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            batch_id: BatchId::read(buf)?,
            claim: ExternalPayoutClaim::read(buf)?,
        })
    }
}

pub(crate) type AcknowledgeExternalPayoutRequest = ExternalPayoutEvidenceResponse;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartCloseResponse {
    pub(crate) epoch: u64,
    pub(crate) queued: bool,
}

impl Write for StartCloseResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.queued.write(buf);
    }
}

impl EncodeSize for StartCloseResponse {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.queued.encode_size()
    }
}

impl Read for StartCloseResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            queued: bool::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CloseFinishedResponse {
    pub(crate) epoch: u64,
    pub(crate) header: Bytes,
    pub(crate) rows: u64,
    pub(crate) slices: u64,
    pub(crate) payout_total: u64,
    pub(crate) header_bytes: u64,
    pub(crate) certificate_bytes: u64,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

impl Write for CloseFinishedResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.header.write(buf);
        self.rows.write(buf);
        self.slices.write(buf);
        self.payout_total.write(buf);
        self.header_bytes.write(buf);
        self.certificate_bytes.write(buf);
        self.prepare_micros.write(buf);
        self.deal_micros.write(buf);
        self.seal_micros.write(buf);
    }
}

impl EncodeSize for CloseFinishedResponse {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.header.encode_size()
            + self.rows.encode_size()
            + self.slices.encode_size()
            + self.payout_total.encode_size()
            + self.header_bytes.encode_size()
            + self.certificate_bytes.encode_size()
            + self.prepare_micros.encode_size()
            + self.deal_micros.encode_size()
            + self.seal_micros.encode_size()
    }
}

impl Read for CloseFinishedResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            header: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_CLOSE_HEADER_BYTES))?,
            rows: u64::read(buf)?,
            slices: u64::read(buf)?,
            payout_total: u64::read(buf)?,
            header_bytes: u64::read(buf)?,
            certificate_bytes: u64::read(buf)?,
            prepare_micros: u128::read(buf)?,
            deal_micros: u128::read(buf)?,
            seal_micros: u128::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PollCloseResponse {
    NoEvent,
    Finished(CloseFinishedResponse),
    Failed { epoch: u64, error: Bytes },
}

impl Write for PollCloseResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::NoEvent => 0u8.write(buf),
            Self::Finished(finished) => {
                1u8.write(buf);
                finished.write(buf);
            }
            Self::Failed { epoch, error } => {
                2u8.write(buf);
                epoch.write(buf);
                error.write(buf);
            }
        }
    }
}

impl EncodeSize for PollCloseResponse {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::NoEvent => 0,
            Self::Finished(finished) => finished.encode_size(),
            Self::Failed { epoch, error } => epoch.encode_size() + error.encode_size(),
        }
    }
}

impl Read for PollCloseResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::NoEvent),
            1 => Ok(Self::Finished(CloseFinishedResponse::read(buf)?)),
            2 => Ok(Self::Failed {
                epoch: u64::read(buf)?,
                error: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_CLOSE_ERROR_BYTES))?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

fn count(value: usize, name: &'static str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{name} does not fit the RPC representation"))
}

fn build_status(operator: &Operator) -> Result<StatusResponse> {
    let close_in_progress = operator.close_in_progress();
    let faulted = operator.fault().is_some();
    let status = operator.status().context("read operator status")?;
    Ok(StatusResponse {
        epoch: status.epoch,
        accounts: status.accounts,
        present_accounts: status.present_accounts,
        recent_payments: status.recent_payments,
        reserved_payout_value: status.reserved_payout_value,
        close_in_progress,
        faulted,
    })
}

fn close_event(event: Option<CloseEvent>) -> Result<PollCloseResponse> {
    let Some(event) = event else {
        return Ok(PollCloseResponse::NoEvent);
    };
    match event {
        CloseEvent::Finished(finished) => Ok(PollCloseResponse::Finished(CloseFinishedResponse {
            epoch: finished.epoch,
            header: rpc::bounded_utf8(finished.header_digest, MAX_CLOSE_HEADER_BYTES),
            rows: count(finished.rows, "close row count")?,
            slices: count(finished.slices, "close slice count")?,
            payout_total: finished.payout_total,
            header_bytes: count(finished.header_bytes, "header byte count")?,
            certificate_bytes: count(finished.certificate_bytes, "certificate byte count")?,
            prepare_micros: finished.prepare_micros,
            deal_micros: finished.deal_micros,
            seal_micros: finished.seal_micros,
        })),
        CloseEvent::Failed { epoch, error } => Ok(PollCloseResponse::Failed {
            epoch,
            error: rpc::bounded_utf8(error, MAX_CLOSE_ERROR_BYTES),
        }),
    }
}

pub(crate) enum OperatorRequest {
    Status,
    PaymentQuote(PaymentQuoteRequest),
    AcceptSend(AcceptSendRequest),
    ApplyDeposit(ApplyDepositRequest),
    WithdrawalOpening(WithdrawalOpeningRequest),
    ApplyWithdrawal(ApplyWithdrawalRequest),
    StartClose(StartCloseRequest),
    PollClose(PollCloseRequest),
    WithdrawalEvidence(WithdrawalEvidenceRequest),
    AcknowledgeWithdrawal(Box<AcknowledgeWithdrawalRequest>),
    ExternalPayoutEvidence(ExternalPayoutEvidenceRequest),
    AcknowledgeExternalPayout(Box<AcknowledgeExternalPayoutRequest>),
}

pub(crate) fn decode_request(request: rpc::Request) -> Result<OperatorRequest> {
    let body = request.body;
    match request.method {
        METHOD_STATUS => StatusRequest::decode(body)
            .map(|_| OperatorRequest::Status)
            .context("decode status request"),
        METHOD_PAYMENT_QUOTE => PaymentQuoteRequest::decode(body)
            .map(OperatorRequest::PaymentQuote)
            .context("decode payment-quote request"),
        METHOD_ACCEPT_SEND => AcceptSendRequest::decode(body)
            .map(OperatorRequest::AcceptSend)
            .context("decode accept-send request"),
        METHOD_APPLY_DEPOSIT => ApplyDepositRequest::decode(body)
            .map(OperatorRequest::ApplyDeposit)
            .context("decode apply-deposit request"),
        METHOD_WITHDRAWAL_OPENING => WithdrawalOpeningRequest::decode(body)
            .map(OperatorRequest::WithdrawalOpening)
            .context("decode withdrawal-opening request"),
        METHOD_APPLY_WITHDRAWAL => ApplyWithdrawalRequest::decode(body)
            .map(OperatorRequest::ApplyWithdrawal)
            .context("decode apply-withdrawal request"),
        METHOD_START_CLOSE => StartCloseRequest::decode(body)
            .map(OperatorRequest::StartClose)
            .context("decode start-close request"),
        METHOD_POLL_CLOSE => PollCloseRequest::decode(body)
            .map(OperatorRequest::PollClose)
            .context("decode poll-close request"),
        METHOD_WITHDRAWAL_EVIDENCE => WithdrawalEvidenceRequest::decode(body)
            .map(OperatorRequest::WithdrawalEvidence)
            .context("decode withdrawal-evidence request"),
        METHOD_ACKNOWLEDGE_WITHDRAWAL => AcknowledgeWithdrawalRequest::decode(body)
            .map(Box::new)
            .map(OperatorRequest::AcknowledgeWithdrawal)
            .context("decode withdrawal-acknowledgement request"),
        METHOD_EXTERNAL_PAYOUT_EVIDENCE => ExternalPayoutEvidenceRequest::decode(body)
            .map(OperatorRequest::ExternalPayoutEvidence)
            .context("decode external-payout-evidence request"),
        METHOD_ACKNOWLEDGE_EXTERNAL_PAYOUT => AcknowledgeExternalPayoutRequest::decode(body)
            .map(Box::new)
            .map(OperatorRequest::AcknowledgeExternalPayout)
            .context("decode external-payout-acknowledgement request"),
        method => bail!("unknown operator RPC method {method}"),
    }
}

fn dispatch(operator: &mut Operator, request: OperatorRequest) -> Result<Bytes> {
    match request {
        OperatorRequest::Status => Ok(build_status(operator)?.encode()),
        OperatorRequest::PaymentQuote(request) => {
            let quote = operator
                .payment_quote(&request.account)
                .context("read payment quote")?;
            Ok(PaymentQuoteResponse {
                context: quote.context,
                state: quote.state,
                root: quote.root,
                opening: quote.opening,
            }
            .encode())
        }
        OperatorRequest::AcceptSend(request) => {
            let accepted = operator
                .accept_send(request.send)
                .context("accept payment send")?;
            Ok(AcceptedBatchResponse {
                epoch: accepted.epoch,
                sequence: accepted.sequence,
                total: accepted.total,
                acceptance: accepted.acceptance,
            }
            .encode())
        }
        OperatorRequest::ApplyDeposit(request) => {
            let staged = operator.apply_deposit(request).context("apply deposit")?;
            Ok(DepositAck {
                epoch: staged.epoch,
                id: staged.id,
                account: staged.account,
                amount: staged.amount,
            }
            .encode())
        }
        OperatorRequest::WithdrawalOpening(request) => {
            let quote = operator
                .withdrawal_opening(&request.account)
                .context("read withdrawal opening")?;
            Ok(WithdrawalOpeningResponse {
                root: quote.root,
                opening: quote.opening,
            }
            .encode())
        }
        OperatorRequest::ApplyWithdrawal(request) => {
            let account = request.request.account().clone();
            let action = *request.request.body().action();
            let digest = withdrawal_digest(&request.request);
            let staged = operator
                .apply_withdrawal(request.request)
                .context("apply withdrawal")?;
            anyhow::ensure!(
                staged.account == account && staged.action == action,
                "operator staged another withdrawal"
            );
            Ok(WithdrawalAck {
                epoch: staged.epoch,
                digest,
            }
            .encode())
        }
        OperatorRequest::StartClose(request) => {
            let started = operator
                .start_close(request.expected_epoch)
                .context("start close")?;
            Ok(StartCloseResponse {
                epoch: started.epoch,
                queued: started.queued,
            }
            .encode())
        }
        OperatorRequest::PollClose(request) => {
            Ok(close_event(operator.poll_close(request.epoch).context("poll close")?)?.encode())
        }
        OperatorRequest::WithdrawalEvidence(request) => {
            let evidence = operator
                .withdrawal_evidence(&request.account)
                .context("read withdrawal evidence")?;
            Ok(WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: evidence.account,
                claim: evidence.claim,
            }
            .encode())
        }
        OperatorRequest::AcknowledgeWithdrawal(_) => {
            bail!("settlement confirmation is required before acknowledging a withdrawal")
        }
        OperatorRequest::ExternalPayoutEvidence(request) => {
            let evidence = operator
                .external_payout_evidence(&request.account)
                .context("read external payout evidence")?;
            Ok(ExternalPayoutEvidenceResponse {
                batch_id: evidence.batch_id,
                claim: evidence.claim,
            }
            .encode())
        }
        OperatorRequest::AcknowledgeExternalPayout(_) => {
            bail!("settlement confirmation is required before acknowledging an external payout")
        }
    }
}

fn error_response(error: String) -> rpc::Response {
    rpc::Response::Error {
        error: rpc::bounded_utf8(error, MAX_ERROR_BYTES),
    }
}

#[cfg(test)]
pub(crate) fn handle(operator: &mut Operator, request: rpc::Request) -> rpc::Response {
    let request = decode_request(request);
    match request.and_then(|request| dispatch(operator, request)) {
        Ok(body) => rpc::Response::Success { body },
        Err(error) => error_response(format!("{error:#}")),
    }
}

pub(crate) fn handle_decoded(operator: &mut Operator, request: OperatorRequest) -> rpc::Response {
    match dispatch(operator, request) {
        Ok(body) => rpc::Response::Success { body },
        Err(error) => error_response(format!("{error:#}")),
    }
}

pub(crate) fn acknowledge_withdrawal_confirmed(
    operator: &mut Operator,
    request: &AcknowledgeWithdrawalRequest,
) -> rpc::Response {
    match operator
        .acknowledge_withdrawal_claim(request.batch_id, &request.account, &request.claim)
        .context("acknowledge withdrawal claim")
    {
        Ok(()) => rpc::Response::Success { body: Bytes::new() },
        Err(error) => error_response(format!("{error:#}")),
    }
}

pub(crate) fn acknowledge_external_payout_confirmed(
    operator: &mut Operator,
    request: &AcknowledgeExternalPayoutRequest,
) -> rpc::Response {
    match operator
        .acknowledge_external_payout_claim(request.batch_id, &request.claim)
        .context("acknowledge external payout claim")
    {
        Ok(()) => rpc::Response::Success { body: Bytes::new() },
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
        .context("call operator")?;
    match response {
        rpc::Response::Success { body } => Ok(body),
        rpc::Response::Error { error } => {
            bail!(
                "operator rejected request: {}",
                String::from_utf8_lossy(&error)
            )
        }
    }
}

pub(crate) async fn status<E: Network>(network: &E, address: SocketAddr) -> Result<StatusResponse> {
    StatusResponse::decode(invoke(network, address, METHOD_STATUS, StatusRequest.encode()).await?)
        .context("decode operator status")
}

pub(crate) async fn payment_quote<E: Network>(
    network: &E,
    address: SocketAddr,
    request: PaymentQuoteRequest,
) -> Result<PaymentQuoteResponse> {
    PaymentQuoteResponse::decode(
        invoke(network, address, METHOD_PAYMENT_QUOTE, request.encode()).await?,
    )
    .context("decode payment quote")
}

pub(crate) async fn accept_send<E: Network>(
    network: &E,
    address: SocketAddr,
    request: AcceptSendRequest,
) -> Result<AcceptedBatchResponse> {
    AcceptedBatchResponse::decode(
        invoke(network, address, METHOD_ACCEPT_SEND, request.encode()).await?,
    )
    .context("decode accepted payment")
}

pub(crate) async fn apply_deposit<E: Network>(
    network: &E,
    address: SocketAddr,
    request: ApplyDepositRequest,
) -> Result<DepositAck> {
    DepositAck::decode(invoke(network, address, METHOD_APPLY_DEPOSIT, request.encode()).await?)
        .context("decode applied deposit")
}

pub(crate) async fn withdrawal_opening<E: Network>(
    network: &E,
    address: SocketAddr,
    request: WithdrawalOpeningRequest,
) -> Result<WithdrawalOpeningResponse> {
    WithdrawalOpeningResponse::decode(
        invoke(
            network,
            address,
            METHOD_WITHDRAWAL_OPENING,
            request.encode(),
        )
        .await?,
    )
    .context("decode withdrawal opening")
}

pub(crate) async fn apply_withdrawal<E: Network>(
    network: &E,
    address: SocketAddr,
    request: ApplyWithdrawalRequest,
) -> Result<WithdrawalAck> {
    WithdrawalAck::decode(
        invoke(network, address, METHOD_APPLY_WITHDRAWAL, request.encode()).await?,
    )
    .context("decode applied withdrawal")
}

pub(crate) async fn start_close<E: Network>(
    network: &E,
    address: SocketAddr,
    expected_epoch: u64,
) -> Result<StartCloseResponse> {
    StartCloseResponse::decode(
        invoke(
            network,
            address,
            METHOD_START_CLOSE,
            StartCloseRequest { expected_epoch }.encode(),
        )
        .await?,
    )
    .context("decode close start")
}

pub(crate) async fn poll_close<E: Network>(
    network: &E,
    address: SocketAddr,
    epoch: u64,
) -> Result<PollCloseResponse> {
    PollCloseResponse::decode(
        invoke(
            network,
            address,
            METHOD_POLL_CLOSE,
            PollCloseRequest { epoch }.encode(),
        )
        .await?,
    )
    .context("decode close event")
}

pub(crate) async fn withdrawal_evidence<E: Network>(
    network: &E,
    address: SocketAddr,
    request: WithdrawalEvidenceRequest,
) -> Result<WithdrawalEvidenceResponse> {
    WithdrawalEvidenceResponse::decode(
        invoke(
            network,
            address,
            METHOD_WITHDRAWAL_EVIDENCE,
            request.encode(),
        )
        .await?,
    )
    .context("decode withdrawal evidence")
}

pub(crate) async fn acknowledge_withdrawal<E: Network>(
    network: &E,
    address: SocketAddr,
    request: AcknowledgeWithdrawalRequest,
) -> Result<()> {
    let response = invoke(
        network,
        address,
        METHOD_ACKNOWLEDGE_WITHDRAWAL,
        request.encode(),
    )
    .await?;
    anyhow::ensure!(response.is_empty(), "operator returned an unexpected body");
    Ok(())
}

pub(crate) async fn external_payout_evidence<E: Network>(
    network: &E,
    address: SocketAddr,
    request: ExternalPayoutEvidenceRequest,
) -> Result<ExternalPayoutEvidenceResponse> {
    ExternalPayoutEvidenceResponse::decode(
        invoke(
            network,
            address,
            METHOD_EXTERNAL_PAYOUT_EVIDENCE,
            request.encode(),
        )
        .await?,
    )
    .context("decode external payout evidence")
}

pub(crate) async fn acknowledge_external_payout<E: Network>(
    network: &E,
    address: SocketAddr,
    request: AcknowledgeExternalPayoutRequest,
) -> Result<()> {
    let response = invoke(
        network,
        address,
        METHOD_ACKNOWLEDGE_EXTERNAL_PAYOUT,
        request.encode(),
    )
    .await?;
    anyhow::ensure!(response.is_empty(), "operator returned an unexpected body");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Protocol, identities, wallets};
    use bytes::BytesMut;
    use commonware_codec::Decode as _;
    use commonware_cryptography::{Hasher, Sha256};
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        path::Path,
        thread,
        time::Duration,
    };

    fn operator() -> Operator {
        Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap()
    }

    fn request(method: u8, body: impl Into<Bytes>) -> rpc::Request {
        rpc::Request {
            method,
            body: body.into(),
        }
    }

    #[test]
    fn withdrawal_ack_binds_the_complete_signed_request() {
        let wallets = wallets();
        let payer = &wallets[0];
        let deployment = Sha256::hash(&[b"withdrawal-ack-deployment"]);
        let state_root = Sha256::hash(&[b"withdrawal-ack-state"]);
        let amount = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
        let baseline = SignedWithdrawal::sign(
            deployment,
            state_root,
            Bytes::from_static(b"destination"),
            amount,
            50,
            payer.signer(),
        );
        let mut variants = vec![
            SignedWithdrawal::sign(
                Sha256::hash(&[b"another-deployment"]),
                state_root,
                Bytes::from_static(b"destination"),
                amount,
                50,
                payer.signer(),
            ),
            SignedWithdrawal::sign(
                deployment,
                Sha256::hash(&[b"another-state-root"]),
                Bytes::from_static(b"destination"),
                amount,
                50,
                payer.signer(),
            ),
            SignedWithdrawal::sign(
                deployment,
                state_root,
                Bytes::from_static(b"another-destination"),
                amount,
                50,
                payer.signer(),
            ),
            SignedWithdrawal::sign(
                deployment,
                state_root,
                Bytes::from_static(b"destination"),
                WithdrawalAction::Close,
                50,
                payer.signer(),
            ),
            SignedWithdrawal::sign(
                deployment,
                state_root,
                Bytes::from_static(b"destination"),
                amount,
                51,
                payer.signer(),
            ),
            SignedWithdrawal::sign(
                deployment,
                state_root,
                Bytes::from_static(b"destination"),
                amount,
                50,
                wallets[1].signer(),
            ),
        ];
        let mut changed_signature = baseline.encode().to_vec();
        *changed_signature.last_mut().unwrap() ^= 1;
        variants.push(
            SignedWithdrawal::decode_cfg(
                Bytes::from(changed_signature),
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )
            .unwrap(),
        );

        let digest = withdrawal_digest(&baseline);
        for variant in variants {
            assert_ne!(withdrawal_digest(&variant), digest);
        }

        let ack = WithdrawalAck { epoch: 9, digest };
        let encoded = ack.encode();
        assert_eq!(WithdrawalAck::decode(encoded.clone()).unwrap(), ack);
        for end in 0..encoded.len() {
            assert!(WithdrawalAck::decode(encoded.slice(..end)).is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(WithdrawalAck::decode(Bytes::from(trailing)).is_err());
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

    #[test]
    fn unknown_method_is_rejected() {
        let mut operator = operator();
        let error = error_text(handle(&mut operator, request(u8::MAX, Bytes::new())));
        assert!(error.contains("unknown operator RPC method 255"));
    }

    #[test]
    fn malformed_trailing_and_oversized_bodies_are_rejected() {
        let mut operator = operator();
        assert!(
            !error_text(handle(
                &mut operator,
                request(METHOD_ACCEPT_SEND, Bytes::from_static(&[0])),
            ))
            .is_empty()
        );

        let error = error_text(handle(
            &mut operator,
            request(METHOD_STATUS, Bytes::from_static(&[0])),
        ));
        assert!(error.contains("Extra Data"));

        let account = identities().remove(0).key;
        let mut trailing = PaymentQuoteRequest { account }.encode().to_vec();
        trailing.push(0xff);
        let error = error_text(handle(
            &mut operator,
            request(METHOD_PAYMENT_QUOTE, trailing),
        ));
        assert!(error.contains("Extra Data"));

        let close = StartCloseRequest { expected_epoch: 7 };
        assert_eq!(StartCloseRequest::decode(close.encode()).unwrap(), close);
        let mut trailing = close.encode().to_vec();
        trailing.push(0xff);
        let error = error_text(handle(&mut operator, request(METHOD_START_CLOSE, trailing)));
        assert!(error.contains("Extra Data"));

        let wallet = wallets().remove(0);
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let oversized = SignedWithdrawal::sign(
            protocol.deployment(),
            Sha256::hash(&[b"oversized-withdrawal-root"]),
            Bytes::from(vec![0; MAX_DESTINATION_BYTES + 1]),
            WithdrawalAction::Amount(NonZeroU64::MIN),
            100,
            wallet.signer(),
        );
        let error = error_text(handle(
            &mut operator,
            request(
                METHOD_APPLY_WITHDRAWAL,
                ApplyWithdrawalRequest { request: oversized }.encode(),
            ),
        ));
        assert!(error.contains("Invalid Length"));

        let mut oversized_error = BytesMut::new();
        2u8.write(&mut oversized_error);
        0u64.write(&mut oversized_error);
        Bytes::from(vec![0; MAX_CLOSE_ERROR_BYTES + 1]).write(&mut oversized_error);
        assert!(PollCloseResponse::decode(oversized_error.freeze()).is_err());

        let mut trailing_response = StatusResponse {
            epoch: 0,
            accounts: 0,
            present_accounts: 0,
            recent_payments: 0,
            reserved_payout_value: 0,
            close_in_progress: false,
            faulted: false,
        }
        .encode()
        .to_vec();
        trailing_response.push(0xff);
        assert!(StatusResponse::decode(trailing_response.as_slice()).is_err());
    }

    #[test]
    fn operator_methods_round_trip() {
        let mut operator = operator();
        let mut wallets = wallets();
        let payer = wallets.remove(0);
        let payer_key = payer.public_key();

        let status = StatusResponse::decode(success_body(handle(
            &mut operator,
            request(METHOD_STATUS, Bytes::new()),
        )))
        .unwrap();
        assert_eq!(status.epoch, 0);
        assert_eq!(status.accounts, 4);
        assert_eq!(status.present_accounts, 4);
        assert_eq!(status.recent_payments, 0);

        let deposit = ApplyDepositRequest {
            id: Sha256::hash(&[b"operator-rpc-deposit"]),
            account: payer_key.clone(),
            amount: 10,
        };
        let applied = DepositAck::decode(success_body(handle(
            &mut operator,
            request(METHOD_APPLY_DEPOSIT, deposit.encode()),
        )))
        .unwrap();
        assert_eq!(applied.epoch, 0);
        assert_eq!(applied.account, payer_key);
        assert_eq!(applied.amount, 10);

        let opening = WithdrawalOpeningResponse::decode(success_body(handle(
            &mut operator,
            request(
                METHOD_WITHDRAWAL_OPENING,
                WithdrawalOpeningRequest {
                    account: payer_key.clone(),
                }
                .encode(),
            ),
        )))
        .unwrap();
        assert_eq!(opening.opening.leaf.account, payer_key);

        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let withdrawal = SignedWithdrawal::sign(
            protocol.deployment(),
            opening.root.digest,
            Bytes::from_static(b"wallet-destination"),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            100,
            payer.signer(),
        );
        let expected_digest = withdrawal_digest(&withdrawal);
        let applied = WithdrawalAck::decode(success_body(handle(
            &mut operator,
            request(
                METHOD_APPLY_WITHDRAWAL,
                ApplyWithdrawalRequest {
                    request: withdrawal,
                }
                .encode(),
            ),
        )))
        .unwrap();
        assert_eq!(applied.epoch, 0);
        assert_eq!(applied.digest, expected_digest);

        let close_account = wallets[0].public_key();
        let close_opening = WithdrawalOpeningResponse::decode(success_body(handle(
            &mut operator,
            request(
                METHOD_WITHDRAWAL_OPENING,
                WithdrawalOpeningRequest {
                    account: close_account.clone(),
                }
                .encode(),
            ),
        )))
        .unwrap();
        let close = SignedWithdrawal::sign(
            protocol.deployment(),
            close_opening.root.digest,
            Bytes::from_static(b"close-destination"),
            WithdrawalAction::Close,
            100,
            wallets[0].signer(),
        );
        let close_digest = withdrawal_digest(&close);
        let applied_close = WithdrawalAck::decode(success_body(handle(
            &mut operator,
            request(
                METHOD_APPLY_WITHDRAWAL,
                ApplyWithdrawalRequest { request: close }.encode(),
            ),
        )))
        .unwrap();
        assert_eq!(applied_close.digest, close_digest);
        assert_eq!(
            operator
                .payment_quote(&close_account)
                .unwrap()
                .state
                .balance,
            100
        );

        let quote = PaymentQuoteResponse::decode(success_body(handle(
            &mut operator,
            request(
                METHOD_PAYMENT_QUOTE,
                PaymentQuoteRequest {
                    account: payer_key.clone(),
                }
                .encode(),
            ),
        )))
        .unwrap();
        assert_eq!(quote.state.balance, 103);

        let send = SignedSend::sign_next(
            &quote.context,
            payer.signer(),
            wallets[0].public_key(),
            5,
            quote.state.cumulative_debit,
        )
        .unwrap();
        let accepted = AcceptedBatchResponse::decode(success_body(handle(
            &mut operator,
            request(METHOD_ACCEPT_SEND, AcceptSendRequest { send }.encode()),
        )))
        .unwrap();
        assert_eq!(accepted.epoch, 0);
        assert_eq!(accepted.total, 5);
        assert_eq!(accepted.acceptance.receipts[0].body().amount(), 5);
        accepted.acceptance.verify(&quote.context).unwrap();

        let started = StartCloseResponse::decode(success_body(handle(
            &mut operator,
            request(
                METHOD_START_CLOSE,
                StartCloseRequest { expected_epoch: 0 }.encode(),
            ),
        )))
        .unwrap();
        assert_eq!(started.epoch, 0);
        assert!(!started.queued);

        loop {
            let event = PollCloseResponse::decode(success_body(handle(
                &mut operator,
                request(
                    METHOD_POLL_CLOSE,
                    PollCloseRequest {
                        epoch: started.epoch,
                    }
                    .encode(),
                ),
            )))
            .unwrap();
            match event {
                PollCloseResponse::NoEvent => thread::sleep(Duration::from_millis(5)),
                PollCloseResponse::Finished(finished) => {
                    assert_eq!(finished.epoch, 0);
                    assert!(finished.rows > 0);
                    break;
                }
                PollCloseResponse::Failed { error, .. } => {
                    panic!("close failed: {}", String::from_utf8_lossy(&error));
                }
            }
        }

        let evidence = WithdrawalEvidenceResponse::decode(success_body(handle(
            &mut operator,
            request(
                METHOD_WITHDRAWAL_EVIDENCE,
                WithdrawalEvidenceRequest {
                    account: payer_key.clone(),
                }
                .encode(),
            ),
        )))
        .unwrap();
        assert_eq!(evidence.account, payer_key);
        assert_eq!(evidence.claim.output().amount(), 7);
        assert_eq!(
            evidence.claim.output().destination().as_ref(),
            b"wallet-destination"
        );
    }

    #[test]
    fn unconfirmed_withdrawal_acknowledgement_keeps_evidence() {
        let mut operator = operator();
        let account = wallets()[0].public_key();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()))
            .unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let acknowledgement = AcknowledgeWithdrawalRequest {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };

        let error = error_text(handle(
            &mut operator,
            request(METHOD_ACKNOWLEDGE_WITHDRAWAL, acknowledgement.encode()),
        ));
        assert!(error.contains("settlement confirmation"));
        assert!(operator.withdrawal_evidence(&account).is_ok());
    }

    #[test]
    fn unconfirmed_external_payout_acknowledgement_keeps_evidence() {
        let mut operator = operator();
        let recipient = crate::protocol::external_identity().key;
        operator.pay(0, operator.wallet_count(), 7).unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();
        let evidence = operator.external_payout_evidence(&recipient).unwrap();
        let acknowledgement = AcknowledgeExternalPayoutRequest {
            batch_id: evidence.batch_id,
            claim: evidence.claim,
        };

        let error = error_text(handle(
            &mut operator,
            request(METHOD_ACKNOWLEDGE_EXTERNAL_PAYOUT, acknowledgement.encode()),
        ));
        assert!(error.contains("settlement confirmation"));
        assert!(operator.external_payout_evidence(&recipient).is_ok());
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
