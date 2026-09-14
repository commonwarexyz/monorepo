//! Concrete protocol wiring for the operator.

use anyhow::{Context, Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use commonware_clearing::bajillion::{
    admission::{Committee, Vote, bls12381, seal},
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{HigherEntryLookup, higher_entry_lookup},
    commitment::{Builder as VectorBuilder, Opening, VectorKind, VectorRoot},
    payment::{EntryReceipt, PaymentContext, VectorAck, VectorSendBody},
    qmdb::{PreparedState, State, StateRoot},
    settlement::{EpochDeadlinePolicy, Genesis as ConfiguredGenesis, SettlementConfig},
    transition::{
        BatchId, ChallengeIndex, Close, CloseContext, CloseLimits, EpochContext, Header,
        OperatorKey, OperatorSignature, OperatorVariant, RootBundle, Terminal, WithdrawalClaim,
        prepare_dealing,
    },
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::{compute_public, sign_message},
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, Signature, SigningKey, StrictVerifyingKey,
};
use commonware_parallel::{Rayon, Sequential};
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU64, NZUsize, Participant, sync::Mutex};
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Instant,
};

pub(crate) type Key = StrictVerifyingKey;
pub(crate) type Ack = VectorAck<Key, Digest>;
pub(crate) type Receipt = EntryReceipt<Key, Digest>;

/// Binds a withdrawal output to its authorizing account in the same certified close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalWitness {
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) withdrawal_total: u64,
    pub(crate) request: SignedWithdrawal<Key, Digest>,
    pub(crate) opening: Opening<Digest>,
    pub(crate) claim: WithdrawalClaim<Digest>,
}

impl WithdrawalWitness {
    pub(crate) fn new(
        context: &CloseContext<Key, Digest>,
        withdrawal_total: u64,
        withdrawals: &WithdrawalBatch<Key, Digest>,
        claim: WithdrawalClaim<Digest>,
    ) -> Result<Self> {
        let request = withdrawals
            .requests()
            .get(claim.position() as usize)
            .context("withdrawal output has no corresponding request")?
            .clone();
        let mut tree = VectorBuilder::<Sha256>::new(
            VectorKind::Withdrawal,
            u32::try_from(withdrawals.len())?,
        )?;
        for request in withdrawals.requests() {
            tree.add_encoded(&request.encode())?;
        }
        let tree = tree.build(&Sequential)?;
        ensure!(
            tree.root() == *context.withdrawal_root(),
            "withdrawal boundary differs from its context"
        );
        Ok(Self {
            context: context.clone(),
            withdrawal_total,
            request,
            opening: tree.opening(claim.position())?,
            claim,
        })
    }

    pub(crate) fn batch_id(&self, roots: &RootBundle<Digest>) -> BatchId<Digest> {
        Header::new::<Sha256, Key>(&self.context, roots, self.withdrawal_total).batch_id::<Sha256>()
    }

    /// Verifies both positions and their descriptor; certification authenticates the returned batch.
    pub(crate) fn verify(
        &self,
        roots: &RootBundle<Digest>,
        deployment: &Digest,
        account: &Key,
        destination: &[u8],
    ) -> Result<BatchId<Digest>> {
        ensure!(
            self.context.deployment() == deployment
                && self.context.epoch_context().verify_anchor::<Sha256>(),
            "withdrawal evidence has an invalid deployment context"
        );
        ensure!(
            self.request.account() == account,
            "withdrawal evidence belongs to another account"
        );
        ensure!(
            self.opening.position == self.claim.position(),
            "withdrawal request and output positions differ"
        );
        self.opening.verify::<Sha256>(
            VectorKind::Withdrawal,
            self.context.withdrawal_root(),
            &self.request.encode(),
        )?;
        let output = self.claim.verify::<Sha256>(&roots.withdrawal_outputs)?;
        ensure!(
            self.request.body().destination().as_ref() == destination
                && output.destination().as_ref() == destination,
            "withdrawal evidence pays another destination"
        );
        Ok(self.batch_id(roots))
    }
}

impl Write for WithdrawalWitness {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.withdrawal_total.write(buf);
        self.request.write(buf);
        self.opening.write(buf);
        self.claim.write(buf);
    }
}

impl EncodeSize for WithdrawalWitness {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.withdrawal_total.encode_size()
            + self.request.encode_size()
            + self.opening.encode_size()
            + self.claim.encode_size()
    }
}

impl Read for WithdrawalWitness {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let destination = RangeCfg::new(0..=MAX_DESTINATION_BYTES);
        Ok(Self {
            context: CloseContext::read(buf)?,
            withdrawal_total: u64::read(buf)?,
            request: SignedWithdrawal::read_cfg(buf, &destination)?,
            opening: Opening::read(buf)?,
            claim: WithdrawalClaim::read_cfg(buf, &destination)?,
        })
    }
}

/// A complete withdrawal witness for operator delivery and durable wallet caching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WithdrawalEvidence {
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) witness: WithdrawalWitness,
}

impl WithdrawalEvidence {
    pub(crate) fn batch_id(&self) -> BatchId<Digest> {
        self.witness.batch_id(&self.roots)
    }
}

impl Write for WithdrawalEvidence {
    fn write(&self, buf: &mut impl BufMut) {
        self.roots.write(buf);
        self.witness.write(buf);
    }
}

impl EncodeSize for WithdrawalEvidence {
    fn encode_size(&self) -> usize {
        self.roots.encode_size() + self.witness.encode_size()
    }
}

impl Read for WithdrawalEvidence {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            roots: RootBundle::read(buf)?,
            witness: WithdrawalWitness::read(buf)?,
        })
    }
}

/// Maximum entries in one batched send, bounding adversarial acceptance decoding.
pub(crate) const MAX_ENTRIES: usize = 256;

const DEPLOYMENT_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_DEPLOYMENT";

/// Deterministic deployment identity for in-process protocol fixtures.
/// Network deployments use domains committed by genesis or the native registry.
pub(crate) fn deployment_of(operator: &Key) -> Digest {
    Sha256::hash(&[DEPLOYMENT_NAMESPACE, &operator.encode()])
}

/// Namespace for chain registrations. The signed payload is the boundary
/// material and native fee (epoch, predecessor liability, deposit root,
/// withdrawal batch): execution assigns the absolute block-height deadlines
/// at the registration's inclusion height, so the operator has nothing about
/// timing to commit.
const CHAIN_REGISTRATION_SIGNATURE_NAMESPACE: &[u8] =
    b"_COMMONWARE_EXAMPLES_TERMINAL_CHAIN_REGISTRATION";
const VALIDATOR_SEED_START: u64 = 10_000;
const OPERATOR_ACK_SEED_START: u64 = 20_000;
const VALIDATORS: usize = 4;

/// Maximum funded accounts encoded in a deployment's authenticated bootstrap.
pub(crate) const MAX_GENESIS_ACCOUNTS: usize = 1_024;
/// Maximum accepted payments in one epoch, counting one per batched-send entry.
pub(crate) const MAX_ACCEPTED_PAYMENTS: usize = 1_024;
/// Reservation floor covering a complete close at the native activity and entry limits.
pub(crate) const MIN_DEALING_BYTES: u32 = 256 * 1024;
/// Bounds one encoded [`Acceptance`] at [`MAX_ENTRIES`], including its shared acknowledgment
/// and a full-depth opening per entry. The entry count uses a seven-bit varint; each opening
/// has a one-byte sibling count and up to `u32::BITS` digests.
pub(crate) const MAX_ACCEPTANCE_BYTES: usize = Ack::SIZE
    + ((MAX_ENTRIES.ilog2() + 1) as usize).div_ceil(7)
    + MAX_ENTRIES
        * (Key::SIZE + u64::SIZE * 2 + u32::SIZE * 2 + 1 + Digest::SIZE * u32::BITS as usize);
pub(crate) const MAX_DEPOSIT_EVENTS: usize = 1_024;
pub(crate) const MAX_WITHDRAWALS: usize = 1_024;
/// Each accepted entry contributes at most one payer and one recipient; boundary records
/// contribute at most one account each. Dormant balances contribute no activity rows.
pub(crate) const MAX_ACTIVITY_ROWS: usize =
    2 * MAX_ACCEPTED_PAYMENTS + MAX_DEPOSIT_EVENTS + MAX_WITHDRAWALS;

/// Maximum withdrawal destination length in bytes, shared by every codec that carries one.
pub(crate) const MAX_DESTINATION_BYTES: usize = 256;
pub(crate) const INITIAL_BALANCE: u64 = 100;
/// Largest monetary value that the SQLite operator can persist exactly.
pub(crate) const SQLITE_U64_MAX: u64 = i64::MAX as u64;
// Pre-registration contexts and in-process fixtures use this placeholder grid.
// A native registration adopts the deadlines assigned by its genesis policy.
const ADMISSION_OFFSET: u64 = 10;
const CHALLENGE_DURATION: u64 = 1;
const CHALLENGE_OFFSET: u64 = ADMISSION_OFFSET + CHALLENGE_DURATION;
const EPOCH_STRIDE: u64 = CHALLENGE_OFFSET + 1;

// The admission runway setup writes into a new chain's genesis. The deadline
// keeps running while an operator is down and only the admitted close
// consumes it, so the runway must cover an operator relaunch (which resumes
// the cut on startup), not just the immediate cut: the compiled grid's ten
// blocks pass in seconds at live cadence.
const GENESIS_ADMISSION_OFFSET: u64 = 300;

// A deposit must reach an admitted close within this many blocks of its
// custody record. A registered boundary's deposits stay pending until that
// close admits, and the close may consume most of the genesis admission
// runway (an operator relaunch included), so the timeout dominates it.
const DEPOSIT_INCLUSION_TIMEOUT: u64 = GENESIS_ADMISSION_OFFSET + 100;
/// Genesis-fixed epoch timing policy, in blocks.
///
/// The policy is fixed once at chain creation (setup writes it into
/// `genesis.json`) and applied to every configured deployment, rather than
/// chosen per epoch or per operator: such a choice would let an operator
/// pick a challenge window too short for anyone to enforce in. Forced
/// withdrawal remains the escape from a badly configured chain, not a
/// substitute for a sane window.
///
/// The genesis fixes the policy and the chain assigns the instance: every
/// window opens at the inclusion of the operator submission that triggers
/// it. A registration's inclusion assigns its admission and challenge
/// deadlines from this policy, and an admission opens the challenge window
/// and the successor epoch's registration eligibility. An operator never
/// chooses timing, only when to submit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Timing {
    /// Maximum blocks from a registration's inclusion height to its admission
    /// deadline.
    pub(crate) admission_offset: u64,
    /// Exact blocks between a registration's admission deadline and its
    /// challenge deadline.
    pub(crate) challenge_duration: u64,
}

impl Timing {
    /// The compiled fixture-grid pair the harness and placeholder contexts
    /// run on.
    pub(crate) const DEFAULT: Self = Self {
        admission_offset: ADMISSION_OFFSET,
        challenge_duration: CHALLENGE_DURATION,
    };

    /// The defaults setup writes into a new chain's genesis: the fixture
    /// challenge duration under the wall-clock admission runway.
    pub(crate) const GENESIS: Self = Self {
        admission_offset: GENESIS_ADMISSION_OFFSET,
        challenge_duration: CHALLENGE_DURATION,
    };
}

#[cfg(test)]
pub(crate) const TERMINAL_EPOCH: u64 = (u64::MAX - CHALLENGE_OFFSET) / EPOCH_STRIDE;

#[derive(Clone)]
pub(crate) struct AccountIdentity {
    pub(crate) name: &'static str,
    pub(crate) key: Key,
}

/// An agent wallet. Its private key stays outside the SQLite operator store.
pub(crate) struct Wallet {
    pub(crate) name: &'static str,
    signing_key: SigningKey,
}

impl Wallet {
    pub(crate) fn from_seed(name: &'static str, seed: u64) -> Self {
        Self {
            name,
            signing_key: SigningKey::from_seed(seed),
        }
    }

    pub(crate) fn public_key(&self) -> Key {
        self.signing_key.public_key()
    }

    pub(crate) const fn signer(&self) -> &SigningKey {
        &self.signing_key
    }
}

pub(crate) fn wallets() -> Vec<Wallet> {
    vec![
        Wallet::from_seed("Alice", 101),
        Wallet::from_seed("Bob", 102),
        Wallet::from_seed("Carol", 103),
        Wallet::from_seed("Dave", 104),
    ]
}

pub(crate) fn identities() -> Vec<AccountIdentity> {
    wallets()
        .into_iter()
        .map(|wallet| AccountIdentity {
            name: wallet.name,
            key: wallet.public_key(),
        })
        .collect()
}

pub(crate) fn eve_wallet() -> Wallet {
    Wallet::from_seed("Eve", 999)
}

pub(crate) fn eve_identity() -> AccountIdentity {
    let wallet = eve_wallet();
    AccountIdentity {
        name: wallet.name,
        key: wallet.public_key(),
    }
}

/// One credited recipient and positive amount inside a batched send.
///
/// The wire carries per-batch deltas so both sides can maintain the payer's cumulative
/// out vector independently. Entries must be strictly recipient-sorted and unique.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) recipient: Key,
    pub(crate) amount: u64,
}

impl Write for Entry {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.amount.write(buf);
    }
}

impl EncodeSize for Entry {
    fn encode_size(&self) -> usize {
        self.recipient.encode_size() + self.amount.encode_size()
    }
}

impl Read for Entry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            recipient: Key::read(buf)?,
            amount: u64::read(buf)?,
        })
    }
}

/// One accepted entry: the credited recipient's cumulative endpoint and its membership
/// opening under the acknowledged vector root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedEntry {
    pub(crate) recipient: Key,
    pub(crate) cumulative: u64,
    pub(crate) count: u64,
    pub(crate) opening: Opening<Digest>,
}

impl Write for AcceptedEntry {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.cumulative.write(buf);
        self.count.write(buf);
        self.opening.write(buf);
    }
}

impl EncodeSize for AcceptedEntry {
    fn encode_size(&self) -> usize {
        self.recipient.encode_size()
            + self.cumulative.encode_size()
            + self.count.encode_size()
            + self.opening.encode_size()
    }
}

impl Read for AcceptedEntry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            recipient: Key::read(buf)?,
            cumulative: u64::read(buf)?,
            count: u64::read(buf)?,
            opening: Opening::read(buf)?,
        })
    }
}

/// One accepted send: the dual-signed vector endpoint and one opened entry per credited
/// recipient, in entry order.
///
/// This is the shape the wire and both SQLite stores share. The acknowledgment is carried
/// once. Per-entry [`Receipt`]s are reassembled where transferable evidence is needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Acceptance {
    pub(crate) ack: Ack,
    pub(crate) entries: Vec<AcceptedEntry>,
}

impl Acceptance {
    /// Verifies the acknowledgment and every entry's membership under its committed root.
    pub(crate) fn verify(&self, context: &PaymentContext<Key, Digest>) -> Result<()> {
        ensure!(!self.entries.is_empty(), "acceptance opens no entries");
        ensure!(
            self.entries
                .windows(2)
                .all(|pair| pair[0].recipient < pair[1].recipient),
            "acceptance entries are not strictly recipient-sorted"
        );
        for receipt in self.receipts() {
            receipt
                .verify::<Sha256>(context)
                .context("verify acceptance entry receipt")?;
        }
        Ok(())
    }

    /// Reassembles one transferable entry receipt per credited recipient.
    pub(crate) fn receipts(&self) -> impl Iterator<Item = Receipt> + '_ {
        self.entries.iter().map(|entry| EntryReceipt {
            ack: self.ack.clone(),
            recipient: entry.recipient.clone(),
            cumulative: entry.cumulative,
            count: entry.count,
            opening: entry.opening.clone(),
        })
    }
}

impl Write for Acceptance {
    fn write(&self, buf: &mut impl BufMut) {
        self.ack.write(buf);
        self.entries.write(buf);
    }
}

impl EncodeSize for Acceptance {
    fn encode_size(&self) -> usize {
        self.ack.encode_size() + self.entries.encode_size()
    }
}

impl Read for Acceptance {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            ack: Ack::read(buf)?,
            entries: Vec::<AcceptedEntry>::read_cfg(buf, &(RangeCfg::new(1..=MAX_ENTRIES), ()))?,
        })
    }
}

/// One custody deposit event retained by SQLite for settlement replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DepositEvent {
    pub(crate) id: Digest,
    pub(crate) account: Key,
    pub(crate) amount: u64,
}

impl Write for DepositEvent {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.account.write(buf);
        self.amount.write(buf);
    }
}

impl EncodeSize for DepositEvent {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.account.encode_size() + self.amount.encode_size()
    }
}

impl Read for DepositEvent {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            id: Digest::read(buf)?,
            account: Key::read(buf)?,
            amount: u64::read(buf)?,
        })
    }
}

/// Root-independent epoch authorization paired with its sealed boundary inputs.
#[derive(Clone)]
pub(crate) struct EpochRegistration {
    /// Deposit records the sealed boundary includes.
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) context: EpochContext<Key, Digest>,
}

/// Immutable root-independent input prepared for full-validator execution.
#[derive(Clone)]
pub(crate) struct PreparedEpoch {
    registration: EpochRegistration,
    encoded: Bytes,
    prepare_micros: u128,
}

impl PreparedEpoch {
    #[cfg(test)]
    pub(crate) const fn epoch(&self) -> u64 {
        self.registration.context.payment().epoch()
    }
    pub(crate) const fn context(&self) -> &EpochContext<Key, Digest> {
        &self.registration.context
    }
    pub(crate) const fn encoded(&self) -> &Bytes {
        &self.encoded
    }

    /// Validates a validator-certified close and reconstructs its retained claims.
    pub(crate) fn certify(
        &self,
        certified: CertifiedEpoch,
        deal_micros: u128,
        seal_micros: u128,
    ) -> Result<SettlementResult> {
        let close = certified.validate(&self.registration.context, &self.encoded)?;
        let verifier = bls12381::Scheme::verifier(committee()?);
        ensure!(
            verifier.verify_exact(&certified.header, &certified.certificate),
            "assembled certificate failed verification"
        );

        let withdrawal_claims = self
            .registration
            .withdrawals
            .requests()
            .iter()
            .enumerate()
            .map(|(position, request)| {
                let claim = close
                    .withdrawal_claim(request.account())
                    .context("assemble withdrawal claim")?;
                ensure!(
                    u32::try_from(position).ok() == Some(claim.position()),
                    "withdrawal claim has the wrong request position"
                );
                ensure!(
                    claim.output().destination() == request.body().destination(),
                    "withdrawal claim has the wrong request destination"
                );
                if let WithdrawalAction::Amount(amount) = request.body().action() {
                    ensure!(
                        claim.output().amount() == 0 || claim.output().amount() == amount.get(),
                        "withdrawal claim has the wrong requested amount"
                    );
                }
                Ok(claim)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(SettlementResult {
            context: certified.context,
            evidence: certified.evidence,
            withdrawals: self.registration.withdrawals.clone(),
            header: certified.header,
            roots: certified.roots,
            certificate: certified.certificate,
            withdrawal_total: certified.withdrawal_total,
            withdrawal_claims,
            rows: close.rows.len(),
            dealing_bytes: self.encoded.len(),
            prepare_micros: self.prepare_micros,
            deal_micros,
            seal_micros,
        })
    }
}

/// Validator-derived close artifacts bound to one certified dealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertifiedEpoch {
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) withdrawal_total: u64,
    pub(crate) evidence: Bytes,
    pub(crate) certificate: bls12381::Certificate,
}

impl CertifiedEpoch {
    /// Validates the certified artifacts against the exact registered context and proposal.
    pub(crate) fn validate(
        &self,
        expected_context: &EpochContext<Key, Digest>,
        expected_input: &Bytes,
    ) -> Result<Close<Key, Digest>> {
        ensure!(
            self.context.epoch_context() == expected_context,
            "certified close has the wrong registered context"
        );
        let close =
            Close::decode_evidence::<Sha256>(self.evidence.clone(), &self.context, &self.header)
                .context("validate certified close evidence")?;
        ensure!(
            close.header == self.header
                && close.roots == self.roots
                && close.withdrawal_total == self.withdrawal_total,
            "certified close artifacts disagree"
        );
        ensure!(
            close.encoded() == expected_input,
            "certified close has the wrong dealing"
        );
        Ok(close)
    }
}

/// Artifacts and metrics held through one clean finalization.
#[derive(Clone)]
pub(crate) struct SettlementResult {
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) evidence: Bytes,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) certificate: bls12381::Certificate,
    pub(crate) withdrawal_total: u64,
    pub(crate) withdrawal_claims: Vec<WithdrawalClaim<Digest>>,
    pub(crate) rows: usize,
    pub(crate) dealing_bytes: usize,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

impl Write for SettlementResult {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.evidence.write(buf);
        self.withdrawals.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.withdrawal_total.write(buf);
        self.certificate.write(buf);
        self.withdrawal_claims.write(buf);
        self.rows.write(buf);
        self.dealing_bytes.write(buf);
        self.prepare_micros.write(buf);
        self.deal_micros.write(buf);
        self.seal_micros.write(buf);
    }
}
impl EncodeSize for SettlementResult {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.evidence.encode_size()
            + self.withdrawals.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.withdrawal_total.encode_size()
            + self.certificate.encode_size()
            + self.withdrawal_claims.encode_size()
            + self.rows.encode_size()
            + self.dealing_bytes.encode_size()
            + self.prepare_micros.encode_size()
            + self.deal_micros.encode_size()
            + self.seal_micros.encode_size()
    }
}
impl Read for SettlementResult {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let context = CloseContext::read(buf)?;
        Ok(Self {
            context,
            evidence: Bytes::read_cfg(buf, &RangeCfg::new(0..=crate::rpc::MAX_BODY_SIZE))?,
            withdrawals: WithdrawalBatch::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_WITHDRAWALS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            withdrawal_total: u64::read(buf)?,
            certificate: bls12381::Certificate::read_cfg(buf, &VALIDATORS)?,
            withdrawal_claims: Vec::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_WITHDRAWALS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            rows: usize::read_cfg(buf, &RangeCfg::new(0..=MAX_ACTIVITY_ROWS))?,
            dealing_bytes: usize::read_cfg(buf, &RangeCfg::new(0..=crate::rpc::MAX_BODY_SIZE))?,
            prepare_micros: u128::read(buf)?,
            deal_micros: u128::read(buf)?,
            seal_micros: u128::read(buf)?,
        })
    }
}

/// One close the in-process simulation sealed for every quorum validator:
/// the material the harness serves validator evidence from, exactly what a
/// real validator retains (see [`crate::chain::da`]) with the bound context
/// the simulation held in memory.
pub(crate) struct RetainedClose {
    pub(crate) operations: u64,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) mutations: commonware_clearing::bajillion::qmdb::Mutations,
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) close: Arc<Close<Key, Digest>>,
}

/// Complete validated close evidence retained by the in-process committee simulation.
static RETAINED: Mutex<Vec<Arc<RetainedClose>>> = Mutex::new(Vec::new());

/// Snapshot of every close the in-process simulation retains.
pub(crate) fn retained_closes() -> Vec<Arc<RetainedClose>> {
    RETAINED.lock().clone()
}

#[derive(Clone)]
struct Validators {
    committee: Committee,
    private_keys: Vec<Private>,
}

impl Validators {
    fn new() -> Result<Self> {
        let mut validators = (0..VALIDATORS)
            .map(|index| {
                let offset = u64::try_from(index).expect("validator count fits in u64");
                let private = Private::new(Scalar::from(VALIDATOR_SEED_START + offset + 1));
                (compute_public::<MinSig>(&private), private)
            })
            .collect::<Vec<_>>();
        validators.sort_unstable_by_key(|(public, _)| *public);
        let committee = Committee::new(validators.iter().map(|(public, _)| *public).collect())
            .context("construct operator validator committee")?;
        ensure!(
            committee.quorum() == 3,
            "operator committee must have quorum 3"
        );
        Ok(Self {
            committee,
            private_keys: validators.into_iter().map(|(_, private)| private).collect(),
        })
    }

    /// The dealt signing scheme of one committee validator.
    ///
    /// Holding every committee key is the in-process simulation: only the
    /// deterministic harness and the fraud fixture seal through it. A real
    /// validator holds exactly its own [`clearing_private`] key.
    fn signer(&self, validator: Participant) -> Result<bls12381::Scheme> {
        let private = self
            .private_keys
            .get(usize::from(validator))
            .context("validator is not in the committee")?
            .clone();
        bls12381::Scheme::signer(self.committee.clone(), private)
            .context("construct operator validator signer")
    }
}

/// The default deployment digest: the compiled seed-1 operator's deployment.
///
/// The fixture and harness paths run this single deployment. The chain path
/// reads its configured deployment set from genesis instead.
pub(crate) fn deployment() -> Digest {
    deployment_of(&operator_key())
}

/// The clearing signing key of demo operator `index`.
///
/// Operator clearing keys are demo protocol constants like the wallet seeds:
/// setup writes operator `index`'s key into `operator-<index>/node.json` and
/// its public key into the genesis deployment list.
pub(crate) fn operator_signer(index: u64) -> SigningKey {
    SigningKey::from_seed(
        index
            .checked_add(1)
            .expect("the demo operator index fits the seed space"),
    )
}

pub(crate) fn operator_key() -> Key {
    operator_signer(0).public_key()
}

/// The aggregable-acknowledgment BLS signing key of demo operator `index`.
///
/// Deployment-fixed and dedicated like the operator clearing key: the close carries one
/// combined countersignature per complete close under this key, and validators verify the
/// aggregates against the public half committed in the genesis deployment list.
pub(crate) fn operator_ack_signer(index: u64) -> Private {
    Private::new(Scalar::from(
        OPERATOR_ACK_SEED_START
            .checked_add(index)
            .and_then(|seed| seed.checked_add(1))
            .expect("the demo operator index fits the seed space"),
    ))
}

pub(crate) fn operator_ack_key(index: u64) -> OperatorKey {
    compute_public::<OperatorVariant>(&operator_ack_signer(index))
}

/// One authenticated genesis balance allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Account {
    pub(crate) key: Key,
    pub(crate) balance: u64,
}

/// One deployment's identity, signing authorities, and initial account state.
/// The registry authenticates the identity within its chain's replay domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Deployment {
    digest: Digest,
    pub(crate) operator: Key,
    pub(crate) operator_ack: OperatorKey,
    /// Bootstrap allocations; any canonical key can receive credits or deposit later.
    pub(crate) accounts: Vec<Account>,
    genesis: Option<ConfiguredGenesis<Digest>>,
}

impl Deployment {
    pub(crate) const fn new(
        digest: Digest,
        operator: Key,
        operator_ack: OperatorKey,
        accounts: Vec<Account>,
    ) -> Self {
        Self {
            digest,
            genesis: None,
            operator,
            operator_ack,
            accounts,
        }
    }

    /// Generate the trusted configuration commitment through native batch preparation.
    /// Setup and deterministic fixtures own this temporary database; followers read the result.
    pub(crate) async fn generate<E>(&mut self, context: E) -> Result<()>
    where
        E: commonware_storage::Context + commonware_runtime::Spawner,
    {
        let config = state_config(
            &format!("setup-genesis-{}", self.digest),
            &context,
            commonware_parallel::Sequential,
        );
        let state = State::<_, Sha256>::open(context, config).await?;
        ensure!(
            state.is_bootstrap(),
            "genesis generation requires fresh storage"
        );
        let candidate = state
            .prepare(
                state.head(),
                genesis_balances(self)?
                    .into_iter()
                    .map(|(key, balance)| (key, Some(balance)))
                    .collect(),
            )
            .await?;
        self.genesis = Some(ConfiguredGenesis::from(candidate.head()));
        Ok(())
    }

    pub(crate) fn configured(
        digest: Digest,
        operator: Key,
        operator_ack: OperatorKey,
        accounts: Vec<Account>,
        root: StateRoot<Digest>,
        operations: u64,
    ) -> Result<Self> {
        let mut deployment = Self::new(digest, operator, operator_ack, accounts);
        deployment.genesis = Some(ConfiguredGenesis::new(
            root,
            operations,
            &genesis_balances(&deployment)?,
        )?);
        Ok(deployment)
    }

    /// Binds setup's generated commitment to its complete network identity.
    pub(crate) const fn rebind(&mut self, digest: Digest) {
        self.digest = digest;
    }

    pub(crate) const fn genesis(&self) -> &ConfiguredGenesis<Digest> {
        self.genesis
            .as_ref()
            .expect("genesis configured before chain execution")
    }

    /// The deployment's chain-scoped identity.
    pub(crate) const fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// Canonical genesis account mutations shared by every balance replica.
pub(crate) fn genesis_balances(
    deployment: &Deployment,
) -> Result<Vec<(commonware_clearing::bajillion::qmdb::AccountKey, NonZeroU64)>> {
    let mut balances = deployment
        .accounts
        .iter()
        .map(|account| {
            Ok((
                commonware_clearing::bajillion::qmdb::account_key(&account.key)?,
                NonZeroU64::new(account.balance),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    balances.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    ensure!(
        balances.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "duplicate genesis account"
    );
    Ok(balances
        .into_iter()
        .filter_map(|(key, balance)| balance.map(|balance| (key, balance)))
        .collect())
}

/// Partitions for the single account QMDB and its retained historical proofs.
pub(crate) fn state_config<S: commonware_parallel::Strategy>(
    prefix: &str,
    pooler: &impl commonware_runtime::BufferPooler,
    strategy: S,
) -> commonware_clearing::bajillion::qmdb::Config<S> {
    let page_cache = CacheRef::from_pooler(
        pooler,
        crate::chain::validator::PAGE_SIZE,
        crate::chain::validator::PAGE_CACHE_SIZE,
    );
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle"),
            metadata_partition: format!("{prefix}-metadata"),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(65536),
            replay_buffer: NZUsize!(65536),
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-journal"),
            items_per_blob: NZU64!(4096),
            page_cache,
            write_buffer: NZUsize!(65536),
            replay_buffer: NZUsize!(65536),
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(2097152),
        init_concurrency: (),
    }
}

impl Write for Account {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.balance.write(buf);
    }
}

impl EncodeSize for Account {
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.balance.encode_size()
    }
}

impl Read for Account {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            key: Key::read(buf)?,
            balance: u64::read(buf)?,
        })
    }
}

impl Write for Deployment {
    fn write(&self, buf: &mut impl BufMut) {
        self.digest.write(buf);
        self.operator.write(buf);
        self.operator_ack.write(buf);
        self.accounts.write(buf);
        self.genesis().root().write(buf);
        self.genesis().operations().write(buf);
    }
}

impl EncodeSize for Deployment {
    fn encode_size(&self) -> usize {
        self.digest.encode_size()
            + self.operator.encode_size()
            + self.operator_ack.encode_size()
            + self.accounts.encode_size()
            + self.genesis().root().encode_size()
            + self.genesis().operations().encode_size()
    }
}

impl Read for Deployment {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Self::configured(
            Digest::read(buf)?,
            Key::read(buf)?,
            OperatorKey::read(buf)?,
            Vec::<Account>::read_cfg(buf, &(RangeCfg::new(0..=MAX_GENESIS_ACCOUNTS), ()))?,
            StateRoot::read(buf)?,
            u64::read(buf)?,
        )
        .map_err(|_| CodecError::Invalid("Deployment", "invalid genesis configuration"))
    }
}

/// Generates the trusted empty account commitment for runtime deployment creation.
pub(crate) async fn empty_genesis<E>(context: E) -> Result<ConfiguredGenesis<Digest>>
where
    E: commonware_storage::Context + commonware_runtime::Spawner,
{
    let config = state_config(
        "setup-empty-genesis",
        &context,
        commonware_parallel::Sequential,
    );
    let state = State::<_, Sha256>::open(context, config).await?;
    ensure!(
        state.is_bootstrap(),
        "empty genesis generation requires fresh storage"
    );
    let candidate = state.prepare(state.head(), Vec::new()).await?;
    Ok(ConfiguredGenesis::from(candidate.head()))
}

/// The compiled demo account set: the four wallets at the initial balance,
/// which setup writes into every generated deployment's genesis.
pub(crate) fn accounts() -> Vec<Account> {
    identities()
        .into_iter()
        .map(|identity| Account {
            key: identity.key,
            balance: INITIAL_BALANCE,
        })
        .collect()
}

/// The compiled default deployment set: the seed-1 operator alone, the
/// configuration the fixture and harness paths run under.
pub(crate) fn deployments() -> Vec<Deployment> {
    vec![Deployment::new(
        deployment(),
        operator_key(),
        operator_ack_key(0),
        accounts(),
    )]
}

/// Digest committing to the whole configured deployment set in genesis
/// order: the chain identity the genesis block's parent field carries.
pub(crate) fn chain_id<'a>(deployments: impl IntoIterator<Item = &'a Deployment>) -> Digest {
    let digests = deployments
        .into_iter()
        .map(|deployment| deployment.digest().as_ref())
        .collect::<Vec<_>>();
    Sha256::hash(&digests)
}

/// The chain registration message: the named deployment plus exactly the
/// boundary material the operator legitimately chooses, so the signature
/// binds the deployment it registers under. The deadlines are not part of it
/// because execution assigns them at the inclusion height.
fn chain_registration_message(
    deployment: &Digest,
    epoch: u64,
    predecessor_liability: u64,
    deposits_root: &VectorRoot<Digest>,

    withdrawals: &WithdrawalBatch<Key, Digest>,
    fee: u64,
) -> Bytes {
    let mut message = BytesMut::with_capacity(
        deployment.encode_size()
            + epoch.encode_size()
            + predecessor_liability.encode_size()
            + deposits_root.encode_size()
            + withdrawals.encode_size()
            + fee.encode_size(),
    );
    deployment.write(&mut message);
    epoch.write(&mut message);
    predecessor_liability.write(&mut message);
    deposits_root.write(&mut message);

    withdrawals.write(&mut message);
    fee.write(&mut message);
    message.freeze()
}

/// Verifies a chain registration against one configured deployment: the
/// signature must be the deployment's operator's, over a message naming the
/// deployment's own digest.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_chain_registration_signature(
    deployment: &Deployment,
    epoch: u64,
    predecessor_liability: u64,
    deposits_root: &VectorRoot<Digest>,

    withdrawals: &WithdrawalBatch<Key, Digest>,
    fee: u64,
    signature: &Signature,
) -> bool {
    deployment.operator.verify(
        CHAIN_REGISTRATION_SIGNATURE_NAMESPACE,
        &chain_registration_message(
            deployment.digest(),
            epoch,
            predecessor_liability,
            deposits_root,
            withdrawals,
            fee,
        ),
        signature,
    )
}

pub(crate) fn committee() -> Result<Committee> {
    Ok(Validators::new()?.committee)
}

/// The clearing committee BLS private key dealt to validator `index`.
///
/// The clearing committee is the same machines as the consensus committee
/// under separate key material: these fixed seeded keys are demo protocol
/// constants like the wallet seeds, distributed to the validator directories
/// by setup and committed to genesis state through [`committee`].
pub(crate) fn clearing_private(index: usize) -> Result<Private> {
    ensure!(index < VALIDATORS, "index is not a clearing validator");
    let offset = u64::try_from(index).context("validator index fits in u64")?;
    Ok(Private::new(Scalar::from(
        VALIDATOR_SEED_START + offset + 1,
    )))
}

/// Committee participant index of the clearing key dealt to validator `index`.
///
/// Setup deals key `index` to validator directory `index`, but the committee
/// orders participants by public key, so the two indices differ in general.
pub(crate) fn dealt_participant(index: usize) -> Result<Participant> {
    let committee = committee()?;
    let public = compute_public::<MinSig>(&clearing_private(index)?);
    committee
        .index_of(&public)
        .context("dealt key is not in the clearing committee")
}

/// The anchor-bound close resource limits shared by every epoch context.
pub(crate) const fn limits() -> CloseLimits {
    // Every live account holds at least one unit, so the monetary bound also bounds
    // lifetime membership. Per-close work is bounded independently by accepted activity.
    CloseLimits::new(
        SQLITE_U64_MAX,
        MAX_ACTIVITY_ROWS as u64,
        MAX_WITHDRAWALS as u64,
        MAX_ACCEPTED_PAYMENTS as u64,
        MAX_ACCEPTED_PAYMENTS as u64,
        SQLITE_U64_MAX,
        SQLITE_U64_MAX,
        SQLITE_U64_MAX,
    )
}

/// Settlement chain configuration under `timing`.
///
/// The chain's own epoch deadline policy is derived from the genesis-fixed
/// timing: the admission delay mirrors the stride shape (offset plus duration
/// plus one) so pipelined admission monotonicity keeps its one-block slack,
/// and the challenge duration is exact. Execution assigns registration
/// deadlines from the inclusion height ([`crate::chain::state`]), so the
/// assigned instances satisfy this policy by construction.
pub(crate) fn settlement_config(timing: &Timing) -> Result<SettlementConfig> {
    let delay = timing
        .admission_offset
        .checked_add(timing.challenge_duration)
        .and_then(|delay| delay.checked_add(1))
        .context("the deployment timing policy exceeds the epoch clock")?;
    ensure!(
        timing.admission_offset > 0,
        "admission offset must be positive"
    );
    let challenge = NonZeroU64::new(timing.challenge_duration)
        .context("challenge duration must be positive")?;
    // Native deadlines overlap. Notice covers admission of the current epoch and
    // finalization of the successor carrying the withdrawal, with inclusion slack.
    let minimum_notice = delay
        .checked_add(2)
        .and_then(|notice| notice.checked_add(delay.saturating_sub(3)))
        .context("withdrawal notice exceeds the epoch clock")?;
    let maximum_notice = minimum_notice
        .checked_add(100)
        .context("withdrawal horizon exceeds the epoch clock")?;
    Ok(SettlementConfig::new(
        EpochDeadlinePolicy::new(
            NonZeroU64::new(delay).expect("admission delay is nonzero"),
            challenge,
            challenge,
        ),
        NonZeroU64::new(DEPOSIT_INCLUSION_TIMEOUT).expect("deposit timeout is nonzero"),
        NonZeroU64::new(minimum_notice).expect("notice is nonzero"),
        NonZeroU64::new(maximum_notice).expect("notice is nonzero"),
        256,
        NonZeroUsize::new(MAX_DEPOSIT_EVENTS).expect("deposit bound is nonzero"),
    ))
}

#[cfg(test)]
pub(crate) fn epoch_context(
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    predecessor_liability: u64,
) -> Result<EpochContext<Key, Digest>> {
    let (admission_deadline, challenge_deadline) = deadlines(epoch)?;
    epoch_context_at(
        deployment(),
        operator_key(),
        epoch,
        deposits,
        withdrawals,
        predecessor_liability,
        admission_deadline,
        challenge_deadline,
    )
}

/// Builds the epoch context for explicit absolute deadlines: the
/// chain-assigned block-height deadlines execution derives from a
/// registration's inclusion height, and the deadlines an operator adopts
/// from the certified registration record. Pre-registration placeholder
/// contexts derive deterministic grid deadlines through
/// [`Protocol::registration`] instead.
#[allow(clippy::too_many_arguments)]
pub(crate) fn epoch_context_at(
    deployment: Digest,
    operator: Key,
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    predecessor_liability: u64,
    admission_deadline: u64,
    challenge_deadline: u64,
) -> Result<EpochContext<Key, Digest>> {
    let limits = limits();
    EpochContext::new::<Sha256>(
        deployment,
        epoch,
        operator,
        deposits,
        withdrawals,
        predecessor_liability,
        admission_deadline,
        challenge_deadline,
        limits,
        committee()?.commitment::<Sha256>(),
    )
    .context("construct epoch context")
}

/// Shared cryptographic and parallel machinery for every operator action.
#[derive(Clone)]
pub(crate) struct Protocol {
    deployment: Digest,
    operator: SigningKey,
    operator_ack: Private,
    operator_ack_key: OperatorKey,
    validators: Validators,
    strategy: Rayon,
}

impl Protocol {
    /// Protocol machinery for the compiled default deployment (the seed-1
    /// demo operator): the fixture and harness path.
    pub(crate) fn new(workers: NonZeroUsize) -> Result<Self> {
        Self::with_signer(
            workers,
            deployment(),
            operator_signer(0),
            operator_ack_signer(0),
        )
    }

    /// Protocol machinery bound to a registered deployment and its signing keys.
    pub(crate) fn with_signer(
        workers: NonZeroUsize,
        deployment: Digest,
        operator: SigningKey,
        operator_ack: Private,
    ) -> Result<Self> {
        Ok(Self {
            deployment,
            operator,
            operator_ack_key: compute_public::<OperatorVariant>(&operator_ack),
            operator_ack,
            validators: Validators::new()?,
            strategy: Rayon::new(workers).context("create clearing worker pool")?,
        })
    }

    /// The operator's aggregable-acknowledgment public key.
    pub(crate) const fn operator_ack_key(&self) -> &OperatorKey {
        &self.operator_ack_key
    }

    /// Countersigns one accepted endpoint body for the close's complete-close aggregate.
    pub(crate) fn sign_ack_aggregate(
        &self,
        body: &VectorSendBody<Key, Digest>,
    ) -> OperatorSignature {
        sign_message::<OperatorVariant>(
            &self.operator_ack,
            commonware_clearing::bajillion::payment::VECTOR_ACK_AGGREGATE_NAMESPACE,
            body.encode().as_ref(),
        )
    }

    pub(crate) const fn strategy(&self) -> &Rayon {
        &self.strategy
    }

    pub(crate) const fn deployment(&self) -> Digest {
        self.deployment
    }

    pub(crate) const fn operator(&self) -> &SigningKey {
        &self.operator
    }

    /// Signs a chain registration over exactly the boundary material.
    /// Execution assigns the deadlines at the inclusion height, so the
    /// signature commits nothing about timing.
    pub(crate) fn sign_chain_registration(
        &self,
        epoch: u64,
        predecessor_liability: u64,
        deposits_root: &VectorRoot<Digest>,

        withdrawals: &WithdrawalBatch<Key, Digest>,
        fee: u64,
    ) -> Signature {
        self.operator.sign(
            CHAIN_REGISTRATION_SIGNATURE_NAMESPACE,
            &chain_registration_message(
                &self.deployment,
                epoch,
                predecessor_liability,
                deposits_root,
                withdrawals,
                fee,
            ),
        )
    }

    pub(crate) fn registration(
        &self,
        epoch: u64,
        staged: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
        predecessor_liability: u64,
    ) -> Result<EpochRegistration> {
        let (admission_deadline, challenge_deadline) = deadlines(epoch)?;
        self.registration_at(
            epoch,
            staged,
            withdrawals,
            predecessor_liability,
            admission_deadline,
            challenge_deadline,
        )
    }

    /// Builds a registration for explicit absolute deadlines, the registered
    /// path: the chain assigns the deadlines at inclusion and the operator
    /// adopts them from the certified registration record.
    /// [`Self::registration`] instead derives deterministic placeholder grid
    /// deadlines for contexts that have not registered on the chain yet.
    pub(crate) fn registration_at(
        &self,
        epoch: u64,
        staged: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
        predecessor_liability: u64,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> Result<EpochRegistration> {
        let deposits = staged;
        let context = epoch_context_at(
            self.deployment,
            self.operator.public_key(),
            epoch,
            &deposits,
            &withdrawals,
            predecessor_liability,
            admission_deadline,
            challenge_deadline,
        )?;
        ensure!(
            context.deployment() == &self.deployment
                && context.payment().operator() == &self.operator.public_key()
                && context.committee() == &self.validators.committee.commitment::<Sha256>(),
            "operator protocol configuration drifted"
        );
        Ok(EpochRegistration {
            deposits,
            withdrawals,
            context,
        })
    }

    pub(crate) fn prepare(
        &self,
        registration: EpochRegistration,
        terminals: Vec<Terminal<Key, Digest>>,
    ) -> Result<PreparedEpoch> {
        let started = Instant::now();
        let dealing = prepare_dealing::<Sha256, _, _>(
            &registration.context,
            &registration.deposits,
            &registration.withdrawals,
            terminals,
        )
        .context("prepare dealing")?;
        Ok(PreparedEpoch {
            registration,
            encoded: dealing.encoded().clone(),
            prepare_micros: started.elapsed().as_micros(),
        })
    }

    /// Verify-only clearing scheme over the fixed committee, for vote and
    /// certificate verification.
    #[cfg(test)]
    pub(crate) fn verifier(&self) -> bls12381::Scheme {
        bls12381::Scheme::verifier(self.validators.committee.clone())
    }

    /// Completes one prepared close in process, simulating every committee
    /// validator with its dealt key, for the deterministic harness and the
    /// fraud fixture. The operator binary certifies over the settlement DA
    /// channel and completes with [`PreparedEpoch::certify`] instead.
    pub(crate) async fn complete<E, R: CryptoRng>(
        &self,
        epoch: PreparedEpoch,
        state: &State<E, Sha256, Rayon>,
        rng: &mut R,
    ) -> Result<(SettlementResult, PreparedState<Digest, Rayon>)>
    where
        E: commonware_storage::Context + commonware_runtime::Spawner,
    {
        self.complete_with_strategy(epoch, state, rng, &self.strategy)
            .await
    }

    async fn complete_with_strategy<E, R, S>(
        &self,
        epoch: PreparedEpoch,
        state: &State<E, Sha256, S>,
        rng: &mut R,
        strategy: &S,
    ) -> Result<(SettlementResult, PreparedState<Digest, S>)>
    where
        E: commonware_storage::Context + commonware_runtime::Spawner,
        R: CryptoRng,
        S: commonware_parallel::Strategy,
    {
        let started = Instant::now();
        let context = epoch
            .registration
            .context
            .clone()
            .bind::<Sha256, _, _>(
                state,
                &epoch.registration.deposits,
                &epoch.registration.withdrawals,
            )
            .context("bind close to validator state")?;
        let mut votes = Vec::<Vote>::new();
        let mut validated = None;
        for index in 0..self.validators.committee.quorum() {
            let scheme = self.validators.signer(Participant::from_usize(index))?;
            let (vote, candidate) = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                &scheme,
                state,
                &context,
                &self.operator_ack_key,
                &epoch.registration.deposits,
                &epoch.registration.withdrawals,
                epoch.encoded().clone(),
                rng,
                strategy,
            )
            .await
            .context("validate complete dealing")?;
            if validated.is_none() {
                validated = Some(candidate);
            }
            votes.push(vote);
        }
        let certificate = self
            .validators
            .signer(Participant::new(0))?
            .assemble_exact(votes)
            .context("assemble exact-quorum certificate")?;
        let (close, candidate) = validated.expect("nonempty quorum").into_parts();
        let certified = CertifiedEpoch {
            context: context.clone(),
            header: close.header,
            roots: close.roots,
            withdrawal_total: close.withdrawal_total,
            evidence: close.encode_evidence(),
            certificate,
        };
        let retained = RetainedClose {
            operations: candidate.head().operations(),
            deposits: epoch.registration.deposits.clone(),
            withdrawals: epoch.registration.withdrawals.clone(),
            mutations: candidate.mutations().to_vec(),
            context,
            header: close.header,
            roots: close.roots,
            close: Arc::new(close),
        };
        let result = epoch.certify(certified, 0, started.elapsed().as_micros())?;
        RETAINED.lock().push(Arc::new(retained));
        Ok((result, candidate))
    }

    /// Derives the configured genesis commitment through an isolated validator replica.
    #[cfg(test)]
    pub(crate) fn fixture_genesis(
        &self,
        accounts: &[Account],
    ) -> Result<ConfiguredGenesis<Digest>> {
        use commonware_runtime::Runner as _;

        let protocol = self.clone();
        let accounts = accounts.to_vec();
        commonware_runtime::deterministic::Runner::default().start(move |context| async move {
            let state = fixture_state(context, &protocol, &accounts, &[]).await?;
            Ok(ConfiguredGenesis::from(state.head()))
        })
    }

    /// Runs one prepared close through an isolated deterministic validator replica.
    #[cfg(test)]
    pub(crate) fn fixture_complete(
        &self,
        accounts: &[Account],
        history: &[SettlementResult],
        prepared: PreparedEpoch,
        seed: u64,
    ) -> Result<SettlementResult> {
        use commonware_runtime::Runner as _;

        let protocol = self.clone();
        let accounts = accounts.to_vec();
        let history = history.to_vec();
        commonware_runtime::deterministic::Runner::default().start(move |context| async move {
            let state = fixture_state(context, &protocol, &accounts, &history).await?;
            let (result, _) = protocol
                .complete_with_strategy(
                    prepared,
                    &state,
                    &mut commonware_utils::TestRng::new(seed),
                    &Sequential,
                )
                .await?;
            Ok(result)
        })
    }

    /// Opens one account from the validator state reconstructed through certified history.
    #[cfg(test)]
    pub(crate) fn fixture_opening(
        &self,
        accounts: &[Account],
        history: &[SettlementResult],
        account: &Key,
    ) -> Result<commonware_clearing::bajillion::qmdb::StateOpening<Key, Digest>> {
        use commonware_runtime::Runner as _;

        let protocol = self.clone();
        let accounts = accounts.to_vec();
        let history = history.to_vec();
        let account = account.clone();
        commonware_runtime::deterministic::Runner::default().start(move |context| async move {
            let state = fixture_state(context, &protocol, &accounts, &history).await?;
            state.opening(account).await.context("open fixture account")
        })
    }
}

#[cfg(test)]
async fn fixture_state<E>(
    context: E,
    protocol: &Protocol,
    accounts: &[Account],
    history: &[SettlementResult],
) -> Result<State<E, Sha256>>
where
    E: commonware_storage::Context + commonware_runtime::Spawner + commonware_runtime::BufferPooler,
{
    let config = state_config("fixture-validator", &context, Sequential);
    let mut state = State::<_, Sha256>::open(context, config).await?;
    ensure!(
        state.is_bootstrap(),
        "fixture validator storage is not fresh"
    );
    let deployment = Deployment::new(
        protocol.deployment,
        protocol.operator.public_key(),
        protocol.operator_ack_key,
        accounts.to_vec(),
    );
    let candidate = state
        .prepare(
            state.head(),
            genesis_balances(&deployment)?
                .into_iter()
                .map(|(key, balance)| (key, Some(balance)))
                .collect(),
        )
        .await?;
    state = state.apply(candidate).await?.commit().await?;

    for (expected_epoch, result) in history.iter().enumerate() {
        ensure!(
            usize::try_from(result.context.payment().epoch()).ok() == Some(expected_epoch),
            "fixture validator history is not contiguous"
        );
        ensure!(
            result.context.deployment() == &protocol.deployment
                && result.context.payment().operator() == &protocol.operator.public_key()
                && result.context.committee()
                    == &protocol.validators.committee.commitment::<Sha256>()
                && result.context.predecessor_root() == &state.root()
                && result.context.predecessor_liability() == state.liability(),
            "fixture validator history has the wrong predecessor or deployment"
        );
        let close = Close::decode_evidence::<Sha256>(
            result.evidence.clone(),
            &result.context,
            &result.header,
        )
        .context("decode fixture validator history")?;
        ensure!(
            close.header == result.header
                && close.roots == result.roots
                && close.withdrawal_total == result.withdrawal_total,
            "fixture validator history artifacts disagree"
        );
        ensure!(
            protocol
                .verifier()
                .verify_exact(&result.header, &result.certificate),
            "fixture validator history certificate is invalid"
        );
        let mutations = close
            .rows
            .iter()
            .map(|row| {
                Ok((
                    commonware_clearing::bajillion::qmdb::account_key(&row.account)?,
                    NonZeroU64::new(row.successor),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let prepared = state.prepare(state.head(), mutations).await?;
        ensure!(
            prepared.root() == result.roots.successor,
            "fixture validator mutations differ from certified history"
        );
        state = state.apply(prepared).await?.commit().await?;
    }
    Ok(state)
}

/// The deterministic placeholder grid pair for `epoch`, from the compiled
/// default geometry. Pre-registration staging and the fixture harness run on
/// this grid: a registered epoch adopts the chain-assigned deadlines instead.
fn deadlines(epoch: u64) -> Result<(u64, u64)> {
    let base = epoch_start(epoch)?;
    Ok((
        base.checked_add(ADMISSION_OFFSET)
            .context("admission deadline overflow")?,
        base.checked_add(CHALLENGE_OFFSET)
            .context("challenge deadline overflow")?,
    ))
}

pub(crate) fn epoch_start(epoch: u64) -> Result<u64> {
    epoch
        .checked_mul(EPOCH_STRIDE)
        .context("epoch clock overflow")
}

fn openable_epoch_at_offset(epoch: u64, offset: u64) -> Result<u64> {
    let candidate = epoch.checked_add(offset).context("epoch overflow")?;
    deadlines(candidate).context("required epoch clock overflow")?;
    Ok(candidate)
}

/// Returns the successor when its epoch context can be represented.
pub(crate) fn openable_epoch_after(epoch: u64) -> Result<u64> {
    openable_epoch_at_offset(epoch, 1)
}

/// Ensures work that can leave a balance has time to close and later exit.
pub(crate) fn ensure_balance_intake_horizon(epoch: u64) -> Result<()> {
    openable_epoch_at_offset(epoch, 3).map(drop)
}

/// Ensures a withdrawal can close while retaining one successor for residual state.
pub(crate) fn ensure_amount_withdrawal_horizon(epoch: u64) -> Result<()> {
    openable_epoch_at_offset(epoch, 2).map(drop)
}

/// Ensures an amountless close can reach finalization.
pub(crate) fn ensure_close_horizon(epoch: u64) -> Result<()> {
    openable_epoch_at_offset(epoch, 1).map(drop)
}

pub(crate) fn short_digest(digest: &Digest) -> String {
    digest
        .as_ref()
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A committed close that omits one receiver's credit, plus that receiver's held receipt.
///
/// This is the demo's fraud construction, kept out of the honest operator binary. The close
/// credits a deposit to a bystander account, so the paying sender is absent from its change
/// vector, mirroring how the challenge tests build an inconsistent close. The held receipt is
/// a valid operator-acknowledged entry crediting the receiver under the same epoch context,
/// so it convicts the close with a `HigherAckEntry` challenge.
pub(crate) struct OmittingClose {
    pub(crate) result: SettlementResult,
    pub(crate) receiver: Key,
    pub(crate) held_credit: u64,
    pub(crate) held_receipt: Receipt,
    pub(crate) held_lookup: HigherEntryLookup<Key, Digest>,
}

/// The omitting close's boundary: the bystander deposit event and its
/// canonical batch, exposed so the fraud arcs can register the boundary on
/// the chain and learn the assigned deadlines before building the close.
pub(crate) fn omitting_boundary() -> Result<(DepositEvent, DepositBatch<Key>)> {
    let bystander = wallets()[2].public_key();
    let deposit = DepositEvent {
        id: Sha256::hash(&[b"_COMMONWARE_EXAMPLES_TERMINAL_OMITTING_CLOSE"]),
        account: bystander.clone(),
        amount: 1,
    };
    let deposits = DepositBatch::new(vec![DepositRecord::new(bystander, 1)?])?;
    Ok((deposit, deposits))
}

/// Builds an omitting close over epoch 0 at explicit absolute deadlines (the
/// chain-assigned pair read back from the registered record): Alice's
/// operator-signed receipt credits Bob, but the admitted close instead
/// credits a deposit to Carol and omits Bob entirely.
pub(crate) async fn omitting_close<E, R: CryptoRng>(
    state: State<E, Sha256, Rayon>,
    rng: &mut R,
    admission_deadline: u64,
    challenge_deadline: u64,
) -> Result<OmittingClose>
where
    E: commonware_storage::Context + commonware_runtime::Spawner,
{
    let protocol = Protocol::new(NonZeroUsize::MIN)?;
    let wallets = wallets();
    let payer = &wallets[0];
    let receiver = wallets[1].public_key();
    let held_credit = 5;

    let (_, deposits) = omitting_boundary()?;
    let registration = protocol.registration_at(
        0,
        deposits,
        WithdrawalBatch::empty(),
        400,
        admission_deadline,
        challenge_deadline,
    )?;
    let prepared = protocol.prepare(registration, Vec::new())?;
    let (result, candidate) = protocol.complete(prepared, &state, rng).await?;
    let close =
        Close::decode_evidence::<Sha256>(result.evidence.clone(), &result.context, &result.header)
            .context("decode the omitting close")?;

    // The omitting close excludes the paying sender entirely, so its composed lookup is an
    // ordered change-vector absence and the public terminal entry resolves to zero.
    let index = ChallengeIndex::new::<Sha256>(&result.context, &close)
        .context("index the omitting close")?;
    let held_lookup =
        higher_entry_lookup::<Sha256, _, _>(&index, &payer.public_key(), None, &receiver)
            .context("compose the omitted sender lookup")?;
    let _state = state.apply(candidate).await?.commit().await?;
    let context = result.context.payment().clone();

    // The receiver holds an operator-acknowledged entry crediting it under the same epoch
    // context, opened under the acknowledged vector root.
    let out_vector = OutVector::new(
        context.epoch(),
        payer.public_key(),
        vec![OutEntry {
            recipient: receiver.clone(),
            cumulative: held_credit,
            count: 1,
        }],
    )
    .context("build the omitted receiver's out vector")?;
    let body = VectorSendBody::new(
        &context,
        payer.public_key(),
        1,
        held_credit,
        out_vector
            .root::<Sha256, Digest>()
            .context("commit the omitted receiver's out vector")?,
    );
    let ack = Ack::sign_by_authorities(body, payer.signer(), protocol.operator());
    let opening = match out_vector
        .lookup::<Sha256, Digest>(&receiver)
        .context("open the omitted receiver's entry")?
    {
        OutTipLookup::Present { opening, .. } => opening,
        OutTipLookup::Absent { .. } => anyhow::bail!("the held entry is present by construction"),
    };
    Ok(OmittingClose {
        result,
        receiver,
        held_credit,
        held_receipt: EntryReceipt {
            ack,
            recipient: wallets[1].public_key(),
            cumulative: held_credit,
            count: 1,
            opening,
        },
        held_lookup,
    })
}

pub(crate) fn encoded_artifacts(result: &SettlementResult) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        result.header.encode().to_vec(),
        result.roots.encode().to_vec(),
        result.certificate.encode().to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_clearing::bajillion::{payment::SendAuthorization, qmdb::account_key};
    use commonware_codec::DecodeExt as _;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::TestRng;

    fn certified(result: &SettlementResult) -> CertifiedEpoch {
        CertifiedEpoch {
            context: result.context.clone(),
            header: result.header,
            roots: result.roots,
            withdrawal_total: result.withdrawal_total,
            evidence: result.evidence.clone(),
            certificate: result.certificate.clone(),
        }
    }

    #[test]
    fn fixture_replay_uses_certified_successor_root() {
        let protocol = Protocol::new(NonZeroUsize::new(2).unwrap()).unwrap();
        let wallet = wallets().remove(0);
        let account = Account {
            key: wallet.public_key(),
            balance: 10,
        };
        let genesis = protocol
            .fixture_genesis(std::slice::from_ref(&account))
            .unwrap();
        let request = SignedWithdrawal::sign(
            deployment(),
            genesis.root().digest,
            wallet.public_key().encode(),
            WithdrawalAction::Amount(NonZeroU64::MIN),
            50,
            wallet.signer(),
        );
        let registration = protocol
            .registration(
                0,
                DepositBatch::empty(),
                WithdrawalBatch::new(vec![request]).unwrap(),
                genesis.liability(),
            )
            .unwrap();
        let prepared = protocol.prepare(registration, Vec::new()).unwrap();
        let result = protocol
            .fixture_complete(std::slice::from_ref(&account), &[], prepared, 31)
            .unwrap();
        assert_eq!(
            protocol
                .fixture_opening(
                    std::slice::from_ref(&account),
                    std::slice::from_ref(&result),
                    &account.key,
                )
                .unwrap()
                .balance
                .get(),
            9
        );

        let mut poisoned = result;
        let mut close = Close::decode_evidence::<Sha256>(
            poisoned.evidence.clone(),
            &poisoned.context,
            &poisoned.header,
        )
        .unwrap();
        let row = close
            .rows
            .iter_mut()
            .find(|row| row.account == account.key)
            .unwrap();
        row.successor = row.successor.checked_add(1).unwrap();
        poisoned.evidence = close.encode_evidence();
        assert!(
            protocol
                .fixture_opening(std::slice::from_ref(&account), &[poisoned], &account.key,)
                .is_err()
        );
    }

    #[test]
    fn certification_retains_an_unfunded_amount_withdrawal_as_zero() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let wallet = wallets().remove(0);
            let config = state_config("zero-withdrawal", &context, protocol.strategy().clone());
            let state = State::<_, Sha256, Rayon>::open(context, config)
                .await
                .unwrap();
            let candidate = state
                .prepare(
                    state.head(),
                    vec![(
                        account_key(&wallet.public_key()).unwrap(),
                        NonZeroU64::new(10),
                    )],
                )
                .await
                .unwrap();
            let state = state
                .apply(candidate)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
            let request = SignedWithdrawal::sign(
                deployment(),
                state.root().digest,
                wallet.public_key().encode(),
                WithdrawalAction::Amount(NonZeroU64::new(10).unwrap()),
                50,
                wallet.signer(),
            );
            let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
            let registration = protocol
                .registration(0, DepositBatch::empty(), withdrawals, state.liability())
                .unwrap();
            let vector = OutVector::new(
                0,
                wallet.public_key(),
                vec![OutEntry {
                    recipient: eve_wallet().public_key(),
                    cumulative: 1,
                    count: 1,
                }],
            )
            .unwrap();
            let body = VectorSendBody::new(
                registration.context.payment(),
                wallet.public_key(),
                1,
                1,
                vector.root::<Sha256, Digest>().unwrap(),
            );
            let terminal = Terminal {
                operator_signature: protocol.sign_ack_aggregate(&body),
                authorization: SendAuthorization::sign(body, wallet.signer()),
                vector,
            };
            let prepared = protocol.prepare(registration, vec![terminal]).unwrap();
            let certification_input = prepared.clone();
            let (result, successor) = protocol
                .complete(prepared, &state, &mut TestRng::new(29))
                .await
                .expect("an authenticated zero release remains certifiable");
            assert_eq!(result.withdrawal_claims.len(), 1);
            let claim = result.withdrawal_claims[0].clone();
            assert_eq!(claim.output().amount(), 0);
            assert_eq!(successor.head().liability(), 10);
            let encoded = result.encode();
            assert_eq!(
                SettlementResult::decode(encoded.clone()).unwrap().encode(),
                encoded
            );
            let witness = WithdrawalWitness::new(
                &result.context,
                result.withdrawal_total,
                &result.withdrawals,
                claim,
            )
            .unwrap();
            assert_eq!(witness.request, request);
            assert_eq!(
                WithdrawalWitness::decode(witness.encode()).unwrap(),
                witness
            );
            assert_eq!(
                witness
                    .verify(
                        &result.roots,
                        &deployment(),
                        &wallet.public_key(),
                        wallet.public_key().as_ref()
                    )
                    .unwrap(),
                result.header.batch_id::<Sha256>(),
            );

            let alternate_registration = protocol
                .registration(
                    0,
                    DepositBatch::empty(),
                    WithdrawalBatch::new(vec![request]).unwrap(),
                    state.liability(),
                )
                .unwrap();
            let alternate = protocol
                .prepare(alternate_registration, Vec::new())
                .unwrap();
            let (alternate, _) = protocol
                .complete(alternate, &state, &mut TestRng::new(30))
                .await
                .unwrap();

            certification_input
                .certify(certified(&result), 7, 11)
                .expect("the exact context, input, artifacts, and certificate certify");

            let mut wrong_context = certification_input.clone();
            wrong_context.registration.context = protocol
                .registration_at(
                    0,
                    DepositBatch::empty(),
                    result.withdrawals.clone(),
                    state.liability(),
                    20,
                    21,
                )
                .unwrap()
                .context;
            assert!(wrong_context.certify(certified(&result), 0, 0).is_err());

            let mut wrong_input = certification_input.clone();
            wrong_input.encoded = Bytes::from_static(b"another canonical proposal");
            assert!(wrong_input.certify(certified(&result), 0, 0).is_err());

            let mut wrong_header = certified(&result);
            wrong_header.header = alternate.header;
            assert!(certification_input.certify(wrong_header, 0, 0).is_err());

            let mut wrong_roots = certified(&result);
            wrong_roots.roots = alternate.roots;
            assert!(certification_input.certify(wrong_roots, 0, 0).is_err());

            let mut wrong_evidence = certified(&result);
            wrong_evidence.evidence = alternate.evidence.clone();
            assert!(certification_input.certify(wrong_evidence, 0, 0).is_err());

            let mut wrong_certificate = certified(&result);
            wrong_certificate.certificate = alternate.certificate;
            assert!(
                certification_input
                    .certify(wrong_certificate, 0, 0)
                    .is_err()
            );
        });
    }
}
