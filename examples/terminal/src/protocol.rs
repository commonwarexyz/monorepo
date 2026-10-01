//! Concrete protocol wiring for the operator.

use anyhow::{Context, Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
#[cfg(test)]
use commonware_clearing::bajillion::boundary::WithdrawalAction;
use commonware_clearing::bajillion::{
    admission::{Committee, Vote, bls12381, seal},
    boundary::{DepositBatch, DepositRecord, WithdrawalBatch},
    challenge::HigherEntryLookup,
    commitment::{self, Opening, VectorKind, VectorRoot},
    custody::Epoch,
    logs::{Floors, LogHead, Logs},
    payment::{EntryReceipt, PaymentContext, SendAuthorization, VectorAck, VectorSendBody},
    qmdb::{State, StateRoot},
    replica::{PreparedReplica, Replica},
    settlement::{EpochDeadlinePolicy, Genesis as ConfiguredGenesis, SettlementConfig},
    transition::{
        Close, CloseContext, CloseLimits, EpochContext, Header, OperatorKey, OperatorSignature,
        OperatorVariant, ProposalId, RootBundle, Terminal, prepare_dealing,
    },
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{G1, Private, Scalar},
        ops::{compute_public, sign_message},
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, Signature, SigningKey, StrictVerifyingKey,
};
use commonware_parallel::Rayon;
#[cfg(test)]
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{Faults as _, N3f1, NZU64, NZUsize, Participant, sync::Mutex};
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    ops::{Range, RangeInclusive},
    sync::Arc,
    time::Instant,
};

pub(crate) type Key = StrictVerifyingKey;
pub(crate) type Ack = VectorAck<Key, Digest>;
pub(crate) type Receipt = EntryReceipt<Key, Digest>;

/// The finalized payout head and epoch from one settlement checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PayoutTip {
    pub(crate) payouts: LogHead<Digest>,
    pub(crate) finalized: Option<u64>,
}
impl Write for PayoutTip {
    fn write(&self, buf: &mut impl BufMut) {
        self.payouts.write(buf);
        self.finalized.write(buf);
    }
}
impl EncodeSize for PayoutTip {
    fn encode_size(&self) -> usize {
        self.payouts.encode_size() + self.finalized.encode_size()
    }
}
impl Read for PayoutTip {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            payouts: LogHead::read(buf)?,
            finalized: Option::read(buf)?,
        })
    }
}

/// Maximum entries in one batched send, bounding adversarial acceptance decoding.
pub(crate) const MAX_ENTRIES: usize = 256;

/// Bounds the independently authorized sends in one wallet submission.
pub(crate) const MAX_SENDS_PER_BATCH: usize = 1024;
/// Bounds the aggregate recipient increments in one wallet submission.
pub(crate) const MAX_BATCH_SEND_ENTRIES: usize = 16_384;

const DEPLOYMENT_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_DEPLOYMENT";

/// Deterministic deployment identity for in-process protocol fixtures.
/// Network deployments use domains committed by genesis or the native registry.
pub(crate) fn deployment_of(operator: &Key) -> Digest {
    Sha256::hash(&[DEPLOYMENT_NAMESPACE, &operator.encode()])
}

/// Namespace for chain registrations. The signed payload is the deployment,
/// epoch, inbox end, deposit root, withdrawal batch, and native fee:
/// settlement binds the predecessor and assigns the absolute block-height
/// deadlines when the epoch becomes the admission frontier, so the operator
/// commits nothing about either.
const CHAIN_REGISTRATION_SIGNATURE_NAMESPACE: &[u8] =
    b"_COMMONWARE_EXAMPLES_TERMINAL_CHAIN_REGISTRATION";
const VALIDATOR_SEED_START: u64 = 10_000;
const OPERATOR_ACK_SEED_START: u64 = 20_000;
const VALIDATORS: usize = 4;

/// The fixed terminal committee requires consensus intersection for admission and recovery.
/// Signature verification and exact committee membership are checked separately.
pub(crate) fn has_consensus_quorum(certificate: &bls12381::Certificate) -> bool {
    certificate.signers.count() >= N3f1::quorum(VALIDATORS) as usize
}

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
// In-process closes bind deadlines from this placeholder grid until the
// operator adopts the ones settlement assigned from its genesis policy.
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

// The challenge window setup writes into a new chain's genesis. A recipient
// learns of an admitted close only from finalized blocks, then fetches its
// evidence and waits for the challenge to be included, all at live cadence.
// The window therefore matches the admission runway.
const GENESIS_CHALLENGE_DURATION: u64 = 300;

// Blocks a deposit's inclusion deadline allows beyond one admission offset.
const DEPOSIT_INCLUSION_SLACK: u64 = 100;

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
/// it. An epoch receives its admission and challenge deadlines from this
/// policy when it becomes the admission frontier: at its registration's
/// inclusion when no earlier epoch awaits admission, otherwise at its
/// predecessor's admission. An operator never chooses timing, only when to
/// submit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Timing {
    /// Exact blocks from the height an epoch becomes the admission frontier
    /// to its admission deadline.
    pub(crate) admission_offset: u64,
    /// Exact blocks between a registration's admission deadline and its
    /// challenge deadline.
    pub(crate) challenge_duration: u64,
}

impl Timing {
    /// The compiled fixture-grid pair the harness and in-process closes that
    /// have not adopted assigned deadlines run on.
    pub(crate) const DEFAULT: Self = Self {
        admission_offset: ADMISSION_OFFSET,
        challenge_duration: CHALLENGE_DURATION,
    };

    /// The defaults setup writes into a new chain's genesis: the wall-clock
    /// admission runway and a challenge window of the same length.
    pub(crate) const GENESIS: Self = Self {
        admission_offset: GENESIS_ADMISSION_OFFSET,
        challenge_duration: GENESIS_CHALLENGE_DURATION,
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

/// Predecessor-independent epoch authorization paired with its sealed boundary inputs.
#[derive(Clone)]
pub(crate) struct EpochRegistration {
    /// Deposit records the sealed boundary includes.
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) context: EpochContext<Key, Digest>,
    /// The operator's own projection of the predecessor liability. Settlement
    /// derives the bound value independently, and certification requires both
    /// to agree.
    pub(crate) liability: u64,
    /// Log floors captured by the certified registration, once adopted.
    pub(crate) floors: Option<Floors>,
    /// Admission and challenge deadlines settlement assigned when the epoch
    /// became the admission frontier, once adopted.
    pub(crate) deadlines: Option<(u64, u64)>,
    /// Account rows of the predecessor close. Settlement binds this interval
    /// itself, so only a close bound in process reads it.
    pub(crate) rows: Range<u64>,
    /// Inbox indices the boundary takes: from the first index no earlier
    /// registration pulled up to the exclusive end the registration signs.
    pub(crate) intake: Range<u64>,
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

    /// Binds a validator certificate to this exact proposal.
    pub(crate) fn certify(
        &self,
        certified: CertifiedEpoch,
        deal_micros: u128,
        seal_micros: u128,
    ) -> Result<SettlementResult> {
        certified.validate(&self.registration.context, &self.encoded)?;
        if let Some(floors) = self.registration.floors {
            ensure!(
                certified.context.floors() == floors,
                "certified close differs from the adopted native boundary"
            );
        }
        ensure!(
            certified.context.predecessor_liability() == self.registration.liability,
            "certified close binds a predecessor liability the operator did not project"
        );
        let verifier = bls12381::Scheme::verifier(committee()?);
        ensure!(
            has_consensus_quorum(&certified.certificate)
                && verifier.verify(&certified.header, &certified.certificate),
            "assembled certificate failed verification"
        );

        certified.roots.activity_range(&certified.context)?;

        Ok(SettlementResult {
            context: certified.context,
            header: certified.header,
            roots: certified.roots,
            certificate: certified.certificate,
            withdrawal_total: certified.withdrawal_total,
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
    pub(crate) certificate: bls12381::Certificate,
}

impl CertifiedEpoch {
    /// Validates the certified artifacts against the exact registered context and proposal.
    pub(crate) fn validate(
        &self,
        expected_context: &EpochContext<Key, Digest>,
        expected_input: &Bytes,
    ) -> Result<()> {
        ensure!(
            self.context.epoch_context() == expected_context,
            "certified close has the wrong registered context"
        );
        ensure!(
            self.roots.proposal
                == ProposalId::for_dealing::<Sha256, Key>(expected_context, expected_input),
            "certified close has the wrong dealing"
        );
        ensure!(
            self.header
                == Header::new::<Sha256, Key>(&self.context, &self.roots, self.withdrawal_total),
            "certified descriptor does not match its header"
        );
        Ok(())
    }
}

/// Artifacts and metrics held through one clean finalization.
#[derive(Clone)]
pub(crate) struct SettlementResult {
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) certificate: bls12381::Certificate,
    pub(crate) withdrawal_total: u64,
    pub(crate) dealing_bytes: usize,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

impl SettlementResult {
    /// Returns the account rows this close appended, which its successor binds.
    pub(crate) fn rows(&self) -> Result<Range<u64>> {
        let range = self
            .roots
            .activity_range(&self.context)
            .context("certified close has no valid activity range")?;
        Ok(range.start..range.end)
    }
}

/// Bounds the retained descriptor, certificate, and metrics for one close.
/// The certificate has one MinSig signature and a bitmap of at most `VALIDATORS` bits.
pub(crate) const MAX_RESULT_BYTES: usize = CloseContext::<Key, Digest>::SIZE
    + Header::<Digest>::SIZE
    + RootBundle::<Digest>::SIZE
    + u64::SIZE
    + G1::SIZE
    + u64::SIZE
    + VALIDATORS.div_ceil(8)
    + 3 * u128::SIZE
    + ((crate::rpc::MAX_BODY_SIZE.ilog2() + 1) as usize).div_ceil(7);

impl Write for SettlementResult {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.withdrawal_total.write(buf);
        self.certificate.write(buf);
        self.dealing_bytes.write(buf);
        self.prepare_micros.write(buf);
        self.deal_micros.write(buf);
        self.seal_micros.write(buf);
    }
}
impl EncodeSize for SettlementResult {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.withdrawal_total.encode_size()
            + self.certificate.encode_size()
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
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            withdrawal_total: u64::read(buf)?,
            certificate: bls12381::Certificate::read_cfg(buf, &VALIDATORS)?,
            dealing_bytes: usize::read_cfg(buf, &RangeCfg::new(0..=crate::rpc::MAX_BODY_SIZE))?,
            prepare_micros: u128::read(buf)?,
            deal_micros: u128::read(buf)?,
            seal_micros: u128::read(buf)?,
        })
    }
}

/// One in-process committee result used to seed deterministic proof fixtures.
pub(crate) struct RetainedClose {
    pub(crate) mutations: commonware_clearing::bajillion::qmdb::Mutations,
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) close: Arc<Close<Key, Digest>>,
}

/// Complete validated close evidence retained by the in-process committee simulation.
static RETAINED: Mutex<Vec<Arc<RetainedClose>>> = Mutex::new(Vec::new());

/// Snapshot of every close the in-process simulation retains.
pub(crate) fn retained_closes() -> Vec<Arc<RetainedClose>> {
    RETAINED.lock().clone()
}

/// Opens the in-process committee's retained close for a test fixture.
#[cfg(test)]
pub(crate) fn fixture_close(result: &SettlementResult) -> Arc<Close<Key, Digest>> {
    let retained = RETAINED.lock();
    let retained = retained
        .iter()
        .find(|retained| retained.close.header == result.header)
        .expect("fixture close was sealed by the in-process committee");
    assert_eq!(retained.context, result.context);
    retained.close.clone()
}

/// Assembles a genuine fixed-committee certificate for threshold policy tests.
#[cfg(test)]
pub(crate) fn fixture_certificate(
    header: &Header<Digest>,
    signer_count: usize,
) -> bls12381::Certificate {
    let validators = Validators::new().unwrap();
    bls12381::Scheme::verifier(validators.committee.clone())
        .assemble((0..signer_count).map(|index| {
            validators
                .signer(Participant::from_usize(index))
                .unwrap()
                .sign(header)
                .unwrap()
        }))
        .unwrap()
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
            N3f1::quorum(committee.members().len()) == 3,
            "operator committee must have consensus quorum 3"
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
        let page_cache = CacheRef::from_pooler(
            &context,
            crate::chain::validator::PAGE_SIZE,
            TRANSIENT_PAGE_CACHE_SIZE,
        );
        let config = state_config(
            &format!("setup-genesis-{}", self.digest),
            page_cache,
            commonware_parallel::Sequential,
        );
        let state = State::<_, Sha256>::open(context, config, None).await?;
        ensure!(
            state.is_bootstrap(),
            "genesis generation requires fresh storage"
        );
        let balances = genesis_balances(self)?;
        let candidate = state
            .prepare(
                state.head(),
                balances
                    .iter()
                    .cloned()
                    .map(|(key, balance)| (key, Some(balance)))
                    .collect(),
            )
            .await?;
        self.genesis = Some(ConfiguredGenesis::new(
            candidate.root(),
            candidate.head().operations(),
            &balances,
        )?);
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

// GiB-scale blobs amortize rollover. Small test blobs keep rollover and pruning reachable.
pub(crate) const STATE_OPERATIONS_PER_BLOB: NonZeroU64 =
    NZU64!(if cfg!(test) { 4_096 } else { 1 << 25 });
pub(crate) const STATE_MERKLE_NODES_PER_BLOB: NonZeroU64 =
    NZU64!(if cfg!(test) { 4_096 } else { 1 << 26 });
const TRANSIENT_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16);

/// Production page geometry with bounded capacity for deterministic fixtures.
#[cfg(test)]
pub(crate) fn fixture_page_cache(pooler: &impl commonware_runtime::BufferPooler) -> CacheRef {
    CacheRef::from_pooler(
        pooler,
        crate::chain::validator::PAGE_SIZE,
        TRANSIENT_PAGE_CACHE_SIZE,
    )
}

/// Partitions for the single account QMDB and its retained historical proofs.
pub(crate) fn state_config<S: commonware_parallel::Strategy>(
    prefix: &str,
    page_cache: CacheRef,
    strategy: S,
) -> commonware_clearing::bajillion::qmdb::Config<S> {
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle"),
            metadata_partition: format!("{prefix}-metadata"),
            items_per_blob: STATE_MERKLE_NODES_PER_BLOB,
            write_buffer: crate::chain::validator::IO_BUFFER_SIZE,
            replay_buffer: crate::chain::validator::IO_BUFFER_SIZE,
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-journal"),
            items_per_blob: STATE_OPERATIONS_PER_BLOB,
            page_cache,
            write_buffer: crate::chain::validator::IO_BUFFER_SIZE,
            replay_buffer: crate::chain::validator::IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(2097152),
        init_concurrency: (),
    }
}

/// Opens the three native stores with the configured balance allocation and empty flat logs.
pub(crate) async fn init_replica<E, S>(
    context: E,
    prefix: &str,
    strategy: S,
    balances: Vec<(commonware_clearing::bajillion::qmdb::AccountKey, NonZeroU64)>,
) -> Result<Replica<E, Sha256, Key, S>>
where
    E: commonware_storage::Context + commonware_runtime::Spawner,
    S: commonware_parallel::Strategy,
{
    let page_cache = CacheRef::from_pooler(
        &context,
        crate::chain::validator::PAGE_SIZE,
        TRANSIENT_PAGE_CACHE_SIZE,
    );
    let config = crate::chain::da::replica_config(prefix, page_cache, strategy);
    let state = State::init(context.child("state"), config.state, balances).await?;
    let logs = Logs::open(context.child("logs"), config.logs, None).await?;
    Ok(Replica::from_parts(state, logs))
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
    let page_cache = CacheRef::from_pooler(
        &context,
        crate::chain::validator::PAGE_SIZE,
        TRANSIENT_PAGE_CACHE_SIZE,
    );
    let config = state_config(
        "setup-empty-genesis",
        page_cache,
        commonware_parallel::Sequential,
    );
    let state = State::<_, Sha256>::open(context, config, None).await?;
    ensure!(
        state.is_bootstrap(),
        "empty genesis generation requires fresh storage"
    );
    let candidate = state.prepare(state.head(), Vec::new()).await?;
    Ok(ConfiguredGenesis::new(
        candidate.root(),
        candidate.head().operations(),
        &[],
    )?)
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
/// binds the deployment it registers under. That material includes the
/// exclusive end of the inbox prefix the registration pulls. The prefix
/// starts where the previous registration ended, so the start is not signed.
/// The predecessor and the deadlines are not part of it because settlement
/// binds them when the epoch becomes the admission frontier.
fn chain_registration_message(
    deployment: &Digest,
    epoch: u64,
    end: u64,
    deposits_root: &VectorRoot<Digest>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    fee: u64,
) -> Bytes {
    let mut message = BytesMut::with_capacity(
        deployment.encode_size()
            + epoch.encode_size()
            + end.encode_size()
            + deposits_root.encode_size()
            + withdrawals.encode_size()
            + fee.encode_size(),
    );
    deployment.write(&mut message);
    epoch.write(&mut message);
    end.write(&mut message);
    deposits_root.write(&mut message);
    withdrawals.write(&mut message);
    fee.write(&mut message);
    message.freeze()
}

/// Verifies a chain registration against one configured deployment: the
/// signature must be the deployment's operator's, over a message naming the
/// deployment's own digest.
pub(crate) fn verify_chain_registration_signature(
    deployment: &Deployment,
    epoch: u64,
    end: u64,
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
            end,
            deposits_root,
            withdrawals,
            fee,
        ),
        signature,
    )
}

/// Folds deposit events into their canonical per-account aggregate batch.
pub(crate) fn deposit_batch<'a>(
    events: impl IntoIterator<Item = &'a DepositEvent>,
) -> Result<DepositBatch<Key>> {
    let mut aggregates = std::collections::BTreeMap::<Key, u64>::new();
    for event in events {
        let amount = aggregates.entry(event.account.clone()).or_default();
        *amount = amount
            .checked_add(event.amount)
            .context("deposit total overflow")?;
    }
    Ok(DepositBatch::new(
        aggregates
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?)
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
/// Settlement assigns every admission frontier exactly the genesis admission
/// offset and challenge duration. An epoch registered while no earlier epoch
/// awaits admission therefore receives the same deadlines as one registered
/// at its predecessor's admission.
pub(crate) fn settlement_config(timing: &Timing) -> Result<SettlementConfig> {
    let admission =
        NonZeroU64::new(timing.admission_offset).context("admission offset must be positive")?;
    let challenge = NonZeroU64::new(timing.challenge_duration)
        .context("challenge duration must be positive")?;

    // A close window runs from an epoch's promotion to the admission frontier
    // through its challenge deadline and the block after it, where the close
    // can first finalize.
    let window = timing
        .admission_offset
        .checked_add(timing.challenge_duration)
        .and_then(|window| window.checked_add(1))
        .context("the deployment timing policy exceeds the epoch clock")?;

    // Notice covers the close window of the current epoch and the finalization
    // of the successor carrying the withdrawal, with inclusion slack.
    let minimum_notice = window
        .checked_add(2)
        .and_then(|notice| notice.checked_add(window.saturating_sub(3)))
        .context("withdrawal notice exceeds the epoch clock")?;

    // The 100-block difference is the window in which an authorization signed
    // at maximum notice can enter settlement.
    let maximum_notice = minimum_notice
        .checked_add(100)
        .context("withdrawal horizon exceeds the epoch clock")?;

    // A deposit enters the inbox and must be pulled by a registration: the
    // operator observes it, takes it into the live boundary, and registers
    // that boundary within one dwell. Once pulled, no timer applies, and the
    // deposit follows its epoch to admission, or to a refund if the deployment
    // faults first, however many registrations wait ahead. Registration never
    // waits for earlier closes or their challenge windows, so the timeout
    // omits the challenge duration. The operator cuts the live epoch within
    // its dwell, which never exceeds one admission offset. That offset is also
    // the runway that covers an operator relaunch. The slack covers
    // observation and inclusion. Pulls are prefixes and a registration carries
    // at most `MAX_WITHDRAWALS` requests, so a deposit behind a larger backlog
    // of chain-queued withdrawals waits one more epoch per capacity. The
    // operator refuses fresh extras while inbox rows wait, and the timeout
    // assumes the chain records fewer queued withdrawals within the slack
    // than the epochs cut in it carry.
    let deposit_timeout = timing
        .admission_offset
        .checked_add(DEPOSIT_INCLUSION_SLACK)
        .context("deposit inclusion timeout exceeds the epoch clock")?;
    Ok(SettlementConfig::new(
        EpochDeadlinePolicy::new(admission, challenge),
        NonZeroU64::new(deposit_timeout).expect("deposit timeout is nonzero"),
        NonZeroU64::new(minimum_notice).expect("notice is nonzero"),
        NonZeroU64::new(maximum_notice).expect("notice is nonzero"),
        256,
        NonZeroUsize::new(MAX_DEPOSIT_EVENTS).expect("deposit bound is nonzero"),
    ))
}

/// Returns the deadlines a withdrawal authorization included at `height + 1` may carry.
///
/// Settlement admits an authorization only while its deadline lies in the notice window of the
/// accepting block. Heights only grow, so a deadline below this window can never enter.
pub(crate) fn withdrawal_notice(timing: &Timing, height: u64) -> Result<RangeInclusive<u64>> {
    let config = settlement_config(timing)?;
    let inclusion = height
        .checked_add(1)
        .context("withdrawal inclusion height overflow")?;
    let minimum = inclusion
        .checked_add(config.minimum_withdrawal_notice.get())
        .context("withdrawal notice overflow")?;
    let maximum = inclusion.saturating_add(config.maximum_withdrawal_notice.get());
    Ok(minimum..=maximum)
}

#[cfg(test)]
pub(crate) fn epoch_context(
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
) -> Result<EpochContext<Key, Digest>> {
    epoch_context_at(
        deployment(),
        operator_key(),
        epoch,
        deposits,
        withdrawals,
        committee()?.commitment::<Sha256>(),
    )
}

/// Builds the epoch context one deployment's operator registers for `epoch`
/// under the clearing `committee` commitment.
///
/// The context commits nothing about the predecessor or about timing, so
/// the chain and the operator derive the same anchor from the same boundary.
pub(crate) fn epoch_context_at(
    deployment: Digest,
    operator: Key,
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    committee: Digest,
) -> Result<EpochContext<Key, Digest>> {
    EpochContext::new::<Sha256>(
        deployment,
        epoch,
        operator,
        deposits,
        withdrawals,
        limits(),
        committee,
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
    committee: Digest,
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
        let validators = Validators::new()?;
        Ok(Self {
            deployment,
            operator,
            operator_ack_key: compute_public::<OperatorVariant>(&operator_ack),
            operator_ack,
            committee: validators.committee.commitment::<Sha256>(),
            validators,
            strategy: Rayon::new(workers).context("create clearing worker pool")?,
        })
    }

    /// The operator's aggregable-acknowledgment public key.
    pub(crate) const fn operator_ack_key(&self) -> &OperatorKey {
        &self.operator_ack_key
    }

    /// Countersigns one accepted message for the close's complete-close aggregate.
    pub(crate) fn sign_ack_aggregate(
        &self,
        authorization: &SendAuthorization<Key, Digest>,
    ) -> OperatorSignature {
        sign_message::<OperatorVariant>(
            &self.operator_ack,
            commonware_clearing::bajillion::payment::VECTOR_ACK_AGGREGATE_NAMESPACE,
            authorization.message().as_ref(),
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

    /// Signs a chain registration over exactly the boundary material, including
    /// the exclusive end of the inbox prefix it pulls. Settlement binds the
    /// predecessor and the deadlines, so the signature commits nothing about
    /// either.
    pub(crate) fn sign_chain_registration(
        &self,
        epoch: u64,
        end: u64,
        deposits_root: &VectorRoot<Digest>,
        withdrawals: &WithdrawalBatch<Key, Digest>,
        fee: u64,
    ) -> Signature {
        self.operator.sign(
            CHAIN_REGISTRATION_SIGNATURE_NAMESPACE,
            &chain_registration_message(
                &self.deployment,
                epoch,
                end,
                deposits_root,
                withdrawals,
                fee,
            ),
        )
    }

    /// Builds the registration for one boundary and the operator's projected
    /// predecessor liability. Nothing is adopted from the chain yet.
    pub(crate) fn registration(
        &self,
        epoch: u64,
        deposits: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
        liability: u64,
    ) -> Result<EpochRegistration> {
        let context = epoch_context_at(
            self.deployment,
            self.operator.public_key(),
            epoch,
            &deposits,
            &withdrawals,
            self.committee,
        )?;
        ensure!(
            context.deployment() == &self.deployment
                && context.payment().operator() == &self.operator.public_key(),
            "operator protocol configuration drifted"
        );
        Ok(EpochRegistration {
            deposits,
            withdrawals,
            context,
            liability,
            floors: None,
            deadlines: None,
            rows: 0..0,
            intake: 0..0,
        })
    }

    /// Builds a registration whose deadlines were adopted from a certified
    /// record, so an in-process close binds them.
    #[cfg(test)]
    pub(crate) fn registration_at(
        &self,
        epoch: u64,
        deposits: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
        liability: u64,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> Result<EpochRegistration> {
        let mut registration = self.registration(epoch, deposits, withdrawals, liability)?;
        registration.deadlines = Some((admission_deadline, challenge_deadline));
        Ok(registration)
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
        state: &Replica<E, Sha256, Key, Rayon>,
        rng: &mut R,
    ) -> Result<(SettlementResult, PreparedReplica<Key, Digest, Rayon>)>
    where
        E: commonware_storage::Context + commonware_runtime::Spawner,
    {
        self.complete_with_strategy(epoch, state, rng, &self.strategy)
            .await
    }

    async fn complete_with_strategy<E, R, S>(
        &self,
        epoch: PreparedEpoch,
        state: &Replica<E, Sha256, Key, S>,
        rng: &mut R,
        strategy: &S,
    ) -> Result<(SettlementResult, PreparedReplica<Key, Digest, S>)>
    where
        E: commonware_storage::Context + commonware_runtime::Spawner,
        R: CryptoRng,
        S: commonware_parallel::Strategy,
    {
        let started = Instant::now();
        let (admission_deadline, challenge_deadline) = match epoch.registration.deadlines {
            Some(deadlines) => deadlines,
            None => deadlines(epoch.registration.context.payment().epoch())?,
        };
        let context = epoch
            .registration
            .context
            .clone()
            .bind::<Sha256, _, _>(
                state,
                &epoch.registration.deposits,
                &epoch.registration.withdrawals,
                epoch.registration.rows.clone(),
                epoch.registration.liability,
                admission_deadline,
                challenge_deadline,
                epoch.registration.floors.unwrap_or(Floors {
                    activity: state.logs().head().activity.floor,
                    payouts: state.logs().head().payouts.floor,
                }),
            )
            .context("bind close to validator state")?;
        let mut votes = Vec::<Vote>::new();
        let mut validated = None;
        for index in 0..N3f1::quorum(self.validators.committee.members().len()) as usize {
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
            .assemble(votes)
            .context("assemble consensus-quorum certificate")?;
        let (close, candidate) = validated.expect("nonempty quorum").into_parts();
        let certified = CertifiedEpoch {
            context: context.clone(),
            header: close.header,
            roots: close.roots,
            withdrawal_total: close.withdrawal_total,
            certificate,
        };
        let retained = RetainedClose {
            mutations: candidate.state().mutations().to_vec(),
            context,
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
            let deployment = Deployment::new(
                protocol.deployment,
                protocol.operator.public_key(),
                protocol.operator_ack_key,
                accounts,
            );
            let balances = genesis_balances(&deployment)?;
            Ok(ConfiguredGenesis::new(
                state.state().root(),
                state.state().head().operations(),
                &balances,
            )?)
        })
    }

    /// Runs one prepared close through an isolated deterministic validator replica.
    #[cfg(test)]
    pub(crate) fn fixture_complete(
        &self,
        accounts: &[Account],
        history: &[SettlementResult],
        mut prepared: PreparedEpoch,
        seed: u64,
    ) -> Result<SettlementResult> {
        use commonware_runtime::Runner as _;

        prepared.registration.rows = history.last().map_or(Ok(0..0), SettlementResult::rows)?;
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
            state
                .state()
                .opening(account)
                .await
                .context("open fixture account")
        })
    }
}

#[cfg(test)]
#[commonware_macros::boxed]
async fn fixture_state<E>(
    context: E,
    protocol: &Protocol,
    accounts: &[Account],
    history: &[SettlementResult],
) -> Result<Replica<E, Sha256, Key>>
where
    E: commonware_storage::Context + commonware_runtime::Spawner + commonware_runtime::BufferPooler,
{
    let page_cache = fixture_page_cache(&context);
    let config = crate::chain::da::replica_config("fixture-validator", page_cache, Sequential);
    let logs = Logs::open(context.child("logs"), config.logs, None).await?;
    let mut state = State::<_, Sha256>::open(context.child("state"), config.state, None).await?;
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
    let mut state = Replica::from_parts(state, logs);

    for (expected_epoch, result) in history.iter().enumerate() {
        ensure!(
            usize::try_from(result.context.payment().epoch()).ok() == Some(expected_epoch),
            "fixture validator history is not contiguous"
        );
        ensure!(
            result.context.deployment() == &protocol.deployment
                && result.context.payment().operator() == &protocol.operator.public_key()
                && result.context.committee() == &protocol.committee
                && result.context.predecessor_root() == &state.state().root(),
            "fixture validator history has the wrong predecessor or deployment"
        );
        let close = fixture_close(result);
        ensure!(
            close.header == result.header
                && close.roots == result.roots
                && close.withdrawal_total == result.withdrawal_total,
            "fixture validator history artifacts disagree"
        );
        ensure!(
            has_consensus_quorum(&result.certificate)
                && protocol
                    .verifier()
                    .verify(&result.header, &result.certificate),
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
        let prepared = state
            .prepare(
                &state.head(),
                mutations,
                close.activity_input::<Sha256>(),
                close.withdrawal_outputs().to_vec(),
                result.context.floors(),
            )
            .await?;
        ensure!(
            prepared.state().root() == result.roots.successor
                && prepared.head().logs == result.roots.logs(),
            "fixture validator mutations differ from certified history"
        );
        state = state.apply(prepared).await?.sync().await?;
    }
    Ok(state)
}

/// The deterministic placeholder grid pair for `epoch`, from the compiled
/// default geometry. In-process closes bind these until the operator adopts
/// the deadlines settlement assigned.
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
/// The first epoch becomes the admission frontier at registration, so its
/// record carries the deadlines immediately.
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
    state: Replica<E, Sha256, Key, Rayon>,
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
    let mut registration = protocol.registration(0, deposits, WithdrawalBatch::empty(), 400)?;
    registration.deadlines = Some((admission_deadline, challenge_deadline));
    let prepared = protocol.prepare(registration, Vec::new())?;
    let (result, candidate) = protocol.complete(prepared, &state, rng).await?;

    // The omitting close excludes the paying sender entirely, so its composed lookup is an
    // ordered activity absence and the public terminal entry resolves to zero.
    let state = state.apply(candidate).await?.sync().await?;
    let range = result.roots.activity_range(&result.context)?;
    let held_lookup = Epoch::at(state.logs(), result.context.payment().epoch(), range)
        .await?
        .higher_entry_lookup(state.logs(), &payer.public_key(), &receiver)
        .await?;
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
    let ack = Ack::sign_by_authorities(
        body,
        commitment::empty_root::<Sha256>(VectorKind::OutEntry),
        payer.signer(),
        protocol.operator(),
    );
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
    use commonware_clearing::bajillion::{
        boundary::SignedWithdrawal, qmdb::account_key, transition::WithdrawalClaim,
    };
    use commonware_codec::DecodeExt as _;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::TestRng;

    fn certified(result: &SettlementResult) -> CertifiedEpoch {
        CertifiedEpoch {
            context: result.context.clone(),
            header: result.header,
            roots: result.roots,
            withdrawal_total: result.withdrawal_total,
            certificate: result.certificate.clone(),
        }
    }

    /// The genesis timing yields the windows the README's Deadlines table lists.
    #[test]
    fn genesis_timing_yields_the_documented_windows() {
        let timing = Timing::GENESIS;
        assert_eq!(timing.admission_offset, 300);
        assert_eq!(timing.challenge_duration, 300);

        // A close whose deadlines start at `H` first finalizes at `H + 601`.
        assert_eq!(timing.admission_offset + timing.challenge_duration + 1, 601);

        // Deposits must be pulled within 400 blocks, and a withdrawal deadline lies 1,201 to
        // 1,301 blocks after the block that queues it.
        let config = settlement_config(&timing).unwrap();
        assert_eq!(config.deposit_inclusion_timeout.get(), 400);
        assert_eq!(config.minimum_withdrawal_notice.get(), 1_201);
        assert_eq!(config.maximum_withdrawal_notice.get(), 1_301);
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
        poisoned.roots.successor = genesis.root();
        assert!(
            protocol
                .fixture_opening(std::slice::from_ref(&account), &[poisoned], &account.key,)
                .is_err()
        );
    }

    #[test]
    fn certified_zero_amount_withdrawal_is_provable_from_the_native_payout_log() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let wallet = wallets().remove(0);
            let state = init_replica(
                context,
                "zero-withdrawal",
                protocol.strategy().clone(),
                vec![(
                    account_key(&wallet.public_key()).unwrap(),
                    NonZeroU64::new(10).unwrap(),
                )],
            )
            .await
            .unwrap();
            let request = SignedWithdrawal::sign(
                deployment(),
                wallet.public_key().encode(),
                WithdrawalAction::Amount(NonZeroU64::new(10).unwrap()),
                50,
                wallet.signer(),
            );
            let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
            let registration = protocol
                .registration(0, DepositBatch::empty(), withdrawals, 10)
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
            let authorization = SendAuthorization::sign(
                body,
                commitment::empty_root::<Sha256>(VectorKind::OutEntry),
                wallet.signer(),
            );
            let terminal = Terminal {
                operator_signature: protocol.sign_ack_aggregate(&authorization),
                authorization,
                vector,
            };
            let prepared = protocol.prepare(registration, vec![terminal]).unwrap();
            let certification_input = prepared.clone();
            let (result, successor) = protocol
                .complete(prepared, &state, &mut TestRng::new(29))
                .await
                .expect("an authenticated zero release remains certifiable");
            let position = result.context.predecessor_logs().payouts.operations;
            let mut maximum = result.clone();
            maximum.dealing_bytes = crate::rpc::MAX_BODY_SIZE;
            maximum.prepare_micros = u128::MAX;
            maximum.deal_micros = u128::MAX;
            maximum.seal_micros = u128::MAX;
            let encoded = maximum.encode();
            assert_eq!(encoded.len(), MAX_RESULT_BYTES);
            assert_eq!(
                SettlementResult::decode(encoded.clone()).unwrap().encode(),
                encoded
            );
            maximum.dealing_bytes += 1;
            assert!(SettlementResult::decode(maximum.encode()).is_err());
            let alternate_registration = protocol
                .registration(
                    0,
                    DepositBatch::empty(),
                    WithdrawalBatch::new(vec![request]).unwrap(),
                    10,
                )
                .unwrap();
            let alternate = protocol
                .prepare(alternate_registration, Vec::new())
                .unwrap();
            let (alternate, _) = protocol
                .complete(alternate, &state, &mut TestRng::new(30))
                .await
                .unwrap();

            for count in 2..=4 {
                let mut candidate = certified(&result);
                candidate.certificate = fixture_certificate(&candidate.header, count);
                assert!(
                    protocol
                        .verifier()
                        .verify(&candidate.header, &candidate.certificate)
                );
                assert_eq!(
                    certification_input.certify(candidate, 7, 11).is_ok(),
                    count >= 3,
                    "terminal certification requires consensus quorum: {count} signers"
                );
            }

            let mut wrong_context = certification_input.clone();
            wrong_context.registration.context = protocol
                .registration(0, DepositBatch::empty(), WithdrawalBatch::empty(), 10)
                .unwrap()
                .context;
            assert!(wrong_context.certify(certified(&result), 0, 0).is_err());

            // The operator fences a certified close whose settlement-derived
            // liability differs from its own projection.
            let mut wrong_liability = certification_input.clone();
            wrong_liability.registration.liability = 11;
            assert!(wrong_liability.certify(certified(&result), 0, 0).is_err());

            let mut wrong_input = certification_input.clone();
            wrong_input.encoded = Bytes::from_static(b"another canonical proposal");
            assert!(wrong_input.certify(certified(&result), 0, 0).is_err());

            let mut wrong_header = certified(&result);
            wrong_header.header = alternate.header;
            assert!(certification_input.certify(wrong_header, 0, 0).is_err());

            let mut wrong_roots = certified(&result);
            wrong_roots.roots = alternate.roots;
            assert!(certification_input.certify(wrong_roots, 0, 0).is_err());

            let mut wrong_certificate = certified(&result);
            wrong_certificate.certificate = alternate.certificate;
            assert!(
                certification_input
                    .certify(wrong_certificate, 0, 0)
                    .is_err()
            );
            let successor = state.apply(successor).await.unwrap();
            let (opening, operations) = successor
                .logs()
                .payout_opening(&result.roots.withdrawal_outputs, position, NonZeroU64::MIN)
                .await
                .unwrap();
            let [commonware_storage::qmdb::keyless::Operation::Append(output)] =
                operations.as_slice()
            else {
                panic!("withdrawal output is not the native payout append")
            };
            let claim = WithdrawalClaim::new(output.clone(), opening);
            assert_eq!(
                claim
                    .verify::<Sha256>(&result.roots.withdrawal_outputs)
                    .unwrap()
                    .amount(),
                0
            );
            assert_eq!(
                successor
                    .state()
                    .opening(wallet.public_key())
                    .await
                    .unwrap()
                    .balance
                    .get(),
                9
            );
        });
    }
}
