//! Concrete protocol wiring for the operator.

use anyhow::{Context, Result, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_clearing::bajillion::{
    admission::{Committee, Vote, bls12381, seal},
    boundary::{DepositBatch, DepositRecord, WithdrawalAction, WithdrawalBatch},
    challenge::{HigherEntryLookup, higher_entry_lookup},
    commitment::{Opening, VectorRoot},
    payment::{EntryReceipt, PaymentContext, VectorAck, VectorSendBody},
    qmdb::{PreparedState, State, StateHead, StateOpening, StateRoot},
    settlement::{
        EpochDeadlinePolicy, FinalizedBatch, Genesis as ConfiguredGenesis, SettlementChain,
        SettlementConfig,
    },
    state::SettlementOutput,
    transition::{
        ChallengeIndex, Close, CloseAmounts, CloseContext, CloseLimits, EpochContext,
        ExternalPayoutClaim, Header, OperatorKey, OperatorSignature, OperatorVariant,
        PreparedClose, RootBundle, Terminal, WithdrawalClaim, prepare_close_with_strategy,
    },
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
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
use commonware_parallel::Rayon;
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

/// Maximum entries in one batched send, bounding adversarial acceptance decoding.
pub(crate) const MAX_ENTRIES: usize = 256;

const DEPLOYMENT_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_DEPLOYMENT";

/// The deployment digest of one operator clearing key: the deployment
/// namespace folded with the operator identity, so every configured
/// deployment's digest is unique and self-describing. One settlement chain
/// hosts one deployment per operator.
pub(crate) fn deployment_of(operator: &Key) -> Digest {
    Sha256::hash(&[DEPLOYMENT_NAMESPACE, &operator.encode()])
}

/// Namespace for chain registrations. The signed payload is the boundary
/// material alone (epoch, predecessor liability, deposit and staged roots,
/// withdrawal batch): execution assigns the absolute block-height deadlines
/// at the registration's inclusion height, so the operator has nothing about
/// timing to commit.
const CHAIN_REGISTRATION_SIGNATURE_NAMESPACE: &[u8] =
    b"_COMMONWARE_EXAMPLES_TERMINAL_CHAIN_REGISTRATION";
const VALIDATOR_SEED_START: u64 = 10_000;
const OPERATOR_ACK_SEED_START: u64 = 20_000;
const VALIDATORS: usize = 4;

pub(crate) const MAX_ACCOUNTS: usize = 1_024;
/// Maximum accepted payments in one epoch, counting one per batched-send entry.
pub(crate) const MAX_ACCEPTED_PAYMENTS: usize = 1_024;
/// Bounds one encoded [`Acceptance`]: a batch send at the protocol entry limit plus one receipt
/// per entry.
pub(crate) const MAX_ACCEPTANCE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_DEPOSIT_EVENTS: usize = MAX_ACCOUNTS;
pub(crate) const MAX_WITHDRAWALS: usize = MAX_ACCOUNTS;

/// Maximum withdrawal destination length in bytes, shared by every codec that carries one.
pub(crate) const MAX_DESTINATION_BYTES: usize = 256;
const MAX_ROWS: u64 = 1_024;
const MAX_SHARDS: u64 = 1_024;
pub(crate) const INITIAL_BALANCE: u64 = 100;
/// Largest monetary value that the SQLite operator can persist exactly.
pub(crate) const SQLITE_U64_MAX: u64 = i64::MAX as u64;
// The compiled deadline geometry, in blocks: a registration gets a ten-block
// admission runway from its inclusion height and one inclusive challenge
// block. On the chain-facing flow the genesis policy is the timing authority
// end to end: execution assigns each registration's deadlines from it and
// the close worker's rehearsal derives its horizons from the adopted pair,
// so these consts bind only the deterministic placeholder grid that
// pre-registration contexts are staged under and the fixture harness that
// runs on that grid. Deposit and withdrawal deadlines remain independent
// obligations and may permanently fault an admitted close before that point.
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
const MINIMUM_WITHDRAWAL_NOTICE: u64 = 4;

/// Blocks between a wallet's signed-withdrawal head read and its absolute
/// deadline. A carried request must outlive its close's challenge deadline
/// (the genesis admission offset plus challenge duration plus one past the
/// registration's inclusion), so the horizon dominates the genesis runway
/// with slack for the registration to land, while staying under the queue's
/// maximum notice so escalation stays available.
pub(crate) const WITHDRAWAL_HORIZON: u64 = GENESIS_ADMISSION_OFFSET + 100;
const MAXIMUM_WITHDRAWAL_NOTICE: u64 = WITHDRAWAL_HORIZON + 100;

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

pub(crate) fn external_wallet() -> Wallet {
    Wallet::from_seed("Eve (external)", 999)
}

pub(crate) fn external_identity() -> AccountIdentity {
    let wallet = external_wallet();
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
    /// Staged aggregates exactly offset by a batch withdrawal. The chain defers each one
    /// whole to the successor epoch, so the sealed boundary excludes them.
    pub(crate) deferred: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) context: EpochContext<Key, Digest>,
}

/// A validated close candidate and its immutable settlement inputs.
pub(crate) struct PreparedEpoch {
    context: CloseContext<Key, Digest>,
    deposits: DepositBatch<Key>,
    withdrawals: WithdrawalBatch<Key, Digest>,
    deposit_events: Vec<DepositEvent>,
    predecessor: StateHead<Digest>,
    extra_openings: Vec<StateOpening<Key, Digest>>,
    prepared: PreparedClose<Key, Digest, Rayon>,
    prepare_micros: u128,
}

impl PreparedEpoch {
    #[cfg(test)]
    pub(crate) const fn epoch(&self) -> u64 {
        self.context.payment().epoch()
    }
    pub(crate) const fn close_context(&self) -> &CloseContext<Key, Digest> {
        &self.context
    }
    pub(crate) const fn close(&self) -> &Close<Key, Digest> {
        self.prepared.close()
    }
    pub(crate) const fn encoded(&self) -> &Bytes {
        self.prepared.encoded()
    }
    #[cfg(test)]
    pub(crate) fn mutations(
        &self,
    ) -> &[(
        commonware_clearing::bajillion::qmdb::AccountKey,
        Option<NonZeroU64>,
    )] {
        self.prepared.state().mutations()
    }
}

/// Artifacts and metrics held through one clean finalization.
pub(crate) struct SettlementResult {
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) evidence: Bytes,
    pub(crate) epoch: u64,
    pub(crate) predecessor_root: StateRoot<Digest>,
    pub(crate) epoch_context: EpochContext<Key, Digest>,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) payment_context:
        commonware_clearing::bajillion::payment::PaymentContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) certificate: bls12381::Certificate,
    pub(crate) amounts: CloseAmounts,
    pub(crate) external_claims: Vec<ExternalPayoutClaim<Key, Digest>>,
    pub(crate) withdrawal_claims: Vec<WithdrawalClaim<Digest>>,
    pub(crate) finalized: FinalizedBatch<Digest>,
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
        self.epoch.write(buf);
        self.predecessor_root.write(buf);
        self.deposits.write(buf);
        self.withdrawals.write(buf);
        self.payment_context.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.amounts.write(buf);
        self.certificate.write(buf);
        self.external_claims.write(buf);
        self.withdrawal_claims.write(buf);
        self.finalized.batch_id.write(buf);
        self.finalized.epoch.write(buf);
        self.finalized.successor_root.write(buf);
        self.finalized.withdrawal_total.write(buf);
        self.finalized.payout_total.write(buf);
        self.finalized.custody_balance.write(buf);
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
            + self.epoch.encode_size()
            + self.predecessor_root.encode_size()
            + self.deposits.encode_size()
            + self.withdrawals.encode_size()
            + self.payment_context.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.amounts.encode_size()
            + self.certificate.encode_size()
            + self.external_claims.encode_size()
            + self.withdrawal_claims.encode_size()
            + self.finalized.batch_id.encode_size()
            + self.finalized.epoch.encode_size()
            + self.finalized.successor_root.encode_size()
            + 24
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
            epoch_context: context.epoch_context().clone(),
            context,
            evidence: Bytes::read_cfg(buf, &RangeCfg::new(0..=crate::rpc::MAX_BODY_SIZE))?,
            epoch: u64::read(buf)?,
            predecessor_root: StateRoot::read(buf)?,
            deposits: DepositBatch::read_cfg(buf, &RangeCfg::new(0..=MAX_ACCOUNTS))?,
            withdrawals: WithdrawalBatch::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_WITHDRAWALS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            payment_context: PaymentContext::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            amounts: CloseAmounts::read(buf)?,
            certificate: bls12381::Certificate::read_cfg(buf, &VALIDATORS)?,
            external_claims: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_ACCOUNTS), ()))?,
            withdrawal_claims: Vec::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_WITHDRAWALS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            finalized: FinalizedBatch {
                batch_id: commonware_clearing::bajillion::transition::BatchId::read(buf)?,
                epoch: u64::read(buf)?,
                successor_root: StateRoot::read(buf)?,
                withdrawal_total: u64::read(buf)?,
                payout_total: u64::read(buf)?,
                custody_balance: u64::read(buf)?,
            },
            rows: usize::read_cfg(buf, &RangeCfg::new(0..=MAX_ACCOUNTS))?,
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
    pub(crate) predecessor_operations: u64,
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

/// One configured account of a deployment's genesis machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Account {
    pub(crate) key: Key,
    pub(crate) balance: u64,
}

/// One configured deployment: an operator clearing identity and the account
/// set its genesis machine opens with. The epoch timing policy is not part
/// of it: one chain-wide genesis policy applies to every deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Deployment {
    digest: Digest,
    pub(crate) operator: Key,
    pub(crate) operator_ack: OperatorKey,
    pub(crate) accounts: Vec<Account>,
    genesis: Option<ConfiguredGenesis<Digest>>,
}

impl Deployment {
    pub(crate) fn new(operator: Key, operator_ack: OperatorKey, accounts: Vec<Account>) -> Self {
        Self {
            digest: deployment_of(&operator),
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
        operator: Key,
        operator_ack: OperatorKey,
        accounts: Vec<Account>,
        root: StateRoot<Digest>,
        operations: u64,
    ) -> Result<Self> {
        let mut deployment = Self::new(operator, operator_ack, accounts);
        deployment.genesis = Some(ConfiguredGenesis::new(
            root,
            operations,
            &genesis_balances(&deployment)?,
        )?);
        Ok(deployment)
    }

    pub(crate) const fn genesis(&self) -> &ConfiguredGenesis<Digest> {
        self.genesis
            .as_ref()
            .expect("genesis configured before chain execution")
    }

    /// The deployment digest, derived from the operator clearing key.
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
                NonZeroU64::new(account.balance).context("genesis balance must be positive")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    balances.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    ensure!(
        balances.windows(2).all(|w| w[0].0 < w[1].0),
        "duplicate genesis account"
    );
    Ok(balances)
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
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-journal"),
            items_per_blob: NZU64!(4096),
            page_cache,
            write_buffer: NZUsize!(65536),
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(2097152),
        init_concurrency: (),
    }
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
        operator_key(),
        operator_ack_key(0),
        accounts(),
    )]
}

/// Digest committing to the whole configured deployment set in genesis
/// order: the chain identity the genesis block's parent field carries.
pub(crate) fn chain_id(deployments: &[Deployment]) -> Digest {
    let digests = deployments
        .iter()
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
    staged_root: &VectorRoot<Digest>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
) -> Bytes {
    let mut message = BytesMut::with_capacity(
        deployment.encode_size()
            + epoch.encode_size()
            + predecessor_liability.encode_size()
            + deposits_root.encode_size()
            + staged_root.encode_size()
            + withdrawals.encode_size(),
    );
    deployment.write(&mut message);
    epoch.write(&mut message);
    predecessor_liability.write(&mut message);
    deposits_root.write(&mut message);
    staged_root.write(&mut message);
    withdrawals.write(&mut message);
    message.freeze()
}

/// Verifies a chain registration against one configured deployment: the
/// signature must be the deployment's operator's, over a message naming the
/// deployment's own digest.
pub(crate) fn verify_chain_registration_signature(
    deployment: &Deployment,
    epoch: u64,
    predecessor_liability: u64,
    deposits_root: &VectorRoot<Digest>,
    staged_root: &VectorRoot<Digest>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    signature: &Signature,
) -> bool {
    deployment.operator.verify(
        CHAIN_REGISTRATION_SIGNATURE_NAMESPACE,
        &chain_registration_message(
            deployment.digest(),
            epoch,
            predecessor_liability,
            deposits_root,
            staged_root,
            withdrawals,
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
    CloseLimits::new(
        MAX_ACCOUNTS as u64,
        MAX_ROWS,
        MAX_ACCOUNTS as u64,
        MAX_SHARDS,
        MAX_SHARDS,
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
pub(crate) fn settlement_config(timing: &Timing) -> SettlementConfig {
    let delay = timing
        .admission_offset
        .checked_add(timing.challenge_duration)
        .and_then(|delay| delay.checked_add(1))
        .expect("the deployment timing policy fits the epoch clock");
    SettlementConfig::new(
        NonZeroUsize::new(4).expect("pipeline bound is nonzero"),
        EpochDeadlinePolicy::new(
            NonZeroU64::new(delay).expect("admission delay is nonzero"),
            NonZeroU64::new(timing.challenge_duration)
                .expect("every timing source keeps the challenge duration nonzero"),
            NonZeroU64::new(timing.challenge_duration)
                .expect("every timing source keeps the challenge duration nonzero"),
        ),
        NonZeroU64::new(DEPOSIT_INCLUSION_TIMEOUT).expect("deposit timeout is nonzero"),
        NonZeroU64::new(MINIMUM_WITHDRAWAL_NOTICE).expect("notice is nonzero"),
        NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).expect("notice is nonzero"),
        256,
        NonZeroUsize::new(MAX_DEPOSIT_EVENTS).expect("deposit bound is nonzero"),
    )
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
        Self::with_signer(workers, operator_signer(0), operator_ack_signer(0))
    }

    /// Protocol machinery for the deployment `operator` runs: the deployment
    /// digest derives from the signing identity.
    pub(crate) fn with_signer(
        workers: NonZeroUsize,
        operator: SigningKey,
        operator_ack: Private,
    ) -> Result<Self> {
        Ok(Self {
            deployment: deployment_of(&operator.public_key()),
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
        staged_root: &VectorRoot<Digest>,
        withdrawals: &WithdrawalBatch<Key, Digest>,
    ) -> Signature {
        self.operator.sign(
            CHAIN_REGISTRATION_SIGNATURE_NAMESPACE,
            &chain_registration_message(
                &self.deployment,
                epoch,
                predecessor_liability,
                deposits_root,
                staged_root,
                withdrawals,
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
        // Mirror the chain's boundary rule: a staged aggregate exactly offset by a batch
        // withdrawal defers whole to the successor epoch, so the sealed context commits
        // only the included records and the boundary roots agree by construction whenever
        // the deposit sets agree.
        let mut deposits = Vec::new();
        let mut deferred = Vec::new();
        for record in staged.records() {
            let defers = withdrawals
                .request_for(record.account())
                .is_some_and(|request| {
                    SettlementChain::<Sha256, Key>::withdrawal_defers_deposit(
                        request,
                        record.amount(),
                    )
                });
            if defers {
                deferred.push(record.clone());
            } else {
                deposits.push(record.clone());
            }
        }
        let deposits = DepositBatch::new(deposits).context("split included deposit boundary")?;
        let deferred = DepositBatch::new(deferred).context("split deferred deposit boundary")?;
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
            deferred,
            withdrawals,
            context,
        })
    }

    pub(crate) async fn prepare<E>(
        &self,
        registration: EpochRegistration,
        deposit_events: Vec<DepositEvent>,
        predecessor: &State<E, Sha256, Rayon>,
        terminals: Vec<Terminal<Key, Digest>>,
    ) -> Result<PreparedEpoch>
    where
        E: commonware_storage::Context + commonware_runtime::Spawner,
    {
        let started = Instant::now();
        let context = registration
            .context
            .bind::<Sha256, _, _>(
                predecessor,
                &registration.deposits,
                &registration.withdrawals,
            )
            .await
            .context("bind close to balance state")?;
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            predecessor,
            &context,
            &registration.deposits,
            &registration.withdrawals,
            terminals,
            &self.strategy,
        )
        .await
        .context("prepare close")?;
        let mut extra_openings = Vec::with_capacity(registration.withdrawals.requests().len());
        for request in registration.withdrawals.requests() {
            extra_openings.push(predecessor.opening(request.account().clone()).await?);
        }
        Ok(PreparedEpoch {
            context,
            deposits: registration.deposits,
            withdrawals: registration.withdrawals,
            deposit_events,
            predecessor: *predecessor.head(),
            extra_openings,
            prepared,
            prepare_micros: started.elapsed().as_micros(),
        })
    }

    /// Verify-only clearing scheme over the fixed committee, for vote and
    /// certificate verification.
    pub(crate) fn verifier(&self) -> bls12381::Scheme {
        bls12381::Scheme::verifier(self.validators.committee.clone())
    }

    /// Completes one prepared close in process, simulating every committee
    /// validator with its dealt key, for the deterministic harness and the
    /// fraud fixture. The operator binary certifies over the settlement DA
    /// channel and completes with [`Self::certify`] instead.
    pub(crate) async fn complete<E, R: CryptoRng>(
        &self,
        epoch: PreparedEpoch,
        state: &State<E, Sha256, Rayon>,
        rng: &mut R,
    ) -> Result<(SettlementResult, PreparedState<Digest, Rayon>)>
    where
        E: commonware_storage::Context + commonware_runtime::Spawner,
    {
        let started = Instant::now();
        let mut votes = Vec::<Vote>::new();
        let mut retained_close = None;
        for index in 0..self.validators.committee.quorum() {
            let scheme = self.validators.signer(Participant::from_usize(index))?;
            let (vote, validated) = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                &scheme,
                state,
                &epoch.context,
                &self.operator_ack_key,
                &epoch.deposits,
                &epoch.withdrawals,
                epoch.encoded().clone(),
                rng,
                &self.strategy,
            )
            .await
            .context("validate complete dealing")?;
            let (close, _) = validated.into_parts();
            if retained_close.is_none() {
                retained_close = Some(Arc::new(close));
            }
            votes.push(vote);
        }
        let certificate = self
            .validators
            .signer(Participant::new(0))?
            .assemble_exact(votes)
            .context("assemble exact-quorum certificate")?;
        let retained = RetainedClose {
            operations: epoch.prepared.state().head().operations(),
            predecessor_operations: epoch.prepared.state().predecessor().operations(),
            deposits: epoch.deposits.clone(),
            withdrawals: epoch.withdrawals.clone(),
            mutations: epoch.prepared.state().mutations().to_vec(),
            context: epoch.context.clone(),
            header: epoch.close().header,
            roots: epoch.close().roots,
            close: retained_close.expect("nonempty quorum"),
        };
        let (result, state) = self.certify(epoch, certificate, 0, started.elapsed().as_micros())?;
        RETAINED.lock().push(Arc::new(retained));
        Ok((result, state))
    }

    /// Completes a prepared close from an exact-quorum certificate: verifies
    /// the certificate over the close header, assembles the retained claims
    /// and rehearses the exact settlement transition before
    /// anything is published.
    pub(crate) fn certify(
        &self,
        epoch: PreparedEpoch,
        certificate: bls12381::Certificate,
        deal_micros: u128,
        seal_micros: u128,
    ) -> Result<(SettlementResult, PreparedState<Digest, Rayon>)> {
        let PreparedEpoch {
            context,
            deposits,
            withdrawals,
            deposit_events,
            predecessor,
            extra_openings,
            prepared,
            prepare_micros,
        } = epoch;
        let epoch = context.payment().epoch();
        ensure!(
            self.verifier()
                .verify_exact(&prepared.close().header, &certificate),
            "assembled certificate failed verification"
        );

        let amounts = prepared.close().amounts;
        let external_claims = prepared
            .close()
            .rows
            .iter()
            .filter(|row| matches!(row.output, SettlementOutput::ExternalPayout(_)))
            .map(|row| {
                prepared
                    .external_payout_claim(&row.account)
                    .context("assemble external payout claim")
            })
            .collect::<Result<Vec<_>>>()?;
        let withdrawal_claims = withdrawals
            .requests()
            .iter()
            .enumerate()
            .map(|(position, request)| {
                let claim = prepared
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
                        claim.output().amount() == amount.get(),
                        "withdrawal claim has the wrong requested amount"
                    );
                }
                Ok(claim)
            })
            .collect::<Result<Vec<_>>>()?;

        // Rehearse the exact settlement transition before publishing it. The authoritative
        // settlement repeats this bounded check and controls whether the result becomes durable.
        // The rehearsal policy must accept the context's exact deadline spacing, so its
        // challenge duration comes from the deadlines themselves. On the chain path they are
        // the pair execution assigned from the genesis policy, adopted from the certified
        // registration record, so the derived duration is the deployment's own. On the
        // fixture grid they are spaced by the compiled default. The context constructor
        // rejects an admission deadline at or after the challenge deadline, so the
        // difference is nonzero.
        let challenge_duration = context
            .challenge_deadline()
            .checked_sub(context.admission_deadline())
            .expect("the epoch context orders its deadlines");

        // Rehearse at a registration height within the compiled admission
        // offset of the admission deadline. The policy below bounds the
        // admission delay by at least that offset, so the rehearsal accepts
        // both grid placeholders and chain-assigned deadlines whatever the
        // deployment's genesis admission offset.
        let now = context
            .admission_deadline()
            .saturating_sub(ADMISSION_OFFSET);

        // That compiled height is not the inclusion height the chain assigned,
        // so the genesis-tuned intake horizons cannot be reused verbatim: a
        // fixed deposit timeout expires the rehearsal's own deposits before
        // its finalize tick once the adopted challenge duration outgrows it,
        // and a fixed withdrawal notice can refuse a carried request the
        // chain already accepted under its own clock. Both horizons derive
        // from the deadlines this close actually rehearses: the deposit
        // timeout spans every rehearsal deposit through the finalize tick,
        // and the notice window widens by the compiled offset to absorb the
        // clock shift. The authoritative settlement enforces the genuine
        // policy itself.
        let mut config = settlement_config(&Timing {
            admission_offset: ADMISSION_OFFSET,
            challenge_duration,
        });
        config.deposit_inclusion_timeout = context
            .challenge_deadline()
            .checked_add(2)
            .and_then(|end| end.checked_sub(now))
            .and_then(NonZeroU64::new)
            .expect("the rehearsal spans at least the challenge window");
        config.maximum_withdrawal_notice = config
            .maximum_withdrawal_notice
            .checked_add(ADMISSION_OFFSET)
            .expect("the rehearsal notice window fits the epoch clock");
        let mut chain = SettlementChain::<Sha256, Key>::new(
            self.deployment,
            self.operator.public_key(),
            self.validators.committee.clone(),
            &ConfiguredGenesis::from(&predecessor),
            epoch,
            config,
        )
        .context("construct settlement chain")?;
        for event in &deposit_events {
            chain
                .record_deposit(now, event.id, event.account.clone(), event.amount)
                .context("record deposit in settlement chain")?;
        }
        // Withdrawals are operator-carried, so the boundary passes through registration
        // exactly as the authoritative settlement validates it: one predecessor-root
        // opening per carried request proves the close certifiable before it registers.
        chain
            .register_close(
                now,
                context.clone(),
                withdrawals.clone(),
                &extra_openings,
                |_| true,
            )
            .context("register close")?;
        chain
            .admit(
                now,
                prepared.close().header,
                prepared.close().roots,
                amounts,
                certificate.clone(),
            )
            .context("admit certified close")?;
        let finalized = chain
            .finalize(context.challenge_deadline() + 1)
            .context("finalize certified close")?;
        ensure!(
            finalized.successor_root == prepared.close().roots.successor,
            "finalized root does not match SQLite state"
        );
        let claimed_payout = external_claims.iter().try_fold(0_u64, |total, claim| {
            let payout = claim
                .verify::<Sha256>(&prepared.close().roots.change)
                .context("verify assembled external payout claim")?;
            total
                .checked_add(payout.amount)
                .context("external payout total overflow")
        })?;
        ensure!(
            finalized.payout_total == claimed_payout,
            "operator payout reserve does not match its external claims"
        );

        let header = prepared.close().header;
        let roots = prepared.close().roots;
        let rows = prepared.close().rows.len();
        let dealing_bytes = prepared.encoded().len();
        let evidence = prepared.close().encode_evidence();
        let (_, state) = prepared.into_parts();
        Ok((
            SettlementResult {
                context: context.clone(),
                evidence,
                epoch,
                predecessor_root: *context.predecessor_root(),
                epoch_context: context.epoch_context().clone(),
                deposits,
                withdrawals,
                payment_context: context.payment().clone(),
                header,
                roots,
                certificate,
                amounts,
                external_claims,
                withdrawal_claims,
                finalized,
                rows,
                dealing_bytes,
                prepare_micros,
                deal_micros,
                seal_micros,
            },
            state,
        ))
    }
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

    let (deposit, deposits) = omitting_boundary()?;
    let registration = protocol.registration_at(
        0,
        deposits,
        WithdrawalBatch::empty(),
        400,
        admission_deadline,
        challenge_deadline,
    )?;
    let prepared = protocol
        .prepare(registration, vec![deposit], &state, Vec::new())
        .await?;

    // The omitting close excludes the paying sender entirely, so its composed lookup is an
    // ordered change-vector absence and the public terminal entry resolves to zero.
    let index = ChallengeIndex::new::<Sha256>(prepared.close_context(), prepared.close())
        .context("index the omitting close")?;
    let held_lookup =
        higher_entry_lookup::<Sha256, _, _>(&index, &payer.public_key(), None, &receiver)
            .context("compose the omitted sender lookup")?;
    let (result, candidate) = protocol.complete(prepared, &state, rng).await?;
    let _state = state.apply(candidate).await?.commit().await?;
    let context = result.payment_context.clone();

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
