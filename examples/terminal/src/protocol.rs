//! Concrete protocol wiring for the operator.

use crate::operator::Operator;
use anyhow::{Context, Result, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_clearing::bajillion::{
    admission::{
        Committee, SealedDealing, Vote, assigned_slice_spans, bls12381, committee_spans, seal,
    },
    boundary::{DepositBatch, DepositRecord, WithdrawalAction, WithdrawalBatch},
    challenge::{HigherEntryLookup, higher_entry_lookup},
    commitment::{Opening, VectorRoot},
    payment::{EntryReceipt, PaymentContext, VectorAck, VectorSendBody},
    retained::{Dealings, DealtSlice, Interval, Wire},
    settlement::{EpochDeadlinePolicy, FinalizedBatch, SettlementChain, SettlementConfig},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Assignment, ChallengeIndex, CloseContext, CloseLimits, EpochContext, ExternalPayoutClaim,
        Header, OperatorKey, OperatorSignature, OperatorVariant, PreparedClose, ProofSlice,
        RootBundle, SliceCodecConfig, StateCache, WithdrawalClaim, account_slice,
        prepare_close_with_strategy,
    },
    vector::{OutEntry, OutTipLookup, OutVector, TransposeEntry},
};
use commonware_codec::{
    Decode as _, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
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
use commonware_utils::{Participant, sync::Mutex};
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::Arc,
    time::Instant,
};

pub(crate) type Key = StrictVerifyingKey;
pub(crate) type Ack = VectorAck<Key, Digest>;
pub(crate) type Receipt = EntryReceipt<Key, Digest>;
pub(crate) type AccountCache = StateCache<Key, Digest>;

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
pub(crate) const SLICE_BITS: u8 = 2;

/// Maximum proof slices one close partitions into, and so the most slices one
/// validator dealing can carry.
pub(crate) const MAX_SLICES: usize = 1 << SLICE_BITS;
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

/// Root-complete close ready for background dealing and sealing.
pub(crate) struct PreparedEpoch {
    context: CloseContext<Key, Digest>,
    deposits: DepositBatch<Key>,
    withdrawals: WithdrawalBatch<Key, Digest>,
    deposit_events: Vec<DepositEvent>,
    predecessor: AccountCache,
    /// Predecessor leaf position at each slice boundary, one more than the
    /// slice count: slice `s` retains `leaves[partition[s]..partition[s + 1]]`.
    partition: Vec<usize>,
    prepared: PreparedClose<Key, Digest>,
    prepare_micros: u128,
}

impl PreparedEpoch {
    #[cfg(test)]
    pub(crate) const fn epoch(&self) -> u64 {
        self.context.payment().epoch()
    }

    /// Returns the bound close context for committed-side evidence reconstruction.
    pub(crate) const fn close_context(&self) -> &CloseContext<Key, Digest> {
        &self.context
    }

    /// Returns the canonical prepared close for committed-side evidence reconstruction.
    pub(crate) const fn close(
        &self,
    ) -> &commonware_clearing::bajillion::transition::Close<Key, Digest> {
        self.prepared.close()
    }

    /// Receives one validator's dealing as that validator does: decodes each
    /// span's wire and hydrates it against the span's live predecessor
    /// leaves. The simulation reads those as the span's contiguous range of
    /// the predecessor state the close was prepared over, where a validator
    /// reads the intervals it retains at that root.
    pub(crate) fn hydrate(&self, dealing: Vec<Wire>) -> Result<Vec<ProofSlice<Key, Digest>>> {
        dealing
            .into_iter()
            .map(|wire| {
                let dealt = DealtSlice::<Key, Digest>::decode_cfg(wire.encode(), &slice_codec())
                    .context("decode dealt slice")?;
                let span = dealt.span();
                ensure!(
                    usize::from(span.end) < self.partition.len(),
                    "dealt span is outside the close"
                );
                let leaves = self.predecessor.leaves()[self.partition[usize::from(span.start)]
                    ..self.partition[usize::from(span.end)]]
                    .to_vec();
                let interval =
                    Interval::new(leaves).context("predecessor leaves form no interval")?;
                dealt
                    .hydrate::<Sha256>(&interval, &self.context, &self.deposits, &self.withdrawals)
                    .context("hydrate dealt slice")
            })
            .collect()
    }
}

/// One close's dealt wire: every slice's chunk encoded once and one witness
/// per distinct span some committee member is assigned.
pub(crate) struct Dealt {
    dealings: Dealings,
    spans: Vec<Range<u16>>,
}

impl Dealt {
    /// The distinct dealt slices, one per span however many validators share it.
    pub(crate) const fn len(&self) -> usize {
        self.spans.len()
    }
}

/// Artifacts and metrics held through one clean finalization.
pub(crate) struct SettlementResult {
    pub(crate) epoch: u64,
    pub(crate) predecessor_root: commonware_clearing::bajillion::commitment::VectorRoot<Digest>,
    pub(crate) epoch_context: EpochContext<Key, Digest>,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) payment_context:
        commonware_clearing::bajillion::payment::PaymentContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) certificate: bls12381::Certificate,
    pub(crate) terminal_proof: commonware_clearing::bajillion::transition::TerminalProof<Digest>,
    pub(crate) external_claims: Vec<ExternalPayoutClaim<Key, Digest>>,
    pub(crate) withdrawal_claims: Vec<WithdrawalClaim<Digest>>,
    pub(crate) finalized: FinalizedBatch<Digest>,
    pub(crate) rows: usize,
    pub(crate) slices: usize,
    pub(crate) dealing_slices: usize,
    /// Sealed dealings retained by the in-process harness simulation. The
    /// distributed flow leaves this empty: each validator retains its own.
    dealings: Vec<SealedDealing<Key, Digest>>,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

impl SettlementResult {
    /// Releases validator-owned evidence after settlement has completed finalization.
    pub(crate) fn release_dealings(&mut self) {
        self.dealings.clear();
    }
}

/// One close the in-process simulation sealed for every quorum validator:
/// the material the harness serves validator evidence from, exactly what a
/// real validator retains (see [`crate::chain::da`]) with the bound context
/// the simulation held in memory.
pub(crate) struct RetainedClose {
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) dealings: Vec<SealedDealing<Key, Digest>>,
}

/// The closes the in-process simulation has sealed in this process, in
/// completion order. The simulation stands in for every committee validator,
/// so this is the validators' retained evidence for the harness to serve,
/// bounded per deployment by [`retain`].
static RETAINED: Mutex<Vec<Arc<RetainedClose>>> = Mutex::new(Vec::new());

/// Snapshot of every close the in-process simulation retains.
pub(crate) fn retained_closes() -> Vec<Arc<RetainedClose>> {
    RETAINED.lock().clone()
}

/// Retains one completed close, releasing the oldest closes of its
/// deployment beyond the last [`Operator::RETAINED_EPOCHS`]: the operator's
/// own retention contract, and the settlement pipeline bound, so every close
/// still inside its challenge window stays served.
fn retain(retained: &mut Vec<Arc<RetainedClose>>, close: RetainedClose) {
    let deployment = *close.context.deployment();
    retained.push(Arc::new(close));
    let held = retained
        .iter()
        .filter(|close| *close.context.deployment() == deployment)
        .count();
    let mut excess = held.saturating_sub(
        usize::try_from(Operator::RETAINED_EPOCHS).expect("the retention window fits usize"),
    );
    retained.retain(|close| {
        if excess == 0 || *close.context.deployment() != deployment {
            return true;
        }
        excess -= 1;
        false
    });
}

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

    fn assignment(&self) -> Result<Assignment<Digest>> {
        Assignment::new(self.committee.commitment::<Sha256>(), SLICE_BITS)
            .context("construct operator slice assignment")
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
/// combined countersignature per proof slice under this key, and validators verify the
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
}

impl Deployment {
    pub(crate) fn new(operator: Key, operator_ack: OperatorKey, accounts: Vec<Account>) -> Self {
        Self {
            digest: deployment_of(&operator),
            operator,
            operator_ack,
            accounts,
        }
    }

    /// The deployment digest, derived from the operator clearing key.
    pub(crate) const fn digest(&self) -> &Digest {
        &self.digest
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

pub(crate) fn assignment() -> Result<Assignment<Digest>> {
    Validators::new()?.assignment()
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

/// Maximum Merkle proof hashes accepted per decoded slice frontier.
const MAX_PROOF_HASHES: usize = 4_096;

/// Adversarial decode limits for one disseminated proof slice: the
/// anchor-bound close limits every epoch context commits.
pub(crate) const fn slice_codec() -> SliceCodecConfig {
    SliceCodecConfig::new(limits(), MAX_PROOF_HASHES)
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
        assignment()?,
    )
    .context("construct epoch context")
}

/// Shared cryptographic and parallel machinery for every operator action.
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

    /// Countersigns one accepted endpoint body for the close's slice aggregates.
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
                && context.assignment() == &self.validators.assignment()?,
            "operator protocol configuration drifted"
        );
        Ok(EpochRegistration {
            deposits,
            deferred,
            withdrawals,
            context,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        &self,
        registration: EpochRegistration,
        deposit_events: Vec<DepositEvent>,
        predecessor: Vec<StateLeaf<Key>>,
        rows: Vec<AccountRow<Key, Digest>>,
        out_vectors: Vec<OutVector<Key>>,
        operator_signatures: Vec<Option<OperatorSignature>>,
        transpose: Vec<TransposeEntry<Key>>,
        successor: Vec<StateLeaf<Key>>,
    ) -> Result<PreparedEpoch> {
        ensure!(!rows.is_empty(), "there is nothing to settle");
        let prepare_start = Instant::now();
        let predecessor = StateCache::new_with_strategy::<Sha256>(predecessor, &self.strategy)
            .context("commit predecessor account state")?;
        let context = registration
            .context
            .bind::<Sha256>(
                &predecessor,
                &registration.deposits,
                &registration.withdrawals,
            )
            .context("bind epoch registration to its predecessor state")?;
        let successor = StateCache::new_with_strategy::<Sha256>(successor, &self.strategy)
            .context("commit projected successor state")?;
        let successor_root = successor.root();
        let partials = out_vectors
            .iter()
            .map(OutVector::accumulator)
            .collect::<Vec<_>>();
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &predecessor,
            &context,
            &registration.deposits,
            &registration.withdrawals,
            rows,
            out_vectors,
            &partials,
            &operator_signatures,
            transpose,
            &self.strategy,
        )
        .context("prepare close")?;
        prepared
            .validate::<Sha256, PaymentBatchVerifier, _>(
                &context,
                &self.operator_ack_key,
                &registration.deposits,
                &registration.withdrawals,
                &mut rand::rng(),
                &self.strategy,
            )
            .context("validate prepared close")?;
        ensure!(
            prepared.close().roots.successor == successor_root,
            "prepared close does not match SQLite successor state"
        );
        let prepare_micros = prepare_start.elapsed().as_micros();

        // The predecessor leaves are key-sorted, so each slice's retained leaves are one
        // contiguous run, found once here for every dealing the simulation hydrates.
        let assignment = context.assignment();
        let leaves = predecessor.leaves();
        let mut partition = Vec::with_capacity(usize::from(assignment.slice_count()) + 1);
        let mut position = 0_usize;
        for slice in 0..assignment.slice_count() {
            while leaves.get(position).is_some_and(|leaf| {
                account_slice(&leaf.account, assignment.slice_bits())
                    .is_ok_and(|member| member < slice)
            }) {
                position += 1;
            }
            partition.push(position);
        }
        partition.push(leaves.len());

        Ok(PreparedEpoch {
            context,
            deposits: registration.deposits,
            withdrawals: registration.withdrawals,
            deposit_events,
            predecessor,
            partition,
            prepared,
            prepare_micros,
        })
    }

    /// One committee member's assigned contiguous slice spans, in slice order.
    fn spans(&self, epoch: &PreparedEpoch, validator: Participant) -> Result<Vec<Range<u16>>> {
        assigned_slice_spans::<Sha256, _>(
            &self.validators.committee,
            epoch.context.assignment(),
            validator,
        )
        .context("derive validator dealing")
    }

    /// Deals the distinct proof slices of a prepared close: one per span some
    /// committee member is assigned, every slice's content encoded once and
    /// every span's witness once, without materializing a slice.
    ///
    /// The distributed close worker disseminates these per-validator over the
    /// settlement DA channel. The harness seals them in process instead.
    pub(crate) fn slices(&self, epoch: &PreparedEpoch) -> Result<Dealt> {
        let spans =
            committee_spans::<Sha256, _>(&self.validators.committee, epoch.context.assignment())
                .context("derive committee spans")?;
        let dealings = epoch
            .prepared
            .deal(&epoch.predecessor, &spans, &self.strategy)
            .context("deal proof slices")?;
        Ok(Dealt { dealings, spans })
    }

    /// Assembles each committee member's exact dealing, in committee
    /// participant order: one dealt slice wire per assigned span, in span
    /// order, sharing the dealt chunk buffers instead of copying them.
    pub(crate) fn dealings(&self, epoch: &PreparedEpoch, dealt: &Dealt) -> Result<Vec<Vec<Wire>>> {
        (0..self.validators.committee.members().len())
            .map(|index| {
                Ok(self
                    .spans(epoch, Participant::from_usize(index))?
                    .iter()
                    .map(|span| dealt.dealings.encode_span(span))
                    .collect())
            })
            .collect()
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
    pub(crate) fn complete<R: CryptoRng>(
        &self,
        epoch: PreparedEpoch,
        rng: &mut R,
    ) -> Result<SettlementResult> {
        let deal_start = Instant::now();
        let slices = self.slices(&epoch)?;
        let dealt = self.dealings(&epoch, &slices)?;
        let deal_micros = deal_start.elapsed().as_micros();

        let seal_start = Instant::now();
        let quorum = self.validators.committee.quorum();
        let mut votes = Vec::<Vote>::with_capacity(quorum);
        let mut dealings = Vec::<SealedDealing<Key, Digest>>::with_capacity(quorum);
        for (index, dealing) in dealt.into_iter().take(quorum).enumerate() {
            let scheme = self.validators.signer(Participant::from_usize(index))?;
            let (vote, sealed) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &epoch.context,
                &self.operator_ack_key,
                &epoch.deposits,
                &epoch.withdrawals,
                &epoch.prepared.close().header,
                &epoch.prepared.close().roots,
                epoch.hydrate(dealing)?,
                rng,
                &self.strategy,
            )
            .context("validator failed to seal its dealing")?;
            votes.push(vote);
            dealings.push(sealed);
        }
        let assembler = self.validators.signer(Participant::new(0))?;
        let certificate = assembler
            .assemble_exact(votes)
            .context("assemble exact-quorum certificate")?;
        let seal_micros = seal_start.elapsed().as_micros();

        let dealing_slices = dealings.iter().map(|dealing| dealing.slices().len()).sum();
        retain(
            &mut RETAINED.lock(),
            RetainedClose {
                context: epoch.context.clone(),
                withdrawals: epoch.withdrawals.clone(),
                header: epoch.prepared.close().header,
                roots: epoch.prepared.close().roots,
                dealings: dealings.clone(),
            },
        );
        let mut result = self.certify(
            epoch,
            slices.len(),
            dealing_slices,
            certificate,
            deal_micros,
            seal_micros,
        )?;
        result.dealings = dealings;
        Ok(result)
    }

    /// Completes a prepared close from an exact-quorum certificate: verifies
    /// the certificate over the close header, assembles the terminal proof
    /// and claims, and rehearses the exact settlement transition before
    /// anything is published.
    pub(crate) fn certify(
        &self,
        epoch: PreparedEpoch,
        slices: usize,
        dealing_slices: usize,
        certificate: bls12381::Certificate,
        deal_micros: u128,
        seal_micros: u128,
    ) -> Result<SettlementResult> {
        let PreparedEpoch {
            context,
            deposits,
            withdrawals,
            deposit_events,
            predecessor,
            partition: _,
            prepared,
            prepare_micros,
        } = epoch;
        let epoch = context.payment().epoch();
        ensure!(
            self.verifier()
                .verify_exact(&prepared.close().header, &certificate),
            "assembled certificate failed verification"
        );

        let terminal_proof = prepared
            .terminal_proof()
            .context("assemble terminal settlement proof")?;
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
                    .withdrawal_claim(&withdrawals, request.account())
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
            &predecessor,
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
        let extra_openings = withdrawals
            .requests()
            .iter()
            .map(|request| {
                predecessor
                    .opening(request.account())
                    .context("open carried withdrawal account")
            })
            .collect::<Result<Vec<_>>>()?;
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
                terminal_proof.clone(),
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
        Ok(SettlementResult {
            epoch,
            predecessor_root: *context.predecessor_root(),
            epoch_context: context.epoch_context().clone(),
            deposits,
            withdrawals,
            payment_context: context.payment().clone(),
            header,
            roots,
            certificate,
            terminal_proof,
            external_claims,
            withdrawal_claims,
            finalized,
            rows,
            slices,
            dealing_slices,
            dealings: Vec::new(),
            prepare_micros,
            deal_micros,
            seal_micros,
        })
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
pub(crate) fn omitting_close<R: CryptoRng>(
    rng: &mut R,
    admission_deadline: u64,
    challenge_deadline: u64,
) -> Result<OmittingClose> {
    let protocol = Protocol::new(NonZeroUsize::MIN)?;
    let wallets = wallets();
    let payer = &wallets[0];
    let receiver = wallets[1].public_key();
    let bystander = wallets[2].public_key();
    let held_credit = 5;

    let mut predecessor = identities()
        .into_iter()
        .map(|identity| StateLeaf {
            account: identity.key,
            state: AccountState {
                balance: INITIAL_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    predecessor.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    let state =
        StateCache::new::<Sha256>(predecessor.clone()).context("commit fraud predecessor state")?;
    let (deposit, deposits) = omitting_boundary()?;
    let bystander_state = predecessor
        .iter()
        .find(|leaf| leaf.account == bystander)
        .context("fraud bystander is not in genesis")?
        .state;
    let bystander_successor = AccountState {
        balance: bystander_state.balance + 1,
        ..bystander_state
    };
    let row = AccountRow {
        account: bystander.clone(),
        predecessor: bystander_state,
        successor: bystander_successor,
        outgoing: None,
        output: SettlementOutput::None,
        prefix: Prefix {
            deposit: 1,
            ..Prefix::default()
        },
    };
    let mut successor = predecessor;
    successor
        .iter_mut()
        .find(|leaf| leaf.account == bystander)
        .context("fraud bystander is not in genesis")?
        .state = bystander_successor;
    let registration = protocol.registration_at(
        0,
        deposits,
        WithdrawalBatch::empty(),
        400,
        admission_deadline,
        challenge_deadline,
    )?;
    let prepared = protocol.prepare(
        registration,
        vec![deposit],
        state.leaves().to_vec(),
        vec![row],
        vec![OutVector::empty(0, bystander)],
        vec![None],
        Vec::new(),
        successor,
    )?;

    // The omitting close excludes the paying sender entirely, so its composed lookup is an
    // ordered change-vector absence and the public terminal entry resolves to zero.
    let index = ChallengeIndex::new::<Sha256>(prepared.close_context(), prepared.close())
        .context("index the omitting close")?;
    let held_lookup =
        higher_entry_lookup::<Sha256, _, _>(&index, &payer.public_key(), None, &receiver)
            .context("compose the omitted sender lookup")?;
    let result = protocol.complete(prepared, rng)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A retained close for `epoch` of `deployment` with nothing dealt: the
    /// retention rule reads only the bound context.
    fn retained_close(deployment: Digest, epoch: u64) -> RetainedClose {
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let cache = AccountCache::new::<Sha256>(Vec::new()).unwrap();
        let (admission_deadline, challenge_deadline) = deadlines(epoch).unwrap();
        let context = epoch_context_at(
            deployment,
            operator_key(),
            epoch,
            &deposits,
            &withdrawals,
            0,
            admission_deadline,
            challenge_deadline,
        )
        .unwrap()
        .bind::<Sha256>(&cache, &deposits, &withdrawals)
        .unwrap();
        let root = VectorRoot {
            digest: Sha256::hash(&[b"retained-close", &epoch.to_be_bytes()]),
        };
        let roots = RootBundle {
            change: root,
            withdrawal_outputs: root,
            successor: root,
            coverage: root,
            transpose: root,
            transpose_len: 0,
        };
        RetainedClose {
            header: Header::new::<Sha256, Key>(&context, &roots),
            context,
            withdrawals,
            roots,
            dealings: Vec::new(),
        }
    }

    #[test]
    fn retained_closes_are_bounded_per_deployment() {
        let epochs = |retained: &[Arc<RetainedClose>], deployment: &Digest| {
            retained
                .iter()
                .filter(|close| close.context.deployment() == deployment)
                .map(|close| close.context.payment().epoch())
                .collect::<Vec<_>>()
        };
        let other = Sha256::hash(&[b"other-deployment"]);
        let mut retained = Vec::new();
        retain(&mut retained, retained_close(other, 0));
        for epoch in 0..=Operator::RETAINED_EPOCHS + 1 {
            retain(&mut retained, retained_close(deployment(), epoch));
        }

        // Pushing past the window evicts the deployment's oldest closes and
        // leaves the other deployment's alone.
        assert_eq!(
            epochs(&retained, &deployment()),
            (2..=Operator::RETAINED_EPOCHS + 1).collect::<Vec<_>>()
        );
        assert_eq!(epochs(&retained, &other), vec![0]);
        assert_eq!(
            retained.len(),
            usize::try_from(Operator::RETAINED_EPOCHS).unwrap() + 1
        );
    }
}
