//! Concrete protocol wiring for the operator.

use anyhow::{Context, Result, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_clearing::bajillion::{
    admission::{Committee, SealedDealing, Vote, assigned_slice_indices, bls12381, seal},
    boundary::{DepositBatch, DepositRecord, WithdrawalAction, WithdrawalBatch},
    challenge::HigherShardTipLookup,
    commitment::VectorRoot,
    credit::ShardSet,
    payment::{MAX_ENTRIES, PaymentContext, SignedReceipt, SignedSend, verify_acceptance},
    settlement::{EpochDeadlinePolicy, FinalizedBatch, SettlementChain, SettlementConfig},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        Assignment, ChallengeIndex, CloseContext, CloseLimits, EpochContext, ExternalPayoutClaim,
        Header, PreparedClose, ProofSlice, RootBundle, StateCache, WithdrawalClaim,
        prepare_close_with_strategy,
    },
};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, Signature, SigningKey, StrictVerifyingKey,
};
use commonware_parallel::Rayon;
use commonware_utils::Participant;
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Instant,
};

pub(crate) type Key = StrictVerifyingKey;
pub(crate) type Payment = commonware_clearing::bajillion::payment::Payment<Key, Digest>;
pub(crate) type AccountCache = StateCache<Key, Digest>;

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
const VALIDATORS: usize = 4;
const SLICE_BITS: u8 = 2;

/// Maximum proof slices one close partitions into, and so the most slices one
/// validator dealing can carry.
pub(crate) const MAX_SLICES: usize = 1 << SLICE_BITS;
pub(crate) const MAX_ACCOUNTS: usize = 1_024;
/// Maximum accepted payments in one epoch, counting one per batched-send entry.
pub(crate) const MAX_ACCEPTED_PAYMENTS: usize = 1_024;
/// Bounds one encoded linked payment: a batch send at the protocol entry limit plus one receipt.
pub(crate) const MAX_PAYMENT_BYTES: usize = 12 * 1024;
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
const DEPOSIT_INCLUSION_TIMEOUT: u64 = 100;
const MINIMUM_WITHDRAWAL_NOTICE: u64 = 4;
const MAXIMUM_WITHDRAWAL_NOTICE: u64 = 100;

// The default deadline geometry, in blocks: a registration gets a ten-block
// admission runway from its inclusion height and one inclusive challenge
// block. Setup writes these defaults into a new chain's genesis, where the
// timing policy is fixed for the chain's life and applied to every
// configured deployment. On the chain-facing
// flow that genesis policy is the authority end to end: execution assigns
// each registration's deadlines from it and the close worker's rehearsal
// derives its challenge duration from the adopted pair, so the consts bind
// only the deterministic placeholder grid that pre-registration contexts are
// staged under and the fixture harness that runs on that grid. Deposit and
// withdrawal deadlines remain independent obligations and may permanently
// fault an admitted close before that point.
const ADMISSION_OFFSET: u64 = 10;
const CHALLENGE_DURATION: u64 = 1;
const CHALLENGE_OFFSET: u64 = ADMISSION_OFFSET + CHALLENGE_DURATION;
const EPOCH_STRIDE: u64 = CHALLENGE_OFFSET + 1;

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
    /// The compiled defaults setup writes into a new chain's genesis.
    pub(crate) const DEFAULT: Self = Self {
        admission_offset: ADMISSION_OFFSET,
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

/// One accepted send: the signed batch and one operator receipt per entry, in entry order.
///
/// This is the shape the wire and both SQLite stores share. The send is carried once. Per-entry
/// [`Payment`] pairs are reassembled where linked evidence is needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Acceptance {
    pub(crate) send: SignedSend<Key, Digest>,
    pub(crate) receipts: Vec<SignedReceipt<Key, Digest>>,
}

impl Acceptance {
    /// Verifies every linked entry pair and that the receipts cover the entries in entry order.
    pub(crate) fn verify(&self, context: &PaymentContext<Key, Digest>) -> Result<()> {
        ensure!(
            self.receipts.len() == self.send.body().entries().len(),
            "acceptance does not cover every send entry"
        );

        // Entries are strictly recipient-sorted and unique, so positional recipient equality
        // proves the receipts cover every entry exactly once.
        for (receipt, entry) in self.receipts.iter().zip(self.send.body().entries()) {
            ensure!(
                receipt.body().recipient() == entry.recipient(),
                "acceptance receipts are not in entry order"
            );
        }
        verify_acceptance::<Sha256, _, _>(context, &self.send, &self.receipts)
            .context("verify acceptance receipt")
    }

    /// Reassembles one transferable linked pair per entry.
    #[cfg(test)]
    pub(crate) fn payments(&self) -> impl Iterator<Item = Payment> + '_ {
        self.receipts
            .iter()
            .map(|receipt| Payment::from_parts_unchecked(self.send.clone(), receipt.clone()))
    }
}

impl Write for Acceptance {
    fn write(&self, buf: &mut impl BufMut) {
        self.send.write(buf);
        self.receipts.write(buf);
    }
}

impl EncodeSize for Acceptance {
    fn encode_size(&self) -> usize {
        self.send.encode_size() + self.receipts.encode_size()
    }
}

impl Read for Acceptance {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            send: SignedSend::read(buf)?,
            receipts: Vec::<SignedReceipt<Key, Digest>>::read_cfg(
                buf,
                &(RangeCfg::new(1..=MAX_ENTRIES), ()),
            )?,
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
    pub(crate) accounts: Vec<Account>,
}

impl Deployment {
    pub(crate) fn new(operator: Key, accounts: Vec<Account>) -> Self {
        Self {
            digest: deployment_of(&operator),
            operator,
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
    vec![Deployment::new(operator_key(), accounts())]
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
    validators: Validators,
    strategy: Rayon,
}

impl Protocol {
    /// Protocol machinery for the compiled default deployment (the seed-0
    /// demo operator): the fixture and harness path.
    pub(crate) fn new(workers: NonZeroUsize) -> Result<Self> {
        Self::with_signer(workers, operator_signer(0))
    }

    /// Protocol machinery for the deployment `operator` runs: the deployment
    /// digest derives from the signing identity.
    pub(crate) fn with_signer(workers: NonZeroUsize, operator: SigningKey) -> Result<Self> {
        Ok(Self {
            deployment: deployment_of(&operator.public_key()),
            operator,
            validators: Validators::new()?,
            strategy: Rayon::new(workers).context("create clearing worker pool")?,
        })
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

    pub(crate) fn prepare(
        &self,
        registration: EpochRegistration,
        deposit_events: Vec<DepositEvent>,
        predecessor: Vec<StateLeaf<Key>>,
        rows: Vec<AccountRow<Key, Digest>>,
        shard_sets: Vec<ShardSet<Key, Digest>>,
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
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &predecessor,
            &context,
            &registration.deposits,
            &registration.withdrawals,
            rows,
            shard_sets,
            &self.strategy,
        )
        .context("prepare close")?;
        prepared
            .validate::<Sha256, PaymentBatchVerifier, _>(
                &context,
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

        Ok(PreparedEpoch {
            context,
            deposits: registration.deposits,
            withdrawals: registration.withdrawals,
            deposit_events,
            predecessor,
            prepared,
            prepare_micros,
        })
    }

    /// Assembles the canonical proof slices of a prepared close.
    ///
    /// The distributed close worker disseminates these per-validator over the
    /// settlement DA channel. The harness seals them in process instead.
    pub(crate) fn slices(&self, epoch: &PreparedEpoch) -> Result<Vec<ProofSlice<Key, Digest>>> {
        epoch
            .prepared
            .assemble_slices(&epoch.predecessor, &self.strategy)
            .context("assemble proof slices")
    }

    /// Splits assembled slices into each committee member's exact dealing, in
    /// committee participant order.
    pub(crate) fn dealings(
        &self,
        epoch: &PreparedEpoch,
        slices: &[ProofSlice<Key, Digest>],
    ) -> Result<Vec<Vec<ProofSlice<Key, Digest>>>> {
        (0..self.validators.committee.members().len())
            .map(|index| {
                let validator = Participant::from_usize(index);
                let assigned = assigned_slice_indices::<Sha256, _>(
                    &self.validators.committee,
                    epoch.context.assignment(),
                    validator,
                )
                .context("derive validator dealing")?;
                assigned
                    .iter()
                    .map(|slice| {
                        slices
                            .get(usize::from(*slice))
                            .cloned()
                            .context("assigned slice is missing from the assembled set")
                    })
                    .collect()
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
        let deal_micros = deal_start.elapsed().as_micros();

        let seal_start = Instant::now();
        let mut votes = Vec::<Vote>::with_capacity(self.validators.committee.quorum());
        let mut dealings =
            Vec::<SealedDealing<Key, Digest>>::with_capacity(self.validators.committee.quorum());
        for index in 0..self.validators.committee.quorum() {
            let validator = Participant::from_usize(index);
            let scheme = self.validators.signer(validator)?;
            let assigned = assigned_slice_indices::<Sha256, _>(
                &self.validators.committee,
                epoch.context.assignment(),
                validator,
            )
            .context("derive validator dealing")?;
            let dealing = assigned
                .iter()
                .map(|slice| slices[usize::from(*slice)].clone())
                .collect();
            let (vote, sealed) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &epoch.context,
                &epoch.deposits,
                &epoch.withdrawals,
                &epoch.prepared.close().header,
                &epoch.prepared.close().roots,
                dealing,
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
                    .withdrawal_claim::<Sha256>(&withdrawals, request.account())
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
        let config = settlement_config(&Timing {
            admission_offset: ADMISSION_OFFSET,
            challenge_duration,
        });
        let mut chain = SettlementChain::<Sha256, Key>::new(
            self.deployment,
            self.operator.public_key(),
            self.validators.committee.clone(),
            &predecessor,
            epoch,
            config,
        )
        .context("construct settlement chain")?;

        // Rehearse at a registration height within the compiled admission
        // offset of the admission deadline. The policy above bounds the
        // admission delay by at least that offset, so the rehearsal accepts
        // both grid placeholders and chain-assigned deadlines whatever the
        // deployment's genesis admission offset.
        let now = context
            .admission_deadline()
            .saturating_sub(ADMISSION_OFFSET);
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
/// credits a deposit to a bystander account, so the omitted receiver is absent from its change
/// vector, mirroring how the challenge tests build an inconsistent close. The held pair is a
/// valid operator-signed receipt crediting the receiver under the same epoch context, so it
/// convicts the close with a `HigherShardTip` challenge.
pub(crate) struct OmittingClose {
    pub(crate) result: SettlementResult,
    pub(crate) receiver: Key,
    pub(crate) held_credit: u64,
    pub(crate) held_pair: Payment,
    pub(crate) held_lookup: HigherShardTipLookup<Key, Digest>,
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
        vec![ShardSet::empty(0, bystander)],
        successor,
    )?;

    // The omitting close excludes the receiver, so its composed lookup is an ordered absence.
    let index = ChallengeIndex::new::<Sha256>(prepared.close_context(), prepared.close())
        .context("index the omitting close")?;
    let held_lookup = index
        .higher_shard_tip_lookup::<Sha256>(&receiver, None, 0)
        .context("compose the omitted receiver lookup")?;
    let result = protocol.complete(prepared, rng)?;
    let context = result.payment_context.clone();

    // The receiver holds an operator-signed receipt crediting it under the same epoch context.
    let send = SignedSend::sign_next(&context, payer.signer(), receiver.clone(), held_credit, 0)
        .context("sign the omitted receiver's send")?;
    let receipt = SignedReceipt::issue_next::<Sha256, _>(
        &context,
        &send,
        &receiver,
        0,
        0,
        0,
        protocol.operator(),
    )
    .context("issue the omitted receiver's receipt")?;
    Ok(OmittingClose {
        result,
        receiver,
        held_credit,
        held_pair: Payment::from_parts_unchecked(send, receipt),
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
