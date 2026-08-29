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
        Header, PreparedClose, RootBundle, StateCache, WithdrawalClaim,
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
const REGISTRATION_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_EPOCH_REGISTRATION";
const VALIDATOR_SEED_START: u64 = 10_000;
const VALIDATORS: usize = 4;
const SLICE_BITS: u8 = 2;
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

// Each epoch gets ten admission ticks and one inclusive challenge tick. The next epoch begins on
// the first tick at which its predecessor can finalize. Deposit and withdrawal deadlines remain
// independent obligations and may permanently fault an admitted close before that point.
const ADMISSION_OFFSET: u64 = 10;
const CHALLENGE_DURATION: u64 = 1;
const CHALLENGE_OFFSET: u64 = ADMISSION_OFFSET + CHALLENGE_DURATION;
const EPOCH_STRIDE: u64 = CHALLENGE_OFFSET + 1;

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
/// This is the shape the wire and both SQLite stores share. The send is carried once; per-entry
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

pub(crate) fn deployment() -> Digest {
    Sha256::hash(&[DEPLOYMENT_NAMESPACE])
}

pub(crate) fn operator_key() -> Key {
    SigningKey::from_seed(1).public_key()
}

fn registration_message(
    epoch: u64,
    predecessor_liability: u64,
    deposits_root: &VectorRoot<Digest>,
    staged_root: &VectorRoot<Digest>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
) -> Bytes {
    let mut message = BytesMut::with_capacity(
        epoch.encode_size()
            + predecessor_liability.encode_size()
            + deposits_root.encode_size()
            + staged_root.encode_size()
            + withdrawals.encode_size(),
    );
    epoch.write(&mut message);
    predecessor_liability.write(&mut message);
    deposits_root.write(&mut message);
    staged_root.write(&mut message);
    withdrawals.write(&mut message);
    message.freeze()
}

pub(crate) fn verify_registration_signature(
    epoch: u64,
    predecessor_liability: u64,
    deposits_root: &VectorRoot<Digest>,
    staged_root: &VectorRoot<Digest>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    signature: &Signature,
) -> bool {
    operator_key().verify(
        REGISTRATION_SIGNATURE_NAMESPACE,
        &registration_message(
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

pub(crate) const fn settlement_config() -> SettlementConfig {
    SettlementConfig::new(
        NonZeroUsize::new(4).expect("pipeline bound is nonzero"),
        EpochDeadlinePolicy::new(
            NonZeroU64::new(EPOCH_STRIDE).expect("admission delay is nonzero"),
            NonZeroU64::new(CHALLENGE_DURATION).expect("minimum challenge duration is nonzero"),
            NonZeroU64::new(CHALLENGE_DURATION).expect("maximum challenge duration is nonzero"),
        ),
        NonZeroU64::new(DEPOSIT_INCLUSION_TIMEOUT).expect("deposit timeout is nonzero"),
        NonZeroU64::new(MINIMUM_WITHDRAWAL_NOTICE).expect("notice is nonzero"),
        NonZeroU64::new(MAXIMUM_WITHDRAWAL_NOTICE).expect("notice is nonzero"),
        256,
        NonZeroUsize::new(MAX_DEPOSIT_EVENTS).expect("deposit bound is nonzero"),
    )
}

pub(crate) fn epoch_context(
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    predecessor_liability: u64,
) -> Result<EpochContext<Key, Digest>> {
    let (admission_deadline, challenge_deadline) = deadlines(epoch)?;
    let limits = CloseLimits::new(
        MAX_ACCOUNTS as u64,
        MAX_ROWS,
        MAX_ACCOUNTS as u64,
        MAX_SHARDS,
        MAX_SHARDS,
        SQLITE_U64_MAX,
        SQLITE_U64_MAX,
        SQLITE_U64_MAX,
    );
    EpochContext::new::<Sha256>(
        deployment(),
        epoch,
        operator_key(),
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
    pub(crate) fn new(workers: NonZeroUsize) -> Result<Self> {
        Ok(Self {
            deployment: deployment(),
            operator: SigningKey::from_seed(1),
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

    pub(crate) fn sign_registration(
        &self,
        epoch: u64,
        predecessor_liability: u64,
        deposits_root: &VectorRoot<Digest>,
        staged_root: &VectorRoot<Digest>,
        withdrawals: &WithdrawalBatch<Key, Digest>,
    ) -> Signature {
        self.operator.sign(
            REGISTRATION_SIGNATURE_NAMESPACE,
            &registration_message(
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
        let context = epoch_context(epoch, &deposits, &withdrawals, predecessor_liability)?;
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

    pub(crate) fn complete<R: CryptoRng>(
        &self,
        epoch: PreparedEpoch,
        rng: &mut R,
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

        let deal_start = Instant::now();
        let slices = prepared
            .assemble_slices(&predecessor, &self.strategy)
            .context("assemble proof slices")?;
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
                context.assignment(),
                validator,
            )
            .context("derive validator dealing")?;
            let dealing = assigned
                .iter()
                .map(|slice| slices[usize::from(*slice)].clone())
                .collect();
            let (vote, sealed) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &scheme,
                &context,
                &deposits,
                &withdrawals,
                &prepared.close().header,
                &prepared.close().roots,
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
        let verifier = bls12381::Scheme::verifier(self.validators.committee.clone());
        ensure!(
            verifier.verify_exact(&prepared.close().header, &certificate),
            "assembled certificate failed verification"
        );
        let seal_micros = seal_start.elapsed().as_micros();

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
        let config = settlement_config();
        let mut chain = SettlementChain::<Sha256, Key>::new(
            self.deployment,
            self.operator.public_key(),
            self.validators.committee.clone(),
            &predecessor,
            epoch,
            config,
        )
        .context("construct settlement chain")?;
        let now = epoch_start(epoch)?;
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
        let dealing_slices = dealings.iter().map(|dealing| dealing.slices().len()).sum();
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
            slices: slices.len(),
            dealing_slices,
            dealings,
            prepare_micros,
            deal_micros,
            seal_micros,
        })
    }
}

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

/// A committed close that omits one recipient's credit, plus that recipient's held receipt.
///
/// This is the demo's fraud construction, kept out of the honest operator binary. The close
/// credits a deposit to a bystander account, so the omitted recipient is absent from its change
/// vector, mirroring how the challenge tests build an inconsistent close. The held pair is a
/// valid operator-signed receipt crediting the recipient under the same epoch context, so it
/// convicts the close with a `HigherShardTip` challenge.
pub(crate) struct OmittingClose {
    pub(crate) deposit: DepositEvent,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) result: SettlementResult,
    pub(crate) recipient: Key,
    pub(crate) held_credit: u64,
    pub(crate) held_pair: Payment,
    pub(crate) held_lookup: HigherShardTipLookup<Key, Digest>,
}

/// Builds an omitting close over epoch 0: Alice's operator-signed receipt credits Bob, but the
/// admitted close instead credits a deposit to Carol and omits Bob entirely.
pub(crate) fn omitting_close<R: CryptoRng>(rng: &mut R) -> Result<OmittingClose> {
    let protocol = Protocol::new(NonZeroUsize::MIN)?;
    let wallets = wallets();
    let payer = &wallets[0];
    let recipient = wallets[1].public_key();
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
    let deposit = DepositEvent {
        id: Sha256::hash(&[b"_COMMONWARE_EXAMPLES_TERMINAL_OMITTING_CLOSE"]),
        account: bystander.clone(),
        amount: 1,
    };
    let deposits = DepositBatch::new(vec![DepositRecord::new(bystander.clone(), 1)?])?;
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
    let registration = protocol.registration(0, deposits.clone(), WithdrawalBatch::empty(), 400)?;
    let prepared = protocol.prepare(
        registration,
        vec![deposit.clone()],
        state.leaves().to_vec(),
        vec![row],
        vec![ShardSet::empty(0, bystander)],
        successor,
    )?;

    // The omitting close excludes the recipient, so its composed lookup is an ordered absence.
    let index = ChallengeIndex::new::<Sha256>(prepared.close_context(), prepared.close())
        .context("index the omitting close")?;
    let held_lookup = index
        .higher_shard_tip_lookup::<Sha256>(&recipient, None, 0)
        .context("compose the omitted recipient lookup")?;
    let result = protocol.complete(prepared, rng)?;
    let context = result.payment_context.clone();

    // The recipient holds an operator-signed receipt crediting it under the same epoch context.
    let send = SignedSend::sign_next(&context, payer.signer(), recipient.clone(), held_credit, 0)
        .context("sign the omitted recipient's send")?;
    let receipt = SignedReceipt::issue_next::<Sha256, _>(
        &context,
        &send,
        &recipient,
        0,
        0,
        0,
        protocol.operator(),
    )
    .context("issue the omitted recipient's receipt")?;
    Ok(OmittingClose {
        deposit,
        deposits,
        result,
        recipient,
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
