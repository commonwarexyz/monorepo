//! Concrete protocol wiring for the operator.

use anyhow::{Context, Result, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_clearing::bajillion::{
    admission::{Committee, RetainedAssignment, Vote, assigned_slice_indices, bls12381, seal},
    boundary::{DepositBatch, WithdrawalBatch},
    credit::ShardSet,
    settlement::{FinalizedBatch, SettlementChain, SettlementConfig},
    state::{AccountRow, StateLeaf},
    transition::{
        Assignment, CloseContext, CloseLimits, EpochContext, ExternalPayoutClaim, Header,
        PreparedClose, RootBundle, StateCache, WithdrawalClaim, prepare_close_with_strategy,
    },
};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
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
const FREEZE_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_FREEZE";
const VALIDATOR_SEED_START: u64 = 10_000;
const VALIDATORS: usize = 4;
const SLICE_BITS: u8 = 2;
const MAX_ACCOUNTS: usize = 1_024;
/// Maximum distinct payments accepted into one epoch.
pub(crate) const MAX_ACCEPTED_PAYMENTS: usize = 1_024;
pub(crate) const MAX_DEPOSIT_EVENTS: usize = MAX_ACCOUNTS;
pub(crate) const MAX_WITHDRAWALS: usize = MAX_ACCOUNTS;
const MAX_ROWS: u64 = 1_024;
const MAX_SHARDS: u64 = 1_024;
pub(crate) const INITIAL_BALANCE: u64 = 100;
/// Largest monetary value that the SQLite operator can persist exactly.
pub(crate) const SQLITE_U64_MAX: u64 = i64::MAX as u64;

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
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) context: EpochContext<Key, Digest>,
}

/// Root-complete close ready for background dealing and sealing.
pub(crate) struct PreparedEpoch {
    context: CloseContext<Key, Digest>,
    deposits: DepositBatch<Key>,
    withdrawals: WithdrawalBatch<Key, Digest>,
    deposit_events: Vec<DepositEvent>,
    opening: AccountCache,
    prepared: PreparedClose<Key, Digest>,
    prepare_micros: u128,
}

impl PreparedEpoch {
    #[cfg(test)]
    pub(crate) const fn epoch(&self) -> u64 {
        self.context.payment().epoch()
    }
}

/// Artifacts and metrics held through one clean finalization.
pub(crate) struct SettlementResult {
    pub(crate) epoch: u64,
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
    pub(crate) withdrawal_claims: Vec<WithdrawalClaim<Key, Digest>>,
    pub(crate) finalized: FinalizedBatch<Digest>,
    pub(crate) rows: usize,
    pub(crate) slices: usize,
    pub(crate) retained_slices: usize,
    retained: Vec<RetainedAssignment<Key, Digest>>,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

impl SettlementResult {
    /// Releases validator-owned evidence after settlement has completed finalization.
    pub(crate) fn release_dealings(&mut self) {
        self.retained.clear();
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
            .context("validator index is in committee")?
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

fn freeze_message(
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
) -> Bytes {
    let mut message = BytesMut::with_capacity(
        epoch.encode_size() + deposits.encode_size() + withdrawals.encode_size(),
    );
    epoch.write(&mut message);
    deposits.write(&mut message);
    withdrawals.write(&mut message);
    message.freeze()
}

pub(crate) fn verify_freeze_signature(
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    signature: &Signature,
) -> bool {
    operator_key().verify(
        FREEZE_SIGNATURE_NAMESPACE,
        &freeze_message(epoch, deposits, withdrawals),
        signature,
    )
}

pub(crate) fn committee() -> Result<Committee> {
    Ok(Validators::new()?.committee)
}

pub(crate) fn assignment() -> Result<Assignment<Digest>> {
    Assignment::new(committee()?.commitment::<Sha256>(), SLICE_BITS)
        .context("construct operator slice assignment")
}

pub(crate) const fn settlement_config() -> SettlementConfig {
    SettlementConfig::new(
        NonZeroUsize::new(4).expect("pipeline bound is nonzero"),
        NonZeroU64::new(4).expect("notice is nonzero"),
        NonZeroU64::new(100).expect("notice is nonzero"),
        NonZeroUsize::new(MAX_ACCOUNTS).expect("account bound is nonzero"),
        256,
        NonZeroUsize::new(MAX_DEPOSIT_EVENTS).expect("deposit bound is nonzero"),
        NonZeroUsize::new(MAX_ACCOUNTS).expect("claim-batch bound is nonzero"),
    )
}

pub(crate) fn epoch_context(
    epoch: u64,
    deposits: &DepositBatch<Key>,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    opening_liability: u64,
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
        opening_liability,
        admission_deadline,
        challenge_deadline,
        limits,
        assignment()?,
    )
    .context("construct epoch registration")
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

    pub(crate) fn sign_freeze(
        &self,
        epoch: u64,
        deposits: &DepositBatch<Key>,
        withdrawals: &WithdrawalBatch<Key, Digest>,
    ) -> Signature {
        self.operator.sign(
            FREEZE_SIGNATURE_NAMESPACE,
            &freeze_message(epoch, deposits, withdrawals),
        )
    }

    pub(crate) fn registration(
        &self,
        epoch: u64,
        deposits: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
        opening_liability: u64,
    ) -> Result<EpochRegistration> {
        let context = epoch_context(epoch, &deposits, &withdrawals, opening_liability)?;
        ensure!(
            context.deployment() == &self.deployment
                && context.payment().operator() == &self.operator.public_key()
                && context.assignment() == &self.validators.assignment()?,
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
        deposit_events: Vec<DepositEvent>,
        opening: Vec<StateLeaf<Key>>,
        rows: Vec<AccountRow<Key, Digest>>,
        shard_sets: Vec<ShardSet<Key, Digest>>,
        closing: Vec<StateLeaf<Key>>,
    ) -> Result<PreparedEpoch> {
        ensure!(!rows.is_empty(), "there is nothing to settle");
        let prepare_start = Instant::now();
        let opening = StateCache::new_with_strategy::<Sha256>(opening, &self.strategy)
            .context("commit opening account state")?;
        let context = registration
            .context
            .bind::<Sha256>(&opening, &registration.deposits, &registration.withdrawals)
            .context("bind epoch registration to its opening state")?;
        let closing = StateCache::new_with_strategy::<Sha256>(closing, &self.strategy)
            .context("commit projected closing state")?;
        let closing_root = closing.root();
        let prepared = prepare_close_with_strategy::<Sha256, _, _>(
            &opening,
            &context,
            &registration.deposits,
            &registration.withdrawals,
            rows,
            shard_sets,
            &self.strategy,
        )
        .context("prepare close")?;
        prepared
            .validate::<Sha256>(&context, &registration.deposits, &registration.withdrawals)
            .context("validate prepared close")?;
        ensure!(
            prepared.close().roots.closing == closing_root,
            "prepared close does not match SQLite closing state"
        );
        let prepare_micros = prepare_start.elapsed().as_micros();

        Ok(PreparedEpoch {
            context,
            deposits: registration.deposits,
            withdrawals: registration.withdrawals,
            deposit_events,
            opening,
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
            opening,
            prepared,
            prepare_micros,
        } = epoch;
        let epoch = context.payment().epoch();

        let deal_start = Instant::now();
        let slices = prepared
            .assemble_slices(&opening, &self.strategy)
            .context("assemble proof slices")?;
        let deal_micros = deal_start.elapsed().as_micros();

        let seal_start = Instant::now();
        let mut votes = Vec::<Vote>::with_capacity(self.validators.committee.quorum());
        let mut retained = Vec::<RetainedAssignment<Key, Digest>>::with_capacity(
            self.validators.committee.quorum(),
        );
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
            let (vote, assignment) = seal::<Sha256, _, _, PaymentBatchVerifier, _>(
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
            retained.push(assignment);
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
            .filter(|row| !row.opening.active && deposits.amount_for(&row.account) == 0)
            .map(|row| {
                prepared
                    .external_payout_claim(&row.account)
                    .context("assemble external payout claim")
            })
            .collect::<Result<Vec<_>>>()?;
        let withdrawal_claims = withdrawals
            .requests()
            .iter()
            .map(|request| {
                prepared
                    .withdrawal_claim::<Sha256>(&withdrawals, request.account())
                    .context("assemble withdrawal claim")
            })
            .collect::<Result<Vec<_>>>()?;

        // Rehearse the exact settlement transition before publishing it. The authoritative
        // settlement repeats this bounded check and controls whether the result becomes durable.
        let config = settlement_config();
        let mut chain = SettlementChain::<Sha256, Key>::new(
            self.deployment,
            self.operator.public_key(),
            self.validators.committee.clone(),
            &opening,
            epoch,
            config,
        )
        .context("construct settlement chain")?;
        let now = epoch.checked_mul(10).context("epoch clock overflow")?;
        for event in &deposit_events {
            chain
                .record_deposit(now, event.id, event.account.clone(), event.amount)
                .context("record deposit in settlement chain")?;
        }
        for request in withdrawals.requests() {
            let account_opening = opening
                .opening(request.account())
                .context("open withdrawing account")?;
            chain
                .queue_withdrawal(now, request.clone(), &[account_opening], |_| true)
                .context("queue withdrawal in settlement chain")?;
        }
        chain
            .register(now, context.clone(), deposits.clone(), withdrawals.clone())
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
            finalized.closing_state_root == prepared.close().roots.closing,
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
        let retained_slices = retained
            .iter()
            .map(|assignment| assignment.slices().len())
            .sum();
        Ok(SettlementResult {
            epoch,
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
            retained_slices,
            retained,
            prepare_micros,
            deal_micros,
            seal_micros,
        })
    }
}

fn deadlines(epoch: u64) -> Result<(u64, u64)> {
    let base = epoch.checked_mul(10).context("epoch clock overflow")?;
    Ok((
        base.checked_add(1).context("admission deadline overflow")?,
        base.checked_add(2).context("challenge deadline overflow")?,
    ))
}

pub(crate) fn short_digest(digest: &Digest) -> String {
    digest
        .as_ref()
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn encoded_artifacts(result: &SettlementResult) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        result.header.encode().to_vec(),
        result.roots.encode().to_vec(),
        result.certificate.encode().to_vec(),
    )
}
