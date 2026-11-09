//! End-to-end tests of Bajillion, run against reference implementations of its five roles.
//!
//! The roles here are built from the crate's public API alone. They show that a deployment can
//! build every role, and each keeps that role's obligations.

mod roles {
    pub mod ledger;
    pub mod operator;
    pub mod receiver;
    pub mod sender;
    pub mod validator;
}

mod ledger;
mod lifecycle;
mod model;
mod operator;
mod payments;
mod validator;

use commonware_clearing::bajillion::{
    Amount, Amounts, Close, Deposit, Epoch, Limits, Namespace, Proposal, Queue, Row, Signatures,
    State, Summary, Withdrawal,
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, Signer, certificate,
    ed25519::{PrivateKey, PublicKey, certificate::mocks},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::full::Config as MerkleConfig,
    qmdb::{current::unordered::fixed, keyless},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty, test_rng};
use roles::{
    ledger::Ledger,
    operator::Operator,
    receiver::Receiver,
    sender::Sender,
    validator::{Config, Persisted, Validator},
};

/// Namespace of the deployment under test.
const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_TEST";

/// Close limits large enough not to constrain any test that uses them.
const LIMITS: Limits = Limits {
    rows: 1_024,
    receivers: 1_024,
    withdrawals: 1_024,
};

/// Ed25519 certificates over summaries from at least `2f + 1` of `3f + 1` validators.
// The macro gates its fixture on a `mocks` feature that this crate does not define.
#[allow(unexpected_cfgs)]
mod scheme {
    use commonware_clearing::bajillion::{Namespace, Summary};
    use commonware_cryptography::{Sha256, impl_certificate_ed25519};
    use commonware_utils::N3f1;

    impl_certificate_ed25519!(&'a Summary<Sha256>, Namespace, N3f1);
}

type TestOperator = Operator<PublicKey, PrivateKey, Sha256, u64>;
type TestSender = Sender<PrivateKey, PublicKey, Sha256, u64>;
type TestReceiver = Receiver<PublicKey, PublicKey, Sha256, u64>;
type TestValidator = DeployedValidator<PublicKey, PublicKey, u64>;
type TestLedger = Ledger<PublicKey, PublicKey, scheme::Scheme, Sha256, u64>;
type TestClose = Close<PublicKey, PublicKey, u64>;
type TestProposal = Proposal<PublicKey, Sha256, Sequential, u64>;
type TestDeployment = Deployment<PublicKey, PrivateKey, scheme::Scheme, u64>;

/// A validator of a deployment under test with user keys `P`, operator key `O`, and amounts `A`.
type DeployedValidator<P, O, A> =
    Validator<deterministic::Context, P, O, Sha256, EightCap, Sequential, A>;

/// Returns the signature namespaces of the deployment under test.
fn namespace() -> Namespace {
    Namespace::new(NAMESPACE)
}

/// Returns the signing key of user `index`.
fn user(index: u64) -> PrivateKey {
    PrivateKey::from_seed(index)
}

/// Returns the account of user `index`.
fn account(index: u64) -> PublicKey {
    user(index).public_key()
}

/// Returns the operator's signing key.
fn operator_key() -> PrivateKey {
    PrivateKey::from_seed(1_000)
}

/// Returns user `index` sending through the deployment's operator.
fn sender(index: u64) -> TestSender {
    Sender::new(user(index), namespace(), operator_key().public_key())
}

/// Returns user `index` receiving while the ledger expects the close of `next`.
fn receiver(index: u64, next: Epoch) -> TestReceiver {
    Receiver::new(
        account(index),
        namespace(),
        operator_key().public_key(),
        next,
    )
}

/// Returns an operator for the first epoch.
fn operator() -> TestOperator {
    Operator::new(operator_key(), namespace(), LIMITS)
}

/// Closes `operator`'s epoch, processing the oldest `deposits` and `forced_withdrawals` requests
/// in `queue`.
fn close_epoch(
    operator: &mut TestOperator,
    queue: &Queue<PublicKey, u64>,
    deposits: u64,
    forced_withdrawals: u64,
) -> TestClose {
    operator
        .close(queue, deposits, forced_withdrawals)
        .unwrap()
        .0
}

/// Funds users by closing the operator's epoch with a deposit of each `(index, amount)`.
fn fund(operator: &mut TestOperator, balances: &[(u64, u64)]) -> TestClose {
    let queue = deposits(operator.epoch(), balances);
    close_epoch(operator, &queue, queue.deposits.len() as u64, 0)
}

/// Closes the operator's epoch without processing any queued request.
fn close(operator: &mut TestOperator) -> TestClose {
    close_epoch(operator, &deposits(operator.epoch(), &[]), 0, 0)
}

/// Returns amounts paying user `index` its `amount` for each `(index, amount)`.
fn amounts(entries: &[(u64, u64)]) -> Amounts<PublicKey, u64> {
    Amounts::new(
        entries
            .iter()
            .map(|(index, amount)| (account(*index), *amount)),
    )
    .unwrap()
}

/// Returns a queue for the close of `epoch` holding a deposit for each `(index, amount)`, none
/// of which the close must process.
fn deposits(epoch: Epoch, entries: &[(u64, u64)]) -> Queue<PublicKey, u64> {
    Queue {
        epoch,
        deposits: entries
            .iter()
            .map(|(index, amount)| Deposit {
                account: account(*index),
                amount: *amount,
            })
            .collect(),
        required_deposits: 0,
        forced_withdrawals: Vec::new(),
        required_forced_withdrawals: 0,
    }
}

/// Returns the row user `sender` signs for `payments` in `epoch` on top of `previous`.
fn row(
    epoch: Epoch,
    sender: u64,
    payments: Amounts<PublicKey, u64>,
    previous: &Amounts<PublicKey, u64>,
) -> Row<PublicKey, u64> {
    let state = State {
        epoch,
        account: account(sender),
        payments: payments.root::<Sha256>(),
        previous: previous.root::<Sha256>(),
    };
    Row {
        signature: user(sender).sign(&namespace().state, &state.encode()),
        account: account(sender),
        payments,
    }
}

/// Returns a close of `queue`'s epoch with the given rows and soft withdrawals, signed by
/// `signer` without checking their signatures or the validators' limits, as a faulty operator
/// could.
fn forge(
    signer: &PrivateKey,
    queue: &Queue<PublicKey, u64>,
    rows: Vec<Row<PublicKey, u64>>,
    withdrawals: Vec<Withdrawal<PublicKey, u64>>,
    deposits: u64,
    forced_withdrawals: u64,
) -> TestClose {
    Close::assemble::<Sha256, _>(
        signer,
        &namespace(),
        queue,
        rows,
        withdrawals,
        deposits,
        forced_withdrawals,
    )
    .unwrap()
    .0
}

/// Returns `hash` extended by `H(hash || request)` for each of `requests`.
fn chain<R: Encode>(hash: Digest, requests: &[R]) -> Digest {
    requests.iter().fold(hash, |hash, request| {
        Sha256::hash(&[hash.as_ref(), request.encode().as_ref()])
    })
}

/// Checks that each running hash in `summary` extends the one in `parent` over the requests its
/// close processed from `queue`.
fn assert_chained(
    parent: &Summary<Sha256>,
    summary: &Summary<Sha256>,
    queue: &Queue<PublicKey, u64>,
) {
    let (deposits, forced) = queue
        .prefix(summary.deposits.count, summary.forced_withdrawals.count)
        .unwrap();
    assert_eq!(summary.deposits.hash, chain(parent.deposits.hash, deposits));
    assert_eq!(
        summary.forced_withdrawals.hash,
        chain(parent.forced_withdrawals.hash, forced)
    );
}

/// Returns the configuration of a validator keeping its balances and payout log in partitions
/// named after `name`.
fn config(name: &str) -> Config<PublicKey, EightCap, Sequential> {
    config_for(name, operator_key().public_key())
}

/// Returns the configuration of a validator of a deployment whose operator is `operator`.
fn config_for<O: commonware_cryptography::PublicKey>(
    name: &str,
    operator: O,
) -> Config<O, EightCap, Sequential> {
    let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(8));
    let merkle = |name: String| MerkleConfig {
        journal_partition: format!("{name}-merkle-journal"),
        metadata_partition: format!("{name}-merkle-metadata"),
        items_per_blob: NZU64!(16),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
        strategy: Sequential,
        page_cache: page_cache.clone(),
    };
    let log = |name: String| JournalConfig {
        partition: format!("{name}-log"),
        items_per_blob: NZU64!(16),
        page_cache: page_cache.clone(),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
    };
    let payouts = format!("{name}-payouts");
    Config {
        namespace: namespace(),
        operator,
        limits: LIMITS,
        balances: fixed::Config {
            merkle: merkle(name.to_string()),
            log: log(name.to_string()),
            grafted_metadata_partition: format!("{name}-grafted-metadata"),
            translator: EightCap,
            init_cache: None,
            init_buffer: NZUsize!(1024),
            init_concurrency: (),
        },
        payouts: keyless::fixed::Config {
            merkle: merkle(payouts.clone()),
            log: log(payouts),
        },
    }
}

/// Certifies `summary` with every scheme's signature, as validators that did not check it would.
fn certify<C>(schemes: &[C], summary: &Summary<Sha256>) -> C::Certificate
where
    C: certificate::Scheme
        + for<'a> certificate::Verifier<Subject<'a, Digest> = &'a Summary<Sha256>>,
{
    let attestations: Vec<_> = schemes
        .iter()
        .map(|scheme| scheme.sign::<Digest>(summary).unwrap())
        .collect();
    schemes[0]
        .assemble(non_empty![@attestations], &Sequential)
        .unwrap()
}

/// An operator, a committee of validators certifying with scheme `C`, and the ledger they settle
/// on.
struct Deployment<
    P: commonware_cryptography::PublicKey,
    K: Signer,
    C: certificate::Scheme,
    A: Amount,
> {
    operator: Operator<P, K, Sha256, A>,
    validators: Vec<DeployedValidator<P, K::PublicKey, A>>,
    schemes: Vec<C>,
    ledger: Ledger<P, K::PublicKey, C, Sha256, A>,
}

/// Returns the signing schemes of `validators` validators and the verifier of their
/// certificates. Every call returns the same keys.
fn committee(validators: u32) -> (Vec<scheme::Scheme>, scheme::Scheme) {
    let fixture = mocks::fixture(
        &mut test_rng(),
        NAMESPACE,
        validators,
        scheme::Scheme::signer,
        scheme::Scheme::verifier,
    );
    (fixture.schemes, fixture.verifier)
}

impl TestDeployment {
    /// Starts a deployment with `validators` validators, keeping their balances in partitions
    /// named after `name`.
    async fn new(context: &deterministic::Context, name: &str, validators: u32) -> Self {
        let (schemes, verifier) = committee(validators);
        Self::start(context, name, operator_key(), schemes, verifier).await
    }
}

impl<P, K, C, A> Deployment<P, K, C, A>
where
    P: commonware_cryptography::PublicKey,
    K: Signer,
    C: certificate::Scheme
        + for<'a> certificate::Verifier<Subject<'a, Digest> = &'a Summary<Sha256>>,
    A: Amount,
{
    /// Starts a deployment whose operator signs with `operator` and whose validators sign with
    /// `schemes`, one validator each.
    async fn start(
        context: &deterministic::Context,
        name: &str,
        operator: K,
        schemes: Vec<C>,
        verifier: C,
    ) -> Self {
        let mut validators = Vec::new();
        for index in 0..schemes.len() {
            let validator = Validator::init(
                context.child("validator").with_attribute("index", index),
                config_for(&format!("{name}-{index}"), operator.public_key()),
                Persisted::default(),
                None,
            )
            .await
            .unwrap();
            validators.push(validator);
        }
        let ledger = Ledger::new(
            namespace(),
            operator.public_key(),
            verifier,
            validators[0].summary().balances,
        );
        Self {
            operator: Operator::new(operator, namespace(), LIMITS),
            validators,
            schemes,
            ledger,
        }
    }

    /// Checks that the operator and every validator hold each balance, and that the ledger holds
    /// exactly those balances and the deposits no close processed. Every posted payout must already
    /// be withdrawn.
    async fn check_balances(&self, balances: &[(P, A)]) {
        for (account, expected) in balances {
            assert_eq!(self.operator.balance(account), *expected);
            for validator in &self.validators {
                assert_eq!(validator.balance(account).await.unwrap(), *expected);
            }
        }
        let held = balances
            .iter()
            .map(|(_, balance)| *balance)
            .chain(
                self.ledger
                    .queue()
                    .deposits
                    .iter()
                    .map(|deposit| deposit.amount),
            )
            .try_fold(A::ZERO, |total, amount| total.checked_add(amount))
            .unwrap();
        assert_eq!(self.ledger.custody(), held);
    }

    /// Checks `close` with every validator against the ledger's queues. Each validator persists
    /// the close before its proposal is certified.
    async fn verify(
        &mut self,
        close: &Close<P, K::PublicKey, A>,
    ) -> Vec<Proposal<P, Sha256, Sequential, A>> {
        let queue = self.ledger.queue();
        let mut proposals = Vec::new();
        for validator in &mut self.validators {
            proposals.push(validator.verify(close.clone(), &queue).await.unwrap());
        }
        proposals
    }

    /// Certifies the summary every proposal shares with every validator's signature.
    fn certify(&self, proposals: &[Proposal<P, Sha256, Sequential, A>]) -> C::Certificate {
        let summary = proposals[0].summary();
        assert!(
            proposals
                .iter()
                .all(|proposal| proposal.summary() == summary)
        );
        certify(&self.schemes, summary)
    }

    /// Posts the summary the proposals share and applies it at every validator. The payouts stay
    /// owed.
    async fn post(
        &mut self,
        context: &mut deterministic::Context,
        proposals: Vec<Proposal<P, Sha256, Sequential, A>>,
    ) -> Summary<Sha256> {
        let certificate = self.certify(&proposals);
        let summary = *proposals[0].summary();
        self.ledger.post(context, &summary, &certificate).unwrap();
        let posted = summary.digest();
        for (validator, proposal) in self.validators.iter_mut().zip(proposals) {
            validator.apply(proposal, &posted).await.unwrap();
        }
        summary
    }

    /// Closes the operator's epoch, processing every queued request, posts the close, and
    /// withdraws each of its payouts with a proof from a validator.
    async fn close(
        &mut self,
        context: &mut deterministic::Context,
    ) -> (Close<P, K::PublicKey, A>, Summary<Sha256>) {
        let queue = self.ledger.queue();
        let (close, _) = self
            .operator
            .close(
                &queue,
                queue.deposits.len() as u64,
                queue.forced_withdrawals.len() as u64,
            )
            .unwrap();
        let proposals = self.verify(&close).await;
        let payouts = proposals[0].payouts().clone();
        let summary = self.post(context, proposals).await;
        self.withdraw_payouts(summary.epoch, &payouts).await;
        (close, summary)
    }

    /// Withdraws the `payouts` the posted close of `epoch` owes, each with a proof from a
    /// validator.
    async fn withdraw_payouts(&mut self, epoch: Epoch, payouts: &Amounts<P, A>) {
        for (account, amount) in payouts.iter() {
            let proof = self.validators[0]
                .prove_payout(epoch, account)
                .await
                .unwrap()
                .expect("the close must owe the account a payout");
            let withdrawn = self.ledger.withdraw_payout(&proof).unwrap();
            assert_eq!(withdrawn, (account.clone(), amount));
        }
    }
}
