//! Tests of Bajillion's roles working together.

mod ledger;
mod lifecycle;
mod payments;
mod shards;
mod validator;

use super::{
    Amounts, Close, Config, Deposit, Epoch, Ledger, Limits, Matrix, MemoryBalances, Namespace,
    Operator, Proposal, Queue, Receiver, Row, Sender, Summary, Validator, Withdrawal,
};
use commonware_cryptography::{
    Sha256, Signer as _,
    certificate::{self, Scheme as _},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::unordered::fixed, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, TryCollect as _, non_empty, ordered::Set};

/// Namespace of the deployment under test.
const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_TEST";

/// Limits of the closes operators build, beyond any test's activity unless it sets its own.
const LIMITS: Limits = Limits {
    rows: 1_024,
    receivers: 1_024,
    withdrawals: 1_024,
};

/// Validators certify summaries with Ed25519 signatures from at least `2f + 1` of `3f + 1`.
///
/// The macro gates its fixture on a `mocks` feature that this crate does not define.
#[allow(unexpected_cfgs)]
mod scheme {
    use crate::bajillion::{Namespace, Summary};
    use commonware_cryptography::impl_certificate_ed25519;
    use commonware_utils::N3f1;

    impl_certificate_ed25519!(&'a Summary<D>, Namespace, N3f1);
}

type TestSender = Sender<PublicKey, PrivateKey, PublicKey, Sha256, u64>;
type TestReceiver = Receiver<PublicKey, PublicKey, Sha256, u64>;
type TestOperator =
    Operator<PublicKey, PublicKey, PrivateKey, Sha256, u64, MemoryBalances<PublicKey, u64>>;
type TestValidator =
    Validator<deterministic::Context, PublicKey, PublicKey, Sha256, EightCap, Sequential, u64>;
type TestProposal = Proposal<PublicKey, Sha256, Sequential, u64>;
type TestLedger = Ledger<PublicKey, PublicKey, scheme::Scheme, Sha256, u64>;
type TestClose = Close<PublicKey, PublicKey, u64>;
type TestCertificate = <scheme::Scheme as certificate::Verifier>::Certificate;

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

fn sender(index: u64) -> TestSender {
    Sender::new(user(index), operator_key().public_key(), namespace())
}

/// Returns an operator for the first epoch, keeping its balances in memory.
async fn operator() -> TestOperator {
    Operator::init(
        operator_key(),
        namespace(),
        LIMITS,
        MemoryBalances::new(),
        [],
        None,
    )
    .await
    .unwrap()
}

/// Closes `operator`'s epoch, processing the oldest `deposits` deposits and `forced_withdrawals`
/// forced withdrawals in `queue`.
async fn close_epoch(
    operator: &mut TestOperator,
    queue: &Queue<PublicKey, u64>,
    deposits: u64,
    forced_withdrawals: u64,
) -> TestClose {
    operator
        .close(queue, deposits, forced_withdrawals)
        .await
        .unwrap()
}

/// Returns user `index` receiving while the ledger expects the close of `next`.
fn receiver(index: u64, next: Epoch) -> TestReceiver {
    Receiver::new(
        account(index),
        operator_key().public_key(),
        namespace(),
        next,
    )
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

/// Returns a queue for the close of `epoch` holding a deposit for each `(index, amount)`, none of
/// which the close must process.
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

/// Signs a close as `operator` would, without checking any of its contents.
fn sign_close(
    operator: &PrivateKey,
    epoch: Epoch,
    rows: Vec<Row<PublicKey, u64>>,
    withdrawals: Vec<Withdrawal<PublicKey, u64>>,
    deposits: u64,
    forced_withdrawals: u64,
) -> TestClose {
    let root = Matrix::new::<Sha256>(
        rows.iter()
            .map(|row| (row.account.clone(), row.payments.clone())),
    )
    .unwrap()
    .root();
    let signature = operator.sign(
        &namespace().close,
        &TestClose::message(epoch, &root, &withdrawals, deposits, forced_withdrawals),
    );
    Close::new(
        epoch,
        rows,
        withdrawals,
        deposits,
        forced_withdrawals,
        signature,
    )
}

/// Returns the configuration of a validator keeping its balances in partitions named after
/// `name`.
fn config(name: &str) -> Config<PublicKey, EightCap, Sequential> {
    config_for(name, operator_key().public_key())
}

/// Returns the configuration of a validator of a deployment whose operator is `operator`.
fn config_for<O: commonware_cryptography::PublicKey>(
    name: &str,
    operator: O,
) -> Config<O, EightCap, Sequential> {
    let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(8));
    Config {
        namespace: namespace(),
        operator,
        balances: fixed::Config {
            merkle: MerkleConfig {
                journal_partition: format!("{name}-merkle-journal"),
                metadata_partition: format!("{name}-merkle-metadata"),
                items_per_blob: NZU64!(16),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                partition: format!("{name}-log"),
                items_per_blob: NZU64!(16),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: format!("{name}-grafted-metadata"),
            translator: EightCap,
            init_cache: None,
            init_buffer: NZUsize!(1024),
            init_concurrency: (),
        },
    }
}

/// Certifies `summary` with every validator's signature, as validators that did not check it
/// would.
fn certify(schemes: &[scheme::Scheme], summary: &Summary<Digest>) -> TestCertificate {
    let attestations: Vec<_> = schemes
        .iter()
        .map(|scheme| scheme.sign::<Digest>(summary).unwrap())
        .collect();
    schemes[0]
        .assemble(non_empty![@attestations], &Sequential)
        .unwrap()
}

/// An operator, a committee of validators, and the ledger they settle on.
struct Deployment {
    operator: TestOperator,
    validators: Vec<TestValidator>,
    schemes: Vec<scheme::Scheme>,
    ledger: TestLedger,
}

impl Deployment {
    /// Starts a deployment with `validators` validators, keeping their balances in partitions
    /// named after `name`.
    async fn new(context: &deterministic::Context, name: &str, validators: u32) -> Self {
        let keys: Vec<_> = (0..validators)
            .map(|index| PrivateKey::from_seed(2_000 + u64::from(index)))
            .collect();
        let participants: Set<PublicKey> = keys
            .iter()
            .map(PrivateKey::public_key)
            .try_collect()
            .unwrap();
        let schemes = keys
            .into_iter()
            .map(|key| scheme::Scheme::signer(NAMESPACE, participants.clone(), key).unwrap())
            .collect();
        let verifier = scheme::Scheme::verifier(NAMESPACE, participants);
        let mut handles = Vec::new();
        for index in 0..validators {
            let validator = TestValidator::init(
                context.child("validator").with_attribute("index", index),
                config(&format!("{name}-{index}")),
                Vec::new(),
            )
            .await
            .unwrap();
            handles.push(validator);
        }
        let ledger = Ledger::new(
            namespace(),
            operator_key().public_key(),
            verifier,
            handles[0].summary().balances,
        );
        Self {
            operator: operator().await,
            validators: handles,
            schemes,
            ledger,
        }
    }

    /// Checks `close` with every validator against the ledger's queues.
    async fn verify(&self, close: &TestClose) -> Vec<TestProposal> {
        let queue = self.ledger.queue();
        let mut proposals = Vec::new();
        for validator in &self.validators {
            proposals.push(validator.verify(close.clone(), &queue).await.unwrap());
        }
        proposals
    }

    /// Certifies the summary every proposal shares with every validator's signature.
    fn certify(&self, proposals: &[TestProposal]) -> TestCertificate {
        let summary = proposals[0].summary();
        assert!(
            proposals
                .iter()
                .all(|proposal| proposal.summary() == summary)
        );
        certify(&self.schemes, summary)
    }

    /// Posts the summary the proposals share and applies it at every validator.
    async fn post(
        &mut self,
        context: &mut deterministic::Context,
        proposals: Vec<TestProposal>,
    ) -> Summary<Digest> {
        let certificate = self.certify(&proposals);
        let summary = *proposals[0].summary();
        self.ledger
            .post(context, &summary, proposals[0].payouts(), &certificate)
            .unwrap();
        let validators = std::mem::take(&mut self.validators);
        for (validator, proposal) in validators.into_iter().zip(proposals) {
            self.validators
                .push(validator.apply(proposal).await.unwrap());
        }
        summary
    }

    /// Closes the operator's epoch, processing every queued request, and posts the close.
    async fn close(
        &mut self,
        context: &mut deterministic::Context,
    ) -> (TestClose, Summary<Digest>) {
        let queue = self.ledger.queue();
        let close = close_epoch(
            &mut self.operator,
            &queue,
            queue.deposits.len() as u64,
            queue.forced_withdrawals.len() as u64,
        )
        .await;
        let proposals = self.verify(&close).await;
        let summary = self.post(context, proposals).await;
        (close, summary)
    }
}
