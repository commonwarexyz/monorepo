//! Helpers shared by the unit tests, and the test vector for implementations of the ledger.

use super::{
    Amounts, ApplyError, BalanceProof, Balances, CheckError, Checked, Checkpoint, Close, Deposit,
    Epoch, ForcedWithdrawal, Matrix, Namespace, Payout, PayoutProof, Payouts, Proposal, Queue,
    Receipt, Request, Row, SettleError, State, Summary, Withdrawal,
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, Signer as _,
    certificate::{self, Scheme as _},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_formatting::hex;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    index::{Unordered, unordered::Index},
    journal::{authenticated::Config as MerkleConfig, contiguous::fixed::Config as JournalConfig},
    merkle::{Location, mmb, mmr},
    qmdb::{current::unordered::fixed, keyless},
    translator::{EightCap, Translator},
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty};

/// Namespace of the deployment under test.
pub(crate) const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_TEST";

/// Ed25519 certificates over summaries from at least `2f + 1` of `3f + 1` validators.
pub(crate) mod scheme {
    use crate::bajillion::{Namespace, Summary};
    use commonware_cryptography::{Sha256, impl_certificate_ed25519};
    use commonware_utils::N3f1;

    impl_certificate_ed25519!(&'a Summary<Sha256>, Namespace, N3f1);
}

pub(crate) type TestClose = Close<PublicKey, PublicKey, u64>;
pub(crate) type TestQueue = Queue<PublicKey, u64>;
pub(crate) type TestCheckpoint = Checkpoint<PublicKey, Sha256, u64>;
type TestChecked = Checked<PublicKey, Sha256, u64>;
pub(crate) type TestProposal = Proposal<PublicKey, Sha256, Sequential, u64>;
type TestCertificate = <scheme::Scheme as certificate::Verifier>::Certificate;

/// A balances database over the unordered index `I`.
pub(crate) type TestDb<I> = Balances<deterministic::Context, PublicKey, Sha256, I, Sequential, u64>;

/// A balances database over the plain unordered index with translator `T`.
pub(crate) type TestBalances<T = EightCap> = TestDb<Index<T, Location<mmb::Family>>>;

/// A payout log.
pub(crate) type TestLog = Payouts<deterministic::Context, PublicKey, Sha256, Sequential, u64>;

/// A validator's balances database over the unordered index `I`, with its payout log.
pub(crate) struct Store<
    I: Unordered<Value = Location<mmb::Family>> = Index<EightCap, Location<mmb::Family>>,
> {
    pub(crate) balances: TestDb<I>,
    pub(crate) log: TestLog,
}

impl<I: Unordered<Value = Location<mmb::Family>> + 'static> Store<I> {
    /// Settles `checked` on both databases.
    pub(crate) async fn settle(&self, checked: &TestChecked) -> Result<TestProposal, SettleError> {
        checked.settle(&self.balances, &self.log).await
    }

    /// Applies `proposal` to both databases as the posted close with digest `posted`.
    pub(crate) async fn apply(
        self,
        proposal: TestProposal,
        posted: &Digest,
    ) -> Result<(Self, TestCheckpoint), ApplyError> {
        let (balances, log, checkpoint) = proposal.apply(self.balances, self.log, posted).await?;
        Ok((Self { balances, log }, checkpoint))
    }

    /// Makes the balance writes durable. The log is durable once a close applies.
    pub(crate) async fn commit(self) -> Self {
        Self {
            balances: self.balances.commit().await.unwrap(),
            log: self.log,
        }
    }

    /// Returns the roots of the balances database and the payout log.
    pub(crate) fn roots(&self) -> (Digest, Digest) {
        (self.balances.root(), self.log.root())
    }
}

/// Returns the signature namespaces of the deployment under test.
pub(crate) fn namespace() -> Namespace {
    Namespace::new(NAMESPACE)
}

/// Returns the signing key of user `index`.
pub(crate) fn user(index: u64) -> PrivateKey {
    PrivateKey::from_seed(index)
}

/// Returns the account of user `index`.
pub(crate) fn account(index: u64) -> PublicKey {
    user(index).public_key()
}

/// Returns the signing keys of users `0..count`, in increasing order of their accounts.
pub(crate) fn users(count: u64) -> Vec<PrivateKey> {
    let mut users: Vec<_> = (0..count).map(user).collect();
    users.sort_by_key(PrivateKey::public_key);
    users
}

/// Returns the accounts of users `0..count` in increasing order.
pub(crate) fn accounts(count: u64) -> Vec<PublicKey> {
    users(count).iter().map(PrivateKey::public_key).collect()
}

/// Returns the operator's signing key.
pub(crate) fn operator_key() -> PrivateKey {
    PrivateKey::from_seed(1_000)
}

/// Returns amounts paying user `index` its `amount` for each `(index, amount)`.
pub(crate) fn amounts(entries: &[(u64, u64)]) -> Amounts<PublicKey, u64> {
    Amounts::new(
        entries
            .iter()
            .map(|(index, amount)| (account(*index), *amount)),
    )
    .unwrap()
}

/// Returns the root of the empty payment map.
pub(crate) fn empty_root() -> Digest {
    Amounts::<PublicKey, u64>::empty().root::<Sha256>()
}

/// Returns the row user `sender` signs for `payments` in `epoch` on top of the map with root
/// `previous`.
pub(crate) fn row(
    epoch: Epoch,
    sender: u64,
    payments: Amounts<PublicKey, u64>,
    previous: Digest,
) -> Row<PublicKey, u64> {
    let state = State {
        epoch,
        account: account(sender),
        payments: payments.root::<Sha256>(),
        previous,
    };
    Row {
        signature: state.sign(&user(sender), &namespace()),
        account: account(sender),
        payments,
    }
}

/// Signs a close of `rows` and `withdrawals`, given in any order, as `operator`, without checking
/// any of its contents.
pub(crate) fn sign_close(
    operator: &PrivateKey,
    epoch: Epoch,
    mut rows: Vec<Row<PublicKey, u64>>,
    mut withdrawals: Vec<Withdrawal<PublicKey, u64>>,
    deposits: u64,
    forced_withdrawals: u64,
) -> TestClose {
    rows.sort_by(|a, b| a.account.cmp(&b.account));
    withdrawals.sort_by(|a, b| a.request().cmp(&b.request()));
    Close::sign::<Sha256, _>(
        operator,
        &namespace(),
        epoch,
        rows,
        withdrawals,
        deposits,
        forced_withdrawals,
        &Sequential,
    )
}

/// Returns a queue for the close of `epoch` holding a deposit for each `(index, amount)` in
/// `deposits` and a forced withdrawal for each in `forced`, none of which the close must process.
pub(crate) fn queue(epoch: Epoch, deposits: &[(u64, u64)], forced: &[(u64, u64)]) -> TestQueue {
    Queue {
        epoch,
        deposits: deposits
            .iter()
            .map(|(index, amount)| Deposit {
                account: account(*index),
                amount: *amount,
            })
            .collect(),
        required_deposits: 0,
        forced_withdrawals: forced
            .iter()
            .map(|(index, amount)| ForcedWithdrawal {
                account: account(*index),
                amount: *amount,
            })
            .collect(),
        required_forced_withdrawals: 0,
    }
}

/// Returns the configurations of a database's merkle and log journals in partitions named after
/// `name`, sharing one page cache.
fn journals(name: &str) -> (MerkleConfig<Sequential>, JournalConfig) {
    let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(8));
    let merkle = MerkleConfig {
        partition: format!("{name}-merkle"),
        replay_buffer: NZUsize!(1024),
        replay_concurrency: NZUsize!(2),
        strategy: Sequential,
        resident_height: Default::default(),
    };
    let log = JournalConfig {
        partition: format!("{name}-log"),
        items_per_blob: NZU64!(7),
        page_cache,
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
    };
    (merkle, log)
}

/// Returns the configuration of a balances database in partitions named after `name`.
pub(crate) fn config<T: Translator>(name: &str, translator: T) -> fixed::Config<T, Sequential> {
    let (merkle, log) = journals(name);
    fixed::Config {
        merkle,
        log,
        grafted_metadata_partition: format!("{name}-grafted-metadata"),
        translator,
        init_cache: None,
        init_buffer: NZUsize!(1024),
        init_concurrency: (),
    }
}

/// Returns the configuration of a payout log in partitions named after `name`.
fn log_config(name: &str) -> keyless::fixed::Config<Sequential> {
    let (merkle, log) = journals(&format!("{name}-payouts"));
    keyless::fixed::Config { merkle, log }
}

/// Opens the payout log in partitions named after `name`, at its latest commit with at most
/// `size` operations if given.
pub(crate) async fn open_log(
    context: deterministic::Context,
    name: &str,
    size: Option<Location<mmr::Family>>,
) -> TestLog {
    TestLog::init(context, log_config(name), size)
        .await
        .unwrap()
}

/// Opens the balances database and the payout log in partitions named after `name`.
pub(crate) async fn open(context: deterministic::Context, name: &str) -> Store {
    Store {
        balances: TestBalances::init(context.child("balances"), config(name, EightCap), None)
            .await
            .unwrap(),
        log: open_log(context.child("log"), name, None).await,
    }
}

/// Returns the checkpoint before the first close, on top of a balances database with root
/// `balances`.
pub(crate) fn genesis(balances: Digest) -> TestCheckpoint {
    Checkpoint {
        summary: Summary::<Sha256>::genesis::<PublicKey, u64>(balances),
        matrix: Matrix::empty(),
    }
}

/// Checks `close` as the successor of `parent` against `queue`.
pub(crate) fn check(
    close: TestClose,
    parent: &TestCheckpoint,
    queue: &TestQueue,
) -> Result<TestChecked, CheckError> {
    close.check::<Sha256>(
        &namespace(),
        &operator_key().public_key(),
        parent,
        queue,
        &Sequential,
    )
}

/// Checks, settles, and applies `close` on top of `parent` as its posted successor, and returns the
/// databases with the close's checkpoint.
pub(crate) async fn post<I: Unordered<Value = Location<mmb::Family>> + 'static>(
    store: Store<I>,
    parent: &TestCheckpoint,
    close: TestClose,
    queue: &Queue<PublicKey, u64>,
) -> (Store<I>, TestCheckpoint) {
    let checked = check(close, parent, queue).unwrap();
    let proposal = store.settle(&checked).await.unwrap();
    let posted = proposal.summary().digest();
    store.apply(proposal, &posted).await.unwrap()
}

/// Certifies `summary` with every scheme's signature.
pub(crate) fn certify(schemes: &[scheme::Scheme], summary: &Summary<Sha256>) -> TestCertificate {
    let attestations: Vec<_> = schemes
        .iter()
        .map(|scheme| scheme.sign::<Digest>(summary).unwrap())
        .collect();
    schemes[0]
        .assemble(non_empty![@attestations], &Sequential)
        .unwrap()
}

/// Returns `hash` extended by `H(hash || request)` for each of `requests`.
pub(crate) fn chain<R: Encode>(hash: Digest, requests: &[R]) -> Digest {
    requests.iter().fold(hash, |hash, request| {
        Sha256::hash(&[hash.as_ref(), request.encode().as_ref()])
    })
}

/// Pins the digests, roots, and encodings an implementation of the ledger must compute, for
/// SHA-256, Ed25519 keys, and `u64` amounts, and a deposit running hash that validators compute.
/// Alice pays bob 5 and carol 7 in epoch 1. The close of epoch 1 settles her map, processes bob's
/// deposit of 5 and alice's of 20, and pays out 3 to bob and 4 to carol on their forced
/// withdrawals. The close of epoch 2 pays out 1 to alice and 2 to bob, and the payout log then
/// has three peaks.
#[test]
fn test_ledger_vector() {
    deterministic::Runner::default().start(|context| async move {
        // The empty balances database and payout log, and the summary before the first close.
        let store = open(context, "vector").await;
        let genesis = Summary::<Sha256>::genesis::<PublicKey, u64>(store.balances.root());
        assert_eq!(
            hex(store.balances.root().as_ref()),
            "4e051a8ba89ab421a291d4b906848b2e0f80402175824a056cc3cc00efc4cc65"
        );
        assert_eq!(genesis.payouts.root, store.log.root());
        assert_eq!(store.log.bounds().end, genesis.payouts.size);
        assert_eq!(
            hex(store.log.root().as_ref()),
            "97f9a47536a9ff3eda91ef4e53351d365e104280df46dbcc5dddc7adfabcef2c"
        );
        assert_eq!(
            hex(genesis.digest().as_ref()),
            "dc78896a8eab075c7672d704b58798ff2687447dc6132852a86f007847bf5af0"
        );

        // The deposit queue's running hash after bob's deposit, chained from genesis. The queues
        // of epoch 1 also hold alice's deposit after bob's and the forced withdrawals of bob and
        // carol.
        let queued = queue(1, &[(1, 5), (0, 20)], &[(1, 3), (2, 4)]);
        let deposits = genesis.deposits.next::<Sha256, _>(&queued.deposits[..1]);
        assert_eq!(
            hex(deposits.hash.as_ref()),
            "e3a81ed35a6c131dc7ea391436b14bc6bc9882a0cf7d815fbd936179601427b4"
        );

        // Bob's receipt, with alice's signature and the operator's countersignature.
        let namespace = namespace();
        let states = Request::states::<Sha256>(
            1,
            account(0),
            amounts(&[(1, 5), (2, 7)]),
            None,
            &empty_root(),
        )
        .unwrap();
        let receipt = Receipt::<_, PublicKey, _, _>::issue::<Sha256>(
            &states.current,
            &states.current.sign(&user(0), &namespace),
            &states.current.acknowledge(&operator_key(), &namespace),
            &states.payments,
            [account(1)],
        )
        .unwrap()
        .pop()
        .unwrap();
        assert!(receipt.verify::<Sha256>(&namespace, &operator_key().public_key()));
        assert_eq!(
            hex(receipt.encode().as_ref()),
            concat!(
                "0000000000000001edd0f6de342a1e6a7236d6244f23d83eedfcecd059a386c8",
                "5055701498e7703316004c952b79b61f079ea03f168e671ba4ef1b92b99f648b",
                "947f1d130bdbf77dd4f280154cb1f1ecee668774e73759cdff911f869b36bb77",
                "a89b2e1d91166e63f3a702485e545330ff175028de6ebf13eb6d26206e9f9197",
                "b921356a0ba71203c9aa2291e5add7d3b7c73857894f99e31e210a03cd3c15a0",
                "0eba08c03fdff20fb8c05e67fbb03bd0bbc88c2e51683e9b7cb260bf4550c9b7",
                "c34bb2c8b649ca6988d0e278349baabbdd2a1198645179ff95503ccbdf54815d",
                "1644f4ed9e157c0b478b8e507e0bb2b18c0f9e0824769e8562d10df9abe2e774",
                "896f82b4b440526600000000000000050000000000000002014b496c9d7a3218",
                "e471ff8ecd0f2eb2c0e482a17687241dbac72334d783f33b47",
            )
        );

        // Openings of bob's entry and of dave's absent one in alice's row.
        let close = sign_close(
            &operator_key(),
            1,
            vec![row(1, 0, states.payments, empty_root())],
            Vec::new(),
            2,
            2,
        );
        let matrix = close.matrix::<Sha256>(&Sequential);
        let member = matrix.open(&account(0), &account(1));
        let absent = matrix.open(&account(0), &account(3));
        let root = matrix.root();
        assert_eq!(
            member
                .verify::<Sha256>(&root, &account(0), &account(1))
                .unwrap(),
            5
        );
        assert_eq!(
            absent
                .verify::<Sha256>(&root, &account(0), &account(3))
                .unwrap(),
            0
        );
        assert_eq!(
            hex(root.as_ref()),
            "bb7e4f8026a16dea4b1b699ee9a17fa361272f269a044f0532c3fae7729b059c"
        );
        assert_eq!(
            hex(member.encode().as_ref()),
            concat!(
                "000000000016004c952b79b61f079ea03f168e671ba4ef1b92b99f648b947f1d",
                "130bdbf77d0000000100010000000000000000000000000500000002014b496c",
                "9d7a3218e471ff8ecd0f2eb2c0e482a17687241dbac72334d783f33b47",
            )
        );
        assert_eq!(
            hex(absent.encode().as_ref()),
            concat!(
                "000000000016004c952b79b61f079ea03f168e671ba4ef1b92b99f648b947f1d",
                "130bdbf77d0000000100010100000002015925ba86e2189444a6c3b437b25d2e",
                "f35daecd1abf82c5fb36060f9fc0af428c0000000000000007000000000201ed",
                "446b5e41b60f4b9747cf253e918e823d1c2db3c7f50b6e47b6f6336cfefb7c",
            )
        );

        // The summary of the close of epoch 1. The close processes both queues in full.
        let start = Checkpoint {
            summary: genesis,
            matrix: Matrix::empty(),
        };
        let (store, first) = post(store, &start, close, &queued).await;
        assert_eq!(
            hex(first.summary.encode().as_ref()),
            concat!(
                "0000000000000001dc78896a8eab075c7672d704b58798ff2687447dc6132852",
                "a86f007847bf5af0bb7e4f8026a16dea4b1b699ee9a17fa361272f269a044f05",
                "32c3fae7729b059ccbeaa33ee0fadca40a7a84e3ef4538a6d5a9225c44b2e85f",
                "c27c58fc0dde40f50451b5519948527b730a86197f813f51283fa3545ca2b6c7",
                "4ca20596b4f4461fec02f90c99746c6dc051366862ffe2d129f1729cb9134387",
                "158fe590c943d69f55e902e9e2c7b054fce05131d767f27fe4b9b130cf6fd441",
                "14d394fbf97853f27ef05d",
            )
        );
        assert_eq!(
            hex(first.summary.digest().as_ref()),
            "4ea46f121bbf323e7dd93e6c34665a9cc8f3b0cd117b950586426d44729165ae"
        );

        // Bob's balance under the balances root of that summary, as a claim after a halt proves it.
        let (proof, balance) = store.balances.key_value_proof(&account(1)).await.unwrap();
        let proof = BalanceProof { balance, proof };
        assert!(proof.verify::<Sha256, _>(&first.summary.balances, &account(1)));
        assert_eq!(proof.balance, 7);
        assert_eq!(
            hex(proof.encode().as_ref()),
            concat!(
                "0000000000000007043c00000000000000000000000000000000000000000000",
                "000000000000000000060002e8deb066466eaf1b04f892d6986303eb407d463a",
                "51b4739a8c2513ac826becca71e1ff83de02f877f9e2c800a2502f61e761b10a",
                "0432c6703d620d79f7a9318c00011aee11ebaa71f4483e3129068f72caf28d4c",
                "1b4faa01f6b925e7fe97c2493636199f565a0c239b645ac33ac70a041ffda7cf",
                "66adc2e76d88454be81900cd252a",
            )
        );

        // The payout log after that close, and the proof of bob's payout at index 1.
        let payouts = first.summary.payouts;
        let (proof, _) = store.log.proof(Location::new(1), NZU64!(1)).await.unwrap();
        let early = PayoutProof {
            index: Location::new(1),
            payout: Payout {
                account: account(1),
                amount: 3u64,
            },
            proof,
        };
        assert!(early.verify::<Sha256>(&payouts.root));
        assert_eq!(payouts.size, 4);
        assert_eq!(
            hex(payouts.root.as_ref()),
            "51b5519948527b730a86197f813f51283fa3545ca2b6c74ca20596b4f4461fec"
        );
        assert_eq!(
            hex(early.encode().as_ref()),
            concat!(
                "01478b8e507e0bb2b18c0f9e0824769e8562d10df9abe2e774896f82b4b44052",
                "66000000000000000304000266b4a8b2a17f0463f7427c0239106eaf710ea712",
                "9f42d184a58c50cdff614ba4c9b32f58d153a4f26cb6078783a7d3a6cfab16d8",
                "f6fcedaa19ed63c338e2a9ce",
            )
        );

        // The close of epoch 2 pays out 1 to alice and 2 to bob, so the log holds three peaks. The
        // proof of bob's first payout under the new root folds the two later peaks.
        let queued = queue(2, &[], &[(0, 1), (1, 2)]);
        let close = sign_close(&operator_key(), 2, Vec::new(), Vec::new(), 0, 2);
        let (store, second) = post(store, &first, close, &queued).await;
        let payouts = second.summary.payouts;
        let (proof, _) = store.log.proof(Location::new(1), NZU64!(1)).await.unwrap();
        let late = PayoutProof {
            proof,
            ..early.clone()
        };
        assert!(late.verify::<Sha256>(&payouts.root));
        assert!(!early.verify::<Sha256>(&payouts.root));
        assert_eq!(payouts.size, 7);
        assert_eq!(
            hex(payouts.root.as_ref()),
            "540a194296da3b72974ec85cba28b56ce0cae59481844b2480db323061d7554d"
        );
        assert_eq!(
            hex(late.encode().as_ref()),
            concat!(
                "01478b8e507e0bb2b18c0f9e0824769e8562d10df9abe2e774896f82b4b44052",
                "6600000000000000030700038a4c9a9db0462d62f8c5467b7d7ae30b90514a34",
                "7f1abb4265e7184ec9052e4266b4a8b2a17f0463f7427c0239106eaf710ea712",
                "9f42d184a58c50cdff614ba4c9b32f58d153a4f26cb6078783a7d3a6cfab16d8",
                "f6fcedaa19ed63c338e2a9ce",
            )
        );
    });
}
