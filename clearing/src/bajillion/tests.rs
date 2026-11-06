//! Helpers shared by the unit tests, and the vector a port of the ledger checks itself against.

use super::{
    Acknowledgement, Amounts, Balances, Checked, Checkpoint, Close, Deposit, Epoch,
    ForcedWithdrawal, Matrix, Namespace, Proposal, Queue, Receipt, Request, Row, State, Summary,
    Withdrawal,
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _,
    certificate::{self, Scheme as _},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    index::{Unordered, unordered::Index},
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Location, full::Config as MerkleConfig, mmb},
    qmdb::current::unordered::fixed,
    translator::{EightCap, Translator},
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty};

/// Namespace of the deployment under test.
pub(crate) const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_TEST";

/// Validators certify summaries with Ed25519 signatures from at least `2f + 1` of `3f + 1`.
// The macro gates its fixture on a `mocks` feature that this crate does not define.
#[allow(unexpected_cfgs)]
pub(crate) mod scheme {
    use crate::bajillion::{Namespace, Summary};
    use commonware_cryptography::impl_certificate_ed25519;
    use commonware_utils::N3f1;

    impl_certificate_ed25519!(&'a Summary<D>, Namespace, N3f1);
}

pub(crate) type TestClose = Close<PublicKey, PublicKey, u64>;
pub(crate) type TestCheckpoint = Checkpoint<PublicKey, Digest, u64>;
pub(crate) type TestChecked = Checked<PublicKey, Digest, u64>;
pub(crate) type TestProposal = Proposal<PublicKey, Sha256, Sequential, u64>;
pub(crate) type TestCertificate = <scheme::Scheme as certificate::Verifier>::Certificate;

/// A balances database over the unordered index `I`.
pub(crate) type TestDb<I> = Balances<deterministic::Context, PublicKey, Sha256, I, Sequential, u64>;

/// A balances database over the plain unordered index with translator `T`.
pub(crate) type TestBalances<T = EightCap> = TestDb<Index<T, Location<mmb::Family>>>;

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
    sender: u64,
    epoch: Epoch,
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

/// Signs a close of `rows` and `withdrawals` in any order as `operator`, without checking any of
/// its contents.
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
    let root = Matrix::from_sorted::<Sha256>(
        rows.iter()
            .map(|row| {
                (
                    row.account.clone(),
                    row.payments.clone(),
                    row.payments.root::<Sha256>(),
                )
            })
            .collect(),
    )
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

/// Returns a queue for the close of `epoch` holding a deposit for each `(index, amount)` in
/// `deposits` and a forced withdrawal for each in `forced`, none of which the close must process.
pub(crate) fn queue(
    epoch: Epoch,
    deposits: &[(u64, u64)],
    forced: &[(u64, u64)],
) -> Queue<PublicKey, u64> {
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

/// Returns the configuration of a balances database in partitions named after `name`.
pub(crate) fn config<T: Translator>(name: &str, translator: T) -> fixed::Config<T, Sequential> {
    let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(8));
    fixed::Config {
        merkle: MerkleConfig {
            journal_partition: format!("{name}-merkle-journal"),
            metadata_partition: format!("{name}-merkle-metadata"),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        log: JournalConfig {
            partition: format!("{name}-log"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        },
        grafted_metadata_partition: format!("{name}-grafted-metadata"),
        translator,
        init_cache: None,
        init_buffer: NZUsize!(1024),
        init_concurrency: (),
    }
}

/// Opens the balances database in partitions named after `name`.
pub(crate) async fn open(context: deterministic::Context, name: &str) -> TestBalances {
    TestBalances::init(context, config(name, EightCap), None)
        .await
        .unwrap()
}

/// Returns the checkpoint before the first close, on top of a database with root `balances`.
pub(crate) fn genesis(balances: Digest) -> TestCheckpoint {
    Checkpoint {
        summary: Summary::genesis::<Sha256>(balances),
        matrix: Matrix::empty::<Sha256>(),
    }
}

/// Checks `close` as the successor of `parent` against `queue`.
pub(crate) fn check(
    close: TestClose,
    parent: &TestCheckpoint,
    queue: &Queue<PublicKey, u64>,
) -> Result<TestChecked, super::Error> {
    close.check::<Sha256, _>(
        &namespace(),
        &operator_key().public_key(),
        &Sequential,
        parent,
        queue,
    )
}

/// Checks, settles, and applies `close` on top of `parent` as its posted successor, and returns the
/// database with the close's checkpoint.
pub(crate) async fn post<I: Unordered<Value = Location<mmb::Family>> + 'static>(
    balances: TestDb<I>,
    parent: &TestCheckpoint,
    close: TestClose,
    queue: &Queue<PublicKey, u64>,
) -> (TestDb<I>, TestCheckpoint) {
    let proposal = check(close, parent, queue)
        .unwrap()
        .settle(&balances)
        .await
        .unwrap();
    let posted = proposal.summary().digest::<Sha256>();
    proposal.apply(balances, &posted).await.unwrap()
}

/// Certifies `summary` with every scheme's signature.
pub(crate) fn certify(schemes: &[scheme::Scheme], summary: &Summary<Digest>) -> TestCertificate {
    let attestations: Vec<_> = schemes
        .iter()
        .map(|scheme| scheme.sign::<Digest>(summary).unwrap())
        .collect();
    schemes[0]
        .assemble(non_empty![@attestations], &Sequential)
        .unwrap()
}

/// Returns `hash` extended by `H(hash || request)` for each of `requests`. Tests check
/// `Processed::next` against this independent fold.
pub(crate) fn chain<R: Encode>(hash: Digest, requests: &[R]) -> Digest {
    requests.iter().fold(hash, |hash, request| {
        Sha256::hash(&[hash.as_ref(), request.encode().as_ref()])
    })
}

/// Returns `bytes` in lowercase hex.
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Pins what a port of the ledger must reproduce bit for bit, for SHA-256, Ed25519 keys, and `u64`
/// amounts. It also pins a deposit running hash that a port of the validators must reproduce. Alice
/// pays bob 5 and carol 7 in epoch 1, and the close of epoch 1 settles her map and processes bob's
/// deposit of 5. The payouts root commits to payouts of 3 to bob and 4 to carol.
#[test]
fn test_port_vector() {
    deterministic::Runner::default().start(|context| async move {
        // The empty balances database, and the summary before the first close.
        let balances = open(context, "vector").await;
        let genesis = Summary::genesis::<Sha256>(balances.root());
        assert_eq!(
            hex(balances.root()),
            "4e051a8ba89ab421a291d4b906848b2e0f80402175824a056cc3cc00efc4cc65"
        );
        assert_eq!(
            hex(genesis.digest::<Sha256>()),
            "2b36d082705b9f8f212818c6832e86b2a4a31f584dcafa0a13b3a4115fff57a1"
        );

        // The deposit queue's running hash after bob's deposit, chained from genesis.
        let deposit = Deposit {
            account: account(1),
            amount: 5u64,
        };
        let deposits = genesis.deposits.next::<Sha256, _>(&[deposit]);
        assert_eq!(
            hex(deposits.hash),
            "e3a81ed35a6c131dc7ea391436b14bc6bc9882a0cf7d815fbd936179601427b4"
        );

        // Bob's receipt, with alice's signature and the operator's countersignature.
        let namespace = namespace();
        let states = Request::states::<Sha256>(
            account(0),
            1,
            amounts(&[(1, 5), (2, 7)]),
            &Amounts::empty(),
            &empty_root(),
            false,
        )
        .unwrap();
        let acknowledgement = Acknowledgement {
            signature: states.state.acknowledge(&operator_key(), &namespace),
        };
        let receipt = Receipt::<_, PublicKey, _, _>::issue::<Sha256>(
            &states.state,
            &states.state.sign(&user(0), &namespace),
            &acknowledgement,
            &states.payments,
            [account(1)],
        )
        .unwrap()
        .pop()
        .unwrap();
        receipt
            .verify::<Sha256>(&namespace, &operator_key().public_key())
            .unwrap();
        assert_eq!(
            hex(receipt.encode()),
            concat!(
                "0000000000000001edd0f6de342a1e6a7236d6244f23d83eedfcecd059a386c8",
                "5055701498e7703316004c952b79b61f079ea03f168e671ba4ef1b92b99f648b",
                "947f1d130bdbf77dd4f280154cb1f1ecee668774e73759cdff911f869b36bb77",
                "a89b2e1d91166e63c1847d31231c26d301edd7ff4d776d9e115410c9447fd87e",
                "44181812bf2fe6d16321b1e1d35e4691af2bc3b2e61a91e126f7e138d54d6d8e",
                "b9c65084d8de3b0eaffcbe13e4e9e111597ea5a4609fb65ed24968e7c67dd646",
                "6ae1022eaa1b5ed1d040ab5b3ec8b00f2c1da82c7fa14fd3a75b653928a4c68a",
                "a3d03178e63eb805478b8e507e0bb2b18c0f9e0824769e8562d10df9abe2e774",
                "896f82b4b440526600000000000000050000000000000002014b496c9d7a3218",
                "e471ff8ecd0f2eb2c0e482a17687241dbac72334d783f33b47",
            )
        );

        // Openings of bob's entry and of dave's absent one in alice's row.
        let close = sign_close(
            &operator_key(),
            1,
            vec![row(0, 1, states.payments, empty_root())],
            Vec::new(),
            1,
            0,
        );
        let matrix = close.matrix::<Sha256>();
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
            hex(root),
            "bb7e4f8026a16dea4b1b699ee9a17fa361272f269a044f0532c3fae7729b059c"
        );
        assert_eq!(
            hex(member.encode()),
            concat!(
                "000000000016004c952b79b61f079ea03f168e671ba4ef1b92b99f648b947f1d",
                "130bdbf77d0000000100010000000000000000000000000500000002014b496c",
                "9d7a3218e471ff8ecd0f2eb2c0e482a17687241dbac72334d783f33b47",
            )
        );
        assert_eq!(
            hex(absent.encode()),
            concat!(
                "000000000016004c952b79b61f079ea03f168e671ba4ef1b92b99f648b947f1d",
                "130bdbf77d0000000100010100000002015925ba86e2189444a6c3b437b25d2e",
                "f35daecd1abf82c5fb36060f9fc0af428c0000000000000007000000000201ed",
                "446b5e41b60f4b9747cf253e918e823d1c2db3c7f50b6e47b6f6336cfefb7c",
            )
        );

        // The payouts root.
        let payouts = amounts(&[(1, 3), (2, 4)]).root::<Sha256>();
        assert_eq!(
            hex(payouts),
            "3dff1a3fa6437053f151b531ea7f3a23ee3cea7f344d860d3585ddaea3ead852"
        );
    });
}
