//! Shared parts of the clearing fuzz targets that run Bajillion next to the ideal clearing
//! functionality of the Bajillion paper (arXiv:2611.21883): the functionality itself, the
//! crate's reference roles, a mock committee, and the sampling and wire helpers the targets use.

pub mod functionality;
pub mod roles;
pub mod sampling;

use commonware_clearing::bajillion::{
    Amounts, Close, Epoch, Limits, Namespace, Queue, Receipt, Request, Row, State, Summary,
    Withdrawal,
};
use commonware_codec::Codec;
use commonware_cryptography::{
    Sha256,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::full::Config as MerkleConfig,
    qmdb::{current::unordered::fixed, keyless},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use roles::{ledger, operator, receiver, sender, validator};
use std::fmt::Debug;

/// Mock certificates over summaries from at least `2f + 1` of `3f + 1` validators. Signatures and
/// certificates are synthetic identifiers, so certifying costs no curve arithmetic.
pub mod scheme {
    use commonware_clearing::bajillion::{Namespace, Summary};
    use commonware_cryptography::{Sha256, impl_certificate_mock};
    use commonware_utils::N3f1;

    impl_certificate_mock!(&'a Summary<Sha256>, Namespace, N3f1);
}

pub type Committee = scheme::Scheme<PublicKey>;
pub type TestAmounts = Amounts<PublicKey, u64>;
pub type TestState = State<PublicKey, Digest>;
pub type TestRequest = Request<PublicKey, Digest, u64>;
pub type TestReceipt = Receipt<PublicKey, PublicKey, Digest, u64>;
pub type TestWithdrawal = Withdrawal<PublicKey, u64>;
pub type TestRow = Row<PublicKey, u64>;
pub type TestClose = Close<PublicKey, PublicKey, u64>;
pub type TestQueue = Queue<PublicKey, u64>;
pub type TestSummary = Summary<Sha256>;
pub type TestOperator = operator::Operator<PublicKey, PrivateKey, Sha256, u64>;
pub type TestSender = sender::Sender<PrivateKey, PublicKey, Sha256, u64>;
pub type TestReceiver = receiver::Receiver<PublicKey, PublicKey, Sha256, u64>;
pub type TestLedger = ledger::Ledger<PublicKey, PublicKey, Committee, Sha256, u64>;
pub type TestValidator = validator::Validator<
    deterministic::Context,
    PublicKey,
    PublicKey,
    Sha256,
    EightCap,
    Sequential,
    u64,
>;

/// Amounts from each sender to each receiver, by user index.
pub type Table = Vec<Vec<u128>>;

/// Users of a plan. Two already pay each other, and four give a close several rows.
pub const MIN_USERS: usize = 2;
pub const MAX_USERS: usize = 4;

/// Validators of the committee that certifies each summary.
pub const VALIDATORS: u32 = 4;

/// Most receivers a batch pays.
pub const MAX_BATCH: usize = 3;

/// Epochs past the one the ledger expects that a signed state can name: a request of the next
/// epoch carries a state of the one after it.
pub const OPEN_EPOCHS: Epoch = 2;

/// The smallest amount. A request of one unit follows a refused request of nothing, of too much, or
/// of another epoch.
pub const UNIT: u8 = 1;

/// A close that posted: its epoch and counts, the matrix it settles, the payouts it owes, and the
/// balances after it.
pub struct Posted {
    pub epoch: Epoch,
    pub deposits: usize,
    pub forced: usize,
    pub matrix: Table,
    pub payouts: TestAmounts,
    pub balances: Vec<u128>,
}

/// Sends `value` to another party: it encodes to its stated size, and the party decodes what was
/// sent.
pub fn wire<T: Codec + PartialEq + Debug>(value: T, cfg: &T::Cfg) -> T {
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    let decoded = T::decode_cfg(encoded, cfg).expect("an encoded message decodes");
    assert_eq!(decoded, value);
    decoded
}

/// Returns the configuration of a validator of the deployment with signature namespaces
/// `namespace` and operator `operator`, which decodes closes under `limits`.
pub fn config(
    namespace: Namespace,
    operator: PublicKey,
    limits: Limits,
) -> validator::Config<PublicKey, EightCap, Sequential> {
    let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(8));
    let merkle = |name: &str| MerkleConfig {
        journal_partition: format!("{name}-merkle-journal"),
        metadata_partition: format!("{name}-merkle-metadata"),
        items_per_blob: NZU64!(7),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
        strategy: Sequential,
        page_cache: page_cache.clone(),
    };
    let log = |name: &str| JournalConfig {
        partition: format!("{name}-log"),
        items_per_blob: NZU64!(7),
        page_cache: page_cache.clone(),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
    };
    validator::Config {
        namespace,
        operator,
        limits,
        balances: fixed::Config {
            merkle: merkle("balances"),
            log: log("balances"),
            grafted_metadata_partition: "balances-grafted-metadata".into(),
            translator: EightCap,
            init_cache: None,
            init_buffer: NZUsize!(1024),
            init_concurrency: (),
        },
        payouts: keyless::fixed::Config {
            merkle: merkle("payouts"),
            log: log("payouts"),
        },
    }
}
