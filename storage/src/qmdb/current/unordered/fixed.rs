//! An _unordered_ variant of a [crate::qmdb::current] authenticated database optimized for
//! fixed-size values.
//!
//! This variant does not maintain key ordering, so it cannot generate exclusion proofs. Use
//! [crate::qmdb::current::ordered::fixed] if exclusion proofs are required.
//!
//! See [Db] for the main database type.

pub use super::db::KeyValueProof;
use crate::{
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    merkle::{Graftable, Location},
    qmdb::{
        any::{unordered::fixed::Operation, value::FixedEncoding, FixedValue},
        current::FixedConfig as Config,
        Error,
    },
    translator::Translator,
    Context,
};
use commonware_cryptography::Hasher;
use commonware_utils::Array;

/// A specialization of [super::db::Db] for unordered key spaces and fixed-size values.
pub type Db<F, E, K, V, H, T, const N: usize> = super::db::Db<
    F,
    E,
    Journal<E, Operation<F, K, V>>,
    K,
    FixedEncoding<V>,
    Index<T, Location<F>>,
    H,
    N,
>;

impl<
        F: Graftable,
        E: Context,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<F, E, K, V, H, T, N>
{
    /// Initializes a [Db] authenticated database from the given `config`. Leverages parallel
    /// Merkleization to initialize the bitmap tree if a thread pool is provided.
    pub async fn init(context: E, config: Config<T>) -> Result<Self, Error<F>> {
        crate::qmdb::current::init(context, config).await
    }
}

pub mod partitioned {
    //! A partitioned variant of [super] that uses a partitioned index for the snapshot.
    //!
    //! See [crate::qmdb::any::unordered::fixed::partitioned] for details on partitioned indices and
    //! when to use them.

    use super::*;
    use crate::index::partitioned::unordered::Index;

    /// A partitioned variant of [super::Db].
    ///
    /// The const generic `P` specifies the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    pub type Db<F, E, K, V, H, T, const P: usize, const N: usize> =
        crate::qmdb::current::unordered::db::Db<
            F,
            E,
            Journal<E, Operation<F, K, V>>,
            K,
            FixedEncoding<V>,
            Index<T, Location<F>, P>,
            H,
            N,
        >;

    impl<
            F: Graftable,
            E: Context,
            K: Array,
            V: FixedValue,
            H: Hasher,
            T: Translator,
            const P: usize,
            const N: usize,
        > Db<F, E, K, V, H, T, P, N>
    {
        /// Initializes a [Db] authenticated database from the given `config`. Leverages parallel
        /// Merkleization to initialize the bitmap Merkle tree if a thread pool is provided.
        pub async fn init(context: E, config: Config<T>) -> Result<Self, Error<F>> {
            crate::qmdb::current::init(context, config).await
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        mmr,
        qmdb::current::{tests::fixed_config, unordered::tests as shared},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::deterministic;

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest = Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, 32>;

    #[allow(dead_code)]
    type CurrentTokio =
        Db<mmr::Family, commonware_runtime::tokio::Context, Digest, Digest, Sha256, TwoCap, 32>;
    fn _assert_send<T: Send>() {}
    fn _assert_sync<T: Sync>() {}
    fn _check_current_send_sync() {
        _assert_send::<CurrentTest>();
        _assert_sync::<CurrentTest>();
        _assert_send::<CurrentTokio>();
        _assert_sync::<CurrentTokio>();
    }

    fn assert_send<T: Send>(_: T) {}
    fn require_send_future<F: core::future::Future + Send>(_: F) {}

    #[allow(dead_code)]
    fn _check_current_ref_send_and_futures(db: &CurrentTokio, key: &Digest) {
        assert_send(db);
        assert_send(db.get(key));
        assert_send(db.get_metadata());
        assert_send(db.bounds());
        assert_send(db.sync());
    }

    // Mirrors the "submit pipeline doing 3-5 QMDB reads" scenario from issue #3666:
    // &Db is held across multiple .await points inside the caller's own Send future.
    #[allow(dead_code)]
    async fn _current_pipeline_3_reads(db: &CurrentTokio, k1: &Digest, k2: &Digest, k3: &Digest) {
        let _ = db.get(k1).await;
        let _ = db.get(k2).await;
        let _ = db.get(k3).await;
    }

    #[allow(dead_code)]
    fn _check_current_pipeline_send(db: &CurrentTokio, k1: &Digest, k2: &Digest, k3: &Digest) {
        assert_send(_current_pipeline_3_reads(db, k1, k2, k3));
        require_send_future(async move {
            let _ = db.get(k1).await;
            let _ = db.get(k2).await;
        });
    }

    /// Return a [Db] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context, partition_prefix: String) -> CurrentTest {
        let cfg = fixed_config::<TwoCap>(&partition_prefix, &context);
        CurrentTest::init(context, cfg).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        shared::test_verify_proof_over_bits_in_uncommitted_chunk(open_db);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        shared::test_range_proofs(open_db);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        shared::test_key_value_proof(open_db);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        shared::test_proving_repeated_updates(open_db);
    }
}
