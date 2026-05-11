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
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::Array;

/// A specialization of [super::db::Db] for unordered key spaces and fixed-size values.
pub type Db<F, E, K, V, H, T, const N: usize, S = Sequential> = super::db::Db<
    F,
    E,
    Journal<E, Operation<F, K, V>>,
    K,
    FixedEncoding<V>,
    Index<T, Location<F>>,
    H,
    N,
    S,
>;

impl<
        F: Graftable,
        E: Context,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        S: Strategy,
    > Db<F, E, K, V, H, T, N, S>
{
    /// Initializes a [Db] authenticated database from the given `config`.
    /// The configured [`Strategy`] is used to parallelize merkleization.
    pub async fn init(context: E, config: Config<T, S>) -> Result<Self, Error<F>> {
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
    pub type Db<F, E, K, V, H, T, const P: usize, const N: usize, S = Sequential> =
        crate::qmdb::current::unordered::db::Db<
            F,
            E,
            Journal<E, Operation<F, K, V>>,
            K,
            FixedEncoding<V>,
            Index<T, Location<F>, P>,
            H,
            N,
            S,
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
            S: Strategy,
        > Db<F, E, K, V, H, T, P, N, S>
    {
        /// Initializes a [Db] authenticated database from the given `config`.
        /// The configured [`Strategy`] is used to parallelize merkleization.
        pub async fn init(context: E, config: Config<T, S>) -> Result<Self, Error<F>> {
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
    use commonware_runtime::{deterministic, Metrics, Runner as _, Supervisor as _};

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest = Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, 32>;

    /// Return a [Db] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context, partition_prefix: String) -> CurrentTest {
        let cfg = fixed_config::<TwoCap>(&partition_prefix, &context);
        CurrentTest::init(context, cfg).await.unwrap()
    }

    #[test_traced("INFO")]
    pub fn test_current_unordered_fixed_metrics() {
        deterministic::Runner::default().start(|ctx| async move {
            let mut db = open_db(ctx.child("current"), "metrics".to_string()).await;
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(2u8);
            let batch = db
                .new_batch()
                .write(key, Some(value))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(batch).await.unwrap();
            assert_eq!(db.get(&key).await.unwrap(), Some(value));
            db.sync().await.unwrap();
            db.prune(db.sync_boundary()).await.unwrap();

            let metrics = ctx.encode();
            for expected in [
                "current_apply_batch_calls_total 1",
                "current_sync_calls_total 1",
                "current_prune_calls_total 1",
                "current_pruned_chunks 0",
                "current_sync_boundary 0",
                "current_apply_batch_duration_count 1",
                "current_sync_duration_count 1",
                "current_prune_duration_count 1",
                "current_any_get_calls_total 1",
                "current_any_apply_batch_calls_total 1",
            ] {
                assert!(metrics.contains(expected), "missing {expected}\n{metrics}");
            }
            assert!(!metrics.contains("current_get_calls_total"));
        });
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
