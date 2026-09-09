//! An _unordered_ variant of a [crate::qmdb::current] authenticated database for variable-size
//! values.
//!
//! This variant does not maintain key ordering, so it cannot generate exclusion proofs. Use
//! [crate::qmdb::current::ordered::variable] if exclusion proofs are required.
//!
//! See [Db] for the main database type.

pub use super::db::KeyValueProof;
use crate::{
    Context,
    index::unordered::Index,
    journal::contiguous::variable::Journal,
    merkle::{Graftable, Location},
    qmdb::{
        Error,
        any::{VariableValue, unordered::variable::Operation, value::VariableEncoding},
        current::VariableConfig as Config,
        operation::Key,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;

pub type Db<F, E, K, V, H, T, const N: usize, S> = super::db::Db<
    F,
    E,
    Journal<E, Operation<F, K, V>>,
    K,
    VariableEncoding<V>,
    Index<T, Location<F>>,
    H,
    N,
    S,
>;

impl<
    F: Graftable,
    E: Context + Spawner,
    K: Key,
    V: VariableValue,
    H: Hasher,
    T: Translator,
    const N: usize,
    S: Strategy,
> Db<F, E, K, V, H, T, N, S>
where
    Operation<F, K, V>: Read,
{
    /// Initializes a [Db] from the given `config`.
    /// The configured [`Strategy`] is used to parallelize merkleization.
    pub async fn init(
        context: E,
        config: Config<T, <Operation<F, K, V> as Read>::Cfg, S>,
    ) -> Result<Self, Error<F>> {
        crate::qmdb::current::init(context, config).await
    }
}

pub mod partitioned {
    //! A variant of [super] that uses a partitioned index for the snapshot.

    use super::*;
    use crate::index::partitioned::unordered::Index;

    /// A partitioned variant of [super::Db].
    ///
    /// The const generic `P` specifies the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    pub type Db<F, E, K, V, H, T, const P: usize, const N: usize, S> =
        crate::qmdb::current::unordered::db::Db<
            F,
            E,
            Journal<E, Operation<F, K, V>>,
            K,
            VariableEncoding<V>,
            Index<T, Location<F>, P>,
            H,
            N,
            S,
        >;

    impl<
        F: Graftable,
        E: Context + Spawner,
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
        S: Strategy,
    > Db<F, E, K, V, H, T, P, N, S>
    where
        Operation<F, K, V>: Read,
    {
        /// Initializes a [Db] from the given `config`.
        /// The configured [`Strategy`] is used to parallelize merkleization.
        pub async fn init(
            context: E,
            config: Config<T, <Operation<F, K, V> as Read>::Cfg, S, core::num::NonZeroUsize>,
        ) -> Result<Self, Error<F>> {
            crate::qmdb::current::init(context, config).await
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        mmr,
        qmdb::current::{tests::variable_config, unordered::tests as shared},
        translator::TwoCap,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest = Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        32,
        commonware_parallel::Sequential,
    >;

    /// Return a [Db] database initialized with a variable config.
    async fn open_db(context: deterministic::Context, partition_prefix: String) -> CurrentTest {
        let cfg = variable_config::<TwoCap>(&partition_prefix, &context);
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

    /// A [Db] keyed by variable-length byte keys.
    type VecKeyTest = Db<
        mmr::Family,
        deterministic::Context,
        Vec<u8>,
        Digest,
        Sha256,
        TwoCap,
        32,
        commonware_parallel::Sequential,
    >;

    #[test_traced("WARN")]
    pub fn test_current_db_variable_length_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Configure the operation codec for variable-length keys.
            let base = variable_config::<TwoCap>("vec-keys", &context);
            let cfg = crate::qmdb::current::VariableConfig {
                merkle_config: base.merkle_config.clone(),
                journal_config: crate::journal::contiguous::variable::Config {
                    partition: base.journal_config.partition.clone(),
                    items_per_section: base.journal_config.items_per_section,
                    compression: None,
                    codec_config: (((0..).into(), ()), ()),
                    page_cache: base.journal_config.page_cache.clone(),
                    write_buffer: base.journal_config.write_buffer,
                    replay_buffer: base.journal_config.replay_buffer,
                },
                grafted_metadata_partition: base.grafted_metadata_partition.clone(),
                translator: TwoCap,
                init_cache_size: base.init_cache_size,
                init_buffer: base.init_buffer,
                init_concurrency: (),
            };

            // Commit a value and verify its lookup and proof under a variable-length key.
            let db = VecKeyTest::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            let key = b"variable-length-key".to_vec();
            let value = Sha256::hash(&[b"value"]);
            let merkleized = db
                .new_batch()
                .write(key.clone(), Some(value))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let db = db.commit().await.unwrap();
            assert_eq!(db.get(&key).await.unwrap().unwrap(), value);
            let root = db.root();
            let proof = db.key_value_proof(key.clone()).await.unwrap();
            assert!(VecKeyTest::verify_key_value_proof(
                key.clone(),
                value,
                &proof,
                &root
            ));
            drop(db);

            // Reopen the database and verify the committed root and value.
            let db = VecKeyTest::init(context.child("second"), cfg)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.get(&key).await.unwrap().unwrap(), value);
            db.destroy().await.unwrap();
        });
    }
}
