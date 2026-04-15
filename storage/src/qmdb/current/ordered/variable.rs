//! An _ordered_ variant of a [crate::qmdb::current] authenticated database for variable-size values
//!
//! This variant maintains the lexicographic-next active key for each active key, enabling exclusion
//! proofs (proving a key is currently inactive). Use [crate::qmdb::current::unordered::variable] if
//! exclusion proofs are not needed.
//!
//! See [Db] for the main database type and [super::ExclusionProof] for proving key inactivity.

pub use super::db::KeyValueProof;
use crate::{
    index::ordered::Index,
    journal::contiguous::variable::Journal,
    merkle::{Graftable, Location},
    qmdb::{
        any::{ordered::variable::Operation, value::VariableEncoding, VariableValue},
        current::VariableConfig as Config,
        operation::Key,
        Error,
    },
    translator::Translator,
    Context,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;

pub type Db<F, E, K, V, H, T, const N: usize> = super::db::Db<
    F,
    E,
    Journal<E, Operation<F, K, V>>,
    K,
    VariableEncoding<V>,
    Index<T, Location<F>>,
    H,
    N,
>;

impl<
        F: Graftable,
        E: Context,
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<F, E, K, V, H, T, N>
where
    Operation<F, K, V>: Codec,
{
    /// Initializes a [Db] from the given `config`. Leverages parallel Merkleization to initialize
    /// the bitmap Merkle tree if a thread pool is provided.
    pub async fn init(
        context: E,
        config: Config<T, <Operation<F, K, V> as Read>::Cfg>,
    ) -> Result<Self, Error<F>> {
        crate::qmdb::current::init(context, config).await
    }
}

pub mod partitioned {
    //! A variant of [super] that uses a partitioned index for the snapshot.

    use super::*;
    use crate::index::partitioned::ordered::Index;

    /// A partitioned variant of [super::Db].
    ///
    /// The const generic `P` specifies the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    pub type Db<F, E, K, V, H, T, const P: usize, const N: usize> =
        crate::qmdb::current::ordered::db::Db<
            F,
            E,
            Journal<E, Operation<F, K, V>>,
            K,
            VariableEncoding<V>,
            Index<T, Location<F>, P>,
            H,
            N,
        >;

    impl<
            F: Graftable,
            E: Context,
            K: Key,
            V: VariableValue,
            H: Hasher,
            T: Translator,
            const P: usize,
            const N: usize,
        > Db<F, E, K, V, H, T, P, N>
    where
        Operation<F, K, V>: Codec,
    {
        /// Initializes a [Db] from the given `config`. Leverages parallel Merkleization to initialize
        /// the bitmap Merkle tree if a thread pool is provided.
        pub async fn init(
            context: E,
            config: Config<T, <Operation<F, K, V> as Read>::Cfg>,
        ) -> Result<Self, Error<F>> {
            crate::qmdb::current::init(context, config).await
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        mmr,
        qmdb::current::{
            ordered::tests as shared,
            tests::{variable_config, PAGE_CACHE_SIZE, PAGE_SIZE},
        },
        translator::OneCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics};

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest =
        super::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 32>;

    /// Return a [Db] database initialized with a variable config.
    async fn open_db(context: deterministic::Context, partition_prefix: String) -> CurrentTest {
        let cfg = variable_config::<OneCap>(
            &partition_prefix,
            CacheRef::from_pooler(context.with_label("cache"), PAGE_SIZE, PAGE_CACHE_SIZE),
        );
        CurrentTest::init(context.with_label("db"), cfg)
            .await
            .unwrap()
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

    #[test_traced("DEBUG")]
    pub fn test_current_db_exclusion_proofs() {
        shared::test_exclusion_proofs(open_db);
    }
}
