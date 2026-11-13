//! An _ordered_ variant of a [crate::qmdb::current] authenticated database for variable-size values
//!
//! This variant maintains the lexicographic-next active key for each active key, enabling exclusion
//! proofs (proving a key is currently inactive). Use [crate::qmdb::current::unordered::variable] if
//! exclusion proofs are not needed.
//!
//! See [Db] for the main database type and
//! [ExclusionProof](super::proof::constant::ExclusionProof) for proving key inactivity.

pub use crate::qmdb::any::ordered::variable::{Operation, Update};
use crate::{
    index::ordered::Index,
    journal::contiguous::variable::{Config as JournalConfig, Journal},
    merkle::Location,
    qmdb::{current, value::VariableEncoding},
};

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

/// Configuration for a [Db].
pub type Config<T, C, S> = current::Config<T, JournalConfig<C>, S>;

pub mod partitioned {
    //! A variant of [super] that uses a partitioned key index, dividing the key space
    //! into `2^(P*8)` partitions. See [Any's counterpart] for when to use one.
    //!
    //! See [Db] for the generic type, or use the convenience aliases:
    //! - [p256::Db] for 256 partitions (P=1)
    //! - [p64k::Db] for 65,536 partitions (P=2)
    //!
    //! `p256` suits smaller datasets, but its partitions spill to a `BTreeMap` once the index holds
    //! more than 130,816 entries (see [`crate::index::partitioned::ordered`]). Prefer `p64k` to
    //! keep ordered access mostly inline at larger scale.
    //!
    //! [Any's counterpart]: crate::qmdb::any::ordered::variable::partitioned

    use super::*;
    pub use super::{Operation, Update};
    use crate::index::partitioned::ordered::Index;
    use core::num::NonZeroUsize;

    /// A partitioned variant of [super::Db].
    ///
    /// The const generic `P` specifies the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    pub type Db<F, E, K, V, H, T, const P: usize, const N: usize, S> =
        crate::qmdb::current::ordered::db::Db<
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

    /// Configuration for a [Db].
    pub type Config<T, C, S> = current::Config<T, JournalConfig<C>, S, NonZeroUsize>;

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Variable-value DB with 256 partitions.
        pub type Db<F, E, K, V, H, T, const N: usize, S> = super::Db<F, E, K, V, H, T, 1, N, S>;
        pub use super::Config;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Variable-value DB with 65,536 partitions.
        pub type Db<F, E, K, V, H, T, const N: usize, S> = super::Db<F, E, K, V, H, T, 2, N, S>;
        pub use super::Config;
    }
}

#[cfg(test)]
mod test {
    use crate::{
        merkle::Graftable,
        mmb, mmr,
        qmdb::current::{ordered::tests as shared, tests::variable_config},
        translator::OneCap,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::deterministic;

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest<F = mmr::Family> = super::Db<
        F,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        32,
        commonware_parallel::Sequential,
    >;

    /// Return a [Db] database initialized with a variable config.
    async fn open_db<F: Graftable>(
        context: deterministic::Context,
        partition_prefix: String,
    ) -> CurrentTest<F> {
        let cfg = variable_config::<OneCap>(&partition_prefix);
        CurrentTest::<F>::init(context, cfg, None).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        shared::test_verify_proof_over_bits_in_uncommitted_chunk(open_db::<mmr::Family>);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        shared::test_range_proofs(open_db::<mmr::Family>);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        shared::test_key_value_proof(open_db::<mmr::Family>);
    }

    #[test_traced("DEBUG")]
    fn test_current_db_dynamic_key_value_proof_mmb() {
        shared::test_key_value_proof(open_db::<mmb::Family>);
    }

    #[test_traced("DEBUG")]
    fn test_current_db_dynamic_exclusion_proofs_mmb() {
        shared::test_exclusion_proofs(open_db::<mmb::Family>);
    }

    #[test_traced("DEBUG")]
    fn test_current_db_dynamic_inactive_proof_mmb() {
        shared::test_verify_proof_over_bits_in_uncommitted_chunk(open_db::<mmb::Family>);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        shared::test_proving_repeated_updates(open_db::<mmr::Family>);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_exclusion_proofs() {
        shared::test_exclusion_proofs(open_db::<mmr::Family>);
    }
}
