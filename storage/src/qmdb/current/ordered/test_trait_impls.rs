//! Test trait implementations for the ordered Current QMDB.

use super::fixed::Db;
use crate::{
    mmr::Location,
    qmdb::{
        any::{
            ordered::fixed::Operation,
            states::{CleanAny, MerkleizedNonDurableAny, MutableAny, UnmerkleizedDurableAny},
            FixedValue,
        },
        Durable, Error, Merkleized, NonDurable, Unmerkleized,
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::ops::Range;

// CleanAny implementation
impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > CleanAny for Db<E, K, V, H, T, N, Merkleized<H>, Durable>
{
    type Mutable = Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

// UnmerkleizedDurableAny implementation
impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > UnmerkleizedDurableAny for Db<E, K, V, H, T, N, Unmerkleized, Durable>
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Mutable = Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;
    type Merkleized = Db<E, K, V, H, T, N, Merkleized<H>, Durable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }
}

// MerkleizedNonDurableAny implementation
impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MerkleizedNonDurableAny for Db<E, K, V, H, T, N, Merkleized<H>, NonDurable>
{
    type Mutable = Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

// MutableAny implementation
impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MutableAny for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Merkleized = Db<E, K, V, H, T, N, Merkleized<H>, NonDurable>;
    type Durable = Db<E, K, V, H, T, N, Unmerkleized, Durable>;

    async fn commit(self, metadata: Option<V>) -> Result<(Self::Durable, Range<Location>), Error> {
        self.commit(metadata).await
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }

    fn steps(&self) -> u64 {
        self.any.durable_state.steps
    }
}
