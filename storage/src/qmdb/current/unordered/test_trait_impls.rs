//! Test trait implementations for the unordered Current QMDB.

use super::{fixed, variable};
use crate::{
    mmr::Location,
    qmdb::{
        any::{
            states::{CleanAny, MerkleizedNonDurableAny, MutableAny, UnmerkleizedDurableAny},
            unordered::{
                fixed::Operation as FixedOperation, variable::Operation as VariableOperation,
            },
            FixedValue, VariableValue,
        },
        current::{
            db::{Merkleized, Unmerkleized},
            BitmapPrunedBits,
        },
        store::LogStore,
        Durable, Error, NonDurable,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::ops::Range;

// =============================================================================
// Fixed variant test trait implementations
// =============================================================================

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > CleanAny for fixed::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
{
    type Mutable = fixed::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > UnmerkleizedDurableAny for fixed::Db<E, K, V, H, T, N, Unmerkleized, Durable>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Mutable = fixed::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;
    type Merkleized = fixed::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MerkleizedNonDurableAny for fixed::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, NonDurable>
{
    type Mutable = fixed::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MutableAny for fixed::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Durable = fixed::Db<E, K, V, H, T, N, Unmerkleized, Durable>;
    type Merkleized = fixed::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, NonDurable>;

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

// =============================================================================
// Variable variant test trait implementations
// =============================================================================

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > CleanAny for variable::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
where
    VariableOperation<K, V>: Read,
{
    type Mutable = variable::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > UnmerkleizedDurableAny for variable::Db<E, K, V, H, T, N, Unmerkleized, Durable>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Mutable = variable::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;
    type Merkleized = variable::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MerkleizedNonDurableAny
    for variable::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, NonDurable>
where
    VariableOperation<K, V>: Read,
{
    type Mutable = variable::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MutableAny for variable::Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Durable = variable::Db<E, K, V, H, T, N, Unmerkleized, Durable>;
    type Merkleized = variable::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, NonDurable>;

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

// =============================================================================
// BitmapPrunedBits trait implementations
// =============================================================================

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > BitmapPrunedBits for fixed::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
{
    fn pruned_bits(&self) -> u64 {
        self.status.current().pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.current().get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > BitmapPrunedBits for variable::Db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
where
    VariableOperation<K, V>: Read,
{
    fn pruned_bits(&self) -> u64 {
        self.status.current().pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.current().get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}

// =============================================================================
// Partitioned Fixed variant test trait implementations
// =============================================================================

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > CleanAny for fixed::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, Durable>
{
    type Mutable = fixed::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > UnmerkleizedDurableAny
    for fixed::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, Durable>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Mutable = fixed::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>;
    type Merkleized = fixed::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, Durable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > MerkleizedNonDurableAny
    for fixed::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, NonDurable>
{
    type Mutable = fixed::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > MutableAny for fixed::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Durable = fixed::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, Durable>;
    type Merkleized =
        fixed::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, NonDurable>;

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

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > BitmapPrunedBits
    for fixed::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, Durable>
{
    fn pruned_bits(&self) -> u64 {
        self.status.current().pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.current().get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}

// =============================================================================
// Partitioned Variable variant test trait implementations
// =============================================================================

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > CleanAny for variable::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, Durable>
where
    VariableOperation<K, V>: Read,
{
    type Mutable = variable::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > UnmerkleizedDurableAny
    for variable::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, Durable>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Mutable = variable::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>;
    type Merkleized =
        variable::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, Durable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > MerkleizedNonDurableAny
    for variable::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, NonDurable>
where
    VariableOperation<K, V>: Read,
{
    type Mutable = variable::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > MutableAny for variable::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, NonDurable>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Durable = variable::partitioned::Db<E, K, V, H, T, P, N, Unmerkleized, Durable>;
    type Merkleized =
        variable::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, NonDurable>;

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

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > BitmapPrunedBits
    for variable::partitioned::Db<E, K, V, H, T, P, N, Merkleized<DigestOf<H>>, Durable>
where
    VariableOperation<K, V>: Read,
{
    fn pruned_bits(&self) -> u64 {
        self.status.current().pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.current().get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}
