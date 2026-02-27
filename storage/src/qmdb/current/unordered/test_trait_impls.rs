//! Test trait implementations for the unordered Current QMDB.

use super::{fixed, variable};
use crate::{
    mmr::Location,
    qmdb::{
        any::{
            states::{CleanAny, MutableAny},
            unordered::{
                fixed::Operation as FixedOperation, variable::Operation as VariableOperation,
            },
            FixedValue, VariableValue,
        },
        current::BitmapPrunedBits,
        store::LogStore,
        Durable, Error, NonDurable,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
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
    > CleanAny for fixed::Db<E, K, V, H, T, N, Durable>
{
    type Mutable = fixed::Db<E, K, V, H, T, N, NonDurable>;

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
    > MutableAny for fixed::Db<E, K, V, H, T, N, NonDurable>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Clean = fixed::Db<E, K, V, H, T, N, Durable>;

    async fn commit(self, metadata: Option<V>) -> Result<(Self::Clean, Range<Location>), Error> {
        self.commit(metadata).await
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
    > CleanAny for variable::Db<E, K, V, H, T, N, Durable>
where
    VariableOperation<K, V>: Read,
{
    type Mutable = variable::Db<E, K, V, H, T, N, NonDurable>;

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
    > MutableAny for variable::Db<E, K, V, H, T, N, NonDurable>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Clean = variable::Db<E, K, V, H, T, N, Durable>;

    async fn commit(self, metadata: Option<V>) -> Result<(Self::Clean, Range<Location>), Error> {
        self.commit(metadata).await
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
    > BitmapPrunedBits for fixed::Db<E, K, V, H, T, N, Durable>
{
    fn pruned_bits(&self) -> u64 {
        self.status.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.get_bit(index)
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
    > BitmapPrunedBits for variable::Db<E, K, V, H, T, N, Durable>
where
    VariableOperation<K, V>: Read,
{
    fn pruned_bits(&self) -> u64 {
        self.status.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.get_bit(index)
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
    > CleanAny for fixed::partitioned::Db<E, K, V, H, T, P, N, Durable>
{
    type Mutable = fixed::partitioned::Db<E, K, V, H, T, P, N, NonDurable>;

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
    > MutableAny for fixed::partitioned::Db<E, K, V, H, T, P, N, NonDurable>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Clean = fixed::partitioned::Db<E, K, V, H, T, P, N, Durable>;

    async fn commit(self, metadata: Option<V>) -> Result<(Self::Clean, Range<Location>), Error> {
        self.commit(metadata).await
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
    > BitmapPrunedBits for fixed::partitioned::Db<E, K, V, H, T, P, N, Durable>
{
    fn pruned_bits(&self) -> u64 {
        self.status.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.get_bit(index)
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
    > CleanAny for variable::partitioned::Db<E, K, V, H, T, P, N, Durable>
where
    VariableOperation<K, V>: Read,
{
    type Mutable = variable::partitioned::Db<E, K, V, H, T, P, N, NonDurable>;

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
    > MutableAny for variable::partitioned::Db<E, K, V, H, T, P, N, NonDurable>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Clean = variable::partitioned::Db<E, K, V, H, T, P, N, Durable>;

    async fn commit(self, metadata: Option<V>) -> Result<(Self::Clean, Range<Location>), Error> {
        self.commit(metadata).await
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
    > BitmapPrunedBits for variable::partitioned::Db<E, K, V, H, T, P, N, Durable>
where
    VariableOperation<K, V>: Read,
{
    fn pruned_bits(&self) -> u64 {
        self.status.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}
