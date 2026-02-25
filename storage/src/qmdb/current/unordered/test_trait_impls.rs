//! Test trait implementations for the unordered Current QMDB.

use super::{fixed, variable};
use crate::{
    mmr::Location,
    qmdb::{
        any::{
            states::CleanAny, unordered::variable::Operation as VariableOperation, FixedValue,
            VariableValue,
        },
        current::BitmapPrunedBits,
        store::LogStore,
        Error,
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
    > CleanAny for fixed::Db<E, K, V, H, T, N>
{
    fn into_mutable(self) -> Self {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self, Error> {
        self.into_merkleized().await
    }

    async fn commit(self, metadata: Option<V>) -> Result<(Self, Range<Location>), Error> {
        self.commit(metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.pending_steps
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
    > CleanAny for variable::Db<E, K, V, H, T, N>
where
    VariableOperation<K, V>: Read,
{
    fn into_mutable(self) -> Self {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self, Error> {
        self.into_merkleized().await
    }

    async fn commit(self, metadata: Option<V>) -> Result<(Self, Range<Location>), Error> {
        self.commit(metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.pending_steps
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
    > BitmapPrunedBits for fixed::Db<E, K, V, H, T, N>
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
    > BitmapPrunedBits for variable::Db<E, K, V, H, T, N>
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
    > CleanAny for fixed::partitioned::Db<E, K, V, H, T, P, N>
{
    fn into_mutable(self) -> Self {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self, Error> {
        self.into_merkleized().await
    }

    async fn commit(self, metadata: Option<V>) -> Result<(Self, Range<Location>), Error> {
        self.commit(metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.pending_steps
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
    > BitmapPrunedBits for fixed::partitioned::Db<E, K, V, H, T, P, N>
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
    > CleanAny for variable::partitioned::Db<E, K, V, H, T, P, N>
where
    VariableOperation<K, V>: Read,
{
    fn into_mutable(self) -> Self {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self, Error> {
        self.into_merkleized().await
    }

    async fn commit(self, metadata: Option<V>) -> Result<(Self, Range<Location>), Error> {
        self.commit(metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.pending_steps
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
    > BitmapPrunedBits for variable::partitioned::Db<E, K, V, H, T, P, N>
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
