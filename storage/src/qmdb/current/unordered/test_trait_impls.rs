//! Test trait implementations for the unordered Current QMDB.

use super::{fixed, variable};
use crate::{
    mmr::Location,
    qmdb::{
        any::{
            traits::DbAny, unordered::variable::Operation as VariableOperation, FixedValue,
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
    > DbAny for fixed::Db<E, K, V, H, T, N>
{
    type Digest = H::Digest;

    async fn commit(&mut self, metadata: Option<V>) -> Result<Range<Location>, Error> {
        Self::commit(self, metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.steps
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
    > DbAny for variable::Db<E, K, V, H, T, N>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;

    async fn commit(&mut self, metadata: Option<V>) -> Result<Range<Location>, Error> {
        Self::commit(self, metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.steps
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
    > DbAny for fixed::partitioned::Db<E, K, V, H, T, P, N>
{
    type Digest = H::Digest;

    async fn commit(&mut self, metadata: Option<V>) -> Result<Range<Location>, Error> {
        Self::commit(self, metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.steps
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
    > DbAny for variable::partitioned::Db<E, K, V, H, T, P, N>
where
    VariableOperation<K, V>: Read,
{
    type Digest = H::Digest;

    async fn commit(&mut self, metadata: Option<V>) -> Result<Range<Location>, Error> {
        Self::commit(self, metadata).await
    }

    fn steps(&self) -> u64 {
        self.any.steps
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
