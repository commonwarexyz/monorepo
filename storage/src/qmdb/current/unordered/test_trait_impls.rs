//! Test trait implementations for the unordered Current QMDB.

use super::{fixed, variable};
use crate::{
    merkle::Graftable,
    qmdb::{
        any::{unordered::variable::Operation as VariableOperation, FixedValue, VariableValue},
        current::BitmapPrunedBits,
    },
    translator::Translator,
    Context,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_utils::Array;

// =============================================================================
// Fixed variant test trait implementations
// =============================================================================

crate::qmdb::any::traits::impl_db_any! {
    [F, E, K, V, H, T, const N: usize] fixed::Db<F, E, K, V, H, T, N>
    where {
        F: Graftable,
        E: Context,
        K: Array,
        V: FixedValue + 'static,
        H: Hasher,
        T: Translator,
    }
    Family = F, Key = K, Value = V, Digest = H::Digest
}

// =============================================================================
// Variable variant test trait implementations
// =============================================================================

crate::qmdb::any::traits::impl_db_any! {
    [F, E, K, V, H, T, const N: usize] variable::Db<F, E, K, V, H, T, N>
    where {
        F: Graftable,
        E: Context,
        K: Array,
        V: VariableValue + 'static,
        H: Hasher,
        T: Translator,
        VariableOperation<F, K, V>: Read,
    }
    Family = F, Key = K, Value = V, Digest = H::Digest
}

// =============================================================================
// BitmapPrunedBits trait implementations
// =============================================================================

impl<
        F: Graftable,
        E: Context,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > BitmapPrunedBits for fixed::Db<F, E, K, V, H, T, N>
{
    fn pruned_bits(&self) -> u64 {
        self.any.bitmap.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.any.bitmap.get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}

impl<
        F: Graftable,
        E: Context,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > BitmapPrunedBits for variable::Db<F, E, K, V, H, T, N>
where
    VariableOperation<F, K, V>: Read,
{
    fn pruned_bits(&self) -> u64 {
        self.any.bitmap.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.any.bitmap.get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}

// =============================================================================
// Partitioned Fixed variant test trait implementations
// =============================================================================

crate::qmdb::any::traits::impl_db_any! {
    [F, E, K, V, H, T, const P: usize, const N: usize] fixed::partitioned::Db<F, E, K, V, H, T, P, N>
    where {
        F: Graftable,
        E: Context,
        K: Array,
        V: FixedValue + 'static,
        H: Hasher,
        T: Translator,
    }
    Family = F, Key = K, Value = V, Digest = H::Digest
}

impl<
        F: Graftable,
        E: Context,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > BitmapPrunedBits for fixed::partitioned::Db<F, E, K, V, H, T, P, N>
{
    fn pruned_bits(&self) -> u64 {
        self.any.bitmap.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.any.bitmap.get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}

// =============================================================================
// Partitioned Variable variant test trait implementations
// =============================================================================

crate::qmdb::any::traits::impl_db_any! {
    [F, E, K, V, H, T, const P: usize, const N: usize]
    variable::partitioned::Db<F, E, K, V, H, T, P, N>
    where {
        F: Graftable,
        E: Context,
        K: Array,
        V: VariableValue + 'static,
        H: Hasher,
        T: Translator,
        VariableOperation<F, K, V>: Read,
    }
    Family = F, Key = K, Value = V, Digest = H::Digest
}

impl<
        F: Graftable,
        E: Context,
        K: Array,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > BitmapPrunedBits for variable::partitioned::Db<F, E, K, V, H, T, P, N>
where
    VariableOperation<F, K, V>: Read,
{
    fn pruned_bits(&self) -> u64 {
        self.any.bitmap.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.any.bitmap.get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        *self.any.bounds().await.start
    }
}
