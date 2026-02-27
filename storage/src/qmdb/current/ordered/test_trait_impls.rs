//! Test trait implementations for the ordered Current QMDB.

use super::{fixed, variable};
use crate::{
    journal::contiguous::{Contiguous, Reader},
    mmr::Location,
    qmdb::{
        any::{
            ordered::{
                fixed::Operation as FixedOperation, variable::Operation as VariableOperation,
            },
            states::{CleanAny, MutableAny},
            FixedValue, VariableValue,
        },
        current::BitmapPrunedBits,
        operation::Key,
        store::LogStore as _,
        Error,
    },
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::{future::Future, ops::Range};

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
    type Mutable = Self;

    fn into_mutable(self) -> Self::Mutable {
        self
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MutableAny for fixed::Db<E, K, V, H, T, N>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Clean = Self;

    #[allow(clippy::manual_async_fn, clippy::needless_borrow)]
    fn commit(
        self,
        metadata: Option<V>,
    ) -> impl Future<Output = Result<(Self::Clean, Range<Location>), Error>> + Send {
        async move {
            let mut db = self;
            let range = (&mut db).commit(metadata).await?;
            Ok::<_, Error>((db, range))
        }
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
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > CleanAny for variable::Db<E, K, V, H, T, N>
where
    VariableOperation<K, V>: Codec,
{
    type Mutable = Self;

    fn into_mutable(self) -> Self::Mutable {
        self
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MutableAny for variable::Db<E, K, V, H, T, N>
where
    VariableOperation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Clean = Self;

    #[allow(clippy::manual_async_fn, clippy::needless_borrow)]
    fn commit(
        self,
        metadata: Option<V>,
    ) -> impl Future<Output = Result<(Self::Clean, Range<Location>), Error>> + Send {
        async move {
            let mut db = self;
            let range = (&mut db).commit(metadata).await?;
            Ok::<_, Error>((db, range))
        }
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
        self.any.log.reader().await.bounds().start
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > BitmapPrunedBits for variable::Db<E, K, V, H, T, N>
where
    VariableOperation<K, V>: Codec,
{
    fn pruned_bits(&self) -> u64 {
        self.status.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.status.get_bit(index)
    }

    async fn oldest_retained(&self) -> u64 {
        self.any.log.reader().await.bounds().start
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
    type Mutable = Self;

    fn into_mutable(self) -> Self::Mutable {
        self
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
    > MutableAny for fixed::partitioned::Db<E, K, V, H, T, P, N>
{
    type Digest = H::Digest;
    type Operation = FixedOperation<K, V>;
    type Clean = Self;

    #[allow(clippy::manual_async_fn, clippy::needless_borrow)]
    fn commit(
        self,
        metadata: Option<V>,
    ) -> impl Future<Output = Result<(Self::Clean, Range<Location>), Error>> + Send {
        async move {
            let mut db = self;
            let range = (&mut db).commit(metadata).await?;
            Ok::<_, Error>((db, range))
        }
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
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > CleanAny for variable::partitioned::Db<E, K, V, H, T, P, N>
where
    VariableOperation<K, V>: Codec,
{
    type Mutable = Self;

    fn into_mutable(self) -> Self::Mutable {
        self
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > MutableAny for variable::partitioned::Db<E, K, V, H, T, P, N>
where
    VariableOperation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = VariableOperation<K, V>;
    type Clean = Self;

    #[allow(clippy::manual_async_fn, clippy::needless_borrow)]
    fn commit(
        self,
        metadata: Option<V>,
    ) -> impl Future<Output = Result<(Self::Clean, Range<Location>), Error>> + Send {
        async move {
            let mut db = self;
            let range = (&mut db).commit(metadata).await?;
            Ok::<_, Error>((db, range))
        }
    }

    fn steps(&self) -> u64 {
        self.any.steps
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Key,
        V: VariableValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        const N: usize,
    > BitmapPrunedBits for variable::partitioned::Db<E, K, V, H, T, P, N>
where
    VariableOperation<K, V>: Codec,
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
