use crate::{
    adb::{
        any::{sync::Error, Any},
        operation::Fixed,
        sync::engine::FetchResult,
    },
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, RwLock, Storage};
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Trait for network communication with the sync server
pub trait Resolver: Send + Sync + Clone + 'static {
    type Digest: Digest;
    type Op;

    /// Get the operations starting at `start_loc` in the database, up to `max_ops` operations.
    /// Returns the operations and a proof that they were present in the database when it had
    /// `size` operations.
    #[allow(clippy::type_complexity)]
    fn get_operations<'a>(
        &'a self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<FetchResult<Self::Op, Self::Digest>, Error>> + Send + 'a;
}

impl<E, K, V, H, T> Resolver for Arc<Any<E, K, V, H, T>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
{
    type Digest = H::Digest;
    type Op = Fixed<K, V>;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Error> {
        self.historical_proof(size, start_loc, max_ops.get())
            .await
            .map(|(proof, operations)| FetchResult {
                proof,
                operations,
                // Result of proof verification isn't used by this implementation.
                success_tx: oneshot::channel().0,
            })
    }
}

/// Implement Resolver directly for `Arc<RwLock<Any>>` to provide maximum ergonomics.
/// This eliminates the need for wrapper types while allowing direct database access.
impl<E, K, V, H, T> Resolver for Arc<RwLock<Any<E, K, V, H, T>>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
{
    type Digest = H::Digest;
    type Op = Fixed<K, V>;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Error> {
        let db = self.read().await;
        db.historical_proof(size, start_loc, max_ops.get())
            .await
            .map(|(proof, operations)| FetchResult {
                proof,
                operations,
                // Result of proof verification isn't used by this implementation.
                success_tx: oneshot::channel().0,
            })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::marker::PhantomData;

    #[derive(Clone)]
    pub struct FailResolver<D, K, V> {
        _digest: PhantomData<D>,
        _key: PhantomData<K>,
        _value: PhantomData<V>,
    }

    impl<D, K, V> Resolver for FailResolver<D, K, V>
    where
        D: Digest,
        K: Array,
        V: Array,
    {
        type Digest = D;
        type Op = Fixed<K, V>;

        async fn get_operations(
            &self,
            _size: u64,
            _start_loc: u64,
            _max_ops: NonZeroU64,
        ) -> Result<FetchResult<Self::Op, Self::Digest>, Error> {
            Err(Error::KeyNotFound) // Arbitrary dummy error
        }
    }

    impl<D, K, V> FailResolver<D, K, V> {
        pub fn new() -> Self {
            Self {
                _digest: PhantomData,
                _key: PhantomData,
                _value: PhantomData,
            }
        }
    }
}
