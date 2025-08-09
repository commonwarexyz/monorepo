use crate::{
    adb::any::{fixed::Any, sync::Error},
    mmr::verification::Proof,
    store::operation::Fixed,
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, RwLock, Storage};
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Result of a call to [Resolver::get_operations].
pub struct GetOperationsResult<D: Digest, K: Array, V: Array> {
    /// Proof that the operations are valid.
    pub proof: Proof<D>,
    /// The operations in the requested range.
    pub operations: Vec<Fixed<K, V>>,
    /// A channel to send the result of the proof verification.
    /// Caller should send `true` if the proof is valid, `false` otherwise.
    /// Caller should ignore error if the channel is closed.
    pub success_tx: oneshot::Sender<bool>,
}

/// Trait for network communication with the sync server
pub trait Resolver: Send + Sync + Clone + 'static {
    type Digest: Digest;
    type Key: Array;
    type Value: Array;

    /// Get the operations starting at `start_loc` in the database, up to `max_ops` operations.
    /// Returns the operations and a proof that they were present in the database when it had
    /// `size` operations.
    #[allow(clippy::type_complexity)]
    fn get_operations<'a>(
        &'a self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, Error>>
           + Send
           + 'a;
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
    type Key = K;
    type Value = V;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, Error> {
        self.historical_proof(size, start_loc, max_ops.get())
            .await
            .map_err(Error::Adb)
            .map(|(proof, operations)| GetOperationsResult {
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
    type Key = K;
    type Value = V;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, Error> {
        let db = self.read().await;
        db.historical_proof(size, start_loc, max_ops.get())
            .await
            .map_err(Error::Adb)
            .map(|(proof, operations)| GetOperationsResult {
                proof,
                operations,
                // Result of proof verification isn't used by this implementation.
                success_tx: oneshot::channel().0,
            })
    }
}

#[cfg(test)]
pub(super) mod tests {
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
        type Key = K;
        type Value = V;

        async fn get_operations(
            &self,
            _size: u64,
            _start_loc: u64,
            _max_ops: NonZeroU64,
        ) -> Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, Error> {
            Err(Error::AlreadyComplete)
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
