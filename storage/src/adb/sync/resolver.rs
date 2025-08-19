use crate::{
    adb::{self, any::fixed::Any, immutable::Immutable},
    mmr::verification::Proof,
    store::operation::{Fixed, Variable},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, RwLock, Storage};
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Result from a fetch operation
pub struct FetchResult<Op, D: Digest> {
    /// The proof for the operations
    pub proof: Proof<D>,
    /// The operations that were fetched
    pub operations: Vec<Op>,
    /// Channel to report success/failure back to resolver
    pub success_tx: oneshot::Sender<bool>,
}

impl<Op: std::fmt::Debug, D: Digest> std::fmt::Debug for FetchResult<Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchResult")
            .field("proof", &self.proof)
            .field("operations", &self.operations)
            .field("success_tx", &"<callback>")
            .finish()
    }
}

/// Trait for network communication with the sync server
pub trait Resolver: Send + Sync + Clone + 'static {
    /// The digest type used in proofs returned by the resolver
    type Digest: Digest;

    /// The type of operations returned by the resolver
    type Op;

    /// The error type returned by the resolver
    type Error: std::error::Error + Send + 'static;

    /// Get the operations starting at `start_loc` in the database, up to `max_ops` operations.
    /// Returns the operations and a proof that they were present in the database when it had
    /// `size` operations.
    #[allow(clippy::type_complexity)]
    fn get_operations<'a>(
        &'a self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<FetchResult<Self::Op, Self::Digest>, Self::Error>> + Send + 'a;
}

impl<E, K, V, H, T> Resolver for Arc<Any<E, K, V, H, T>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()> + Send + Sync + 'static,
    H: Hasher,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
{
    type Digest = H::Digest;
    type Op = Fixed<K, V>;
    type Error = adb::Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
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

/// Implement Resolver directly for `Arc<RwLock<Any>>` to eliminate the need for wrapper types
/// while allowing direct database access.
impl<E, K, V, H, T> Resolver for Arc<RwLock<Any<E, K, V, H, T>>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()> + Send + Sync + 'static,
    H: Hasher,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
{
    type Digest = H::Digest;
    type Op = Fixed<K, V>;
    type Error = adb::Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, adb::Error> {
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

impl<E, K, V, H, T> Resolver for Arc<Immutable<E, K, V, H, T>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: commonware_codec::Codec + Send + Sync + 'static,
    H: Hasher,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
{
    type Digest = H::Digest;
    type Op = Variable<K, V>;
    type Error = crate::adb::Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
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

/// Implement Resolver directly for `Arc<RwLock<Immutable>>` to eliminate the need for wrapper
/// types while allowing direct database access.
impl<E, K, V, H, T> Resolver for Arc<RwLock<Immutable<E, K, V, H, T>>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: commonware_codec::Codec + Send + Sync + 'static,
    H: Hasher,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
{
    type Digest = H::Digest;
    type Op = Variable<K, V>;
    type Error = crate::adb::Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
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
        V: CodecFixed<Cfg = ()> + Clone + Send + Sync + 'static,
    {
        type Digest = D;
        type Op = Fixed<K, V>;
        type Error = adb::Error;

        async fn get_operations(
            &self,
            _size: u64,
            _start_loc: u64,
            _max_ops: NonZeroU64,
        ) -> Result<FetchResult<Self::Op, Self::Digest>, adb::Error> {
            Err(adb::Error::KeyNotFound) // Arbitrary dummy error
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
