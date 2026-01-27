use crate::{
    mmr::{Location, Proof},
    qmdb::{
        self,
        any::{
            ordered::{
                fixed::{Db as OrderedFixedDb, Operation as OrderedFixedOperation},
                variable::{Db as OrderedVariableDb, Operation as OrderedVariableOperation},
            },
            unordered::{
                fixed::{Db as FixedDb, Operation as FixedOperation},
                variable::{Db as VariableDb, Operation as VariableOperation},
            },
            FixedValue, VariableValue,
        },
        immutable::{Immutable, Operation as ImmutableOp},
        Durable, Merkleized,
    },
    translator::Translator,
};
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
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<FetchResult<Self::Op, Self::Digest>, Self::Error>> + Send + 'a;
}

macro_rules! impl_resolver {
    ($db:ident, $op:ident, $val_bound:ident) => {
        impl<E, K, V, H, T> Resolver for Arc<$db<E, K, V, H, T, Merkleized<H>, Durable>>
        where
            E: Storage + Clock + Metrics,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: NonZeroU64,
            ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
                self.historical_proof(op_count, start_loc, max_ops)
                    .await
                    .map(|(proof, operations)| FetchResult {
                        proof,
                        operations,
                        success_tx: oneshot::channel().0,
                    })
            }
        }

        impl<E, K, V, H, T> Resolver for Arc<RwLock<$db<E, K, V, H, T, Merkleized<H>, Durable>>>
        where
            E: Storage + Clock + Metrics,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: NonZeroU64,
            ) -> Result<FetchResult<Self::Op, Self::Digest>, qmdb::Error> {
                let db = self.read().await;
                db.historical_proof(op_count, start_loc, max_ops).await.map(
                    |(proof, operations)| FetchResult {
                        proof,
                        operations,
                        success_tx: oneshot::channel().0,
                    },
                )
            }
        }

        impl<E, K, V, H, T> Resolver
            for Arc<RwLock<Option<$db<E, K, V, H, T, Merkleized<H>, Durable>>>>
        where
            E: Storage + Clock + Metrics,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: NonZeroU64,
            ) -> Result<FetchResult<Self::Op, Self::Digest>, qmdb::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                db.historical_proof(op_count, start_loc, max_ops).await.map(
                    |(proof, operations)| FetchResult {
                        proof,
                        operations,
                        success_tx: oneshot::channel().0,
                    },
                )
            }
        }
    };
}

// Unordered Fixed
impl_resolver!(FixedDb, FixedOperation, FixedValue);

// Unordered Variable
impl_resolver!(VariableDb, VariableOperation, VariableValue);

// Ordered Fixed
impl_resolver!(OrderedFixedDb, OrderedFixedOperation, FixedValue);

// Ordered Variable
impl_resolver!(OrderedVariableDb, OrderedVariableOperation, VariableValue);

// Immutable
impl_resolver!(Immutable, ImmutableOp, VariableValue);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::marker::PhantomData;

    /// A resolver that always fails.
    #[derive(Clone)]
    pub struct FailResolver<Op, D> {
        _phantom: PhantomData<(Op, D)>,
    }

    impl<Op, D> Resolver for FailResolver<Op, D>
    where
        D: Digest,
        Op: Send + Sync + Clone + 'static,
    {
        type Digest = D;
        type Op = Op;
        type Error = qmdb::Error;

        async fn get_operations(
            &self,
            _op_count: Location,
            _start_loc: Location,
            _max_ops: NonZeroU64,
        ) -> Result<FetchResult<Self::Op, Self::Digest>, qmdb::Error> {
            Err(qmdb::Error::KeyNotFound) // Arbitrary dummy error
        }
    }

    impl<Op, D> FailResolver<Op, D> {
        pub fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
    }
}
