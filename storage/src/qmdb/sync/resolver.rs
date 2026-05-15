use crate::{
    merkle::{Family, Location, Proof},
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
        immutable::{
            fixed::{Db as ImmutableFixedDb, Operation as ImmutableFixedOp},
            variable::{Db as ImmutableVariableDb, Operation as ImmutableVariableOp},
        },
        keyless::{
            fixed::{Db as KeylessFixedDb, Operation as KeylessFixedOp},
            variable::{Db as KeylessVariableDb, Operation as KeylessVariableOp},
        },
        operation::Key,
    },
    translator::Translator,
    Context,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{channel::oneshot, sync::AsyncRwLock, Array};
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Result from a fetch operation.
pub struct FetchResult<F: Family, Op, D: Digest> {
    /// The proof for the operations
    pub proof: Proof<F, D>,
    /// The operations that were fetched
    pub operations: Vec<Op>,
    /// Channel to report success/failure back to resolver
    pub success_tx: oneshot::Sender<bool>,
    /// Pinned merkle nodes at the start location, if requested
    pub pinned_nodes: Option<Vec<D>>,
}

impl<F: Family, Op: std::fmt::Debug, D: Digest> std::fmt::Debug for FetchResult<F, Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchResult")
            .field("proof", &self.proof)
            .field("operations", &self.operations)
            .field("success_tx", &"<callback>")
            .field("pinned_nodes", &self.pinned_nodes)
            .finish()
    }
}

/// Trait for network communication with the sync server.
pub trait Resolver: Send + Sync + Clone + 'static {
    /// The merkle family backing the resolver's proofs
    type Family: Family;

    /// The digest type used in proofs returned by the resolver
    type Digest: Digest;

    /// The type of operations returned by the resolver
    type Op;

    /// The error type returned by the resolver
    type Error: std::error::Error + Send + 'static;

    /// Get the operations starting at `start_loc` in the database, up to `max_ops` operations.
    /// Returns the operations and a proof that they were present in the database when it had
    /// `op_count` operations. If `include_pinned_nodes` is true, the result will include the
    /// pinned merkle nodes at `start_loc`.
    ///
    /// The corresponding `cancel_tx` is dropped when the engine no longer needs this
    /// request (e.g. due to a target update), causing `cancel_rx.await` to return
    /// `Err`. Implementations may `select!` on it to abort in-flight work early.
    #[allow(clippy::type_complexity)]
    fn get_operations<'a>(
        &'a self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> impl Future<Output = Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>>
           + Send
           + 'a;
}

macro_rules! impl_resolver {
    ($db:ident, $op:ident, $val_bound:ident) => {
        impl<F, E, K, V, H, T, S> Resolver for Arc<$db<F, E, K, V, H, T, S>>
        where
            F: Family,
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let (proof, operations) =
                    self.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(self.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<F, E, K, V, H, T, S> Resolver for Arc<AsyncRwLock<$db<F, E, K, V, H, T, S>>>
        where
            F: Family,
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                let (proof, operations) = db.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<F, E, K, V, H, T, S> Resolver for Arc<AsyncRwLock<Option<$db<F, E, K, V, H, T, S>>>>
        where
            F: Family,
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                let (proof, operations) = db.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
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

// Immutable types need a separate macro because the key bound varies
// (Array for fixed, Key for variable) unlike the other DB types which
// always use Array.
macro_rules! impl_resolver_immutable {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path) => {
        impl<F, E, K, V, H, T, S> Resolver for Arc<$db<F, E, K, V, H, T, S>>
        where
            F: Family,
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let (proof, operations) =
                    self.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(self.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<F, E, K, V, H, T, S> Resolver for Arc<AsyncRwLock<$db<F, E, K, V, H, T, S>>>
        where
            F: Family,
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                let (proof, operations) = db.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<F, E, K, V, H, T, S> Resolver for Arc<AsyncRwLock<Option<$db<F, E, K, V, H, T, S>>>>
        where
            F: Family,
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                let (proof, operations) = db.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }
    };
}

// Immutable Fixed
impl_resolver_immutable!(ImmutableFixedDb, ImmutableFixedOp, FixedValue, Array);

// Immutable Variable
impl_resolver_immutable!(ImmutableVariableDb, ImmutableVariableOp, VariableValue, Key);

// Keyless types have no key or translator, so they need their own macro.
macro_rules! impl_resolver_keyless {
    ($db:ident, $op:ident, $val_bound:ident) => {
        impl<F, E, V, H, S> Resolver for Arc<$db<F, E, V, H, S>>
        where
            F: Family,
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let (proof, operations) =
                    self.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(self.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<F, E, V, H, S> Resolver for Arc<AsyncRwLock<$db<F, E, V, H, S>>>
        where
            F: Family,
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                let (proof, operations) = db.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<F, E, V, H, S> Resolver for Arc<AsyncRwLock<Option<$db<F, E, V, H, S>>>>
        where
            F: Family,
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                let (proof, operations) = db.historical_proof(op_count, start_loc, max_ops).await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }
    };
}

// Keyless Fixed
impl_resolver_keyless!(KeylessFixedDb, KeylessFixedOp, FixedValue);

// Keyless Variable
impl_resolver_keyless!(KeylessVariableDb, KeylessVariableOp, VariableValue);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        merkle::mmr,
        translator::{OneCap, TwoCap},
    };
    use commonware_cryptography::{sha256::Digest as ShaDigest, Sha256};
    use commonware_parallel::Rayon;
    use commonware_runtime::deterministic;
    use commonware_utils::sync::AsyncRwLock;
    use std::{marker::PhantomData, sync::Arc};

    macro_rules! assert_resolver_variants {
        ($db:ty) => {
            assert_resolver::<Arc<$db>>();
            assert_resolver::<Arc<AsyncRwLock<$db>>>();
            assert_resolver::<Arc<AsyncRwLock<Option<$db>>>>();
        };
    }

    fn assert_resolver<R: Resolver>() {}

    /// A resolver that always fails.
    #[derive(Clone)]
    pub struct FailResolver<F: Family, Op, D> {
        _phantom: PhantomData<(F, Op, D)>,
    }

    impl<F, Op, D> Resolver for FailResolver<F, Op, D>
    where
        F: Family,
        D: Digest,
        Op: Send + Sync + Clone + 'static,
    {
        type Family = F;
        type Digest = D;
        type Op = Op;
        type Error = qmdb::Error<F>;

        async fn get_operations(
            &self,
            _op_count: Location<F>,
            _start_loc: Location<F>,
            _max_ops: NonZeroU64,
            _include_pinned_nodes: bool,
            _cancel: oneshot::Receiver<()>,
        ) -> Result<FetchResult<F, Op, D>, qmdb::Error<F>> {
            Err(qmdb::Error::KeyNotFound) // Arbitrary dummy error
        }
    }

    impl<F: Family, Op, D> FailResolver<F, Op, D> {
        pub fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
    }

    #[test]
    fn test_all_qmdb_variants_implement_strategy_resolvers() {
        type AnyOrderedFixed = crate::qmdb::any::ordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            OneCap,
            Rayon,
        >;
        type AnyOrderedVariable = crate::qmdb::any::ordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            OneCap,
            Rayon,
        >;
        type AnyUnorderedFixed = crate::qmdb::any::unordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type AnyUnorderedVariable = crate::qmdb::any::unordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type CurrentOrderedFixed = crate::qmdb::current::ordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            OneCap,
            32,
            Rayon,
        >;
        type CurrentOrderedVariable = crate::qmdb::current::ordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            OneCap,
            32,
            Rayon,
        >;
        type CurrentUnorderedFixed = crate::qmdb::current::unordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            TwoCap,
            32,
            Rayon,
        >;
        type CurrentUnorderedVariable = crate::qmdb::current::unordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            TwoCap,
            32,
            Rayon,
        >;
        type ImmutableFixed = crate::qmdb::immutable::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type ImmutableVariable = crate::qmdb::immutable::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type KeylessFixed = crate::qmdb::keyless::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Sha256,
            Rayon,
        >;
        type KeylessVariable = crate::qmdb::keyless::variable::Db<
            mmr::Family,
            deterministic::Context,
            Vec<u8>,
            Sha256,
            Rayon,
        >;

        assert_resolver_variants!(AnyOrderedFixed);
        assert_resolver_variants!(AnyOrderedVariable);
        assert_resolver_variants!(AnyUnorderedFixed);
        assert_resolver_variants!(AnyUnorderedVariable);
        assert_resolver_variants!(CurrentOrderedFixed);
        assert_resolver_variants!(CurrentOrderedVariable);
        assert_resolver_variants!(CurrentUnorderedFixed);
        assert_resolver_variants!(CurrentUnorderedVariable);
        assert_resolver_variants!(ImmutableFixed);
        assert_resolver_variants!(ImmutableVariable);
        assert_resolver_variants!(KeylessFixed);
        assert_resolver_variants!(KeylessVariable);
    }
}
