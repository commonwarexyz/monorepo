use crate::{
    merkle::{mmr, Family, Location, Proof},
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
        current::sync::CurrentOverlayState,
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
use commonware_utils::{channel::oneshot, sync::AsyncRwLock, Array};
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Result from a fetch operation.
///
/// Parameterized over the merkle family `F` so the embedded `Proof<F, D>` matches
/// the [Database](super::Database) being synced.
pub struct FetchResult<F: Family, Op, D: Digest> {
    /// The proof for the operations
    pub proof: Proof<F, D>,
    /// The operations that were fetched
    pub operations: Vec<Op>,
    /// Channel to report success/failure back to resolver
    pub success_tx: oneshot::Sender<bool>,
    /// Pinned MMR nodes at the start location, if requested
    pub pinned_nodes: Option<Vec<D>>,
    /// Sender's current overlay state, populated only on the first (boundary) batch by
    /// [crate::qmdb::current::sync] resolvers; `None` otherwise. The engine extracts overlay
    /// state only when the same conditions that gate `pinned_nodes` hold (first batch at the
    /// sync range's lower bound).
    ///
    /// Overlay state is not authenticated by the ops-root proof chain and must be validated
    /// indirectly by the receiver by comparing the rebuilt database's canonical root against
    /// a trusted canonical root supplied in the sync target.
    pub overlay_state: Option<CurrentOverlayState<D>>,
}

impl<F: Family, Op: std::fmt::Debug, D: Digest> std::fmt::Debug for FetchResult<F, Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchResult")
            .field("proof", &self.proof)
            .field("operations", &self.operations)
            .field("success_tx", &"<callback>")
            .field("pinned_nodes", &self.pinned_nodes)
            .field("overlay_state", &self.overlay_state)
            .finish()
    }
}

/// Trait for network communication with the sync server.
///
/// The associated `Family` is the merkle family whose proofs this resolver serves.
/// It must match the [Database](super::Database) being synced.
pub trait Resolver: Send + Sync + Clone + 'static {
    /// The merkle family backing the resolver's proofs.
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
    /// pinned MMR nodes at `start_loc` and, for `current` resolvers, the sender's current
    /// [`CurrentOverlayState`] in `FetchResult::overlay_state`.
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
        impl<E, K, V, H, T> Resolver for Arc<$db<mmr::Family, E, K, V, H, T>>
        where
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<mmr::Family, K, V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
                })
            }
        }

        impl<E, K, V, H, T> Resolver for Arc<AsyncRwLock<$db<mmr::Family, E, K, V, H, T>>>
        where
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<mmr::Family, K, V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
                })
            }
        }

        impl<E, K, V, H, T> Resolver for Arc<AsyncRwLock<Option<$db<mmr::Family, E, K, V, H, T>>>>
        where
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<mmr::Family, K, V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
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

// Immutable types have a different Operation signature (no F parameter),
// so we use a separate macro.
macro_rules! impl_resolver_immutable {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path) => {
        impl<E, K, V, H, T> Resolver for Arc<$db<mmr::Family, E, K, V, H, T>>
        where
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
                })
            }
        }

        impl<E, K, V, H, T> Resolver for Arc<AsyncRwLock<$db<mmr::Family, E, K, V, H, T>>>
        where
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
                })
            }
        }

        impl<E, K, V, H, T> Resolver for Arc<AsyncRwLock<Option<$db<mmr::Family, E, K, V, H, T>>>>
        where
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
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
        impl<E, V, H> Resolver for Arc<$db<mmr::Family, E, V, H>>
        where
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
                })
            }
        }

        impl<E, V, H> Resolver for Arc<AsyncRwLock<$db<mmr::Family, E, V, H>>>
        where
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
                })
            }
        }

        impl<E, V, H> Resolver for Arc<AsyncRwLock<Option<$db<mmr::Family, E, V, H>>>>
        where
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
        {
            type Family = mmr::Family;
            type Digest = H::Digest;
            type Op = $op<V>;
            type Error = qmdb::Error<mmr::Family>;

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
                    overlay_state: None,
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
    use std::marker::PhantomData;

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
}
