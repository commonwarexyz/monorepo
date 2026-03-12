//! Database batch lifecycle traits for stateful applications.
//!
//! This module defines the traits that bridge the [`Stateful`](super::wrapper::Stateful)
//! wrapper with the underlying storage layer (QMDB). The batch lifecycle has
//! three stages:
//!
//! 1. [`Unmerkleized`]: an in-progress batch of reads and writes.
//! 2. [`Merkleized`]: a sealed batch whose state root has been computed.
//! 3. Finalization: applying a merkleized batch's changeset to the
//!    database via [`ManagedDb::finalize`].
//!
//! [`DatabaseSet`] composes one or more [`ManagedDb`] instances (each behind
//! its own `Arc<AsyncRwLock<...>>`) into a single unit that the wrapper
//! manages as a group. It is implemented for `Arc<AsyncRwLock<T>>` (singleton)
//! and for tuples of up to 8 such values.

use commonware_cryptography::Digest;
use commonware_utils::sync::AsyncRwLock;
use std::{fmt::Debug, future::Future, sync::Arc};

/// An in-progress batch of mutations that has not yet been merkleized.
///
/// The application reads state via [`get`](Self::get), writes mutations via
/// [`write`](Self::write), and seals the batch by calling
/// [`merkleize`](Self::merkleize) at the end of execution.
pub trait Unmerkleized: Sized + Send {
    /// The key type for this database.
    type Key: Send;

    /// The value type for this database.
    type Value: Send;

    /// The merkleized batch produced by [`merkleize`](Self::merkleize).
    type Merkleized: Merkleized;

    /// The error type returned by fallible operations.
    type Error: Send;

    /// Read a value by key.
    ///
    /// Returns the most recent mutation in this batch's chain, falling back
    /// to the committed database state.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>> + Send;

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    fn write(self, key: Self::Key, value: Option<Self::Value>) -> Self;

    /// Resolve all mutations, compute the new state root, and produce a
    /// merkleized batch.
    fn merkleize(self) -> impl Future<Output = Result<Self::Merkleized, Self::Error>> + Send;
}

/// A sealed batch whose state root has been computed.
///
/// The application inspects the [`root`](Self::root) to embed in a block
/// header. The wrapper stores the batch as pending and later finalizes it.
pub trait Merkleized: Sized + Send + Sync {
    /// The digest type used for the state root.
    type Digest: Digest;

    /// The unmerkleized batch type produced by [`new_batch`](Self::new_batch).
    type Unmerkleized: Unmerkleized;

    /// The committed state root after merkleization.
    fn root(&self) -> Self::Digest;

    /// Create a child unmerkleized batch that reads through this batch's
    /// pending changes before falling back to the committed database state.
    ///
    /// In QMDB, this maps to `merkleized_batch.new_batch()`.
    fn new_batch(&self) -> Self::Unmerkleized;
}

/// A single database whose batch lifecycle is managed by the
/// [`Stateful`](super::wrapper::Stateful) wrapper.
///
/// Each instance wraps a QMDB database and knows how to create
/// unmerkleized batches from committed state and how to persist a
/// finalized changeset. Child batches (forked from pending state) are
/// created via [`Merkleized::new_batch`] instead.
pub trait ManagedDb: Send + Sync {
    /// An in-progress batch of mutations that has not yet been merkleized.
    type Unmerkleized: Unmerkleized;

    /// A batch whose root has been computed but has not yet been applied to
    /// the underlying database.
    ///
    /// Constrained so that [`Merkleized::new_batch`] produces the same
    /// [`Unmerkleized`] type as [`ManagedDb::new_batch`](Self::new_batch).
    type Merkleized: Merkleized<Unmerkleized = Self::Unmerkleized>;

    /// The error type returned by fallible operations.
    type Error: Debug + Send;

    /// Create a new unmerkleized batch rooted at the database's committed
    /// state.
    ///
    /// In QMDB, this maps to `db.new_batch()`.
    fn new_batch(&self) -> Self::Unmerkleized;

    /// Apply a merkleized batch's changeset to the underlying database.
    ///
    /// In QMDB, this encapsulates calling `merkleized.finalize()` to produce
    /// a `Changeset`, then `db.apply_batch(changeset)` and `db.commit()`.
    fn finalize(
        &mut self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A collection of individually-locked [`ManagedDb`] instances.
///
/// Each database is wrapped in `Arc<AsyncRwLock<...>>` so that the set
/// can be cheaply cloned (for consensus) and individual databases can be
/// shared with external services (RPC, state sync) without a global lock.
///
/// Implemented for `Arc<AsyncRwLock<T>>` (singleton) and for tuples of
/// such values via `impl_database_set`.
pub trait DatabaseSet: Clone + Send + Sync + 'static {
    /// Tuple of [`ManagedDb::Unmerkleized`] for every database in the set.
    type Unmerkleized: Send;

    /// Tuple of [`ManagedDb::Merkleized`] for every database in the set.
    type Merkleized: Send + Sync;

    /// Create unmerkleized batches from each database's committed state.
    ///
    /// Acquires a read lock on each database.
    fn new_batches(&self) -> impl Future<Output = Self::Unmerkleized> + Send;

    /// Create child unmerkleized batches from a pending merkleized parent.
    ///
    /// No lock is needed; reads come from the in-memory merkleized state.
    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized;

    /// Apply each merkleized batch's changeset to its underlying database.
    ///
    /// Acquires a write lock on each database.
    fn finalize(&self, batches: Self::Merkleized) -> impl Future<Output = ()> + Send;
}

/// Implement [`DatabaseSet`] for a single [`ManagedDb`] behind a lock.
impl<T: ManagedDb + 'static> DatabaseSet for Arc<AsyncRwLock<T>> {
    type Unmerkleized = T::Unmerkleized;
    type Merkleized = T::Merkleized;

    async fn new_batches(&self) -> Self::Unmerkleized {
        self.read().await.new_batch()
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        parent.new_batch()
    }

    async fn finalize(&self, batches: Self::Merkleized) {
        self.write()
            .await
            .finalize(batches)
            .await
            .expect("finalize must succeed");
    }
}

/// Implement [`DatabaseSet`] for a tuple of individually-locked
/// [`ManagedDb`] instances.
macro_rules! impl_database_set {
    ($($T:ident : $idx:tt),+) => {
        impl<$($T: ManagedDb + 'static),+> DatabaseSet
            for ($(Arc<AsyncRwLock<$T>>,)+)
        {
            type Unmerkleized = ($($T::Unmerkleized,)+);
            type Merkleized = ($($T::Merkleized,)+);

            async fn new_batches(&self) -> Self::Unmerkleized {
                ($(self.$idx.read().await.new_batch(),)+)
            }

            fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
                ($(parent.$idx.new_batch(),)+)
            }

            async fn finalize(&self, batches: Self::Merkleized) {
                $(
                    self.$idx
                        .write()
                        .await
                        .finalize(batches.$idx)
                        .await
                        .expect("finalize must succeed");
                )+
            }
        }
    };
}

impl_database_set!(DB1: 0);
impl_database_set!(DB1: 0, DB2: 1);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5, DB7: 6);
impl_database_set!(DB1: 0, DB2: 1, DB3: 2, DB4: 3, DB5: 4, DB6: 5, DB7: 6, DB8: 7);
