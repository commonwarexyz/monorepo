//! Databases that are based on an append-only log of operations that define the database state. The
//! different implementations within this module provide various specializations. For example, those
//! in `adb/` provide a spectrum of authentication capabilities, and some implementations are
//! specialized to offer higher performance when stored values have fixed vs variable length or an
//! unordered vs ordered key space (or no key space at all in the case of [adb::keyless::Keyless]).
//!
//! Because we treat each operation as a leaf node in an MMR for the authenticated variants, we use
//! [Location] from the [crate::mmr] module to represent the index of each operation in the log,
//! even for unauthenticated databases.

use crate::{mmr::Location, translator::Translator};
use commonware_codec::Codec;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use core::future::Future;

pub mod adb;
pub mod operation;
pub mod store;

/// Errors that can occur when interacting with a database.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("adb error: {0}")]
    Adb(#[from] crate::log_db::adb::Error),

    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),

    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),

    /// The requested operation has been pruned.
    #[error("operation pruned: {0}")]
    OperationPruned(Location),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,

    /// An attempt was made to prune beyond the last commit point.
    #[error("prune location {0} beyond last commit {1}")]
    PruneBeyondCommit(Location, Location),

    /// Returned by databases that maintain an inactivity floor when an attempt is made to prune
    /// operations beyond it.
    #[error("prune location {0} beyond inactivity floor {1}")]
    PruneBeyondInactivityFloor(Location, Location),

    /// There are pending operations that must be committed before the requested function can be
    /// performed.
    #[error("uncommitted operations present")]
    UncommittedOperations,
}

/// A trait for a key-value store based on an append-only log of operations.
pub trait KeyValueStore<E: RStorage + Clock + Metrics, K: Array, V: Codec, T: Translator> {
    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    fn op_count(&self) -> Location;

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    fn inactivity_floor_loc(&self) -> Location;

    /// Get the value of `key` in the db, or None if it has no value.
    fn get(&self, key: &K) -> impl Future<Output = Result<Option<V>, Error>>;

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    fn update(&mut self, key: K, value: V) -> impl Future<Output = Result<(), Error>>;

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    fn delete(&mut self, key: K) -> impl Future<Output = Result<(), Error>>;

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    fn commit(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Prune historical operations prior to `target_prune_loc`. This does not affect the db's root
    /// or current snapshot.
    fn prune(&mut self, target_prune_loc: Location) -> impl Future<Output = Result<(), Error>>;

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Destroy the db, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}
