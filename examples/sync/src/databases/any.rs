//! Any database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::Hasher as CryptoHasher;
use commonware_runtime::{buffer, Clock, Metrics, Storage};
use commonware_storage::{
    adb::{
        self,
        any::fixed::{unordered::Any, Config},
        operation,
    },
    mmr::{
        mem::{Clean, Dirty},
        Location, Proof, StandardHasher as Standard,
    },
};
use commonware_utils::{NZUsize, NZU64};
use std::{future::Future, num::NonZeroU64};

/// Database enum that can be either Clean or Dirty.
pub enum Database<E>
where
    E: Storage + Clock + Metrics,
{
    Clean(
        Any<
            E,
            Key,
            Value,
            Hasher,
            Translator,
            Clean<<Hasher as commonware_cryptography::Hasher>::Digest>,
        >,
    ),
    Dirty(Any<E, Key, Value, Hasher, Translator, Dirty>),
}

/// Operation type alias.
pub type Operation = operation::fixed::unordered::Operation<Key, Value>;

/// Create a database configuration for use in tests.
pub fn create_config() -> Config<Translator> {
    Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: NZU64!(4096),
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: "log_journal".into(),
        log_items_per_blob: NZU64!(4096),
        log_write_buffer: NZUsize!(1024),
        translator: Translator::default(),
        thread_pool: None,
        buffer_pool: buffer::PoolRef::new(NZUsize!(1024), NZUsize!(10)),
    }
}

impl<E> Database<E>
where
    E: Storage + Clock + Metrics,
{
    /// Initialize a database from the given context and config.
    pub async fn init(context: E, config: Config<Translator>) -> Result<Self, adb::Error> {
        let db = Any::init(context, config).await?;
        Ok(Database::Clean(db))
    }

    /// Get the root digest of the database.
    pub fn root(&self) -> Key {
        match self {
            Database::Clean(db) => db.root(),
            Database::Dirty(_) => {
                // For Dirty state, we need to convert to Clean, but we only have &self
                // Since we can't clone or take ownership, we'll need to handle this differently
                // For now, we'll require the database to be Clean for root access
                // In practice, callers should ensure the database is Clean before calling root
                panic!("root() requires Clean state - convert to Clean first");
            }
        }
    }

    /// Close the database.
    pub async fn close(self) -> Result<(), adb::Error> {
        match self {
            Database::Clean(db) => db.close().await,
            Database::Dirty(db) => {
                // Convert to Clean before closing
                let clean_db = db.merkleize();
                clean_db.close().await
            }
        }
    }
}

impl<E> crate::databases::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Operation = Operation;

    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation> {
        let mut hasher = <Hasher as CryptoHasher>::new();
        let mut operations = Vec::new();
        for i in 0..count {
            let key = {
                hasher.update(&i.to_be_bytes());
                hasher.update(&seed.to_be_bytes());
                hasher.finalize()
            };

            let value = {
                hasher.update(&key);
                hasher.update(b"value");
                hasher.finalize()
            };

            operations.push(Operation::Update(key, value));

            if (i + 1) % 10 == 0 {
                operations.push(Operation::CommitFloor(Location::from(i + 1)));
            }
        }

        // Always end with a commit
        operations.push(Operation::CommitFloor(Location::from(count)));
        operations
    }

    async fn add_operations(
        database: Self,
        operations: Vec<Self::Operation>,
    ) -> Result<Self, commonware_storage::adb::Error> {
        // Convert to Dirty state
        let mut dirty_db = match database {
            Database::Clean(db) => db.into_dirty(),
            Database::Dirty(db) => db,
        };

        // Apply all operations
        for operation in operations {
            match operation {
                Operation::Update(key, value) => {
                    dirty_db.update(key, value).await?;
                }
                Operation::Delete(key) => {
                    dirty_db.delete(key).await?;
                }
                Operation::CommitFloor(_) => {
                    dirty_db.commit().await?;
                }
            }
        }

        // Convert back to Clean after operations
        Ok(Database::Clean(dirty_db.merkleize()))
    }

    async fn commit(self) -> Result<Self, commonware_storage::adb::Error> {
        // Convert to Dirty, commit, then convert back to Clean
        let mut dirty_db = match self {
            Database::Clean(db) => db.into_dirty(),
            Database::Dirty(db) => db,
        };
        dirty_db.commit().await?;
        Ok(Database::Clean(dirty_db.merkleize()))
    }

    fn root(&self, _hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key {
        match self {
            Database::Clean(db) => db.root(),
            Database::Dirty(_) => {
                // For Dirty state, we need to convert to Clean, but we only have &self
                // Since we can't clone or take ownership, we'll need to handle this differently
                // For now, we'll require the database to be Clean for root access
                // In practice, callers should ensure the database is Clean before calling root
                panic!("root() requires Clean state - convert to Clean first");
            }
        }
    }

    fn op_count(&self) -> Location {
        match self {
            Database::Clean(db) => db.op_count(),
            Database::Dirty(db) => db.op_count(),
        }
    }

    fn lower_bound(&self) -> Location {
        match self {
            Database::Clean(db) => db.inactivity_floor_loc(),
            Database::Dirty(db) => db.inactivity_floor_loc(),
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send {
        // historical_proof is only available on Clean state
        // Since we only have &self, we can't convert Dirty to Clean
        // We'll need to handle this by requiring Clean state
        // Use Box::pin to unify the types from both match arms
        #[allow(clippy::redundant_async_block)]
        async move {
            match self {
                Database::Clean(db) => db.historical_proof(op_count, start_loc, max_ops).await,
                Database::Dirty(_) => {
                    // For Dirty state, we can't convert without ownership
                    // Return an error indicating the database needs to be Clean
                    Err(adb::Error::Mmr(
                        commonware_storage::mmr::Error::RangeOutOfBounds(start_loc),
                    ))
                }
            }
        }
    }

    fn name() -> &'static str {
        "any"
    }
}

// Note: We can't implement adb::sync::Database here because it's pub(crate) in the storage crate.
// Instead, we use Any directly for sync operations and convert to/from Database enum as needed.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::Syncable;
    use commonware_runtime::deterministic;

    type AnyDb = Database<deterministic::Context>;

    #[test]
    fn test_create_test_operations() {
        let ops = <AnyDb as Syncable>::create_test_operations(5, 12345);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        if let Operation::CommitFloor(loc) = &ops[5] {
            assert_eq!(*loc, 5);
        } else {
            panic!("Last operation should be a commit");
        }
    }

    #[test]
    fn test_deterministic_operations() {
        // Operations should be deterministic based on seed
        let ops1 = <AnyDb as Syncable>::create_test_operations(3, 12345);
        let ops2 = <AnyDb as Syncable>::create_test_operations(3, 12345);
        assert_eq!(ops1, ops2);

        // Different seeds should produce different operations
        let ops3 = <AnyDb as Syncable>::create_test_operations(3, 54321);
        assert_ne!(ops1, ops3);
    }
}
