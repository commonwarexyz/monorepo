//! Any database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::Hasher as CryptoHasher;
use commonware_runtime::{buffer, BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::{
        self,
        any::{
            unordered::{
                fixed::{Db, Operation as FixedOperation},
                Update,
            },
            FixedConfig as Config,
        },
        operation::Committable,
        store::LogStore,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::{future::Future, num::NonZeroU64};
use tracing::error;

/// Database type alias for the Clean state.
pub type Database<E> = Db<E, Key, Value, Hasher, Translator>;

/// Operation type alias.
pub type Operation = FixedOperation<Key, Value>;

/// Create a database configuration for use in tests.
pub fn create_config(context: &impl BufferPooler) -> Config<Translator> {
    Config {
        mmr_journal_partition: "mmr-journal".into(),
        mmr_metadata_partition: "mmr-metadata".into(),
        mmr_items_per_blob: NZU64!(4096),
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: "log-journal".into(),
        log_items_per_blob: NZU64!(4096),
        log_write_buffer: NZUsize!(1024),
        translator: Translator::default(),
        thread_pool: None,
        page_cache: buffer::paged::CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
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

            operations.push(Operation::Update(Update(key, value)));

            if (i + 1) % 10 == 0 {
                operations.push(Operation::CommitFloor(None, Location::from(i + 1)));
            }
        }

        // Always end with a commit
        operations.push(Operation::CommitFloor(None, Location::from(count)));
        operations
    }

    async fn add_operations(
        self,
        operations: Vec<Self::Operation>,
    ) -> Result<Self, commonware_storage::qmdb::Error> {
        if operations.last().is_none() || !operations.last().unwrap().is_commit() {
            // Ignore bad inputs rather than return errors.
            error!("operations must end with a commit");
            return Ok(self);
        }
        let mut db = self.into_mutable();
        let num_ops = operations.len();

        for (i, operation) in operations.into_iter().enumerate() {
            match operation {
                Operation::Update(Update(key, value)) => {
                    db.write_batch([(key, Some(value))]).await?;
                }
                Operation::Delete(key) => {
                    db.write_batch([(key, None)]).await?;
                }
                Operation::CommitFloor(metadata, _) => {
                    let (durable_db, _) = db.commit(metadata).await?;
                    if i == num_ops - 1 {
                        // Last operation - return the clean database
                        return Ok(durable_db.into_merkleized());
                    }
                    // Not the last operation - continue in mutable state
                    db = durable_db.into_mutable();
                }
            }
        }
        panic!("operations should end with a commit");
    }

    async fn root(&self) -> Key {
        self.root().await
    }

    async fn size(&self) -> Location {
        LogStore::bounds(self).await.end
    }

    async fn inactivity_floor(&self) -> Location {
        self.inactivity_floor_loc()
    }

    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), qmdb::Error>> + Send {
        self.historical_proof(op_count, start_loc, max_ops)
    }

    fn name() -> &'static str {
        "any"
    }
}

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

        if let Operation::CommitFloor(_, loc) = &ops[5] {
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
