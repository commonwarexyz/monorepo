//! Any database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::Hasher as CryptoHasher;
use commonware_runtime::{buffer, Clock, Metrics, Storage};
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::{
        self,
        any::{unordered::fixed::Any, FixedConfig as Config},
        operation,
        store::CleanStore,
    },
};
use commonware_utils::{NZUsize, NZU64};
use std::{future::Future, num::NonZeroU64};

/// Database type alias.
pub type Database<E> = Any<E, Key, Value, Hasher, Translator>;

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
                operations.push(Operation::CommitFloor(None, Location::from(i + 1)));
            }
        }

        // Always end with a commit
        operations.push(Operation::CommitFloor(None, Location::from(count)));
        operations
    }

    async fn add_operations(
        database: &mut Self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), commonware_storage::qmdb::Error> {
        for operation in operations {
            match operation {
                Operation::Update(key, value) => {
                    database.update(key, value).await?;
                }
                Operation::Delete(key) => {
                    database.delete(key).await?;
                }
                Operation::CommitFloor(metadata, _) => {
                    database.commit(metadata).await?;
                }
            }
        }
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::qmdb::Error> {
        self.commit(None).await?;
        Ok(())
    }

    fn root(&self) -> Key {
        CleanStore::root(self)
    }

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn lower_bound(&self) -> Location {
        self.inactivity_floor_loc()
    }

    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), qmdb::Error>> + Send {
        CleanStore::historical_proof(self, op_count, start_loc, max_ops)
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
