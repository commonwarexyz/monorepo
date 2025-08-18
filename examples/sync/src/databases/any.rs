//! Any database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::Hasher as CryptoHasher;
use commonware_runtime::{buffer, Clock, Metrics, Storage};
use commonware_storage::{
    adb::{
        self,
        any::{fixed, variable},
    },
    mmr::{hasher::Standard, verification::Proof},
    store::operation,
};
use commonware_utils::{NZUsize, NZU64};
use std::future::Future;

/// Fixed-size Any database type alias.
pub type FixedDatabase<E> = fixed::Any<E, Key, Value, Hasher, Translator>;

/// Variable-size Any database type alias.
pub type VariableDatabase<E> = variable::Any<E, Key, Value, Hasher, Translator>;

/// Database type alias (defaults to fixed for backward compatibility).
pub type Database<E> = FixedDatabase<E>;

/// Fixed operation type alias.
pub type FixedOperation = operation::Fixed<Key, Value>;

/// Variable operation type alias.
pub type VariableOperation = operation::Variable<Key, Value>;

/// Operation type alias (defaults to fixed for backward compatibility).
pub type Operation = FixedOperation;

/// Create a fixed database configuration for use in tests.
pub fn create_fixed_config() -> fixed::Config<Translator> {
    fixed::Config {
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
        pruning_delay: 1024,
    }
}

/// Create a variable database configuration for use in tests.
pub fn create_variable_config() -> variable::Config<Translator, ()> {
    variable::Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: NZU64!(4096),
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: "log_journal".into(),
        log_items_per_section: NZU64!(512),
        log_compression: None,
        log_codec_config: (),
        log_write_buffer: NZUsize!(1024),
        locations_journal_partition: "locations_journal".into(),
        locations_items_per_blob: NZU64!(4096),
        metadata_partition: "metadata".into(),
        translator: Translator::default(),
        thread_pool: None,
        buffer_pool: buffer::PoolRef::new(NZUsize!(1024), NZUsize!(10)),
        pruning_delay: 1024,
    }
}

/// Create a database configuration for use in tests (defaults to fixed for backward compatibility).
pub fn create_config() -> fixed::Config<Translator> {
    create_fixed_config()
}

impl<E> crate::databases::Syncable for FixedDatabase<E>
where
    E: Storage + Clock + Metrics,
{
    type Operation = FixedOperation;

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

            operations.push(FixedOperation::Update(key, value));

            if (i + 1) % 10 == 0 {
                operations.push(FixedOperation::CommitFloor(i as u64 + 1));
            }
        }

        // Always end with a commit
        operations.push(FixedOperation::CommitFloor(count as u64));
        operations
    }

    async fn add_operations(
        database: &mut Self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), commonware_storage::adb::Error> {
        for operation in operations {
            match operation {
                FixedOperation::Update(key, value) => {
                    database.update(key, value).await?;
                }
                FixedOperation::Delete(key) => {
                    database.delete(key).await?;
                }
                FixedOperation::CommitFloor(_) => {
                    database.commit().await?;
                }
            }
        }
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::adb::Error> {
        self.commit().await
    }

    fn root(&self, hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key {
        self.root(hasher)
    }

    fn op_count(&self) -> u64 {
        self.op_count()
    }

    fn lower_bound_ops(&self) -> u64 {
        self.inactivity_floor_loc()
    }

    fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: u64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send {
        self.historical_proof(size, start_loc, max_ops)
    }

    fn name() -> &'static str {
        "any_fixed"
    }
}

impl<E> crate::databases::Syncable for VariableDatabase<E>
where
    E: Storage + Clock + Metrics,
{
    type Operation = VariableOperation;

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

            operations.push(VariableOperation::Update(key, value));

            if (i + 1) % 10 == 0 {
                operations.push(VariableOperation::Commit());
            }
        }

        // Always end with a commit
        operations.push(VariableOperation::Commit());
        operations
    }

    async fn add_operations(
        database: &mut Self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), commonware_storage::adb::Error> {
        for operation in operations {
            match operation {
                VariableOperation::Update(key, value) => {
                    database.update(key, value).await?;
                }
                VariableOperation::Delete(key) => {
                    database.delete(key).await?;
                }
                VariableOperation::Set(key, value) => {
                    database.update(key, value).await?;
                }
                VariableOperation::Commit() => {
                    database.commit().await?;
                }
                VariableOperation::CommitFloor(_) => {
                    database.commit().await?;
                }
            }
        }
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::adb::Error> {
        self.commit().await
    }

    fn root(&self, hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key {
        self.root(hasher)
    }

    fn op_count(&self) -> u64 {
        self.op_count()
    }

    fn lower_bound_ops(&self) -> u64 {
        self.oldest_retained_loc().unwrap_or(0)
    }

    fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: u64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send {
        self.historical_proof(size, start_loc, max_ops)
    }

    fn name() -> &'static str {
        "any_variable"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::Syncable;
    use commonware_runtime::deterministic;

    type FixedAnyDb = FixedDatabase<deterministic::Context>;
    type VariableAnyDb = VariableDatabase<deterministic::Context>;
    type AnyDb = Database<deterministic::Context>;

    #[test]
    fn test_create_test_operations_fixed() {
        let ops = <FixedAnyDb as Syncable>::create_test_operations(5, 12345);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        if let FixedOperation::CommitFloor(loc) = &ops[5] {
            assert_eq!(*loc, 5);
        } else {
            panic!("Last operation should be a commit");
        }
    }

    #[test]
    fn test_create_test_operations_variable() {
        let ops = <VariableAnyDb as Syncable>::create_test_operations(5, 12345);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        if let VariableOperation::Commit() = &ops[5] {
            // Good
        } else {
            panic!("Last operation should be a commit");
        }
    }

    #[test]
    fn test_create_test_operations_default() {
        let ops = <AnyDb as Syncable>::create_test_operations(5, 12345);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        if let Operation::CommitFloor(loc) = &ops[5] {
            assert_eq!(*loc, 5);
        } else {
            panic!("Last operation should be a commit");
        }
    }

    #[test]
    fn test_deterministic_operations_fixed() {
        // Operations should be deterministic based on seed
        let ops1 = <FixedAnyDb as Syncable>::create_test_operations(3, 12345);
        let ops2 = <FixedAnyDb as Syncable>::create_test_operations(3, 12345);
        assert_eq!(ops1, ops2);

        // Different seeds should produce different operations
        let ops3 = <FixedAnyDb as Syncable>::create_test_operations(3, 54321);
        assert_ne!(ops1, ops3);
    }

    #[test]
    fn test_deterministic_operations_variable() {
        // Operations should be deterministic based on seed
        let ops1 = <VariableAnyDb as Syncable>::create_test_operations(3, 12345);
        let ops2 = <VariableAnyDb as Syncable>::create_test_operations(3, 12345);
        assert_eq!(ops1, ops2);

        // Different seeds should produce different operations
        let ops3 = <VariableAnyDb as Syncable>::create_test_operations(3, 54321);
        assert_ne!(ops1, ops3);
    }
}
