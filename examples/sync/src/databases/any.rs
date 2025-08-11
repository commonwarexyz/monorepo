//! Any database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::Hasher as CryptoHasher;
use commonware_storage::{adb::any::fixed, store::operation};
use commonware_utils::NZUsize;

/// Database type alias.
pub type Database<E> = fixed::Any<E, Key, Value, Hasher, Translator>;

/// Operation type alias.
pub type Operation = operation::Fixed<Key, Value>;

/// Create a database configuration with appropriate partitioning.
pub fn create_config() -> fixed::Config<Translator> {
    fixed::Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: 4096,
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: "log_journal".into(),
        log_items_per_blob: 4096,
        log_write_buffer: NZUsize!(1024),
        translator: Translator::default(),
        thread_pool: None,
        buffer_pool: commonware_runtime::buffer::PoolRef::new(NZUsize!(1024), NZUsize!(10)),
        pruning_delay: 10,
    }
}

/// Create deterministic test operations for demonstration purposes.
///
/// This function creates a sequence of Update operations followed by
/// periodic Commit operations. The operations are deterministic based
/// on the count and seed parameters.
pub fn create_test_operations(count: usize, seed: u64) -> Vec<Operation> {
    let mut operations = Vec::new();
    let mut hasher = <Hasher as CryptoHasher>::new();

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
            operations.push(Operation::CommitFloor(i as u64 + 1));
        }
    }

    // Always end with a commit
    operations.push(Operation::CommitFloor(count as u64));
    operations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_operations() {
        let ops = create_test_operations(5, 12345);
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
        let ops1 = create_test_operations(3, 12345);
        let ops2 = create_test_operations(3, 12345);
        assert_eq!(ops1, ops2);

        // Different seeds should produce different operations
        let ops3 = create_test_operations(3, 54321);
        assert_ne!(ops1, ops3);
    }
}
