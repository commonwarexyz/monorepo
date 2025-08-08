//! Any database types and helpers for the sync example.

use commonware_cryptography::Hasher as CryptoHasher;
use commonware_storage::adb::any::Config;

/// Hasher type used in the database.
pub type Hasher = commonware_cryptography::sha256::Sha256;

/// Key type used in the database.
pub type Key = commonware_cryptography::sha256::Digest;

/// Value type used in the database.
pub type Value = commonware_cryptography::sha256::Digest;

/// Database type alias.
pub type Database<E> = commonware_storage::adb::any::Any<E, Key, Value, Hasher, Translator>;

/// Operation type alias.
pub type Operation = commonware_storage::adb::operation::Fixed<Key, Value>;

/// Translator type for the database.
pub type Translator = commonware_storage::translator::EightCap;

/// Create a database configuration with appropriate partitioning.
pub fn create_any_config() -> Config<Translator> {
    Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: 4096,
        mmr_write_buffer: 1024,
        log_journal_partition: "log_journal".into(),
        log_items_per_blob: 4096,
        log_write_buffer: 1024,
        translator: Translator::default(),
        thread_pool: None,
        buffer_pool: commonware_runtime::buffer::PoolRef::new(1024, 10),
        pruning_delay: 10,
    }
}

/// Create deterministic test operations for demonstration purposes.
///
/// This function creates a sequence of Update operations followed by
/// periodic Commit operations. The operations are deterministic based
/// on the count and seed parameters.
pub fn create_any_test_operations(count: usize, seed: u64) -> Vec<Operation> {
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
            operations.push(Operation::Commit(i as u64 + 1));
        }
    }

    // Always end with a commit
    operations.push(Operation::Commit(count as u64));
    operations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_operations() {
        let ops = create_any_test_operations(5, 12345);
        assert_eq!(ops.len(), 6);

        if let Operation::Commit(loc) = &ops[5] {
            assert_eq!(*loc, 5);
        } else {
            panic!("Last operation should be a commit");
        }
    }

    #[test]
    fn test_deterministic_operations() {
        // Operations should be deterministic based on seed
        let ops1 = create_any_test_operations(3, 12345);
        let ops2 = create_any_test_operations(3, 12345);
        assert_eq!(ops1, ops2);

        // Different seeds should produce different operations
        let ops3 = create_any_test_operations(3, 54321);
        assert_ne!(ops1, ops3);
    }
}
