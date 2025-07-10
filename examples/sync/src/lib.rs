//! ADB sync example library.
//!
//! This library demonstrates ADB (Any Database) synchronization between clients and servers.
//! It includes network protocols, database configuration, and utilities for creating test data.
//!
//! The sync example showcases how to:
//! - Create and configure ADB databases
//! - Implement network-based resolvers for fetching operations
//! - Synchronize database state between remote peers

use commonware_cryptography::Hasher as CryptoHasher;
use commonware_storage::adb::any::Config;

pub mod protocol;
pub mod resolver;

pub use protocol::*;
pub use resolver::NetworkResolver;

/// Hasher type used in the database.
pub type Hasher = commonware_cryptography::sha256::Sha256;

/// Key type used in the database.
pub type Key = commonware_cryptography::sha256::Digest;

/// Value type used in the database.
pub type Value = commonware_cryptography::sha256::Digest;

/// Database type alias.
pub type Database<E> = commonware_storage::adb::any::Any<E, Key, Value, Hasher, Translator>;

/// Operation type alias.
pub type Operation = commonware_storage::adb::operation::Operation<Key, Value>;

/// Translator type for the database.
pub type Translator = commonware_storage::index::translator::EightCap;

/// Create a database configuration with appropriate partitioning.
pub fn create_adb_config(db_id: &str) -> Config<Translator> {
    Config {
        mmr_journal_partition: format!("mmr_journal_{db_id}"),
        mmr_metadata_partition: format!("mmr_metadata_{db_id}"),
        mmr_items_per_blob: 1024,
        mmr_write_buffer: 64,
        log_journal_partition: format!("log_journal_{db_id}"),
        log_items_per_blob: 1024,
        log_write_buffer: 64,
        translator: Translator::default(),
        pool: None,
        buffer_pool: commonware_runtime::buffer::PoolRef::new(1024, 10),
    }
}

/// Generate a unique database ID based on current timestamp.
pub fn generate_db_id<E>(context: &E) -> String
where
    E: commonware_runtime::Clock,
{
    let timestamp = context
        .current()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("db_{timestamp}")
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

        // Add a commit operation every 10 operations
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
        let ops = create_test_operations(5, 12345);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        // Verify the last operation is a commit
        if let Operation::Commit(loc) = &ops[5] {
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
