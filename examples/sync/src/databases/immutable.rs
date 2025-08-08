//! Immutable database types and helpers for the sync example.

use commonware_cryptography::Hasher as CryptoHasher;
use commonware_storage::adb::immutable::Config;

/// Hasher type used in the database.
pub type Hasher = commonware_cryptography::sha256::Sha256;

/// Key type used in the database.
pub type Key = commonware_cryptography::sha256::Digest;

/// Value type used in the database.
pub type Value = commonware_cryptography::sha256::Digest;

/// Database type alias.
pub type Database<E> =
    commonware_storage::adb::immutable::Immutable<E, Key, Value, Hasher, Translator>;

/// Operation type alias.
pub type Operation = commonware_storage::adb::operation::Variable<Key, Value>;

/// Translator type for the database.
pub type Translator = commonware_storage::translator::TwoCap;

/// Create a database configuration with appropriate partitioning for Immutable.
pub fn create_immutable_config() -> Config<Translator, ()> {
    Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: 4096,
        mmr_write_buffer: 1024,
        log_journal_partition: "log_journal".into(),
        log_items_per_section: 512,
        log_compression: None,
        log_codec_config: (),
        log_write_buffer: 1024,
        locations_journal_partition: "locations_journal".into(),
        locations_items_per_blob: 4096,
        translator: commonware_storage::translator::TwoCap,
        thread_pool: None,
        buffer_pool: commonware_runtime::buffer::PoolRef::new(1024, 10),
    }
}

/// Create deterministic test operations for demonstration purposes.
/// Generates Set operations and periodic Commit operations.
pub fn create_test_immutable_operations(count: usize, seed: u64) -> Vec<Operation> {
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

        operations.push(Operation::Set(key, value));

        if (i + 1) % 10 == 0 {
            operations.push(Operation::Commit());
        }
    }

    // Always end with a commit
    operations.push(Operation::Commit());
    operations
}
