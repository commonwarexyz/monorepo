//! TBD

mod storage;
pub use storage::Archive;
pub mod translator;

use prometheus_client::registry::Registry;
use std::{
    hash::Hash,
    sync::{Arc, Mutex},
};
use thiserror::Error;

/// Errors that can occur when interacting with the journal.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("duplicate key found during replay")]
    DuplicateKey,
    #[error("already pruned to section: {0}")]
    AlreadyPrunedSection(u64),
}

pub trait Translator: Clone {
    type Key: Eq + Hash + Send + Sync + Clone;

    fn transform(&self, key: &[u8]) -> Self::Key;
}

/// Configuration for `archive` storage.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Logic to transform keys into their index representation.
    ///
    /// The `Archive` assumes that all internal keys are spread uniformly across the key space.
    /// If that is not the case, lookups may be O(n) instead of O(1).
    pub translator: T,

    /// The number of writes to buffer in a section before forcing a sync in the journal.
    ///
    /// If set to 0, the journal will be synced each time a new item is stored.
    pub pending_writes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{Config as JournalConfig, Journal};
    use bytes::Bytes;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Runner};
    use prometheus_client::{encoding::text::encode, registry::Registry};
    use rand::Rng;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use translator::{FourCap, TwoCap};

    #[test_traced]
    fn test_archive_put_get() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                translator: FourCap,
                pending_writes: 10,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let section = 1u64;
            let key = b"testkey";
            let data = Bytes::from("testdata");

            // Put the key-data pair
            archive
                .put(section, key, data.clone())
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(key)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 1"));
        });
    }

    #[test_traced]
    fn test_archive_duplicate_key() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                translator: FourCap,
                pending_writes: 10,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let section = 1u64;
            let key = b"duplicate";
            let data1 = Bytes::from("data1");
            let data2 = Bytes::from("data2");

            // Put the key-data pair
            archive
                .put(section, key, data1.clone())
                .await
                .expect("Failed to put data");

            // Put the key-data pair again
            let result = archive.put(section, key, data2.clone()).await;
            assert!(matches!(result, Err(Error::DuplicateKey)));

            // Get the data back
            let retrieved = archive
                .get(key)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 1"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 1"));
        });
    }

    #[test_traced]
    fn test_archive_get_nonexistent_key() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                translator: FourCap,
                pending_writes: 10,
            };
            let archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Attempt to get a key that doesn't exist
            let key = b"nonexistent";
            let retrieved = archive.get(key).await.expect("Failed to get data");
            assert!(retrieved.is_none());

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 0"));
            assert!(buffer.contains("unnecessary_reads_total 0"));
            assert!(buffer.contains("gets_total 1"));
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                translator: FourCap,
                pending_writes: 10,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let section = 1u64;
            let key1 = b"keys1";
            let data1 = Bytes::from("data1");
            let key2 = b"keys2";
            let data2 = Bytes::from("data2");

            // Put the key-data pair
            archive
                .put(section, key1, data1.clone())
                .await
                .expect("Failed to put data");

            // Put the key-data pair
            archive
                .put(section, key2, data2.clone())
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(key1)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Get the data back
            let retrieved = archive
                .get(key2)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 2"));
            assert!(buffer.contains("unnecessary_reads_total 2"));
            assert!(buffer.contains("gets_total 2"));
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key_multiple_sections() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context,
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry,
                translator: FourCap,
                pending_writes: 10,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let section1 = 1u64;
            let key1 = b"keys1";
            let data1 = Bytes::from("data1");
            let section2 = 2u64;
            let key2 = b"keys2";
            let data2 = Bytes::from("data2");

            // Put the key-data pair
            archive
                .put(section1, key1, data1.clone())
                .await
                .expect("Failed to put data");

            // Put the key-data pair
            archive
                .put(section2, key2, data2.clone())
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(key1)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Get the data back
            let retrieved = archive
                .get(key2)
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);
        });
    }

    #[test_traced]
    fn test_archive_prune_keys() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry: registry.clone(),
                translator: FourCap,
                pending_writes: 10,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let keys = vec![
                (1u64, "key1-blah", Bytes::from("data1")),
                (2u64, "key2-blah", Bytes::from("data2")),
                (3u64, "key3-blah", Bytes::from("data3")),
                (3u64, "key3-blah-again", Bytes::from("data3-again")),
                (4u64, "key4-blah", Bytes::from("data4")),
            ];

            for (section, key, data) in &keys {
                archive
                    .put(*section, key.as_bytes(), data.clone())
                    .await
                    .expect("Failed to put data");
            }

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 5"));

            // Prune sections less than 3
            archive.prune(3).await.expect("Failed to prune");

            // Ensure keys 1 and 2 are no longer present
            for (section, key, data) in keys {
                let retrieved = archive
                    .get(key.as_bytes())
                    .await
                    .expect("Failed to get data");
                if section < 3 {
                    assert!(retrieved.is_none());
                } else {
                    assert_eq!(retrieved.expect("Data not found"), data);
                }
            }

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 5")); // have not lazily removed keys yet
            assert!(buffer.contains("keys_pruned_total 0"));

            // Try to prune older section
            let result = archive.prune(2).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedSection(3))));

            // Try to prune current section again
            let result = archive.prune(3).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedSection(3))));

            // Trigger lazy removal of keys
            archive
                .put(3, "key2-blah-2".as_bytes(), Bytes::from("data2-2"))
                .await
                .expect("Failed to put data");

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 5")); // lazily remove one, add one
            assert!(buffer.contains("keys_pruned_total 1"));
        });
    }

    #[test_traced]
    fn test_archive_many_keys_and_restart() {
        // Configure test
        let num_keys = 100_000;
        let num_partitions = 10;

        // Initialize the deterministic runtime
        let (executor, mut context, _) = Executor::default();
        executor.start(async move {
            // Create a registry for metrics
            let registry = Arc::new(Mutex::new(Registry::default()));

            // Initialize an empty journal
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");

            // Initialize the archive
            let cfg = Config {
                registry: registry.clone(),
                translator: TwoCap,
                pending_writes: 10,
            };
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let mut keys = BTreeMap::new();
            while keys.len() < num_keys {
                let mut key = [0u8; 32];
                context.fill(&mut key);
                let section = context.gen_range(0..num_partitions);
                let mut data = [0u8; 1024];
                context.fill(&mut data);
                let data = Bytes::from(data.to_vec());
                archive
                    .put(section, &key, data.clone())
                    .await
                    .expect("Failed to put data");
                keys.insert(key, (section, data));
            }

            // Ensure all keys can be retrieved
            for (key, (_, data)) in &keys {
                let retrieved = archive
                    .get(key)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, data);
            }

            // Close the archive
            archive.close().await.expect("Failed to close archive");

            // Reinitialize the archive
            let journal = Journal::init(
                context.clone(),
                JournalConfig {
                    registry: registry.clone(),
                    partition: "test_partition".into(),
                },
            )
            .await
            .expect("Failed to initialize journal");
            let mut archive = Archive::init(journal, cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Ensure all keys can be retrieved
            for (key, (_, data)) in &keys {
                let retrieved = archive
                    .get(key)
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, data);
            }

            // Prune first half of partitions
            let min = num_partitions / 2;
            archive.prune(min).await.expect("Failed to prune");

            // Ensure all keys can be retrieved that haven't been pruned
            for (key, (section, data)) in keys {
                if section >= min {
                    let retrieved = archive
                        .get(&key)
                        .await
                        .expect("Failed to get data")
                        .expect("Data not found");
                    assert_eq!(retrieved, data);
                } else {
                    let retrieved = archive.get(&key).await.expect("Failed to get data");
                    assert!(retrieved.is_none());
                }
            }

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("keys_tracked 100000")); // have not lazily removed keys yet
            assert!(buffer.contains("keys_pruned_total 0"));
        });
    }
}
