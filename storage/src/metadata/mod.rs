//! TBD

mod storage;
use std::sync::{Arc, Mutex};

use prometheus_client::registry::Registry;
pub use storage::Metadata;

use thiserror::Error;

/// Errors that can occur when interacting with the journal.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("blob too large: {0}")]
    BlobTooLarge(u64),
    #[error("value too big: {0}")]
    ValueTooBig(u32),
}

/// Configuration for `Metadata` storage.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// The `commonware_runtime::Storage` partition to
    /// use for storing metadata.
    pub partition: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Runner};
    use prometheus_client::encoding::text::encode;

    #[test_traced]
    fn test_metadata_put_get() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create a metadata store
            let registry = Arc::new(Mutex::new(Registry::default()));
            let cfg = Config {
                registry: registry.clone(),
                partition: "test".to_string(),
            };
            let mut metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Get a key that doesn't exist
            let key = 42;
            let value = metadata.get(key);
            assert!(value.is_none());

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 0"));

            // Put a key
            let hello = Bytes::from("hello");
            metadata.put(key, hello.clone());

            // Get the key
            let value = metadata.get(key).unwrap();
            assert_eq!(value, &hello);

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 1"));

            // Close the metadata store
            metadata.close().await.unwrap();

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("syncs_total 1"));
            assert!(buffer.contains("keys 1"));

            // Reopen the metadata store
            let registry = Arc::new(Mutex::new(Registry::default()));
            let cfg = Config {
                registry: registry.clone(),
                partition: "test".to_string(),
            };
            let metadata = Metadata::init(context.clone(), cfg).await.unwrap();

            // Check metrics
            let mut buffer = String::new();
            encode(&mut buffer, &registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("syncs_total 0"));
            assert!(buffer.contains("keys 1"));

            // Get the key
            let value = metadata.get(key).unwrap();
            assert_eq!(value, &hello);
        });
    }
}
