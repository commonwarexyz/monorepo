#![no_main]
use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::array::U64;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum MetadataOperation {
    Put { key: u64, value: Vec<u8> },
    Get { key: u64 },
    Remove { key: u64 },
    Clear,
    Sync,
    LastUpdate,
    Close,
    Destroy,
    // Add operations that test edge cases
    PutLargeValue { key: u64 },
    PutEmptyValue { key: u64 },
    MultipleSyncs,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<MetadataOperation>,
}

fn fuzz(input: FuzzInput) {
    if input.operations.is_empty() || input.operations.len() > 100 {
        return;
    }

    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        // Initialize metadata store
        let cfg = Config {
            partition: "metadata_operations_fuzz_test".to_string(),
        };
        let mut metadata = match Metadata::init(context.clone(), cfg).await {
            Ok(m) => Some(m),
            Err(err) => panic!("Unable to init metadata {err:?}"), 
        };

        for op in input.operations.iter() {
            // Skip operations if metadata is consumed
            let metadata_ref = match metadata.as_mut() {
                Some(m) => m,
                None => break,
            };

            match op {
                MetadataOperation::Put { key, value } => {
                    // Don't limit value size too much - let larger values through to test edge cases
                    let limited_value = if value.len() > 50_000 {
                        &value[0..50_000] // Allow up to 50KB to stress test
                    } else {
                        value
                    };
                    
                    let array_key = U64::new(*key);
                    metadata_ref.put(array_key, limited_value.to_vec());
                }

                MetadataOperation::Get { key } => {
                    let array_key = U64::new(*key);
                    metadata_ref.get(&array_key);
                }

                MetadataOperation::Remove { key } => {
                    let array_key = U64::new(*key);
                    metadata_ref.remove(&array_key);
                }

                MetadataOperation::Clear => {
                    metadata_ref.clear();
                }

                MetadataOperation::Sync => {
                    // Panic on sync errors to find bugs
                    metadata_ref.sync().await.unwrap();
                }

                MetadataOperation::LastUpdate => {
                    metadata_ref.last_update();
                }

                MetadataOperation::Close => {
                    // Close metadata (takes ownership) - panic on errors
                    if let Some(m) = metadata.take() {
                        m.close().await.unwrap();
                        return;
                    }
                }

                MetadataOperation::Destroy => {
                    // Destroy metadata (takes ownership) - panic on errors
                    if let Some(m) = metadata.take() {
                        m.destroy().await.unwrap();
                        return;
                    }
                }

                MetadataOperation::PutLargeValue { key } => {
                    // Test with large values to find memory/size bugs
                    let array_key = U64::new(*key);
                    let large_value = vec![0u8; 100_000]; // 100KB
                    metadata_ref.put(array_key, large_value);
                }

                MetadataOperation::PutEmptyValue { key } => {
                    // Test with empty values to find edge case bugs
                    let array_key = U64::new(*key);
                    metadata_ref.put(array_key, Vec::new());
                }

                MetadataOperation::MultipleSyncs => {
                    // Test multiple rapid syncs to find race conditions
                    metadata_ref.sync().await.unwrap();
                    metadata_ref.sync().await.unwrap();
                    metadata_ref.sync().await.unwrap();
                }
            }
        }

        // Clean up if metadata still exists - panic on cleanup errors
        if let Some(m) = metadata.take() {
            m.destroy().await.unwrap();
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});