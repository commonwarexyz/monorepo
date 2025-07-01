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
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        // Initialize metadata store
        let cfg = Config {
            partition: "metadata_operations_fuzz_test".to_string(),
            codec_config: ((0..).into(), ()),
        };
        let mut metadata = match Metadata::init(context.clone(), cfg).await {
            Ok(m) => Some(m),
            Err(_) => panic!("Unable to init metadata"),
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
                    if metadata_ref.sync().await.is_err() {
                        panic!("Sync failed");
                    }
                }

                MetadataOperation::Close => {
                    if let Some(m) = metadata.take() {
                        if m.close().await.is_err() {
                            panic!("close failed");
                        }
                        return;
                    }
                }

                MetadataOperation::Destroy => {
                    if let Some(m) = metadata.take() {
                        if m.destroy().await.is_err() {
                            panic!("destroy failed");
                        }
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
                    for i in 0..3 {
                        if metadata_ref.sync().await.is_err() {
                            panic!("MultipleSync failed at iteration {i}");
                        }
                    }
                }
            }
        }

        // Clean up if metadata still exists - panic on cleanup errors
        if let Some(m) = metadata.take() {
            if m.destroy().await.is_err() {
                panic!("final destroy failed");
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
