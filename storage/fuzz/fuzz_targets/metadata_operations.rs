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
    Keys { prefix: Option<Vec<u8>> },
    RemovePrefix { prefix: Vec<u8> },
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
        let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg.clone())
            .await
            .unwrap();

        for op in input.operations.iter() {
            match op {
                MetadataOperation::Put { key, value } => {
                    let array_key = U64::new(*key);
                    metadata.put(array_key, value.to_vec());
                }

                MetadataOperation::Get { key } => {
                    let array_key = U64::new(*key);
                    metadata.get(&array_key);
                }

                MetadataOperation::Remove { key } => {
                    let array_key = U64::new(*key);
                    metadata.remove(&array_key);
                }

                MetadataOperation::Keys { prefix } => {
                    let _ = metadata.keys(prefix.as_deref());
                }

                MetadataOperation::RemovePrefix { prefix } => {
                    metadata.remove_prefix(prefix);
                }

                MetadataOperation::Clear => {
                    metadata.clear();
                }

                MetadataOperation::Sync => {
                    if metadata.sync().await.is_err() {
                        panic!("Sync failed");
                    }
                }

                MetadataOperation::Close => {
                    if metadata.close().await.is_err() {
                        panic!("close failed");
                    }
                    return;
                }

                MetadataOperation::Destroy => {
                    if metadata.destroy().await.is_err() {
                        panic!("destroy failed");
                    }
                    return;
                }

                MetadataOperation::PutLargeValue { key } => {
                    // Test with large values to find memory/size bugs
                    let array_key = U64::new(*key);
                    let large_value = vec![0u8; 100_000]; // 100KB
                    metadata.put(array_key, large_value);
                }

                MetadataOperation::PutEmptyValue { key } => {
                    // Test with empty values to find edge case bugs
                    let array_key = U64::new(*key);
                    metadata.put(array_key, Vec::new());
                }

                MetadataOperation::MultipleSyncs => {
                    for i in 0..3 {
                        if metadata.sync().await.is_err() {
                            panic!("MultipleSync failed at iteration {i}");
                        }
                    }
                }
            }
        }

        // Clean up if metadata still exists - panic on cleanup errors

        if metadata.destroy().await.is_err() {
            panic!("final destroy failed");
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
