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
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<MetadataOperation>,
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    if input.operations.is_empty() || input.operations.len() > 100 {
        return;
    }

    runner.start(|context| async move {
        // Initialize metadata store
        let cfg = Config {
            partition: "fuzz_test".to_string(),
        };
        let mut metadata = match Metadata::init(context.clone(), cfg).await {
            Ok(m) => Some(m),
            Err(err) => panic!("{:?}", err), 
        };

        for op in input.operations.iter() {
            // Skip operations if metadata is consumed
            let metadata_ref = match metadata.as_mut() {
                Some(m) => m,
                None => break,
            };

            match op {
                MetadataOperation::Put { key, value } => {
                    // Limit value size to prevent memory issues
                    let limited_value = if value.len() > 1000 {
                        &value[0..1000]
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
                    // Ignore sync errors - they're expected in some edge cases
                    metadata_ref.sync().await.unwrap();
                }

                MetadataOperation::LastUpdate => {
                    metadata_ref.last_update();
                }

                MetadataOperation::Close => {
                    // Close metadata (takes ownership)
                    if let Some(m) = metadata.take() {
                        let _ = m.close().await;
                        return;
                    }
                }

                MetadataOperation::Destroy => {
                    // Destroy metadata (takes ownership)
                    if let Some(m) = metadata.take() {
                        let _ = m.destroy().await;
                        return;
                    }
                }
            }
        }

        // Clean up if metadata still exists
        if let Some(m) = metadata.take() {
            let _ = m.destroy().await;
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});