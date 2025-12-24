#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::sequence::U64;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

#[derive(Arbitrary, Debug, Clone)]
enum MetadataOperation {
    Put { key: u64, value: Vec<u8> },
    Get { key: u64 },
    Remove { key: u64 },
    Clear,
    Sync,
    Destroy,
    Keys { prefix: Option<Vec<u8>> },
    RemovePrefix { prefix: Vec<u8> },
    PutLargeValue { key: u64 },
    PutEmptyValue { key: u64 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<MetadataOperation>,
}

fn bytes_u64(k: u64) -> [u8; 8] {
    k.to_be_bytes()
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config {
            partition: "metadata_operations_fuzz_test".to_string(),
            codec_config: ((0..).into(), ()),
        };
        let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.clone(), cfg)
            .await
            .unwrap();

        let mut model: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

        for op in input.operations.iter() {
            match op {
                MetadataOperation::Put { key, value } => {
                    metadata.put(U64::new(*key), value.clone());
                    model.insert(*key, value.clone());
                }
                MetadataOperation::Get { key } => {
                    let a = metadata.get(&U64::new(*key));
                    let b = model.get(key).cloned();
                    assert_eq!(a, b.as_ref());
                }
                MetadataOperation::Remove { key } => {
                    let a = metadata.remove(&U64::new(*key));
                    let b = model.remove(key);
                    assert_eq!(a, b);
                }
                MetadataOperation::Clear => {
                    metadata.clear();
                    model.clear();
                }
                MetadataOperation::Sync => {
                    metadata.sync().await.unwrap();
                }
                MetadataOperation::Destroy => {
                    metadata.destroy().await.unwrap();
                    return;
                }
                MetadataOperation::Keys { prefix } => {
                    let mut a: Vec<u64> = metadata
                        .keys()
                        .filter(|k| {
                            if let Some(p) = prefix {
                                k.as_ref().starts_with(p)
                            } else {
                                true
                            }
                        })
                        .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
                        .collect();
                    let mut b: Vec<u64> = model
                        .iter()
                        .filter(|(k, _)| {
                            if let Some(p) = prefix {
                                bytes_u64(**k).starts_with(p)
                            } else {
                                true
                            }
                        })
                        .map(|(k, _)| *k)
                        .collect();
                    a.sort();
                    b.sort();
                    assert_eq!(a, b);
                }
                MetadataOperation::RemovePrefix { prefix } => {
                    metadata.retain(|k, _| !k.as_ref().starts_with(prefix));
                    model.retain(|k, _| !bytes_u64(*k).starts_with(prefix));
                }
                MetadataOperation::PutLargeValue { key } => {
                    let v = vec![0u8; 100_000];
                    metadata.put(U64::new(*key), v.clone());
                    model.insert(*key, v);
                }
                MetadataOperation::PutEmptyValue { key } => {
                    metadata.put(U64::new(*key), Vec::new());
                    model.insert(*key, Vec::new());
                }
            }
        }

        let mut a: Vec<u64> = metadata
            .keys()
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        let mut b: Vec<u64> = model.keys().copied().collect();
        a.sort();
        b.sort();
        assert_eq!(a, b);

        metadata.destroy().await.unwrap();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
