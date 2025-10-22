#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::current::{Config, Current},
    mmr::{hasher::Hasher as MmrHasher, Location, Position, Proof, StandardHasher as Standard},
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{collections::HashMap, num::NonZeroU64};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type RawKey = [u8; 32];
type RawValue = [u8; 32];

#[derive(Arbitrary, Debug, Clone)]
enum CurrentOperation {
    Update {
        key: RawKey,
        value: RawValue,
    },
    Delete {
        key: RawKey,
    },
    Get {
        key: RawKey,
    },
    Commit,
    Prune,
    OpCount,
    Root,
    RangeProof {
        start_loc: u64,
        max_ops: NonZeroU64,
    },
    KeyValueProof {
        key: RawKey,
    },
    ArbitraryProof {
        proof_size: u64,
        start_loc: u64,
        digests: Vec<[u8; 32]>,
        max_ops: NonZeroU64,
        chunks: Vec<[u8; 32]>,
    },
}

const MAX_OPERATIONS: usize = 100;

#[derive(Debug)]
struct FuzzInput {
    operations: Vec<CurrentOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..num_ops)
            .map(|_| CurrentOperation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { operations })
    }
}

const PAGE_SIZE: usize = 88;
const PAGE_CACHE_SIZE: usize = 8;

fn fuzz(data: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut hasher = Standard::<Sha256>::new();
        let cfg = Config {
            mmr_journal_partition: "fuzz_current_mmr_journal".into(),
            mmr_metadata_partition: "fuzz_current_mmr_metadata".into(),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: "fuzz_current_log_journal".into(),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            bitmap_metadata_partition: "fuzz_current_bitmap_metadata".into(),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            thread_pool: None,
        };

        let mut db = Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::init(context.clone(), cfg)
            .await
            .expect("Failed to initialize Current database");

        let mut expected_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut all_keys = std::collections::HashSet::new();
        let mut uncommitted_ops = 0;
        let mut last_committed_op_count = Location::new(0).unwrap();

        for op in &data.operations {
            match op {
                CurrentOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    db.update(k, v).await.expect("Update should not fail");
                    expected_state.insert(*key, Some(*value));
                    all_keys.insert(*key);
                    uncommitted_ops += 1;

                }

                CurrentOperation::Delete { key } => {
                    let k = Key::new(*key);
                    // Check if key exists before deletion
                    let key_existed = db.get(&k).await.expect("Get before delete should not fail").is_some();
                    db.delete(k).await.expect("Delete should not fail");
                    if key_existed {
                        expected_state.insert(*key, None);
                        all_keys.insert(*key);
                        uncommitted_ops += 1;
                    }
                }

                CurrentOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = db.get(&k).await.expect("Get should not fail");

                    match expected_state.get(key) {
                        Some(Some(expected_value)) => {
                            assert!(result.is_some(), "Expected value for key {key:?}");
                            let actual_value = result.expect("Should have value");
                            let actual_bytes: &[u8; 32] = actual_value.as_ref().try_into().expect("Value should be 32 bytes");
                            assert_eq!(actual_bytes, expected_value, "Value mismatch for key {key:?}");
                        }
                        Some(None) => {
                            assert!(result.is_none(), "Expected no value for deleted key {key:?}");
                        }
                        None => {
                            assert!(result.is_none(), "Expected no value for unset key {key:?}");
                        }
                    }

                    all_keys.insert(*key);
                }

                CurrentOperation::OpCount => {
                    let actual_count = db.op_count();
                    let expected_count = last_committed_op_count + uncommitted_ops;
                    assert_eq!(actual_count, expected_count,
                        "Operation count mismatch: expected {expected_count}, got {actual_count}");
                }

                CurrentOperation::Commit => {
                    db.commit().await.expect("Commit should not fail");
                    last_committed_op_count = db.op_count();
                    uncommitted_ops = 0;
                }

                CurrentOperation::Prune => {
                    db.prune(db.inactivity_floor_loc()).await.expect("Prune should not fail");
                }

                CurrentOperation::Root => {
                    if uncommitted_ops > 0 {
                        db.commit().await.expect("Commit before root should not fail");
                        last_committed_op_count = db.op_count();
                        uncommitted_ops = 0;
                    }

                    let _root = db.root(&mut hasher).await.expect("Root computation should not fail");
                }

                CurrentOperation::RangeProof { start_loc, max_ops } => {
                    let current_op_count = db.op_count();

                    if current_op_count > 0 {
                        if uncommitted_ops > 0 {
                            db.commit().await.expect("Commit before proof should not fail");
                            last_committed_op_count = db.op_count();
                            uncommitted_ops = 0;
                        }

                        let current_root = db.root(&mut hasher).await.expect("Root computation should not fail");

                        // Adjust start_loc and max_ops to be within the valid range
                        let start_loc = Location::new(start_loc % *current_op_count).unwrap();

                        let oldest_loc = db.inactivity_floor_loc();
                        if start_loc >= oldest_loc {
                            let (proof, ops, chunks) = db
                                .range_proof(hasher.inner(), start_loc, *max_ops)
                                .await
                                .expect("Range proof should not fail");

                            assert!(
                                Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::verify_range_proof(
                                    &mut hasher,
                                    &proof,
                                    start_loc,
                                    &ops,
                                    &chunks,
                                    &current_root
                                ),
                                "Range proof verification failed for start_loc={start_loc}, max_ops={max_ops}"
                            );
                        }
                    }
                }

                CurrentOperation::ArbitraryProof {proof_size, start_loc, digests, max_ops, chunks} => {
                    let mut hasher = Standard::<Sha256>::new();
                    let current_op_count = db.op_count();
                    if current_op_count == 0 {
                        continue;
                    }

                    let proof = Proof {
                        size: Position::new(*proof_size),
                        digests: digests.iter().map(|d| Digest::from(*d)).collect(),
                    };

                    let start_loc = Location::new(start_loc % current_op_count.as_u64()).unwrap();
                    let root = db.root(&mut hasher).await.expect("Root computation should not fail");

                    if let Ok(res) = db
                        .range_proof(hasher.inner(), start_loc, *max_ops)
                        .await {

                        let _ = Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::verify_range_proof(
                            &mut hasher,
                            &proof,
                            start_loc,
                            &res.1,
                            chunks,
                            &root
                        );

                    }

                }

                CurrentOperation::KeyValueProof { key } => {
                    let k = Key::new(*key);

                    if uncommitted_ops > 0 {
                        db.commit().await.expect("Commit before key value proof should not fail");
                        last_committed_op_count = db.op_count();
                        uncommitted_ops = 0;
                    }

                    let current_root = db.root(&mut hasher).await.expect("Root computation should not fail");

                    match db.key_value_proof(hasher.inner(), k).await {
                        Ok((proof, info)) => {
                            let verification_result = Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::verify_key_value_proof(
                                hasher.inner(),
                                &proof,
                                info.clone(),
                                &current_root,
                            );
                            assert!(verification_result, "Key value proof verification failed for key {key:?}");

                            let expected_value = expected_state.get(key);
                            match expected_value {
                                Some(Some(expected_val)) => {
                                    let info_bytes: &[u8; 32] = info.value.as_ref().try_into().expect("Value should be 32 bytes");
                                    assert_eq!(info_bytes, expected_val, "Proof value mismatch for key {key:?}");
                                }
                                Some(None) => {
                                    panic!("Proof generated for deleted key {key:?}");
                                }
                                None => {
                                    panic!("Proof generated for unset key {key:?}");
                                }
                            }
                        }
                        Err(commonware_storage::adb::Error::KeyNotFound) => {
                            let expected_value = expected_state.get(key);
                            if let Some(Some(_)) = expected_value {
                                panic!("Key {key:?} should exist but proof generation failed");
                            }
                        }
                        Err(e) => {
                            panic!("Unexpected error during key value proof generation: {e:?}");
                        }
                    }
                }
            }
        }

        if uncommitted_ops > 0 {
            db.commit().await.expect("Final commit should not fail");
        }

        for key in &all_keys {
            let k = Key::new(*key);
            let result = db.get(&k).await.expect("Final get should not fail");

            match expected_state.get(key) {
                Some(Some(expected_value)) => {
                    assert!(result.is_some(), "Lost value for key {key:?} at end");
                    let actual_value = result.expect("Should have value");
                    let actual_bytes: &[u8; 32] = actual_value.as_ref().try_into().expect("Value should be 32 bytes");
                    assert_eq!(actual_bytes, expected_value, "Final value mismatch for key {key:?}");
                }
                Some(None) => {
                    assert!(result.is_none(), "Deleted key {key:?} should remain deleted");
                }
                None => {
                    assert!(result.is_none(), "Unset key {key:?} should not exist");
                }
            }
        }

        db.close().await.expect("Close should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
