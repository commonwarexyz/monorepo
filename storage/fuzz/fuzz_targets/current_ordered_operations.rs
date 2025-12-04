#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::current::{ordered::Current, Config},
    mmr::{hasher::Hasher as _, Location, Position, Proof, StandardHasher as Standard},
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
    GetSpan {
        key: RawKey,
    },
    ExclusionProof {
        key: RawKey,
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
const MMR_ITEMS_PER_BLOB: u64 = 11;
const LOG_ITEMS_PER_BLOB: u64 = 7;
const WRITE_BUFFER_SIZE: usize = 1024;

fn fuzz(data: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut hasher = Standard::<Sha256>::new();
        let cfg = Config {
            mmr_journal_partition: "fuzz_current_mmr_journal".into(),
            mmr_metadata_partition: "fuzz_current_mmr_metadata".into(),
            mmr_items_per_blob: NZU64!(MMR_ITEMS_PER_BLOB),
            mmr_write_buffer: NZUsize!(WRITE_BUFFER_SIZE),
            log_journal_partition: "fuzz_current_log_journal".into(),
            log_items_per_blob: NZU64!(LOG_ITEMS_PER_BLOB),
            log_write_buffer: NZUsize!(WRITE_BUFFER_SIZE),
            bitmap_metadata_partition: "fuzz_current_bitmap_metadata".into(),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            thread_pool: None,
        };

        let mut db = Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::init(context.clone(), cfg)
            .await
            .expect("Failed to initialize Current database");

        let mut expected_state: HashMap<RawKey, RawValue> = HashMap::new();
        let mut all_keys = std::collections::HashSet::new();
        let mut uncommitted_ops = 0;
        let mut last_committed_op_count = Location::new(0).unwrap();

        for op in &data.operations {
            match op {
                CurrentOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    let empty = db.is_empty();
                    db.update(k, v).await.expect("update should not fail");
                    let result = expected_state.insert(*key, *value);
                    all_keys.insert(*key);
                    uncommitted_ops += 1;
                    if !empty && result.is_none() {
                        // Account for the previous key update
                        uncommitted_ops += 1;
                    }
                    let actual_count = db.op_count();
                    let expected_count = last_committed_op_count + uncommitted_ops;
                    assert_eq!(actual_count, expected_count,
                        "Operation count mismatch: expected {expected_count} (last_known={last_committed_op_count} + uncommitted={uncommitted_ops}), got {actual_count}");
                }

                CurrentOperation::Delete { key } => {
                    let k = Key::new(*key);
                    db.delete(k).await.expect("delete should not fail");
                    if expected_state.remove(key).is_some() {
                        all_keys.insert(*key);
                        uncommitted_ops += 1;
                        if expected_state.keys().len() != 0 {
                            uncommitted_ops += 1;
                        }
                    }
                }

                CurrentOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = db.get(&k).await.expect("get should not fail");

                    // Verify against expected state
                    match expected_state.get(key) {
                        Some(expected_value) => {
                            // Key should exist with this value
                            let v = result.expect("get should not fail");
                            let v_bytes: &[u8; 32] = v.as_ref().try_into().expect("bytes");
                            assert_eq!(v_bytes, expected_value, "Value mismatch for key {key:?}");
                        }
                        None => {
                            assert!(
                                result.is_none(),
                                "Found unexpected value for key {key:?} that was never touched",
                            );
                        }
                    }

                    // Track that we accessed this key
                    all_keys.insert(*key);
                }

                CurrentOperation::GetSpan { key } => {
                    let k = Key::new(*key);
                    let result = db.get_span(&k).await.expect("get should not fail");
                    assert_eq!(result.is_some(), !db.is_empty(), "span should be empty only if db is empty");
                }

                CurrentOperation::OpCount => {
                    let actual_count = db.op_count();
                    let expected_count = last_committed_op_count + uncommitted_ops;
                    assert_eq!(actual_count, expected_count,
                        "Operation count mismatch: expected {expected_count}, got {actual_count}");
                }

                CurrentOperation::Commit => {
                    db.commit(None).await.expect("Commit should not fail");
                    last_committed_op_count = db.op_count();
                    uncommitted_ops = 0;
                }

                CurrentOperation::Prune => {
                    db.prune(db.inactivity_floor_loc()).await.expect("Prune should not fail");
                }

                CurrentOperation::Root => {
                    if uncommitted_ops > 0 {
                        db.commit(None).await.expect("Commit before root should not fail");
                        last_committed_op_count = db.op_count();
                        uncommitted_ops = 0;
                    }

                    let _root = db.root(&mut hasher).await.expect("Root computation should not fail");
                }

                CurrentOperation::RangeProof { start_loc, max_ops } => {
                    let current_op_count = db.op_count();

                    if current_op_count > 0 {
                        if uncommitted_ops > 0 {
                            db.commit(None).await.expect("Commit before proof should not fail");
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
                        db.commit(None).await.expect("Commit before key value proof should not fail");
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
                                Some(expected_val) => {
                                    let info_bytes: &[u8; 32] = info.value.as_ref().try_into().expect("Value should be 32 bytes");
                                    assert_eq!(info_bytes, expected_val, "Proof value mismatch for key {key:?}");
                                }
                                None => {
                                    panic!("Proof generated for unset key {key:?}");
                                }
                            }
                        }
                        Err(commonware_storage::adb::Error::KeyNotFound) => {
                            assert!(!expected_state.contains_key(key), "Proof generation failed for existing key {key:?}");
                        }
                        Err(e) => {
                            panic!("Unexpected error during key value proof generation: {e:?}");
                        }
                    }
                }

                CurrentOperation::ExclusionProof { key } => {
                    let k = Key::new(*key);

                    if uncommitted_ops > 0 {
                        db.commit(None).await.expect("Commit before exclusion proof should not fail");
                        last_committed_op_count = db.op_count();
                        uncommitted_ops = 0;
                    }

                    let current_root = db.root(&mut hasher).await.expect("Root computation should not fail");

                    match db.exclusion_proof(hasher.inner(), &k).await {
                        Ok((proof, info)) => {
                            let verification_result = Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::verify_exclusion_proof(
                                hasher.inner(),
                                &proof,
                                &k,
                                info.clone(),
                                &current_root,
                            );
                            assert!(verification_result, "Key value proof verification failed for key {key:?}");
                        }
                        Err(commonware_storage::adb::Error::KeyExists) => {
                            assert!(expected_state.contains_key(key), "Proof generation should not fail for non-existent key {key:?}");
                        }
                        Err(e) => {
                            panic!("Unexpected error during exclusion proof generation: {e:?}");
                        }
                    }
                }
            }
        }

        if uncommitted_ops > 0 {
            db.commit(None).await.expect("Final commit should not fail");
        }

        for key in &all_keys {
            let k = Key::new(*key);
            let result = db.get(&k).await.expect("Final get should not fail");

            match expected_state.get(key) {
                Some(expected_value) => {
                    assert!(result.is_some(), "Lost value for key {key:?} at end");
                    let actual_value = result.expect("Should have value");
                    let actual_bytes: &[u8; 32] = actual_value.as_ref().try_into().expect("Value should be 32 bytes");
                    assert_eq!(actual_bytes, expected_value, "Final value mismatch for key {key:?}");
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
