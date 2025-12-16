#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    mmr::{hasher::Hasher as _, Location, StandardHasher as Standard},
    qmdb::current::{unordered::Current, Config},
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
        start_loc: u64,
        bad_digests: Vec<[u8; 32]>,
        max_ops: NonZeroU64,
        bad_chunks: Vec<[u8; 32]>,
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

        let mut expected_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut all_keys = std::collections::HashSet::new();
        let mut uncommitted_ops = 0;
        let mut last_committed_op_count = Location::new(1).unwrap();

        for op in &data.operations {
            match op {
                CurrentOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    let mut dirty_db = db.into_dirty();
                    dirty_db.update(k, v).await.expect("Update should not fail");
                    db = dirty_db.merkleize().await.unwrap();
                    expected_state.insert(*key, Some(*value));
                    all_keys.insert(*key);
                    uncommitted_ops += 1;

                }

                CurrentOperation::Delete { key } => {
                    let k = Key::new(*key);
                    // Check if key exists before deletion
                    let key_existed = db.get(&k).await.expect("Get before delete should not fail").is_some();
                    let mut dirty_db = db.into_dirty();
                    dirty_db.delete(k).await.expect("Delete should not fail");
                    db = dirty_db.merkleize().await.unwrap();
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

                    let _root = db.root();
                }

                CurrentOperation::RangeProof { start_loc, max_ops } => {
                    let current_op_count = db.op_count();

                    if current_op_count > 0 {
                        if uncommitted_ops > 0 {
                            db.commit(None).await.expect("Commit before proof should not fail");
                            last_committed_op_count = db.op_count();
                            uncommitted_ops = 0;
                        }

                        let current_root = db.root();

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
                                    hasher.inner(),
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

                CurrentOperation::ArbitraryProof {start_loc, bad_digests, max_ops, bad_chunks} => {
                    let mut hasher = Standard::<Sha256>::new();
                    let current_op_count = db.op_count();
                    if current_op_count == 0 {
                        continue;
                    }

                    let start_loc = Location::new(start_loc % current_op_count.as_u64()).unwrap();
                    let root = db.root();

                    if let Ok((range_proof, ops, chunks)) = db
                        .range_proof(hasher.inner(), start_loc, *max_ops)
                        .await {
                        // Try to verify the proof when providing bad proof digests.
                        let bad_digests = bad_digests.iter().map(|d| Digest::from(*d)).collect();
                        if range_proof.proof.digests != bad_digests {
                            let mut bad_proof = range_proof.clone();
                            bad_proof.proof.digests = bad_digests;
                            assert!(!Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::verify_range_proof(
                                hasher.inner(),
                                &bad_proof,
                                start_loc,
                                &ops,
                                &chunks,
                                &root
                            ), "proof with bad digests should not verify");
                        }

                        // Try to verify the proof when providing bad input chunks.
                        if &chunks != bad_chunks {
                            assert!(!Current::<deterministic::Context, Key, Value, Sha256, TwoCap, 32>::verify_range_proof(
                                    hasher.inner(),
                                    &range_proof,
                                    start_loc,
                                    &ops,
                                    bad_chunks,
                                    &root
                                ), "proof with bad chunks should not verify");
                        }
                    }
                }

                CurrentOperation::KeyValueProof { key } => {
                    let k = Key::new(*key);

                    if uncommitted_ops > 0 {
                        db.commit(None).await.expect("Commit before key value proof should not fail");
                        last_committed_op_count = db.op_count();
                        uncommitted_ops = 0;
                    }

                    let current_root = db.root();

                    match db.key_value_proof(hasher.inner(), k.clone()).await {
                        Ok(proof) => {
                            let value = db.get(&k).await.expect("get should not fail").expect("key should exist");
                            let verification_result = Current::<deterministic::Context, _, _, _, TwoCap, _>::verify_key_value_proof(
                                hasher.inner(),
                                k,
                                value,
                                &proof,
                                &current_root,
                            );
                            assert!(verification_result, "Key value proof verification failed for key {key:?}");
                        }
                        Err(commonware_storage::qmdb::Error::KeyNotFound) => {
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
            db.commit(None).await.expect("Final commit should not fail");
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
