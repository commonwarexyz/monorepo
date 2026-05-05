#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Supervisor as _};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{full::Config as MerkleConfig, mmb, mmr, Graftable, Location},
    qmdb::current::{ordered::fixed::Db as CurrentDb, FixedConfig as Config},
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
    num::{NonZeroU16, NonZeroU64},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type RawKey = [u8; 32];
type RawValue = [u8; 32];
type Db<F> = CurrentDb<F, deterministic::Context, Key, Value, Sha256, TwoCap, 32>;

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

const PAGE_SIZE: NonZeroU16 = NZU16!(91);
const PAGE_CACHE_SIZE: usize = 8;
const MERKLE_ITEMS_PER_BLOB: u64 = 11;
const LOG_ITEMS_PER_BLOB: u64 = 7;
const WRITE_BUFFER_SIZE: usize = 1024;

async fn commit_pending<F: Graftable>(
    db: &mut Db<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    committed_state: &mut HashMap<RawKey, RawValue>,
    pending_inserts: &mut HashMap<RawKey, RawValue>,
    pending_deletes: &mut HashSet<RawKey>,
) {
    let mut batch = db.new_batch();
    for (k, v) in pending_writes.drain(..) {
        batch = batch.write(k, v);
    }
    let merkleized = batch.merkleize(db, None).await.unwrap();
    db.apply_batch(merkleized)
        .await
        .expect("commit should not fail");
    db.commit().await.expect("commit fsync should not fail");
    for key in pending_deletes.drain() {
        committed_state.remove(&key);
    }
    committed_state.extend(pending_inserts.drain());
}

fn fuzz_family<F: Graftable>(data: &FuzzInput, suffix: &str) {
    let runner = deterministic::Runner::default();

    let suffix = suffix.to_string();
    let operations = data.operations.clone();
    runner.start(|context| async move {
        let mut hasher = Sha256::new();
        let page_cache = CacheRef::from_pooler(
            &context,
            PAGE_SIZE,
            NZUsize!(PAGE_CACHE_SIZE),
        );
        let cfg = Config {
            merkle_config: MerkleConfig {
                journal_partition: format!("fuzz-current-ord-{suffix}-merkle-journal"),
                metadata_partition: format!("fuzz-current-ord-{suffix}-merkle-metadata"),
                items_per_blob: NZU64!(MERKLE_ITEMS_PER_BLOB),
                write_buffer: NZUsize!(WRITE_BUFFER_SIZE),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FConfig {
                partition: format!("fuzz-current-ord-{suffix}-log-journal"),
                items_per_blob: NZU64!(LOG_ITEMS_PER_BLOB),
                write_buffer: NZUsize!(WRITE_BUFFER_SIZE),
                page_cache,
            },
            grafted_metadata_partition: format!("fuzz-current-ord-{suffix}-grafted-merkle-metadata"),
            translator: TwoCap,
        };

        let mut db: Db<F> = Db::init(context.child("storage"), cfg)
            .await
            .expect("Failed to initialize Current database");

        // committed_state tracks state after apply_batch. pending_inserts/pending_deletes
        // track uncommitted mutations.
        let mut committed_state: HashMap<RawKey, RawValue> = HashMap::new();
        let mut pending_inserts: HashMap<RawKey, RawValue> = HashMap::new();
        let mut pending_deletes: HashSet<RawKey> = HashSet::new();
        let mut all_keys = HashSet::new();
        let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();
        let mut committed_op_count = Location::<F>::new(1);

        for op in &operations {
            match op {
                CurrentOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    pending_writes.push((k, Some(v)));
                    pending_deletes.remove(key);
                    pending_inserts.insert(*key, *value);
                    all_keys.insert(*key);
                }

                CurrentOperation::Delete { key } => {
                    let k = Key::new(*key);
                    pending_writes.push((k, None));
                    pending_inserts.remove(key);
                    pending_deletes.insert(*key);
                }

                CurrentOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = db.get(&k).await.expect("get should not fail");

                    // Verify against committed state only.
                    match committed_state.get(key) {
                        Some(expected_value) => {
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

                    all_keys.insert(*key);
                }

                CurrentOperation::GetSpan { key } => {
                    let k = Key::new(*key);
                    let result = db.get_span(&k).await.expect("get should not fail");
                    assert_eq!(result.is_some(), !db.is_empty(), "span should be empty only if db is empty");
                }

                CurrentOperation::OpCount => {
                    let actual = db.bounds().await.end;
                    assert_eq!(
                        actual, committed_op_count,
                        "Op count mismatch: expected {committed_op_count}, got {actual}"
                    );
                }

                CurrentOperation::Commit => {
                    commit_pending(
                        &mut db, &mut pending_writes, &mut committed_state,
                        &mut pending_inserts, &mut pending_deletes,
                    ).await;
                    committed_op_count = db.bounds().await.end;
                }

                CurrentOperation::Prune => {
                    commit_pending(
                        &mut db, &mut pending_writes, &mut committed_state,
                        &mut pending_inserts, &mut pending_deletes,
                    ).await;
                    committed_op_count = db.bounds().await.end;
                    db.prune(db.sync_boundary()).await.expect("Prune should not fail");
                }

                CurrentOperation::Root => {
                    commit_pending(
                        &mut db, &mut pending_writes, &mut committed_state,
                        &mut pending_inserts, &mut pending_deletes,
                    ).await;
                    committed_op_count = db.bounds().await.end;
                    let _root = db.root();
                }

                CurrentOperation::RangeProof { start_loc, max_ops } => {
                    let current_op_count = db.bounds().await.end;
                    if current_op_count == 0 {
                        continue;
                    }

                    commit_pending(
                        &mut db, &mut pending_writes, &mut committed_state,
                        &mut pending_inserts, &mut pending_deletes,
                    ).await;
                    committed_op_count = db.bounds().await.end;
                    let current_root = db.root();

                    let current_op_count = db.bounds().await.end;
                    let start_loc = Location::<F>::new(start_loc % *current_op_count);

                    let oldest_loc = db.sync_boundary();
                    if start_loc >= oldest_loc {
                        let (proof, ops, chunks) = db
                            .range_proof(&mut hasher, start_loc, *max_ops)
                            .await
                            .expect("Range proof should not fail");

                        assert!(
                            Db::<F>::verify_range_proof(
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

                CurrentOperation::ArbitraryProof {start_loc, bad_digests, max_ops, bad_chunks} => {
                    let current_op_count = db.bounds().await.end;
                    if current_op_count == 0 {
                        continue;
                    }
                    commit_pending(
                        &mut db, &mut pending_writes, &mut committed_state,
                        &mut pending_inserts, &mut pending_deletes,
                    ).await;
                    committed_op_count = db.bounds().await.end;

                    let current_op_count = db.bounds().await.end;
                    let start_loc = Location::<F>::new(start_loc % current_op_count.as_u64());
                    let root = db.root();

                    if let Ok((range_proof, ops, chunks)) = db
                        .range_proof(&mut hasher, start_loc, *max_ops)
                        .await {
                        // Try to verify the proof when providing bad proof digests.
                        let bad_digests = bad_digests.iter().map(|d| Digest::from(*d)).collect();
                        if range_proof.proof.digests != bad_digests {
                            let mut bad_proof = range_proof.clone();
                            bad_proof.proof.digests = bad_digests;
                            assert!(!Db::<F>::verify_range_proof(
                                &mut hasher,
                                &bad_proof,
                                start_loc,
                                &ops,
                                &chunks,
                                &root
                            ), "proof with bad digests should not verify");
                        }

                        // Try to verify the proof when providing bad input chunks.
                        if &chunks != bad_chunks {
                            assert!(!Db::<F>::verify_range_proof(
                                &mut hasher,
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

                    commit_pending(
                        &mut db, &mut pending_writes, &mut committed_state,
                        &mut pending_inserts, &mut pending_deletes,
                    ).await;
                    committed_op_count = db.bounds().await.end;
                    let current_root = db.root();

                    match db.key_value_proof(&mut hasher, k.clone()).await {
                        Ok(proof) => {
                            let value = db.get(&k).await.expect("get should not fail").expect("key should exist");
                            let verification_result = Db::<F>::verify_key_value_proof(
                                &mut hasher,
                                k,
                                value,
                                &proof,
                                &current_root,
                            );
                            assert!(verification_result, "Key value proof verification failed for key {key:?}");
                        }
                        Err(commonware_storage::qmdb::Error::KeyNotFound) => {
                            assert!(!committed_state.contains_key(key), "Proof generation failed for existing key {key:?}");
                        }
                        Err(e) => {
                            panic!("Unexpected error during key value proof generation: {e:?}");
                        }
                    }
                }

                CurrentOperation::ExclusionProof { key } => {
                    let k = Key::new(*key);

                    commit_pending(
                        &mut db, &mut pending_writes, &mut committed_state,
                        &mut pending_inserts, &mut pending_deletes,
                    ).await;
                    committed_op_count = db.bounds().await.end;
                    let current_root = db.root();

                    match db.exclusion_proof(&mut hasher, &k).await {
                        Ok(proof) => {
                            let verification_result = Db::<F>::verify_exclusion_proof(
                                &mut hasher,
                                &k,
                                &proof,
                                &current_root,
                            );
                            assert!(verification_result, "Exclusion proof verification failed for key {key:?}");
                        }
                        Err(commonware_storage::qmdb::Error::KeyExists) => {
                            assert!(committed_state.contains_key(key), "Proof generation should not fail for non-existent key {key:?}");
                        }
                        Err(e) => {
                            panic!("Unexpected error during exclusion proof generation: {e:?}");
                        }
                    }
                }
            }
        }

        // Final commit to ensure all pending operations are persisted.
        if !pending_writes.is_empty() {
            commit_pending(
                &mut db, &mut pending_writes, &mut committed_state,
                &mut pending_inserts, &mut pending_deletes,
            ).await;
        }


        for key in &all_keys {
            let k = Key::new(*key);
            let result = db.get(&k).await.expect("Final get should not fail");

            match committed_state.get(key) {
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

        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family>(&input, "mmr");
    fuzz_family::<mmb::Family>(&input, "mmb");
});
