#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::{
        any::fixed::{ordered::Any, Config},
        verify_proof,
    },
    mmr::{Location, Position, Proof, StandardHasher as Standard},
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU64,
};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];

const MAX_OPS: usize = 25;

enum AdbState<
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    K: commonware_utils::sequence::Array,
    V: commonware_codec::CodecFixed<Cfg = ()>,
    H: commonware_cryptography::Hasher,
    T: commonware_storage::translator::Translator,
> {
    Clean(
        Any<
            E,
            K,
            V,
            H,
            T,
            commonware_storage::mmr::mem::Clean<<H as commonware_cryptography::Hasher>::Digest>,
        >,
    ),
    Dirty(Any<E, K, V, H, T, commonware_storage::mmr::mem::Dirty>),
}

#[derive(Arbitrary, Debug, Clone)]
enum AdbOperation {
    Update {
        key: RawKey,
        value: RawValue,
    },
    Delete {
        key: RawKey,
    },
    Commit,
    OpCount,
    Root,
    Proof {
        start_loc: u64,
        max_ops: NonZeroU64,
    },
    ArbitraryProof {
        start_loc: u64,
        max_ops: NonZeroU64,
        proof_size: u64,
        digests: Vec<[u8; 32]>,
    },
    Get {
        key: RawKey,
    },
    GetSpan {
        key: RawKey,
    },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<AdbOperation>,
}

const PAGE_SIZE: usize = 555;
const PAGE_CACHE_SIZE: usize = 100;

fn fuzz(data: FuzzInput) {
    let mut hasher = Standard::<Sha256>::new();
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config::<EightCap> {
            mmr_journal_partition: "test_adb_mmr_journal".into(),
            mmr_items_per_blob: NZU64!(500000),
            mmr_write_buffer: NZUsize!(1024),
            mmr_metadata_partition: "test_adb_mmr_metadata".into(),
            log_journal_partition: "test_adb_log_journal".into(),
            log_items_per_blob: NZU64!(500000),
            log_write_buffer: NZUsize!(1024),
            translator: EightCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        };

        let adb = Any::<_, Key, Value, Sha256, EightCap>::init(context.clone(), cfg.clone())
            .await
            .expect("init adb");

        let mut adb = AdbState::Clean(adb);
        let mut expected_state: HashMap<RawKey, RawValue> = HashMap::new();
        let mut all_keys: HashSet<RawKey> = HashSet::new();
        let mut uncommitted_ops = 0;
        let mut last_known_op_count = Location::new(0).unwrap();

        for op in data.operations.iter().take(MAX_OPS) {
            adb = match op {
                AdbOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    let mut db = match adb {
                        AdbState::Clean(d) => d.into_dirty(),
                        AdbState::Dirty(d) => d,
                    };
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
                    let expected_count = last_known_op_count + uncommitted_ops;
                    assert_eq!(actual_count, expected_count,
                        "Operation count mismatch: expected {expected_count} (last_known={last_known_op_count} + uncommitted={uncommitted_ops}), got {actual_count}");
                    AdbState::Dirty(db)
                }

                AdbOperation::Delete { key } => {
                    let k = Key::new(*key);
                    let mut db = match adb {
                        AdbState::Clean(d) => d.into_dirty(),
                        AdbState::Dirty(d) => d,
                    };
                    db.delete(k).await.expect("delete should not fail");
                    if expected_state.remove(key).is_some() {
                        uncommitted_ops += 1;
                        if expected_state.keys().len() != 0 {
                            uncommitted_ops += 1;
                        }
                    }
                    AdbState::Dirty(db)
                }

                AdbOperation::OpCount => {
                    match &adb {
                        AdbState::Clean(d) => {
                            let actual_count = d.op_count();
                            let expected_count = last_known_op_count + uncommitted_ops;
                            assert_eq!(actual_count, expected_count,
                                "Operation count mismatch: expected {expected_count} (last_known={last_known_op_count} + uncommitted={uncommitted_ops}), got {actual_count}");
                        }
                        AdbState::Dirty(d) => {
                            let actual_count = d.op_count();
                            let expected_count = last_known_op_count + uncommitted_ops;
                            assert_eq!(actual_count, expected_count,
                                "Operation count mismatch: expected {expected_count} (last_known={last_known_op_count} + uncommitted={uncommitted_ops}), got {actual_count}");
                        }
                    }
                    adb
                }

                AdbOperation::Commit => {
                    let mut db = match adb {
                        AdbState::Clean(d) => d.into_dirty(),
                        AdbState::Dirty(d) => d,
                    };
                    db.commit().await.expect("commit should not fail");
                    let db = db.merkleize();
                    // After commit, update our last known count since commit may add more operations
                    last_known_op_count = db.op_count();
                    uncommitted_ops = 0; // Reset uncommitted operations counter
                    AdbState::Clean(db)
                }

                AdbOperation::Root => {
                    let db = match adb {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => {
                            let mut dirty_db = d;
                            if uncommitted_ops > 0 {
                                dirty_db.commit().await.expect("commit should not fail");
                                last_known_op_count = dirty_db.op_count();
                                uncommitted_ops = 0;
                            }
                            dirty_db.merkleize()
                        }
                    };
                    db.root();
                    AdbState::Clean(db)
                }

                AdbOperation::Proof { start_loc, max_ops } => {
                    let db = match adb {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => {
                            let mut dirty_db = d;
                            if uncommitted_ops > 0 {
                                dirty_db.commit().await.expect("commit should not fail");
                                last_known_op_count = dirty_db.op_count();
                                uncommitted_ops = 0;
                            }
                            dirty_db.merkleize()
                        }
                    };
                    let actual_op_count = db.op_count();

                    // Only generate proof if ADB has operations and valid parameters
                    if actual_op_count > 0 {
                        let current_root = db.root();
                        // Adjust start_loc to be within valid range
                        // Locations are 0-indexed (first operation is at location 0)
                        let adjusted_start = Location::new(*start_loc % *actual_op_count).unwrap();

                        let (proof, log) = db
                            .proof(adjusted_start, *max_ops)
                            .await
                            .expect("proof should not fail");

                        assert!(
                            verify_proof(
                                &mut hasher,
                                &proof,
                                adjusted_start,
                                &log,
                                &current_root
                            ),
                            "Proof verification failed for start_loc={adjusted_start}, max_ops={max_ops}",
                        );
                    }
                    AdbState::Clean(db)
                }

                AdbOperation::ArbitraryProof { start_loc, max_ops , proof_size, digests} => {
                    let db = match adb {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => {
                            let mut dirty_db = d;
                            if uncommitted_ops > 0 {
                                dirty_db.commit().await.expect("commit should not fail");
                                last_known_op_count = dirty_db.op_count();
                                uncommitted_ops = 0;
                            }
                            dirty_db.merkleize()
                        }
                    };
                    let actual_op_count = db.op_count();

                    let proof = Proof {
                        size: Position::new(*proof_size),
                        digests: digests.iter().map(|d| Digest::from(*d)).collect(),
                    };

                    // Only generate proof if ADB has operations and valid parameters
                    if actual_op_count > 0 {
                        let current_root = db.root();
                        let adjusted_start = Location::new(*start_loc % *actual_op_count).unwrap();

                        if let Ok(res) = db
                            .proof(adjusted_start, *max_ops)
                            .await {
                                let _ = verify_proof(
                                    &mut hasher,
                                    &proof,
                                    adjusted_start,
                                    &res.1,
                                    &current_root
                                );

                        }
                    }
                    AdbState::Clean(db)
                }

                AdbOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = match &adb {
                        AdbState::Clean(d) => d.get(&k).await.expect("get should not fail"),
                        AdbState::Dirty(d) => d.get(&k).await.expect("get should not fail"),
                    };

                    // Verify against expected state
                    match expected_state.get(key) {
                        Some(expected_value) => {
                            // Key should exist with this value
                            let v = result.expect("get should not fail");
                            let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
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
                    adb
                }

                AdbOperation::GetSpan { key } => {
                    let k = Key::new(*key);
                    let result = match &adb {
                        AdbState::Clean(d) => d.get_span(&k).await.expect("get should not fail"),
                        AdbState::Dirty(d) => d.get_span(&k).await.expect("get should not fail"),
                    };
                    let is_empty = match &adb {
                        AdbState::Clean(d) => d.is_empty(),
                        AdbState::Dirty(d) => d.is_empty(),
                    };
                    assert_eq!(result.is_some(), !is_empty, "span should be empty only if db is empty");
                    adb
                }
            };
        }

        // Final commit to ensure all operations are persisted
        let db = match adb {
            AdbState::Clean(d) => d,
            AdbState::Dirty(d) => {
                let mut dirty_db = d;
                if uncommitted_ops > 0 {
                    dirty_db.commit().await.expect("final commit should not fail");
                }
                dirty_db.merkleize()
            }
        };

        // Comprehensive final verification - check ALL keys ever touched
        for key in &all_keys {
            let k = Key::new(*key);
            let result = db.get(&k).await.expect("final get should not fail");

            match expected_state.get(key) {
                Some(expected_value) => {
                    let v = result.expect("get should not fail");
                    let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
                    assert_eq!(
                        v_bytes, expected_value,
                        "Final value mismatch for key {key:?}"
                    );
                }
                None => {
                    assert!(
                        result.is_none(),
                        "Deleted key {key:?} should remain deleted, but found value",
                    );
                },
            }
        }

        db.destroy().await.expect("destroy should not fail");
        expected_state.clear();
        all_keys.clear();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
