#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::{
    adb::any::{Any, Config},
    index::translator::EightCap,
    mmr::hasher::Standard,
};
use commonware_utils::array::FixedBytes;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];

#[derive(Arbitrary, Debug, Clone)]
enum AdbOperation {
    Update { key: RawKey, value: RawValue },
    Delete { key: RawKey },
    Commit,
    OpCount,
    OldestRetainedLoC,
    Root,
    Proof { start_loc: u64, max_ops: u64 },
    Get { key: RawKey },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<AdbOperation>,
}

fn fuzz(data: FuzzInput) {
    let mut hasher = Standard::<Sha256>::new();
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config::<EightCap> {
            mmr_journal_partition: "test_adb_mmr_journal".into(),
            mmr_items_per_blob: 500000,
            mmr_write_buffer: 1024,
            mmr_metadata_partition: "test_adb_mmr_metadata".into(),
            log_journal_partition: "test_adb_log_journal".into(),
            log_items_per_blob: 500000,
            log_write_buffer: 1024,
            translator: EightCap,
            pool: None,
        };

        let mut adb = Any::<_, Key, Value, Sha256, EightCap>::init(context.clone(), cfg.clone())
            .await
            .expect("init adb");

        let mut expected_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut all_keys: HashSet<RawKey> = HashSet::new();
        let op_count: u64 = 0;

        for op in &data.operations {
            match op {
                AdbOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    let update_result = adb.update(k, v).await.expect("update should not fail");

                    match update_result {
                        commonware_storage::adb::any::UpdateResult::Inserted(_) => {
                            expected_state.insert(*key, Some(*value));
                            all_keys.insert(*key);
                        }
                        commonware_storage::adb::any::UpdateResult::Updated(..) => {
                            expected_state.insert(*key, Some(*value));
                            all_keys.insert(*key);
                        }
                        commonware_storage::adb::any::UpdateResult::NoOp => {
                            // NoOp means the value was already the same
                            // We should still track this key
                            all_keys.insert(*key);
                        }
                    }
                }

                AdbOperation::Delete { key } => {
                    let k = Key::new(*key);
                    let result = adb.delete(k).await.expect("delete should not fail");

                    if result.is_some() {
                        // Delete succeeded - mark as deleted, not remove
                        expected_state.insert(*key, None);
                        all_keys.insert(*key);
                    }
                    // If result is None, it was a no-op (key didn't exist)
                }

                AdbOperation::OpCount => {
                    adb.op_count();
                }

                AdbOperation::OldestRetainedLoC => {
                    adb.oldest_retained_loc();
                }

                AdbOperation::Commit => {
                    adb.commit().await.expect("commit should not fail");
                }

                AdbOperation::Root => {
                    // root panics if there are uncommitted operations.
                    adb.commit().await.expect("commit should not fail");
                    adb.root(&mut hasher);
                }

                AdbOperation::Proof { start_loc, max_ops } => {
                    // Only generate proof if we have operations and valid parameters
                    if op_count > 0 && *start_loc < op_count && *max_ops > 0 {
                        // Ensure all operations are committed before generating proof
                        adb.commit().await.expect("commit should not fail");

                        // Get the current root
                        let current_root = adb.root(&mut hasher);

                        // Adjust start_loc to be within valid range (1-indexed)
                        let adjusted_start = (*start_loc % op_count) + 1;
                        let adjusted_max_ops = (*max_ops % 100) + 1; // Limit max_ops to reasonable range

                        let (proof, log) = adb
                            .proof(adjusted_start, adjusted_max_ops)
                            .await
                            .expect("proof should not fail");
                        assert!(
                            Any::<deterministic::Context, _, _, _, EightCap>::verify_proof(
                                &mut hasher,
                                &proof,
                                adjusted_start,
                                &log,
                                &current_root
                            )
                            .expect("verify proof should not fail")
                        );
                    }
                }

                AdbOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = adb.get(&k).await.expect("get should not fail");

                    // Verify against expected state
                    match expected_state.get(key) {
                        Some(Some(expected_value)) => {
                            // Key should exist with this value
                            assert!(result.is_some(), "Expected value for key {key:?}");
                            let v = result.expect("get should not fail");
                            let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
                            assert_eq!(v_bytes, expected_value, "Value mismatch for key {key:?}");
                        }
                        Some(None) => {
                            // Key was explicitly deleted
                            assert!(
                                result.is_none(),
                                "Expected no value for deleted key {key:?}, but found one",
                            );
                        }
                        None => {
                            // Key was never set or deleted
                            assert!(
                                result.is_none(),
                                "Found unexpected value for key {key:?} that was never touched",
                            );
                        }
                    }

                    // Track that we accessed this key
                    all_keys.insert(*key);
                }
            }
        }

        // Final commit to ensure all operations are persisted
        adb.commit().await.expect("commit should not fail");

        // Comprehensive final verification - check ALL keys ever touched
        for key in &all_keys {
            let k = Key::new(*key);
            let result = adb.get(&k).await.expect("final get should not fail");

            match expected_state.get(key) {
                Some(Some(expected_value)) => {
                    assert!(result.is_some(), "Lost value for key {key:?} at end");
                    let v = result.expect("get should not fail");
                    let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
                    assert_eq!(
                        v_bytes, expected_value,
                        "Final value mismatch for key {key:?}"
                    );
                }
                Some(None) => {
                    assert!(
                        result.is_none(),
                        "Deleted key {key:?} should remain deleted, but found value",
                    );
                }
                None => {
                    // This case shouldn't happen in final verification since we're
                    // iterating over all_keys, but include for completeness
                    assert!(result.is_none(), "Key {key:?} should not exist");
                }
            }
        }

        adb.close().await.expect("close should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
