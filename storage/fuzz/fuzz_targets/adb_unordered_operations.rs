#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::{
        any::{unordered::fixed::Any, AnyDb as _, FixedConfig as Config},
        store::Db as _,
        verify_proof,
    },
    mmr::{Location, StandardHasher as Standard},
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
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
    Root,
    Proof { start_loc: u64, max_ops: u64 },
    Get { key: RawKey },
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

        let mut adb = Any::<_, Key, Value, Sha256, EightCap>::init(context.clone(), cfg.clone())
            .await
            .expect("init adb");

        let mut expected_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut all_keys: HashSet<RawKey> = HashSet::new();
        let mut uncommitted_ops = 0;
        let mut last_known_op_count = Location::new(0).unwrap();

        for op in &data.operations {
            match op {
                AdbOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    adb.update(k, v).await.expect("update should not fail");
                    expected_state.insert(*key, Some(*value));
                    all_keys.insert(*key);
                    uncommitted_ops += 1;
                }

                AdbOperation::Delete { key } => {
                    let k = Key::new(*key);
                    if adb.delete(k).await.expect("delete should not fail") {
                        // Delete succeeded - mark as deleted, not remove
                        assert!(all_keys.contains(key), "there was no key");
                        expected_state.insert(*key, None);
                        uncommitted_ops += 1;
                    }
                }

                AdbOperation::OpCount => {
                    let actual_count = adb.op_count();
                    // The count should have increased by the number of uncommitted operations
                    let expected_count = last_known_op_count + uncommitted_ops;
                    assert_eq!(actual_count, expected_count,
                        "Operation count mismatch: expected {expected_count} (last_known={last_known_op_count} + uncommitted={uncommitted_ops}), got {actual_count}");
                }

                AdbOperation::Commit => {
                    adb.commit(None).await.expect("commit should not fail");
                    // After commit, update our last known count since commit may add more operations
                    last_known_op_count = adb.op_count();
                    uncommitted_ops = 0; // Reset uncommitted operations counter
                }

                AdbOperation::Root => {
                    // root requires all operations to be committed
                    if uncommitted_ops > 0 {
                        adb.commit(None).await.expect("commit should not fail");
                        last_known_op_count = adb.op_count();
                        uncommitted_ops = 0;
                    }
                    adb.root();
                }

                AdbOperation::Proof { start_loc, max_ops } => {
                    let actual_op_count = adb.op_count();

                    // Only generate proof if ADB has operations and valid parameters
                    if actual_op_count > 0 && *max_ops > 0 {
                        // Ensure all operations are committed before generating proof
                        if uncommitted_ops > 0 {
                            adb.commit(None).await.expect("commit should not fail");
                            last_known_op_count = adb.op_count();
                            uncommitted_ops = 0;
                        }

                        let current_root = adb.root();
                        // Adjust start_loc to be within valid range
                        // Locations are 0-indexed (first operation is at location 0)
                        let adjusted_start = Location::new(*start_loc % *actual_op_count).unwrap();
                        let adjusted_max_ops = (*max_ops % 100).max(1); // Ensure at least 1

                        let (proof, log) = adb
                            .proof(adjusted_start, NZU64!(adjusted_max_ops))
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
                            "Proof verification failed for start_loc={adjusted_start}, max_ops={adjusted_max_ops}",
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
        if uncommitted_ops > 0 {
            adb.commit(None).await.expect("final commit should not fail");
        }

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

        adb.destroy().await.expect("destroy should not fail");
        expected_state.clear();
        all_keys.clear();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
