#![no_main]
use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::{
    adb::any::{Any, Config},
};
use commonware_utils::array::FixedBytes;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};
use commonware_storage::index::translator::TwoCap;

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];

#[derive(Arbitrary, Debug, Clone)]
enum AdbOperation {
    Update { key: RawKey, value: RawValue },
    Delete { key: RawKey },
    Commit,
    Get { key: RawKey },
}
#[derive(Arbitrary, Debug)]
struct FuzzData {
    operations: Vec<AdbOperation>,
}

fuzz_target!(|data: FuzzData| {
    if data.operations.is_empty() || data.operations.len() > 4 {
        return;
    }
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config::<TwoCap> {
            mmr_journal_partition: "test_adb_mmr_journal".into(),
            mmr_items_per_blob: 500000,
            mmr_write_buffer: 1024,
            mmr_metadata_partition: "test_adb_mmr_metadata".into(),
            log_journal_partition: "test_adb_log_journal".into(),
            log_items_per_blob: 500000,
            log_write_buffer: 1024,
            translator: TwoCap,
            pool: None,
        };

        let mut adb = Any::<_, Key, Value, Sha256, TwoCap>::init(context.clone(), cfg.clone())
            .await
            .unwrap();

        let mut expected_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut all_keys: HashSet<RawKey> = HashSet::new();

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

                AdbOperation::Commit => {
                    adb.commit().await.unwrap();
                }

                AdbOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = adb.get(&k).await.expect("get should not fail");

                    // Verify against expected state
                    match expected_state.get(key) {
                        Some(Some(expected_value)) => {
                            // Key should exist with this value
                            assert!(result.is_some(), "Expected value for key {key:?}");
                            let v = result.unwrap();
                            let v_bytes: &[u8; 64] = v.as_ref().try_into().unwrap();
                            assert_eq!(v_bytes, expected_value, "Value mismatch for key {key:?}");
                        }
                        Some(None) => {
                            // Key was explicitly deleted
                            assert!(
                                result.is_none(),
                                "Expected no value for deleted key {:?}, but found one",
                                key
                            );
                        }
                        None => {
                            // Key was never set or deleted
                            assert!(
                                result.is_none(),
                                "Found unexpected value for key {:?} that was never touched",
                                key
                            );
                        }
                    }

                    // Track that we accessed this key
                    all_keys.insert(*key);
                }
            }
        }

        // Final commit to ensure all operations are persisted
        adb.commit().await.unwrap();

        // Comprehensive final verification - check ALL keys ever touched
        for key in &all_keys {
            let k = Key::new(*key);
            let result = adb.get(&k).await.expect("final get should not fail");

            match expected_state.get(key) {
                Some(Some(expected_value)) => {
                    assert!(result.is_some(), "Lost value for key {key:?} at end");
                    let v = result.unwrap();
                    let v_bytes: &[u8; 64] = v.as_ref().try_into().unwrap();
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

        adb.close().await.unwrap();
    });
});
