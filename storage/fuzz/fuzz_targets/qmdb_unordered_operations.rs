#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    mmr::{Location, StandardHasher as Standard},
    qmdb::{
        any::{unordered::fixed::Db, FixedConfig as Config},
        verify_proof,
    },
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU16,
};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];

#[derive(Arbitrary, Debug, Clone)]
enum QmdbOperation {
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
    operations: Vec<QmdbOperation>,
}

const PAGE_SIZE: NonZeroU16 = NZU16!(223);
const PAGE_CACHE_SIZE: usize = 100;

fn fuzz(data: FuzzInput) {
    let mut hasher = Standard::<Sha256>::new();
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config::<EightCap> {
            mmr_journal_partition: "test_qmdb_mmr_journal".into(),
            mmr_items_per_blob: NZU64!(500000),
            mmr_write_buffer: NZUsize!(1024),
            mmr_metadata_partition: "test_qmdb_mmr_metadata".into(),
            log_journal_partition: "test_qmdb_log_journal".into(),
            log_items_per_blob: NZU64!(500000),
            log_write_buffer: NZUsize!(1024),
            translator: EightCap,
            thread_pool: None,
            page_cache: CacheRef::new(PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
        };

        let mut db = Db::<_, Key, Value, Sha256, EightCap>::init(context.clone(), cfg.clone())
            .await
            .expect("init qmdb").into_mutable();

        let mut expected_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut all_keys: HashSet<RawKey> = HashSet::new();
        let mut uncommitted_ops = 0;
        let mut last_known_op_count = Location::new(1).unwrap();

        for op in &data.operations {
            match op {
                QmdbOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    db.update(k, v).await.expect("update should not fail");
                    expected_state.insert(*key, Some(*value));
                    all_keys.insert(*key);
                    uncommitted_ops += 1;
                }

                QmdbOperation::Delete { key } => {
                    let k = Key::new(*key);
                    if db.delete(k).await.expect("delete should not fail") {
                        // Delete succeeded - mark as deleted, not remove
                        assert!(all_keys.contains(key), "there was no key");
                        expected_state.insert(*key, None);
                        uncommitted_ops += 1;
                    }
                }

                QmdbOperation::OpCount => {
                    let actual_count = db.op_count();
                    // The count should have increased by the number of uncommitted operations
                    let expected_count = last_known_op_count + uncommitted_ops;
                    assert_eq!(actual_count, expected_count,
                        "Operation count mismatch: expected {expected_count} (last_known={last_known_op_count} + uncommitted={uncommitted_ops}), got {actual_count}");
                }

                QmdbOperation::Commit => {
                    let (durable_db, _) = db.commit(None).await.expect("commit should not fail");
                    // After commit, update our last known count since commit may add more operations
                    last_known_op_count = durable_db.op_count();
                    uncommitted_ops = 0; // Reset uncommitted operations counter
                    db = durable_db.into_mutable();
                }

                QmdbOperation::Root => {
                    // root requires merkleization but not commit
                    let clean_db = db.into_merkleized();
                    clean_db.root();
                    db = clean_db.into_mutable();
                }

                QmdbOperation::Proof { start_loc, max_ops } => {
                    let actual_op_count = db.op_count();
                    // Only generate proof if proof will have operations.
                    if actual_op_count == 0 || *max_ops == 0 {
                        continue;
                    }

                    let clean_db = db.into_merkleized();

                    let current_root = clean_db.root();
                    // Adjust start_loc to be within valid range
                    // Locations are 0-indexed (first operation is at location 0)
                    let adjusted_start = Location::new(*start_loc % *actual_op_count).unwrap();
                    let adjusted_max_ops = (*max_ops % 100).max(1); // Ensure at least 1

                    let (proof, log) = clean_db
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
                    db = clean_db.into_mutable();
                }

                QmdbOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = db.get(&k).await.expect("get should not fail");

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
            let (durable_db, _) = db.commit(None).await.expect("final commit should not fail");
            db = durable_db.into_mutable();
        }

        // Comprehensive final verification - check ALL keys ever touched
        for key in &all_keys {
            let k = Key::new(*key);
            let result = db.get(&k).await.expect("final get should not fail");

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

        let (durable_db, _) = db.commit(None).await.expect("final commit should not fail");
        durable_db.into_merkleized().destroy().await.expect("destroy should not fail");
        expected_state.clear();
        all_keys.clear();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
