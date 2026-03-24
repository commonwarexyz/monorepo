#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    mmr::{journaled::Config as MmrConfig, Location, StandardHasher as Standard},
    qmdb::{
        any::{unordered::fixed::Db as AnyDb, FixedConfig as Config},
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
type Db = AnyDb<deterministic::Context, Key, Value, Sha256, EightCap>;

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

async fn commit_pending(
    db: &mut Db,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    committed_state: &mut HashMap<RawKey, Option<RawValue>>,
    pending_expected: &mut HashMap<RawKey, Option<RawValue>>,
) {
    let finalized = {
        let mut batch = db.new_batch();
        for (k, v) in pending_writes.drain(..) {
            batch = batch.write(k, v);
        }
        batch.merkleize(None).await.unwrap().finalize()
    };
    db.apply_batch(finalized)
        .await
        .expect("commit should not fail");
    db.commit().await.expect("commit fsync should not fail");
    committed_state.extend(pending_expected.drain());
}

fn fuzz(data: FuzzInput) {
    let hasher = Standard::<Sha256>::new();
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let page_cache = CacheRef::from_pooler(
            &context,
            PAGE_SIZE,
            NZUsize!(PAGE_CACHE_SIZE),
        );
        let cfg = Config::<EightCap> {
            mmr_config: MmrConfig {
                journal_partition: "test-qmdb-mmr-journal".into(),
                metadata_partition: "test-qmdb-mmr-metadata".into(),
                items_per_blob: NZU64!(500000),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: FConfig {
                partition: "test-qmdb-log-journal".into(),
                items_per_blob: NZU64!(500000),
                write_buffer: NZUsize!(1024),
                page_cache,
            },
            translator: EightCap,
        };

        let mut db = Db::init(context.clone(), cfg.clone())
            .await
            .expect("init qmdb");

        // committed_state tracks state after apply_batch. pending_expected tracks
        // uncommitted mutations that haven't been applied yet.
        let mut committed_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut pending_expected: HashMap<RawKey, Option<RawValue>> = HashMap::new();
        let mut all_keys: HashSet<RawKey> = HashSet::new();
        let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();

        for op in &data.operations {
            match op {
                QmdbOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    pending_writes.push((k, Some(v)));
                    pending_expected.insert(*key, Some(*value));
                    all_keys.insert(*key);
                }

                QmdbOperation::Delete { key } => {
                    let k = Key::new(*key);
                    // Check if the key exists in committed state or pending writes.
                    let exists = db.get(&k).await.expect("get should not fail").is_some()
                        || pending_expected
                            .get(key)
                            .is_some_and(|v| v.is_some());
                    if exists {
                        pending_writes.push((k, None));
                        pending_expected.insert(*key, None);
                    }
                }

                QmdbOperation::OpCount => {
                    let _ = db.bounds().await.end;
                }

                QmdbOperation::Commit => {
                    commit_pending(&mut db, &mut pending_writes, &mut committed_state, &mut pending_expected).await;
                }

                QmdbOperation::Root => {
                    commit_pending(&mut db, &mut pending_writes, &mut committed_state, &mut pending_expected).await;
                    db.root();
                }

                QmdbOperation::Proof { start_loc, max_ops } => {
                    let actual_op_count = db.bounds().await.end;
                    if actual_op_count == 0 || *max_ops == 0 {
                        continue;
                    }

                    commit_pending(&mut db, &mut pending_writes, &mut committed_state, &mut pending_expected).await;
                    let current_root = db.root();
                    let actual_op_count = db.bounds().await.end;
                    let adjusted_start = Location::new(*start_loc % *actual_op_count);
                    let adjusted_max_ops = (*max_ops % 100).max(1);

                    let (proof, log) = db
                        .proof(adjusted_start, NZU64!(adjusted_max_ops))
                        .await
                        .expect("proof should not fail");

                    assert!(
                        verify_proof(
                            &hasher,
                            &proof,
                            adjusted_start,
                            &log,
                            &current_root
                            ),
                        "Proof verification failed for start_loc={adjusted_start}, max_ops={adjusted_max_ops}",
                    );
                }

                QmdbOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = db.get(&k).await.expect("get should not fail");

                    // Verify against committed state only (pending writes not yet applied).
                    match committed_state.get(key) {
                        Some(Some(expected_value)) => {
                            assert!(result.is_some(), "Expected value for key {key:?}");
                            let v = result.expect("get should not fail");
                            let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
                            assert_eq!(v_bytes, expected_value, "Value mismatch for key {key:?}");
                        }
                        Some(None) => {
                            assert!(
                                result.is_none(),
                                "Expected no value for deleted key {key:?}, but found one",
                            );
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
            }
        }

        // Final commit to ensure all operations are persisted.
        if !pending_writes.is_empty() {
            commit_pending(&mut db, &mut pending_writes, &mut committed_state, &mut pending_expected).await;
        }

        // Comprehensive final verification - check ALL keys ever touched.
        for key in &all_keys {
            let k = Key::new(*key);
            let result = db.get(&k).await.expect("final get should not fail");

            match committed_state.get(key) {
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
                    assert!(result.is_none(), "Key {key:?} should not exist");
                }
            }
        }

        let finalized = db.new_batch().merkleize(None).await.unwrap().finalize();
        db.apply_batch(finalized).await.expect("final commit should not fail");
        db.destroy().await.expect("destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
