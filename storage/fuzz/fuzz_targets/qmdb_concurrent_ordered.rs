#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    kv::{Deletable as _, Gettable as _, Updatable as _},
    mmr::{Location, StandardHasher as Standard},
    qmdb::{
        any::{ordered::fixed::Db, FixedConfig as Config, SyncPolicy},
        verify_proof,
    },
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroU64},
    time::Duration,
};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];
type OrderedDb = Db<deterministic::Context, Key, Value, Sha256, EightCap>;

const MAX_OPS: usize = 25;
const PAGE_SIZE: NonZeroU16 = NZU16!(555);
const PAGE_CACHE_SIZE: usize = 100;

#[derive(Arbitrary, Debug, Clone)]
enum Op {
    Update {
        key: RawKey,
        value: RawValue,
    },
    Delete {
        key: RawKey,
    },
    Commit,
    Get {
        key: RawKey,
    },
    Root,
    Proof {
        historical_size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzSyncPolicy {
    Never,
    Always,
    Interval,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    sync_policy: FuzzSyncPolicy,
    operations: Vec<Op>,
}

fn fuzz(data: FuzzInput) {
    let mut hasher = Standard::<Sha256>::new();
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config::<EightCap> {
            mmr_journal_partition: "test-qmdb-mmr-journal".into(),
            mmr_items_per_blob: NZU64!(500000),
            mmr_write_buffer: NZUsize!(1024),
            mmr_metadata_partition: "test-qmdb-mmr-metadata".into(),
            log_journal_partition: "test-qmdb-log-journal".into(),
            log_items_per_blob: NZU64!(500000),
            log_write_buffer: NZUsize!(1024),
            translator: EightCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
        };

        let db = OrderedDb::init(context.clone(), cfg)
            .await
            .expect("init qmdb");

        let sync_policy = match data.sync_policy {
            FuzzSyncPolicy::Never => SyncPolicy::Never,
            FuzzSyncPolicy::Always => SyncPolicy::Always,
            FuzzSyncPolicy::Interval => SyncPolicy::Interval(Duration::from_millis(50)),
        };

        let (mut writer, shared) = db.into_concurrent(context.clone(), sync_policy);

        let mut expected_state: HashMap<RawKey, RawValue> = HashMap::new();
        let mut roots: HashMap<Location, Digest> = HashMap::new();
        let mut last_commit_size = Location::new(0).unwrap();

        for op in data.operations.iter().take(MAX_OPS) {
            match op {
                Op::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);
                    let mut batch = shared.start_batch().await;
                    batch.update(k, v).await.expect("update should not fail");
                    writer
                        .write_batch(batch)
                        .await
                        .expect("write_batch should not fail");
                    expected_state.insert(*key, *value);
                }

                Op::Delete { key } => {
                    let k = Key::new(*key);
                    let mut batch = shared.start_batch().await;
                    batch.delete(k).await.expect("delete should not fail");
                    writer
                        .write_batch(batch)
                        .await
                        .expect("write_batch should not fail");
                    expected_state.remove(key);
                }

                Op::Commit => {
                    let range = writer.commit(None).await.expect("commit should not fail");
                    last_commit_size = range.end;
                }

                Op::Get { key } => {
                    let k = Key::new(*key);
                    let reader = shared.reader().await;
                    let result = reader.get(&k).await.expect("get should not fail");
                    match expected_state.get(key) {
                        Some(expected_value) => {
                            let v = result.expect("key should exist");
                            let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
                            assert_eq!(v_bytes, expected_value, "Value mismatch for key {key:?}");
                        }
                        None => {
                            assert!(result.is_none(), "Deleted key {key:?} should be None");
                        }
                    }
                }

                Op::Root => {
                    let (root, range) = writer
                        .commit_and_compute_root(None)
                        .await
                        .expect("commit_and_compute_root should not fail");
                    last_commit_size = range.end;
                    roots.insert(range.end, root);
                }

                Op::Proof {
                    historical_size,
                    start_loc,
                    max_ops,
                } => {
                    let size = Location::new(*historical_size).unwrap_or(last_commit_size);
                    let start = Location::new(*start_loc).unwrap_or(last_commit_size);
                    if let Ok((proof, log)) = shared.historical_proof(size, start, *max_ops).await {
                        // Verify the proof if we have a root for this exact historical size.
                        if let Some(root) = roots.get(&proof.leaves) {
                            assert!(
                                verify_proof(&mut hasher, &proof, start, &log, root),
                                "Proof verification failed for start={start}, max_ops={max_ops}",
                            );
                        }
                    }
                }
            }
        }

        // Final commit.
        let _ = writer
            .commit(None)
            .await
            .expect("final commit should not fail");

        // Verify all keys via the shared reader.
        let reader = shared.reader().await;
        for (key, expected_value) in &expected_state {
            let k = Key::new(*key);
            let result = reader.get(&k).await.expect("final get should not fail");
            let v = result.expect("committed key should exist");
            let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
            assert_eq!(
                v_bytes, expected_value,
                "Final value mismatch for key {key:?}"
            );
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
