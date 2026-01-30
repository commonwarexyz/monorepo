#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    kv::{Batchable as _, Deletable as _, Gettable as _, Updatable as _},
    qmdb::any::{ordered::fixed::Db, FixedConfig as Config},
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, HashSet},
    num::NonZeroU16,
    ops::Bound::{Excluded, Unbounded},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];
type OrderedDb = Db<deterministic::Context, Key, Value, Sha256, EightCap>;

const MAX_OPS: usize = 25;

#[derive(Arbitrary, Debug, Clone)]
enum QmdbOperation {
    Update { key: RawKey, value: RawValue },
    Delete { key: RawKey },
    Commit { value: RawValue },
    Get { key: RawKey },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<QmdbOperation>,
}

const PAGE_SIZE: NonZeroU16 = NZU16!(111);
const PAGE_CACHE_SIZE: usize = 100;

fn fuzz(data: FuzzInput) {
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

        let mut db = OrderedDb::init(context.clone(), cfg.clone())
            .await
            .expect("init qmdb")
            .into_mutable();
        let mut batch = Some(db.start_batch());
        let mut last_commit = None;

        let mut expected_state: BTreeMap<RawKey, RawValue> = BTreeMap::new();
        let mut all_keys: HashSet<RawKey> = HashSet::new();

        for op in data.operations.iter().take(MAX_OPS) {
            match op {
                QmdbOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);

                    batch
                        .as_mut()
                        .unwrap()
                        .update(k, v)
                        .await
                        .expect("update should not fail");
                    expected_state.insert(*key, *value);
                    all_keys.insert(*key);
                }

                QmdbOperation::Delete { key } => {
                    let k = Key::new(*key);
                    batch
                        .as_mut()
                        .unwrap()
                        .delete(k)
                        .await
                        .expect("delete should not fail");
                    expected_state.remove(key);
                }

                QmdbOperation::Commit { value } => {
                    assert_eq!(last_commit, db.get_metadata().await.unwrap());
                    let b = batch.take().unwrap();
                    let iter = b.into_iter();
                    db.write_batch(iter)
                        .await
                        .expect("write batch should not fail");
                    last_commit = Some(Value::new(*value));
                    let (durable_db, _) = db
                        .commit(Some(Value::new(*value)))
                        .await
                        .expect("commit should not fail");
                    db = durable_db.into_merkleized().into_mutable();

                    // Restore batch for subsequent operations
                    batch = Some(db.start_batch());
                }

                QmdbOperation::Get { key } => {
                    let k = Key::new(*key);
                    let result = batch
                        .as_ref()
                        .unwrap()
                        .get(&k)
                        .await
                        .expect("get should not fail");

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
                }
            }
        }

        // Write any pending batch operations
        let b = batch.take().unwrap();
        let iter = b.into_iter();
        db.write_batch(iter)
            .await
            .expect("write batch should not fail");
        let (durable_db, _) = db.commit(None).await.expect("commit should not fail");
        let db = durable_db.into_merkleized();

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
                    // check the span is correct.
                    let span = db
                        .get_span(&k)
                        .await
                        .expect("get span should not fail")
                        .expect("span should exist");
                    let expected_next = expected_state.range((Excluded(*key), Unbounded)).next();
                    match expected_next {
                        Some((next_key, _)) => {
                            assert_eq!(span.1.next_key, Key::new(*next_key));
                        }
                        None => {
                            let first_key = expected_state.first_key_value().unwrap().0;
                            assert_eq!(span.1.next_key, Key::new(*first_key));
                        }
                    }
                }
                None => {
                    assert!(
                        result.is_none(),
                        "Deleted key {key:?} should remain deleted, but found value",
                    );
                }
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
