#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Supervisor};
use commonware_storage::{
    index::ordered::Index,
    journal::contiguous::fixed::{Config as FConfig, Journal},
    merkle::{mmb, mmr, Family as MerkleFamily, Location},
    mmr::journaled::Config as MerkleConfig,
    qmdb::any::{
        db::Db as AnyDb,
        ordered::{Operation, Update},
        value::FixedEncoding,
        FixedConfig as Config,
    },
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::NonZeroU16,
    ops::Bound::{Excluded, Unbounded},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];
type GenericDb<F> = AnyDb<
    F,
    deterministic::Context,
    Journal<deterministic::Context, Operation<F, Key, FixedEncoding<Value>>>,
    Index<EightCap, Location<F>>,
    Sha256,
    Update<Key, FixedEncoding<Value>>,
>;

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

async fn commit_pending<F: MerkleFamily>(
    db: &mut GenericDb<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    committed_state: &mut BTreeMap<RawKey, RawValue>,
    pending_inserts: &mut HashMap<RawKey, RawValue>,
    pending_deletes: &mut HashSet<RawKey>,
    metadata: Option<Value>,
) {
    let mut batch = db.new_batch();
    for (k, v) in pending_writes.drain(..) {
        batch = batch.write(k, v);
    }
    let merkleized = batch.merkleize(db, metadata).await.unwrap();
    db.apply_batch(merkleized)
        .await
        .expect("commit should not fail");
    db.commit().await.expect("commit fsync should not fail");
    for key in pending_deletes.drain() {
        committed_state.remove(&key);
    }
    committed_state.extend(pending_inserts.drain());
}

fn fuzz_family<F: MerkleFamily>(data: &FuzzInput, suffix: &str) {
    let runner = deterministic::Runner::default();

    runner.start(|context| {
        let operations = data.operations.clone();
        async move {
            let page_cache =
                CacheRef::from_pooler(context.child("cache"), PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
            let cfg = Config::<EightCap> {
                merkle_config: MerkleConfig {
                    journal_partition: format!("test-qmdb-merkle-journal-{suffix}"),
                    metadata_partition: format!("test-qmdb-merkle-metadata-{suffix}"),
                    items_per_blob: NZU64!(500000),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: page_cache.clone(),
                },
                journal_config: FConfig {
                    partition: format!("test-qmdb-log-journal-{suffix}"),
                    items_per_blob: NZU64!(500000),
                    write_buffer: NZUsize!(1024),
                    page_cache,
                },
                translator: EightCap,
            };

            let mut db: GenericDb<F> =
                commonware_storage::qmdb::any::init(context.child("db"), cfg, None, |_, _| {})
                    .await
                    .expect("init qmdb");
            let mut last_commit = None;
            let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();

            // committed_state tracks state after apply_batch. pending_inserts/pending_deletes
            // track uncommitted mutations.
            let mut committed_state: BTreeMap<RawKey, RawValue> = BTreeMap::new();
            let mut pending_inserts: HashMap<RawKey, RawValue> = HashMap::new();
            let mut pending_deletes: HashSet<RawKey> = HashSet::new();
            let mut all_keys: HashSet<RawKey> = HashSet::new();

            for op in operations.iter().take(MAX_OPS) {
                match op {
                    QmdbOperation::Update { key, value } => {
                        let k = Key::new(*key);
                        let v = Value::new(*value);

                        pending_writes.push((k, Some(v)));
                        pending_deletes.remove(key);
                        pending_inserts.insert(*key, *value);
                        all_keys.insert(*key);
                    }

                    QmdbOperation::Delete { key } => {
                        let k = Key::new(*key);
                        pending_writes.push((k, None));
                        pending_inserts.remove(key);
                        pending_deletes.insert(*key);
                    }

                    QmdbOperation::Commit { value } => {
                        assert_eq!(last_commit, db.get_metadata().await.unwrap());
                        commit_pending(
                            &mut db,
                            &mut pending_writes,
                            &mut committed_state,
                            &mut pending_inserts,
                            &mut pending_deletes,
                            Some(Value::new(*value)),
                        )
                        .await;
                        last_commit = Some(Value::new(*value));
                    }

                    QmdbOperation::Get { key } => {
                        let k = Key::new(*key);
                        let result = db.get(&k).await.expect("get should not fail");

                        // Verify against committed state only.
                        match committed_state.get(key) {
                            Some(expected_value) => {
                                let v = result.expect("get should not fail");
                                let v_bytes: &[u8; 64] = v.as_ref().try_into().expect("bytes");
                                assert_eq!(
                                    v_bytes, expected_value,
                                    "Value mismatch for key {key:?}"
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

            // Commit any remaining pending operations.
            commit_pending(
                &mut db,
                &mut pending_writes,
                &mut committed_state,
                &mut pending_inserts,
                &mut pending_deletes,
                None,
            )
            .await;

            // Comprehensive final verification - check ALL keys ever touched
            for key in &all_keys {
                let k = Key::new(*key);
                let result = db.get(&k).await.expect("final get should not fail");

                match committed_state.get(key) {
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
                        let expected_next =
                            committed_state.range((Excluded(*key), Unbounded)).next();
                        match expected_next {
                            Some((next_key, _)) => {
                                assert_eq!(span.1.next_key, Key::new(*next_key));
                            }
                            None => {
                                let first_key = committed_state.first_key_value().unwrap().0;
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
            committed_state.clear();
            all_keys.clear();
        }
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input, "fuzz-mmr");
    fuzz_family::<mmb::Family>(&input, "fuzz-mmb");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
