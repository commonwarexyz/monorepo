#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    index::unordered::Index,
    journal::contiguous::fixed::{Config as FConfig, Journal},
    merkle::{Family as MerkleFamily, Location, mmb, mmr},
    mmr::full::Config as MerkleConfig,
    qmdb::{
        any::{
            FixedConfig as Config,
            db::Db as AnyDb,
            unordered::{Operation, Update},
            value::FixedEncoding,
        },
        verify_proof,
    },
    translator::EightCap,
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU16,
};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];
const BITMAP_CHUNK_BYTES: usize = 64;
const MAX_OPERATIONS: usize = 50;

type GenericDb<F> = AnyDb<
    F,
    deterministic::Context,
    Journal<deterministic::Context, Operation<F, Key, FixedEncoding<Value>>>,
    Index<EightCap, Location<F>>,
    Sha256,
    Update<Key, FixedEncoding<Value>>,
    BITMAP_CHUNK_BYTES,
    Sequential,
>;

#[derive(Arbitrary, Debug, Clone)]
enum QmdbOperation {
    Update { key: RawKey, value: RawValue },
    Delete { key: RawKey },
    Commit,
    OpCount,
    Root,
    Proof { start_loc: u64, max_ops: u64 },
    Get { key: RawKey },
    GetMany { keys: [RawKey; 2] },
}

#[derive(Debug)]
struct FuzzInput {
    operations: Vec<QmdbOperation>,
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let num_operations = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..num_operations)
            .map(|_| QmdbOperation::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            operations,
            raw_bytes,
        })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(223);
const PAGE_CACHE_SIZE: usize = 100;

async fn commit_pending<F: MerkleFamily>(
    db: GenericDb<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    committed_state: &mut HashMap<RawKey, Option<RawValue>>,
    pending_expected: &mut HashMap<RawKey, Option<RawValue>>,
    expected_op_count: &mut Location<F>,
) -> GenericDb<F> {
    let mut batch = db.new_batch();
    for (k, v) in pending_writes.drain(..) {
        batch = batch.write(k, v);
    }
    let merkleized = batch.merkleize(&db, None).await.unwrap();
    let expected_end = merkleized.bounds().tip.size;
    let (db, applied) = db
        .apply_batch(merkleized)
        .await
        .expect("commit should not fail");
    assert_eq!(
        applied,
        *expected_op_count..expected_end,
        "applied operation range disagreed with the modeled log tip",
    );
    *expected_op_count = expected_end;
    let db = db.commit().await.expect("commit fsync should not fail");
    committed_state.extend(pending_expected.drain());
    db
}

fn fuzz_family<F: MerkleFamily>(data: &FuzzInput, suffix: &str) {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(data.raw_bytes.clone())));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| {
        let operations = data.operations.clone();
        async move {
            let page_cache = CacheRef::from_pooler(
                &context,
                PAGE_SIZE,
                NZUsize!(PAGE_CACHE_SIZE),
            );
            let cfg = Config::<EightCap, Sequential> {
                merkle_config: MerkleConfig {
                    journal_partition: format!("test-qmdb-mmr-journal-{suffix}"),
                    metadata_partition: format!("test-qmdb-mmr-metadata-{suffix}"),
                    items_per_blob: NZU64!(500000),
                    write_buffer: NZUsize!(1024),
                    strategy: Sequential,
                    page_cache: page_cache.clone(),
                },
                journal_config: FConfig {
                    partition: format!("test-qmdb-log-journal-{suffix}"),
                    items_per_blob: NZU64!(500000),
                    write_buffer: NZUsize!(1024),
                    page_cache,
                },
                translator: EightCap,
                init_cache_size: Some(NZUsize!(3)),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };

            let mut db: GenericDb<F> =
                commonware_storage::qmdb::any::init(context.child("storage"), cfg)
                    .await
                    .expect("init qmdb");

            // committed_state tracks state after apply_batch. pending_expected tracks
            // uncommitted mutations that haven't been applied yet.
            let mut committed_state: HashMap<RawKey, Option<RawValue>> = HashMap::new();
            let mut pending_expected: HashMap<RawKey, Option<RawValue>> = HashMap::new();
            let mut all_keys: HashSet<RawKey> = HashSet::new();
            let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();
            let mut expected_op_count = db.bounds().end;

            for op in &operations {
                db = match op {
                    QmdbOperation::Update { key, value } => {
                        let k = Key::new(*key);
                        let v = Value::new(*value);

                        pending_writes.push((k, Some(v)));
                        pending_expected.insert(*key, Some(*value));
                        all_keys.insert(*key);
                        db
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
                        db
                    }

                    QmdbOperation::OpCount => {
                        assert_eq!(
                            db.bounds().end,
                            expected_op_count,
                            "operation count disagreed with the modeled log tip",
                        );
                        db
                    }

                    QmdbOperation::Commit => {
                        commit_pending(
                            db,
                            &mut pending_writes,
                            &mut committed_state,
                            &mut pending_expected,
                            &mut expected_op_count,
                        )
                        .await
                    }

                    QmdbOperation::Root => {
                        let db = commit_pending(
                            db,
                            &mut pending_writes,
                            &mut committed_state,
                            &mut pending_expected,
                            &mut expected_op_count,
                        )
                        .await;
                        assert_eq!(
                            db.root(),
                            db.to_batch().root(),
                            "database root disagreed with its base batch view",
                        );
                        db
                    }

                    QmdbOperation::Proof { start_loc, max_ops } => {
                        let actual_op_count = db.bounds().end;
                        if actual_op_count == 0 || *max_ops == 0 {
                            continue;
                        }

                        let db = commit_pending(
                            db,
                            &mut pending_writes,
                            &mut committed_state,
                            &mut pending_expected,
                            &mut expected_op_count,
                        )
                        .await;
                        let current_root = db.root();
                        let actual_op_count = db.bounds().end;
                        let adjusted_start = Location::<F>::new(*start_loc % *actual_op_count);
                        let adjusted_max_ops = (*max_ops % 100).max(1);

                        let (proof, log) = db
                            .proof(adjusted_start, NZU64!(adjusted_max_ops))
                            .await
                            .expect("proof should not fail");

                        assert!(
                            verify_proof::<Sha256, _, _>(
                                &proof,
                                adjusted_start,
                                &log,
                                &current_root),
                            "Proof verification failed for start_loc={adjusted_start}, max_ops={adjusted_max_ops}",
                        );
                        db
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
                        db
                    }

                    QmdbOperation::GetMany { keys } => {
                        let encoded_keys = keys.map(Key::new);
                        let key_refs = [&encoded_keys[0], &encoded_keys[1]];
                        let values = db
                            .get_many(&key_refs)
                            .await
                            .expect("get many should not fail");
                        for (key, value) in keys.iter().zip(values) {
                            let expected = committed_state
                                .get(key)
                                .and_then(Option::as_ref)
                                .map(|value| Value::new(*value));
                            assert_eq!(
                                value,
                                expected,
                                "batched get disagreed with committed model",
                            );
                        }
                        db
                    }
                };
            }

            // Final commit to ensure all operations are persisted.
            if !pending_writes.is_empty() {
                db = commit_pending(
                    db,
                    &mut pending_writes,
                    &mut committed_state,
                    &mut pending_expected,
                    &mut expected_op_count,
                )
                .await;
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

            let batch = db.new_batch().merkleize(&db, None).await.unwrap();
            let (db, _) = db
                .apply_batch(batch)
                .await
                .expect("final commit should not fail");
            db.destroy().await.expect("destroy should not fail");
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
