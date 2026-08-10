#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    index::ordered::Index,
    journal::contiguous::fixed::{Config as FConfig, Journal},
    merkle::{Family as MerkleFamily, Location, Proof, mmb, mmr},
    mmr::full::Config as MerkleConfig,
    qmdb::{
        any::{
            FixedConfig as Config,
            db::Db as AnyDb,
            ordered::{Operation, Update},
            value::FixedEncoding,
        },
        create_multi_proof, create_proof_store, verify_multi_proof, verify_proof,
        verify_proof_and_extract_digests, verify_proof_and_pinned_nodes,
    },
    translator::EightCap,
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize, sequence::FixedBytes};
use futures::StreamExt as _;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::{NonZeroU16, NonZeroU64},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<64>;
type RawKey = [u8; 32];
type RawValue = [u8; 64];
const BITMAP_CHUNK_BYTES: usize = 64;

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

const MAX_OPS: usize = 25;

#[derive(Arbitrary, Debug, Clone)]
enum QmdbOperation {
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
        proof_leaves: u64,
        digests: Vec<[u8; 32]>,
    },
    Get {
        key: RawKey,
    },
    GetMany {
        keys: [RawKey; 2],
    },
    GetAll {
        key: RawKey,
    },
    GetSpan {
        key: RawKey,
    },
    StreamRange {
        start: RawKey,
    },
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
        let num_operations = u.int_in_range(1..=MAX_OPS)?;
        let operations = (0..num_operations)
            .map(|_| QmdbOperation::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            operations,
            raw_bytes,
        })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(555);
const PAGE_CACHE_SIZE: usize = 100;

async fn commit_pending<F: MerkleFamily>(
    db: GenericDb<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    committed_state: &mut BTreeMap<RawKey, RawValue>,
    pending_inserts: &mut HashMap<RawKey, RawValue>,
    pending_deletes: &mut HashSet<RawKey>,
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
    for key in pending_deletes.drain() {
        committed_state.remove(&key);
    }
    committed_state.extend(pending_inserts.drain());
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
            let mut committed_state: BTreeMap<RawKey, RawValue> = BTreeMap::new();
            let mut pending_inserts: HashMap<RawKey, RawValue> = HashMap::new();
            let mut pending_deletes: HashSet<RawKey> = HashSet::new();
            let mut all_keys: HashSet<RawKey> = HashSet::new();
            let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();
            let mut expected_op_count = db.bounds().end;

            for op in operations.iter().take(MAX_OPS) {
                db = match op {
                    QmdbOperation::Update { key, value } => {
                        let k = Key::new(*key);
                        let v = Value::new(*value);

                        pending_writes.push((k, Some(v)));
                        pending_deletes.remove(key);
                        pending_inserts.insert(*key, *value);
                        all_keys.insert(*key);
                        db
                    }

                    QmdbOperation::Delete { key } => {
                        let k = Key::new(*key);
                        pending_writes.push((k, None));
                        pending_inserts.remove(key);
                        pending_deletes.insert(*key);
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
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes, &mut expected_op_count,
                        ).await
                    }

                    QmdbOperation::Root => {
                        let db = commit_pending(
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes, &mut expected_op_count,
                        ).await;
                        assert_eq!(
                            db.root(),
                            db.to_batch().root(),
                            "database root disagreed with its base batch view",
                        );
                        db
                    }

                    QmdbOperation::Proof { start_loc, max_ops } => {
                        let db = commit_pending(
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes, &mut expected_op_count,
                        ).await;
                        let actual_op_count = db.bounds().end;

                        if actual_op_count > 0 {
                            let current_root = db.root();
                            let adjusted_start = Location::<F>::new(*start_loc % *actual_op_count);
                            let (proof, log) = db
                                .proof(adjusted_start, *max_ops)
                                .await
                                .expect("proof should not fail");

                            assert!(
                                verify_proof::<Sha256, _, _>(
                                    &proof,
                                    adjusted_start,
                                    &log,
                                    &current_root),
                                "Proof verification failed for start_loc={adjusted_start}, max_ops={max_ops}",
                            );

                            let pinned_nodes = db
                                .pinned_nodes_at(adjusted_start)
                                .await
                                .expect("pinned nodes should be available at the proof start");
                            assert!(
                                verify_proof_and_pinned_nodes::<Sha256, _, _>(
                                    &proof,
                                    adjusted_start,
                                    &log,
                                    &pinned_nodes,
                                    &current_root,
                                ),
                                "Proof and database-provided pinned nodes should verify",
                            );

                            let extracted = verify_proof_and_extract_digests::<Sha256, _, _>(
                                &proof,
                                adjusted_start,
                                &log,
                                &current_root,
                            )
                            .expect("Verified proof should yield authenticated digests");

                            let proof_store = create_proof_store::<Sha256, _, _>(
                                &proof,
                                adjusted_start,
                                &log,
                                &current_root,
                            )
                            .expect("Verified proof should create a proof store");
                            let locations = (0..log.len())
                                .map(|offset| {
                                    adjusted_start
                                        .checked_add(offset as u64)
                                        .expect("Proven operation location should not overflow")
                                })
                                .collect::<Vec<_>>();
                            assert!(!locations.is_empty(), "Generated proof should contain operations");

                            match create_multi_proof(&proof_store, &locations, &extracted) {
                                Ok(multi_proof) => {
                                    let selected_ops = locations
                                        .iter()
                                        .copied()
                                        .zip(log.iter().cloned())
                                        .collect::<Vec<_>>();
                                    assert!(
                                        verify_multi_proof::<Sha256, _, _>(
                                            &multi_proof,
                                            &selected_ops,
                                            &current_root,
                                        ),
                                        "Generated multi-proof should verify",
                                    );
                                }
                                Err(
                                    commonware_storage::merkle::Error::CompressedDigest(_)
                                    | commonware_storage::merkle::Error::ElementPruned(_),
                                ) => {}
                                Err(err) => panic!("unexpected multi-proof error: {err:?}"),
                            }
                        }
                        db
                    }

                    QmdbOperation::ArbitraryProof { start_loc, max_ops , proof_leaves, digests} => {
                        let db = commit_pending(
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes, &mut expected_op_count,
                        ).await;
                        let actual_op_count = db.bounds().end;

                        let proof = Proof {
                            leaves: Location::<F>::new(*proof_leaves),
                            inactive_peaks: 0,
                            digests: digests.iter().map(|d| Digest::from(*d)).collect(),
                        };

                        if actual_op_count > 0 {
                            let current_root = db.root();
                            let adjusted_start = Location::<F>::new(*start_loc % *actual_op_count);

                            if let Ok((expected_proof, log)) =
                                db.proof(adjusted_start, *max_ops).await
                            {
                                let verified = verify_proof::<Sha256, _, _>(
                                    &proof,
                                    adjusted_start,
                                    &log,
                                    &current_root,
                                );
                                assert!(
                                    !verified
                                        || (proof.leaves == expected_proof.leaves
                                            && proof.inactive_peaks
                                                == expected_proof.inactive_peaks
                                            && proof.digests == expected_proof.digests),
                                    "an accepted arbitrary proof should describe the authenticated tree",
                                );
                            }
                        }
                        db
                    }

                    QmdbOperation::Get { key } => {
                        let k = Key::new(*key);
                        let result = db.get(&k).await.expect("get should not fail");

                        // Verify against committed state only.
                        match committed_state.get(key) {
                            Some(expected_value) => {
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
                                .map(|value| Value::new(*value));
                            assert_eq!(
                                value,
                                expected,
                                "batched get disagreed with committed model",
                            );
                        }
                        db
                    }

                    QmdbOperation::GetAll { key } => {
                        let actual = db
                            .get_all(&Key::new(*key))
                            .await
                            .expect("get all should not fail");
                        let expected = committed_state.get(key).map(|value| {
                            let next = committed_state
                                .range((std::ops::Bound::Excluded(*key), std::ops::Bound::Unbounded))
                                .next()
                                .or_else(|| committed_state.first_key_value())
                                .expect("active key implies non-empty state")
                                .0;
                            (Value::new(*value), Key::new(*next))
                        });
                        assert_eq!(actual, expected, "get all disagreed with ordered model");
                        db
                    }

                    QmdbOperation::GetSpan { key } => {
                        let k = Key::new(*key);
                        let result = db.get_span(&k).await.expect("get should not fail");
                        assert_eq!(
                            result.is_some(),
                            !committed_state.is_empty(),
                            "span should be empty only if the model is empty",
                        );
                        if let Some((_, update)) = result {
                            let (expected_key, expected_value) = committed_state
                                .range(..=*key)
                                .next_back()
                                .or_else(|| committed_state.last_key_value())
                                .expect("a returned span requires a non-empty model");
                            let expected_next = committed_state
                                .range((
                                    std::ops::Bound::Excluded(*expected_key),
                                    std::ops::Bound::Unbounded,
                                ))
                                .next()
                                .or_else(|| committed_state.first_key_value())
                                .expect("a returned span requires a non-empty model")
                                .0;
                            assert_eq!(update.key, Key::new(*expected_key));
                            assert_eq!(update.value, Value::new(*expected_value));
                            assert_eq!(update.next_key, Key::new(*expected_next));
                            assert!(
                                GenericDb::<F>::span_contains(&update.key, &update.next_key, &k),
                                "returned span does not contain the requested key",
                            );
                        }
                        db
                    }

                    QmdbOperation::StreamRange { start } => {
                        let actual = {
                            let stream = db
                                .stream_range(Key::new(*start))
                                .await
                                .expect("stream range should not fail");
                            futures::pin_mut!(stream);
                            let mut actual = Vec::new();
                            while let Some(entry) = stream.next().await {
                                actual.push(entry.expect("stream entry should not fail"));
                            }
                            actual
                        };
                        let expected = committed_state
                            .range(*start..)
                            .map(|(key, value)| (Key::new(*key), Value::new(*value)))
                            .collect::<Vec<_>>();
                        assert_eq!(actual, expected, "stream range disagreed with ordered model");
                        db
                    }
                };
            }

            // Final commit to ensure all operations are persisted.
            if !pending_writes.is_empty() {
                db = commit_pending(
                    db, &mut pending_writes, &mut committed_state,
                    &mut pending_inserts, &mut pending_deletes, &mut expected_op_count,
                ).await;
            }

            // Comprehensive final verification - check ALL keys ever touched.
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
                    }
                    None => {
                        assert!(
                            result.is_none(),
                            "Deleted key {key:?} should remain deleted, but found value",
                        );
                    },
                }
            }

            let batch = db.new_batch().merkleize(&db, None).await.unwrap();
            let (db, _) = db
                .apply_batch(batch)
                .await
                .expect("final commit should not fail");
            let db = db
                .commit()
                .await
                .expect("final commit fsync should not fail");
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
