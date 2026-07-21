#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::Encode as _;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    index::ordered::Index,
    journal::contiguous::fixed::{Config as FConfig, Journal},
    merkle::{Family as MerkleFamily, Location, Proof, mmb, mmr},
    mmr::full::Config as MerkleConfig,
    qmdb::{
        self,
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
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
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
    GetSpan {
        key: RawKey,
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
    committed_state: &mut HashMap<RawKey, RawValue>,
    pending_inserts: &mut HashMap<RawKey, RawValue>,
    pending_deletes: &mut HashSet<RawKey>,
) -> GenericDb<F> {
    let mut batch = db.new_batch();
    for (k, v) in pending_writes.drain(..) {
        batch = batch.write(k, v);
    }
    let merkleized = batch.merkleize(&db, None).await.unwrap();
    let (db, _) = db
        .apply_batch(merkleized)
        .await
        .expect("commit should not fail");
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
            let mut committed_state: HashMap<RawKey, RawValue> = HashMap::new();
            let mut pending_inserts: HashMap<RawKey, RawValue> = HashMap::new();
            let mut pending_deletes: HashSet<RawKey> = HashSet::new();
            let mut all_keys: HashSet<RawKey> = HashSet::new();
            let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();

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
                        let _ = db.bounds().end;
                        db
                    }

                    QmdbOperation::Commit => {
                        commit_pending(
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes,
                        ).await
                    }

                    QmdbOperation::Root => {
                        let db = commit_pending(
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes,
                        ).await;
                        db.root();
                        db
                    }

                    QmdbOperation::Proof { start_loc, max_ops } => {
                        let db = commit_pending(
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes,
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

                            let hasher = qmdb::hasher::<Sha256>();
                            let elements = log.iter().map(|op| op.encode()).collect::<Vec<_>>();
                            let pinned_nodes = proof.digests.as_slice();
                            assert_eq!(
                                verify_proof_and_pinned_nodes::<Sha256, _, _>(
                                    &proof,
                                    adjusted_start,
                                    &log,
                                    pinned_nodes,
                                    &current_root,
                                ),
                                proof.verify_proof_and_pinned_nodes(
                                    &hasher,
                                    &elements,
                                    adjusted_start,
                                    pinned_nodes,
                                    &current_root,
                                ),
                                "Pinned proof wrapper disagreed with the Merkle verifier",
                            );

                            let extracted = verify_proof_and_extract_digests::<Sha256, _, _>(
                                &proof,
                                adjusted_start,
                                &log,
                                &current_root,
                            )
                            .expect("Verified proof should yield authenticated digests");
                            assert_eq!(
                                extracted,
                                proof
                                    .verify_range_inclusion_and_extract_digests(
                                        &hasher,
                                        &elements,
                                        adjusted_start,
                                        &current_root,
                                    )
                                    .expect("Verified Merkle proof should yield authenticated digests"),
                                "Extracted proof digests differed from the Merkle verifier",
                            );

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

                            let multi_proof =
                                create_multi_proof(&proof_store, &locations, &extracted);
                            let expected_multi_proof =
                                proof_store.multi_proof(&locations, &extracted);
                            assert_eq!(
                                multi_proof.as_ref().ok(),
                                expected_multi_proof.as_ref().ok(),
                                "Multi-proof wrapper disagreed with the proof store",
                            );
                            assert_eq!(
                                multi_proof
                                    .as_ref()
                                    .err()
                                    .map(core::mem::discriminant),
                                expected_multi_proof
                                    .as_ref()
                                    .err()
                                    .map(core::mem::discriminant),
                                "Multi-proof wrapper returned a different error",
                            );

                            if let Ok(multi_proof) = multi_proof {
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
                        }
                        db
                    }

                    QmdbOperation::ArbitraryProof { start_loc, max_ops , proof_leaves, digests} => {
                        let db = commit_pending(
                            db, &mut pending_writes, &mut committed_state,
                            &mut pending_inserts, &mut pending_deletes,
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

                            if let Ok(res) = db
                                .proof(adjusted_start, *max_ops)
                                .await {
                                let elements =
                                    res.1.iter().map(|op| op.encode()).collect::<Vec<_>>();
                                assert_eq!(
                                    verify_proof::<Sha256, _, _>(
                                        &proof,
                                        adjusted_start,
                                        &res.1,
                                        &current_root,
                                    ),
                                    proof.verify_range_inclusion(
                                        &qmdb::hasher::<Sha256>(),
                                        &elements,
                                        adjusted_start,
                                        &current_root,
                                    ),
                                    "Proof wrapper disagreed with the Merkle verifier",
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

                    QmdbOperation::GetSpan { key } => {
                        let k = Key::new(*key);
                        let result = db.get_span(&k).await.expect("get should not fail");
                        assert_eq!(result.is_some(), !db.is_empty(), "span should be empty only if db is empty");
                        db
                    }
                };
            }

            // Final commit to ensure all operations are persisted.
            if !pending_writes.is_empty() {
                db = commit_pending(
                    db, &mut pending_writes, &mut committed_state,
                    &mut pending_inserts, &mut pending_deletes,
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
