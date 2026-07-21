#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::RangeCfg;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::{Sequential, Strategy as _};
use commonware_runtime::{BufferPooler, Runner, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{Family as MerkleFamily, Location, mmb, mmr},
    mmr::full::Config as MerkleConfig,
    qmdb::{
        immutable::{Config, variable::Db as Immutable},
        verify_proof,
    },
    translator::TwoCap,
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize, TestRng};
use libfuzzer_sys::fuzz_target;
use rand::RngExt as _;
use rand_core::CryptoRng;
use std::num::{NonZeroU16, NonZeroU64};

const MAX_OPERATIONS: usize = 50;
const MAX_KEY_SIZE: usize = 32;
const MAX_VALUE_SIZE: usize = 256;
const MAX_PROOF_OPS: u64 = 100;
const PAGE_SIZE: NonZeroU16 = NZU16!(77);
const PAGE_CACHE_SIZE: usize = 9;
const ITEMS_PER_SECTION: u64 = 5;
const ITEMS_PER_BLOB: u64 = 11;

#[derive(Arbitrary, Debug, Clone)]
enum ImmutableOperation {
    Set {
        key_seed: u64,
        value_size: usize,
    },
    Get {
        key_seed: u64,
    },
    GetMany {
        first_key_seed: u64,
        second_key_seed: u64,
    },
    BatchReads {
        first_key_seed: u64,
        second_key_seed: u64,
    },
    Commit {
        has_metadata: bool,
        metadata_size: usize,
        advance_floor: bool,
    },
    Prune {
        loc: u64,
    },
    Proof {
        start_index: u64,
        max_ops: u64,
    },
    HistoricalProof {
        size: u64,
        start_loc: u64,
        max_ops: u64,
    },
    GetMetadata,
    OpCount,
    Size,
    OldestRetainedLoc,
    SyncBoundary,
    Sync,
    Rewind {
        idx: u8,
    },
    ValidateBatch,
    ToBatch,
    Root,
    Strategy {
        values: [u8; 4],
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<ImmutableOperation>,
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let seed = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }

        Ok(FuzzInput {
            seed,
            operations,
            raw_bytes,
        })
    }
}

fn generate_key(rng: &mut impl CryptoRng, seed: u64) -> Digest {
    let mut data = vec![0u8; rng.random_range(1..=MAX_KEY_SIZE)];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = ((seed >> (i % 8)) & 0xFF) as u8 ^ rng.random::<u8>();
    }
    Sha256::hash(&data)
}

fn generate_value(rng: &mut impl CryptoRng, size: usize) -> Vec<u8> {
    let actual_size = size.clamp(1, MAX_VALUE_SIZE);
    (0..actual_size).map(|_| rng.random()).collect()
}

#[allow(clippy::type_complexity)]
fn db_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> Config<TwoCap, VConfig<((), (RangeCfg<usize>, ()))>, Sequential> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
    Config {
        merkle_config: MerkleConfig {
            journal_partition: format!("journal-{suffix}"),
            metadata_partition: format!("metadata-{suffix}"),
            items_per_blob: NZU64!(ITEMS_PER_BLOB),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        log: VConfig {
            partition: format!("log-{suffix}"),
            items_per_section: NZU64!(ITEMS_PER_SECTION),
            compression: None,
            codec_config: ((), ((0..=10000).into(), ())),
            write_buffer: NZUsize!(1024),
            page_cache,
        },
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(3)),
        init_buffer: NZUsize!(1 << 21),
    }
}

/// Assign locations to pending keys based on sorted order (matching BTreeMap
/// iteration in `merkleize()`).
fn assign_pending_locations<F: MerkleFamily>(
    pending: &[(Digest, Vec<u8>)],
    base: Location<F>,
    keys_set: &mut Vec<(Digest, Location<F>)>,
    set_locations: &mut Vec<(Digest, Location<F>)>,
) {
    let mut sorted_keys: Vec<Digest> = pending.iter().map(|(k, _)| *k).collect();
    sorted_keys.sort();
    for (i, key) in sorted_keys.iter().enumerate() {
        let loc = Location::new(base.as_u64() + i as u64);
        keys_set.push((*key, loc));
        set_locations.push((*key, loc));
    }
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput, suffix: &str) {
    let cfg =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| {
        let operations = input.operations.clone();
        async move {
            let mut rng = TestRng::new(input.seed);

            let cfg = db_config(suffix, &context);
            let mut db =
                Immutable::<F, _, Digest, Vec<u8>, Sha256, TwoCap, Sequential>::init(context, cfg)
                    .await
                    .unwrap();

            let mut keys_set: Vec<(Digest, Location<F>)> = Vec::new();
            let mut set_locations: Vec<(Digest, Location<F>)> = Vec::new();
            let mut last_commit_loc: Option<Location<F>> = None;
            let mut pending_sets: Vec<(Digest, Vec<u8>)> = Vec::new();
            let mut expected_metadata = db.get_metadata().await.unwrap();
            let mut commit_history = vec![(
                db.size(),
                db.root(),
                db.inactivity_floor_loc(),
                db.get_metadata().await.unwrap(),
            )];

            for op in operations {
                db = match op {
                    ImmutableOperation::Set {
                        key_seed,
                        value_size,
                    } => {
                        let key = generate_key(&mut rng, key_seed);
                        let value = generate_value(&mut rng, value_size);

                        if !keys_set.iter().any(|(k, _)| k == &key)
                            && !pending_sets.iter().any(|(k, _)| k == &key)
                        {
                            pending_sets.push((key, value));
                        }
                        db
                    }

                    ImmutableOperation::Get { key_seed } => {
                        let key = generate_key(&mut rng, key_seed);
                        let actual = db.get(&key).await;
                        match actual {
                            Ok(value) => assert_eq!(
                                db.get_many(&[&key]).await.unwrap(),
                                vec![value],
                                "single and batched reads disagreed",
                            ),
                            Err(_) => assert!(db.get_many(&[&key]).await.is_err()),
                        }
                        db
                    }

                    ImmutableOperation::GetMany {
                        first_key_seed,
                        second_key_seed,
                    } => {
                        let first = generate_key(&mut rng, first_key_seed);
                        let second = generate_key(&mut rng, second_key_seed);
                        let expected = vec![
                            db.get(&first).await.unwrap(),
                            db.get(&second).await.unwrap(),
                        ];
                        assert_eq!(db.get_many(&[&first, &second]).await.unwrap(), expected);
                        db
                    }

                    ImmutableOperation::BatchReads {
                        first_key_seed,
                        second_key_seed,
                    } => {
                        let first = generate_key(&mut rng, first_key_seed);
                        let second = generate_key(&mut rng, second_key_seed);
                        let mut batch = db.new_batch();
                        for (key, value) in &pending_sets {
                            batch = batch.set(*key, value.clone());
                        }
                        let expected = vec![
                            batch.get(&first, &db).await.unwrap(),
                            batch.get(&second, &db).await.unwrap(),
                        ];
                        assert_eq!(
                            batch.get_many(&[&first, &second], &db).await.unwrap(),
                            expected
                        );
                        let merkleized =
                            batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
                        assert_eq!(
                            merkleized.get_many(&[&first, &second], &db).await.unwrap(),
                            vec![
                                merkleized.get(&first, &db).await.unwrap(),
                                merkleized.get(&second, &db).await.unwrap(),
                            ]
                        );
                        assert_eq!(
                            merkleized.bounds().total_size,
                            db.size().as_u64() + pending_sets.len() as u64 + 1
                        );
                        db
                    }

                    ImmutableOperation::Commit {
                        has_metadata,
                        metadata_size,
                        advance_floor,
                    } => {
                        let metadata = if has_metadata {
                            Some(generate_value(&mut rng, metadata_size))
                        } else {
                            None
                        };

                        let end = db.bounds().end;
                        let pending_count = pending_sets.len() as u64;
                        assign_pending_locations(
                            &pending_sets,
                            end,
                            &mut keys_set,
                            &mut set_locations,
                        );
                        let mut batch = db.new_batch();
                        for (k, v) in pending_sets.drain(..) {
                            batch = batch.set(k, v);
                        }
                        let floor = if advance_floor {
                            // Advance floor to the commit location (end of this batch).
                            // total_size = end + pending_count + 1 (commit op).
                            // Floor at the commit op is the maximum valid value.
                            Location::new(*end + pending_count)
                        } else {
                            db.inactivity_floor_loc()
                        };
                        let expected_metadata_after = metadata.clone();
                        let merkleized = batch.merkleize(&db, metadata, floor).await;
                        let expected_root = merkleized.root();
                        let expected_size = Location::new(merkleized.bounds().total_size);
                        let (db, _) = db.apply_batch(merkleized).await.unwrap();
                        let db = db.commit().await.unwrap();
                        assert_eq!(db.size(), expected_size);
                        assert_eq!(db.root(), expected_root);
                        assert_eq!(db.inactivity_floor_loc(), floor);
                        assert_eq!(db.get_metadata().await.unwrap(), expected_metadata_after);
                        expected_metadata = expected_metadata_after;
                        last_commit_loc = Some(db.bounds().end - 1);
                        commit_history.push((
                            db.size(),
                            db.root(),
                            db.inactivity_floor_loc(),
                            db.get_metadata().await.unwrap(),
                        ));
                        db
                    }

                    ImmutableOperation::Prune { loc } => {
                        if let Some(commit_loc) = last_commit_loc {
                            let safe_loc = loc % (commit_loc + 1).as_u64();
                            let safe_loc = Location::new(safe_loc);
                            assign_pending_locations(
                                &pending_sets,
                                db.bounds().end,
                                &mut keys_set,
                                &mut set_locations,
                            );
                            let mut batch = db.new_batch();
                            for (k, v) in pending_sets.drain(..) {
                                batch = batch.set(k, v);
                            }
                            // Set the floor to at least safe_loc so the prune succeeds,
                            // but never below the current floor (monotonicity).
                            let floor = safe_loc.max(db.inactivity_floor_loc());
                            let merkleized = batch.merkleize(&db, None, floor).await;
                            let expected_root = merkleized.root();
                            let (db, _) = db.apply_batch(merkleized).await.unwrap();
                            let db = db.commit().await.unwrap();
                            expected_metadata = None;
                            last_commit_loc = Some(db.bounds().end - 1);
                            commit_history.push((
                                db.size(),
                                db.root(),
                                db.inactivity_floor_loc(),
                                db.get_metadata().await.unwrap(),
                            ));
                            let size = db.size();
                            let db = db.prune(safe_loc).await.expect("prune should not fail");
                            assert_eq!(db.size(), size);
                            assert_eq!(db.root(), expected_root);
                            let oldest = db.bounds().start;
                            set_locations.retain(|(_, l)| *l >= oldest);
                            keys_set.retain(|(_, l)| *l >= oldest);
                            db
                        } else {
                            db
                        }
                    }

                    ImmutableOperation::Proof {
                        start_index,
                        max_ops,
                    } => {
                        let op_count = db.bounds().end;
                        if op_count > 0 {
                            let safe_start = start_index % op_count.as_u64();
                            let safe_start = Location::new(safe_start);
                            let safe_max_ops =
                                NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();
                            assign_pending_locations(
                                &pending_sets,
                                db.bounds().end,
                                &mut keys_set,
                                &mut set_locations,
                            );
                            let mut batch = db.new_batch();
                            for (k, v) in pending_sets.drain(..) {
                                batch = batch.set(k, v);
                            }
                            let floor = db.inactivity_floor_loc();
                            let merkleized = batch.merkleize(&db, None, floor).await;
                            let (db, _) = db.apply_batch(merkleized).await.unwrap();
                            let db = db.commit().await.unwrap();
                            expected_metadata = None;
                            last_commit_loc = Some(db.bounds().end - 1);
                            commit_history.push((
                                db.size(),
                                db.root(),
                                db.inactivity_floor_loc(),
                                db.get_metadata().await.unwrap(),
                            ));
                            if let Ok((proof, ops)) = db.proof(safe_start, safe_max_ops).await {
                                let root = db.root();
                                assert!(verify_proof::<Sha256, _, _>(
                                    &proof, safe_start, &ops, &root
                                ));
                                let pinned = db.pinned_nodes_at(safe_start).await.unwrap();
                                assert!(commonware_storage::qmdb::verify_proof_and_pinned_nodes::<
                                    Sha256,
                                    _,
                                    _,
                                >(
                                    &proof, safe_start, &ops, &pinned, &root,
                                ));
                                for op in &ops {
                                    assert_eq!(op.key().is_some(), !op.is_commit());
                                    assert_eq!(op.has_floor().is_some(), op.is_commit());
                                }
                            }
                            db
                        } else {
                            db
                        }
                    }

                    ImmutableOperation::HistoricalProof {
                        size,
                        start_loc,
                        max_ops,
                    } => {
                        let bounds = db.bounds();
                        let candidates = commit_history
                            .iter()
                            .filter(|(candidate_size, _, floor, _)| {
                                *candidate_size > bounds.start && *floor >= bounds.start
                            })
                            .collect::<Vec<_>>();
                        if !candidates.is_empty() && pending_sets.is_empty() {
                            let expected = candidates[size as usize % candidates.len()];
                            let safe_size = expected.0;
                            let retained = (safe_size - bounds.start).as_u64();
                            let safe_start = bounds.start + (start_loc % retained);
                            let safe_max_ops =
                                NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();
                            let (proof, ops) = db
                                .historical_proof(safe_size, safe_start, safe_max_ops)
                                .await
                                .expect("retained commit should produce a historical proof");
                            assert!(verify_proof::<Sha256, _, _>(
                                &proof,
                                safe_start,
                                &ops,
                                &expected.1,
                            ));
                            db
                        } else {
                            db
                        }
                    }

                    ImmutableOperation::GetMetadata => {
                        assert_eq!(db.get_metadata().await.unwrap(), expected_metadata);
                        db
                    }

                    ImmutableOperation::OpCount => {
                        assert_eq!(db.bounds().end, db.size());
                        db
                    }

                    ImmutableOperation::Size => {
                        assert_eq!(db.size(), db.bounds().end);
                        db
                    }

                    ImmutableOperation::OldestRetainedLoc => {
                        assert!(db.bounds().start <= db.inactivity_floor_loc());
                        assert!(db.bounds().start <= db.size());
                        db
                    }

                    ImmutableOperation::SyncBoundary => {
                        assert_eq!(db.sync_boundary(), db.inactivity_floor_loc());
                        db
                    }

                    ImmutableOperation::Sync => {
                        let expected = (
                            db.size(),
                            db.root(),
                            db.inactivity_floor_loc(),
                            db.get_metadata().await.unwrap(),
                        );
                        let db = db.sync().await.unwrap();
                        assert_eq!(
                            (
                                db.size(),
                                db.root(),
                                db.inactivity_floor_loc(),
                                db.get_metadata().await.unwrap(),
                            ),
                            expected
                        );
                        db
                    }

                    ImmutableOperation::Rewind { idx } => {
                        let bounds = db.bounds();
                        let candidates = commit_history
                            .iter()
                            .filter(|(size, _, floor, _)| {
                                *size > bounds.start && *floor >= bounds.start
                            })
                            .collect::<Vec<_>>();
                        if candidates.len() < 2 {
                            db
                        } else {
                            let expected = candidates[idx as usize % (candidates.len() - 1)];
                            let target = expected.0;
                            let db = db.rewind(target).await.unwrap();
                            assert_eq!(db.size(), expected.0);
                            assert_eq!(db.root(), expected.1);
                            assert_eq!(db.inactivity_floor_loc(), expected.2);
                            assert_eq!(db.get_metadata().await.unwrap(), expected.3);
                            expected_metadata = expected.3.clone();
                            commit_history.retain(|(size, _, _, _)| *size <= target);
                            keys_set.retain(|(_, loc)| *loc < target);
                            set_locations.retain(|(_, loc)| *loc < target);
                            last_commit_loc = Some(target - 1);
                            db
                        }
                    }

                    ImmutableOperation::ValidateBatch => {
                        let before = (db.size(), db.root(), db.inactivity_floor_loc());
                        let mut batch = db.new_batch();
                        for (key, value) in &pending_sets {
                            batch = batch.set(*key, value.clone());
                        }
                        let merkleized =
                            batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
                        assert!(db.validate_batch(&merkleized).is_ok());
                        assert_eq!((db.size(), db.root(), db.inactivity_floor_loc()), before);
                        db
                    }

                    ImmutableOperation::ToBatch => {
                        let batch = db.to_batch();
                        assert_eq!(batch.root(), db.root());
                        assert_eq!(batch.bounds().base_size, db.size().as_u64());
                        assert_eq!(batch.bounds().total_size, db.size().as_u64());
                        assert_eq!(batch.bounds().inactivity_floor, db.inactivity_floor_loc());
                        db
                    }

                    ImmutableOperation::Root => {
                        assign_pending_locations(
                            &pending_sets,
                            db.bounds().end,
                            &mut keys_set,
                            &mut set_locations,
                        );
                        let mut batch = db.new_batch();
                        for (k, v) in pending_sets.drain(..) {
                            batch = batch.set(k, v);
                        }
                        let floor = db.inactivity_floor_loc();
                        let merkleized = batch.merkleize(&db, None, floor).await;
                        let expected_root = merkleized.root();
                        let (db, _) = db.apply_batch(merkleized).await.unwrap();
                        let db = db.commit().await.unwrap();
                        expected_metadata = None;
                        last_commit_loc = Some(db.bounds().end - 1);
                        assert_eq!(db.root(), expected_root);
                        commit_history.push((
                            db.size(),
                            db.root(),
                            db.inactivity_floor_loc(),
                            db.get_metadata().await.unwrap(),
                        ));
                        db
                    }

                    ImmutableOperation::Strategy { values } => {
                        let expected = values.iter().map(|value| u64::from(*value)).sum::<u64>();
                        let actual = db.strategy().fold(
                            values,
                            || 0u64,
                            |sum, value| sum + u64::from(value),
                            |left, right| left + right,
                        );
                        assert_eq!(actual, expected, "database strategy produced a wrong fold");
                        db
                    }
                };
            }

            assign_pending_locations(
                &pending_sets,
                db.bounds().end,
                &mut keys_set,
                &mut set_locations,
            );
            let mut batch = db.new_batch();
            for (k, v) in pending_sets.drain(..) {
                batch = batch.set(k, v);
            }
            let floor = db.inactivity_floor_loc();
            let merkleized = batch.merkleize(&db, None, floor).await;
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            db.destroy().await.unwrap();
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
