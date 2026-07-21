#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{BufferPooler, Runner, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{Family as MerkleFamily, Location, mmb, mmr},
    mmr::full::Config as MerkleConfig,
    qmdb::{
        immutable::{Config, fixed::Db as Immutable},
        verify_proof,
    },
    translator::TwoCap,
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use rand::RngExt as _;
use rand_core::CryptoRng;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
};

const MAX_OPERATIONS: usize = 50;
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
    OldestRetainedLoc,
    Root,
}

#[derive(Debug)]
struct FuzzInput {
    operations: Vec<ImmutableOperation>,
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }

        Ok(FuzzInput {
            operations,
            raw_bytes,
        })
    }
}

fn generate_key(seed: u64) -> Digest {
    Sha256::hash(&seed.to_be_bytes())
}

fn generate_value(rng: &mut impl CryptoRng, size: usize) -> Digest {
    let actual_size = size.clamp(1, MAX_VALUE_SIZE);
    let bytes = (0..actual_size).map(|_| rng.random()).collect::<Vec<u8>>();
    Sha256::hash(&bytes)
}

#[allow(clippy::type_complexity)]
fn db_config(suffix: &str, pooler: &impl BufferPooler) -> Config<TwoCap, FConfig, Sequential> {
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
        log: FConfig {
            partition: format!("log-{suffix}"),
            items_per_blob: NZU64!(ITEMS_PER_SECTION),
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
    pending: &[(Digest, Digest)],
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
            let mut rng = FuzzRng::new(input.raw_bytes.clone());

            let cfg = db_config(suffix, &context);
            let mut db =
                Immutable::<F, _, Digest, Digest, Sha256, TwoCap, Sequential>::init(context, cfg)
                    .await
                    .unwrap();

            let mut keys_set: Vec<(Digest, Location<F>)> = Vec::new();
            let mut set_locations: Vec<(Digest, Location<F>)> = Vec::new();
            let mut pending_sets: Vec<(Digest, Digest)> = Vec::new();
            let mut committed_values = BTreeMap::<Digest, (Digest, Location<F>)>::new();
            let mut expected_metadata = None;
            let mut expected_root = db.root();
            let mut expected_size = db.bounds().end;
            let mut commits = vec![(expected_size, expected_root)];

            for op in operations {
                db = match op {
                    ImmutableOperation::Set {
                        key_seed,
                        value_size,
                    } => {
                        let key = generate_key(key_seed);
                        let value = generate_value(&mut rng, value_size);

                        if !keys_set.iter().any(|(k, _)| k == &key)
                            && !pending_sets.iter().any(|(k, _)| k == &key)
                        {
                            pending_sets.push((key, value));
                        }
                        db
                    }

                    ImmutableOperation::Get { key_seed } => {
                        let key = generate_key(key_seed);
                        let actual = db.get(&key).await.expect("get should not fail");
                        let expected = committed_values
                            .get(&key)
                            .filter(|(_, loc)| *loc >= db.bounds().start)
                            .map(|(value, _)| *value);
                        assert_eq!(actual, expected);
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
                        let mut committed = pending_sets.clone();
                        committed.sort_by_key(|(key, _)| *key);
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
                        let merkleized = batch.merkleize(&db, metadata, floor).await;
                        let expected_batch_root = merkleized.root();
                        let (db, range) = db.apply_batch(merkleized).await.unwrap();
                        assert_eq!(range.start, end);
                        assert_eq!(range.end, db.bounds().end);
                        assert_eq!(db.root(), expected_batch_root);
                        let db = db.commit().await.unwrap();
                        for ((key, value), (_, loc)) in committed.into_iter().zip(
                            set_locations[set_locations.len() - pending_count as usize..]
                                .iter()
                                .copied(),
                        ) {
                            committed_values.insert(key, (value, loc));
                        }
                        expected_metadata = metadata;
                        expected_root = expected_batch_root;
                        expected_size = db.bounds().end;
                        commits.push((expected_size, expected_root));
                        db
                    }

                    ImmutableOperation::Prune { loc } => {
                        let bounds = db.bounds();
                        let floor = db.inactivity_floor_loc();
                        let width = floor.as_u64().saturating_sub(bounds.start.as_u64()) + 1;
                        let safe_loc = Location::new(bounds.start.as_u64() + loc % width);
                        let root = db.root();
                        let db = db.prune(safe_loc).await.expect("prune should not fail");
                        assert_eq!(db.root(), root);
                        assert_eq!(db.bounds().end, expected_size);
                        committed_values
                            .retain(|_, (_, value_loc)| *value_loc >= db.bounds().start);
                        set_locations.retain(|(_, value_loc)| *value_loc >= db.bounds().start);
                        keys_set.retain(|(_, value_loc)| *value_loc >= db.bounds().start);
                        db
                    }

                    ImmutableOperation::Proof {
                        start_index,
                        max_ops,
                    } => {
                        let bounds = db.bounds();
                        if bounds.start < bounds.end {
                            let safe_start = Location::new(
                                bounds.start.as_u64()
                                    + start_index % (bounds.end - bounds.start).as_u64(),
                            );
                            let safe_max_ops =
                                NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();
                            let (proof, ops) = db
                                .proof(safe_start, safe_max_ops)
                                .await
                                .expect("proof should not fail for a retained location");
                            assert!(verify_proof::<Sha256, _, _>(
                                &proof,
                                safe_start,
                                &ops,
                                &expected_root,
                            ));
                        }
                        db
                    }

                    ImmutableOperation::HistoricalProof {
                        size,
                        start_loc,
                        max_ops,
                    } => {
                        let retained = commits
                            .iter()
                            .filter(|(commit_size, _)| *commit_size > db.bounds().start)
                            .copied()
                            .collect::<Vec<_>>();
                        if !retained.is_empty() {
                            let (safe_size, historical_root) =
                                retained[size as usize % retained.len()];
                            let safe_start = Location::new(
                                db.bounds().start.as_u64()
                                    + start_loc % (safe_size - db.bounds().start).as_u64(),
                            );
                            let safe_max_ops =
                                NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();
                            let (proof, ops) = db
                                .historical_proof(safe_size, safe_start, safe_max_ops)
                                .await
                                .expect("historical proof should not fail at a retained commit");
                            assert!(verify_proof::<Sha256, _, _>(
                                &proof,
                                safe_start,
                                &ops,
                                &historical_root,
                            ));
                        }
                        db
                    }

                    ImmutableOperation::GetMetadata => {
                        assert_eq!(
                            db.get_metadata()
                                .await
                                .expect("metadata read should not fail"),
                            expected_metadata
                        );
                        db
                    }

                    ImmutableOperation::OpCount => {
                        assert_eq!(db.bounds().end, expected_size);
                        db
                    }

                    ImmutableOperation::OldestRetainedLoc => {
                        assert!(db.bounds().start <= db.inactivity_floor_loc());
                        db
                    }

                    ImmutableOperation::Root => {
                        assert_eq!(db.root(), expected_root);
                        db
                    }
                };
            }

            db.destroy().await.unwrap();
        }
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input, "fuzz-fixed-mmr");
    fuzz_family::<mmb::Family>(&input, "fuzz-fixed-mmb");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
