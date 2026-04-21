#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::RangeCfg;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Supervisor};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{hasher::Standard, mmb, mmr, Family as MerkleFamily, Location},
    mmr::journaled::Config as MerkleConfig,
    qmdb::{
        immutable::{variable::Db as Immutable, Config},
        verify_proof,
    },
    translator::TwoCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
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
    Commit {
        has_metadata: bool,
        metadata_size: usize,
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
    seed: u64,
    operations: Vec<ImmutableOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }

        Ok(FuzzInput { seed, operations })
    }
}

fn generate_key(rng: &mut StdRng, seed: u64) -> Digest {
    let mut data = vec![0u8; rng.gen_range(1..=MAX_KEY_SIZE)];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = ((seed >> (i % 8)) & 0xFF) as u8 ^ rng.gen::<u8>();
    }
    Sha256::hash(&data)
}

fn generate_value(rng: &mut StdRng, size: usize) -> Vec<u8> {
    let actual_size = size.clamp(1, MAX_VALUE_SIZE);
    (0..actual_size).map(|_| rng.gen()).collect()
}

#[allow(clippy::type_complexity)]
fn db_config(
    suffix: &str,
    page_cache: CacheRef,
) -> Config<TwoCap, VConfig<((), (RangeCfg<usize>, ()))>> {
    Config {
        merkle_config: MerkleConfig {
            journal_partition: format!("journal-{suffix}"),
            metadata_partition: format!("metadata-{suffix}"),
            items_per_blob: NZU64!(ITEMS_PER_BLOB),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
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
    let runner = deterministic::Runner::seeded(input.seed);

    runner.start(|context| {
        let operations = input.operations.clone();
        async move {
            let mut rng = StdRng::seed_from_u64(input.seed);

            let page_cache =
                CacheRef::from_pooler(context.child("cache"), PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
            let cfg = db_config(suffix, page_cache);
            let mut db =
                Immutable::<F, _, Digest, Vec<u8>, Sha256, TwoCap>::init(context.child("db"), cfg)
                    .await
                    .unwrap();

            let hasher = Standard::<Sha256>::new();
            let mut keys_set: Vec<(Digest, Location<F>)> = Vec::new();
            let mut set_locations: Vec<(Digest, Location<F>)> = Vec::new();
            let mut last_commit_loc: Option<Location<F>> = None;
            let mut pending_sets: Vec<(Digest, Vec<u8>)> = Vec::new();

            for op in operations {
                match op {
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
                    }

                    ImmutableOperation::Get { key_seed } => {
                        let key = generate_key(&mut rng, key_seed);
                        let _ = db.get(&key).await;
                    }

                    ImmutableOperation::Commit {
                        has_metadata,
                        metadata_size,
                    } => {
                        let metadata = if has_metadata {
                            Some(generate_value(&mut rng, metadata_size))
                        } else {
                            None
                        };

                        assign_pending_locations(
                            &pending_sets,
                            db.bounds().await.end,
                            &mut keys_set,
                            &mut set_locations,
                        );
                        let mut batch = db.new_batch();
                        for (k, v) in pending_sets.drain(..) {
                            batch = batch.set(k, v);
                        }
                        let merkleized = batch.merkleize(&db, metadata);
                        db.apply_batch(merkleized).await.unwrap();
                        db.commit().await.unwrap();
                        last_commit_loc = Some(db.bounds().await.end - 1);
                    }

                    ImmutableOperation::Prune { loc } => {
                        if let Some(commit_loc) = last_commit_loc {
                            let safe_loc = loc % (commit_loc + 1).as_u64();
                            let safe_loc = Location::new(safe_loc);
                            assign_pending_locations(
                                &pending_sets,
                                db.bounds().await.end,
                                &mut keys_set,
                                &mut set_locations,
                            );
                            let mut batch = db.new_batch();
                            for (k, v) in pending_sets.drain(..) {
                                batch = batch.set(k, v);
                            }
                            let merkleized = batch.merkleize(&db, None);
                            db.apply_batch(merkleized).await.unwrap();
                            db.commit().await.unwrap();
                            last_commit_loc = Some(db.bounds().await.end - 1);
                            db.prune(safe_loc).await.expect("prune should not fail");
                            let oldest = db.bounds().await.start;
                            set_locations.retain(|(_, l)| *l >= oldest);
                            keys_set.retain(|(_, l)| *l >= oldest);
                        }
                    }

                    ImmutableOperation::Proof {
                        start_index,
                        max_ops,
                    } => {
                        let op_count = db.bounds().await.end;
                        if op_count > 0 {
                            let safe_start = start_index % op_count.as_u64();
                            let safe_start = Location::new(safe_start);
                            let safe_max_ops =
                                NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();
                            assign_pending_locations(
                                &pending_sets,
                                db.bounds().await.end,
                                &mut keys_set,
                                &mut set_locations,
                            );
                            let mut batch = db.new_batch();
                            for (k, v) in pending_sets.drain(..) {
                                batch = batch.set(k, v);
                            }
                            let merkleized = batch.merkleize(&db, None);
                            db.apply_batch(merkleized).await.unwrap();
                            db.commit().await.unwrap();
                            last_commit_loc = Some(db.bounds().await.end - 1);
                            if let Ok((proof, ops)) = db.proof(safe_start, safe_max_ops).await {
                                let root = db.root();
                                let _ = verify_proof(&hasher, &proof, safe_start, &ops, &root);
                            }
                        }
                    }

                    ImmutableOperation::HistoricalProof {
                        size,
                        start_loc,
                        max_ops,
                    } => {
                        let op_count = db.bounds().await.end;
                        if op_count > 0 && pending_sets.is_empty() {
                            let safe_size = (size % op_count.as_u64()).max(1);
                            let safe_size = Location::new(safe_size);
                            let safe_start = start_loc % safe_size.as_u64();
                            let safe_start = Location::new(safe_start);
                            let safe_max_ops =
                                NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();

                            let batch = db.new_batch().merkleize(&db, None);
                            db.apply_batch(batch).await.unwrap();
                            db.commit().await.unwrap();
                            last_commit_loc = Some(db.bounds().await.end - 1);
                            if safe_start >= db.bounds().await.start {
                                let _ = db
                                    .historical_proof(safe_size, safe_start, safe_max_ops)
                                    .await;
                            }
                        }
                    }

                    ImmutableOperation::GetMetadata => {
                        let _ = db.get_metadata().await;
                    }

                    ImmutableOperation::OpCount => {
                        let _ = db.bounds().await.end;
                    }

                    ImmutableOperation::OldestRetainedLoc => {
                        let _ = db.bounds().await.start;
                    }

                    ImmutableOperation::Root => {
                        assign_pending_locations(
                            &pending_sets,
                            db.bounds().await.end,
                            &mut keys_set,
                            &mut set_locations,
                        );
                        let mut batch = db.new_batch();
                        for (k, v) in pending_sets.drain(..) {
                            batch = batch.set(k, v);
                        }
                        let merkleized = batch.merkleize(&db, None);
                        db.apply_batch(merkleized).await.unwrap();
                        db.commit().await.unwrap();
                        last_commit_loc = Some(db.bounds().await.end - 1);
                        let _ = db.root();
                    }
                }
            }

            assign_pending_locations(
                &pending_sets,
                db.bounds().await.end,
                &mut keys_set,
                &mut set_locations,
            );
            let mut batch = db.new_batch();
            for (k, v) in pending_sets.drain(..) {
                batch = batch.set(k, v);
            }
            let merkleized = batch.merkleize(&db, None);
            db.apply_batch(merkleized).await.unwrap();
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
