#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::RangeCfg;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    mmr::Location,
    qmdb::{
        immutable::{Config, Immutable},
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

fn db_config(suffix: &str) -> Config<TwoCap, (RangeCfg<usize>, ())> {
    Config {
        mmr_journal_partition: format!("journal_{suffix}"),
        mmr_metadata_partition: format!("metadata_{suffix}"),
        mmr_items_per_blob: NZU64!(ITEMS_PER_BLOB),
        mmr_write_buffer: NZUsize!(1024),
        log_partition: format!("log_{suffix}"),
        log_items_per_section: NZU64!(ITEMS_PER_SECTION),
        log_compression: None,
        log_codec_config: ((0..=10000).into(), ()),
        log_write_buffer: NZUsize!(1024),
        translator: TwoCap,
        thread_pool: None,
        page_cache: CacheRef::new(PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::seeded(input.seed);

    runner.start(|context| async move {
        let mut rng = StdRng::seed_from_u64(input.seed);

        let mut db = Immutable::<_, Digest, Vec<u8>, Sha256, TwoCap>::init(
            context.clone(),
            db_config("fuzz_partition"),
        )
        .await
        .unwrap()
        .into_mutable();

        let mut hasher = commonware_storage::mmr::StandardHasher::<Sha256>::new();
        let mut keys_set = Vec::new();
        let mut set_locations = Vec::new(); // Track locations that contain Set operations
        let mut last_commit_loc = None;
        let mut uncommitted_ops = Vec::new();

        for op in input.operations {
            match op {
                ImmutableOperation::Set {
                    key_seed,
                    value_size,
                } => {
                    let key = generate_key(&mut rng, key_seed);
                    let value = generate_value(&mut rng, value_size);

                    if !keys_set.iter().any(|(k, _)| k == &key) {
                        let loc = db.op_count();
                        if let Ok(()) = db.set(key, value.clone()).await {
                            keys_set.push((key, loc));
                            set_locations.push((key, loc));
                            uncommitted_ops.push((key, loc));
                        }
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

                    let (durable_db, _) = db.commit(metadata).await.unwrap();
                    last_commit_loc = Some(durable_db.op_count() - 1);
                    uncommitted_ops.clear();
                    db = durable_db.into_mutable();
                }

                ImmutableOperation::Prune { loc } => {
                    if let Some(commit_loc) = last_commit_loc {
                        let safe_loc = loc % (commit_loc + 1).as_u64();
                        let safe_loc = Location::new(safe_loc).unwrap();
                        let mut merkleized_db = db.into_merkleized();
                        merkleized_db
                            .prune(safe_loc)
                            .await
                            .expect("prune should not fail");
                        let oldest = merkleized_db.oldest_retained_loc();
                        set_locations.retain(|(_, l)| *l >= oldest);
                        keys_set.retain(|(_, l)| *l >= oldest);
                        db = merkleized_db.into_mutable();
                    }
                }

                ImmutableOperation::Proof {
                    start_index,
                    max_ops,
                } => {
                    let op_count = db.op_count();
                    if op_count > 0 && uncommitted_ops.is_empty() {
                        let safe_start = start_index % op_count.as_u64();
                        let safe_start = Location::new(safe_start).unwrap();
                        let safe_max_ops =
                            NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();
                        let merkleized_db = db.into_merkleized();
                        if let Ok((proof, ops)) =
                            merkleized_db.proof(safe_start, safe_max_ops).await
                        {
                            let root = merkleized_db.root();
                            let _ = verify_proof(&mut hasher, &proof, safe_start, &ops, &root);
                        }
                        db = merkleized_db.into_mutable();
                    }
                }

                ImmutableOperation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                } => {
                    let op_count = db.op_count();
                    if op_count > 0 && uncommitted_ops.is_empty() {
                        let safe_size = (size % op_count.as_u64()).max(1);
                        let safe_size = Location::new(safe_size).unwrap();
                        let safe_start = start_loc % safe_size.as_u64();
                        let safe_start = Location::new(safe_start).unwrap();
                        let safe_max_ops =
                            NonZeroU64::new((max_ops % MAX_PROOF_OPS).max(1)).unwrap();

                        let merkleized_db = db.into_merkleized();
                        if safe_start >= merkleized_db.oldest_retained_loc() {
                            let _ = merkleized_db
                                .historical_proof(safe_size, safe_start, safe_max_ops)
                                .await;
                        }
                        db = merkleized_db.into_mutable();
                    }
                }

                ImmutableOperation::GetMetadata => {
                    let _ = db.get_metadata().await;
                }

                ImmutableOperation::OpCount => {
                    let _ = db.op_count();
                }

                ImmutableOperation::OldestRetainedLoc => {
                    let _ = db.oldest_retained_loc();
                }

                ImmutableOperation::Root => {
                    let clean_db = db.into_merkleized();
                    let _ = clean_db.root();
                    db = clean_db.into_mutable();
                }
            }
        }

        let (durable_db, _) = db.commit(None).await.unwrap();
        let clean_db = durable_db.into_merkleized();
        clean_db.destroy().await.unwrap();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
