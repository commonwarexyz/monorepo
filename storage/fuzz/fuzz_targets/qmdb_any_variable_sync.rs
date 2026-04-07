#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::Family as _,
    mmr::{self, journaled::Config as MmrConfig, Family, StandardHasher as Standard},
    qmdb::{
        any::{unordered::variable::Db, VariableConfig as Config},
        verify_proof,
    },
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use mmr::Location;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
};

const MAX_OPERATIONS: usize = 50;

type Key = FixedBytes<32>;

#[derive(Debug)]
enum Operation {
    Update {
        key: [u8; 32],
        value_bytes: Vec<u8>,
    },
    Delete {
        key: [u8; 32],
    },
    Commit {
        metadata_bytes: Option<Vec<u8>>,
    },
    Prune,
    Get {
        key: [u8; 32],
    },
    GetMetadata,
    Proof {
        start_loc: Location,
        max_ops: NonZeroU64,
    },
    HistoricalProof {
        size: u64,
        start_loc: Location,
        max_ops: NonZeroU64,
    },
    Sync,
    InactivityFloorLoc,
    OpCount,
    Root,
    SimulateFailure,
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 14 {
            0 => {
                let key = u.arbitrary()?;
                let value_len: u16 = u.arbitrary()?;
                let actual_len = ((value_len as usize) % 10000) + 1;
                let value_bytes = u.bytes(actual_len)?.to_vec();
                Ok(Operation::Update { key, value_bytes })
            }
            1 => {
                let key = u.arbitrary()?;
                Ok(Operation::Delete { key })
            }
            2 => {
                let has_metadata: bool = u.arbitrary()?;
                let metadata_bytes = if has_metadata {
                    let metadata_len: u16 = u.arbitrary()?;
                    let actual_len = ((metadata_len as usize) % 1000) + 1;
                    Some(u.bytes(actual_len)?.to_vec())
                } else {
                    None
                };
                Ok(Operation::Commit { metadata_bytes })
            }
            3 => Ok(Operation::Prune),
            4 => {
                let key = u.arbitrary()?;
                Ok(Operation::Get { key })
            }
            5 => Ok(Operation::GetMetadata),
            6 => {
                let start_loc = u.arbitrary::<u64>()? % (*Family::MAX_LEAVES + 1);
                let start_loc = Location::new(start_loc);
                let max_ops = u.int_in_range(1..=u32::MAX)? as u64;
                let max_ops = NZU64!(max_ops);
                Ok(Operation::Proof { start_loc, max_ops })
            }
            7 => {
                let size = u.arbitrary()?;
                let start_loc = u.arbitrary::<u64>()? % (*Family::MAX_LEAVES + 1);
                let start_loc = Location::new(start_loc);
                let max_ops = u.int_in_range(1..=u32::MAX)? as u64;
                let max_ops = NZU64!(max_ops);
                Ok(Operation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                })
            }
            8 => Ok(Operation::Sync),
            9 => Ok(Operation::InactivityFloorLoc),
            10 => Ok(Operation::OpCount),
            11 => Ok(Operation::Root),
            12 | 13 => Ok(Operation::SimulateFailure {}),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { ops })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(128);

fn test_config(
    test_name: &str,
    pooler: &impl BufferPooler,
) -> Config<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(1));
    Config {
        merkle_config: MmrConfig {
            journal_partition: format!("{test_name}-mmr"),
            metadata_partition: format!("{test_name}-meta"),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        journal_config: VConfig {
            partition: format!("{test_name}-log"),
            items_per_section: NZU64!(3),
            write_buffer: NZUsize!(1024),
            compression: None,
            codec_config: ((), ((0..=100000).into(), ())),
            page_cache,
        },
        translator: TwoCap,
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let hasher = Standard::<Sha256>::new();
        let cfg = test_config("qmdb-any-variable-fuzz-test", &context);
        let mut db = Db::<Family, _, Key, Vec<u8>, Sha256, TwoCap>::init(context.clone(), cfg)
            .await
            .expect("Failed to init source db");
        let mut restarts = 0usize;

        let mut historical_roots: BTreeMap<
            Location,
            <Sha256 as commonware_cryptography::Hasher>::Digest,
        > = BTreeMap::new();

        let mut pending_writes: Vec<(Key, Option<Vec<u8>>)> = Vec::new();

        for op in &input.ops {
            match op {
                Operation::Update { key, value_bytes } => {
                    pending_writes.push((Key::new(*key), Some(value_bytes.to_vec())));
                }

                Operation::Delete { key } => {
                    pending_writes.push((Key::new(*key), None));
                }

                Operation::Commit { metadata_bytes } => {
                    let mut batch = db.new_batch();
                    for (k, v) in pending_writes.drain(..) {
                        batch = batch.write(k, v);
                    }
                    let merkleized = batch.merkleize(&db, metadata_bytes.clone()).await.unwrap();
                    db.apply_batch(merkleized)
                        .await
                        .expect("commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    historical_roots.insert(db.bounds().await.end, db.root());
                }

                Operation::Prune => {
                    db.prune(db.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                }

                Operation::Get { key } => {
                    let _ = db.get(&Key::new(*key)).await;
                }

                Operation::GetMetadata => {
                    let _ = db.get_metadata().await;
                }

                Operation::Proof { start_loc, max_ops } => {
                    // proof requires commit
                    let mut batch = db.new_batch();
                    for (k, v) in pending_writes.drain(..) {
                        batch = batch.write(k, v);
                    }
                    let merkleized = batch.merkleize(&db, None).await.unwrap();
                    db.apply_batch(merkleized)
                        .await
                        .expect("commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    historical_roots.insert(db.bounds().await.end, db.root());
                    let op_count = db.bounds().await.end;
                    let oldest_retained_loc = db.inactivity_floor_loc();
                    if *start_loc >= oldest_retained_loc && *start_loc < *op_count {
                        if let Ok((proof, log)) = db.proof(*start_loc, *max_ops).await {
                            let root = db.root();
                            assert!(verify_proof(&hasher, &proof, *start_loc, &log, &root));
                        }
                    }
                }

                Operation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                } => {
                    // historical proof verification requires a root captured at a commit point.
                    let mut batch = db.new_batch();
                    for (k, v) in pending_writes.drain(..) {
                        batch = batch.write(k, v);
                    }
                    let merkleized = batch.merkleize(&db, None).await.unwrap();
                    db.apply_batch(merkleized)
                        .await
                        .expect("commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    historical_roots.insert(db.bounds().await.end, db.root());
                    let op_count = {
                        let idx = (*size as usize) % historical_roots.len();
                        *historical_roots
                            .keys()
                            .nth(idx)
                            .expect("historical roots should contain at least one key")
                    };

                    if *start_loc >= op_count || op_count > max_ops.get() {
                        continue;
                    }

                    if let Ok((proof, log)) =
                        db.historical_proof(op_count, *start_loc, *max_ops).await
                    {
                        let root = historical_roots
                            .get(&op_count)
                            .expect("historical root missing for known commit point");
                        assert!(verify_proof(&hasher, &proof, *start_loc, &log, root));
                    }
                }

                Operation::Sync => {
                    let mut batch = db.new_batch();
                    for (k, v) in pending_writes.drain(..) {
                        batch = batch.write(k, v);
                    }
                    let merkleized = batch.merkleize(&db, None).await.unwrap();
                    db.apply_batch(merkleized)
                        .await
                        .expect("commit should not fail");
                    historical_roots.insert(db.bounds().await.end, db.root());
                    db.sync().await.expect("Sync should not fail");
                }

                Operation::InactivityFloorLoc => {
                    let _ = db.inactivity_floor_loc();
                }

                Operation::OpCount => {
                    let _ = db.bounds().await.end;
                }

                Operation::Root => {
                    // root requires commit
                    let mut batch = db.new_batch();
                    for (k, v) in pending_writes.drain(..) {
                        batch = batch.write(k, v);
                    }
                    let merkleized = batch.merkleize(&db, None).await.unwrap();
                    db.apply_batch(merkleized)
                        .await
                        .expect("commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    historical_roots.insert(db.bounds().await.end, db.root());
                    let _ = db.root();
                }

                Operation::SimulateFailure => {
                    // Simulate unclean shutdown by dropping the db without committing
                    pending_writes.clear();
                    historical_roots.clear();
                    drop(db);

                    let cfg = test_config("qmdb-any-variable-fuzz-test", &context);
                    db = Db::<Family, _, Key, Vec<u8>, Sha256, TwoCap>::init(
                        context
                            .with_label("db")
                            .with_attribute("instance", restarts),
                        cfg,
                    )
                    .await
                    .expect("Failed to init source db");
                    restarts += 1;
                }
            }
        }

        let mut batch = db.new_batch();
        for (k, v) in pending_writes.drain(..) {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized)
            .await
            .expect("commit should not fail");
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
