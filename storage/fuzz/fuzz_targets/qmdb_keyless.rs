#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{hasher::Standard, journaled::Config as MerkleConfig, mmb, mmr, Family, Location},
    qmdb::{
        keyless::variable::{Config, Db as Keyless},
        verify_proof,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

const MAX_OPERATIONS: usize = 50;
const MAX_PROOF_OPS: u64 = 100;

#[derive(Debug)]
enum Operation {
    Append {
        value_bytes: Vec<u8>,
    },
    Commit {
        metadata_bytes: Option<Vec<u8>>,
    },
    Get {
        loc_offset: u32,
    },
    GetMetadata,
    Prune,
    Sync,
    OpCount,
    LastCommitLoc,
    OldestRetainedLoc,
    Root,
    Proof {
        start_offset: u32,
        max_ops: u16,
    },
    HistoricalProof {
        size_offset: u32,
        start_offset: u32,
        max_ops: u16,
    },
    SimulateFailure {},
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 13 {
            0 => {
                let value_len: u16 = u.arbitrary()?;
                let actual_len = ((value_len as usize) % 10000) + 1;
                let value_bytes = u.bytes(actual_len)?.to_vec();
                Ok(Operation::Append { value_bytes })
            }
            1 => {
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
            2 => {
                let loc_offset = u.arbitrary()?;
                Ok(Operation::Get { loc_offset })
            }
            3 => Ok(Operation::GetMetadata),
            4 => Ok(Operation::Prune),
            5 => Ok(Operation::Sync),
            6 => Ok(Operation::OpCount),
            7 => Ok(Operation::LastCommitLoc),
            8 => Ok(Operation::OldestRetainedLoc),
            9 => Ok(Operation::Root),
            10 => {
                let start_offset = u.arbitrary()?;
                let max_ops = u.arbitrary()?;
                Ok(Operation::Proof {
                    start_offset,
                    max_ops,
                })
            }
            11 => {
                let size_offset = u.arbitrary()?;
                let start_offset = u.arbitrary()?;
                let max_ops = u.arbitrary()?;
                Ok(Operation::HistoricalProof {
                    size_offset,
                    start_offset,
                    max_ops,
                })
            }
            12 => Ok(Operation::SimulateFailure {}),
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

const PAGE_SIZE: NonZeroU16 = NZU16!(127);
const PAGE_CACHE_SIZE: usize = 8;

type Db<F> = Keyless<F, deterministic::Context, Vec<u8>, Sha256>;

fn test_config(
    test_name: &str,
    pooler: &impl BufferPooler,
) -> Config<(commonware_codec::RangeCfg<usize>, ())> {
    let page_cache = CacheRef::from_pooler(pooler.clone(), PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
    Config {
        merkle: MerkleConfig {
            journal_partition: format!("{test_name}-journal"),
            metadata_partition: format!("{test_name}-meta"),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        log: VConfig {
            partition: format!("{test_name}-log"),
            write_buffer: NZUsize!(1024),
            compression: None,
            codec_config: ((0..=10000).into(), ()),
            items_per_section: NZU64!(7),
            page_cache,
        },
    }
}

fn fuzz_family<F: Family>(input: &FuzzInput, suffix: &str) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let hasher = Standard::<Sha256>::new();
        let cfg = test_config(suffix, &context);
        let mut db: Db<F> = Db::init(context.clone(), cfg)
            .await
            .expect("Failed to init keyless db");
        let mut restarts = 0usize;

        let mut pending_appends: Vec<Vec<u8>> = Vec::new();

        for op in &input.ops {
            match op {
                Operation::Append { value_bytes } => {
                    pending_appends.push(value_bytes.clone());
                }

                Operation::Commit { metadata_bytes } => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, metadata_bytes.clone());
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                }

                Operation::Get { loc_offset } => {
                    let op_count = db.bounds().await.end;
                    if op_count > 0 {
                        let loc = (*loc_offset as u64) % op_count.as_u64();
                        let _ = db.get(loc.into()).await;
                    }
                }

                Operation::GetMetadata => {
                    let _ = db.get_metadata().await;
                }

                Operation::Prune => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None);
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    db.prune(db.last_commit_loc())
                        .await
                        .expect("Prune should not fail");
                }

                Operation::Sync => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None);
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.sync().await.expect("Sync should not fail");
                }

                Operation::OpCount => {
                    let _ = db.bounds().await.end;
                }

                Operation::LastCommitLoc => {
                    let _ = db.last_commit_loc();
                }

                Operation::OldestRetainedLoc => {
                    let _ = db.bounds().await.start;
                }

                Operation::Root => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None);
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    let _ = db.root();
                }

                Operation::Proof {
                    start_offset,
                    max_ops,
                } => {
                    let op_count = db.bounds().await.end;
                    if op_count == 0 {
                        continue;
                    }
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None);
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    let start_loc = (*start_offset as u64) % op_count.as_u64();
                    let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                    let start_loc: Location<F> = Location::new(start_loc);
                    let root = db.root();
                    if let Ok((proof, ops)) = db.proof(start_loc, NZU64!(max_ops_value)).await {
                            assert!(
                                verify_proof(&hasher, &proof, start_loc, &ops, &root),
                                "Failed to verify proof for start loc{start_loc} with ops {max_ops} ops",
                            );
                    }
                }

                Operation::HistoricalProof {
                    size_offset,
                    start_offset,
                    max_ops,
                } => {
                    let op_count = db.bounds().await.end;
                    if op_count == 0 {
                        continue;
                    }
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None);
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    // Use post-commit op_count so it's consistent with the root.
                    let op_count = db.bounds().await.end;
                    let size = ((*size_offset as u64) % op_count.as_u64()) + 1;
                    let size: Location<F> = Location::new(size);
                    let start_loc = (*start_offset as u64) % *size;
                    let start_loc: Location<F> = Location::new(start_loc);
                    let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                    let root = db.root();
                    if let Ok((proof, ops)) = db
                        .historical_proof(op_count, start_loc, NZU64!(max_ops_value))
                            .await {
                            assert!(
                                verify_proof(&hasher, &proof, start_loc, &ops, &root),
                                "Failed to verify historical proof for start loc{start_loc} with max ops {max_ops}",
                            );
                        }
                }

                Operation::SimulateFailure{} => {
                    pending_appends.clear();
                    drop(db);

                    let cfg = test_config(suffix, &context);
                    db = Db::init(
                        context.with_label("db").with_attribute("instance", restarts),
                        cfg,
                    )
                    .await
                    .expect("Failed to init keyless db");
                    restarts += 1;
                }
            }
        }

        let mut batch = db.new_batch();
        for v in pending_appends.drain(..) {
            batch = batch.append(v);
        }
        let merkleized = batch.merkleize(&db, None);
        db.apply_batch(merkleized).await.expect("Commit should not fail");
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family>(&input, "fuzz-mmr");
    fuzz_family::<mmb::Family>(&input, "fuzz-mmb");
});
