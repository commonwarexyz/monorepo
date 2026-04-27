#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{full::Config as MerkleConfig, hasher::Standard, mmb, mmr, Family, Location},
    qmdb::{
        keyless::variable::{Config, Db as Keyless},
        verify_proof, Error, RootSpec,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

const MAX_OPERATIONS: usize = 50;
const MAX_PROOF_OPS: u64 = 100;

/// Which error variant a bad-floor commit should produce.
#[derive(Debug, Clone, Copy)]
enum BadFloorExpect {
    Regression,
    BeyondSize,
}

fn assert_bad_floor_error<F: Family + RootSpec>(err: &Error<F>, kind: BadFloorExpect) {
    match (err, kind) {
        (Error::FloorRegressed(_, _), BadFloorExpect::Regression) => {}
        (Error::FloorBeyondSize(_, _), BadFloorExpect::BeyondSize) => {}
        _ => panic!("unexpected error for {kind:?}: {err:?}"),
    }
}

/// What floor value a fuzz-generated commit should carry. The `Bad*` variants intentionally
/// produce floors that must be rejected; the handler asserts the expected error variant and
/// that the DB state is untouched.
#[derive(Debug, Clone, Copy)]
enum FloorKind {
    /// Keep the current floor (monotonicity trivially preserved).
    Current,
    /// Advance to the commit location (the tight upper bound).
    AdvanceToCommit,
    /// Floor one below the current floor — must be rejected as `FloorRegressed`.
    BadRegression,
    /// Floor one past the commit location — must be rejected as `FloorBeyondSize`.
    BadBeyondCommit,
}

impl<'a> Arbitrary<'a> for FloorKind {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        Ok(match choice % 4 {
            0 => FloorKind::Current,
            1 => FloorKind::AdvanceToCommit,
            2 => FloorKind::BadRegression,
            3 => FloorKind::BadBeyondCommit,
            _ => unreachable!(),
        })
    }
}

#[derive(Debug)]
enum Operation {
    Append {
        value_bytes: Vec<u8>,
    },
    Commit {
        metadata_bytes: Option<Vec<u8>>,
        floor_kind: FloorKind,
    },
    /// Build a two-level batch chain (parent → child) and apply the child directly. The
    /// parent's floor is intentionally invalid (regressed or beyond its own commit location);
    /// this exercises the per-ancestor validation path in `apply_batch`.
    BadChainedCommit {
        ancestor_kind: FloorKind,
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
        match choice % 14 {
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
                let floor_kind = FloorKind::arbitrary(u)?;
                Ok(Operation::Commit {
                    metadata_bytes,
                    floor_kind,
                })
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
            13 => {
                // Only Bad* kinds make sense here — the ancestor is guaranteed unapplied.
                let ancestor_kind = match u.arbitrary::<bool>()? {
                    false => FloorKind::BadRegression,
                    true => FloorKind::BadBeyondCommit,
                };
                Ok(Operation::BadChainedCommit { ancestor_kind })
            }
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
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
    Config {
        merkle: MerkleConfig {
            journal_partition: format!("{test_name}-journal"),
            metadata_partition: format!("{test_name}-meta"),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
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

fn fuzz_family<F: Family + RootSpec>(input: &FuzzInput, suffix: &str) {
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

                Operation::Commit { metadata_bytes, floor_kind } => {
                    let pending_count = pending_appends.len() as u64;
                    let end = db.bounds().await.end;
                    let commit_loc = end.as_u64() + pending_count;
                    let current_floor = db.inactivity_floor_loc();

                    // Pick the floor for this commit. `Bad*` kinds are guaranteed to trigger
                    // the expected error; Valid kinds (Current/AdvanceToCommit) apply cleanly.
                    let (floor, expect_err) = match floor_kind {
                        FloorKind::Current => (current_floor, None),
                        FloorKind::AdvanceToCommit => (Location::<F>::new(commit_loc), None),
                        FloorKind::BadRegression => {
                            // Only meaningful when current floor > 0; otherwise fall back to Current.
                            if current_floor.as_u64() == 0 {
                                (current_floor, None)
                            } else {
                                let bad = Location::<F>::new(current_floor.as_u64() - 1);
                                (bad, Some(BadFloorExpect::Regression))
                            }
                        }
                        FloorKind::BadBeyondCommit => {
                            let bad = Location::<F>::new(commit_loc + 1);
                            (bad, Some(BadFloorExpect::BeyondSize))
                        }
                    };

                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, metadata_bytes.clone(), floor);

                    match expect_err {
                        None => {
                            db.apply_batch(merkleized).await.expect("Commit should not fail");
                            db.commit().await.expect("Commit should not fail");
                        }
                        Some(kind) => {
                            // Snapshot state; the reject must not mutate.
                            let before_last_commit = db.last_commit_loc();
                            let before_floor = db.inactivity_floor_loc();
                            let before_root = db.root();
                            let err = db
                                .apply_batch(merkleized)
                                .await
                                .expect_err("bad floor must be rejected");
                            assert_bad_floor_error(&err, kind);
                            assert_eq!(db.last_commit_loc(), before_last_commit);
                            assert_eq!(db.inactivity_floor_loc(), before_floor);
                            assert_eq!(db.root(), before_root);
                        }
                    }
                }

                Operation::BadChainedCommit { ancestor_kind } => {
                    let end = db.bounds().await.end;
                    let current_floor = db.inactivity_floor_loc();

                    // Parent batch: base = end, 1 append lands at `end`, commit lands at `end + 1`.
                    // So parent's total_size = end + 2 and parent_commit_loc = end + 1.
                    let parent_commit_loc = end.as_u64() + 1;
                    let (parent_floor, kind) = match ancestor_kind {
                        FloorKind::BadRegression => {
                            if current_floor.as_u64() == 0 {
                                // No regression possible; skip this op (no-op).
                                continue;
                            }
                            (
                                Location::<F>::new(current_floor.as_u64() - 1),
                                BadFloorExpect::Regression,
                            )
                        }
                        FloorKind::BadBeyondCommit => (
                            Location::<F>::new(parent_commit_loc + 1),
                            BadFloorExpect::BeyondSize,
                        ),
                        _ => continue, // only bad kinds are meaningful here
                    };

                    // Don't drain pending_appends — keep them for future ops. Build from scratch.
                    let parent = db
                        .new_batch()
                        .append(vec![0u8; 1])
                        .merkleize(&db, None, parent_floor);
                    // child: valid on its own; only the ancestor should trip the check.
                    let child_floor = parent_floor; // stay ≥ parent_floor even if parent is bad
                    let child = parent
                        .new_batch::<Sha256>()
                        .append(vec![1u8; 1])
                        .merkleize(&db, None, child_floor);

                    let before_last_commit = db.last_commit_loc();
                    let before_floor = db.inactivity_floor_loc();
                    let before_root = db.root();
                    let err = db
                        .apply_batch(child)
                        .await
                        .expect_err("bad ancestor floor must be rejected");
                    assert_bad_floor_error(&err, kind);
                    assert_eq!(db.last_commit_loc(), before_last_commit);
                    assert_eq!(db.inactivity_floor_loc(), before_floor);
                    assert_eq!(db.root(), before_root);
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
                    let pending_count = pending_appends.len() as u64;
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    // Advance the floor to the new commit location so the subsequent prune
                    // actually removes data. This exercises more of the code path than pruning
                    // at a stale floor would.
                    let end = db.bounds().await.end;
                    let floor = Location::<F>::new(end.as_u64() + pending_count);
                    let merkleized = batch.merkleize(&db, None, floor);
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    db.prune(db.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                }

                Operation::Sync => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
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
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
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
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
                    db.apply_batch(merkleized).await.expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    let start_loc = (*start_offset as u64) % op_count.as_u64();
                    let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                    let start_loc: Location<F> = Location::new(start_loc);
                    let root = db.root();
                    if let Ok((proof, ops)) = db.proof(start_loc, NZU64!(max_ops_value)).await {
                            assert!(
                                verify_proof(
                                    &hasher,
                                    &proof,
                                    start_loc,
                                    &ops,
                                    &root,
                                    F::root_spec(proof.inactive_peaks),
                                ),
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
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
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
                                verify_proof(
                                    &hasher,
                                    &proof,
                                    start_loc,
                                    &ops,
                                    &root,
                                    F::root_spec(proof.inactive_peaks),
                                ),
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
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.expect("Commit should not fail");
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family>(&input, "fuzz-mmr");
    fuzz_family::<mmb::Family>(&input, "fuzz-mmb");
});
