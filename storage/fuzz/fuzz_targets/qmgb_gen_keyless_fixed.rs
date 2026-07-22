#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{
    BufferPooler, Runner, Strategizer as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{Family, Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        Error,
        keyless::fixed::{Config, Db as Keyless},
        verify_proof,
    },
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeMap, num::NonZeroU16};

const MAX_OPERATIONS: usize = 50;
const MAX_PROOF_OPS: u64 = 100;

/// Which error variant a bad-floor commit should produce.
#[derive(Debug, Clone, Copy)]
enum BadFloorExpect {
    Regression,
    BeyondSize,
}

fn assert_bad_floor_error<F: Family>(err: &Error<F>, kind: BadFloorExpect) {
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
    /// Floor one below the current floor - must be rejected as `FloorRegressed`.
    BadRegression,
    /// Floor one past the commit location - must be rejected as `FloorBeyondSize`.
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
    /// Build a two-level batch chain (parent -> child) and apply the child directly. The
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
                let actual_len = (((value_len as usize) % 10000) + 1).min(u.len());
                let value_bytes = u.bytes(actual_len)?.to_vec();
                Ok(Operation::Append { value_bytes })
            }
            1 => {
                let has_metadata: bool = u.arbitrary()?;
                let metadata_bytes = if has_metadata {
                    let metadata_len: u16 = u.arbitrary()?;
                    let actual_len = (((metadata_len as usize) % 1000) + 1).min(u.len());
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
                // Only Bad* kinds make sense here - the ancestor is guaranteed unapplied.
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
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { ops, raw_bytes })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(127);
const PAGE_CACHE_SIZE: usize = 8;

type Db<F, S> = Keyless<F, deterministic::Context, Digest, Sha256, S>;

fn test_config<S: Strategy>(test_name: &str, pooler: &impl BufferPooler, strategy: S) -> Config<S> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
    Config {
        merkle: MerkleConfig {
            journal_partition: format!("{test_name}-journal"),
            metadata_partition: format!("{test_name}-meta"),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(1024),
            strategy,
            page_cache: page_cache.clone(),
        },
        log: FConfig {
            partition: format!("{test_name}-log"),
            write_buffer: NZUsize!(1024),
            items_per_blob: NZU64!(7),
            page_cache,
        },
    }
}

/// Reopen the database.
async fn reopen<F: Family, S: Strategy>(
    context: &deterministic::Context,
    suffix: &str,
    strategy: &S,
    restarts: &mut usize,
) -> Db<F, S> {
    let cfg = test_config(suffix, context, strategy.clone());
    let db = Db::init(
        context.child("db").with_attribute("instance", *restarts),
        cfg,
    )
    .await
    .expect("Failed to init keyless db");
    *restarts += 1;
    db
}

fn fuzz_family<F: Family, S: Strategy>(
    input: &FuzzInput,
    suffix: &str,
    strategy: impl FnOnce(&deterministic::Context) -> S,
) {
    let cfg =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| async move {
        let strategy = strategy(&context);
        let cfg = test_config(suffix, &context, strategy.clone());
        let mut db: Db<F, S> = Db::init(context.child("storage"), cfg)
            .await
            .expect("Failed to init keyless db");
        let mut restarts = 0usize;

        let mut pending_appends: Vec<Digest> = Vec::new();
        let mut expected_values = BTreeMap::<u64, Digest>::new();
        let mut expected_metadata = None;
        let mut expected_root = db.root();
        let mut expected_size = db.bounds().end;
        let mut commits = vec![(expected_size, expected_root)];

        for op in &input.ops {
            db = match op {
                Operation::Append { value_bytes } => {
                    pending_appends.push(Sha256::hash(&[value_bytes.as_slice()]));
                    db
                }

                Operation::Commit {
                    metadata_bytes,
                    floor_kind,
                } => {
                    let pending_count = pending_appends.len() as u64;
                    let end = db.bounds().end;
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

                    let appends = std::mem::take(&mut pending_appends);
                    let mut batch = db.new_batch();
                    for v in &appends {
                        batch = batch.append(*v);
                    }
                    let metadata = metadata_bytes
                        .as_deref()
                        .map(|bytes| Sha256::hash(&[bytes]));
                    let merkleized = batch.merkleize(&db, metadata, floor).await;

                    match expect_err {
                        None => {
                            let batch_root = merkleized.root();
                            let (db, range) = db
                                .apply_batch(merkleized)
                                .await
                                .expect("Commit should not fail");
                            assert_eq!(range.start, end);
                            assert_eq!(range.end, db.bounds().end);
                            assert_eq!(db.root(), batch_root);
                            let db = db.commit().await.expect("Commit should not fail");
                            for (offset, value) in appends.into_iter().enumerate() {
                                expected_values.insert(end.as_u64() + offset as u64, value);
                            }
                            if let Some(metadata) = metadata {
                                expected_values.insert(commit_loc, metadata);
                            }
                            expected_metadata = metadata;
                            expected_root = batch_root;
                            expected_size = db.bounds().end;
                            commits.push((expected_size, expected_root));
                            db
                        }
                        Some(kind) => {
                            // Snapshot state; the reject must not mutate persisted state.
                            let before_last_commit = db.last_commit_loc();
                            let before_floor = db.inactivity_floor_loc();
                            let before_root = db.root();
                            let err = match db.apply_batch(merkleized).await {
                                Ok(_) => panic!("bad floor must be rejected"),
                                Err(err) => err,
                            };
                            assert_bad_floor_error(&err, kind);
                            // Reopen and verify the reject persisted nothing.
                            let db = reopen(&context, suffix, &strategy, &mut restarts).await;
                            assert_eq!(db.last_commit_loc(), before_last_commit);
                            assert_eq!(db.inactivity_floor_loc(), before_floor);
                            assert_eq!(db.root(), before_root);
                            pending_appends = appends;
                            db
                        }
                    }
                }

                Operation::BadChainedCommit { ancestor_kind } => {
                    let end = db.bounds().end;
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

                    if pending_appends.len() < 2 {
                        continue;
                    }
                    let parent = db
                        .new_batch()
                        .append(pending_appends[0])
                        .merkleize(&db, None, parent_floor)
                        .await;
                    // child: valid on its own; only the ancestor should trip the check.
                    let child_floor = parent_floor; // stay >= parent_floor even if parent is bad
                    let child = parent
                        .new_batch::<Sha256>()
                        .append(pending_appends[1])
                        .merkleize(&db, None, child_floor)
                        .await;

                    let before_last_commit = db.last_commit_loc();
                    let before_floor = db.inactivity_floor_loc();
                    let before_root = db.root();
                    let err = match db.apply_batch(child).await {
                        Ok(_) => panic!("bad ancestor floor must be rejected"),
                        Err(err) => err,
                    };
                    assert_bad_floor_error(&err, kind);
                    // Reopen and verify the reject persisted nothing.
                    let db = reopen(&context, suffix, &strategy, &mut restarts).await;
                    assert_eq!(db.last_commit_loc(), before_last_commit);
                    assert_eq!(db.inactivity_floor_loc(), before_floor);
                    assert_eq!(db.root(), before_root);
                    db
                }

                Operation::Get { loc_offset } => {
                    let bounds = db.bounds();
                    if bounds.start < bounds.end {
                        let loc = bounds.start.as_u64()
                            + (*loc_offset as u64) % (bounds.end - bounds.start).as_u64();
                        let actual = db
                            .get(Location::new(loc))
                            .await
                            .expect("get should not fail");
                        assert_eq!(actual, expected_values.get(&loc).copied());
                    }
                    db
                }

                Operation::GetMetadata => {
                    assert_eq!(
                        db.get_metadata()
                            .await
                            .expect("metadata read should not fail"),
                        expected_metadata,
                    );
                    db
                }

                Operation::Prune => {
                    let floor = db.inactivity_floor_loc();
                    let root = db.root();
                    let db = db.prune(floor).await.expect("Prune should not fail");
                    assert_eq!(db.root(), root);
                    assert_eq!(db.bounds().end, expected_size);
                    expected_values.retain(|loc, _| *loc >= db.bounds().start.as_u64());
                    db
                }

                Operation::Sync => {
                    let expected = (
                        db.bounds(),
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata()
                            .await
                            .expect("metadata read should not fail"),
                    );
                    let db = db.sync().await.expect("Sync should not fail");
                    assert_eq!(
                        (
                            db.bounds(),
                            db.root(),
                            db.inactivity_floor_loc(),
                            db.get_metadata()
                                .await
                                .expect("metadata read should not fail"),
                        ),
                        expected,
                        "sync should preserve keyless state"
                    );
                    db
                }

                Operation::OpCount => {
                    assert_eq!(db.bounds().end, expected_size);
                    db
                }

                Operation::LastCommitLoc => {
                    assert_eq!(db.last_commit_loc() + 1, expected_size);
                    db
                }

                Operation::OldestRetainedLoc => {
                    assert!(db.bounds().start <= db.inactivity_floor_loc());
                    db
                }

                Operation::Root => {
                    assert_eq!(db.root(), expected_root);
                    db
                }

                Operation::Proof {
                    start_offset,
                    max_ops,
                } => {
                    let bounds = db.bounds();
                    let start_loc = bounds.start.as_u64()
                        + (*start_offset as u64) % (bounds.end - bounds.start).as_u64();
                    let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                    let start_loc: Location<F> = Location::new(start_loc);
                    let (proof, ops) = db
                        .proof(start_loc, NZU64!(max_ops_value))
                        .await
                        .expect("proof should not fail for a retained location");
                    assert!(verify_proof::<Sha256, _, _>(
                        &proof,
                        start_loc,
                        &ops,
                        &expected_root,
                    ));
                    db
                }

                Operation::HistoricalProof {
                    size_offset,
                    start_offset,
                    max_ops,
                } => {
                    let retained = commits
                        .iter()
                        .filter(|(size, _)| *size > db.bounds().start)
                        .copied()
                        .collect::<Vec<_>>();
                    let (size, root) = retained[*size_offset as usize % retained.len()];
                    let start_loc = Location::new(
                        db.bounds().start.as_u64()
                            + (*start_offset as u64) % (size - db.bounds().start).as_u64(),
                    );
                    let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                    let (proof, ops) = db
                        .historical_proof(size, start_loc, NZU64!(max_ops_value))
                        .await
                        .expect("historical proof should not fail at a retained commit");
                    assert!(verify_proof::<Sha256, _, _>(&proof, start_loc, &ops, &root,));
                    db
                }

                Operation::SimulateFailure {} => {
                    pending_appends.clear();
                    drop(db);
                    let db = reopen(&context, suffix, &strategy, &mut restarts).await;
                    assert_eq!(db.bounds().end, expected_size);
                    assert_eq!(db.root(), expected_root);
                    assert_eq!(
                        db.get_metadata()
                            .await
                            .expect("metadata read should not fail"),
                        expected_metadata,
                    );
                    db
                }
            };
        }

        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family, Sequential>(&input, "fuzz-fixed-mmr-sequential", |_| Sequential);
    fuzz_family::<mmb::Family, Sequential>(&input, "fuzz-fixed-mmb-sequential", |_| Sequential);
    fuzz_family::<mmr::Family, Rayon>(&input, "fuzz-fixed-mmr-rayon", |context| {
        context.strategy(NZUsize!(2))
    });
    fuzz_family::<mmb::Family, Rayon>(&input, "fuzz-fixed-mmb-rayon", |context| {
        context.strategy(NZUsize!(2))
    });
});
