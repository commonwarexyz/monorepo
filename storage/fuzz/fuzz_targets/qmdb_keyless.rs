#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{
    BufferPooler, Runner, Strategizer as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{Family, Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        Error,
        keyless::variable::{Config, Db as Keyless},
        verify_proof, verify_proof_and_pinned_nodes,
    },
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

const MAX_OPERATIONS: usize = 50;
const MAX_PROOF_OPS: u64 = 100;
type CodecConfig = (commonware_codec::RangeCfg<usize>, ());

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
    GetMany {
        first_offset: u32,
        second_offset: u32,
    },
    BatchReads {
        loc_offset: u32,
    },
    GetMetadata,
    Prune,
    Sync,
    OpCount,
    LastCommitLoc,
    OldestRetainedLoc,
    SyncBoundary,
    Rewind {
        idx: u8,
    },
    ValidateBatch,
    ToBatch,
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
    Strategy {
        values: [u8; 4],
    },
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 21 {
            0 => {
                let value_len: u16 = u.arbitrary()?;
                let actual_len = ((value_len as usize) % 10000) + 1;
                let value_bytes = u.bytes(actual_len.min(u.len()))?.to_vec();
                Ok(Operation::Append { value_bytes })
            }
            1 => {
                let has_metadata: bool = u.arbitrary()?;
                let metadata_bytes = if has_metadata {
                    let metadata_len: u16 = u.arbitrary()?;
                    let actual_len = ((metadata_len as usize) % 1000) + 1;
                    Some(u.bytes(actual_len.min(u.len()))?.to_vec())
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
            14 => Ok(Operation::GetMany {
                first_offset: u.arbitrary()?,
                second_offset: u.arbitrary()?,
            }),
            15 => Ok(Operation::BatchReads {
                loc_offset: u.arbitrary()?,
            }),
            16 => Ok(Operation::SyncBoundary),
            17 => Ok(Operation::Rewind {
                idx: u.arbitrary()?,
            }),
            18 => Ok(Operation::ValidateBatch),
            19 => Ok(Operation::ToBatch),
            20 => Ok(Operation::Strategy {
                values: u.arbitrary()?,
            }),
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

type Db<F, S> = Keyless<F, deterministic::Context, Vec<u8>, Sha256, S>;

fn test_config<S: Strategy>(
    test_name: &str,
    pooler: &impl BufferPooler,
    strategy: S,
) -> Config<CodecConfig, S> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
    Config {
        merkle: MerkleConfig {
            journal_partition: format!("{test_name}-journal"),
            metadata_partition: format!("{test_name}-meta"),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy,
            page_cache: page_cache.clone(),
        },
        log: VConfig {
            partition: format!("{test_name}-log"),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            compression: None,
            codec_config: ((0..=10000).into(), ()),
            items_per_section: NZU64!(7),
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
    deterministic::Runner::default();
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

        let mut pending_appends: Vec<Vec<u8>> = Vec::new();
        let mut expected_metadata = db.get_metadata().await.unwrap();
        let mut commit_history = vec![(
            db.bounds().end,
            db.root(),
            db.inactivity_floor_loc(),
            db.get_metadata().await.unwrap(),
        )];

        for op in &input.ops {
            db = match op {
                Operation::Append { value_bytes } => {
                    pending_appends.push(value_bytes.clone());
                    db
                }

                Operation::Commit { metadata_bytes, floor_kind } => {
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

                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, metadata_bytes.clone(), floor).await;

                    match expect_err {
                        None => {
                            let expected_root = merkleized.root();
                            let expected_size = merkleized.bounds().tip.size;
                            let (db, _) = db
                                .apply_batch(merkleized)
                                .await
                                .expect("Commit should not fail");
                            let db = db.commit().await.expect("Commit should not fail");
                            assert_eq!(db.bounds().end, expected_size);
                            assert_eq!(db.root(), expected_root);
                            assert_eq!(db.inactivity_floor_loc(), floor);
                            assert_eq!(db.get_metadata().await.unwrap(), metadata_bytes.clone());
                            expected_metadata = metadata_bytes.clone();
                            commit_history.push((
                                db.bounds().end,
                                db.root(),
                                db.inactivity_floor_loc(),
                                db.get_metadata().await.unwrap(),
                            ));
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

                    // Don't drain pending_appends - keep them for future ops. Build from scratch.
                    let parent = db
                        .new_batch()
                        .append(vec![0u8; 1])
                        .merkleize(&db, None, parent_floor).await;
                    // child: valid on its own; only the ancestor should trip the check.
                    let child_floor = parent_floor; // stay >= parent_floor even if parent is bad
                    let child = parent
                        .new_batch::<Sha256>()
                        .append(vec![1u8; 1])
                        .merkleize(&db, None, child_floor).await;

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
                        let retained = (bounds.end - bounds.start).as_u64();
                        let loc = bounds.start + (*loc_offset as u64 % retained);
                        let value = db.get(loc).await.expect("retained get should not fail");
                        assert_eq!(db.get_many(&[loc]).await.unwrap(), vec![value]);
                    }
                    db
                }

                Operation::GetMany {
                    first_offset,
                    second_offset,
                } => {
                    let bounds = db.bounds();
                    if bounds.start < bounds.end {
                        let len = (bounds.end - bounds.start).as_u64();
                        let mut locs = vec![
                            bounds.start + (*first_offset as u64 % len),
                            bounds.start + (*second_offset as u64 % len),
                        ];
                        locs.sort();
                        locs.dedup();
                        let mut expected = Vec::with_capacity(locs.len());
                        for loc in &locs {
                            expected.push(db.get(*loc).await.unwrap());
                        }
                        assert_eq!(db.get_many(&locs).await.unwrap(), expected);
                    }
                    db
                }

                Operation::BatchReads { loc_offset } => {
                    let mut batch = db.new_batch();
                    for value in &pending_appends {
                        batch = batch.append(value.clone());
                    }
                    let bounds = db.bounds();
                    if bounds.start < batch.size() {
                        let len = (batch.size() - bounds.start).as_u64();
                        let loc = bounds.start + (*loc_offset as u64 % len);
                        let expected = batch.get(loc, &db).await.unwrap();
                        assert_eq!(batch.get_many(&[loc], &db).await.unwrap(), vec![expected]);
                        let merkleized = batch
                            .merkleize(&db, None, db.inactivity_floor_loc())
                            .await;
                        assert_eq!(
                            merkleized.get_many(&[loc], &db).await.unwrap(),
                            vec![merkleized.get(loc, &db).await.unwrap()]
                        );
                        assert_eq!(
                            merkleized.bounds().tip.size.as_u64(),
                            db.bounds().end.as_u64() + pending_appends.len() as u64 + 1
                        );
                    }
                    db
                }

                Operation::GetMetadata => {
                    assert_eq!(db.get_metadata().await.unwrap(), expected_metadata);
                    db
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
                    let end = db.bounds().end;
                    let floor = Location::<F>::new(end.as_u64() + pending_count);
                    let merkleized = batch.merkleize(&db, None, floor).await;
                    let expected_root = merkleized.root();
                    let (db, _) = db
                        .apply_batch(merkleized)
                        .await
                        .expect("Commit should not fail");
                    let db = db.commit().await.expect("Commit should not fail");
                    expected_metadata = None;
                    commit_history.push((
                        db.bounds().end,
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata().await.unwrap(),
                    ));
                    let size = db.bounds().end;
                    let floor = db.inactivity_floor_loc();
                    let db = db.prune(floor).await.expect("Prune should not fail");
                    assert_eq!(db.bounds().end, size);
                    assert_eq!(db.root(), expected_root);
                    db
                }

                Operation::Sync => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
                    let (db, _) = db
                        .apply_batch(merkleized)
                        .await
                        .expect("Commit should not fail");
                    let expected_root = db.root();
                    let expected_size = db.bounds().end;
                    let expected_floor = db.inactivity_floor_loc();
                    let db = db.sync().await.expect("Sync should not fail");
                    assert_eq!(db.root(), expected_root);
                    assert_eq!(db.bounds().end, expected_size);
                    assert_eq!(db.inactivity_floor_loc(), expected_floor);
                    assert_eq!(db.get_metadata().await.unwrap(), None);
                    expected_metadata = None;
                    commit_history.push((
                        db.bounds().end,
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata().await.unwrap(),
                    ));
                    db
                }

                Operation::OpCount => {
                    assert_eq!(db.bounds().end, db.last_commit_loc() + 1);
                    db
                }

                Operation::LastCommitLoc => {
                    assert_eq!(db.last_commit_loc() + 1, db.bounds().end);
                    db
                }

                Operation::OldestRetainedLoc => {
                    assert!(db.bounds().start <= db.inactivity_floor_loc());
                    assert!(db.bounds().start <= db.bounds().end);
                    db
                }

                Operation::SyncBoundary => {
                    assert_eq!(db.sync_boundary(), db.inactivity_floor_loc());
                    db
                }

                Operation::Rewind { idx } => {
                    let oldest = db.bounds().start;
                    let candidates = commit_history
                        .iter()
                        .filter(|(size, _, floor, _)| *size > oldest && *floor >= oldest)
                        .collect::<Vec<_>>();
                    if candidates.len() < 2 {
                        db
                    } else {
                        let expected = candidates[*idx as usize % (candidates.len() - 1)];
                        let target = expected.0;
                        let db = db.rewind(target).await.expect("Rewind should not fail");
                        assert_eq!(db.bounds().end, expected.0);
                        assert_eq!(db.root(), expected.1);
                        assert_eq!(db.inactivity_floor_loc(), expected.2);
                        assert_eq!(db.get_metadata().await.unwrap(), expected.3);
                        expected_metadata = expected.3.clone();
                        let db = db.commit().await.expect("Rewind commit should not fail");
                        commit_history.retain(|(size, _, _, _)| *size <= target);
                        db
                    }
                }

                Operation::ValidateBatch => {
                    let before = (db.bounds(), db.root(), db.inactivity_floor_loc());
                    let mut batch = db.new_batch();
                    for value in &pending_appends {
                        batch = batch.append(value.clone());
                    }
                    let merkleized = batch
                        .merkleize(&db, None, db.inactivity_floor_loc())
                        .await;
                    assert!(db.validate_batch(&merkleized).is_ok());
                    assert_eq!(
                        (db.bounds(), db.root(), db.inactivity_floor_loc()),
                        before
                    );
                    db
                }

                Operation::ToBatch => {
                    let batch = db.to_batch();
                    assert_eq!(batch.root(), db.root());
                    assert_eq!(batch.bounds().base.size, db.bounds().end);
                    assert_eq!(batch.bounds().tip.size, db.bounds().end);
                    assert_eq!(batch.bounds().inactivity_floor, db.inactivity_floor_loc());
                    db
                }

                Operation::Root => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
                    let expected_root = merkleized.root();
                    let (db, _) = db
                        .apply_batch(merkleized)
                        .await
                        .expect("Commit should not fail");
                    let db = db.commit().await.expect("Commit should not fail");
                    assert_eq!(db.root(), expected_root);
                    expected_metadata = None;
                    commit_history.push((
                        db.bounds().end,
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata().await.unwrap(),
                    ));
                    db
                }

                Operation::Strategy { values } => {
                    let expected = values.iter().map(|value| u64::from(*value)).sum::<u64>();
                    let actual = db.strategy().fold(
                        values,
                        || 0u64,
                        |sum, value| sum + u64::from(*value),
                        |left, right| left + right,
                    );
                    assert_eq!(actual, expected, "database strategy produced a wrong fold");
                    db
                }

                Operation::Proof {
                    start_offset,
                    max_ops,
                } => {
                    let op_count = db.bounds().end;
                    if op_count == 0 {
                        continue;
                    }
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
                    let (db, _) = db
                        .apply_batch(merkleized)
                        .await
                        .expect("Commit should not fail");
                    let db = db.commit().await.expect("Commit should not fail");
                    expected_metadata = None;
                    commit_history.push((
                        db.bounds().end,
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata().await.unwrap(),
                    ));
                    let start_loc = (*start_offset as u64) % op_count.as_u64();
                    let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                    let start_loc: Location<F> = Location::new(start_loc);
                    let root = db.root();
                    if let Ok((proof, ops)) = db.proof(start_loc, NZU64!(max_ops_value)).await {
                        assert!(
                            verify_proof::<Sha256, _, _>(
                                &proof,
                                start_loc,
                                &ops,
                                &root),
                            "Failed to verify proof for start loc{start_loc} with ops {max_ops} ops",
                        );
                        let pinned = db.pinned_nodes_at(start_loc).await.unwrap();
                        assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(
                            &proof,
                            start_loc,
                            &ops,
                            &pinned,
                            &root,
                        ));
                        for op in ops {
                            let floor = op.has_floor();
                            let value = op.into_value();
                            assert!(
                                floor.is_some() || value.is_some(),
                                "an append must contain a value"
                            );
                        }
                    }
                    db
                }

                Operation::HistoricalProof {
                    size_offset,
                    start_offset,
                    max_ops,
                } => {
                    let mut batch = db.new_batch();
                    for v in pending_appends.drain(..) {
                        batch = batch.append(v);
                    }
                    let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
                    let (db, _) = db
                        .apply_batch(merkleized)
                        .await
                        .expect("Commit should not fail");
                    let db = db.commit().await.expect("Commit should not fail");
                    expected_metadata = None;
                    commit_history.push((
                        db.bounds().end,
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata().await.unwrap(),
                    ));
                    let bounds = db.bounds();
                    let candidates = commit_history
                        .iter()
                        .filter(|(size, _, floor, _)| {
                            *size > bounds.start && *floor >= bounds.start
                        })
                        .collect::<Vec<_>>();
                    let expected = candidates[*size_offset as usize % candidates.len()];
                    let retained = (expected.0 - bounds.start).as_u64();
                    let start_loc = bounds.start + (*start_offset as u64 % retained);
                    let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                    let (proof, ops) = db
                        .historical_proof(expected.0, start_loc, NZU64!(max_ops_value))
                        .await
                        .expect("retained commit should produce a historical proof");
                    assert!(
                        verify_proof::<Sha256, _, _>(&proof, start_loc, &ops, &expected.1),
                        "Failed to verify historical proof for start loc{start_loc} with max ops {max_ops}",
                    );
                    db
                }

                Operation::SimulateFailure{} => {
                    pending_appends.clear();
                    drop(db);
                    let db = reopen(&context, suffix, &strategy, &mut restarts).await;
                    let expected = commit_history.last().unwrap();
                    assert_eq!(db.bounds().end, expected.0);
                    assert_eq!(db.root(), expected.1);
                    assert_eq!(db.inactivity_floor_loc(), expected.2);
                    assert_eq!(db.get_metadata().await.unwrap(), expected.3);
                    expected_metadata = expected.3.clone();
                    db
                }
            };
        }

        let mut batch = db.new_batch();
        for v in pending_appends.drain(..) {
            batch = batch.append(v);
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
        let (db, _) = db
            .apply_batch(merkleized)
            .await
            .expect("Commit should not fail");
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family, Sequential>(&input, "fuzz-mmr-sequential", |_| Sequential);
    fuzz_family::<mmb::Family, Sequential>(&input, "fuzz-mmb-sequential", |_| Sequential);
    fuzz_family::<mmr::Family, Rayon>(&input, "fuzz-mmr-rayon", |context| {
        context.strategy(NZUsize!(2))
    });
    fuzz_family::<mmb::Family, Rayon>(&input, "fuzz-mmb-rayon", |context| {
        context.strategy(NZUsize!(2))
    });
});
