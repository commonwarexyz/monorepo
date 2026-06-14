#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, BufferPooler, Runner, Supervisor as _,
};
use commonware_storage::{
    journal::contiguous::variable::Config as JournalConfig,
    merkle::{mmb, mmr, Error as MerkleError, Family, Location},
    qmdb::{
        keyless::variable::{CompactConfig, CompactDb},
        sync::compact as compact_sync,
        Error,
    },
};
use commonware_utils::{FuzzRng, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{num::NonZeroU16, sync::Arc};

const MAX_OPERATIONS: usize = 50;
const MAX_VALUE_LEN: usize = 10000;
const MAX_METADATA_LEN: usize = 1000;
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
    /// Build a two-level batch chain (parent -> child) and apply the child directly.
    ChainedCommit,
    /// Apply two batches built from the same DB state; the second must be rejected as stale.
    StaleBatch,
    Sync,
    /// Rewind to a recorded synced commit and verify the restored state.
    Rewind {
        idx: u8,
    },
    /// Rewind to a never-synced size: must fail, after which the handle is reopened.
    RewindUnsynced,
    /// Prune witnesses below a recorded synced commit.
    Prune {
        idx: u8,
    },
    /// Drop the handle without syncing and reopen: state must match the last synced commit.
    Restart,
    Root,
    GetMetadata,
    Target,
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 12 {
            0 => {
                let value_len: u16 = u.arbitrary()?;
                let actual_len = (((value_len as usize) % MAX_VALUE_LEN) + 1).min(u.len());
                let value_bytes = u.bytes(actual_len)?.to_vec();
                Ok(Operation::Append { value_bytes })
            }
            1 => {
                let has_metadata: bool = u.arbitrary()?;
                let metadata_bytes = if has_metadata {
                    let metadata_len: u16 = u.arbitrary()?;
                    let actual_len =
                        (((metadata_len as usize) % MAX_METADATA_LEN) + 1).min(u.len());
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
            2 => Ok(Operation::ChainedCommit),
            3 => Ok(Operation::StaleBatch),
            4 => Ok(Operation::Sync),
            5 => {
                let idx = u.arbitrary()?;
                Ok(Operation::Rewind { idx })
            }
            6 => Ok(Operation::RewindUnsynced),
            7 => {
                let idx = u.arbitrary()?;
                Ok(Operation::Prune { idx })
            }
            8 => Ok(Operation::Restart),
            9 => Ok(Operation::Root),
            10 => Ok(Operation::GetMetadata),
            11 => Ok(Operation::Target),
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
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let raw_bytes = u.bytes(u.len())?.to_vec();
        Ok(FuzzInput { ops, raw_bytes })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(127);
const PAGE_CACHE_SIZE: usize = 8;

type Db<F, S> = CompactDb<F, deterministic::Context, Vec<u8>, Sha256, CodecConfig, S>;

fn test_config<S: Strategy>(
    test_name: &str,
    pooler: &impl BufferPooler,
    strategy: S,
) -> CompactConfig<CodecConfig, S> {
    CompactConfig {
        strategy,
        witness: JournalConfig {
            partition: format!("{test_name}-witness"),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            write_buffer: NZUsize!(1024),
        },
        commit_codec_config: ((0..=10000).into(), ()),
    }
}

/// A commit recorded at sync time: the synced size, root, and metadata.
struct SyncedCommit<D> {
    size: u64,
    root: D,
    metadata: Option<Vec<u8>>,
}

fn fuzz_family<F: Family, S: Strategy>(input: &FuzzInput, suffix: &str, strategy: S) {
    let cfg =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| async move {
        let cfg = test_config(suffix, &context, strategy.clone());
        let mut db: Db<F, S> = Db::init(context.child("storage"), cfg.clone())
            .await
            .expect("Failed to init compact keyless db");
        let mut restarts = 0usize;

        let mut pending_appends: Vec<Vec<u8>> = Vec::new();
        // The bootstrap commit is durable, so it is a valid rewind target.
        let mut synced = vec![SyncedCommit {
            size: db.size().as_u64(),
            root: db.root(),
            metadata: db.get_metadata(),
        }];

        for op in &input.ops {
            match op {
                Operation::Append { value_bytes } => {
                    pending_appends.push(value_bytes.clone());
                }

                Operation::Commit {
                    metadata_bytes,
                    floor_kind,
                } => {
                    let pending_count = pending_appends.len() as u64;
                    let commit_loc = db.size().as_u64() + pending_count;
                    let current_floor = db.inactivity_floor_loc();

                    let (floor, expect_err) = match floor_kind {
                        FloorKind::Current => (current_floor, None),
                        FloorKind::AdvanceToCommit => (Location::<F>::new(commit_loc), None),
                        FloorKind::BadRegression => {
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
                            let expected_root = merkleized.root();
                            db.apply_batch(merkleized).expect("Commit should not fail");
                            assert_eq!(db.root(), expected_root);
                        }
                        Some(kind) => {
                            // Snapshot state; the reject must not mutate.
                            let before_size = db.size();
                            let before_floor = db.inactivity_floor_loc();
                            let before_root = db.root();
                            let err = db
                                .apply_batch(merkleized)
                                .expect_err("bad floor must be rejected");
                            assert_bad_floor_error(&err, kind);
                            assert_eq!(db.size(), before_size);
                            assert_eq!(db.inactivity_floor_loc(), before_floor);
                            assert_eq!(db.root(), before_root);
                        }
                    }
                }

                Operation::ChainedCommit => {
                    let floor = db.inactivity_floor_loc();
                    let parent = db
                        .new_batch()
                        .append(vec![0u8; 1])
                        .merkleize(&db, None, floor);
                    let child = parent
                        .new_batch::<Sha256>()
                        .append(vec![1u8; 1])
                        .merkleize(&db, None, floor);
                    let expected_root = child.root();
                    db.apply_batch(child)
                        .expect("Chained commit should not fail");
                    assert_eq!(db.root(), expected_root);
                }

                Operation::StaleBatch => {
                    let floor = db.inactivity_floor_loc();
                    let batch_a = db
                        .new_batch()
                        .append(vec![2u8; 1])
                        .merkleize(&db, None, floor);
                    let batch_b = db
                        .new_batch()
                        .append(vec![3u8; 1])
                        .merkleize(&db, None, floor);
                    db.apply_batch(batch_a).expect("Commit should not fail");
                    assert!(
                        matches!(db.apply_batch(batch_b), Err(Error::StaleBatch { .. })),
                        "second batch from the same state must be stale"
                    );
                }

                Operation::Sync => {
                    db.sync().await.expect("Sync should not fail");
                    let size = db.size().as_u64();
                    if synced.last().map(|c| c.size) != Some(size) {
                        synced.push(SyncedCommit {
                            size,
                            root: db.root(),
                            metadata: db.get_metadata(),
                        });
                    }
                }

                Operation::Rewind { idx } => {
                    let entry = &synced[*idx as usize % synced.len()];
                    let target = entry.size;
                    db.rewind(Location::new(target))
                        .await
                        .expect("Rewind to a synced commit should not fail");
                    synced.retain(|c| c.size <= target);
                    let tip = synced.last().unwrap();
                    assert_eq!(db.size().as_u64(), tip.size);
                    assert_eq!(db.root(), tip.root);
                    assert_eq!(db.get_metadata(), tip.metadata);
                }

                Operation::RewindUnsynced => {
                    // One past the latest synced commit was never persisted, so the rewind
                    // must fail. The handle is fatal after any rewind error: reopen it.
                    let target = synced.last().unwrap().size + 1;
                    let err = db
                        .rewind(Location::new(target))
                        .await
                        .expect_err("rewind to a never-synced size must fail");
                    assert!(
                        matches!(err, Error::Merkle(MerkleError::RewindBeyondHistory)),
                        "unexpected rewind error: {err:?}"
                    );
                    drop(db);
                    pending_appends.clear();
                    db = Db::init(
                        context
                            .child("storage")
                            .with_attribute("instance", restarts),
                        cfg.clone(),
                    )
                    .await
                    .expect("Failed to reopen compact keyless db");
                    restarts += 1;
                    let tip = synced.last().unwrap();
                    assert_eq!(db.size().as_u64(), tip.size);
                    assert_eq!(db.root(), tip.root);
                    assert_eq!(db.get_metadata(), tip.metadata);
                }

                Operation::Prune { idx } => {
                    let boundary = synced[*idx as usize % synced.len()].size;
                    db.prune(Location::new(boundary))
                        .await
                        .expect("Prune should not fail");
                    // Witnesses below the boundary may be gone; stop rewinding to them.
                    synced.retain(|c| c.size >= boundary);
                }

                Operation::Restart => {
                    drop(db);
                    pending_appends.clear();
                    db = Db::init(
                        context
                            .child("storage")
                            .with_attribute("instance", restarts),
                        cfg.clone(),
                    )
                    .await
                    .expect("Failed to reopen compact keyless db");
                    restarts += 1;
                    // Unsynced state is discarded; the reopened db is the last synced commit.
                    let tip = synced.last().unwrap();
                    assert_eq!(db.size().as_u64(), tip.size);
                    assert_eq!(db.root(), tip.root);
                    assert_eq!(db.get_metadata(), tip.metadata);
                }

                Operation::Root => {
                    let _ = db.root();
                }

                Operation::GetMetadata => {
                    let _ = db.get_metadata();
                }

                Operation::Target => {
                    let _ = db.target();
                }
            }
        }

        // Compact-sync round-trip: rebuild a fresh db from the source's persisted compact witness,
        // exercising compact_state, init_from_validated_state, and Store::from_import.
        db.sync().await.expect("Sync should not fail");
        let target = db.target();
        let source = Arc::new(db);
        let client_cfg = test_config(&format!("{suffix}-client"), &context, strategy.clone());
        let client: Db<F, S> = compact_sync::sync(compact_sync::Config {
            context: context.child("client"),
            resolver: source.clone(),
            target: target.clone(),
            db_config: client_cfg.clone(),
        })
        .await
        .expect("Compact sync should not fail");
        assert_eq!(client.root(), target.root);
        assert_eq!(client.get_metadata(), source.get_metadata());
        drop(client);

        // Reopen from disk: the imported witness must persist across a restart.
        let reopened: Db<F, S> = Db::init(context.child("client_reopen"), client_cfg)
            .await
            .expect("Failed to reopen imported client");
        assert_eq!(reopened.root(), target.root);
        assert_eq!(reopened.get_metadata(), source.get_metadata());
        reopened.destroy().await.expect("Destroy should not fail");

        let db = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("single source ref"));
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family, Sequential>(&input, "fuzz-mmr-sequential", Sequential);
    fuzz_family::<mmb::Family, Sequential>(&input, "fuzz-mmb-sequential", Sequential);
    fuzz_family::<mmr::Family, Rayon>(&input, "fuzz-mmr-rayon", Rayon::new(NZUsize!(2)).unwrap());
    fuzz_family::<mmb::Family, Rayon>(&input, "fuzz-mmb-rayon", Rayon::new(NZUsize!(2)).unwrap());
});
