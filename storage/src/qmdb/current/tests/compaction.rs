use super::*;
use crate::qmdb::{
    any::operation::Operation,
    compaction::{CompactionBudget, CompactionStats},
};
use commonware_codec::Encode;

const ONE: CompactionBudget = CompactionBudget {
    max_moves: 1,
    max_scan: u64::MAX,
};

const SKIP: CompactionBudget = CompactionBudget {
    max_moves: 0,
    max_scan: 0,
};

macro_rules! parity {
    ($db:ty, $config:expr) => {{
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let config = $config(&context);
            let db = <$db>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let mut seed = db.new_batch();
            for i in 0..300 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed = seed.merkleize(&db, None).await.unwrap();
            let (mut db, _) = db.apply_batch(seed).await.unwrap();

            for depth in 0..=2 {
                let mut ancestors = Vec::new();
                if depth > 0 {
                    let mut parent = db.new_batch();
                    for i in 0..300 {
                        parent = parent.write(key(i), Some(val(i + 1000)));
                    }
                    let parent = parent.merkleize(&db, None).await.unwrap();
                    if depth == 2 {
                        let child = parent
                            .new_batch::<Sha256>()
                            .write(key(1), None)
                            .write(key(2), Some(val(2000)))
                            .merkleize(&db, None)
                            .await
                            .unwrap();
                        ancestors.push(parent);
                        ancestors.push(child);
                    } else {
                        ancestors.push(parent);
                    }
                }
                let (base_floor, base_tip) = ancestors.last().map_or_else(
                    || (db.inactivity_floor_loc(), db.bounds().end),
                    |parent| (parent.bounds().inactivity_floor, parent.bounds().tip.size),
                );
                let make = || {
                    ancestors
                        .last()
                        .map_or_else(|| db.new_batch(), |parent| parent.new_batch::<Sha256>())
                        .write(key(150), Some(val(999)))
                };
                let encode = |ops: &[_]| ops.iter().map(Encode::encode).collect::<Vec<_>>();

                // The plan sees the resolved batch before compaction: one update of an existing
                // key, appended at the parent's tip.
                let mut seen = None;
                let explicit = make()
                    .merkleize_with_compaction_plan(&db, |stats| {
                        seen = Some(stats);
                        (stats.default_budget(), Some(val(10)))
                    })
                    .await
                    .unwrap();
                let stats: CompactionStats<_> = seen.unwrap();
                assert_eq!(stats.user_steps, 1);
                assert_eq!(stats.inactivity_floor, base_floor);
                assert_eq!(*stats.tip, *base_tip + 1);
                assert_eq!(
                    stats.default_budget(),
                    CompactionBudget {
                        max_moves: 2,
                        max_scan: u64::MAX,
                    }
                );

                // Planning with the default budget matches automatic merkleization.
                let automatic = make().merkleize(&db, Some(val(10))).await.unwrap();
                assert_eq!(automatic.root(), explicit.root());
                assert_eq!(
                    encode(&automatic.operations().1),
                    encode(&explicit.operations().1)
                );

                let bounded = make()
                    .merkleize_with_compaction_plan(&db, |_| (ONE, None))
                    .await
                    .unwrap();
                let ops = bounded.operations().1;
                assert_eq!(ops.len(), 3); // User update, one move, and CommitFloor.
                assert_eq!(
                    ops.iter()
                        .filter(|op| matches!(op, Operation::CommitFloor(..)))
                        .count(),
                    1
                );
                assert!(bounded.bounds().inactivity_floor > base_floor);

                for budget in [
                    SKIP,
                    CompactionBudget {
                        max_moves: 0,
                        max_scan: u64::MAX,
                    },
                    CompactionBudget {
                        max_moves: u64::MAX,
                        max_scan: 0,
                    },
                ] {
                    let skipped = make()
                        .merkleize_with_compaction_plan(&db, |_| (budget, None))
                        .await
                        .unwrap();
                    assert_eq!(skipped.bounds().inactivity_floor, base_floor);
                    assert_eq!(skipped.operations().1.len(), 2); // User update and CommitFloor.
                }

                let skipped = make()
                    .merkleize_with_compaction_plan(&db, |_| (SKIP, None))
                    .await
                    .unwrap();
                let (updated, _) = db.apply_batch(skipped).await.unwrap();
                db = updated;
                assert_eq!(db.get(&key(150)).await.unwrap(), Some(val(999)));
            }
        });
    }};
}

#[test]
fn bounded_compaction_matches_default_ordered() {
    parity!(OrderedVariableDb, |ctx| variable_config::<OneCap>(
        "ordered", ctx
    ));
}

#[test]
fn bounded_compaction_matches_default_unordered() {
    parity!(UnorderedVariableDb, |ctx| variable_config::<OneCap>(
        "unordered",
        ctx
    ));
}

#[test]
fn bounded_compaction_matches_default_any_ordered() {
    type AnyDb = crate::qmdb::any::ordered::variable::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        Sequential,
    >;
    parity!(AnyDb, |ctx| variable_config::<OneCap>("any", ctx).into());
}

#[test]
fn bounded_compaction_matches_default_any_unordered() {
    type AnyDb = crate::qmdb::any::unordered::variable::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        Sequential,
    >;
    parity!(AnyDb, |ctx| variable_config::<OneCap>("any-unordered", ctx)
        .into());
}

#[test]
fn bounded_compaction_progresses_across_inactive_gaps_and_recovers() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let config = || variable_config::<OneCap>("bounded", &context);
        let db = UnorderedVariableDb::init(context.child("first"), config(), None)
            .await
            .unwrap();

        // Leave the floor at 0 with 301 inactive locations below the 300 active updates.
        let mut batch = db.new_batch();
        for i in 0..300 {
            batch = batch.write(key(i), Some(val(i)));
        }
        let batch = batch
            .merkleize_with_compaction_plan(&db, |_| (SKIP, None))
            .await
            .unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        let mut batch = db.new_batch();
        for i in 0..300 {
            batch = batch.write(key(i), Some(val(i + 1000)));
        }
        let batch = batch
            .merkleize_with_compaction_plan(&db, |_| (SKIP, None))
            .await
            .unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        assert_eq!(*db.inactivity_floor_loc(), 0);

        // Compact only while active keys fill less than `percent` of the retained range, and
        // record the active-key count in the metadata.
        let plan = |percent: u64, scan: u64| {
            move |stats: CompactionStats<_>| {
                let retained = *stats.tip - *stats.inactivity_floor;
                let sparse = retained * percent > stats.total_active_keys as u64 * 100;
                let budget = CompactionBudget {
                    max_moves: stats.user_steps + 1,
                    max_scan: if sparse { scan } else { 0 },
                };
                (budget, Some(val(stats.total_active_keys as u64)))
            }
        };

        // A scan limit crossing only inactive locations still advances the floor.
        let mut seen = None;
        let batch = db
            .new_batch()
            .merkleize_with_compaction_plan(&db, |stats| {
                seen = Some(stats);
                plan(100, 256)(stats)
            })
            .await
            .unwrap();
        let stats = seen.unwrap();
        assert_eq!(
            (stats.user_steps, stats.total_active_keys),
            (0, 300)
        );
        assert_eq!((*stats.inactivity_floor, *stats.tip), (0, 603));
        assert_eq!(*batch.bounds().inactivity_floor, 256);
        assert_eq!(batch.operations().1.len(), 1); // CommitFloor only.
        let (db, _) = db.apply_batch(batch).await.unwrap();

        // The next commit resumes from the committed floor.
        let batch = db
            .new_batch()
            .merkleize_with_compaction_plan(&db, plan(100, 46))
            .await
            .unwrap();
        assert_eq!(*batch.bounds().inactivity_floor, 302);
        assert_eq!(batch.operations().1.len(), 1);
        let (db, _) = db.apply_batch(batch).await.unwrap();

        let batch = db
            .new_batch()
            .merkleize_with_compaction_plan(&db, plan(100, 1))
            .await
            .unwrap();
        assert_eq!(*batch.bounds().inactivity_floor, 303);
        assert_eq!(batch.operations().1.len(), 2); // One move and CommitFloor.
        let root = batch.root();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        let db = db.sync().await.unwrap();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        assert_eq!(db.root(), root);
        drop(db);
        let db = UnorderedVariableDb::init(context.child("reopen"), config(), None)
            .await
            .unwrap();
        assert_eq!(db.root(), root);
        assert_eq!(*db.inactivity_floor_loc(), 303);
        assert_eq!(db.get_metadata().await.unwrap(), Some(val(300)));
        for i in 0..300 {
            assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i + 1000)));
        }

        // Above 90% density, a 90% policy skips compaction.
        let mut seen = None;
        let batch = db
            .new_batch()
            .merkleize_with_compaction_plan(&db, |stats| {
                seen = Some(stats);
                plan(90, u64::MAX)(stats)
            })
            .await
            .unwrap();
        let stats = seen.unwrap();
        assert_eq!((*stats.inactivity_floor, *stats.tip), (303, 607));
        assert_eq!(batch.bounds().inactivity_floor, stats.inactivity_floor);
        assert_eq!(batch.operations().1.len(), 1);
    });
}

#[test]
fn bounded_compaction_does_not_recopy_moved_entries() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let db = UnorderedVariableDb::init(
            context.child("db"),
            variable_config::<OneCap>("exhaust", &context),
            None,
        )
        .await
        .unwrap();
        let unbounded = CompactionBudget {
            max_moves: u64::MAX,
            max_scan: u64::MAX,
        };
        let batch = db
            .new_batch()
            .write(key(1), Some(val(1)))
            .write(key(2), Some(val(2)))
            .merkleize_with_compaction_plan(&db, |_| (unbounded, None))
            .await
            .unwrap();
        assert_eq!(batch.operations().1.len(), 5); // Two creates, two moves, one commit.
        let (db, _) = db.apply_batch(batch).await.unwrap();

        // An empty post-state starts compaction at the tip, leaving nothing to scan.
        let mut seen = None;
        let batch = db
            .new_batch()
            .write(key(1), None)
            .write(key(2), None)
            .merkleize_with_compaction_plan(&db, |stats| {
                seen = Some(stats);
                (ONE, None)
            })
            .await
            .unwrap();
        let stats = seen.unwrap();
        assert_eq!((stats.user_steps, stats.total_active_keys), (2, 0));
        assert_eq!(stats.inactivity_floor, stats.tip);
        assert_eq!(batch.operations().1.len(), 3); // Two deletes and CommitFloor.
        assert_eq!(batch.bounds().inactivity_floor, batch.bounds().tip.size - 1);
        let (db, _) = db.apply_batch(batch).await.unwrap();
        assert!(db.is_empty());
    });
}
