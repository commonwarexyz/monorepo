use super::*;
use crate::qmdb::{any::operation::Operation, compaction::CompactionBudget};
use commonware_codec::Encode;

const ONE: CompactionBudget = CompactionBudget {
    max_moves: 1,
    max_scan: u64::MAX,
};

macro_rules! parity {
    ($db:ty, $config:expr) => {{
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let config = $config(&context);
            let db = <$db>::init(context.child("db"), config).await.unwrap();
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
                let make = || {
                    ancestors
                        .last()
                        .map_or_else(|| db.new_batch(), |parent| parent.new_batch::<Sha256>())
                        .write(key(150), Some(val(999)))
                };
                let automatic = make().merkleize(&db, Some(val(10))).await.unwrap();
                let prepared = make().prepare(&db).await.unwrap();
                assert_eq!(prepared.default_compaction_budget().max_moves, 2);
                let (prepared, first) = prepared.compact(&db, ONE).await.unwrap();
                let (prepared, second) = prepared.compact(&db, ONE).await.unwrap();
                assert_eq!((first.moved, second.moved), (1, 1));
                assert!(second.floor > first.floor);
                let manual = prepared.merkleize(&db, Some(val(10))).await.unwrap();
                assert_eq!(automatic.root(), manual.root());
                let encode = |ops: &[_]| ops.iter().map(Encode::encode).collect::<Vec<_>>();
                assert_eq!(
                    encode(&automatic.operations().1),
                    encode(&manual.operations().1)
                );
                assert_eq!(
                    manual
                        .operations()
                        .1
                        .iter()
                        .filter(|op| matches!(op, Operation::CommitFloor(..)))
                        .count(),
                    1
                );

                let prepared = make().prepare(&db).await.unwrap();
                let floor = prepared.inactivity_floor();
                let disabled = prepared.merkleize(&db, None).await.unwrap();
                assert_eq!(disabled.bounds().inactivity_floor, floor);
                assert_eq!(disabled.operations().1.len(), 2); // User update and CommitFloor only.
                let (updated, _) = db.apply_batch(disabled).await.unwrap();
                db = updated;
                assert_eq!(db.get(&key(150)).await.unwrap(), Some(val(999)));
            }
        });
    }};
}

#[test]
fn manual_compaction_matches_default_ordered() {
    parity!(OrderedVariableDb, |ctx| variable_config::<OneCap>(
        "ordered", ctx
    ));
}

#[test]
fn manual_compaction_matches_default_unordered() {
    parity!(UnorderedVariableDb, |ctx| variable_config::<OneCap>(
        "unordered",
        ctx
    ));
}

#[test]
fn manual_compaction_matches_default_any_ordered() {
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
fn manual_compaction_matches_default_any_unordered() {
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
fn manual_compaction_resumes_across_inactive_pages_and_recovers() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let config = || variable_config::<OneCap>("bounded", &context);
        let db = UnorderedVariableDb::init(context.child("first"), config())
            .await
            .unwrap();
        let mut batch = db.new_batch();
        for i in 0..300 {
            batch = batch.write(key(i), Some(val(i)));
        }
        let batch = batch
            .prepare(&db)
            .await
            .unwrap()
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        let mut batch = db.new_batch();
        for i in 0..300 {
            batch = batch.write(key(i), Some(val(i + 1000)));
        }
        let batch = batch
            .prepare(&db)
            .await
            .unwrap()
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        let prepared = db.new_batch().prepare(&db).await.unwrap();
        let (prepared, zero) = prepared
            .compact(
                &db,
                CompactionBudget {
                    max_moves: 0,
                    max_scan: u64::MAX,
                },
            )
            .await
            .unwrap();
        assert_eq!((zero.moved, zero.scanned, *zero.floor), (0, 0, 0));
        let (prepared, zero) = prepared
            .compact(
                &db,
                CompactionBudget {
                    max_moves: u64::MAX,
                    max_scan: 0,
                },
            )
            .await
            .unwrap();
        assert_eq!((zero.moved, zero.scanned), (0, 0));
        let (prepared, gap) = prepared
            .compact(
                &db,
                CompactionBudget {
                    max_moves: 1,
                    max_scan: 256,
                },
            )
            .await
            .unwrap();
        assert_eq!((gap.moved, gap.scanned, *gap.floor), (0, 256, 256));
        assert!(!gap.exhausted);
        // Committing after a round must preserve progress through inactive gaps.
        let batch = prepared.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        let prepared = db.new_batch().prepare(&db).await.unwrap();
        let (prepared, gap) = prepared
            .compact(
                &db,
                CompactionBudget {
                    max_moves: 1,
                    max_scan: 46,
                },
            )
            .await
            .unwrap();
        assert_eq!((gap.moved, gap.scanned, *gap.floor), (0, 46, 302));
        let (prepared, moved) = prepared
            .compact(
                &db,
                CompactionBudget {
                    max_moves: 1,
                    max_scan: 1,
                },
            )
            .await
            .unwrap();
        assert_eq!((moved.moved, moved.scanned, *moved.floor), (1, 1, 303));
        let batch = prepared.merkleize(&db, Some(val(42))).await.unwrap();
        let root = batch.root();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        let db = db.sync().await.unwrap();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        assert_eq!(db.root(), root);
        drop(db);
        let db = UnorderedVariableDb::init(context.child("reopen"), config())
            .await
            .unwrap();
        assert_eq!(db.root(), root);
        for i in 0..300 {
            assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i + 1000)));
        }
    });
}

#[test]
fn manual_compaction_exhaustion_does_not_recopy_moved_entries() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let db = UnorderedVariableDb::init(
            context.child("db"),
            variable_config::<OneCap>("exhaust", &context),
        )
        .await
        .unwrap();
        let prepared = db
            .new_batch()
            .write(key(1), Some(val(1)))
            .write(key(2), Some(val(2)))
            .prepare(&db)
            .await
            .unwrap();
        let (prepared, first) = prepared.compact(&db, ONE).await.unwrap();
        let (prepared, second) = prepared
            .compact(
                &db,
                CompactionBudget {
                    max_moves: u64::MAX,
                    max_scan: u64::MAX,
                },
            )
            .await
            .unwrap();
        let (prepared, exhausted) = prepared.compact(&db, ONE).await.unwrap();
        assert_eq!((first.moved, second.moved, exhausted.moved), (1, 1, 0));
        assert!(second.exhausted && exhausted.exhausted);
        let batch = prepared.merkleize(&db, None).await.unwrap();
        assert_eq!(batch.operations().1.len(), 5); // Two creates, two moves, one commit.
        let (db, _) = db.apply_batch(batch).await.unwrap();
        let prepared = db
            .new_batch()
            .write(key(1), None)
            .write(key(2), None)
            .prepare(&db)
            .await
            .unwrap();
        let (prepared, empty) = prepared.compact(&db, ONE).await.unwrap();
        assert_eq!((empty.moved, empty.scanned), (0, 0));
        assert!(empty.exhausted);
        let batch = prepared.merkleize(&db, None).await.unwrap();
        assert_eq!(batch.bounds().inactivity_floor, batch.bounds().tip.size - 1);
        let (db, _) = db.apply_batch(batch).await.unwrap();
        assert!(db.is_empty());
    });
}

#[test]
fn manual_compaction_rejects_changed_database() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let db = UnorderedVariableDb::init(
            context.child("db"),
            variable_config::<OneCap>("stale", &context),
        )
        .await
        .unwrap();
        let first = db.new_batch().prepare(&db).await.unwrap();
        let second = db.new_batch().prepare(&db).await.unwrap();
        let other = db
            .new_batch()
            .write(key(1), Some(val(1)))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(other).await.unwrap();
        assert!(matches!(
            first.compact(&db, ONE).await,
            Err(Error::StaleBatch)
        ));
        assert!(matches!(
            second.merkleize(&db, None).await,
            Err(Error::StaleBatch)
        ));
    });
}
