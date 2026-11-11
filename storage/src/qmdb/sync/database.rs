use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location},
    qmdb::{
        operation::Floored,
        sync::{Journal, Target},
    },
    translator::Translator,
};
use commonware_codec::{Encode, EncodeShared};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::{future::Future, num::NonZeroU64};

/// Database configuration that can produce the configuration for its sync journal.
pub trait Config {
    /// Configuration for the journal the sync engine fills before building the database.
    type JournalConfig;

    /// Return the configuration for the sync journal.
    fn journal_config(&self) -> Self::JournalConfig;
}

impl<T: Translator, J: Clone, S: Strategy, B> Config for crate::qmdb::any::Config<T, J, S, B> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
    }
}

impl<T: Translator, C: Clone, S: Strategy> Config for crate::qmdb::immutable::Config<T, C, S> {
    type JournalConfig = C;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
    }
}

impl<J: Clone, S: Strategy> Config for crate::qmdb::keyless::Config<J, S> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
    }
}

impl<C: Clone + Send + Sync + 'static, S: Strategy> Config for crate::qmdb::compact::Config<C, S> {
    type JournalConfig = ();

    fn journal_config(&self) -> Self::JournalConfig {}
}

/// A database that [`sync`](super::sync) can build from operations fetched from a [`Source`].
///
/// Every authenticated QMDB variant implements this trait, and callers drive it through
/// [`sync`](super::sync): the engine calls [`Self::local_pinned_nodes`] when a sync journal left
/// on disk already reaches the target, fetches and verifies the remaining operations, builds the
/// database with [`Self::from_sync_result`], checks [`Self::ops_root`] against the target, and only
/// then calls [`Self::persist_sync_result`].
///
/// [`Source`]: super::Source
pub trait Database: Sized + Send {
    /// The Merkle family of the operations log.
    type Family: Family;

    /// The operation type stored in the log.
    type Op: Encode + Send + Sync;

    /// The journal the engine fills with fetched operations.
    type Journal: Journal<Self::Family, Context = Self::Context, Op = Self::Op>;

    /// The database configuration, which also configures the sync journal.
    type Config: Config<JournalConfig = <Self::Journal as Journal<Self::Family>>::Config>;

    /// The digest type of the database's root.
    type Digest: Digest;

    /// The runtime context the database is built in.
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;

    /// The hasher producing [`Self::Digest`].
    type Hasher: commonware_cryptography::Hasher<Digest = Self::Digest>;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<Self::Family>>,
        apply_batch_size: NonZeroU64,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Persist any state that must remain provisional until the engine verifies the rebuilt root.
    ///
    /// The engine calls this only after [`Self::ops_root`] matches the requested target.
    /// Implementations that persist everything in [`Self::from_sync_result`] must explicitly
    /// return `Ok(self)`.
    fn persist_sync_result(
        self,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Return pinned nodes for the target computed from local state, if it can provide them.
    ///
    /// Returning `Some` lets a completed sync journal reuse pinned nodes from an on-disk
    /// database instead of fetching them from peers. The sync checks the resulting root against
    /// the target's. Returning `None` always falls back to fetching from peers.
    fn local_pinned_nodes(
        context: Self::Context,
        config: &Self::Config,
        target: &crate::qmdb::sync::Target<Self::Family, Self::Digest>,
        journal: &Self::Journal,
    ) -> impl Future<Output = Result<Option<Vec<Self::Digest>>, crate::qmdb::Error<Self::Family>>> + Send;

    /// Return the operations root the engine compares against the target.
    ///
    /// For [`current`](crate::qmdb::current), this differs from the canonical database root.
    fn ops_root(&self) -> Self::Digest;
}

/// Whether a completed sync journal's `bounds` cover `range`: retained data reaches back to
/// `range.start()` and ends exactly at `range.end()`.
pub(crate) fn journal_covers_range<F: Family>(
    bounds: std::ops::Range<u64>,
    range: &NonEmptyRange<Location<F>>,
) -> bool {
    Location::new(bounds.start) <= range.start() && Location::new(bounds.end) == range.end()
}

/// Shared body for [`Database::local_pinned_nodes`] implementations backed by an authenticated
/// journal. Returns the pinned nodes at `target.range.start()`, rebuilt by replaying `journal`
/// from the boundary of the frontier read from `config` through its end. Returns `None`
/// if that boundary lies after the target start, `journal` does not hold the operations from the
/// boundary through the target start, or the rebuilt root differs from the target root.
pub(crate) async fn local_pinned_nodes<F, E, H, S>(
    context: E,
    config: authenticated::Config<S>,
    target: &Target<F, H::Digest>,
    journal: &impl Contiguous<Item: EncodeShared + Floored<F>>,
) -> Result<Option<Vec<H::Digest>>, crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = crate::qmdb::hasher::<H>();
    let floor = crate::qmdb::find_inactivity_floor_at(journal, target.range.end()).await?;
    let inactive_peaks = F::inactive_peaks(target.range.end(), floor);
    Ok(authenticated::pinned_nodes_from_frontier(
        context,
        &config,
        journal,
        &hasher,
        target.range.start(),
        target.root,
        inactive_peaks,
    )
    .await?)
}

#[cfg(test)]
mod tests {
    use super::{Journal as _, journal_covers_range, local_pinned_nodes};
    use crate::{
        journal::{authenticated, contiguous::fixed},
        merkle::{Location, mmr::Family as MmrFamily},
        qmdb::{
            keyless::{self, fixed::Operation},
            sync::{
                self, Request, Source as _, Target,
                engine::Config,
                source::tests::{FailSource, SequenceSource},
            },
        },
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{
        NZU16, NZU64, NZUsize, non_empty_range, range::NonEmptyRange, sequence::U64,
    };
    use std::sync::Arc;

    type Op = Operation<MmrFamily, U64>;
    type Ops = fixed::Journal<deterministic::Context, Op>;

    fn merkle_config() -> authenticated::Config<Sequential> {
        authenticated::Config {
            partition: "local-pins-metadata".into(),
            resident_height: Default::default(),
            replay_buffer: NZUsize!(1024),
            replay_concurrency: NZUsize!(2),
            strategy: Sequential,
        }
    }

    fn journal_config() -> fixed::Config {
        fixed::Config {
            partition: "local-pins-journal".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            page_cache: CacheRef::new(NZU16!(111), NZUsize!(5)),
        }
    }

    /// When the local journal covers the target start, a sync keeps the earlier operations until
    /// it records the new boundary, even if the source fails. A sync to a target the local
    /// operations already authenticate rebuilds the pins from them without asking the source.
    #[test]
    fn sync_keeps_operations_until_the_boundary_moves() {
        deterministic::Runner::default().start(|context| async move {
            type Db =
                keyless::fixed::Db<MmrFamily, deterministic::Context, U64, Sha256, Sequential>;
            let config = keyless::Config {
                merkle: merkle_config(),
                log: journal_config(),
            };

            // Create 51 operations ending in a commit whose inactivity floor is 30.
            let mut db = Db::init(context.child("create"), config.clone(), None)
                .await
                .unwrap();
            let mut batch = db.new_batch();
            for value in 0..49 {
                batch = batch.append(U64::new(value));
            }
            let batch = batch
                .with_inactivity_floor(Location::new(30))
                .merkleize(&db)
                .await
                .unwrap();
            db = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root = db.root();
            assert_eq!(db.bounds(), Location::new(0)..Location::new(51));
            drop(db);

            // The frontier is still at 0, behind the target start 30.
            let sync_to = |label, end| {
                sync::sync::<Db, _>(Config {
                    context: context.child(label),
                    source: FailSource::<MmrFamily, Op, Digest>::new(),
                    target: Target {
                        root,
                        range: non_empty_range!(Location::new(30), Location::new(end)),
                    },
                    max_outstanding_requests: NZUsize!(1),
                    fetch_batch_size: NZU64!(10),
                    apply_batch_size: NZU64!(10),
                    db_config: config.clone(),
                    update_rx: None,
                    finish_rx: None,
                    reached_target_tx: None,
                })
            };

            // A sync to a size the source cannot serve fails and leaves the local operations and
            // root unchanged.
            assert!(matches!(
                sync_to("failed", 60).await,
                Err(sync::Error::Source(_))
            ));
            let db = Db::init(context.child("after_failure"), config.clone(), None)
                .await
                .unwrap();
            assert_eq!(db.bounds(), Location::new(0)..Location::new(51));
            assert_eq!(db.root(), root);
            drop(db);

            // A sync to the size the database already holds rebuilds its pins locally without
            // asking the failing source. It then records the target start 30 as its boundary,
            // which persists across a reopen.
            let db = sync_to("local", 51).await.unwrap();
            assert_eq!(db.bounds(), Location::new(30)..Location::new(51));
            assert_eq!(db.root(), root);
            drop(db);
            let db = Db::init(context.child("reopen"), config, None)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
        });
    }

    #[test]
    fn test_journal_covers_range() {
        let range: NonEmptyRange<Location<MmrFamily>> =
            non_empty_range!(Location::new(10), Location::new(20));

        // Bounds reaching at least back to the start and ending exactly at the end cover.
        assert!(journal_covers_range(10..20, &range));
        assert!(journal_covers_range(5..20, &range));

        // Bounds starting after the range start do not cover.
        assert!(!journal_covers_range(11..20, &range));

        // Bounds ending anywhere but exactly at the range end do not cover.
        assert!(!journal_covers_range(10..19, &range));
        assert!(!journal_covers_range(10..21, &range));
        assert!(!journal_covers_range(0..0, &range));
    }

    #[test]
    fn sync_fetches_pins_for_a_different_local_prefix() {
        deterministic::Runner::default().start(|context| async move {
            // Build a local and a source database in separate partitions. Each holds one append
            // at location 1 with a distinct value and a commit at 2, so they share a size of 3 but
            // differ in root.
            type Db =
                keyless::fixed::Db<MmrFamily, deterministic::Context, U64, Sha256, Sequential>;
            let local_config = keyless::Config {
                merkle: merkle_config(),
                log: journal_config(),
            };
            let mut source_config = local_config.clone();
            source_config.merkle.partition.push_str("-source");
            source_config.log.partition.push_str("-source");
            let populate = |label: &'static str, config, value| {
                let context = context.child(label);
                async move {
                    let db = Db::init(context, config, None).await.unwrap();
                    let batch = db
                        .new_batch()
                        .append(U64::new(value))
                        .with_inactivity_floor(Location::new(0))
                        .merkleize(&db)
                        .await
                        .unwrap();
                    db.apply_batch(batch).await.unwrap().sync().await.unwrap()
                }
            };
            let local = populate("local", local_config.clone(), 11).await;
            let source_db = populate("source", source_config, 22).await;
            assert_eq!(local.bounds(), Location::new(0)..Location::new(3));
            assert_ne!(local.root(), source_db.root());
            drop(local);

            // The source answers only one request, with its boundary at start 2. The local
            // journal already holds the target range 2..3, but its pins rebuild the local root, so
            // the sync must request this boundary.
            let root = source_db.root();
            let response = source_db
                .serve(Request::Boundary {
                    size: Location::new(3),
                    start: Location::new(2),
                })
                .await
                .unwrap()
                .0;
            let source = SequenceSource::new(vec![response]);
            let observed = source.clone();
            let db = sync::sync::<Db, _>(Config {
                context: context.child("sync"),
                source,
                target: Target {
                    root,
                    range: non_empty_range!(Location::new(2), Location::new(3)),
                },
                max_outstanding_requests: NZUsize!(1),
                fetch_batch_size: NZU64!(1),
                apply_batch_size: NZU64!(1),
                db_config: local_config.clone(),
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            })
            .await
            .unwrap();

            // The engine accepts the source's boundary, and the synced root survives a reopen.
            assert_eq!(db.root(), root);
            assert_eq!(observed.take_verdicts().await, vec![true]);
            drop(db);
            let reopened = Db::init(context.child("reopen"), local_config, None)
                .await
                .unwrap();
            assert_eq!(reopened.root(), root);
        });
    }

    /// When the local operations end before the target's start, opening the sync resets them, so
    /// a sync interrupted before it records its boundary leaves a database that can't be opened.
    /// Retrying the sync completes it.
    #[test]
    fn interrupted_sync_after_reset_is_retried() {
        deterministic::Runner::default().start(|context| async move {
            type Db =
                keyless::fixed::Db<MmrFamily, deterministic::Context, U64, Sha256, Sequential>;
            let local_config = keyless::Config {
                merkle: merkle_config(),
                log: journal_config(),
            };
            let mut source_config = local_config.clone();
            source_config.merkle.partition.push_str("-source");
            source_config.log.partition.push_str("-source");

            // The local database ends at 3, before the target's start at 30.
            let populate = |label: &'static str, config, values: u64| {
                let context = context.child(label);
                async move {
                    let db = Db::init(context, config, None).await.unwrap();
                    let mut batch = db.new_batch();
                    for value in 0..values {
                        batch = batch.append(U64::new(value));
                    }
                    let batch = batch
                        .with_inactivity_floor(Location::new(0))
                        .merkleize(&db)
                        .await
                        .unwrap();
                    db.apply_batch(batch).await.unwrap().sync().await.unwrap()
                }
            };
            drop(populate("local", local_config.clone(), 1).await);
            let source_db = Arc::new(populate("source", source_config, 39).await);
            let target = Target {
                root: source_db.root(),
                range: non_empty_range!(Location::new(30), Location::new(41)),
            };
            // A source that fails every request interrupts the sync after the reset.
            assert!(matches!(
                sync::sync::<Db, _>(Config {
                    context: context.child("failed"),
                    source: FailSource::<MmrFamily, Op, Digest>::new(),
                    target: target.clone(),
                    max_outstanding_requests: NZUsize!(1),
                    fetch_batch_size: NZU64!(4),
                    apply_batch_size: NZU64!(4),
                    db_config: local_config.clone(),
                    update_rx: None,
                    finish_rx: None,
                    reached_target_tx: None,
                })
                .await,
                Err(sync::Error::Source(_))
            ));
            assert!(
                Db::init(context.child("reopen"), local_config.clone(), None)
                    .await
                    .is_err()
            );

            // Retrying the sync records the target's boundary, and the database opens again.
            let db = sync::sync::<Db, _>(Config {
                context: context.child("retry"),
                source: source_db,
                target: target.clone(),
                max_outstanding_requests: NZUsize!(1),
                fetch_batch_size: NZU64!(4),
                apply_batch_size: NZU64!(4),
                db_config: local_config.clone(),
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            })
            .await
            .unwrap();
            assert_eq!(db.root(), target.root);
            drop(db);
            let db = Db::init(context.child("after_retry"), local_config, None)
                .await
                .unwrap();
            assert_eq!(db.root(), target.root);
            assert_eq!(db.bounds(), Location::new(30)..Location::new(41));
        });
    }

    /// A sync whose root check fails writes no frontier and prunes nothing. Here the local journal
    /// already reaches the target end, so nothing is fetched and the database reopens at its
    /// previous state, while the source's pins and the kept local operations rebuild a root
    /// matching neither.
    #[test]
    fn sync_with_mismatched_root_leaves_the_database_as_it_was() {
        deterministic::Runner::default().start(|context| async move {
            // The local and source databases hold the same commits at 0, 2 and 4, and different
            // values at 1 and 3.
            type Db =
                keyless::fixed::Db<MmrFamily, deterministic::Context, U64, Sha256, Sequential>;
            let local_config = keyless::Config {
                merkle: merkle_config(),
                log: journal_config(),
            };
            let mut source_config = local_config.clone();
            source_config.merkle.partition.push_str("-source");
            source_config.log.partition.push_str("-source");
            let populate = |label: &'static str, config, values: [u64; 2]| {
                let context = context.child(label);
                async move {
                    let mut db = Db::init(context, config, None).await.unwrap();
                    for value in values {
                        let batch = db
                            .new_batch()
                            .append(U64::new(value))
                            .with_inactivity_floor(Location::new(0))
                            .merkleize(&db)
                            .await
                            .unwrap();
                        db = db.apply_batch(batch).await.unwrap();
                    }
                    db.sync().await.unwrap()
                }
            };
            let local = populate("local", local_config.clone(), [11, 13]).await;
            let source_db = populate("source", source_config, [22, 24]).await;
            let local_root = local.root();
            assert_eq!(local.bounds(), Location::new(0)..Location::new(5));
            drop(local);

            // The local journal already reaches the target end, so the sync fetches only the
            // source's pins at 2 and keeps the local operations from 2.
            let root = source_db.root();
            let response = source_db
                .serve(Request::Boundary {
                    size: Location::new(5),
                    start: Location::new(2),
                })
                .await
                .unwrap()
                .0;
            let result = sync::sync::<Db, _>(Config {
                context: context.child("sync"),
                source: SequenceSource::new(vec![response]),
                target: Target {
                    root,
                    range: non_empty_range!(Location::new(2), Location::new(5)),
                },
                max_outstanding_requests: NZUsize!(1),
                fetch_batch_size: NZU64!(1),
                apply_batch_size: NZU64!(1),
                db_config: local_config.clone(),
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            })
            .await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::RootMismatch { .. }))
            ));

            // The local frontier and operations are untouched.
            let reopened = Db::init(context.child("reopen"), local_config, None)
                .await
                .unwrap();
            assert_eq!(reopened.bounds(), Location::new(0)..Location::new(5));
            assert_eq!(reopened.root(), local_root);
        });
    }

    /// Local pins come from replaying the sync journal from the frontier's boundary, and are
    /// unavailable once the sync journal no longer holds the operations from that boundary.
    #[test]
    fn local_pinned_nodes_replay_from_the_frontier() {
        deterministic::Runner::default().start(|context| async move {
            // Build a log of 50 operations ending in a commit with floor 0, then prune it so the
            // frontier records boundary 28. The root and the pins at 30 are what a local replay
            // must reproduce.
            type Log =
                authenticated::Journal<MmrFamily, deterministic::Context, Ops, Sha256, Sequential>;
            let mut log = Log::new(
                context.child("init"),
                merkle_config(),
                journal_config(),
                |_| true,
                crate::qmdb::ROOT_BAGGING,
            )
            .await
            .unwrap();
            for i in 0..49 {
                (log, _) = log.append(&Op::Append(U64::new(i))).await.unwrap();
            }
            (log, _) = log
                .append(&Op::Commit(None, Location::new(0)))
                .await
                .unwrap();
            let (log, boundary) = log.prune(Location::new(30)).await.unwrap();
            assert_eq!(boundary, Location::new(28));
            let root = log.root(0).unwrap();
            let expected = log.pinned_nodes_at(Location::new(30)).await.unwrap();
            drop(log.sync().await.unwrap());

            // A sync journal pruned to 30 still holds operations from boundary 28, so replay
            // rebuilds the target root and its pins. A sync journal pruned to 35 lacks them.
            for (start, pins) in [(30, Some(expected)), (35, None)] {
                let target = Target {
                    root,
                    range: non_empty_range!(Location::new(start), Location::new(50)),
                };
                let journal = Ops::new(
                    context.child("sync"),
                    journal_config(),
                    target.range.clone(),
                )
                .await
                .unwrap();
                let (journal, _) = journal.prune(start).await.unwrap();
                let local = local_pinned_nodes::<MmrFamily, _, Sha256, _>(
                    context.child("local_pins"),
                    merkle_config(),
                    &target,
                    &journal,
                )
                .await
                .unwrap();
                assert_eq!(local, pins, "target start {start}");
                drop(journal);
            }
        });
    }
}
