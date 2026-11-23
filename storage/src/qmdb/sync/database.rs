use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location},
    qmdb::{
        Error,
        operation::Committable,
        single_operation_root,
        sync::{EngineError, Journal, Target},
    },
    translator::Translator,
};
use commonware_codec::{Encode, EncodeShared};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{non_empty_range, range::NonEmptyRange};
use std::{future::Future, num::NonZeroU64};

/// Database configuration that can produce the configuration for its sync journal.
pub trait Config {
    /// Configuration for the journal the sync engine fills before building the database.
    type JournalConfig;

    /// Return the configuration for the sync journal.
    fn journal_config(&self) -> Self::JournalConfig;
}

impl<T: Translator, J: Clone, S: Strategy> Config for crate::qmdb::any::Config<T, J, S> {
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
/// [`sync`](super::sync). The steps the engine takes to build the database are private to this
/// crate.
///
/// This trait is sealed to the databases provided by this crate.
///
/// [`Source`]: super::Source
#[expect(
    private_bounds,
    reason = "the Hooks supertrait is private so only the sync engine can call its methods"
)]
pub trait Database: Hooks<Self> + Sized {
    /// The Merkle family of the operations log.
    type Family: Family;

    /// The operation type stored in the log.
    type Op: Committable<Self::Family> + Encode + Send + Sync;

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

    /// Initialize from the latest retained commit at or below `max_size`, or the latest retained
    /// state when no bound is supplied. A zero bound is invalid.
    fn init(
        context: Self::Context,
        config: Self::Config,
        max_size: Option<Location<Self::Family>>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Sync target of a freshly initialized database.
    fn initial_target() -> Target<Self::Family, Self::Digest> {
        Target {
            root: single_operation_root::<Self::Family, Self::Hasher>(&Self::Op::initial_commit()),
            range: non_empty_range!(Location::new(0), Location::new(1)),
        }
    }

    /// Sync target that reaches this database's applied state.
    ///
    /// Its root is the operations root, which for [`current`](crate::qmdb::current) differs from
    /// the canonical database root.
    fn target(&self) -> Target<Self::Family, Self::Digest>;

    /// Prune history that a previously reached `target` no longer needs.
    fn prune_to_target(
        self,
        target: &Target<Self::Family, Self::Digest>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;
}

/// The steps the sync engine takes to build a [`Database`].
///
/// `DB` is the database the steps build. [`Database`] requires `Hooks<Self>`.
///
/// The engine calls [`Self::validate_target`] on the initial target and on every update it
/// adopts. If the sync journal it opens holds no operation of the target's range, the engine
/// calls [`Self::discard_local_state`]. If the journal already reaches the target, the engine
/// calls [`Self::local_pinned_nodes`]. It fetches and verifies any remaining operations, builds
/// the database with [`Self::from_sync_result`], and calls [`Self::persist_sync_result`] once the
/// root of [`Database::target`] matches the requested root.
pub(in crate::qmdb) trait Hooks<DB: Database>: Sized + Send {
    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: DB::Context,
        config: DB::Config,
        journal: DB::Journal,
        pinned_nodes: Option<Vec<DB::Digest>>,
        range: NonEmptyRange<Location<DB::Family>>,
        apply_batch_size: NonZeroU64,
    ) -> impl Future<Output = Result<Self, Error<DB::Family>>> + Send;

    /// Persist any state that must remain provisional until the engine verifies the rebuilt root.
    ///
    /// The engine calls this only after the root of [`Database::target`] matches the requested
    /// target. Implementations that persist everything in [`Self::from_sync_result`] must
    /// explicitly return `Ok(self)`.
    fn persist_sync_result(self) -> impl Future<Output = Result<Self, Error<DB::Family>>> + Send;

    /// Durably discard persisted state derived from the operations of the sync journal.
    ///
    /// The engine calls this when the sync journal it opens holds no operation of the target's
    /// range, before it appends any fetched operation. State derived from operations the journal
    /// held earlier would otherwise be read as describing the operations fetched in their place.
    /// Implementations with no persisted state that would be read that way must explicitly
    /// return `Ok(())`.
    fn discard_local_state(
        context: DB::Context,
        config: &DB::Config,
    ) -> impl Future<Output = Result<(), Error<DB::Family>>> + Send;

    /// Return pinned nodes for the target computed from local state, if it can provide them.
    ///
    /// Returning `Some` lets a completed sync journal reuse pinned nodes from an on-disk
    /// database instead of fetching them from peers. The sync checks the resulting root against
    /// the target's. Returning `None` always falls back to fetching from peers.
    fn local_pinned_nodes(
        context: DB::Context,
        config: &DB::Config,
        target: &Target<DB::Family, DB::Digest>,
        journal: &DB::Journal,
    ) -> impl Future<Output = Result<Option<Vec<DB::Digest>>, Error<DB::Family>>> + Send;

    /// Reject a target this database cannot sync to. The engine checks the initial target and
    /// every adopted update, and a rejected target fails the sync, since a malformed target is a
    /// caller bug. The default accepts any target.
    fn validate_target(
        _target: &Target<DB::Family, DB::Digest>,
    ) -> Result<(), EngineError<DB::Family, DB::Digest>> {
        Ok(())
    }
}

/// A merkleized batch of a [`Database`].
pub trait MerkleizedBatch {
    /// The Merkle family of the operations log.
    type Family: Family;

    /// The digest type of the batch's root.
    type Digest: Digest;

    /// The root of the database once this batch is applied.
    fn root(&self) -> Self::Digest;

    /// Sync target reached once this batch is applied.
    fn target(&self) -> Target<Self::Family, Self::Digest>;
}

/// Whether a completed sync journal's `bounds` cover `range`: retained data reaches back to
/// `range.start()` and ends exactly at `range.end()`.
fn journal_covers_range<F: Family>(
    bounds: std::ops::Range<u64>,
    range: &NonEmptyRange<Location<F>>,
) -> bool {
    Location::new(bounds.start) <= range.start() && Location::new(bounds.end) == range.end()
}

/// Shared body for [`Hooks::local_pinned_nodes`] implementations backed by an authenticated
/// journal. Genesis needs no pins, and an incomplete journal cannot supply them. Otherwise,
/// returns the pinned nodes at `target.range.start()`, rebuilt by replaying `journal`
/// from the boundary of the frontier read from `config` through its end. Returns `None`
/// if that boundary lies after the target start, `journal` does not hold the operations from the
/// boundary through the target start, or the rebuilt root differs from the target root.
pub(crate) async fn local_pinned_nodes<F, E, H, S>(
    context: E,
    config: &authenticated::Config<S>,
    target: &Target<F, H::Digest>,
    journal: &impl Contiguous<Item: EncodeShared + Committable<F>>,
) -> Result<Option<Vec<H::Digest>>, Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    if target.range.start() == Location::new(0)
        || !journal_covers_range(journal.bounds(), &target.range)
    {
        return Ok(None);
    }

    let hasher = crate::qmdb::hasher::<H>();
    let floor = crate::qmdb::find_inactivity_floor_at(journal, target.range.end()).await?;
    let inactive_peaks = F::inactive_peaks(target.range.end(), floor);
    Ok(authenticated::pinned_nodes_from_frontier(
        context,
        config,
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
            self,
            keyless::{self, fixed::Operation},
            sync::{
                self, Request, Source, Target,
                engine::Config,
                source::{
                    self,
                    tests::{FailSource, SequenceSource},
                },
            },
        },
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{
        NZU16, NZU64, NZUsize, channel::ring, non_empty_range, range::NonEmptyRange, sequence::U64,
    };
    use rstest::rstest;
    use std::sync::Arc;

    type Op = Operation<MmrFamily, U64>;
    type Ops = fixed::Journal<deterministic::Context, Op>;

    fn merkle_config() -> authenticated::Config<Sequential> {
        authenticated::Config {
            partition: "local-pins-metadata".into(),
            resident_height: Default::default(),
            replay_buffer: NZUsize!(1024),
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

    type KeylessDb = keyless::fixed::Db<MmrFamily, deterministic::Context, U64, Sha256, Sequential>;

    /// A keyless config whose partitions end with `suffix`.
    fn keyless_config(suffix: &str) -> keyless::fixed::Config<Sequential> {
        let mut config = keyless::Config {
            merkle: merkle_config(),
            log: journal_config(),
            init_concurrency: NZUsize!(2),
        };
        config.merkle.partition.push_str(suffix);
        config.log.partition.push_str(suffix);
        config
    }

    /// A synced keyless database with one commit at `floor` per entry of `commits`, each
    /// appending that entry's values.
    async fn keyless_db(
        context: deterministic::Context,
        config: keyless::fixed::Config<Sequential>,
        floor: u64,
        commits: &[&[u64]],
    ) -> KeylessDb {
        let mut db = KeylessDb::init(context, config, None).await.unwrap();
        for values in commits {
            let mut batch = db.new_batch();
            for &value in *values {
                batch = batch.append(U64::new(value));
            }
            let batch = batch
                .with_inactivity_floor(Location::new(floor))
                .merkleize(&db)
                .await
                .unwrap();
            db = db.apply_batch(batch).await.unwrap();
        }
        db.sync().await.unwrap()
    }

    /// When the local journal covers the target start, a sync keeps the earlier operations until
    /// it records the new boundary, even if the source fails. A sync to a target the local
    /// operations already authenticate rebuilds the pins from them without asking the source.
    #[test]
    fn sync_keeps_operations_until_the_boundary_moves() {
        deterministic::Runner::default().start(|context| async move {
            // Create 51 operations ending in a commit whose inactivity floor is 30.
            let config = keyless_config("");
            let values: Vec<u64> = (0..49).collect();
            let db = keyless_db(context.child("create"), config.clone(), 30, &[&values]).await;
            let root = db.root();
            assert_eq!(db.bounds(), Location::new(0)..Location::new(51));
            drop(db);

            // The frontier is still at 0, behind the target start 30.
            let sync_to = |label, end| {
                sync::sync::<KeylessDb, _>(Config {
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
            let db = KeylessDb::init(context.child("after_failure"), config.clone(), None)
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
            let db = KeylessDb::init(context.child("reopen"), config, None)
                .await
                .unwrap();
            assert_eq!(db.bounds(), Location::new(30)..Location::new(51));
            assert_eq!(db.root(), root);
        });
    }

    #[test]
    fn local_pinned_nodes_skip_genesis_and_incomplete_journals() {
        deterministic::Runner::default().start(|context| async move {
            // Neither target needs a local lookup. Reading its final commit would fail:
            // position 0 is an append, and position 1 is outside the journal.
            let journal = Ops::init(context.child("journal"), journal_config())
                .await
                .unwrap();
            let (journal, _) = journal.append(&Op::Append(U64::new(1))).await.unwrap();
            let root = <KeylessDb as sync::Database>::initial_target().root;
            for (start, end) in [(0, 1), (1, 2)] {
                let target = Target {
                    root,
                    range: non_empty_range!(Location::new(start), Location::new(end)),
                };
                let pins = local_pinned_nodes::<MmrFamily, _, Sha256, _>(
                    context.child("pins"),
                    &merkle_config(),
                    &target,
                    &journal,
                )
                .await
                .unwrap();
                assert!(pins.is_none());
            }
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
            let local_config = keyless_config("");
            let local = keyless_db(context.child("local"), local_config.clone(), 0, &[&[11]]).await;
            let source_config = keyless_config("-source");
            let source_db = keyless_db(context.child("source"), source_config, 0, &[&[22]]).await;
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
            let db = sync::sync::<KeylessDb, _>(Config {
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
            let reopened = KeylessDb::init(context.child("reopen"), local_config, None)
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
            // The local database ends at 3, before the target's start at 30.
            let local_config = keyless_config("");
            drop(keyless_db(context.child("local"), local_config.clone(), 0, &[&[0]]).await);
            let source_config = keyless_config("-source");
            let values: Vec<u64> = (0..39).collect();
            let source_db = keyless_db(context.child("source"), source_config, 0, &[&values]).await;
            let source_db = Arc::new(source_db);
            let target = Target {
                root: source_db.root(),
                range: non_empty_range!(Location::new(30), Location::new(41)),
            };
            // A source that fails every request interrupts the sync after the reset.
            assert!(matches!(
                sync::sync::<KeylessDb, _>(Config {
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
            assert!(matches!(
                KeylessDb::init(context.child("reopen"), local_config.clone(), None).await,
                Err(qmdb::Error::Journal(crate::journal::Error::ItemPruned(n))) if n == *target.range.start()
            ));

            // Retrying the sync records the target's boundary, and the database opens again.
            let db = sync::sync::<KeylessDb, _>(Config {
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
            let db = KeylessDb::init(context.child("after_retry"), local_config, None)
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
            let local_config = keyless_config("");
            let local = keyless_db(
                context.child("local"),
                local_config.clone(),
                0,
                &[&[11], &[13]],
            );
            let local = local.await;
            let source_config = keyless_config("-source");
            let source_db = keyless_db(context.child("source"), source_config, 0, &[&[22], &[24]]);
            let source_db = source_db.await;
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
            let result = sync::sync::<KeylessDb, _>(Config {
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
            let reopened = KeylessDb::init(context.child("reopen"), local_config, None)
                .await
                .unwrap();
            assert_eq!(reopened.bounds(), Location::new(0)..Location::new(5));
            assert_eq!(reopened.root(), local_root);
        });
    }

    /// Serves requests that start before `limit` from `inner`, and fails the rest.
    struct ServesBefore<S> {
        inner: S,
        limit: Location<MmrFamily>,
    }

    impl<S: Source<Family = MmrFamily, Error = qmdb::Error<MmrFamily>>> Source for ServesBefore<S> {
        type Family = MmrFamily;
        type Digest = S::Digest;
        type Op = S::Op;
        type Error = qmdb::Error<MmrFamily>;

        async fn serve(&self, request: Request<MmrFamily>) -> source::Result<Self> {
            if request.start() >= self.limit {
                return Err(qmdb::Error::KeyNotFound);
            }
            self.inner.serve(request).await
        }
    }

    /// Catch-up interrupted after appending reopens at the last retained commit and can resume.
    #[test]
    fn interrupted_sync_after_appending_is_retried() {
        deterministic::Runner::default().start(|context| async move {
            // The local database is the first 3 operations of the source's 9.
            let local_config = keyless_config("");
            drop(keyless_db(context.child("local"), local_config.clone(), 0, &[&[22]]).await);
            let source_config = keyless_config("-source");
            let commits: [&[u64]; 4] = [&[22], &[24], &[26], &[28]];
            let source_db = keyless_db(context.child("source"), source_config, 0, &commits);
            let source_db = Arc::new(source_db.await);
            let target = Target {
                root: source_db.root(),
                range: non_empty_range!(Location::new(2), Location::new(9)),
            };
            let config = |label: &'static str, source| Config {
                context: context.child(label),
                source,
                target: target.clone(),
                max_outstanding_requests: NZUsize!(1),
                fetch_batch_size: NZU64!(2),
                apply_batch_size: NZU64!(2),
                db_config: local_config.clone(),
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            };

            // A source that stops serving at 7 interrupts the sync after it appends from 3.
            let interrupted = ServesBefore {
                inner: source_db.clone(),
                limit: Location::new(7),
            };
            assert!(matches!(
                sync::sync::<KeylessDb, _>(config("interrupted", interrupted)).await,
                Err(sync::Error::Source(_))
            ));
            let expected = keyless_db(
                context.child("prefix"),
                keyless_config("-prefix"),
                0,
                &commits[..3],
            )
            .await;
            let db = KeylessDb::init(context.child("intermediate"), local_config.clone(), None)
                .await
                .unwrap();
            assert_eq!(db.bounds().end, Location::new(7));
            assert_eq!(db.root(), expected.root());
            drop(db);

            // Syncing again records the target's boundary, and the database opens there.
            let complete = ServesBefore {
                inner: source_db,
                limit: Location::new(9),
            };
            let db = sync::sync::<KeylessDb, _>(config("retry", complete))
                .await
                .unwrap();
            assert_eq!(db.root(), target.root);
            drop(db);
            let db = KeylessDb::init(context.child("reopen"), local_config, None)
                .await
                .unwrap();
            assert_eq!(db.root(), target.root);
        });
    }

    /// The error an open reports for a reset journal whose boundary was not recorded.
    #[derive(Clone, Copy, Debug)]
    enum Unrecorded {
        /// The journal holds no commit, and its start is nonzero.
        ItemPruned,
        /// The journal holds a commit, and the frontier's boundary lies before the journal's start.
        FrontierOutside,
    }

    /// Interrupt sync after a reset, before or after a commit arrives. Retrying supplies the
    /// missing boundary pins even when the target changed during sync.
    #[rstest]
    #[case::before_first_commit(false, 7, Unrecorded::ItemPruned)]
    #[case::after_target_update_before_fetch(true, 4, Unrecorded::ItemPruned)]
    #[case::after_target_update(true, 12, Unrecorded::FrontierOutside)]
    fn interrupted_pruned_sync_is_retried(
        #[case] update_target: bool,
        #[case] stop_at: u64,
        #[case] expected: Unrecorded,
    ) {
        deterministic::Runner::default().start(|context| async move {
            // Commits at 0, 8 and 15. The target starts at 4, inside the first batch.
            let source = Arc::new(
                keyless_db(
                    context.child("source"),
                    keyless_config("-source"),
                    4,
                    &[&[1, 2, 3, 4, 5, 6, 7], &[8, 9, 10, 11, 12, 13]],
                )
                .await,
            );
            let target = Target {
                root: source.root(),
                range: non_empty_range!(source.sync_boundary(), source.bounds().end),
            };
            let mut local = keyless_config("");
            local.log.items_per_blob = NZU64!(2);
            let config = |target, limit, update_rx| Config {
                context: context.child("sync"),
                source: ServesBefore {
                    inner: source.clone(),
                    limit,
                },
                target,
                max_outstanding_requests: NZUsize!(1),
                fetch_batch_size: NZU64!(2),
                apply_batch_size: NZU64!(2),
                db_config: local.clone(),
                update_rx,
                finish_rx: None,
                reached_target_tx: None,
            };

            let (tx, rx) = ring::channel(NZUsize!(1));
            let initial = if update_target {
                let genesis =
                    keyless_db(context.child("genesis"), keyless_config("-genesis"), 0, &[]).await;
                assert!(tx.send_lossy(target.clone()));
                Target {
                    root: genesis.root(),
                    range: non_empty_range!(genesis.sync_boundary(), genesis.bounds().end),
                }
            } else {
                target.clone()
            };
            let interrupted = config(initial, Location::new(stop_at), update_target.then_some(rx));
            assert!(matches!(
                sync::sync::<KeylessDb, _>(interrupted).await,
                Err(sync::Error::Source(_))
            ));
            let start = target.range.start();
            let error = KeylessDb::init(context.child("reopen"), local.clone(), None)
                .await
                .expect_err("reset journal reopened without a boundary");
            match (expected, error) {
                (
                    Unrecorded::ItemPruned,
                    qmdb::Error::Journal(crate::journal::Error::ItemPruned(n)),
                ) => assert_eq!(n, *start),
                (
                    Unrecorded::FrontierOutside,
                    qmdb::Error::Merkle(crate::merkle::Error::DataCorrupted(
                        "frontier outside operation journal",
                    )),
                ) => {}
                (expected, other) => panic!("reopen must fail with {expected:?}, got {other}"),
            }
            assert!(matches!(
                KeylessDb::init(context.child("capped"), local.clone(), Some(start)).await,
                Err(qmdb::Error::NoRetainedCommit(cap)) if cap == start
            ));

            let retry = config(target.clone(), target.range.end(), None);
            let db = sync::sync::<KeylessDb, _>(retry).await.unwrap();
            assert_eq!(db.root(), target.root);
            drop(db);
            let db = KeylessDb::init(context.child("after_retry"), local, None)
                .await
                .unwrap();
            assert_eq!(db.root(), target.root);
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
                    &merkle_config(),
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
