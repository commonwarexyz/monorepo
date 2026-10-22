use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location},
    qmdb::sync::{Journal, Target},
    translator::Translator,
};
use commonware_codec::{Encode, EncodeShared};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::{future::Future, num::NonZeroU64};

/// Database configuration that can produce the configuration for its sync journal.
pub trait Config {
    type JournalConfig;
    fn journal_config(&self) -> Self::JournalConfig;
}

impl<T: Translator, J: Clone, S: Strategy, B> Config for crate::qmdb::any::Config<T, J, S, B> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.journal_config.clone()
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

pub trait Database: Sized + Send {
    type Family: Family;
    type Op: Encode + Send + Sync;
    type Journal: Journal<Self::Family, Context = Self::Context, Op = Self::Op>;
    type Config: Config<JournalConfig = <Self::Journal as Journal<Self::Family>>::Config>;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;
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
    /// The engine calls this only after [`Self::root`] matches the requested target. Implementations
    /// that persist everything in [`Self::from_sync_result`] must explicitly return `Ok(self)`.
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

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
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
/// journal. Returns the pinned nodes at `target.range.start()`, computed by replaying `journal`
/// from the boundary of the frontier read from `config` under `context`, if `journal` still holds
/// the operations in between.
pub(crate) async fn local_pinned_nodes<F, E, H, S>(
    context: E,
    config: authenticated::Config<S>,
    target: &Target<F, H::Digest>,
    journal: &impl Contiguous<Item: EncodeShared>,
) -> Result<Option<Vec<H::Digest>>, crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = crate::qmdb::hasher::<H>();
    Ok(authenticated::pinned_nodes_from_frontier(
        context,
        &config,
        journal,
        &hasher,
        target.range.start(),
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
            sync::{self, Target, engine::Config, source::tests::FailSource},
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

    type Op = Operation<MmrFamily, U64>;
    type Ops = fixed::Journal<deterministic::Context, Op>;

    fn merkle_config() -> authenticated::Config<Sequential> {
        authenticated::Config {
            metadata_partition: "local-pins-metadata".into(),
            cache: Default::default(),
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

    /// A sync keeps the local operations before its target's start until it records the new
    /// boundary. A failed sync leaves the database as it was, and a sync to a target the database
    /// already holds rebuilds the pins from those operations without asking the source.
    #[test]
    fn sync_keeps_operations_until_the_boundary_moves() {
        deterministic::Runner::default().start(|context| async move {
            type Db =
                keyless::fixed::Db<MmrFamily, deterministic::Context, U64, Sha256, Sequential>;
            let config = keyless::Config {
                merkle: merkle_config(),
                log: journal_config(),
            };
            let mut db = Db::init(context.child("create"), config.clone(), None)
                .await
                .unwrap();
            let mut batch = db.new_batch();
            for value in 0..49 {
                batch = batch.append(U64::new(value));
            }
            let batch = batch.merkleize(&db, None, Location::new(30)).await.unwrap();
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

            let db = sync_to("local", 51).await.unwrap();
            assert_eq!(db.bounds(), Location::new(28)..Location::new(51));
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

    /// Local pins come from replaying the sync journal from the frontier's boundary, and are
    /// unavailable once the sync journal no longer holds the operations from that boundary.
    #[test]
    fn local_pinned_nodes_replay_from_the_frontier() {
        deterministic::Runner::default().start(|context| async move {
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
            let expected = log.pinned_nodes_at(Location::new(30)).await.unwrap();
            drop(log.sync().await.unwrap());

            for (start, pins) in [(30, Some(expected)), (35, None)] {
                let target = Target {
                    root: Digest::from([0; 32]),
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
