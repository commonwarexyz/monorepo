use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location},
    qmdb::sync::{Journal, Target},
    translator::Translator,
};
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
    type Op: Send + Sync;
    type Journal: Journal<Self::Family, Context = Self::Context, Op = Self::Op>;
    type Config: Config<JournalConfig = <Self::Journal as Journal<Self::Family>>::Config>;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;
    type Hasher: commonware_cryptography::Hasher<Digest = Self::Digest>;
    /// Durable state held while an operation range is being imported.
    type SyncState: Send + Sync;

    /// Mark synchronization in progress before changing the operation journal. `context` is the one
    /// later passed to [Self::from_sync_result].
    fn begin_sync(
        context: &Self::Context,
        config: &Self::Config,
    ) -> impl Future<Output = Result<Self::SyncState, crate::qmdb::Error<Self::Family>>> + Send;

    /// Durably record a boundary authenticated against the current target.
    fn stage_sync_frontier(
        state: Self::SyncState,
        location: Location<Self::Family>,
        pins: Vec<Self::Digest>,
    ) -> impl Future<Output = Result<Self::SyncState, crate::qmdb::Error<Self::Family>>> + Send;

    /// Discard retained operations if [Self::reject_sync_result] rejected the previous import, so
    /// this attempt downloads its whole range.
    #[allow(clippy::type_complexity)]
    fn restart_rejected_import(
        state: Self::SyncState,
        journal: Self::Journal,
        start: Location<Self::Family>,
    ) -> impl Future<
        Output = Result<(Self::SyncState, Self::Journal), crate::qmdb::Error<Self::Family>>,
    > + Send;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        state: Self::SyncState,
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

    /// Require the next import to discard retained operations. The engine calls this instead of
    /// [`Self::persist_sync_result`] when [`Self::root`] does not match the target.
    fn reject_sync_result(
        self,
    ) -> impl Future<Output = Result<(), crate::qmdb::Error<Self::Family>>> + Send;

    /// Return locally available pinned nodes for the target, if persisted local state can
    /// authenticate them.
    ///
    /// Returning `Some` lets a completed sync journal reuse pinned nodes from an on-disk
    /// database instead of fetching them from peers. Returning `None` always falls back to
    /// fetching from peers.
    fn local_pinned_nodes(
        state: &Self::SyncState,
        config: &Self::Config,
        target: &crate::qmdb::sync::Target<Self::Family, Self::Digest>,
        journal: &Self::Journal,
    ) -> impl Future<Output = Result<Option<Vec<Self::Digest>>, crate::qmdb::Error<Self::Family>>> + Send;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}

/// Whether a completed sync journal's `bounds` cover `range`: retained data reaches back to
/// `range.start()` and reaches at least `range.end()`.
pub(crate) fn journal_covers_range<F: Family>(
    bounds: std::ops::Range<u64>,
    range: &NonEmptyRange<Location<F>>,
) -> bool {
    Location::new(bounds.start) <= range.start() && Location::new(bounds.end) >= range.end()
}

/// Shared body of [`Database::restart_rejected_import`] for databases whose sync state is an
/// [`authenticated::Frontier`].
pub(crate) async fn restart_rejected_import<F, E, D, J>(
    frontier: authenticated::Frontier<F, E, D>,
    journal: J,
    start: Location<F>,
) -> Result<(authenticated::Frontier<F, E, D>, J), crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    D: Digest,
    J: Journal<F>,
{
    if !frontier.rejected() {
        return Ok((frontier, journal));
    }
    let journal = journal.clear(start).await.map_err(Into::into)?;
    Ok((frontier.restart().await?, journal))
}

/// Authenticate a retained operation prefix and recover the requested pruning frontier.
pub(crate) async fn local_pinned_nodes<F, E, H, S, C>(
    frontier: &authenticated::Frontier<F, E, H::Digest>,
    config: &authenticated::Config<S>,
    journal: &C,
    target: &Target<F, H::Digest>,
    inactivity_floor: Location<F>,
) -> Result<Option<Vec<H::Digest>>, crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    C: Contiguous<Item: commonware_codec::EncodeShared>,
{
    frontier
        .authenticate(
            config,
            journal,
            &crate::qmdb::hasher::<H>(),
            target.range.start(),
            target.range.end(),
            target.root,
            F::inactive_peaks(target.range.end(), inactivity_floor),
        )
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::fixed,
        merkle::{Bagging, mmr::Family as F},
    };
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{WriteFaultContext, WriteFaults},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};

    #[test]
    fn test_journal_covers_range() {
        let range: NonEmptyRange<Location<F>> =
            non_empty_range!(Location::new(10), Location::new(20));
        for bounds in [10..20, 5..20, 10..21] {
            assert!(journal_covers_range(bounds, &range));
        }
        for bounds in [11..20, 10..19, 0..0] {
            assert!(!journal_covers_range(bounds, &range));
        }
    }

    #[test]
    fn local_pinned_nodes_treats_interrupted_reset_as_unavailable() {
        deterministic::Runner::default().start(|context| async move {
            let config = authenticated::Config {
                metadata_partition: "frontier".into(),
                cache: Default::default(),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
            };
            let raw_config = fixed::Config {
                partition: "operations".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, NZU16!(111), NZUsize!(5)),
            };
            let mut log = authenticated::Journal::<F, _, fixed::Journal<_, u64>, Sha256, _>::new(
                context.child("init"),
                config.clone(),
                raw_config,
                |_| true,
                Bagging::ForwardFold,
            )
            .await
            .unwrap();
            for i in 0..50 {
                (log, _) = log.append(&i).await.unwrap();
            }
            let (log, _) = log.prune(Location::new(30)).await.unwrap();
            let frontier = log.frontier.importing().await.unwrap();
            let raw = log.journal.clear_to_size(7).await.unwrap();
            let target = Target {
                root: commonware_cryptography::sha256::Digest::from([0; 32]),
                range: non_empty_range!(Location::new(7), Location::new(20)),
            };
            assert!(
                local_pinned_nodes::<F, _, Sha256, _, _>(
                    &frontier,
                    &config,
                    &raw,
                    &target,
                    Location::new(7)
                )
                .await
                .unwrap()
                .is_none()
            );
            assert!(matches!(
                frontier.active(),
                Err(authenticated::Error::IncompleteSync)
            ));
        });
    }

    #[test]
    fn restart_rejected_import_keeps_rejection_until_journal_is_cleared() {
        deterministic::Runner::default().start(|context| async move {
            type Frontier =
                authenticated::Frontier<F, deterministic::Context, <Sha256 as Hasher>::Digest>;
            let frontier = Frontier::open(context.child("rejected"), "frontier".into())
                .await
                .unwrap()
                .reject()
                .await
                .unwrap();
            let raw_config = fixed::Config {
                partition: "operations".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, NZU16!(111), NZUsize!(5)),
            };
            let faults = WriteFaults::default();
            let faulty = |label| WriteFaultContext {
                inner: context.child(label),
                faults: faults.clone(),
            };
            let mut journal = fixed::Journal::<_, u64>::init(faulty("first"), raw_config.clone())
                .await
                .unwrap();
            for i in 0..10 {
                (journal, _) = journal.append(&i).await.unwrap();
            }
            let journal = journal.sync().await.unwrap();

            // A failed reset must leave the rejection in place.
            faults.arm();
            assert!(
                restart_rejected_import(frontier, journal, Location::new(0))
                    .await
                    .is_err()
            );
            faults.disarm();
            let frontier = Frontier::open(context.child("reopened"), "frontier".into())
                .await
                .unwrap();
            assert!(frontier.rejected());

            let journal = fixed::Journal::<_, u64>::init(faulty("retry"), raw_config)
                .await
                .unwrap();
            let (frontier, journal) = restart_rejected_import(frontier, journal, Location::new(0))
                .await
                .unwrap();
            assert!(!frontier.rejected());
            assert_eq!(journal.bounds(), 0..0);
        });
    }
}
