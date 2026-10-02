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

    /// Mark synchronization in progress before changing the operation journal. `context` is the
    /// one later passed to [Self::from_sync_result].
    fn begin_sync(
        context: &Self::Context,
        config: &Self::Config,
    ) -> impl Future<Output = Result<Self::SyncState, crate::qmdb::Error<Self::Family>>> + Send;

    /// Open the sync journal for `range`. If [Self::reject_sync_result] rejected the previous
    /// import, the retained operations are discarded first, so this attempt downloads its whole
    /// range.
    #[allow(clippy::type_complexity)]
    fn open_sync_journal(
        state: Self::SyncState,
        context: Self::Context,
        config: &Self::Config,
        range: NonEmptyRange<Location<Self::Family>>,
    ) -> impl Future<
        Output = Result<(Self::SyncState, Self::Journal), crate::qmdb::Error<Self::Family>>,
    > + Send;

    /// Durably record a boundary authenticated against the current target.
    fn stage_sync_frontier(
        state: Self::SyncState,
        location: Location<Self::Family>,
        pins: Vec<Self::Digest>,
    ) -> impl Future<Output = Result<Self::SyncState, crate::qmdb::Error<Self::Family>>> + Send;

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

    /// Return the target's pinned nodes if the retained operations authenticate against its root.
    ///
    /// The engine calls this only when the journal already reaches the target's end, and discards
    /// the retained operations when it returns `None`.
    fn local_pinned_nodes(
        state: &Self::SyncState,
        config: &Self::Config,
        target: &crate::qmdb::sync::Target<Self::Family, Self::Digest>,
        journal: &Self::Journal,
    ) -> impl Future<Output = Result<Option<Vec<Self::Digest>>, crate::qmdb::Error<Self::Family>>> + Send;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}

/// Shared body of [`Database::open_sync_journal`] for databases whose sync state is an
/// [`authenticated::Frontier`].
pub(crate) async fn open_sync_journal<F, E, D, J>(
    frontier: authenticated::Frontier<F, E, D>,
    context: J::Context,
    config: J::Config,
    range: NonEmptyRange<Location<F>>,
) -> Result<(authenticated::Frontier<F, E, D>, J), crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    D: Digest,
    J: Journal<F>,
{
    if !frontier.rejected() {
        let journal = J::open(context, config, range).await.map_err(Into::into)?;
        return Ok((frontier, journal));
    }
    let journal = J::clear(context, config, range.start())
        .await
        .map_err(Into::into)?;
    Ok((frontier.restart().await?, journal))
}

/// Read the inactivity floor committed at `end - 1`, or `None` if that operation cannot be the
/// target's last commit.
pub(crate) async fn retained_floor<F, R>(
    journal: &R,
    end: Location<F>,
) -> Result<Option<Location<F>>, crate::qmdb::Error<F>>
where
    F: Family,
    R: Contiguous<Item: crate::qmdb::operation::Floored<F>>,
{
    match crate::qmdb::find_inactivity_floor_at(journal, end).await {
        Ok(floor) => Ok(Some(floor)),
        Err(
            crate::qmdb::Error::HistoricalFloorPruned(_) | crate::qmdb::Error::DataCorrupted(_),
        ) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Shared body for [`Database::local_pinned_nodes`] implementations backed by an
/// [`authenticated::Frontier`]. Replays the retained operations from the frontier and returns the
/// pinned nodes at `target.range.start()` if the rebuilt root, computed at the floor committed at
/// `target.range.end() - 1`, matches `target.root`.
pub(crate) async fn local_pinned_nodes<F, E, H, S, C>(
    frontier: &authenticated::Frontier<F, E, H::Digest>,
    config: &authenticated::Config<S>,
    journal: &C,
    target: &Target<F, H::Digest>,
) -> Result<Option<Vec<H::Digest>>, crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    C: Contiguous<Item: commonware_codec::EncodeShared + crate::qmdb::operation::Floored<F>>,
{
    let Some(inactivity_floor) = retained_floor(journal, target.range.end()).await? else {
        return Ok(None);
    };
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
        journal::contiguous::fixed, merkle::mmr::Family as F, qmdb::keyless::fixed::Operation,
    };
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{WriteFaultContext, WriteFaults},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, sequence::U64};

    type Op = Operation<F, U64>;
    type Log = authenticated::Journal<
        F,
        deterministic::Context,
        fixed::Journal<deterministic::Context, Op>,
        Sha256,
        Sequential,
    >;

    fn merkle_config() -> authenticated::Config<Sequential> {
        authenticated::Config {
            metadata_partition: "frontier".into(),
            cache: Default::default(),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
        }
    }

    fn journal_config(pooler: &impl BufferPooler) -> fixed::Config {
        fixed::Config {
            partition: "operations".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(pooler, NZU16!(111), NZUsize!(5)),
        }
    }

    /// The operation at `i` in a 50-operation log whose last operation commits floor zero.
    fn op(i: u64) -> Op {
        if i == 49 {
            Op::Commit(None, Location::new(0))
        } else {
            Op::Append(U64::new(i))
        }
    }

    #[test]
    fn local_pinned_nodes_requires_operations_from_the_frontier() {
        deterministic::Runner::default().start(|context| async move {
            let config = merkle_config();
            let mut log = Log::new(
                context.child("init"),
                config.clone(),
                journal_config(&context),
                |_| true,
                crate::qmdb::ROOT_BAGGING,
            )
            .await
            .unwrap();
            for i in 0..50 {
                (log, _) = log.append(&op(i)).await.unwrap();
            }
            let (log, boundary) = log.prune(Location::new(30)).await.unwrap();
            assert_eq!(boundary, Location::new(28));
            let start = Location::new(35);
            let inactive_peaks = F::inactive_peaks(Location::new(50), Location::new(0));
            let target = Target {
                root: log.root(inactive_peaks).unwrap(),
                range: non_empty_range!(start, Location::new(50)),
            };
            let expected = log.pinned_nodes_at(start).await.unwrap();
            let authenticated::Journal {
                frontier, journal, ..
            } = log;
            let frontier = frontier.importing().await.unwrap();

            // Operations from the frontier through the target end rebuild the target's pins.
            let pins =
                local_pinned_nodes::<F, _, Sha256, _, _>(&frontier, &config, &journal, &target)
                    .await
                    .unwrap();
            assert_eq!(pins, Some(expected));

            // A reset journal starting above the frontier cannot.
            drop(journal);
            let mut journal = authenticated::clear_sync::<_, fixed::Journal<_, Op>>(
                context.child("reset"),
                journal_config(&context),
                *start,
            )
            .await
            .unwrap();
            for i in *start..50 {
                (journal, _) = journal.append(&op(i)).await.unwrap();
            }
            let pins =
                local_pinned_nodes::<F, _, Sha256, _, _>(&frontier, &config, &journal, &target)
                    .await
                    .unwrap();
            assert!(pins.is_none());
            assert!(matches!(
                frontier.active(),
                Err(authenticated::Error::IncompleteSync)
            ));
        });
    }

    #[test]
    fn open_sync_journal_keeps_rejection_until_journal_is_cleared() {
        deterministic::Runner::default().start(|context| async move {
            type Frontier =
                authenticated::Frontier<F, deterministic::Context, <Sha256 as Hasher>::Digest>;
            let frontier = Frontier::open(context.child("rejected"), "frontier".into())
                .await
                .unwrap()
                .reject()
                .await
                .unwrap();
            let faults = WriteFaults::default();
            let faulty = |label| WriteFaultContext {
                inner: context.child(label),
                faults: faults.clone(),
            };
            let mut journal =
                fixed::Journal::<_, u64>::init(faulty("first"), journal_config(&context))
                    .await
                    .unwrap();
            for i in 0..10 {
                (journal, _) = journal.append(&i).await.unwrap();
            }
            drop(journal.sync().await.unwrap());
            let range = non_empty_range!(Location::<F>::new(0), Location::new(20));

            // A failed reset must leave the rejection in place.
            faults.arm();
            assert!(
                open_sync_journal::<F, _, _, fixed::Journal<_, u64>>(
                    frontier,
                    faulty("failed"),
                    journal_config(&context),
                    range.clone(),
                )
                .await
                .is_err()
            );
            faults.disarm();
            let frontier = Frontier::open(context.child("reopened"), "frontier".into())
                .await
                .unwrap();
            assert!(frontier.rejected());

            let (frontier, journal) = open_sync_journal::<F, _, _, fixed::Journal<_, u64>>(
                frontier,
                faulty("retry"),
                journal_config(&context),
                range,
            )
            .await
            .unwrap();
            assert!(!frontier.rejected());
            assert_eq!(journal.bounds(), 0..0);
        });
    }
}
