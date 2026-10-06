use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location},
    qmdb::sync::{Journal, Target},
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::{future::Future, num::NonZeroU64};

/// Durable state held while an operation range is being imported.
pub trait SyncState<F: Family, D: Digest>: Send + Sync + Sized {
    /// Record `pins` as the pinned nodes at `location`, authenticated against the target.
    fn stage(
        self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<F>>> + Send;
}

impl<F: Family, D: Digest> SyncState<F, D> for () {
    async fn stage(self, _: Location<F>, _: Vec<D>) -> Result<Self, crate::qmdb::Error<F>> {
        Ok(())
    }
}

impl<F: Family, E: Context, D: Digest, S: Strategy> SyncState<F, D>
    for authenticated::Import<F, E, D, S>
{
    async fn stage(
        self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> Result<Self, crate::qmdb::Error<F>> {
        Ok(self.stage(location, pins).await?)
    }
}

pub trait Database: Sized + Send {
    type Family: Family;
    type Op: Send + Sync;
    type Journal: Journal<Self::Family, Context = Self::Context, Op = Self::Op>;
    type Config;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;
    type Hasher: commonware_cryptography::Hasher<Digest = Self::Digest>;
    /// Durable state held while an operation range is being imported.
    type SyncState: SyncState<Self::Family, Self::Digest>;

    /// Mark synchronization to `target` in progress and open its journal, pruned to the target's
    /// start. Returns the pinned nodes at the target's start if they are already known.
    ///
    /// Until a sync completes, the database cannot be opened.
    #[allow(clippy::type_complexity)]
    fn open_sync_journal(
        context: &Self::Context,
        config: &Self::Config,
        target: &Target<Self::Family, Self::Digest>,
    ) -> impl Future<
        Output = Result<
            (Self::SyncState, Self::Journal, Option<Vec<Self::Digest>>),
            crate::qmdb::Error<Self::Family>,
        >,
    > + Send;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    /// `pinned_nodes` is empty when the range starts at zero.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        state: Self::SyncState,
        pinned_nodes: Vec<Self::Digest>,
        range: NonEmptyRange<Location<Self::Family>>,
        apply_batch_size: NonZeroU64,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Persist any state that must remain provisional until the engine verifies the rebuilt root.
    ///
    /// The engine calls this only after [`Self::root`] matches the requested target.
    fn persist_sync_result(
        self,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Record that this result failed root verification, so the next
    /// [`Self::open_sync_journal`] discards its operations.
    fn reject_sync_result(
        self,
    ) -> impl Future<Output = Result<(), crate::qmdb::Error<Self::Family>>> + Send;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}

/// Shared body of [`Database::open_sync_journal`] for databases backed by an authenticated
/// journal that opens its frontier under `frontier_context`.
///
/// Operations a rejected import left are discarded first. A journal that already reaches the
/// target is checked against it: operations that rebuild its root yield its pinned nodes, and
/// operations that cannot be the target's are discarded.
#[allow(clippy::type_complexity)]
pub(crate) async fn open_sync_journal<F, E, H, S, J>(
    context: &E,
    frontier_context: E,
    config: &authenticated::Config<S>,
    journal_config: J::Config,
    target: &Target<F, H::Digest>,
) -> Result<
    (
        authenticated::Import<F, E, H::Digest, S>,
        J,
        Option<Vec<H::Digest>>,
    ),
    crate::qmdb::Error<F>,
>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    J: Journal<F, Context = E>
        + Contiguous<Item: commonware_codec::EncodeShared + crate::qmdb::operation::Floored<F>>,
    J::Config: Clone,
{
    let start = target.range.start();
    let mut import = authenticated::Import::begin(frontier_context, config).await?;
    let mut journal = if import.rejected() {
        let journal = J::clear(context.child("journal"), journal_config.clone(), start)
            .await
            .map_err(Into::into)?;
        import = import.restart().await?;
        journal
    } else {
        J::open(
            context.child("journal"),
            journal_config.clone(),
            target.range.clone(),
        )
        .await
        .map_err(Into::into)?
    };

    // A journal that already reaches the target is checked against it before anything is
    // fetched. That may need operations below the start, so prune after.
    let mut pins = None;
    let end = target.range.end();
    if journal.size() >= *end {
        let local = match crate::qmdb::find_inactivity_floor_at(&journal, end).await {
            Ok(floor) => {
                import
                    .authenticate(
                        config,
                        &journal,
                        &crate::qmdb::hasher::<H>(),
                        start,
                        end,
                        target.root,
                        F::inactive_peaks(end, floor),
                    )
                    .await?
            }
            // The target's last operation is a commit, so these operations are not the target's.
            Err(
                crate::qmdb::Error::HistoricalFloorPruned(_) | crate::qmdb::Error::DataCorrupted(_),
            ) => authenticated::Local::Mismatch,
            Err(err) => return Err(err),
        };
        match local {
            authenticated::Local::Authenticated(local) => pins = Some(local),
            // The final root check authenticates them, as it does a partial journal.
            authenticated::Local::Unknown => {}
            authenticated::Local::Mismatch => {
                drop(journal);
                journal = J::clear(context.child("journal"), journal_config, start)
                    .await
                    .map_err(Into::into)?;
            }
        }
    }
    if pins.is_none() && start == Location::new(0) {
        pins = Some(Vec::new());
    }
    if let Some(pins) = &pins {
        import = import.stage(start, pins.clone()).await?;
    }
    let journal = journal.resize(start).await.map_err(Into::into)?;
    Ok((import, journal, pins))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::fixed, merkle::mmr::Family as F, qmdb::keyless::fixed::Operation,
    };
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{WriteFaultContext, WriteFaults},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, sequence::U64};

    type Op = Operation<F, U64>;
    type Ops<E> = fixed::Journal<E, Op>;
    type Log = authenticated::Journal<
        F,
        deterministic::Context,
        Ops<deterministic::Context>,
        Sha256,
        Sequential,
    >;
    type Frontier<E> = authenticated::Frontier<F, E, sha256::Digest>;

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
    fn open_sync_journal_keeps_only_authenticated_operations() {
        deterministic::Runner::default().start(|context| async move {
            let mut log = Log::new(
                context.child("init"),
                merkle_config(),
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
            let root = log.root(inactive_peaks).unwrap();
            let expected = log.pinned_nodes_at(start).await.unwrap();
            drop(log.sync().await.unwrap());
            let open = |target: Target<F, sha256::Digest>| {
                let context = &context;
                async move {
                    open_sync_journal::<F, _, Sha256, _, Ops<_>>(
                        context,
                        context.child("log"),
                        &merkle_config(),
                        journal_config(context),
                        &target,
                    )
                    .await
                    .unwrap()
                }
            };

            // Operations from the frontier rebuild the target's pins, then are pruned to its start.
            let (import, journal, pins) = open(Target {
                root,
                range: non_empty_range!(start, Location::new(50)),
            })
            .await;
            assert_eq!(pins, Some(expected.clone()));
            assert_eq!(journal.bounds(), 35..50);
            drop((import, journal));
            let frontier = Frontier::open(context.child("staged"), "frontier".into())
                .await
                .unwrap();
            assert!(matches!(
                frontier.active_boundary(),
                Err(authenticated::Error::IncompleteSync)
            ));
            let candidate = frontier.boundary().unwrap();
            assert_eq!(candidate.location, start);
            assert_eq!(candidate.digests, expected);
            drop(frontier);

            // A partial journal is kept for the engine to resume.
            let (import, journal, pins) = open(Target {
                root,
                range: non_empty_range!(start, Location::new(60)),
            })
            .await;
            assert!(pins.is_none());
            assert_eq!(journal.bounds(), 35..50);
            drop((import, journal));

            // Operations that do not rebuild the target's root are discarded.
            let (_, journal, pins) = open(Target {
                root: sha256::Digest::from([1; 32]),
                range: non_empty_range!(start, Location::new(50)),
            })
            .await;
            assert!(pins.is_none());
            assert_eq!(journal.bounds(), 35..35);
        });
    }

    /// Operations the staged boundary cannot check, such as those of a journal reset above it, are
    /// kept for the final root check.
    #[test]
    fn open_sync_journal_keeps_unchecked_operations() {
        deterministic::Runner::default().start(|context| async move {
            let mut log = Log::new(
                context.child("init"),
                merkle_config(),
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
            let inactive_peaks = F::inactive_peaks(Location::new(50), Location::new(0));
            let root = log.root(inactive_peaks).unwrap();
            drop(log.sync().await.unwrap());

            // Reset the operations above the frontier, then download them again.
            let start = Location::new(42);
            let mut journal = authenticated::clear_sync::<_, Ops<_>>(
                context.child("reset"),
                journal_config(&context),
                *start,
            )
            .await
            .unwrap();
            for i in *start..50 {
                (journal, _) = journal.append(&op(i)).await.unwrap();
            }
            drop(journal.sync().await.unwrap());

            let target = Target {
                root,
                range: non_empty_range!(start, Location::new(50)),
            };
            let (_, journal, pins) = open_sync_journal::<F, _, Sha256, _, Ops<_>>(
                &context,
                context.child("log"),
                &merkle_config(),
                journal_config(&context),
                &target,
            )
            .await
            .unwrap();
            assert!(pins.is_none());
            assert_eq!(journal.bounds(), 42..50);
        });
    }

    #[test]
    fn open_sync_journal_keeps_rejection_until_journal_is_cleared() {
        deterministic::Runner::default().start(|context| async move {
            let faults = WriteFaults::default();
            let faulty = WriteFaultContext {
                inner: context.child("faulty"),
                faults: faults.clone(),
            };
            let frontier = Frontier::open(faulty.child("rejected"), "frontier".into())
                .await
                .unwrap();
            drop(frontier.reject().await.unwrap());
            let mut journal = Ops::init(faulty.child("first"), journal_config(&context))
                .await
                .unwrap();
            for i in 0..10 {
                (journal, _) = journal.append(&op(i)).await.unwrap();
            }
            drop(journal.sync().await.unwrap());
            let target = Target {
                root: sha256::Digest::from([0; 32]),
                range: non_empty_range!(Location::<F>::new(0), Location::new(20)),
            };

            // A failed reset must leave the rejection in place.
            faults.arm();
            assert!(
                open_sync_journal::<F, _, Sha256, _, Ops<_>>(
                    &faulty,
                    faulty.child("log"),
                    &merkle_config(),
                    journal_config(&context),
                    &target,
                )
                .await
                .is_err()
            );
            faults.disarm();
            let frontier = Frontier::open(faulty.child("reopened"), "frontier".into())
                .await
                .unwrap();
            assert!(frontier.rejected());
            drop(frontier);

            let (import, journal, pins) = open_sync_journal::<F, _, Sha256, _, Ops<_>>(
                &faulty,
                faulty.child("log"),
                &merkle_config(),
                journal_config(&context),
                &target,
            )
            .await
            .unwrap();
            assert!(!import.rejected());
            assert_eq!(journal.bounds(), 0..0);
            assert_eq!(pins, Some(Vec::new()));
        });
    }
}
