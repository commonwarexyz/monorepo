use crate::{
    Context,
    index::unordered::Index,
    journal::{authenticated, contiguous::Mutable},
    merkle::{Family, Location},
    qmdb::{
        self, Error,
        any::ValueEncoding,
        immutable::{self, CompactDb, Metrics, Operation},
        operation::Key,
        sync,
    },
    translator::Translator,
};
use commonware_codec::{EncodeShared, Read};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::num::NonZeroU64;

impl<F, E, K, V, C, H, T, S> sync::Database for immutable::Immutable<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + sync::Journal<F, Context = E, Op = Operation<F, K, V>>,
    C::Item: EncodeShared,
    C::Config: Clone + Send,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    type Family = F;
    type Op = Operation<F, K, V>;
    type Journal = C;
    type Hasher = H;
    type Config = immutable::Config<T, C::Config, S>;
    type Digest = H::Digest;
    type SyncState = authenticated::Frontier<F, E, H::Digest>;

    async fn begin_sync(
        context: &Self::Context,
        config: &Self::Config,
    ) -> Result<Self::SyncState, qmdb::Error<F>> {
        let context = context.child("journal");
        Ok(authenticated::Frontier::begin_import(context, &config.merkle_config).await?)
    }

    async fn stage_sync_frontier(
        state: Self::SyncState,
        location: Location<F>,
        pins: Vec<Self::Digest>,
    ) -> Result<Self::SyncState, qmdb::Error<F>> {
        Ok(state.stage(location, pins).await?)
    }

    async fn restart_rejected_import(
        state: Self::SyncState,
        journal: Self::Journal,
        start: Location<F>,
    ) -> Result<(Self::SyncState, Self::Journal), Error<F>> {
        qmdb::sync::restart_rejected_import(state, journal, start).await
    }

    type Context = E;

    /// Returns an [Immutable](immutable::Immutable) initialized from data collected in the sync process.
    ///
    /// Operations are replayed from the staged pruning frontier. The result remains
    /// provisional until the sync engine authenticates its root and persists it.
    ///
    /// # Returns
    ///
    /// A [super::Immutable] db populated with the state from the given range.
    /// The pruning boundary is set to the range start.
    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        log: Self::Journal,
        state: Self::SyncState,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, Error<F>> {
        let hasher = qmdb::hasher::<H>();

        let expected = pinned_nodes.unwrap_or_default();
        let boundary = state
            .candidate()
            .ok_or(authenticated::Error::MissingFrontier)?;
        if boundary.location != range.start() || boundary.digests != expected {
            return Err(crate::merkle::Error::InvalidPinnedNodes.into());
        }

        let journal = authenticated::Journal::<_, _, _, _, S>::from_components(
            state,
            db_config.merkle_config,
            log,
            hasher,
            apply_batch_size.get(),
        )
        .await?;

        let mut snapshot: Index<T, Location<F>> =
            Index::new(context.child("snapshot"), db_config.translator.clone());

        let size = journal.size();
        if size == 0 {
            return Err(Error::HistoricalFloorPruned(size));
        }
        let inactivity_floor_loc =
            crate::qmdb::find_inactivity_floor_at::<F, _>(&journal.journal, size).await?;

        // Replay the log from the inactivity floor to build the snapshot. Every retained
        // location is inserted, mirroring the live apply path, so a repeated key keeps
        // serving one of its written values across restarts and rewinds.
        immutable::build_snapshot(
            inactivity_floor_loc,
            &journal.journal,
            &mut snapshot,
            db_config.init_buffer,
        )
        .await?;
        let inactive_peaks = F::inactive_peaks(size, inactivity_floor_loc);
        let root = journal.root(inactive_peaks)?;

        let metrics = Metrics::new(context);
        let db = Self {
            journal,
            root,
            snapshot,
            inactivity_floor_loc,
            metrics,
        };
        db.update_metrics();

        Ok(db)
    }

    async fn persist_sync_result(mut self) -> Result<Self, Error<F>> {
        self.journal = self.journal.activate().await?;
        Ok(self)
    }

    async fn reject_sync_result(self) -> Result<(), Error<F>> {
        self.journal.frontier.reject().await?;
        Ok(())
    }

    async fn local_pinned_nodes(
        state: &Self::SyncState,
        config: &Self::Config,
        target: &sync::Target<F, Self::Digest>,
        journal: &Self::Journal,
    ) -> Result<Option<Vec<Self::Digest>>, Error<F>> {
        if target.range.start() == Location::new(0)
            || !sync::journal_covers_range(journal.bounds(), &target.range)
        {
            return Ok(None);
        }

        // The inactivity floor is carried by the last commit operation rather than being
        // the target range's start.
        let inactivity_floor =
            qmdb::find_inactivity_floor_at::<F, _>(journal, target.range.end()).await?;

        sync::local_pinned_nodes::<F, _, H, S, _>(
            state,
            &config.merkle_config,
            journal,
            target,
            inactivity_floor,
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

impl<F, E, K, V, H, Cfg, S> sync::Database for CompactDb<F, E, K, V, H, Cfg, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: Read<Cfg = Cfg>,
    Cfg: Clone + Send + Sync + 'static,
{
    type Family = F;
    type Op = Operation<F, K, V>;
    type Journal = sync::journal::Memory<F, E, Operation<F, K, V>>;
    type Config = immutable::CompactConfig<Cfg, S>;
    type Digest = H::Digest;
    type Context = E;
    type Hasher = H;
    type SyncState = ();

    async fn begin_sync(
        _context: &Self::Context,
        _config: &Self::Config,
    ) -> Result<(), qmdb::Error<F>> {
        Ok(())
    }
    async fn stage_sync_frontier(
        _state: (),
        _location: Location<F>,
        _pins: Vec<Self::Digest>,
    ) -> Result<(), qmdb::Error<F>> {
        Ok(())
    }
    async fn restart_rejected_import(
        state: (),
        journal: Self::Journal,
        _start: Location<F>,
    ) -> Result<((), Self::Journal), qmdb::Error<F>> {
        Ok((state, journal))
    }

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        _state: Self::SyncState,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        _apply_batch_size: NonZeroU64,
    ) -> Result<Self, Error<F>> {
        crate::qmdb::compact::from_sync_result(
            context,
            config,
            log,
            pinned_nodes,
            range,
            Self::init_from_sync,
        )
        .await
    }

    async fn persist_sync_result(self) -> Result<Self, Error<F>> {
        self.sync().await
    }

    async fn reject_sync_result(self) -> Result<(), Error<F>> {
        Ok(())
    }

    async fn local_pinned_nodes(
        _state: &Self::SyncState,
        _config: &Self::Config,
        _target: &sync::Target<F, Self::Digest>,
        _journal: &Self::Journal,
    ) -> Result<Option<Vec<Self::Digest>>, Error<F>> {
        Ok(None)
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

#[cfg(test)]
mod tests;
