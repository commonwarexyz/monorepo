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
    type Context = E;
    type SyncState = authenticated::Frontier<F, E, H::Digest>;

    async fn begin_sync(
        context: &Self::Context,
        config: &Self::Config,
    ) -> Result<Self::SyncState, Error<F>> {
        Ok(
            authenticated::Frontier::begin_import(context.child("journal"), &config.merkle_config)
                .await?,
        )
    }

    async fn open_sync_journal(
        state: Self::SyncState,
        context: Self::Context,
        config: &Self::Config,
        range: NonEmptyRange<Location<F>>,
    ) -> Result<(Self::SyncState, Self::Journal), Error<F>> {
        sync::open_sync_journal(state, context, config.log.clone(), range).await
    }

    async fn stage_sync_frontier(
        state: Self::SyncState,
        location: Location<F>,
        pins: Vec<Self::Digest>,
    ) -> Result<Self::SyncState, Error<F>> {
        Ok(state.stage(location, pins).await?)
    }

    /// Returns an [Immutable](immutable::Immutable) initialized from data collected in the sync process.
    ///
    /// The operations are authenticated by replaying them from the staged frontier, which must be
    /// the boundary the engine received for `range`. Nothing is persisted until
    /// [sync::Database::persist_sync_result].
    ///
    /// # Returns
    ///
    /// A [super::Immutable] db populated with the state from the given range.
    /// Its inactivity floor comes from the final commit, while the Merkle pruning boundary is
    /// the range start.
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

        // Initialize Merkle structure for sync
        // The staged frontier must be the boundary the engine authenticated.
        let expected = pinned_nodes.unwrap_or_default();
        let boundary = state
            .candidate()
            .ok_or(authenticated::Error::MissingFrontier)?;
        if boundary.location != range.start() || boundary.digests != expected {
            return Err(crate::merkle::Error::InvalidPinnedNodes.into());
        }

        let journal = authenticated::Journal::<F, _, _, _, S>::from_components(
            state,
            db_config.merkle_config.clone(),
            log,
            hasher,
            apply_batch_size,
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

        // Replay the log from the inactivity floor to build the snapshot.
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
        sync::local_pinned_nodes::<F, _, H, S, _>(state, &config.merkle_config, journal, target)
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
    ) -> Result<Self::SyncState, Error<F>> {
        Ok(())
    }

    async fn open_sync_journal(
        state: Self::SyncState,
        context: Self::Context,
        _config: &Self::Config,
        range: NonEmptyRange<Location<F>>,
    ) -> Result<(Self::SyncState, Self::Journal), Error<F>> {
        Ok((
            state,
            <Self::Journal as sync::Journal<F>>::open(context, (), range).await?,
        ))
    }

    async fn stage_sync_frontier(
        state: Self::SyncState,
        _location: Location<F>,
        _pins: Vec<Self::Digest>,
    ) -> Result<Self::SyncState, Error<F>> {
        Ok(state)
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
