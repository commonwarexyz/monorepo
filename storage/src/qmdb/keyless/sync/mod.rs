use crate::{
    Context,
    journal::{authenticated, contiguous::Mutable},
    merkle::{Family, Location},
    qmdb::{
        self,
        any::value::ValueEncoding,
        keyless::{CompactDb, Keyless, Metrics, Operation, operation::Codec},
        sync,
    },
};
use commonware_codec::{EncodeShared, Read};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::num::NonZeroU64;

impl<F, E, V, C, H, S> sync::Database for Keyless<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding + Codec,
    C: Mutable<Item = Operation<F, V>> + sync::Journal<F, Context = E, Op = Operation<F, V>>,
    C::Config: Clone + Send,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Family = F;
    type Op = Operation<F, V>;
    type Journal = C;
    type Hasher = H;
    type Config = super::Config<C::Config, S>;
    type Digest = H::Digest;
    type SyncState = authenticated::Frontier<F, E, H::Digest>;

    async fn begin_sync(
        context: &Self::Context,
        config: &Self::Config,
    ) -> Result<Self::SyncState, qmdb::Error<F>> {
        Ok(authenticated::Frontier::begin_import(context.child("journal"), &config.merkle).await?)
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
    ) -> Result<(Self::SyncState, Self::Journal), qmdb::Error<F>> {
        qmdb::sync::restart_rejected_import(state, journal, start).await
    }

    type Context = E;

    /// Returns a [Keyless] db initialized from data collected in the sync process.
    ///
    /// Operations are replayed from the staged pruning frontier. The result remains
    /// provisional until the sync engine authenticates its root and persists it.
    ///
    /// # Returns
    ///
    /// A [Keyless] db populated with the state from the given range.
    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        state: Self::SyncState,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, qmdb::Error<F>> {
        let hasher = qmdb::hasher::<H>();

        let expected = pinned_nodes.unwrap_or_default();
        let boundary = state
            .candidate()
            .ok_or(authenticated::Error::MissingFrontier)?;
        if boundary.location != range.start() || boundary.digests != expected {
            return Err(crate::merkle::Error::InvalidPinnedNodes.into());
        }

        let journal = authenticated::Journal::<F, _, _, _, S>::from_components(
            state,
            config.merkle,
            log,
            hasher,
            apply_batch_size.get(),
        )
        .await?;

        let size = journal.size();
        if size == 0 {
            return Err(qmdb::Error::HistoricalFloorPruned(size));
        }
        let inactivity_floor_loc = qmdb::find_inactivity_floor_at::<F, _>(&journal, size).await?;
        let inactive_peaks = F::inactive_peaks(size, inactivity_floor_loc);
        let root = journal.root(inactive_peaks)?;

        let metrics = Metrics::new(context);
        let db = Self {
            journal,
            root,
            inactivity_floor_loc,
            metrics,
        };
        db.update_metrics();

        Ok(db)
    }

    async fn persist_sync_result(mut self) -> Result<Self, qmdb::Error<F>> {
        self.journal = self.journal.activate().await?;
        Ok(self)
    }

    async fn reject_sync_result(self) -> Result<(), qmdb::Error<F>> {
        self.journal.frontier.reject().await?;
        Ok(())
    }

    async fn local_pinned_nodes(
        state: &Self::SyncState,
        config: &Self::Config,
        target: &sync::Target<F, Self::Digest>,
        journal: &Self::Journal,
    ) -> Result<Option<Vec<Self::Digest>>, qmdb::Error<F>> {
        if !sync::journal_covers_range(journal.bounds(), &target.range) {
            return Ok(None);
        }

        // The inactivity floor is carried by the last commit operation rather than being
        // the target range's start.
        let Some(inactivity_floor) = sync::retained_floor(journal, target.range.end()).await?
        else {
            return Ok(None);
        };

        sync::local_pinned_nodes::<F, _, H, S, _>(
            state,
            &config.merkle,
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

impl<F, E, V, H, Cfg, S> sync::Database for CompactDb<F, E, V, H, Cfg, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding + Codec,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read<Cfg = Cfg>,
    Cfg: Clone + Send + Sync + 'static,
{
    type Family = F;
    type Op = Operation<F, V>;
    type Journal = sync::journal::Memory<F, E, Operation<F, V>>;
    type Config = super::CompactConfig<Cfg, S>;
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
    ) -> Result<Self, qmdb::Error<F>> {
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

    async fn persist_sync_result(self) -> Result<Self, qmdb::Error<F>> {
        self.sync().await
    }

    async fn reject_sync_result(self) -> Result<(), qmdb::Error<F>> {
        Ok(())
    }

    async fn local_pinned_nodes(
        _state: &Self::SyncState,
        _config: &Self::Config,
        _target: &sync::Target<F, Self::Digest>,
        _journal: &Self::Journal,
    ) -> Result<Option<Vec<Self::Digest>>, qmdb::Error<F>> {
        Ok(None)
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

#[cfg(test)]
mod tests;
