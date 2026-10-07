use crate::{
    Context,
    journal::{authenticated, contiguous::Mutable},
    merkle::{Family, Location},
    qmdb::{
        self,
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
    V: Codec,
    C: Mutable<Item = Operation<F, V>>
        + sync::Journal<F, Context = E, Op = Operation<F, V>>
        + crate::journal::authenticated::ReplayEncoded,
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
    type Context = E;
    type SyncState = authenticated::Import<F, E, H::Digest, S>;

    async fn open_sync_journal(
        context: &Self::Context,
        config: &Self::Config,
        target: &sync::Target<F, Self::Digest>,
    ) -> Result<(Self::SyncState, Self::Journal, Option<Vec<Self::Digest>>), qmdb::Error<F>> {
        sync::open_sync_journal::<F, _, H, _, _>(
            context,
            context.child("journal"),
            &config.merkle,
            config.log.clone(),
            target,
        )
        .await
    }

    /// Returns a [Keyless] db initialized from data collected in the sync process.
    ///
    /// The operations are replayed from the boundary staged at `range`'s start. Nothing is
    /// persisted until [sync::Database::persist_sync_result].
    ///
    /// # Returns
    ///
    /// A [Keyless] db populated with the state from the given range.
    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        state: Self::SyncState,
        pinned_nodes: Vec<Self::Digest>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, qmdb::Error<F>> {
        let journal = authenticated::Journal::<F, _, _, _, S>::from_components(
            state,
            &config.merkle,
            log,
            qmdb::hasher::<H>(),
            range.start(),
            pinned_nodes,
            apply_batch_size,
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
        self.journal.reject().await?;
        Ok(())
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

impl<F, E, V, H, Cfg, S> sync::Database for CompactDb<F, E, V, H, Cfg, S>
where
    F: Family,
    E: Context,
    V: Codec,
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

    async fn open_sync_journal(
        context: &Self::Context,
        _config: &Self::Config,
        target: &sync::Target<F, Self::Digest>,
    ) -> Result<(Self::SyncState, Self::Journal, Option<Vec<Self::Digest>>), qmdb::Error<F>> {
        crate::qmdb::compact::open_sync_journal(context, target).await
    }

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        _state: Self::SyncState,
        pinned_nodes: Vec<Self::Digest>,
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

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

#[cfg(test)]
mod tests;
