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
    C: Mutable<Item = Operation<F, V>> + sync::Journal<F, Context = E, Op = Operation<F, V>>,
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

    /// Returns a [Keyless] db initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// The range start becomes the pruning boundary, with `pinned_nodes` as its pinned digests,
    /// and the Merkle digests are rebuilt by replaying the log from there.
    ///
    /// # Returns
    ///
    /// A [Keyless] db populated with the state from the given range.
    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, qmdb::Error<F>> {
        let hasher = qmdb::hasher::<H>();

        let journal = authenticated::Journal::<F, _, _, _, S>::from_components(
            context.child("merkle"),
            &config.merkle,
            log,
            hasher,
            range.start(),
            pinned_nodes.unwrap_or_default(),
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

        db.sync().await
    }

    async fn persist_sync_result(self) -> Result<Self, qmdb::Error<F>> {
        Ok(self)
    }

    async fn local_pinned_nodes(
        context: Self::Context,
        config: &Self::Config,
        target: &sync::Target<F, Self::Digest>,
        journal: &Self::Journal,
    ) -> Result<Option<Vec<Self::Digest>>, qmdb::Error<F>> {
        if target.range.start() == Location::new(0)
            || !sync::journal_covers_range(journal.bounds(), &target.range)
        {
            return Ok(None);
        }

        sync::local_pinned_nodes::<F, _, H, S>(context, config.merkle.clone(), target, journal)
            .await
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

impl<F, E, V, H, S> sync::Database for CompactDb<F, E, V, H, S>
where
    F: Family,
    E: Context,
    V: Codec,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read,
{
    type Family = F;
    type Op = Operation<F, V>;
    type Journal = sync::journal::Memory<F, E, Operation<F, V>>;
    type Config = super::CompactConfig<<Operation<F, V> as Read>::Cfg, S>;
    type Digest = H::Digest;
    type Context = E;
    type Hasher = H;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
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

    async fn local_pinned_nodes(
        _context: Self::Context,
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
