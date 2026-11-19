use crate::{
    Context,
    journal::authenticated,
    merkle::{
        Family, Location,
        full::{self, Merkle},
    },
    qmdb::{
        self,
        keyless::{Db, Operation, operation::OperationCodec},
        metrics::Metrics,
        sync,
    },
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::num::NonZeroU64;

impl<F, E, V, C, H, S> sync::Database for Db<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: OperationCodec,
    C: sync::Journal<F, Context = E, Op = Operation<F, V>>
        + authenticated::Backing<E, Item = Operation<F, V>, Config = <C as sync::Journal<F>>::Config>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Family = F;
    type Op = Operation<F, V>;
    type Journal = C;
    type Hasher = H;
    type Config = super::Config<<C as sync::Journal<F>>::Config, S>;
    type Digest = H::Digest;
    type Context = E;

    async fn init(
        context: E,
        config: Self::Config,
        max_size: Option<Location<F>>,
    ) -> Result<Self, qmdb::Error<F>> {
        Self::init(context, config, max_size).await
    }

    fn target(&self) -> sync::Target<F, H::Digest> {
        sync::Target {
            root: self.root(),
            range: commonware_utils::non_empty_range!(self.sync_boundary(), self.bounds().end),
        }
    }

    async fn prune_to_target(
        self,
        target: &sync::Target<F, H::Digest>,
    ) -> Result<Self, qmdb::Error<F>> {
        self.prune(target.range.start()).await
    }
}

impl<F, E, V, C, H, S> sync::Hooks<Self> for Db<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: OperationCodec,
    C: sync::Journal<F, Context = E, Op = Operation<F, V>>
        + authenticated::Backing<E, Item = Operation<F, V>, Config = <C as sync::Journal<F>>::Config>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Returns a [Db] initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the Merkle journal is empty or the last item is before the range start, it creates
    ///   a fresh Merkle structure from the provided `pinned_nodes`
    /// - If the Merkle journal has data but is incomplete (has length < range end), missing
    ///   operations from the log are applied to bring it up to the target state
    /// - If the Merkle journal has data beyond the range end, initialization truncates it to the
    ///   sync target
    ///
    /// # Returns
    ///
    /// A [Db] populated with the state from the given range.
    async fn from_sync_result(
        context: E,
        config: <Self as sync::Database>::Config,
        log: C,
        pinned_nodes: Option<Vec<H::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, qmdb::Error<F>> {
        let hasher = qmdb::hasher::<H>();

        let merkle = Merkle::<F, _, _, S>::init_sync(
            context.child("merkle"),
            full::SyncConfig {
                config: config.merkle.clone(),
                range: range.clone(),
                pinned_nodes,
            },
        )
        .await?;

        let journal = authenticated::Journal::<F, _, _, _, S>::from_components(
            merkle,
            log,
            hasher,
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

    async fn discard_local_state(
        context: E,
        config: &<Self as sync::Database>::Config,
    ) -> Result<(), qmdb::Error<F>> {
        sync::discard_local_state::<F, _, H, S>(context, config.merkle.clone()).await
    }

    async fn local_pinned_nodes(
        context: E,
        config: &<Self as sync::Database>::Config,
        target: &sync::Target<F, H::Digest>,
        journal: &C,
    ) -> Result<Option<Vec<H::Digest>>, qmdb::Error<F>> {
        if target.range.start() == Location::new(0)
            || !sync::journal_covers_range(journal.bounds(), &target.range)
        {
            return Ok(None);
        }

        // The inactivity floor is carried by the last commit operation rather than being
        // the target range's start.
        let inactivity_floor =
            qmdb::find_inactivity_floor_at::<F, _>(journal, target.range.end()).await?;

        sync::local_pinned_nodes::<F, _, H, S>(
            context,
            config.merkle.clone(),
            target,
            inactivity_floor,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
