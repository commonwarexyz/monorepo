use crate::{
    Context,
    journal::authenticated,
    merkle::{Family, Location},
    qmdb::{
        self, Error,
        immutable::{self, Operation},
        metrics::Metrics,
        operation::Key,
        sync,
        value::ValueEncoding,
    },
    translator::Translator,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_utils::range::NonEmptyRange;
use std::num::NonZeroU64;

impl<F, E, K, V, C, H, T, S> sync::Database for immutable::Db<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context + Spawner,
    K: Key,
    V: ValueEncoding,
    C: sync::Journal<F, Context = E, Op = Operation<F, K, V>>
        + authenticated::Backing<
            E,
            Item = Operation<F, K, V>,
            Config = <C as sync::Journal<F>>::Config,
        > + 'static,
    C::Item: EncodeShared,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    type Family = F;
    type Op = Operation<F, K, V>;
    type Journal = C;
    type Hasher = H;
    type Config = immutable::Config<T, <C as sync::Journal<F>>::Config, S>;
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

impl<F, E, K, V, C, H, T, S> sync::Hooks<Self> for immutable::Db<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context + Spawner,
    K: Key,
    V: ValueEncoding,
    C: sync::Journal<F, Context = E, Op = Operation<F, K, V>>
        + authenticated::Backing<
            E,
            Item = Operation<F, K, V>,
            Config = <C as sync::Journal<F>>::Config,
        > + 'static,
    C::Item: EncodeShared,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    /// Returns a [Db](immutable::Db) initialized from data collected in the sync process.
    ///
    /// The range start becomes the pruning boundary, with `pinned_nodes` as its pinned digests,
    /// and the Merkle digests are rebuilt by replaying the log from there.
    ///
    /// # Returns
    ///
    /// A [super::Db] populated with the state from the given range.
    /// Its inactivity floor comes from the final commit, while the Merkle pruning boundary is
    /// the range start.
    async fn from_sync_result(
        context: E,
        db_config: <Self as sync::Database>::Config,
        log: C,
        pinned_nodes: Option<Vec<H::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, Error<F>> {
        let hasher = qmdb::hasher::<H>();

        let journal = authenticated::Journal::<_, _, _, _, S>::from_components(
            context.child("merkle"),
            &db_config.merkle,
            log,
            hasher,
            range.start(),
            pinned_nodes.unwrap_or_default(),
            apply_batch_size,
        )
        .await?;

        // The synced range ends at the target commit, whose inactivity floor is where the
        // snapshot replay starts. An empty journal holds no commit to take the floor from.
        let size = journal.size();
        if size == 0 {
            return Err(Error::HistoricalFloorPruned(size));
        }
        let inactivity_floor_loc =
            crate::qmdb::find_inactivity_floor_at::<F, _>(&journal, size).await?;

        // Replay the log from the inactivity floor to build the snapshot.
        let snapshot = immutable::db::build_snapshot(
            context.child("snapshot"),
            db_config.translator,
            inactivity_floor_loc,
            &journal,
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
        self.journal = self.journal.persist_boundary().await?;
        Ok(self)
    }

    async fn discard_local_state(
        context: E,
        config: &<Self as sync::Database>::Config,
    ) -> Result<(), Error<F>> {
        Ok(authenticated::discard_frontier::<F, _, H, S>(context, &config.merkle).await?)
    }

    async fn local_pinned_nodes(
        context: E,
        config: &<Self as sync::Database>::Config,
        target: &sync::Target<F, H::Digest>,
        journal: &C,
    ) -> Result<Option<Vec<H::Digest>>, Error<F>> {
        sync::local_pinned_nodes::<F, _, H, S>(context, &config.merkle, target, journal).await
    }
}

#[cfg(test)]
mod tests;
