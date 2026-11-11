use crate::{
    Context,
    journal::{authenticated, contiguous::Mutable},
    merkle::{
        Family, Location,
        full::{self, Merkle},
    },
    qmdb::{
        self, Error,
        immutable::{self, Metrics, Operation},
        operation::Key,
        sync,
        value::ValueEncoding,
    },
    translator::Translator,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::{num::NonZeroU64, ops::Range};

impl<F, E, K, V, C, H, T, S> sync::Database for immutable::Db<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + sync::Journal<F, Context = E, Op = Operation<F, K, V>>,
    C::Item: EncodeShared,
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

    /// Returns a [Db](immutable::Db) initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the Merkle journal is empty or the last item is before the range start, it creates a
    ///   fresh Merkle structure from the provided `pinned_nodes`
    /// - If the Merkle journal has data but is incomplete (has length < range end), missing
    ///   operations from the log are applied to bring it up to the target state
    /// - If the Merkle journal has data beyond the range end, initialization truncates it to the
    ///   sync target
    ///
    /// # Returns
    ///
    /// A [super::Db] populated with the state from the given range.
    /// Its inactivity floor comes from the final commit, while the Merkle pruning boundary is
    /// the range start.
    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, Error<F>> {
        let hasher = qmdb::hasher::<H>();

        // Initialize Merkle structure for sync
        let merkle = Merkle::<F, _, _, S>::init_sync(
            context.child("merkle"),
            full::SyncConfig {
                config: db_config.merkle,
                range: range.clone(),
                pinned_nodes,
            },
        )
        .await?;

        let journal = authenticated::Journal::<_, _, _, _, S>::from_components(
            merkle,
            log,
            hasher,
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
            crate::qmdb::find_inactivity_floor_at::<F, _>(&journal.journal, size).await?;

        // Replay the log from the inactivity floor to build the snapshot.
        let snapshot = immutable::build_snapshot(
            context.child("snapshot"),
            db_config.translator,
            inactivity_floor_loc,
            &journal.journal,
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

        db.sync().await
    }

    async fn persist_sync_result(self) -> Result<Self, Error<F>> {
        Ok(self)
    }

    async fn discard_local_state(
        context: Self::Context,
        config: &Self::Config,
        resumed: Range<Location<F>>,
    ) -> Result<(), Error<F>> {
        sync::discard_local_state::<F, _, H, S>(context, config.merkle.clone(), resumed).await
    }

    async fn local_pinned_nodes(
        context: Self::Context,
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

        sync::local_pinned_nodes::<F, _, H, S>(
            context,
            config.merkle.clone(),
            target,
            inactivity_floor,
        )
        .await
    }

    fn ops_root(&self) -> Self::Digest {
        self.root()
    }
}

#[cfg(test)]
mod tests;
