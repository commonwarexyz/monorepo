use crate::{
    Context,
    index::unordered::Index,
    journal::authenticated,
    merkle::{
        Family, Location,
        full::{self, Merkle},
    },
    qmdb::{
        self, Error,
        any::ValueEncoding,
        build_snapshot_from_log,
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
    C: sync::Journal<F, Context = E, Op = Operation<F, K, V>>
        + authenticated::Backing<
            E,
            Item = Operation<F, K, V>,
            Config = <C as sync::Journal<F>>::Config,
        >,
    Operation<F, K, V>: EncodeShared,
    <C as sync::Journal<F>>::Config: Clone + Send,
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

    /// Returns an [Immutable](immutable::Immutable) initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the Merkle journal is empty or the last item is before the range start, it creates a
    ///   fresh Merkle structure from the provided `pinned_nodes`
    /// - If the Merkle journal has data but is incomplete (has length < range end), missing
    ///   operations from the log are applied to bring it up to the target state
    /// - If the Merkle journal has data beyond the range end, it is rewound to match the sync
    ///   target
    ///
    /// # Returns
    ///
    /// A [super::Immutable] db populated with the state from the given range.
    /// The pruning boundary is set to the range start.
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
                config: db_config.merkle_config.clone(),
                range: range.clone(),
                pinned_nodes,
            },
        )
        .await?;

        let journal = authenticated::Journal::<_, _, _, _, S>::from_components(
            merkle,
            log,
            hasher,
            apply_batch_size.get(),
        )
        .await?;

        let mut snapshot: Index<T, Location<F>> =
            Index::new(context.child("snapshot"), db_config.translator.clone());

        let (last_commit_loc, inactivity_floor_loc) = {
            let bounds = journal.journal.bounds();
            let last_commit_loc = Location::<F>::new(
                bounds
                    .end
                    .checked_sub(1)
                    .ok_or(Error::HistoricalFloorPruned(Location::new(bounds.end)))?,
            );
            let inactivity_floor_loc = crate::qmdb::find_inactivity_floor_at::<F, _>(
                &journal.journal,
                Location::new(bounds.end),
            )
            .await?
            .ok_or(Error::HistoricalFloorPruned(Location::new(bounds.end)))?;

            // Replay the log from the inactivity floor to build the snapshot.
            build_snapshot_from_log::<F, _, _, _>(
                inactivity_floor_loc,
                &journal.journal,
                &mut snapshot,
                db_config.init_buffer,
                db_config.init_cache_size,
                |_, _| {},
            )
            .await?;

            (last_commit_loc, inactivity_floor_loc)
        };
        let inactive_peaks = F::inactive_peaks(last_commit_loc + 1, inactivity_floor_loc);
        let root = journal.root(inactive_peaks)?;

        let metrics = Metrics::new(context);
        let db = Self {
            journal,
            root,
            snapshot,
            last_commit_loc,
            inactivity_floor_loc,
            metrics,
        };
        db.update_metrics();

        db.sync().await
    }

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        Self::init(context, config).await
    }

    async fn persist_sync_result(self) -> Result<Self, Error<F>> {
        Ok(self)
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
        let inactivity_floor = qmdb::find_inactivity_floor_at::<F, _>(journal, target.range.end())
            .await?
            .ok_or(Error::HistoricalFloorPruned(target.range.end()))?;

        sync::local_pinned_nodes::<F, _, H, S>(
            context,
            config.merkle_config.clone(),
            target,
            inactivity_floor,
        )
        .await
    }

    fn target(&self) -> sync::Target<F, H::Digest> {
        sync::Target {
            root: self.root(),
            range: commonware_utils::non_empty_range!(self.sync_boundary(), self.bounds().end),
        }
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

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
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

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        Self::init(context, config).await
    }

    async fn persist_sync_result(self) -> Result<Self, Error<F>> {
        self.sync().await
    }

    async fn local_pinned_nodes(
        _context: Self::Context,
        _config: &Self::Config,
        _target: &sync::Target<F, Self::Digest>,
        _journal: &Self::Journal,
    ) -> Result<Option<Vec<Self::Digest>>, Error<F>> {
        Ok(None)
    }

    fn target(&self) -> sync::Target<F, H::Digest> {
        self.target()
    }

    fn validate_target(
        target: &sync::Target<F, H::Digest>,
    ) -> Result<(), sync::EngineError<F, H::Digest>> {
        qmdb::compact::validate_target(target)
    }
}

#[cfg(test)]
mod tests;
