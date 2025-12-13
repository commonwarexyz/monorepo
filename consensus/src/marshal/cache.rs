use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Finalization, Notarization},
    },
    types::{Epoch, Round, View},
    Block,
};
use commonware_codec::Codec;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{self, prunable, Archive as _, Identifier},
    metadata::{self, Metadata},
    translator::TwoCap,
};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{
    cmp::max,
    collections::BTreeMap,
    num::{NonZero, NonZeroUsize},
    time::Instant,
};
use tracing::{debug, info};

// The key used to store the current epoch in the metadata store.
const CACHED_EPOCHS_KEY: u8 = 0;

/// Configuration parameters for prunable archives.
pub(crate) struct Config {
    pub partition_prefix: String,
    pub prunable_items_per_section: NonZero<u64>,
    pub replay_buffer: NonZeroUsize,
    pub write_buffer: NonZeroUsize,
    pub freezer_journal_buffer_pool: PoolRef,
}

/// Prunable archives for a single epoch.
struct Cache<R: Rng + Spawner + Metrics + Clock + GClock + Storage, B: Block, S: Scheme> {
    /// Verified blocks stored by view
    verified_blocks: prunable::Archive<TwoCap, R, B::Commitment, B>,
    /// Notarized blocks stored by view
    notarized_blocks: prunable::Archive<TwoCap, R, B::Commitment, B>,
    /// Notarizations stored by view
    notarizations: prunable::Archive<TwoCap, R, B::Commitment, Notarization<S, B::Commitment>>,
    /// Finalizations stored by view
    finalizations: prunable::Archive<TwoCap, R, B::Commitment, Finalization<S, B::Commitment>>,
}

impl<R: Rng + Spawner + Metrics + Clock + GClock + Storage, B: Block, S: Scheme> Cache<R, B, S> {
    /// Prune the archives to the given view.
    async fn prune(&mut self, min_view: View) {
        match futures::try_join!(
            self.verified_blocks.prune(min_view.get()),
            self.notarized_blocks.prune(min_view.get()),
            self.notarizations.prune(min_view.get()),
            self.finalizations.prune(min_view.get()),
        ) {
            Ok(_) => debug!(min_view = %min_view, "pruned archives"),
            Err(e) => panic!("failed to prune archives: {e}"),
        }
    }
}

/// Manages prunable caches and their metadata.
pub(crate) struct Manager<
    R: Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme,
> {
    /// Context
    context: R,

    /// Configuration for underlying prunable archives
    cfg: Config,

    /// Codec configuration for block type
    block_codec_config: B::Cfg,

    /// Metadata store for recording which epochs may have data. The value is a tuple of the floor
    /// and ceiling, the minimum and maximum epochs (inclusive) that may have data.
    metadata: Metadata<R, u8, (Epoch, Epoch)>,

    /// A map from epoch to its cache
    caches: BTreeMap<Epoch, Cache<R, B, S>>,
}

impl<R: Rng + Spawner + Metrics + Clock + GClock + Storage, B: Block, S: Scheme> Manager<R, B, S> {
    /// Initialize the cache manager and its metadata store.
    pub(crate) async fn init(context: R, cfg: Config, block_codec_config: B::Cfg) -> Self {
        // Initialize metadata
        let metadata = Metadata::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", cfg.partition_prefix),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize metadata");

        // We don't eagerly initialize any epoch caches here, they will be
        // initialized on demand, otherwise there could be coordination issues
        // around the scheme provider.
        Self {
            context,
            cfg,
            block_codec_config,
            metadata,
            caches: BTreeMap::new(),
        }
    }

    /// Retrieve the epoch range that may have data.
    fn get_metadata(&self) -> (Epoch, Epoch) {
        self.metadata
            .get(&CACHED_EPOCHS_KEY)
            .cloned()
            .unwrap_or((Epoch::zero(), Epoch::zero()))
    }

    /// Set the epoch range that may have data.
    async fn set_metadata(&mut self, floor: Epoch, ceiling: Epoch) {
        self.metadata
            .put_sync(CACHED_EPOCHS_KEY, (floor, ceiling))
            .await
            .expect("failed to write metadata");
    }

    /// Get the cache for the given epoch, initializing it if it doesn't exist.
    ///
    /// If the epoch is less than the minimum cached epoch, then it has already been pruned,
    /// and this will return `None`.
    async fn get_or_init_epoch(&mut self, epoch: Epoch) -> Option<&mut Cache<R, B, S>> {
        // If the cache exists, return it
        if self.caches.contains_key(&epoch) {
            return self.caches.get_mut(&epoch);
        }

        // If the epoch is less than the epoch floor, then it has already been pruned
        let (floor, ceiling) = self.get_metadata();
        if epoch < floor {
            return None;
        }

        // Update the metadata (metadata-first is safe; init is idempotent)
        if epoch > ceiling {
            self.set_metadata(floor, epoch).await;
        }

        // Initialize and return the epoch
        self.init_epoch(epoch).await;
        self.caches.get_mut(&epoch) // Should always be Some
    }

    /// Helper to initialize the cache for a given epoch.
    async fn init_epoch(&mut self, epoch: Epoch) {
        let verified_blocks = self
            .init_archive(epoch, "verified", self.block_codec_config.clone())
            .await;
        let notarized_blocks = self
            .init_archive(epoch, "notarized", self.block_codec_config.clone())
            .await;
        let notarizations = self
            .init_archive(
                epoch,
                "notarizations",
                S::certificate_codec_config_unbounded(),
            )
            .await;
        let finalizations = self
            .init_archive(
                epoch,
                "finalizations",
                S::certificate_codec_config_unbounded(),
            )
            .await;
        let existing = self.caches.insert(
            epoch,
            Cache {
                verified_blocks,
                notarized_blocks,
                notarizations,
                finalizations,
            },
        );
        assert!(existing.is_none(), "cache already exists for epoch {epoch}");
    }

    /// Helper to initialize an archive.
    async fn init_archive<T: Codec>(
        &self,
        epoch: Epoch,
        name: &str,
        codec_config: T::Cfg,
    ) -> prunable::Archive<TwoCap, R, B::Commitment, T> {
        let start = Instant::now();
        let cfg = prunable::Config {
            partition: format!("{}-cache-{epoch}-{name}", self.cfg.partition_prefix),
            translator: TwoCap,
            items_per_section: self.cfg.prunable_items_per_section,
            compression: None,
            codec_config,
            buffer_pool: self.cfg.freezer_journal_buffer_pool.clone(),
            replay_buffer: self.cfg.replay_buffer,
            write_buffer: self.cfg.write_buffer,
        };
        let archive = prunable::Archive::init(self.context.with_label(name), cfg)
            .await
            .unwrap_or_else(|_| panic!("failed to initialize {name} archive"));
        info!(elapsed = ?start.elapsed(), "restored {name} archive");
        archive
    }

    /// Add a verified block to the prunable archive.
    pub(crate) async fn put_verified(&mut self, round: Round, commitment: B::Commitment, block: B) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .verified_blocks
            .put_sync(round.view().get(), commitment, block)
            .await;
        Self::handle_result(result, round, "verified");
    }

    /// Add a notarized block to the prunable archive.
    pub(crate) async fn put_block(&mut self, round: Round, commitment: B::Commitment, block: B) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .notarized_blocks
            .put_sync(round.view().get(), commitment, block)
            .await;
        Self::handle_result(result, round, "notarized");
    }

    /// Add a notarization to the prunable archive.
    pub(crate) async fn put_notarization(
        &mut self,
        round: Round,
        commitment: B::Commitment,
        notarization: Notarization<S, B::Commitment>,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .notarizations
            .put_sync(round.view().get(), commitment, notarization)
            .await;
        Self::handle_result(result, round, "notarization");
    }

    /// Add a finalization to the prunable archive.
    pub(crate) async fn put_finalization(
        &mut self,
        round: Round,
        commitment: B::Commitment,
        finalization: Finalization<S, B::Commitment>,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .finalizations
            .put_sync(round.view().get(), commitment, finalization)
            .await;
        Self::handle_result(result, round, "finalization");
    }

    /// Helper to debug cache results.
    fn handle_result(result: Result<(), archive::Error>, round: Round, name: &str) {
        match result {
            Ok(_) => {
                debug!(?round, name, "cached");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(?round, name, "already pruned");
            }
            Err(e) => {
                panic!("failed to insert {name}: {e}");
            }
        }
    }

    /// Get a notarization from the prunable archive by round.
    pub(crate) async fn get_notarization(
        &self,
        round: Round,
    ) -> Option<Notarization<S, B::Commitment>> {
        let cache = self.caches.get(&round.epoch())?;
        cache
            .notarizations
            .get(Identifier::Index(round.view().get()))
            .await
            .expect("failed to get notarization")
    }

    /// Get a finalization from the prunable archive by commitment.
    pub(crate) async fn get_finalization_for(
        &self,
        commitment: B::Commitment,
    ) -> Option<Finalization<S, B::Commitment>> {
        for cache in self.caches.values().rev() {
            match cache.finalizations.get(Identifier::Key(&commitment)).await {
                Ok(Some(finalization)) => return Some(finalization),
                Ok(None) => continue,
                Err(e) => panic!("failed to get cached finalization: {e}"),
            }
        }
        None
    }

    /// Looks for a block (verified or notarized).
    pub(crate) async fn find_block(&self, commitment: B::Commitment) -> Option<B> {
        // Check in reverse order
        for cache in self.caches.values().rev() {
            // Check verified blocks
            if let Some(block) = cache
                .verified_blocks
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get verified block")
            {
                return Some(block);
            }

            // Check notarized blocks
            if let Some(block) = cache
                .notarized_blocks
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get notarized block")
            {
                return Some(block);
            }
        }
        None
    }

    /// Prune the caches below the given round.
    pub(crate) async fn prune(&mut self, round: Round) {
        // Remove and close prunable archives from older epochs
        let new_floor = round.epoch();
        let old_epochs: Vec<Epoch> = self
            .caches
            .keys()
            .copied()
            .filter(|epoch| *epoch < new_floor)
            .collect();
        for epoch in old_epochs.iter() {
            let Cache::<R, B, S> {
                verified_blocks: vb,
                notarized_blocks: nb,
                notarizations: nv,
                finalizations: fv,
                ..
            } = self.caches.remove(epoch).unwrap();
            vb.destroy().await.expect("failed to destroy vb");
            nb.destroy().await.expect("failed to destroy nb");
            nv.destroy().await.expect("failed to destroy nv");
            fv.destroy().await.expect("failed to destroy fv");
        }

        // Update metadata if necessary
        let (floor, ceiling) = self.get_metadata();
        if new_floor > floor {
            let new_ceiling = max(ceiling, new_floor);
            self.set_metadata(new_floor, new_ceiling).await;
        }

        // Prune archives for the given epoch
        let min_view = round.view();
        if let Some(prunable) = self.caches.get_mut(&round.epoch()) {
            prunable.prune(min_view).await;
        }
    }
}
