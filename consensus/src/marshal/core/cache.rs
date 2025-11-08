use crate::{
    marshal::core::Variant,
    simplex::types::{Finalization, Notarization},
    types::{Epoch, Round, View},
};
use commonware_codec::{CodecShared, Read};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_runtime::{buffer::paged::CacheRef, BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{self, prunable, Archive as _, Identifier},
    metadata::{self, Metadata},
    translator::TwoCap,
};
use rand::Rng;
use std::{
    cmp::max,
    collections::BTreeMap,
    num::{NonZero, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

// The key used to store the current epoch in the metadata store.
const CACHED_EPOCHS_KEY: u8 = 0;

/// Configuration parameters for prunable archives.
pub(crate) struct Config {
    pub partition_prefix: String,
    pub prunable_items_per_section: NonZero<u64>,
    pub replay_buffer: NonZeroUsize,
    pub key_write_buffer: NonZeroUsize,
    pub value_write_buffer: NonZeroUsize,
    pub key_page_cache: CacheRef,
}

/// Prunable archives for a single epoch.
#[allow(clippy::type_complexity)]
struct Cache<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
    /// Scoped context that keeps this epoch's metrics alive until the cache is dropped.
    _scope: R,
    /// Verified blocks stored by view
    verified_blocks: prunable::Archive<TwoCap, R, <V::Block as Digestible>::Digest, V::StoredBlock>,
    /// Notarized blocks stored by view
    notarized_blocks:
        prunable::Archive<TwoCap, R, <V::Block as Digestible>::Digest, V::StoredBlock>,
    /// Notarizations stored by view
    notarizations: prunable::Archive<
        TwoCap,
        R,
        <V::Block as Digestible>::Digest,
        Notarization<S, V::Commitment>,
    >,
    /// Finalizations stored by view
    finalizations: prunable::Archive<
        TwoCap,
        R,
        <V::Block as Digestible>::Digest,
        Finalization<S, V::Commitment>,
    >,
}

impl<R, V, S> Cache<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
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
pub(crate) struct Manager<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
    /// Context
    context: R,

    /// Configuration for underlying prunable archives
    cfg: Config,

    /// Codec configuration for block type
    block_codec_config: <V::Block as Read>::Cfg,

    /// Metadata store for recording which epochs may have data. The value is a tuple of the floor
    /// and ceiling, the minimum and maximum epochs (inclusive) that may have data.
    metadata: Metadata<R, u8, (Epoch, Epoch)>,

    /// A map from epoch to its cache
    caches: BTreeMap<Epoch, Cache<R, V, S>>,
}

impl<R, V, S> Manager<R, V, S>
where
    R: BufferPooler + Rng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    S: Scheme,
{
    /// Initialize the cache manager and its metadata store.
    pub(crate) async fn init(
        context: R,
        cfg: Config,
        block_codec_config: <V::Block as Read>::Cfg,
    ) -> Self {
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
    async fn get_or_init_epoch(&mut self, epoch: Epoch) -> Option<&mut Cache<R, V, S>> {
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
        let scope = self
            .context
            .with_label("cache")
            .with_attribute("epoch", epoch)
            .with_scope();
        let (verified_blocks, notarized_blocks, notarizations, finalizations) = futures::join!(
            Self::init_archive(
                &scope,
                &self.cfg,
                epoch,
                "verified",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &scope,
                &self.cfg,
                epoch,
                "notarized",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &scope,
                &self.cfg,
                epoch,
                "notarizations",
                S::certificate_codec_config_unbounded(),
            ),
            Self::init_archive(
                &scope,
                &self.cfg,
                epoch,
                "finalizations",
                S::certificate_codec_config_unbounded(),
            ),
        );
        let existing = self.caches.insert(
            epoch,
            Cache {
                _scope: scope,
                verified_blocks,
                notarized_blocks,
                notarizations,
                finalizations,
            },
        );
        assert!(existing.is_none(), "cache already exists for epoch {epoch}");
    }

    /// Helper to initialize an archive.
    async fn init_archive<T: CodecShared>(
        ctx: &R,
        cfg: &Config,
        epoch: Epoch,
        name: &str,
        codec_config: T::Cfg,
    ) -> prunable::Archive<TwoCap, R, <V::Block as Digestible>::Digest, T> {
        let start = ctx.current();
        let archive_cfg = prunable::Config {
            translator: TwoCap,
            key_partition: format!("{}-cache-{epoch}-{name}-key", cfg.partition_prefix),
            key_page_cache: cfg.key_page_cache.clone(),
            value_partition: format!("{}-cache-{epoch}-{name}-value", cfg.partition_prefix),
            items_per_section: cfg.prunable_items_per_section,
            compression: None,
            codec_config,
            replay_buffer: cfg.replay_buffer,
            key_write_buffer: cfg.key_write_buffer,
            value_write_buffer: cfg.value_write_buffer,
        };
        let archive = prunable::Archive::init(ctx.with_label(name), archive_cfg)
            .await
            .unwrap_or_else(|_| panic!("failed to initialize {name} archive"));
        info!(elapsed = ?ctx.current().duration_since(start).unwrap_or(Duration::ZERO), "restored {name} archive");
        archive
    }

    /// Add a verified block to the prunable archive.
    pub(crate) async fn put_verified(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        block: V::StoredBlock,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .verified_blocks
            .put_sync(round.view().get(), digest, block)
            .await;
        Self::handle_result(result, round, "verified");
    }

    /// Add a notarized block to the prunable archive.
    pub(crate) async fn put_block(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        block: V::StoredBlock,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .notarized_blocks
            .put_sync(round.view().get(), digest, block)
            .await;
        Self::handle_result(result, round, "notarized");
    }

    /// Add a notarization to the prunable archive.
    pub(crate) async fn put_notarization(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        notarization: Notarization<S, V::Commitment>,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .notarizations
            .put_sync(round.view().get(), digest, notarization)
            .await;
        Self::handle_result(result, round, "notarization");
    }

    /// Add a finalization to the prunable archive.
    pub(crate) async fn put_finalization(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        finalization: Finalization<S, V::Commitment>,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .finalizations
            .put_sync(round.view().get(), digest, finalization)
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
    ) -> Option<Notarization<S, V::Commitment>> {
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
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<Finalization<S, V::Commitment>> {
        for cache in self.caches.values().rev() {
            match cache.finalizations.get(Identifier::Key(&digest)).await {
                Ok(Some(finalization)) => return Some(finalization),
                Ok(None) => continue,
                Err(e) => panic!("failed to get cached finalization: {e}"),
            }
        }
        None
    }

    /// Looks for a block (verified or notarized).
    pub(crate) async fn find_block(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<V::StoredBlock> {
        // Check in reverse order
        for cache in self.caches.values().rev() {
            // Check verified blocks
            if let Some(block) = cache
                .verified_blocks
                .get(Identifier::Key(&digest))
                .await
                .expect("failed to get verified block")
            {
                return Some(block);
            }

            // Check notarized blocks
            if let Some(block) = cache
                .notarized_blocks
                .get(Identifier::Key(&digest))
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
            let Cache {
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
