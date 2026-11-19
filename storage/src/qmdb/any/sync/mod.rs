//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains the implementation of [crate::qmdb::sync::Database] for [Db], covering every
//! variant (ordered/unordered, fixed/variable, any snapshot index).
//!
//! Callers verifying `any` sync proofs directly should use [`crate::qmdb::ProofExt::verify`].

use crate::{
    Context,
    index::{Factory as IndexFactory, Unordered},
    journal::{authenticated, contiguous::Mutable},
    merkle::{self, Location},
    qmdb::{
        self, SnapshotBuild,
        any::{
            Config,
            db::Db,
            operation::{Operation, update::Update},
        },
        metrics::Metrics,
        sync,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_utils::range::NonEmptyRange;
use core::num::{NonZeroU64, NonZeroUsize};

#[cfg(test)]
pub(crate) mod tests;

/// Shared helper to build a [Db] from sync components.
#[allow(clippy::too_many_arguments)]
async fn build_db<F, E, U, I, H, C, S>(
    context: E,
    merkle_config: authenticated::Config<S>,
    log: C,
    translator: I::Translator,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: NonEmptyRange<Location<F>>,
    apply_batch_size: NonZeroU64,
    init_concurrency: NonZeroUsize,
    init_buffer: NonZeroUsize,
    cache_size: Option<NonZeroUsize>,
) -> Result<Db<F, E, C, I, H, U, S>, qmdb::Error<F>>
where
    F: merkle::Family,
    E: Context + Spawner,
    U: Update,
    I: IndexFactory + SnapshotBuild<F>,
    H: Hasher,
    C: Mutable<Item = Operation<F, U>> + 'static,
    S: Strategy,
    Operation<F, U>: Codec,
{
    let hasher = qmdb::hasher::<H>();

    let index = I::new(context.child("index"), translator);

    let log = authenticated::Journal::<F, _, _, _, S>::from_components(
        context.child("merkle"),
        &merkle_config,
        log,
        hasher,
        range.start(),
        pinned_nodes.unwrap_or_default(),
        apply_batch_size,
    )
    .await?;
    let snapshot_context = context.child("snapshot");
    let metrics = Metrics::new(context);
    let db = Db::init_from_log(
        snapshot_context,
        index,
        log,
        None,
        init_concurrency,
        init_buffer,
        cache_size,
        metrics,
    )
    .await?;

    Ok(db)
}

impl<F, E, C, I, H, U, S> sync::Database for Db<F, E, C, I, H, U, S>
where
    F: merkle::Family,
    E: Context + Spawner,
    C: crate::journal::authenticated::Backing<
            E,
            Item = Operation<F, U>,
            Config = <C as sync::Journal<F>>::Config,
        > + sync::Journal<F, Context = E, Op = Operation<F, U>>
        + 'static,
    I: IndexFactory + SnapshotBuild<F> + Unordered<Value = Location<F>>,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    type Family = F;
    type Context = E;
    type Op = Operation<F, U>;
    type Journal = C;
    type Hasher = H;
    type Config = Config<I::Translator, <C as sync::Journal<F>>::Config, S>;
    type Digest = H::Digest;

    async fn init(
        context: E,
        config: Self::Config,
        max_size: Option<Location<F>>,
    ) -> Result<Self, qmdb::Error<F>> {
        crate::qmdb::any::init_with_bitmap(context, config, None, max_size, None).await
    }

    fn target(&self) -> sync::Target<F, H::Digest> {
        sync::Target {
            root: Self::root(self),
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

impl<F, E, C, I, H, U, S> sync::Hooks<Self> for Db<F, E, C, I, H, U, S>
where
    F: merkle::Family,
    E: Context + Spawner,
    C: crate::journal::authenticated::Backing<
            E,
            Item = Operation<F, U>,
            Config = <C as sync::Journal<F>>::Config,
        > + sync::Journal<F, Context = E, Op = Operation<F, U>>
        + 'static,
    I: IndexFactory + SnapshotBuild<F> + Unordered<Value = Location<F>>,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    async fn from_sync_result(
        context: E,
        config: <Self as sync::Database>::Config,
        log: C,
        pinned_nodes: Option<Vec<H::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, qmdb::Error<F>> {
        build_db::<F, _, U, _, H, _, _>(
            context,
            config.merkle,
            log,
            config.translator,
            pinned_nodes,
            range,
            apply_batch_size,
            config.init_concurrency,
            config.init_buffer,
            config.init_cache,
        )
        .await
    }

    async fn persist_sync_result(mut self) -> Result<Self, qmdb::Error<F>> {
        self.log = self.log.persist_boundary().await?;
        Ok(self)
    }

    async fn discard_local_state(
        context: E,
        config: &<Self as sync::Database>::Config,
    ) -> Result<(), qmdb::Error<F>> {
        Ok(authenticated::discard_frontier::<F, _, H, S>(context, &config.merkle).await?)
    }

    async fn local_pinned_nodes(
        context: E,
        config: &<Self as sync::Database>::Config,
        target: &sync::Target<F, H::Digest>,
        journal: &C,
    ) -> Result<Option<Vec<H::Digest>>, qmdb::Error<F>> {
        qmdb::sync::local_pinned_nodes::<F, _, H, S>(context, &config.merkle, target, journal).await
    }
}
