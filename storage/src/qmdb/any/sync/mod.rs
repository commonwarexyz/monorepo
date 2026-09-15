//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains the implementation of [crate::qmdb::sync::Database] for [Db], covering every
//! variant (ordered/unordered, fixed/variable, any snapshot index).
//!
//! Callers verifying `any` sync proofs directly should use [`crate::qmdb::verify_proof`].

use crate::{
    Context,
    index::{Factory as IndexFactory, Unordered},
    journal::{authenticated, contiguous::Mutable},
    merkle::{self, Location, full},
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
async fn build_db<F, E, U, I, H, C, const N: usize, S>(
    context: E,
    merkle_config: full::Config<S>,
    log: C,
    translator: I::Translator,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: NonEmptyRange<Location<F>>,
    apply_batch_size: NonZeroU64,
    init_concurrency: <I as SnapshotBuild<F>>::Concurrency,
    init_buffer: NonZeroUsize,
    cache_size: Option<NonZeroUsize>,
) -> Result<Db<F, E, C, I, H, U, N, S>, qmdb::Error<F>>
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

    let merkle = full::Merkle::<F, _, _, S>::init_sync(
        context.child("merkle"),
        full::SyncConfig {
            config: merkle_config,
            range: range.clone(),
            pinned_nodes,
        },
    )
    .await?;

    let index = I::new(context.child("index"), translator);

    let log = authenticated::Journal::<F, _, _, _, S>::from_components(
        merkle,
        log,
        hasher,
        apply_batch_size.get(),
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

impl<F, E, C, I, H, U, const N: usize, S> sync::Database for Db<F, E, C, I, H, U, N, S>
where
    F: merkle::Family,
    E: Context + Spawner,
    C: Mutable<Item = Operation<F, U>>
        + sync::Journal<F, Context = E, Op = Operation<F, U>>
        + 'static,
    <C as sync::Journal<F>>::Config: Clone + Send,
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
    type Config = Config<
        I::Translator,
        <C as sync::Journal<F>>::Config,
        S,
        <I as SnapshotBuild<F>>::Concurrency,
    >;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: NonZeroU64,
    ) -> Result<Self, qmdb::Error<F>> {
        build_db::<F, _, U, _, H, _, N, _>(
            context,
            config.merkle_config,
            log,
            config.translator,
            pinned_nodes,
            range,
            apply_batch_size,
            config.init_concurrency,
            config.init_buffer,
            config.init_cache_size,
        )
        .await
    }

    async fn persist_sync_result(self) -> Result<Self, qmdb::Error<F>> {
        Ok(self)
    }

    async fn local_pinned_nodes(
        context: Self::Context,
        config: &Self::Config,
        target: &qmdb::sync::Target<Self::Family, Self::Digest>,
        journal: &Self::Journal,
    ) -> Result<Option<Vec<Self::Digest>>, qmdb::Error<F>> {
        if target.range.start() == Location::new(0)
            || !qmdb::sync::journal_covers_range(journal.bounds(), &target.range)
        {
            return Ok(None);
        }

        // The target's range starts at the inactivity floor.
        qmdb::sync::local_pinned_nodes::<F, _, H, S>(
            context,
            config.merkle_config.clone(),
            target,
            target.range.start(),
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        Self::root(self)
    }
}
