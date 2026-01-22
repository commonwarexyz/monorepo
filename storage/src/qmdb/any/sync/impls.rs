use super::{Config, Index};
use crate::{
    index::{self},
    journal::{
        authenticated,
        contiguous::{fixed, variable},
    },
    mmr::{mem::Clean, Location, Position, StandardHasher},
    qmdb::{
        self,
        any::{db::Db, FixedConfig, VariableConfig},
        operation::{Committable, Operation},
        Durable, Merkleized,
    },
};
use commonware_codec::{CodecFixedShared, CodecShared};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use std::ops::Range;

/// Returns a new database from the data fetched by the sync engine.
async fn from_sync_result<E, O, I, H, U, Cfg, J>(
    context: E,
    config: Cfg,
    log: J,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: Range<Location>,
    apply_batch_size: usize,
    new_index: impl FnOnce(&E, &Cfg) -> I,
) -> Result<Db<E, J, I, H, U, Merkleized<H>, Durable>, qmdb::Error>
where
    E: Storage + Clock + Metrics,
    O: Operation + Committable + CodecShared + Send + Sync + 'static,
    I: Index + index::Unordered<Value = Location>,
    H: Hasher,
    U: Send + Sync + 'static,
    Cfg: Config,
    J: crate::journal::contiguous::MutableContiguous<Item = O>,
{
    let mut hasher = StandardHasher::<H>::new();

    let mmr = crate::mmr::journaled::Mmr::init_sync(
        context.with_label("mmr"),
        crate::mmr::journaled::SyncConfig {
            config: config.mmr_config(),
            range: Position::try_from(range.start).unwrap()
                ..Position::try_from(range.end + 1).unwrap(),
            pinned_nodes,
        },
        &mut hasher,
    )
    .await?;

    let log = authenticated::Journal::<_, _, _, Clean<DigestOf<H>>>::from_components(
        mmr,
        log,
        hasher,
        apply_batch_size as u64,
    )
    .await?;
    let index = new_index(&context, &config);
    let db = Db::from_components(range.start, log, index).await?;

    Ok(db)
}

// Blanket implementation for Fixed Journal
impl<E, O, I, H, U> qmdb::sync::Database
    for Db<E, fixed::Journal<E, O>, I, H, U, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    O: Operation + Committable + CodecFixedShared + 'static,
    I: Index + index::Unordered<Value = Location>,
    H: Hasher,
    U: Send + Sync + 'static,
    FixedConfig<I::Translator>: Config,
{
    type Context = E;
    type Op = O;
    type Journal = fixed::Journal<E, O>;
    type Hasher = H;
    type Config = FixedConfig<I::Translator>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        from_sync_result(
            context,
            config,
            log,
            pinned_nodes,
            range,
            apply_batch_size,
            |ctx, cfg| I::new(ctx.with_label("index"), cfg.translator.clone()),
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }
}

// Blanket implementation for Variable Journal
impl<E, O, I, H, U> qmdb::sync::Database
    for Db<E, variable::Journal<E, O>, I, H, U, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    O: Operation + Committable + CodecShared + 'static,
    O::Cfg: Clone + Send + Sync,
    I: Index + index::Unordered<Value = Location>,
    H: Hasher,
    U: Send + Sync + 'static,
    VariableConfig<I::Translator, O::Cfg>: Config,
{
    type Context = E;
    type Op = O;
    type Journal = variable::Journal<E, O>;
    type Hasher = H;
    type Config = VariableConfig<I::Translator, O::Cfg>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        from_sync_result(
            context,
            config,
            log,
            pinned_nodes,
            range,
            apply_batch_size,
            |ctx, cfg| I::new(ctx.with_label("index"), cfg.translator.clone()),
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }
}
