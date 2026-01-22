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
use commonware_codec::{Codec, CodecFixed};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use std::ops::Range;

// Blanket implementation for Fixed Journal
impl<E, O, I, H, U> qmdb::sync::Database
    for Db<E, fixed::Journal<E, O>, I, H, U, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    O: Operation + Committable + CodecFixed<Cfg = ()> + Send + Sync + 'static,
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
        let snapshot = I::new(context.with_label("snapshot"), config.translator.clone());
        let db = Self::from_components(range.start, log, snapshot).await?;

        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }

    async fn resize_journal(
        mut journal: Self::Journal,
        range: Range<Location>,
    ) -> Result<Self::Journal, qmdb::Error> {
        let size = journal.size();

        if size <= range.start {
            journal.clear_to_size(*range.start).await?;
            Ok(journal)
        } else {
            journal.prune(*range.start).await?;
            Ok(journal)
        }
    }
}

// Blanket implementation for Variable Journal
impl<E, O, I, H, U> qmdb::sync::Database
    for Db<E, variable::Journal<E, O>, I, H, U, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    O: Operation + Committable + Codec + Send + Sync + 'static,
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
        let snapshot = I::new(context.with_label("snapshot"), config.translator.clone());
        let db = Self::from_components(range.start, log, snapshot).await?;

        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }

    async fn resize_journal(
        mut journal: Self::Journal,
        range: Range<Location>,
    ) -> Result<Self::Journal, qmdb::Error> {
        let size = journal.size();

        if size <= range.start {
            journal.clear_to_size(*range.start).await?;
            Ok(journal)
        } else {
            journal.prune(*range.start).await?;
            Ok(journal)
        }
    }
}
