//! [`crate::qmdb::sync::Database`] for the compact db.

use super::{Config, db};
use crate::{
    Context,
    journal::contiguous::variable,
    merkle::{Family, Location},
    qmdb::{
        Error,
        sync::{self, journal::Memory},
    },
};
use commonware_codec::{EncodeShared, Read};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use core::num::NonZeroU64;

impl<F, E, O, H, C, S> sync::Database for db::Db<F, E, O, H, C, S>
where
    F: Family,
    E: Context,
    O: db::Variant<F>,
    H: Hasher,
    S: Strategy,
    O::Op: EncodeShared + Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Family = F;
    type Op = O::Op;
    type Journal = Memory<F, E, O::Op>;
    type Config = Config<C, S>;
    type Digest = H::Digest;
    type Context = E;
    type Hasher = H;

    /// Build a compact db from the synced log, which must hold exactly the commit operation at
    /// the start of `range`. `apply_batch_size` is unused: there is nothing to replay.
    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        _apply_batch_size: NonZeroU64,
    ) -> Result<Self, Error<F>> {
        let last_commit_loc = range.start();
        let (start, ops) = log.into_parts();
        let (Ok([op]), true) = (<[O::Op; 1]>::try_from(ops), start == last_commit_loc) else {
            return Err(Error::UnexpectedData(last_commit_loc));
        };

        let journal = variable::Journal::init(context.child("witness"), config.witness).await?;
        Self::init_from_sync(
            config.strategy,
            journal,
            config.commit_codec_config,
            last_commit_loc,
            // None only happens at genesis, where nothing is pinned.
            pinned_nodes.unwrap_or_default(),
            op,
        )
    }

    /// Journal a pending compact-sync import and sync the witness journal.
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

    fn root(&self) -> Self::Digest {
        self.root()
    }
}
