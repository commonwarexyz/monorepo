//! [`crate::qmdb::sync::Database`] for the compact db.

use super::{Config, Db, Operation};
use crate::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        sync::{self, journal::Memory},
    },
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use core::num::NonZeroU64;

impl<F, E, O, H, S> sync::Database for Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Family = F;
    type Op = O;
    type Journal = Memory<F, E, O>;
    type Config = Config<O::Cfg, S>;
    type Digest = H::Digest;
    type Context = E;
    type Hasher = H;

    async fn init(
        context: E,
        config: Self::Config,
        max_size: Option<Location<F>>,
    ) -> Result<Self, Error<F>> {
        Self::init(context, config, max_size).await
    }

    /// The range covers only the last commit, the one operation a compact db holds.
    fn target(&self) -> sync::Target<F, Self::Digest> {
        self.target()
    }

    async fn prune_to_target(
        self,
        target: &sync::Target<F, Self::Digest>,
    ) -> Result<Self, Error<F>> {
        self.prune(target.range.end()).await
    }
}

impl<F, E, O, H, S> sync::Hooks<Self> for Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    /// Build a compact db from the synced log, which must hold exactly the commit operation at
    /// the start of `range`.
    async fn from_sync_result(
        context: E,
        config: <Self as sync::Database>::Config,
        log: Memory<F, E, O>,
        pinned_nodes: Option<Vec<H::Digest>>,
        range: NonEmptyRange<Location<F>>,
        _apply_batch_size: NonZeroU64,
    ) -> Result<Self, Error<F>> {
        let last_commit_loc = range.start();
        let (start, ops) = log.into_parts();
        let Ok([op]) = <[O; 1]>::try_from(ops) else {
            return Err(Error::UnexpectedData(last_commit_loc));
        };
        if start != last_commit_loc {
            return Err(Error::UnexpectedData(last_commit_loc));
        }

        // Nothing touches the destination partition until the import is journaled, after the
        // engine has verified the root. Journaling resets the partition, so its previous
        // witnesses are never decoded.
        Self::init_from_sync(
            context,
            config,
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

    /// Discards nothing. The sync journal lives in memory, and the stored witnesses are never
    /// read to build the synced state.
    async fn discard_local_state(
        _context: E,
        _config: &<Self as sync::Database>::Config,
    ) -> Result<(), Error<F>> {
        Ok(())
    }

    async fn local_pinned_nodes(
        _context: E,
        _config: &<Self as sync::Database>::Config,
        _target: &sync::Target<F, H::Digest>,
        _journal: &Memory<F, E, O>,
    ) -> Result<Option<Vec<H::Digest>>, Error<F>> {
        Ok(None)
    }

    /// Reject a target that covers more than the last commit.
    fn validate_target(
        target: &sync::Target<F, H::Digest>,
    ) -> Result<(), sync::EngineError<F, H::Digest>> {
        if target.range.start() + 1 != target.range.end() {
            return Err(sync::EngineError::InvalidTarget {
                bounds: target.range.clone(),
            });
        }
        Ok(())
    }
}
