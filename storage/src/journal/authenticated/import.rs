//! The state a sync of an authenticated journal carries from opening its journal to building it.

use super::{APPLY_BATCH_SIZE, Config, Error, Frontier, ReplayEncoded, Tree, metrics::Metrics};
use crate::{
    Context,
    merkle::{Family, Location, hasher::Hasher},
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;

/// Whether operations kept locally rebuild a sync target.
pub(crate) enum Local<D> {
    /// They do, and these are the pinned nodes at the target's start.
    Authenticated(Vec<D>),
    /// The frontier's boundary can't check them, so they are left for the final root check.
    Unchecked,
    /// They do not.
    Mismatch,
}

/// A sync in progress, from [`crate::qmdb::sync::Database::open_sync_journal`] until the synced
/// journal is built.
pub struct Import<F: Family, E: Context, D: Digest, S: Strategy> {
    pub(super) frontier: Frontier<F, E, D>,
    pub(super) config: Config<S>,
    pub(super) metrics: Box<Metrics>,
    /// The tree [Self::authenticate] built, pruned to the boundary it returned pins for.
    pub(super) tree: Option<Tree<F, D, S>>,
}

impl<F: Family, E: Context, D: Digest, S: Strategy> Import<F, E, D, S> {
    /// Validate `config`, then open the frontier [super::Journal::new] would open under `context`
    /// and mark an import in progress.
    pub(crate) async fn begin(context: E, config: &Config<S>) -> Result<Self, Error<F>> {
        config.cache.capacity::<D>().map_err(Error::InvalidConfig)?;
        let frontier = Frontier::open(context.child("frontier"), config.metadata_partition.clone())
            .await?
            .begin_import()
            .await?;
        let merkle_context = context.child("merkle");
        Ok(Self {
            frontier,
            config: config.clone(),
            metrics: Box::new(Metrics::new(&merkle_context)),
            tree: None,
        })
    }

    /// Whether the last completed import failed root verification.
    pub(crate) fn rejected(&self) -> bool {
        self.frontier.rejected()
    }

    /// Resume a rejected import once its retained operations have been durably discarded.
    pub(crate) async fn restart(mut self) -> Result<Self, Error<F>> {
        self.frontier = self.frontier.restart().await?;
        Ok(self)
    }

    /// Durably record `pins` at `location` as the sync target's boundary.
    pub(crate) async fn stage(
        mut self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> Result<Self, Error<F>> {
        self.frontier = self.frontier.stage(location, pins).await?;
        Ok(self)
    }

    /// Check whether `journal`, replayed from the frontier's boundary through `end`, rebuilds
    /// `expected` with `inactive` peaks. On success, return the pins at `start`.
    pub(crate) async fn authenticate<C, H>(
        &mut self,
        journal: &C,
        hasher: &H,
        start: Location<F>,
        end: Location<F>,
        expected: D,
        inactive: usize,
    ) -> Result<Local<D>, Error<F>>
    where
        C: ReplayEncoded,
        H: Hasher<F, Digest = D> + 'static,
    {
        let Some(boundary) = self.frontier.boundary() else {
            return Ok(Local::Unchecked);
        };
        let bounds = journal.bounds();
        if boundary.location > start || bounds.start > *boundary.location || bounds.end < *end {
            return Ok(Local::Unchecked);
        }
        let mut tree = Tree::new(
            boundary.location,
            boundary.pins.clone(),
            &self.config,
            Metrics::clone(&self.metrics),
        )?
        .replay(journal, hasher, end, APPLY_BATCH_SIZE)
        .await?;
        if tree.root(hasher, inactive)? != expected {
            return Ok(Local::Mismatch);
        }
        let pins = tree.pinned_nodes_at(journal, hasher, start).await?;
        tree.prune(start, pins.clone());
        self.tree = Some(tree);
        Ok(Local::Authenticated(pins))
    }
}
