//! Durable resident digests of an authenticated journal, so startup replays only the operations
//! after the frontier's checkpoint.
//!
//! Item `i` is the `i`-th node at or above the tree's resident height in position order, counting
//! from position zero. Digests are appended whenever the journal reaches a commit or prunes.
//! Saving makes them durable and records the last commit they cover, with the peaks there, as the
//! frontier's checkpoint. A node depends only on the operations below it, so digests past the
//! checkpoint are harmless: startup discards them.
//!
//! Startup restores a checkpoint only if it was saved under the tree's resident height, lies
//! between the frontier and the recovered end, has every digest it needs retained, and its digests
//! at the peaks match the recorded peaks. Otherwise it replays the operations, since the digests
//! are derived data.

use super::{
    Backing, BackingRecovery, Config, Error,
    frontier::{self, Boundary, Frontier},
    tree::{Tree, resident_rank},
};
use crate::{
    Context,
    journal::contiguous::{Contiguous, Many, fixed},
    merkle::{Family, Location, Position},
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_runtime::{ReadOptions, buffer::paged::CacheRef};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::TryStreamExt as _;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use tracing::warn;

/// Balances the blobs restore must open against the writable tail it reads a page at a time.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1 << 16);
const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(16);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 16);
const REPLAY_BUFFER: NonZeroUsize = NZUsize!(1 << 20);

/// Digests appended per write, which bounds the memory of appending after a full replay.
const APPEND_BATCH: usize = 1 << 16;

/// Leaves committed past the checkpoint, or the boundary if later, that make [Digests::advance]
/// save a new one.
const SAVE_INTERVAL: u64 = 1 << 20;

/// Where resident digests are stored.
struct Store<E: Context> {
    context: E,
    config: fixed::Config,
}

impl<E: Context> Store<E> {
    /// The store beside the frontier in `metadata_partition`.
    fn new(context: E, metadata_partition: &str) -> Self {
        Self {
            config: fixed::Config {
                partition: format!("{metadata_partition}-resident"),
                items_per_blob: ITEMS_PER_BLOB,
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_PAGES),
                write_buffer: WRITE_BUFFER,
                replay_buffer: REPLAY_BUFFER,
            },
            context,
        }
    }

    /// A journal holding no digests, whose next item is the resident node of rank `rank`.
    async fn clear<F: Family, D: Digest>(
        &self,
        rank: u64,
    ) -> Result<fixed::Journal<E, D>, Error<F>> {
        let journal =
            fixed::Journal::clear(self.context.child("journal"), self.config.clone(), rank)
                .await?
                .finish(rank)
                .await?;
        Ok(journal)
    }
}

/// Resident digests opened at startup, before they are matched to the recovered operations.
pub(crate) struct Recovery<E: Context, D: Digest> {
    store: Box<Store<E>>,
    /// The stored digests, or `None` if they will not be read: they could not be recovered, or an
    /// import replaces the operations they describe.
    journal: Option<<fixed::Journal<E, D> as Backing<E>>::Recovery>,
}

impl<E: Context, D: Digest> Recovery<E, D> {
    /// Open the resident digests stored beside the frontier `config` names. Digests that cannot be
    /// recovered are left unread, since startup can replay the operations instead.
    pub(crate) async fn open<S: Strategy>(context: E, config: &Config<S>) -> Self {
        let store = Store::new(context, &config.metadata_partition);
        let journal =
            fixed::Journal::recover(store.context.child("journal"), store.config.clone(), None)
                .await
                .inspect_err(|err| warn!(?err, "replaying operations instead of resident digests"))
                .ok();
        Self {
            store: Box::new(store),
            journal,
        }
    }

    /// The resident digests stored beside the frontier `config` names, left unread because an
    /// import replaces the operations they describe.
    pub(crate) fn discarded<S: Strategy>(context: E, config: &Config<S>) -> Self {
        Self {
            store: Box::new(Store::new(context, &config.metadata_partition)),
            journal: None,
        }
    }

    /// Advance `tree`, which holds nothing past its boundary, to the frontier's checkpoint if
    /// startup may restore it (see the module docs) given the recovered `end`.
    ///
    /// Otherwise drop the checkpoint and return `tree` unchanged, so its operations are replayed.
    pub(crate) async fn restore<F: Family, S: Strategy>(
        self,
        mut tree: Tree<F, D, S>,
        frontier: Frontier<F, E, D>,
        end: Location<F>,
    ) -> Result<(Digests<F, E, D>, Tree<F, D, S>, Frontier<F, E, D>), Error<F>> {
        let height = tree.resident_height();
        let start = resident_rank(height, tree.size());
        let Self { store, journal } = self;
        let usable = frontier
            .checkpoint()
            .zip(journal.as_ref())
            .and_then(|(saved, journal)| {
                let peaks = &saved.peaks;
                let stop = resident_rank(height, Position::try_from(peaks.location).ok()?);
                let retained = journal.bounds();
                let same_height = saved.height == height;
                let within = (tree.leaves()..=end).contains(&peaks.location);
                let complete = retained.start <= start && stop <= retained.end;
                (same_height && within && complete).then(|| (peaks.clone(), stop))
            });
        let kept = match (usable, journal) {
            (Some((peaks, stop)), Some(journal)) => {
                let journal = journal.finish(stop).await?;
                let restored = async {
                    let digests: Vec<D> = journal
                        .replay_range(start..stop, REPLAY_BUFFER, ReadOptions::default())
                        .await?
                        .map_ok(|(_, digest)| digest)
                        .try_collect()
                        .await?;
                    tree.restore(peaks.location, &peaks.digests, digests)?;
                    Ok::<_, Error<F>>(())
                }
                .await;
                match restored {
                    Ok(()) => {
                        let covered = tree.size();
                        let digests = Digests::new(journal, height, covered, Some(peaks));
                        return Ok((digests, tree, frontier));
                    }
                    Err(err) => {
                        warn!(?err, "replaying operations instead of resident digests");
                        drop(journal);
                        None
                    }
                }
            }
            (None, Some(journal))
                if (journal.bounds().start..=journal.bounds().end).contains(&start) =>
            {
                Some(journal.finish(start).await?)
            }
            (_, journal) => {
                drop(journal);
                None
            }
        };
        let frontier = frontier.drop_checkpoint().await?;
        let journal = match kept {
            Some(journal) => journal,
            None => store.clear(start).await?,
        };
        let covered = tree.size();
        Ok((Digests::new(journal, height, covered, None), tree, frontier))
    }

    /// Discard every digest, before operations imported into `tree` from its boundary become
    /// active.
    pub(crate) async fn clear<F: Family, S: Strategy>(
        self,
        tree: &Tree<F, D, S>,
    ) -> Result<Digests<F, E, D>, Error<F>> {
        let height = tree.resident_height();
        let start = Position::try_from(tree.bounds().start)?;
        let Self { store, journal } = self;
        drop(journal);
        let journal = store.clear(resident_rank(height, start)).await?;
        Ok(Digests::new(journal, height, start, None))
    }
}

/// Resident digests, appended as the journal reaches commits and prunes.
pub(crate) struct Digests<F: Family, E: Context, D: Digest> {
    journal: fixed::Journal<E, D>,
    /// The resident height of the tree whose digests the journal holds.
    height: u32,
    /// The tree size whose resident digests the journal holds.
    covered: Position<F>,
    /// The last commit the journal holds digests for, and the peaks there.
    committed: Option<Boundary<F, D>>,
}

impl<F: Family, E: Context, D: Digest> Digests<F, E, D> {
    const fn new(
        journal: fixed::Journal<E, D>,
        height: u32,
        covered: Position<F>,
        committed: Option<Boundary<F, D>>,
    ) -> Self {
        Self {
            journal,
            height,
            covered,
            committed,
        }
    }

    /// Append the resident digests `tree` gained since the last append.
    async fn append<S: Strategy>(mut self, tree: &Tree<F, D, S>) -> Result<Self, Error<F>> {
        let mut digests = tree.resident_digests(self.covered);
        let mut batch = Vec::new();
        loop {
            batch.clear();
            for digest in digests.by_ref().take(APPEND_BATCH) {
                batch.push(digest?);
            }
            if batch.is_empty() {
                break;
            }
            (self.journal, _) = self.journal.append_many(Many::Flat(&batch)).await?;
        }
        self.covered = tree.size();
        Ok(self)
    }

    /// Append the resident digests `tree` gained and note its size, which ends a commit, as the
    /// last commit. Saves a checkpoint there once [SAVE_INTERVAL] leaves have passed since the
    /// frontier's checkpoint, or its boundary if later.
    pub(crate) async fn advance<S: Strategy>(
        mut self,
        tree: &Tree<F, D, S>,
        frontier: Frontier<F, E, D>,
    ) -> Result<(Self, Frontier<F, E, D>), Error<F>> {
        self = self.append(tree).await?;
        self.committed = Some(Boundary {
            location: tree.leaves(),
            digests: tree.peaks()?,
        });
        let Ok(Some(boundary)) = frontier.active_boundary() else {
            return Ok((self, frontier));
        };
        let since = frontier.checkpoint().map_or(boundary.location, |saved| {
            saved.peaks.location.max(boundary.location)
        });
        if tree.leaves().saturating_sub(*since) < SAVE_INTERVAL {
            return Ok((self, frontier));
        }
        self.save(frontier).await
    }

    /// Make the appended digests durable and record the last commit as the frontier's checkpoint,
    /// unless it is already recorded, adds nothing past the boundary, or an import is in progress.
    pub(crate) async fn save(
        mut self,
        frontier: Frontier<F, E, D>,
    ) -> Result<(Self, Frontier<F, E, D>), Error<F>> {
        let Ok(Some(boundary)) = frontier.active_boundary() else {
            return Ok((self, frontier));
        };
        let saved = frontier.checkpoint().map(|saved| saved.peaks.location);
        let Some(committed) = self
            .committed
            .as_ref()
            .filter(|committed| {
                committed.location > boundary.location && Some(committed.location) != saved
            })
            .cloned()
        else {
            return Ok((self, frontier));
        };
        // The checkpoint, not the journal's recovery watermark, decides which digests are read.
        self.journal = self.journal.commit().await?;
        let frontier = frontier
            .save_checkpoint(frontier::Checkpoint {
                height: self.height,
                peaks: committed,
            })
            .await?;
        Ok((self, frontier))
    }

    /// Append the digests `tree` holds past the last append, then drop those of nodes before
    /// `boundary`, in blob-sized steps. Appending first keeps the journal contiguous after `tree`
    /// prunes the same nodes.
    pub(crate) async fn prune<S: Strategy>(
        self,
        tree: &Tree<F, D, S>,
        boundary: Location<F>,
    ) -> Result<Self, Error<F>> {
        let mut digests = self.append(tree).await?;
        let rank = resident_rank(digests.height, Position::try_from(boundary)?);
        (digests.journal, _) = digests.journal.prune(rank).await?;
        Ok(digests)
    }

    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        Ok(())
    }
}
