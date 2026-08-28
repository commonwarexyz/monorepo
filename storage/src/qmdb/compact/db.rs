//! A compact authenticated db that discards historical operations, retaining only a witness
//! for each applied batch.
//!
//! One implementation serves the keyless and immutable variants. [`crate::qmdb::keyless`] and
//! [`crate::qmdb::immutable`] pin the operation type through aliases and add `append` and `set`.
//!
//! Mirrors the API of the full dbs ([`crate::qmdb::keyless::Keyless`],
//! [`crate::qmdb::immutable::Immutable`]): `new_batch -> merkleize -> apply_batch -> commit /
//! sync / start_sync`, pipelined batch chains, `StaleBatch` validation. It is backed by the peak-only
//! [`crate::merkle::compact`]. Because history is discarded, there are no `get` / `proof` /
//! `bounds` methods. Use a full db if you need them.
//!
//! # Witness journal
//!
//! The witness journal is the single durable source of truth. Each entry is a complete witness
//! of one applied state, so [`Db::rewind`] can restore any retained applied state
//! (history is bounded only by [`Db::prune`]). Reopen and rewind rebuild the in-memory Merkle
//! from an entry's pinned nodes and commit operation. An entry whose commit or pinned nodes fail
//! to decode fails the open with [`Error::Journal`]; one that decodes but cannot rebuild
//! surfaces as [`Error::DataCorrupted`]. The witness is also what lets compact nodes serve
//! compact sync without retaining historical operations.
//!
//! Entries are strictly increasing in committed size, so a size uniquely identifies a rewind or
//! prune target. An appended entry becomes durable when [`Db::commit`] or [`Db::sync`]
//! completes, or, for [`Db::start_sync`], when the returned handle completes. Before that point
//! recovery may fall back to the previous entry. The tip entry is never pruned.
//!
//! # Inactivity floor
//!
//! Commits carry the inactivity floor so the compact db's commit leaves and root match the full
//! db's: the root is computed over the peaks the floor leaves active.

use super::{
    Config, Operation, batch as compact_batch,
    witness::{self, Rebuilt, VerifiedWitness, Witness},
};
use crate::{
    Context, SyncCompletion,
    journal::contiguous::{Contiguous, variable},
    merkle::{self, Family, Location, batch, compact as compact_merkle},
    qmdb::{
        self, Error,
        batch_chain::{self, Bounds, Commitment},
        sync::{CompactTarget, FeedbackTx, Request, Response, Source},
    },
};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::{Error as RError, Handle};
use core::cmp::Ordering;
use futures::FutureExt as _;
use std::sync::{Arc, Weak};

type MerkleizedParent<F, H, O, S> = Arc<MerkleizedBatch<F, DigestOf<H>, O, S>>;

/// The tip witness's relationship to the journal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TipState {
    /// Journaled and covered by a durability operation that has at least started.
    Committed,
    /// Journaled after the latest durability operation started.
    Uncommitted,
    /// From compact sync. The journal still holds the partition's previous contents until the
    /// first apply or durability operation replaces them with the tip.
    Imported,
}

/// A compact authenticated db that discards historical operations, retaining only a witness
/// for each applied batch.
pub struct Db<F, E, O, H, S: Strategy>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
{
    /// The peak-only Merkle the witnesses describe.
    merkle: compact_merkle::Merkle<F, H::Digest, S>,

    /// The journal of witnesses, one per applied batch.
    journal: witness::Journal<E, F, H::Digest, O>,

    /// The verified tip witness.
    tip: VerifiedWitness<F, H::Digest, O>,

    /// Whether the tip is journaled and durable.
    tip_state: TipState,

    /// The sync pipelined by the last [`Self::start_sync`], cleared by the next full
    /// journal sync.
    pending_sync: Option<SyncCompletion>,
}

impl<F, E, O, H, S: Strategy> std::fmt::Debug for Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("size", &self.size())
            .field("inactivity_floor_loc", &self.inactivity_floor_loc())
            .finish_non_exhaustive()
    }
}

impl<F, E, O, H, S> Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    /// Returns a compact db initialized from `cfg`.
    pub async fn init(context: E, cfg: Config<O::Cfg, S>) -> Result<Self, Error<F>> {
        let journal = variable::Journal::init(context.child("witness"), cfg.witness).await?;
        Self::init_from_journal(cfg.strategy, journal).await
    }

    /// Build a compact db from state fetched by the sync engine: `last_commit_op` must be a
    /// commit whose floor is at or below `last_commit_loc`.
    ///
    /// The imported witness lives only in memory until the first [`Self::apply_batch`],
    /// [`Self::commit`], [`Self::sync`], or [`Self::start_sync`], which replaces the journal's
    /// contents with it. Until one of those succeeds, rewind and prune are rejected. A crash
    /// during the replacement leaves a journal that fails to reopen, and re-syncing recovers it.
    pub(crate) fn init_from_sync(
        strategy: S,
        journal: witness::Journal<E, F, H::Digest, O>,
        last_commit_loc: Location<F>,
        pinned_nodes: Vec<H::Digest>,
        last_commit_op: O,
    ) -> Result<Self, Error<F>> {
        let Some(inactivity_floor_loc) = last_commit_op.has_floor() else {
            return Err(Error::UnexpectedData(last_commit_loc));
        };
        witness::validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
        let imported = Witness {
            commit: last_commit_op,
            size: last_commit_loc + 1,
            pinned_nodes,
        };
        let Rebuilt { merkle, tip } =
            witness::restore::<F, O, H, S>(strategy, imported, inactivity_floor_loc)?;
        Ok(Self {
            merkle,
            journal,
            tip,
            tip_state: TipState::Imported,
            pending_sync: None,
        })
    }

    /// Open a compact db from its witness journal, rebuilding the Merkle from the tip witness.
    ///
    /// A new db starts with one committed operation, the initial `Commit(None, 0)`, persisted as
    /// the first witness entry so every later reopen and rewind can assume the journal tip is a
    /// complete witness.
    #[boxed]
    pub(crate) async fn init_from_journal(
        strategy: S,
        mut journal: witness::Journal<E, F, H::Digest, O>,
    ) -> Result<Self, Error<F>> {
        let entry = if journal.size() == 0 {
            // Leaf 0 has nothing pinned below it, so the genesis witness needs no Merkle.
            let genesis = Witness {
                commit: O::commit(None, Location::new(0)),
                size: Location::new(1),
                pinned_nodes: Vec::new(),
            };
            (journal, _) = journal.append(&genesis).await?;
            journal = journal.sync().await?;
            genesis
        } else {
            journal.read(journal.size() - 1).await?
        };
        let Rebuilt { merkle, tip } = witness::rebuild::<F, O, H, S>(strategy, entry)?;
        Ok(Self {
            merkle,
            journal,
            tip,
            tip_state: TipState::Committed,
            pending_sync: None,
        })
    }

    /// Return the root of the db.
    pub const fn root(&self) -> H::Digest {
        self.tip.root
    }

    /// Return the inactivity floor declared by the last committed batch.
    pub const fn inactivity_floor_loc(&self) -> Location<F> {
        self.tip.inactivity_floor_loc
    }

    /// Return the location of the next operation appended to this db.
    pub const fn size(&self) -> Location<F> {
        self.tip.size()
    }

    /// Get the metadata associated with the last commit.
    pub fn get_metadata(&self) -> Option<O::Metadata> {
        self.tip.metadata().cloned()
    }

    /// Return the compact-sync target described by the current witness.
    ///
    /// This reflects the most recently applied batch. The target remains non-durable until a
    /// covering [`Self::commit`], [`Self::sync`], or [`Self::start_sync`] completes.
    pub const fn target(&self) -> CompactTarget<F, H::Digest> {
        self.tip.target()
    }

    /// The [`Commitment`] for the database's current state.
    pub(crate) const fn commitment(&self) -> Commitment<F, H::Digest> {
        Commitment::new(self.size(), self.root())
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, O, S> {
        UnmerkleizedBatch::new(self, self.commitment())
    }

    /// Create an owned merkleized batch representing the current applied state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, O, S>> {
        Arc::new(MerkleizedBatch {
            merkle_batch: self.merkle.to_batch(),
            commit: self.tip.witness.commit.clone(),
            parent: None,
            bounds: Bounds::from_db(self.commitment(), self.inactivity_floor_loc()),
        })
    }

    /// Check that `batch` can be applied to the database in its current state, without
    /// applying it.
    pub fn validate_batch(
        &self,
        batch: &MerkleizedBatch<F, H::Digest, O, S>,
    ) -> Result<(), Error<F>> {
        batch
            .bounds
            .validate_apply_to(self.commitment(), self.inactivity_floor_loc())
    }

    /// Apply a merkleized batch to the database, journaling a pending compact-sync import first.
    ///
    /// Returns the range of locations written. The state is updated in memory and appended to the
    /// witness journal. Call [`Self::commit`] or [`Self::sync`], or await the handle returned by
    /// [`Self::start_sync`], to make the applied state durable. A batch that adds no operations
    /// only journals a pending compact-sync import.
    ///
    /// # Errors
    ///
    /// - [`Error::StaleBatch`] if the batch is detected as stale (see
    ///   [`crate::qmdb::batch_chain`] for more details).
    /// - [`Error::FloorRegressed`] if any commit in the chain declares a floor below the
    ///   previous commit's floor.
    /// - [`Error::FloorBeyondSize`] if any commit in the chain declares a floor beyond its own
    ///   commit location.
    #[tracing::instrument(
        name = "qmdb.compact.db.apply_batch",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn apply_batch(
        mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, O, S>>,
    ) -> Result<(Self, core::ops::Range<Location<F>>), Error<F>> {
        self.validate_batch(&batch)?;

        debug_assert_eq!(self.tip.size(), self.merkle.leaves());
        let start_loc = self.size();
        self.merkle.apply_batch(&batch.merkle_batch)?;
        let tip = match self.tip.size().cmp(&self.merkle.leaves()) {
            Ordering::Equal => None,
            Ordering::Greater => {
                return Err(Error::DataCorrupted("witness ahead of in-memory state"));
            }
            // Build before pruning because the commit proof needs the unpruned Merkle.
            Ordering::Less => Some(witness::build_witness::<F, O, H, S>(
                &self.merkle,
                batch.commit.clone(),
                batch.bounds.inactivity_floor,
            )?),
        };
        // Journal the import before the new witness so every applied state has its own entry.
        self = self.flush_import().await?;
        if let Some(tip) = tip {
            self.tip = tip;
            self.merkle.prune_to_frontier();
            self = self.journal_tip().await?;
        }
        debug_assert_eq!(self.commitment(), batch.bounds.tip);
        Ok((self, start_loc..batch.bounds.tip.size))
    }

    /// Journal a pending compact-sync import, if any, in place of the partition's previous
    /// contents.
    ///
    /// Clears to at least size 1 so a crash mid-import reopens as a corrupt journal rather than a
    /// fresh db.
    async fn flush_import(mut self) -> Result<Self, Error<F>> {
        if self.tip_state != TipState::Imported {
            return Ok(self);
        }
        let size = self.journal.size();
        self.journal = self.journal.clear_to_size(size.max(1)).await?;
        self.journal_tip().await
    }

    /// Append the tip's witness to the journal, leaving the tip outside the durable prefix.
    async fn journal_tip(mut self) -> Result<Self, Error<F>> {
        (self.journal, _) = self.journal.append(&self.tip.witness).await?;
        self.tip_state = TipState::Uncommitted;
        Ok(self)
    }

    /// Begin durably persisting the current db state to disk.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit],
    /// plus a best-effort attempt to bound the recovery needed on reopen. Use [Self::sync] to
    /// guarantee none is needed. A new sync waits for the prior sync before starting. Failures
    /// of the deferred durability work surface on the returned handle and the next durability
    /// operation. When nothing new must be appended, the handle still proves the current tip
    /// durable and resurfaces any retained sync failure.
    #[tracing::instrument(
        name = "qmdb.compact.db.start_sync",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error<F>> {
        // Match the deferred-failure convention used by the journal: return a prior completion's
        // error through a ready handle before a later completion can replace it. Errors while
        // journaling an import or initiating this sync continue to use the outer result.
        if let Err(err) = self.wait_for_sync().await {
            return Ok((self, Handle::ready(Err(err))));
        }

        // Journal a pending import before starting the sync so the returned handle covers the
        // current tip. A later apply remains uncommitted and requires a successor durability
        // operation.
        self = self.flush_import().await?;

        // Share one completion between the caller and the db. Retaining a clone keeps a
        // dropped handle's failure observable by the next durability operation.
        let handle;
        (self.journal, handle) = self.journal.start_sync().await?;
        let completion: SyncCompletion = handle.boxed().shared();
        self.tip_state = TipState::Committed;
        self.pending_sync = Some(completion.clone());
        Ok((self, Handle::from_future(completion)))
    }

    /// Durably persist the current db state to disk. This is faster than [`Self::sync`] but
    /// reopen may need to replay the witness journal's tail to recover.
    ///
    /// First waits for any sync pipelined by [`Self::start_sync`], surfacing its failure.
    #[tracing::instrument(
        name = "qmdb.compact.db.commit",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn commit(mut self) -> Result<Self, Error<F>> {
        self.wait_for_sync().await?;
        self = self.flush_import().await?;
        // A commit leaves `pending_sync` set so the next full sync still persists all metadata.
        if self.tip_state == TipState::Uncommitted {
            self.journal = self.journal.commit().await?;
            self.tip_state = TipState::Committed;
        }
        Ok(self)
    }

    /// Durably persist the current db state to disk, also persisting journal metadata to
    /// minimize recovery work on reopen. This also settles any sync pipelined by
    /// [`Self::start_sync`].
    #[tracing::instrument(
        name = "qmdb.compact.db.sync",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn sync(mut self) -> Result<Self, Error<F>> {
        self = self.flush_import().await?;
        if self.tip_state == TipState::Uncommitted || self.pending_sync.is_some() {
            return self.sync_journal().await;
        }
        Ok(self)
    }

    /// Sync the journal and all of its metadata, which covers the tip and settles any sync
    /// pipelined by [`Self::start_sync`].
    async fn sync_journal(mut self) -> Result<Self, Error<F>> {
        self.journal = self.journal.sync().await?;
        self.pending_sync = None;
        self.tip_state = TipState::Committed;
        Ok(self)
    }

    /// Wait for any sync pipelined by [`Self::start_sync`], surfacing its failure.
    ///
    /// A successful completion remains recorded until the next full journal sync, which must
    /// still guarantee that all metadata is current.
    async fn wait_for_sync(&self) -> Result<(), RError> {
        let Some(pending) = self.pending_sync.clone() else {
            return Ok(());
        };
        pending.await
    }

    /// Rewind the db to the applied state with exactly `target` operations, discarding any
    /// uncommitted batches and any later states. The rewind is made durable before this
    /// method returns.
    ///
    /// A committed tip already at `target` only settles its pipelined sync; an uncommitted tip
    /// at `target` takes the regular path so the journal becomes durable before return. The
    /// target entry is rebuilt before the journal is truncated, so a corrupt entry fails the
    /// rewind with the journal intact.
    ///
    /// # Errors
    ///
    /// Returns [`crate::merkle::Error::RewindBeyondHistory`] (wrapped as [`Error::Merkle`]) if
    /// no retained applied state has exactly `target` operations (never applied, or pruned).
    #[tracing::instrument(
        name = "qmdb.compact.db.rewind",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn rewind(mut self, target: Location<F>) -> Result<Self, Error<F>> {
        if self.tip.size() == target && self.tip_state == TipState::Committed {
            self.wait_for_sync().await?;
            return Ok(self);
        }
        self.check_import_applied()?;

        let pos = self.first_at_or_above(target).await?;
        if pos >= self.journal.bounds().end {
            return Err(merkle::Error::RewindBeyondHistory.into());
        }
        let entry = self.journal.read(pos).await?;
        if entry.size != target {
            return Err(merkle::Error::RewindBeyondHistory.into());
        }
        let Rebuilt { merkle, tip } =
            witness::rebuild::<F, O, H, S>(self.merkle.strategy().clone(), entry)?;
        self.journal = self.journal.rewind(pos + 1).await?;
        self = self.sync_journal().await?;
        self.merkle = merkle;
        self.tip = tip;
        Ok(self)
    }

    /// Drop witnesses for commits with fewer than `pruning_boundary` operations. Some witness
    /// below the boundary may survive.
    ///
    /// Pruning bounds how far back [`Self::rewind`] can reach; the current commit's witness
    /// always survives. The prune is made durable before this method returns.
    ///
    /// # Errors
    ///
    /// Fails if a compact-sync import has not yet been applied to the witness journal.
    #[tracing::instrument(
        name = "qmdb.compact.db.prune",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn prune(mut self, pruning_boundary: Location<F>) -> Result<Self, Error<F>> {
        self.check_import_applied()?;

        let bounds = self.journal.bounds();
        if bounds.is_empty() {
            return Ok(self);
        }
        // Clamp below the tip so the journal never empties: the tip is the current state.
        let pos = self
            .first_at_or_above(pruning_boundary)
            .await?
            .min(bounds.end - 1);
        (self.journal, _) = self.journal.prune(pos).await?;
        self.sync_journal().await
    }

    /// Reject operations on a journal whose contents an unapplied compact-sync import is
    /// about to replace.
    const fn check_import_applied(&self) -> Result<(), Error<F>> {
        if matches!(self.tip_state, TipState::Imported) {
            return Err(Error::DataCorrupted("compact-sync import not applied"));
        }
        Ok(())
    }

    /// Binary search for the first retained position whose entry commits at least `size`
    /// leaves, or the end of the journal if none does.
    async fn first_at_or_above(&self, size: Location<F>) -> Result<u64, Error<F>> {
        let bounds = self.journal.bounds();
        let (mut lo, mut hi) = (bounds.start, bounds.end);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.journal.read(mid).await?.size < size {
                // The entry at `mid` is below `size`, so the answer is after it.
                lo = mid + 1;
            } else {
                // The entry at `mid` qualifies, so the answer is `mid` or before it.
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Destroy all persisted state associated with this database.
    #[boxed]
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        Ok(())
    }

    /// Serve `request` from the single committed state the tip witness retains: the final
    /// commit operation and the pinned nodes one operation below it. Anything else is refused
    /// with the same errors a pruned operation log reports.
    #[tracing::instrument(
        name = "qmdb.sync.serve",
        level = "info",
        skip_all,
        fields(
            size = *request.size(),
            start = *request.start(),
            max_ops = request.max_ops().get(),
        ),
    )]
    fn compact_state(&self, request: Request<F>) -> Result<Response<F, O, H::Digest>, Error<F>> {
        let size = self.tip.size();
        let last_commit_loc = size - 1;
        if request.size() > size || request.size() == 0 {
            return Err(merkle::Error::RangeOutOfBounds(request.size()).into());
        }
        if request.size() < size {
            return Err(crate::journal::Error::ItemPruned(*request.size() - 1).into());
        }
        if request.start() >= request.size() {
            return Err(merkle::Error::RangeOutOfBounds(request.start()).into());
        }
        if request.start() < last_commit_loc {
            return Err(crate::journal::Error::ItemPruned(*request.start()).into());
        }
        let op = self.tip.witness.commit.clone();
        // After the checks above, `start == last_commit_loc`, so the stored pinned nodes are the
        // pinned nodes for this request.
        Ok(match request {
            Request::Operations { .. } => Response::Operations {
                proof: self.tip.proof.clone(),
                operations: vec![op],
            },
            Request::Boundary { .. } => Response::Boundary {
                proof: self.tip.proof.clone(),
                op,
                pinned_nodes: self.tip.witness.pinned_nodes.clone(),
            },
        })
    }
}

/// A speculative batch for a compact db.
pub struct UnmerkleizedBatch<F, H, O, S: Strategy>
where
    F: Family,
    H: Hasher,
    O: Operation<F>,
{
    merkle_batch: compact_merkle::UnmerkleizedBatch<F, H::Digest, S>,
    pub(in crate::qmdb) mutations: O::Mutations,
    parent: Option<MerkleizedParent<F, H, O, S>>,
    base: Commitment<F, H::Digest>,
}

impl<F, H, O, S> UnmerkleizedBatch<F, H, O, S>
where
    F: Family,
    H: Hasher,
    O: Operation<F>,
    S: Strategy,
{
    fn new<E>(db: &Db<F, E, O, H, S>, base: Commitment<F, H::Digest>) -> Self
    where
        E: Context,
    {
        Self {
            merkle_batch: db.merkle.new_batch(),
            mutations: O::Mutations::default(),
            parent: None,
            base,
        }
    }

    /// The database boundary for this batch chain.
    ///
    /// A batch created from the database uses its base. A child inherits its parent's `db`.
    fn db(&self) -> Commitment<F, H::Digest> {
        self.parent
            .as_ref()
            .map_or(self.base, |parent| parent.bounds.db)
    }

    /// Resolve pending mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    ///
    /// `inactivity_floor` goes into the commit operation so the root matches the full db's. It
    /// must be at least the db's current floor and at most the batch's commit location
    /// (`total_size - 1`).
    #[tracing::instrument(
        name = "qmdb.compact.batch.merkleize",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn merkleize<E>(
        self,
        db: &Db<F, E, O, H, S>,
        metadata: Option<O::Metadata>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, O, S>>
    where
        E: Context,
    {
        let live_ancestors: Vec<_> =
            batch_chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors())
                .collect();
        let boundary = batch_chain::effective_boundary(
            self.db(),
            live_ancestors.last().map(|oldest| oldest.bounds.base),
        );

        let commit = O::commit(metadata, inactivity_floor);
        let mutations = self.mutations.into_iter().map(O::mutation);
        let mut ops = Vec::with_capacity(mutations.len() + 1);
        ops.extend(mutations);
        ops.push(commit.clone());

        let total_size = self.base.size + ops.len() as u64;
        let inactive_peaks = F::inactive_peaks(total_size, inactivity_floor);
        let (merkle, root) = compact_batch::merkleize_ops::<F, H, S, _>(
            &db.merkle,
            self.merkle_batch,
            ops,
            inactive_peaks,
        )
        .await
        .expect("inactive_peaks computed from batch size");

        let ancestors = batch_chain::collect_ancestor_bounds(
            live_ancestors,
            |batch| batch.bounds.inactivity_floor,
            |batch| batch.commitment(),
        );

        Arc::new(MerkleizedBatch {
            merkle_batch: merkle,
            commit,
            parent: self.parent.as_ref().map(Arc::downgrade),
            bounds: Bounds {
                base: self.base,
                db: boundary,
                tip: Commitment::new(total_size, root),
                ancestors,
                inactivity_floor,
            },
        })
    }
}

/// A speculative batch whose root digest has been computed.
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, O: Operation<F>, S: Strategy> {
    merkle_batch: Arc<batch::MerkleizedBatch<F, D, S>>,
    commit: O,
    parent: Option<Weak<Self>>,
    bounds: Bounds<F, D>,
}

impl<F: Family, D: Digest, O: Operation<F>, S: Strategy> MerkleizedBatch<F, D, O, S> {
    fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, O, S> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }

    /// The [`Commitment`] this batch commits to.
    const fn commitment(&self) -> Commitment<F, D> {
        self.bounds.tip
    }

    /// Return the root digest after this batch is applied.
    pub const fn root(&self) -> D {
        self.bounds.tip.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F, D> {
        &self.bounds
    }

    /// Create a new speculative batch with this one as its parent.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, O, S>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            merkle_batch: compact_merkle::UnmerkleizedBatch::wrap(self.merkle_batch.new_batch()),
            mutations: O::Mutations::default(),
            parent: Some(Arc::clone(self)),
            base: self.commitment(),
        }
    }
}

/// Compute the authenticated root of a newly initialized compact db without opening storage.
///
/// The initial commit never carries metadata, so this root always represents `Commit(None, 0)`.
pub fn initial_root<F, O, H>() -> H::Digest
where
    F: Family,
    O: Operation<F>,
    H: Hasher,
{
    qmdb::single_operation_root::<F, H>(&O::commit(None, Location::new(0)))
}

impl<F, E, O, H, S> Source for Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = O;
    type Error = qmdb::Error<F>;

    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<F, Self::Op, H::Digest>, FeedbackTx), Self::Error> {
        Ok((self.compact_state(request)?, None))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        journal::contiguous::variable::Config as JournalConfig, merkle::mmr, qmdb::compact::witness,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, fail_pending_syncs},
        reschedule,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use core::future::Future;
    use std::num::{NonZeroU16, NonZeroUsize};

    /// An operation type under test: its values and mutations derive from a seed.
    pub(crate) trait TestOperation:
        Operation<mmr::Family, Metadata: PartialEq + std::fmt::Debug, Cfg = ()>
    {
        /// The value (and commit metadata) for `seed`.
        fn value(seed: u64) -> Self::Metadata;

        /// Add the one mutation derived from `seed` to `batch`.
        fn mutate(batch: TestBatch<Self>, seed: u64) -> TestBatch<Self>;
    }

    pub(crate) type TestDb<O> = Db<mmr::Family, deterministic::Context, O, Sha256, Sequential>;
    pub(crate) type TestBatch<O> = UnmerkleizedBatch<mmr::Family, Sha256, O, Sequential>;

    /// Lets tests write `batch.mutate(seed)` for any operation type.
    trait Mutate {
        fn mutate(self, seed: u64) -> Self;
    }

    impl<O: TestOperation> Mutate for TestBatch<O> {
        fn mutate(self, seed: u64) -> Self {
            O::mutate(self, seed)
        }
    }

    const WITNESS_PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const WITNESS_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    fn witness_config(partition: &str, pooler: &impl BufferPooler) -> JournalConfig<()> {
        JournalConfig {
            partition: format!("{partition}-witness"),
            items_per_section: NZU64!(64),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(pooler, WITNESS_PAGE_SIZE, WITNESS_PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(1024),
        }
    }

    pub(crate) async fn open_db<O: TestOperation>(
        context: deterministic::Context,
        partition: &str,
    ) -> TestDb<O> {
        let journal = open_witness_journal::<O>(context.child("witness"), partition).await;
        Db::init_from_journal(Sequential, journal).await.unwrap()
    }

    /// Open the witness journal for `partition`; `open_db` and the tip-corrupting tests share it.
    async fn open_witness_journal<O: TestOperation>(
        context: deterministic::Context,
        partition: &str,
    ) -> witness::Journal<deterministic::Context, mmr::Family, Digest, O> {
        let cfg = witness_config(partition, &context);
        witness::Journal::init(context, cfg).await.unwrap()
    }

    /// The witness serves only the request matching its single committed state. Each mismatch
    /// reports the same error a pruned operation log would.
    pub(crate) fn test_serve_refuses_requests_outside_witness<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-serve-refusal").await;
            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let n = db.target().size;
            let boundary = |size: Location<mmr::Family>, start: Location<mmr::Family>| {
                Request::Boundary { size, start }
            };
            let operations =
                |size: Location<mmr::Family>, start: Location<mmr::Family>| Request::Operations {
                    size,
                    start,
                    max_ops: NZU64!(1),
                };

            let beyond = n + 1;
            assert!(matches!(
                db.serve(boundary(beyond, n)).await,
                Err(Error::Merkle(crate::merkle::Error::RangeOutOfBounds(_)))
            ));
            assert!(matches!(
                db.serve(operations(Location::new(0), Location::new(0)))
                    .await,
                Err(Error::Merkle(crate::merkle::Error::RangeOutOfBounds(_)))
            ));
            assert!(matches!(
                db.serve(operations(n - 1, n - 2)).await,
                Err(Error::Journal(crate::journal::Error::ItemPruned(_)))
            ));
            assert!(matches!(
                db.serve(boundary(n, n)).await,
                Err(Error::Merkle(crate::merkle::Error::RangeOutOfBounds(_)))
            ));
            assert!(matches!(
                db.serve(boundary(n, n - 2)).await,
                Err(Error::Journal(crate::journal::Error::ItemPruned(_)))
            ));

            // Requests without pinned nodes are also served, even when they ask for more operations
            // than the witness holds.
            let (response, feedback_tx) = db
                .serve(Request::Operations {
                    size: n,
                    start: n - 1,
                    max_ops: NZU64!(5),
                })
                .await
                .unwrap();
            assert!(feedback_tx.is_none());
            let Response::Operations { operations, .. } = response else {
                panic!("operations request should get an operations response");
            };
            assert_eq!(operations.len(), 1);
            let (response, _) = db.serve(boundary(n, n - 1)).await.unwrap();
            assert!(matches!(response, Response::Boundary { .. }));
        });
    }

    /// A compact db over a delayed-sync storage backend.
    type DelayedDb<O> =
        Db<mmr::Family, DelayedSyncContext<deterministic::Context>, O, Sha256, Sequential>;

    /// Open a [DelayedDb] whose blob syncs park on `pending`.
    ///
    /// Init durably persists the bootstrap witness, so while syncs park the returned future
    /// must be driven with [drive_pending_syncs] (or the mock unblocked first).
    fn open_delayed_db<O: TestOperation>(
        context: &deterministic::Context,
        label: &'static str,
        partition: &str,
        pending: &PendingSyncs,
    ) -> impl Future<Output = Result<DelayedDb<O>, Error<mmr::Family>>> {
        let witness_cfg = witness_config(partition, context);
        let context = DelayedSyncContext {
            inner: context.child(label),
            pending: pending.clone(),
        };
        async move {
            let journal = witness::Journal::init(context.child("witness"), witness_cfg).await?;
            DelayedDb::<O>::init_from_journal(Sequential, journal).await
        }
    }

    /// Apply a batch holding the one mutation for `seed`, with `seed`'s value as metadata.
    async fn apply<O: TestOperation>(db: DelayedDb<O>, seed: u64) -> DelayedDb<O> {
        let floor = db.inactivity_floor_loc();
        let batch = db
            .new_batch()
            .mutate(seed)
            .merkleize(&db, Some(O::value(seed)), floor)
            .await;
        let (db, _) = db.apply_batch(batch).await.unwrap();
        db
    }

    /// Leave a failed recovery-watermark sync retained after dropping its public handle.
    async fn fail_dropped_watermark_sync<O: TestOperation>(
        mut db: DelayedDb<O>,
        pending: &PendingSyncs,
    ) -> DelayedDb<O> {
        // Prove the data durable so the next call only advances recovery metadata.
        let first;
        (db, first) = db.start_sync().await.unwrap();
        drive_pending_syncs(pending, first).await.unwrap();

        let dropped;
        (db, dropped) = db.start_sync().await.unwrap();
        assert_eq!(
            pending.lock().len(),
            1,
            "expected only the recovery-watermark sync"
        );
        fail_pending_syncs(pending);
        drop(dropped);
        db
    }

    /// Applying a successor does not wait for the witness sync already in flight.
    pub(crate) fn test_compact_apply_overlaps_start_sync<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "compact-start-sync-overlap";
            let pending = PendingSyncs::default();
            let open = open_delayed_db::<O>(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;

            let starts_before = pending.starts();
            let entered_before = pending.entered();
            let completions_before = pending.completions();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);
            assert_eq!(pending.completions(), completions_before);
            let first_target = db.target();

            let waiter = ctx
                .child("await_sync")
                .spawn(|_| async move { handle.await.unwrap() });
            while pending.entered() == entered_before {
                reschedule().await;
            }

            db = apply(db, 2).await;
            assert_ne!(db.root(), first_target.root);
            let second_target = db.target();
            assert_ne!(second_target, first_target);
            assert_eq!(
                pending.completions(),
                completions_before,
                "the database made progress while the sync was still in flight"
            );

            pending.unblock();
            waiter.await.unwrap();

            // The successor becomes durable after the next start_sync handle completes.
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            drop(db);

            let db = open_delayed_db::<O>(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.target(), second_target);
            assert_eq!(db.get_metadata(), Some(O::value(2)));
            let db = db.rewind(first_target.size).await.unwrap();
            assert_eq!(db.target(), first_target);
            db.destroy().await.unwrap();
        });
    }

    /// State persisted via an awaited start_sync handle is recovered on reopen.
    pub(crate) fn test_compact_start_sync_recovery<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "compact-start-sync-recovery";
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db::<O>(&ctx, "delayed", partition, &pending)
                .await
                .unwrap();
            db = apply(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let root = db.root();
            drop(db);

            let db = open_delayed_db::<O>(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.get_metadata(), Some(O::value(1)));
            db.destroy().await.unwrap();
        });
    }

    /// A sync begun by `start_sync` that fails in flight surfaces the error through both the
    /// returned handle and the next durability operation, even when that operation has nothing
    /// new to persist.
    pub(crate) fn test_compact_start_sync_failure_propagates<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db::<O>(&ctx, "delayed", "compact-start-sync-fail", &pending)
                .await
                .unwrap();
            db = apply(db, 1).await;

            // Arm all future syncs to resolve to an injected error.
            pending.arm_fail();

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(
                handle.await.is_err(),
                "the sync handle surfaces the failure"
            );
            let starts_before = pending.starts();

            // The witness entry was already appended, so this commit has nothing to stage.
            // It must still observe the retained failure rather than no-op.
            assert!(
                db.commit().await.is_err(),
                "the next durability op surfaces the failed in-flight sync"
            );
            assert_eq!(
                pending.starts(),
                starts_before,
                "the surfaced error is the retained failure, not a fresh sync's"
            );
        });
    }

    /// A `sync` with nothing new to persist still drains (and proves) the sync started by a
    /// prior `start_sync`.
    pub(crate) fn test_compact_start_sync_then_noop_sync_drains<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "compact-start-sync-noop-drain";
            let pending = PendingSyncs::default();
            let open = open_delayed_db::<O>(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;

            let starts_before = pending.starts();
            let completions_before = pending.completions();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);
            assert_eq!(pending.completions(), completions_before);
            let root = db.root();

            let db = {
                let mut sync = std::pin::pin!(db.sync());
                assert!(
                    sync.as_mut().now_or_never().is_none(),
                    "sync proceeded while the started sync was pending"
                );
                pending.unblock();
                sync.await.unwrap()
            };
            handle.await.unwrap();
            assert!(pending.completions() > completions_before);
            drop(db);

            let db = open_delayed_db::<O>(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            db.destroy().await.unwrap();
        });
    }

    /// A no-op `sync` returns a retained metadata failure before starting new journal work.
    pub(crate) fn test_compact_start_sync_then_noop_sync_fails_without_new_work<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db::<O>(
                &ctx,
                "delayed",
                "compact-start-sync-noop-sync-fail",
                &pending,
            );
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;
            db = fail_dropped_watermark_sync(db, &pending).await;

            let starts_before = pending.starts();
            assert!(
                drive_pending_syncs(&pending, db.sync()).await.is_err(),
                "sync absorbed the retained metadata failure"
            );
            assert_eq!(
                pending.starts(),
                starts_before,
                "sync started new journal work before returning the retained failure"
            );
        });
    }

    /// A `commit` with nothing new to persist still waits for the sync started by a prior
    /// `start_sync` before reporting the tip durable, and starts no journal work when that
    /// sync succeeds.
    pub(crate) fn test_compact_start_sync_then_noop_commit_waits<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open =
                open_delayed_db::<O>(&ctx, "delayed", "compact-start-sync-noop-commit", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            let starts_before = pending.starts();

            let db = {
                let mut commit = std::pin::pin!(db.commit());
                assert!(
                    commit.as_mut().now_or_never().is_none(),
                    "commit proceeded while the started sync was pending"
                );
                pending.unblock();
                commit.await.unwrap()
            };
            handle.await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before,
                "a successful pipelined sync still triggered journal work"
            );
            db.destroy().await.unwrap();
        });
    }

    /// A `start_sync` with nothing new to persist returns a working handle and appends no
    /// duplicate witness entry.
    pub(crate) fn test_compact_start_sync_noop_second_call<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "compact-start-sync-noop-second";
            let pending = PendingSyncs::default();
            let open = open_delayed_db::<O>(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;

            let h1;
            (db, h1) = db.start_sync().await.unwrap();
            // Release the parked sync: a second start_sync waits for the prior sync before
            // starting, so back-to-back calls under a parked mock would deadlock.
            pending.unblock();
            h1.await.unwrap();

            let h2;
            (db, h2) = db.start_sync().await.unwrap();
            h2.await.unwrap();
            let root = db.root();
            drop(db);

            // The journal holds exactly the bootstrap entry and the one durable witness.
            let journal = open_witness_journal::<O>(ctx.child("probe"), partition).await;
            assert_eq!(journal.size(), 2);
            drop(journal);

            let db = open_delayed_db::<O>(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            db.destroy().await.unwrap();
        });
    }

    /// A rewind to the current size waits for the in-flight sync and adopts its proof of
    /// durability instead of starting new journal work.
    pub(crate) fn test_compact_start_sync_rewind_fast_path_drains<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "compact-start-sync-rewind-drain";
            let pending = PendingSyncs::default();
            let open = open_delayed_db::<O>(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            let root = db.root();
            let size = db.size();

            let starts_before = pending.starts();
            let db = {
                let mut rewind = std::pin::pin!(db.rewind(size));
                assert!(
                    rewind.as_mut().now_or_never().is_none(),
                    "rewind proceeded while the started sync was pending"
                );
                pending.unblock();
                rewind.await.unwrap()
            };
            handle.await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before,
                "the fast path started journal work instead of adopting the proven sync"
            );
            assert_eq!(db.root(), root);
            drop(db);

            // The awaited pipelined sync made the witness entry durable.
            let db = open_delayed_db::<O>(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            db.destroy().await.unwrap();
        });
    }

    /// A rewind to the current size fails when the sync started for the tip witness has
    /// already failed, rather than reporting the unproven tip as durable.
    pub(crate) fn test_compact_start_sync_rewind_fast_path_fails<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db =
                open_delayed_db::<O>(&ctx, "delayed", "compact-start-sync-rewind-fail", &pending)
                    .await
                    .unwrap();
            db = apply(db, 1).await;

            pending.arm_fail();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(handle.await.is_err());
            let size = db.size();
            assert!(
                db.rewind(size).await.is_err(),
                "rewind reported an unproven tip as durable"
            );
        });
    }

    /// A metadata sync failure from `start_sync` resurfaces on the next `commit`, even when
    /// that commit has new state to persist.
    pub(crate) fn test_compact_start_sync_metadata_failure_resurfaces_on_commit<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open =
                open_delayed_db::<O>(&ctx, "delayed", "compact-start-sync-meta-fail", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();

            // start_sync parks the data sync and then the offsets sync. Complete the data
            // sync and fail the offsets sync.
            {
                let mut parked = pending.lock();
                assert_eq!(
                    parked.len(),
                    2,
                    "expected the data and offsets syncs parked"
                );
                let offsets = parked.pop().unwrap();
                let data = parked.pop().unwrap();
                data.release.send(Ok(())).unwrap();
                offsets
                    .release
                    .send(Err(commonware_runtime::Error::Io(
                        std::io::Error::other("injected sync failure").into(),
                    )))
                    .unwrap();
            }
            assert!(
                handle.await.is_err(),
                "the sync handle surfaces the failure"
            );

            // Later syncs pass; only the retained offsets failure remains.
            pending.unblock();

            // Apply another batch to prove commit checks the prior sync before persisting a new
            // witness.
            let db = apply(db, 2).await;
            assert!(
                db.commit().await.is_err(),
                "commit absorbed the retained metadata failure"
            );
        });
    }

    /// A later `start_sync` cannot replace an unobserved failure from the prior handle.
    pub(crate) fn test_compact_start_sync_retains_dropped_metadata_failure<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db::<O>(
                &ctx,
                "delayed",
                "compact-start-sync-dropped-meta-fail",
                &pending,
            );
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply(db, 1).await;
            // Leave only the failed recovery-watermark completion for the next call to observe.
            db = fail_dropped_watermark_sync(db, &pending).await;

            // The store retains the dropped handle's completion. Deferred failures stay on the
            // handle channel, so this call succeeds but its handle must fail.
            let next;
            (db, next) = db.start_sync().await.unwrap();
            assert!(
                drive_pending_syncs(&pending, next).await.is_err(),
                "a later start_sync masked the retained metadata failure"
            );
            drop(db);
        });
    }

    /// Once a start_sync handle completes successfully, a commit and a rewind to the current
    /// size have nothing left to prove and touch no storage.
    pub(crate) fn test_compact_start_sync_proven_skips_journal<O: TestOperation>() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db =
                open_delayed_db::<O>(&ctx, "delayed", "compact-start-sync-proven", &pending)
                    .await
                    .unwrap();
            db = apply(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();

            let starts_before = pending.starts();
            let db = db.commit().await.unwrap();
            let size = db.size();
            let db = db.rewind(size).await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before,
                "a proven pipelined sync still triggered journal work"
            );
            db.destroy().await.unwrap();
        });
    }

    /// The first persist after a compact-sync import can be pipelined: awaiting the handle
    /// makes the imported witness durable.
    pub(crate) fn test_compact_start_sync_persists_import<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let dst = "compact-import-start-sync-dst";
            let src = "compact-import-start-sync-src";
            let meta_a = O::value(11);
            let meta_b = O::value(22);

            // Build state B in a separate source partition and capture its validated state.
            let target_b = {
                let source = open_db::<O>(context.child("src"), src).await;
                let batch = source
                    .new_batch()
                    .mutate(2)
                    .merkleize(&source, Some(meta_b.clone()), Location::new(0))
                    .await;
                let (source, _) = source.apply_batch(batch).await.unwrap();
                let source = source.sync().await.unwrap();
                source.target()
            };
            let (_, size_b, pinned_b) = {
                let journal = open_witness_journal::<O>(context.child("src_tip"), src).await;
                witness::tests::tip(&journal).await
            };
            assert_eq!(size_b, target_b.size);

            // Seed the destination partition with a different committed state A.
            {
                let seeded = open_db::<O>(context.child("seed"), dst).await;
                let batch = seeded
                    .new_batch()
                    .mutate(1)
                    .merkleize(&seeded, Some(meta_a), Location::new(0))
                    .await;
                let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                let seeded = seeded.sync().await.unwrap();
                assert_ne!(seeded.target(), target_b);
            }

            // Import state B over the destination and make it durable through a pipelined sync.
            {
                let journal = open_witness_journal::<O>(context.child("import"), dst).await;
                let imported = TestDb::<O>::init_from_sync(
                    Sequential,
                    journal,
                    size_b - 1,
                    pinned_b,
                    O::commit(Some(meta_b.clone()), Location::new(0)),
                )
                .unwrap();
                assert_eq!(imported.target(), target_b);
                let (_imported, handle) = imported.start_sync().await.unwrap();
                handle.await.unwrap();
            }

            // Reopen recovers the imported state, replacing state A.
            let db = open_db::<O>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), target_b);
            assert_eq!(db.root(), target_b.root);
            assert_eq!(db.get_metadata(), Some(meta_b));
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_stale_batch_rejected<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-stale").await;
            let floor = db.inactivity_floor_loc();

            let batch_a = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), floor)
                .await;
            let batch_b = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await;

            let expected_root = batch_a.root();
            let (db, _) = db.apply_batch(batch_a).await.unwrap();
            assert_eq!(db.root(), expected_root);
            assert!(matches!(
                db.apply_batch(batch_b).await,
                Err(Error::StaleBatch)
            ));
        });
    }

    pub(crate) fn test_compact_delayed_merkleize_after_ancestor_apply<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-delayed-child").await;
            let floor = db.inactivity_floor_loc();

            let a = db.new_batch().mutate(1).merkleize(&db, None, floor).await;
            let b = a
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, None, floor)
                .await;
            let c = b.new_batch::<Sha256>().mutate(3);

            let (db, _) = db.apply_batch(a).await.unwrap();
            let c = c.merkleize(&db, None, floor).await;
            let expected_root = c.root();
            let (db, _) = db.apply_batch(c).await.unwrap();

            assert_eq!(db.root(), expected_root);
        });
    }

    /// `to_batch()` reflects the current applied state before it becomes durable.
    pub(crate) fn test_compact_to_batch_reflects_live_state<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-to-batch-live").await;
            let floor = db.inactivity_floor_loc();

            let pre_apply_root = db.root();
            let pre_snapshot = db.to_batch();
            assert_eq!(
                pre_snapshot.root(),
                pre_apply_root,
                "snapshot before any mutation should match the live root"
            );

            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();

            // Observe the applied state before making it durable.
            let live_root = db.root();
            assert_ne!(
                live_root, pre_apply_root,
                "applying a non-empty batch must change the live root"
            );

            let snapshot = db.to_batch();
            assert_eq!(
                snapshot.root(),
                live_root,
                "to_batch().root() must match the live db.root() even before sync"
            );

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_stale_batch_chained<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-chained-stale").await;
            let floor = db.inactivity_floor_loc();

            let common_parent = db
                .new_batch()
                .mutate(10)
                .merkleize(&db, Some(O::value(110)), floor)
                .await;
            let sibling_a = common_parent
                .new_batch::<Sha256>()
                .mutate(11)
                .merkleize(&db, Some(O::value(111)), floor)
                .await;
            let sibling_b = common_parent
                .new_batch::<Sha256>()
                .mutate(12)
                .merkleize(&db, Some(O::value(112)), floor)
                .await;
            let (db, _) = db.apply_batch(sibling_a).await.unwrap();
            assert!(matches!(
                db.validate_batch(&sibling_b),
                Err(Error::StaleBatch)
            ));

            let parent_a = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), floor)
                .await;
            let parent_b = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await;
            let child_b = parent_b
                .new_batch::<Sha256>()
                .mutate(3)
                .merkleize(&db, Some(O::value(33)), floor)
                .await;

            let (db, _) = db.apply_batch(parent_a).await.unwrap();
            assert!(matches!(
                db.validate_batch(&child_b),
                Err(Error::StaleBatch)
            ));
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_stale_parent_after_child_applied<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-child-before-parent").await;
            let floor = db.inactivity_floor_loc();

            let parent = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), floor)
                .await;
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await;

            let (db, _) = db.apply_batch(child).await.unwrap();
            assert!(matches!(
                db.apply_batch(parent).await,
                Err(Error::StaleBatch)
            ));
        });
    }

    pub(crate) fn test_compact_sequential_commit_parent_then_child<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-parent-child").await;
            let floor = db.inactivity_floor_loc();

            let parent = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), floor)
                .await;
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await;
            let expected_root = child.root();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let (db, _) = db.apply_batch(child).await.unwrap();
            let db = db.sync().await.unwrap();

            assert_eq!(db.root(), expected_root);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_floor_regressed<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-floor-regressed").await;

            let advance_floor = db.new_batch().mutate(1);
            let advance_floor = advance_floor.merkleize(&db, None, Location::new(1)).await;
            let (db, _) = db.apply_batch(advance_floor).await.unwrap();
            let db = db.sync().await.unwrap();
            let target = db.target();

            let regressed = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await;

            assert!(matches!(
                db.apply_batch(regressed).await,
                Err(Error::FloorRegressed(new, current))
                    if new == Location::new(0) && current == Location::new(1)
            ));

            // Reopen and verify the rejected batch persisted nothing.
            let db = open_db::<O>(context.child("reopen"), "compact-floor-regressed").await;
            assert_eq!(db.target(), target);
        });
    }

    /// A chained batch whose tip floor is below its parent's floor must be rejected:
    /// the parent's Commit participates in the per-commit monotonicity invariant even
    /// before it is applied.
    pub(crate) fn test_compact_ancestor_floor_regressed<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-ancestor-floor-regressed").await;

            // parent: one op + commit at loc 2 with floor=2.
            let parent = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(2))
                .await;
            // child: one op + commit at loc 4 with floor=1 (regressed from parent's floor=2).
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, None, Location::new(1))
                .await;

            let target = db.target();
            assert!(matches!(
                db.apply_batch(child).await,
                Err(Error::FloorRegressed(new, prev))
                    if new == Location::new(1) && prev == Location::new(2)
            ));

            // Reopen and verify the rejected chain persisted nothing.
            let db =
                open_db::<O>(context.child("reopen"), "compact-ancestor-floor-regressed").await;
            assert_eq!(db.target(), target);
        });
    }

    pub(crate) fn test_compact_rewind_restores_commit_metadata_and_floor<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-rewind-meta").await;

            let meta1 = O::value(11);
            let floor1 = Location::new(0);
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(meta1.clone()), floor1)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();
            let size_after_first = db.size();

            let meta2 = O::value(22);
            let floor2 = Location::new(1);
            let batch = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, Some(meta2.clone()), floor2)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            assert_eq!(db.get_metadata(), Some(meta2));
            assert_eq!(db.inactivity_floor_loc(), floor2);

            let db = db.rewind(size_after_first).await.unwrap();
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.get_metadata(), Some(meta1));
            assert_eq!(db.inactivity_floor_loc(), floor1);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_rewind_persists_across_reopen<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-rewind-reopen";
            let meta1 = O::value(11);
            let floor1 = Location::new(0);
            let meta2 = O::value(22);
            let floor2 = Location::new(1);

            let root_after_first = {
                let db = open_db::<O>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .mutate(1)
                    .merkleize(&db, Some(meta1.clone()), floor1)
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();
                let root = db.root();
                let size_after_first = db.size();

                let batch = db
                    .new_batch()
                    .mutate(2)
                    .merkleize(&db, Some(meta2), floor2)
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();

                let _db = db.rewind(size_after_first).await.unwrap();
                root
            };

            let db = open_db::<O>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.get_metadata(), Some(meta1));
            assert_eq!(db.inactivity_floor_loc(), floor1);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_commit_persists_across_reopen<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-commit-reopen";
            let meta1 = O::value(11);
            let meta2 = O::value(22);

            let root_after_second = {
                let db = open_db::<O>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .mutate(1)
                    .merkleize(&db, Some(meta1), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = db
                    .new_batch()
                    .mutate(2)
                    .merkleize(&db, Some(meta2.clone()), Location::new(1))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();
                db.root()
            };

            // Reopen recovers the committed tip even though the journal was never synced.
            let db = open_db::<O>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_after_second);
            assert_eq!(db.get_metadata(), Some(meta2));
            assert_eq!(db.inactivity_floor_loc(), Location::new(1));
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_rewind_to_committed_entry_after_reopen<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-commit-rewind-reopen";
            let meta1 = O::value(11);
            let meta2 = O::value(22);

            let (root_a, size_a) = {
                let db = open_db::<O>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .mutate(1)
                    .merkleize(&db, Some(meta1.clone()), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();
                let root_a = db.root();
                let size_a = db.size();

                let batch = db
                    .new_batch()
                    .mutate(2)
                    .merkleize(&db, Some(meta2), Location::new(1))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let _db = db.commit().await.unwrap();
                (root_a, size_a)
            };

            // Both committed witnesses survive the crash: reopen recovers the tip, and the
            // earlier commit remains a valid rewind target.
            let db = open_db::<O>(context.child("second"), partition).await;
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.get_metadata(), Some(meta1));
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_sync_after_commit<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-sync-after-commit";
            let meta = O::value(11);

            let root = {
                let db = open_db::<O>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .mutate(1)
                    .merkleize(&db, Some(meta.clone()), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();
                // The commit already made the state durable, so this is a no-op.
                let db = db.sync().await.unwrap();
                db.root()
            };

            let db = open_db::<O>(context.child("second"), partition).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.get_metadata(), Some(meta));
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_import_persists_with_commit<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let dst = "compact-import-commit-dst";
            let src = "compact-import-commit-src";
            let meta_a = O::value(11);
            let meta_b = O::value(22);

            // Build state B in a separate source partition and fetch its state the way a sync
            // client would.
            let (target_b, pinned_b) = {
                let source = open_db::<O>(context.child("src"), src).await;
                let batch = source
                    .new_batch()
                    .mutate(2)
                    .merkleize(&source, Some(meta_b.clone()), Location::new(0))
                    .await;
                let (source, _) = source.apply_batch(batch).await.unwrap();
                let source = source.sync().await.unwrap();
                let target = source.target();
                let (response, _) = source
                    .serve(Request::Boundary {
                        size: target.size,
                        start: target.size - 1,
                    })
                    .await
                    .unwrap();
                let Response::Boundary { pinned_nodes, .. } = response else {
                    panic!("boundary request should get a boundary response");
                };
                (target, pinned_nodes)
            };

            // Seed the destination partition with a different committed state A.
            {
                let seeded = open_db::<O>(context.child("seed"), dst).await;
                let batch = seeded
                    .new_batch()
                    .mutate(1)
                    .merkleize(&seeded, Some(meta_a), Location::new(0))
                    .await;
                let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                let seeded = seeded.sync().await.unwrap();
                assert_ne!(seeded.target(), target_b);
            }

            // Import state B over the destination and make it durable with commit (not sync).
            {
                let journal = open_witness_journal::<O>(context.child("import"), dst).await;
                let imported = TestDb::<O>::init_from_sync(
                    Sequential,
                    journal,
                    target_b.size - 1,
                    pinned_b,
                    O::commit(Some(meta_b.clone()), Location::new(0)),
                )
                .unwrap();
                assert_eq!(imported.target(), target_b);
                let _imported = imported.commit().await.unwrap();
            }

            // Reopen recovers the committed import, replacing state A even though the journal was
            // never synced.
            let db = open_db::<O>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), target_b);
            assert_eq!(db.root(), target_b.root);
            assert_eq!(db.get_metadata(), Some(meta_b));
            db.destroy().await.unwrap();
        });
    }

    /// Applying a batch to an import-pending db journals the imported witness in place of the
    /// partition's previous contents before appending the new one.
    pub(crate) fn test_compact_import_then_apply_persists<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let dst = "compact-import-apply-dst";
            let src = "compact-import-apply-src";
            let meta_a = O::value(11);
            let meta_b = O::value(22);
            let meta_c = O::value(33);

            // Build state B in a separate source partition and fetch its state the way a sync
            // client would.
            let (target_b, pinned_b) = {
                let source = open_db::<O>(context.child("src"), src).await;
                let batch = source
                    .new_batch()
                    .mutate(2)
                    .merkleize(&source, Some(meta_b.clone()), Location::new(0))
                    .await;
                let (source, _) = source.apply_batch(batch).await.unwrap();
                let source = source.sync().await.unwrap();
                let target = source.target();
                let (response, _) = source
                    .serve(Request::Boundary {
                        size: target.size,
                        start: target.size - 1,
                    })
                    .await
                    .unwrap();
                let Response::Boundary { pinned_nodes, .. } = response else {
                    panic!("boundary request should get a boundary response");
                };
                (target, pinned_nodes)
            };

            // Seed the destination partition with a different committed state A of the same size.
            {
                let seeded = open_db::<O>(context.child("seed"), dst).await;
                let batch = seeded
                    .new_batch()
                    .mutate(1)
                    .merkleize(&seeded, Some(meta_a), Location::new(0))
                    .await;
                let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                let seeded = seeded.sync().await.unwrap();
                assert_eq!(seeded.target().size, target_b.size);
                assert_ne!(seeded.target(), target_b);
            }

            // Import state B over the destination and apply a batch on top of it with no
            // durability operation in between.
            let target_c = {
                let journal = open_witness_journal::<O>(context.child("import"), dst).await;
                let imported = TestDb::<O>::init_from_sync(
                    Sequential,
                    journal,
                    target_b.size - 1,
                    pinned_b,
                    O::commit(Some(meta_b.clone()), Location::new(0)),
                )
                .unwrap();
                assert_eq!(imported.target(), target_b);
                let floor = imported.inactivity_floor_loc();
                let batch = imported
                    .new_batch()
                    .mutate(3)
                    .merkleize(&imported, Some(meta_c.clone()), floor)
                    .await;
                let root_c = batch.root();
                let (applied, _) = imported.apply_batch(batch).await.unwrap();
                assert_eq!(applied.root(), root_c);
                let target_c = applied.target();
                let _applied = applied.sync().await.unwrap();
                target_c
            };

            // Reopen lands on the applied state, and the retained history below it is B, not A.
            let db = open_db::<O>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), target_c);
            assert_eq!(db.get_metadata(), Some(meta_c));
            let db = db.rewind(target_b.size).await.unwrap();
            assert_eq!(db.target(), target_b);
            assert_eq!(db.get_metadata(), Some(meta_b));
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_reopen_rejects_tampered_witness<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-witness-tamper";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(7)
                .merkleize(&db, Some(O::value(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Corrupt the entry structurally. An extra pinned node cannot rebuild the Merkle.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let (commit, size, mut pinned_nodes) = witness::tests::tip(&journal).await;
            pinned_nodes.push(Sha256::fill(0xff));
            witness::tests::overwrite_tip(journal, commit, size, pinned_nodes).await;

            let journal =
                open_witness_journal::<O>(context.child("reopen_witness"), partition).await;
            let reopened = TestDb::<O>::init_from_journal(Sequential, journal).await;
            assert!(matches!(reopened, Err(Error::DataCorrupted(_))));
        });
    }

    pub(crate) fn test_compact_rewind_rejects_corrupt_target_entry<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-corrupt-rewind-target";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let rewind_target = db.target().size;
            let batch = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let tip_target = db.target();
            drop(db);

            // Corrupt the rewind target's entry (the journal holds bootstrap, target, tip).
            let mut journal = open_witness_journal::<O>(context.child("corrupt"), partition).await;
            journal = witness::tests::corrupt_entry(journal, 1, |entry| {
                entry.pinned_nodes.push(Sha256::fill(0xff));
            })
            .await;
            drop(journal);

            // The tip entry is intact, so reopen succeeds.
            let journal = open_witness_journal::<O>(context.child("reopen"), partition).await;
            let reopened = TestDb::<O>::init_from_journal(Sequential, journal)
                .await
                .unwrap();
            assert_eq!(reopened.target(), tip_target);

            // The corrupt entry fails the rewind before any truncation.
            assert!(matches!(
                reopened.rewind(rewind_target).await,
                Err(Error::DataCorrupted(_))
            ));

            // The newer history survives: reopen still lands on the original tip.
            let journal = open_witness_journal::<O>(context.child("reopen2"), partition).await;
            let reopened = TestDb::<O>::init_from_journal(Sequential, journal)
                .await
                .unwrap();
            assert_eq!(reopened.target(), tip_target);
            reopened.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_reopen_rejects_interrupted_import<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-interrupted-import";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(7)
                .merkleize(&db, Some(O::value(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Simulate a crash between an import's journal clear and its entry append: the
            // journal is empty but its size is nonzero.
            let journal = open_witness_journal::<O>(context.child("clear"), partition).await;
            let size = journal.size();
            let journal = journal.clear_to_size(size.max(1)).await.unwrap();
            drop(journal);

            // Reopen must fail rather than bootstrap a fresh db.
            let journal =
                open_witness_journal::<O>(context.child("reopen_witness"), partition).await;
            let reopened = TestDb::<O>::init_from_journal(Sequential, journal).await;
            assert!(matches!(reopened, Err(Error::Journal(_))));
        });
    }

    pub(crate) fn test_compact_reopen_rejects_commit_floor_beyond_tip<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-invalid-persisted-floor";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(7)
                .merkleize(&db, Some(O::value(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);
            let oversized_floor = Location::new(10);

            // Overwrite the persisted commit op with a floor beyond its own commit location.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let (_, size, pinned_nodes) = witness::tests::tip(&journal).await;
            let bad_op = O::commit(Some(O::value(11)), oversized_floor);
            witness::tests::overwrite_tip(journal, bad_op, size, pinned_nodes).await;

            let journal =
                open_witness_journal::<O>(context.child("reopen_witness"), partition).await;
            let reopened = TestDb::<O>::init_from_journal(Sequential, journal).await;
            assert!(matches!(
                reopened,
                Err(Error::DataCorrupted("invalid compact witness"))
            ));
        });
    }

    pub(crate) fn test_compact_reopen_rejects_non_commit_tip<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-non-commit-tip";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(7)
                .merkleize(&db, Some(O::value(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let non_commit = O::mutation(
                db.new_batch()
                    .mutate(7)
                    .mutations
                    .into_iter()
                    .next()
                    .unwrap(),
            );
            drop(db);

            // Overwrite the persisted commit op with a mutation.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let (_, size, pinned_nodes) = witness::tests::tip(&journal).await;
            witness::tests::overwrite_tip(journal, non_commit, size, pinned_nodes).await;

            let journal =
                open_witness_journal::<O>(context.child("reopen_witness"), partition).await;
            let reopened = TestDb::<O>::init_from_journal(Sequential, journal).await;
            assert!(matches!(
                reopened,
                Err(Error::DataCorrupted("last operation was not a commit"))
            ));
        });
    }

    pub(crate) fn test_compact_reopen_rejects_tampered_pinned_nodes<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-pinned-nodes-tamper";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(7)
                .merkleize(&db, Some(O::value(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let tampered_target = db.target();
            drop(db);

            // Flip one pinned-node digest. There is no stored proof to cross-check against, so the
            // rebuild succeeds and yields a different root, the same way a bit-flipped replay
            // journal reopens with a different root.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let (commit, size, mut pinned_nodes) = witness::tests::tip(&journal).await;
            pinned_nodes[0] = Sha256::fill(0xff);
            witness::tests::overwrite_tip(journal, commit, size, pinned_nodes).await;

            let journal =
                open_witness_journal::<O>(context.child("reopen_witness"), partition).await;
            let reopened = TestDb::<O>::init_from_journal(Sequential, journal)
                .await
                .unwrap();
            assert_ne!(reopened.target(), tampered_target);
            reopened.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_rewind_to_current_is_noop<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-rewind-noop").await;
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root = db.root();
            let size = db.size();

            let db = db.rewind(size).await.unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.size(), size);
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_prune_past_tip_keeps_tip<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-prune-past-tip";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let target = db.target();

            // Prune with a boundary beyond the tip: the tip entry must survive.
            let boundary = db.size() + 100;
            let db = db.prune(boundary).await.unwrap();
            assert_eq!(db.target(), target);
            drop(db);

            let reopened = open_db::<O>(context.child("reopen"), partition).await;
            assert_eq!(reopened.target(), target);
            reopened.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_rewind_beyond_history<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-rewind-beyond").await;
            // The bootstrap commit is the oldest retained state (one leaf); no commit with zero
            // operations exists to rewind to.
            assert!(matches!(
                db.rewind(Location::new(0)).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));

            let db = open_db::<O>(context.child("reopen"), "compact-rewind-beyond").await;
            // A target past the tip is not a commit either.
            let beyond_tip = db.size() + 100;
            assert!(matches!(
                db.rewind(beyond_tip).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));
        });
    }

    pub(crate) fn test_compact_rewind_between_commits<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-rewind-between").await;
            let floor = db.inactivity_floor_loc();

            // A multi-op commit jumps the committed size from 1 (bootstrap) to 4.
            let batch = db
                .new_batch()
                .mutate(1)
                .mutate(2)
                .merkleize(&db, Some(O::value(11)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_a = db.root();
            let size_a = db.size();
            assert_eq!(size_a, Location::new(4));

            // A second commit moves the size to 6.
            let batch = db
                .new_batch()
                .mutate(3)
                .merkleize(&db, Some(O::value(22)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_b = db.root();

            // Targets inside a commit's span match no entry, even though entries exist on
            // both sides.
            let mut db = db;
            for target in [2u64, 3, 5] {
                assert!(matches!(
                    db.rewind(Location::new(target)).await,
                    Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
                ));
                db = open_db::<O>(
                    context.child("reopen").with_attribute("target", target),
                    "compact-rewind-between",
                )
                .await;
            }
            assert_eq!(db.root(), root_b);

            // The exact commit boundary remains a valid target.
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.get_metadata(), Some(O::value(11)));
            db.destroy().await.unwrap();
        });
    }

    /// A witness entry appended but not synced (a commit interrupted before its journal sync)
    /// must be dropped on reopen, recovering the last synced commit.
    pub(crate) fn test_compact_reopen_drops_unsynced_witness<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-witness-unsynced";
            let db = open_db::<O>(context.child("db"), partition).await;

            // Commit state A.
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let target_a = db.target();
            drop(db);

            // Simulate the crash window: append an entry ahead of the tip without syncing it,
            // then drop the journal. The unsynced tail must not survive reopen.
            let journal = open_witness_journal::<O>(context.child("crash"), partition).await;
            let (commit, mut size, pinned_nodes) = witness::tests::tip(&journal).await;
            size += 2;
            witness::tests::append_unsynced(journal, commit, size, pinned_nodes).await;

            // Reopen must drop the unsynced entry and recover state A.
            let reopened = open_db::<O>(context.child("reopen"), partition).await;
            assert_eq!(reopened.target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_rewind_multiple_commits<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-rewind-multi";
            let db = open_db::<O>(context.child("db"), partition).await;

            // Commit A, B, C, recording the state after A.
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_a = db.root();
            let size_a = db.size();
            let target_a = db.target();

            let mut db = db;
            for i in [2u64, 3] {
                let batch = db
                    .new_batch()
                    .mutate(i)
                    .merkleize(&db, Some(O::value(i * 11)), Location::new(0))
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
            }
            assert_ne!(db.root(), root_a);

            // Rewind two commits in one call.
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.size(), size_a);
            assert_eq!(db.get_metadata(), Some(O::value(11)));
            assert_eq!(db.target(), target_a);
            drop(db);

            // The rewind is durable: reopen recovers state A.
            let db = open_db::<O>(context.child("reopen"), partition).await;
            assert_eq!(db.root(), root_a);
            assert_eq!(db.target(), target_a);
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_prune_then_rewind<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            // One entry per section so pruning takes effect at entry granularity (pruning is
            // section-aligned and never drops a partial section).
            let mut witness_cfg = witness_config("compact-prune-rewind", &context);
            witness_cfg.items_per_section = NZU64!(1);
            let journal = witness::Journal::init(context.child("witness"), witness_cfg.clone())
                .await
                .unwrap();
            let mut db: TestDb<O> = Db::init_from_journal(Sequential, journal).await.unwrap();

            // Commit A, B, C.
            let mut sizes = Vec::new();
            for i in [1u64, 2, 3] {
                let batch = db
                    .new_batch()
                    .mutate(i)
                    .merkleize(&db, Some(O::value(i * 11)), Location::new(0))
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                sizes.push(db.size());
            }

            // Prune history below B: rewinding to B still works, rewinding to A does not.
            let db = db.prune(sizes[1]).await.unwrap();
            assert!(matches!(
                db.rewind(sizes[0]).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));

            // The prune was durable, so reopen and rewind to B.
            let journal = witness::Journal::init(
                context.child("witness").with_attribute("index", 2),
                witness_cfg,
            )
            .await
            .unwrap();
            let db: TestDb<O> = Db::init_from_journal(Sequential, journal).await.unwrap();
            let db = db.rewind(sizes[1]).await.unwrap();
            assert_eq!(db.size(), sizes[1]);
            assert_eq!(db.get_metadata(), Some(O::value(22)));

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_rewind_preserves_pre_advance_batch<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<O>(context.child("db"), "compact-rewind-preserves-pre-advance").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            // Merkleize a batch against the post-commit-A state.
            let held = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await;

            // Advance past that state and commit, then rewind back to it.
            let batch = db
                .new_batch()
                .mutate(3)
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let db = db.rewind(size_after_first).await.unwrap();

            // The rewind restored the state that `held` was merkleized against, so it still
            // matches the Merkle size and applies cleanly.
            let (db, _) = db.apply_batch(held).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_noop_sync_after_sync<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-noop-after-commit").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .mutate(2)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();
            assert_eq!(db.size(), Location::new(4));

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_noop_sync_after_reopen<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-noop-after-reopen";

            let root_before_drop = {
                let db = open_db::<O>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .mutate(1)
                    .mutate(2)
                    .merkleize(&db, Some(O::value(11)), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();
                let root = db.root();
                assert_eq!(db.size(), Location::new(4));
                root
            };

            let db = open_db::<O>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.size(), Location::new(4));

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_before_drop);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_noop_sync_after_rewind<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-noop-after-rewind").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .mutate(2)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();

            let batch = db
                .new_batch()
                .mutate(3)
                .merkleize(&db, Some(O::value(22)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();

            let db = db.rewind(Location::new(4)).await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_rewind_makes_post_advance_batch_stale<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-rewind-makes-stale").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            let batch = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();

            // Merkleize a batch against the post-commit-B state, which the rewind will discard.
            let held = db
                .new_batch()
                .mutate(3)
                .merkleize(&db, None, Location::new(0))
                .await;

            let db = db.rewind(size_after_first).await.unwrap();

            // After rewind, mem.size reflects post-commit-A, but the held batch starts after
            // post-commit-B. Apply must be rejected with StaleBatch.
            assert!(matches!(db.apply_batch(held).await, Err(Error::StaleBatch)));
        });
    }

    pub(crate) fn test_compact_floor_beyond_size<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-floor-beyond").await;

            let batch = db.new_batch().merkleize(&db, None, Location::new(2)).await;

            assert!(matches!(
                db.apply_batch(batch).await,
                Err(Error::FloorBeyondSize(floor, tip))
                    if floor == Location::new(2) && tip == Location::new(1)
            ));
        });
    }

    /// A chained batch whose ancestor's floor exceeds that ancestor's own commit location
    /// must be rejected, identifying the ancestor's bound rather than the tip's.
    pub(crate) fn test_compact_ancestor_floor_beyond_size<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-ancestor-floor-beyond").await;

            // parent: one op + commit at loc 2, floor=3 (one past parent's commit).
            let parent = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(3))
                .await;
            // child: valid on its own (floor=0), but parent's floor is bad.
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await;

            assert!(matches!(
                db.apply_batch(child).await,
                Err(Error::FloorBeyondSize(floor, commit))
                    if floor == Location::new(3) && commit == Location::new(2)
            ));
        });
    }

    /// Emits every compact db test against `$operation`.
    macro_rules! compact_db_tests {
        ($operation:ty) => {
            $crate::qmdb::compact::db::tests::compact_db_tests!(@each $operation;
                test_serve_refuses_requests_outside_witness,
                test_compact_apply_overlaps_start_sync,
                test_compact_start_sync_recovery,
                test_compact_start_sync_failure_propagates,
                test_compact_start_sync_then_noop_sync_drains,
                test_compact_start_sync_then_noop_sync_fails_without_new_work,
                test_compact_start_sync_then_noop_commit_waits,
                test_compact_start_sync_noop_second_call,
                test_compact_start_sync_rewind_fast_path_drains,
                test_compact_start_sync_rewind_fast_path_fails,
                test_compact_start_sync_metadata_failure_resurfaces_on_commit,
                test_compact_start_sync_retains_dropped_metadata_failure,
                test_compact_start_sync_proven_skips_journal,
                test_compact_start_sync_persists_import,
                test_compact_stale_batch_rejected,
                test_compact_delayed_merkleize_after_ancestor_apply,
                test_compact_to_batch_reflects_live_state,
                test_compact_stale_batch_chained,
                test_compact_stale_parent_after_child_applied,
                test_compact_sequential_commit_parent_then_child,
                test_compact_floor_regressed,
                test_compact_ancestor_floor_regressed,
                test_compact_rewind_restores_commit_metadata_and_floor,
                test_compact_rewind_persists_across_reopen,
                test_compact_commit_persists_across_reopen,
                test_compact_rewind_to_committed_entry_after_reopen,
                test_compact_sync_after_commit,
                test_compact_import_persists_with_commit,
                test_compact_import_then_apply_persists,
                test_compact_reopen_rejects_tampered_witness,
                test_compact_rewind_rejects_corrupt_target_entry,
                test_compact_reopen_rejects_interrupted_import,
                test_compact_reopen_rejects_commit_floor_beyond_tip,
                test_compact_reopen_rejects_non_commit_tip,
                test_compact_reopen_rejects_tampered_pinned_nodes,
                test_compact_rewind_to_current_is_noop,
                test_compact_prune_past_tip_keeps_tip,
                test_compact_rewind_beyond_history,
                test_compact_rewind_between_commits,
                test_compact_reopen_drops_unsynced_witness,
                test_compact_rewind_multiple_commits,
                test_compact_prune_then_rewind,
                test_compact_rewind_preserves_pre_advance_batch,
                test_compact_noop_sync_after_sync,
                test_compact_noop_sync_after_reopen,
                test_compact_noop_sync_after_rewind,
                test_compact_rewind_makes_post_advance_batch_stale,
                test_compact_floor_beyond_size,
                test_compact_ancestor_floor_beyond_size
            );
        };
        (@each $operation:ty; $($name:ident),* $(,)?) => {
            $(
                #[commonware_macros::test_traced("INFO")]
                fn $name() {
                    $crate::qmdb::compact::db::tests::$name::<$operation>();
                }
            )*
        };
    }

    pub(crate) use compact_db_tests;
}
