//! The compact db and its batches. See [`crate::qmdb::compact`].

use super::{
    Config, Operation, batch as compact_batch,
    witness::{self, Rebuilt, VerifiedWitness, Witness},
};
use crate::{
    Context, SyncCompletion,
    journal::{
        authenticated::BackingRecovery as _,
        contiguous::{Contiguous, variable},
    },
    merkle::{self, Family, Location, Proof, batch, compact as compact_merkle},
    qmdb::{
        self, Error,
        chain::{self, Bounds, Commitment},
        sync::{CompactTarget, Request, Response, Source, source},
    },
};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::{Error as RError, Handle};
use futures::FutureExt as _;
use std::sync::{Arc, Weak};

type MerkleizedParent<F, H, O, S> = Arc<MerkleizedBatch<F, DigestOf<H>, O, S>>;

/// Result of merkleizing a batch.
type MerkleizeResult<F, D, O, S> = Result<Arc<MerkleizedBatch<F, D, O, S>>, Error<F>>;

/// The journaled tip's durability.
#[derive(PartialEq, Eq)]
enum TipState {
    /// Recovered by [`Db::init`], or covered by a durability operation that has at least started.
    Committed,
    /// Journaled after the latest durability operation started.
    Uncommitted,
}

/// An open witness journal whose last entry is the tip.
struct OpenJournal<E, F, D>
where
    E: Context,
    F: Family,
    D: Digest,
{
    /// The journal of witnesses, one per applied state.
    journal: witness::Journal<E, F, D>,

    /// Whether a durability operation covers the tip.
    tip_state: TipState,

    /// The sync pipelined by the last [`Db::start_sync`], cleared by the next full journal sync.
    pending_sync: Option<SyncCompletion>,
}

impl<E, F, D> OpenJournal<E, F, D>
where
    E: Context,
    F: Family,
    D: Digest,
{
    /// Append `witness` as the new tip, leaving it outside the durable prefix.
    async fn append<O: Operation<F>>(
        mut self,
        witness: &Witness<F, D, O>,
    ) -> Result<Self, Error<F>> {
        (self.journal, _) = self.journal.append(&witness.stored()).await?;
        self.tip_state = TipState::Uncommitted;
        Ok(self)
    }

    /// Sync the journal and all of its metadata, which covers the tip and settles any sync
    /// pipelined by [`Db::start_sync`].
    async fn sync(mut self) -> Result<Self, Error<F>> {
        self.journal = self.journal.sync().await?;
        self.pending_sync = None;
        self.tip_state = TipState::Committed;
        Ok(self)
    }

    /// Wait for any sync pipelined by [`Db::start_sync`], surfacing its failure.
    ///
    /// A successful completion stays recorded until the next full journal sync.
    async fn wait_for_sync(&self) -> Result<(), RError> {
        let Some(pending) = self.pending_sync.clone() else {
            return Ok(());
        };
        pending.await
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
}

/// The partition a pending compact-sync import will replace.
struct Destination<E> {
    /// The context the witness journal opens under.
    context: E,

    /// The witness journal config, without the commit codec config.
    cfg: variable::Config<()>,
}

/// Where a compact db's witnesses live.
enum Storage<E, F, D>
where
    E: Context,
    F: Family,
    D: Digest,
{
    /// The open witness journal.
    Open(OpenJournal<E, F, D>),

    /// A compact-sync import not yet journaled. The partition keeps its previous contents,
    /// unopened, until the first apply or durability operation replaces them with the tip.
    ///
    /// Boxed so the variant does not enlarge every db, and every future that moves one.
    Replacing(Box<Destination<E>>),
}

impl<E, F, D> Storage<E, F, D>
where
    E: Context,
    F: Family,
    D: Digest,
{
    /// Return the open journal, first replacing the partition's contents with `tip` if a
    /// compact-sync import is pending.
    ///
    /// The replacement never decodes the previous contents. It stages a durable reset to position 1
    /// before removing anything, so a crash before that point reopens the previous contents. After
    /// it, a reopen recovers `tip` if its witness survived the crash in full, and otherwise fails
    /// with [`Error::DataCorrupted`] rather than opening a fresh db.
    async fn open<O: Operation<F>>(
        self,
        tip: &Witness<F, D, O>,
    ) -> Result<OpenJournal<E, F, D>, Error<F>> {
        match self {
            Self::Open(open) => Ok(open),
            Self::Replacing(destination) => {
                let Destination { context, cfg } = *destination;
                let journal = witness::Journal::init_at_size(context, cfg, 1).await?;
                let open = OpenJournal {
                    journal,
                    tip_state: TipState::Uncommitted,
                    pending_sync: None,
                };
                open.append(tip).await
            }
        }
    }
}

/// A compact authenticated db that discards historical operations, retaining only a witness
/// for each applied state.
pub struct Db<F, E, O, H, S: Strategy>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
{
    /// The peak-only Merkle the witnesses describe.
    merkle: compact_merkle::Merkle<F, H::Digest, S>,

    /// Where the witnesses live.
    storage: Storage<E, F, H::Digest>,

    /// The verified tip witness.
    tip: VerifiedWitness<F, H::Digest, O>,
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
    /// Initialize from the latest retained witness at or below `max_size` operations.
    /// `None` selects the latest retained state. Fresh storage receives a durable bootstrap
    /// witness.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInitializationBound`] if `max_size` is zero.
    /// - [`Error::HistoricalFloorPruned`] if no retained witness is at or below `max_size`.
    /// - [`Error::Journal`] if the journal or the selected witness's commit cannot be decoded.
    /// - [`Error::DataCorrupted`] if the selected witness cannot be rebuilt, or the journal holds
    ///   an interrupted compact-sync import (re-sync to recover).
    #[boxed]
    pub async fn init(
        context: E,
        cfg: Config<O::Cfg, S>,
        max_size: Option<Location<F>>,
    ) -> Result<Self, Error<F>> {
        qmdb::validate_initialization_bound(max_size)?;
        let (journal_cfg, codec_cfg) = witness::split_config(cfg.witness);
        // Keep recovery unpublished until the target witness has been selected and verified.
        let pending =
            witness::recover::<E, F, H::Digest>(context.child("witness"), journal_cfg, max_size)
                .await?;
        let bounds = pending.bounds();
        let fresh = bounds.is_empty();
        let (entry, end) = if fresh {
            if bounds.start != 0 {
                return Err(Error::DataCorrupted("witness journal has no tip"));
            }
            let genesis = Witness {
                commit: O::commit(None, Location::new(0)),
                size: Location::new(1),
                pinned_nodes: Vec::new(),
            };
            (genesis.stored(), 0)
        } else {
            // Journal positions count witnesses; the cap counts database operations.
            let mut end = bounds.end;
            if let Some(cap) = max_size {
                let mut start = bounds.start;
                while start < end {
                    let mid = start + (end - start) / 2;
                    if pending.read(mid).await?.size <= cap {
                        start = mid + 1;
                    } else {
                        end = mid;
                    }
                }
                if end == bounds.start {
                    return Err(Error::HistoricalFloorPruned(cap));
                }
            }
            (pending.read(end - 1).await?, end)
        };
        // Decode and validate only the selected witness, before discarding newer history or
        // publishing a writer.
        let Rebuilt { merkle, tip } =
            witness::rebuild::<F, O, H, S>(cfg.strategy, entry, &codec_cfg)?;
        let mut journal = pending.finish(end).await?;
        if fresh {
            (journal, _) = journal.append(&tip.witness.stored()).await?;
            journal = journal.sync().await?;
        }
        Ok(Self {
            merkle,
            storage: Storage::Open(OpenJournal {
                journal,
                tip_state: TipState::Committed,
                pending_sync: None,
            }),
            tip,
        })
    }

    /// Build a compact db from state fetched by the sync engine: `last_commit_op` must be a
    /// commit whose floor is at or below `last_commit_loc`, and must decode under `cfg`'s codec
    /// config (otherwise [`Error::Journal`]).
    ///
    /// The imported witness lives only in memory, and the partition `cfg` names is not opened,
    /// until the first [`Self::apply_batch`], [`Self::commit`], [`Self::sync`],
    /// [`Self::start_sync`], or [`Self::prune`] replaces the partition's contents with it. The
    /// replacement stages a durable reset before removing anything, so a crash before that point
    /// reopens the previous contents. After it, a reopen recovers any complete witness that
    /// survived the crash, and otherwise fails with [`Error::DataCorrupted`] until a re-sync
    /// replaces the partition.
    pub(crate) fn init_from_sync(
        strategy: S,
        context: E,
        cfg: variable::Config<O::Cfg>,
        last_commit_loc: Location<F>,
        pinned_nodes: Vec<H::Digest>,
        last_commit_op: O,
    ) -> Result<Self, Error<F>> {
        // Reject a commit this db could not decode on reopen, before anything replaces the
        // destination's contents.
        let (cfg, codec_cfg) = witness::split_config(cfg);
        O::decode_cfg(last_commit_op.encode(), &codec_cfg)
            .map_err(|err| Error::Journal(crate::journal::Error::Codec(err)))?;
        let imported = Witness {
            commit: last_commit_op,
            size: last_commit_loc + 1,
            pinned_nodes,
        };
        let Rebuilt { merkle, tip } = witness::restore::<F, O, H, S>(strategy, imported)?;
        Ok(Self {
            merkle,
            storage: Storage::Replacing(Box::new(Destination { context, cfg })),
            tip,
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
            operations: Arc::new(Vec::new()),
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
    ///   [`crate::qmdb::chain`] for more details).
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
        // Only a [`Self::to_batch`] snapshot has no operations, and it leaves the Merkle
        // unchanged. Any other batch ends with its commit.
        debug_assert_eq!(
            batch.operations.is_empty(),
            self.tip.size() == self.merkle.leaves()
        );
        let tip = match batch.operations.last() {
            None => None,
            // Build before pruning because the commit proof needs the unpruned Merkle.
            Some(commit) => Some(witness::build_witness::<F, O, H, S>(
                &self.merkle,
                commit.clone(),
                batch.bounds.inactivity_floor,
            )?),
        };
        // Journal the import before the new witness so every applied state has its own entry.
        let mut open = self.storage.open(&self.tip.witness).await?;
        if let Some(tip) = tip {
            self.tip = tip;
            self.merkle.prune_to_frontier();
            open = open.append(&self.tip.witness).await?;
        }
        self.storage = Storage::Open(open);
        assert_eq!(self.commitment(), batch.bounds.tip);
        Ok((self, start_loc..batch.bounds.tip.size))
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
        // Journal a pending import before starting the sync so the returned handle covers the
        // current tip. A later apply remains uncommitted and requires a successor durability
        // operation.
        let mut open = self.storage.open(&self.tip.witness).await?;

        // Match the deferred-failure convention used by the journal: return a prior completion's
        // error through a ready handle before a later completion can replace it. Errors while
        // journaling an import or initiating this sync continue to use the outer result.
        if let Err(err) = open.wait_for_sync().await {
            self.storage = Storage::Open(open);
            return Ok((self, Handle::ready(Err(err))));
        }

        // Share one completion between the caller and the db. Retaining a clone keeps a
        // dropped handle's failure observable by the next durability operation.
        let handle;
        (open.journal, handle) = open.journal.start_sync().await?;
        let completion: SyncCompletion = handle.boxed().shared();
        open.tip_state = TipState::Committed;
        open.pending_sync = Some(completion.clone());
        self.storage = Storage::Open(open);
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
        let mut open = self.storage.open(&self.tip.witness).await?;
        open.wait_for_sync().await?;
        if open.tip_state == TipState::Uncommitted {
            open.journal = open.journal.commit().await?;
            open.tip_state = TipState::Committed;
        }
        self.storage = Storage::Open(open);
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
        let open = self.storage.open(&self.tip.witness).await?;
        self.storage = Storage::Open(open.sync().await?);
        Ok(self)
    }

    /// Drop witnesses for commits with fewer than `pruning_boundary` operations. Some witness
    /// below the boundary may survive.
    ///
    /// Pruning bounds how far back bounded initialization can reach; the current commit's witness
    /// always survives. A pending compact-sync import is journaled first. The prune is made
    /// durable before this method returns.
    #[tracing::instrument(
        name = "qmdb.compact.db.prune",
        level = "info",
        skip_all,
        fields(kind = O::NAME)
    )]
    pub async fn prune(mut self, pruning_boundary: Location<F>) -> Result<Self, Error<F>> {
        let mut open = self.storage.open(&self.tip.witness).await?;

        let bounds = open.journal.bounds();
        if bounds.is_empty() {
            self.storage = Storage::Open(open);
            return Ok(self);
        }
        // Clamp below the tip so the journal never empties: the tip is the current state.
        let pos = open
            .first_at_or_above(pruning_boundary)
            .await?
            .min(bounds.end - 1);
        (open.journal, _) = open.journal.prune(pos).await?;
        self.storage = Storage::Open(open.sync().await?);
        Ok(self)
    }

    /// Destroy all persisted state associated with this database.
    #[boxed]
    pub async fn destroy(self) -> Result<(), Error<F>> {
        let journal = match self.storage {
            Storage::Open(open) => open.journal,
            // Reset rather than open, so the previous contents are never decoded.
            Storage::Replacing(destination) => {
                let Destination { context, cfg } = *destination;
                witness::Journal::init_at_size(context, cfg, 0).await?
            }
        };
        journal.destroy().await?;
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
        let proof = self.tip.proof.clone();
        Ok(match request {
            Request::Operations { .. } => Response::Operations {
                proof,
                operations: vec![op],
            },
            Request::Boundary { .. } => Response::Boundary {
                proof,
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

    /// Resolve pending mutations into operations, merkleize, and return the batch.
    ///
    /// `inactivity_floor` goes into the commit operation so the root matches the full db's. It
    /// must be at least the db's current floor and at most the batch's commit location
    /// (`total_size - 1`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleBatch`] if `db` does not match this batch's database boundary or a
    /// live ancestor commitment (both size and root).
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
    ) -> MerkleizeResult<F, H::Digest, O, S>
    where
        E: Context,
    {
        let live_ancestors: Vec<_> =
            chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors())
                .collect();
        let boundary = chain::effective_boundary(
            self.db(),
            live_ancestors.last().map(|oldest| oldest.bounds.base),
        );

        let ancestors = chain::collect_ancestor_bounds(
            live_ancestors.iter().cloned(),
            |batch| batch.bounds.inactivity_floor,
            |batch| batch.commitment(),
        );
        chain::validate_batch_applicable(
            db.commitment(),
            boundary,
            ancestors.iter().map(|ancestor| ancestor.state),
        )?;

        let mutations = self.mutations.into_iter().map(O::mutation);
        let mut ops = Vec::with_capacity(mutations.len() + 1);
        ops.extend(mutations);
        ops.push(O::commit(metadata, inactivity_floor));

        let operations = Arc::new(ops);
        let total_size = self.base.size + operations.len() as u64;
        let inactive_peaks = F::inactive_peaks(total_size, inactivity_floor);
        let (merkle, root) = compact_batch::merkleize_ops::<F, H, S, _>(
            &db.merkle,
            self.merkle_batch,
            Arc::clone(&operations),
            inactive_peaks,
        )
        .await
        .expect("inactive_peaks computed from batch size");

        // Keep ancestor batches alive until their operations and nodes have been captured.
        drop(live_ancestors);

        Ok(Arc::new(MerkleizedBatch {
            merkle_batch: merkle,
            operations,
            parent: self.parent.as_ref().map(Arc::downgrade),
            bounds: Bounds {
                base: self.base,
                db: boundary,
                tip: Commitment::new(total_size, root),
                ancestors,
                inactivity_floor,
            },
        }))
    }
}

/// A speculative batch whose root digest has been computed.
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, O: Operation<F>, S: Strategy> {
    merkle_batch: Arc<batch::MerkleizedBatch<F, D, S>>,
    operations: Arc<Vec<O>>,
    parent: Option<Weak<Self>>,
    bounds: Bounds<F, D>,
}

impl<F: Family, D: Digest, O: Operation<F>, S: Strategy> MerkleizedBatch<F, D, O, S> {
    fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, O, S> {
        chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
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

    /// Return the operations this batch appends to the log and the location of the first.
    pub fn operations(&self) -> (Location<F>, Arc<Vec<O>>) {
        (self.bounds.base.size, Arc::clone(&self.operations))
    }

    /// Inclusion proof for the operations returned by [`Self::operations`], anchored at
    /// this batch's tip. The pair verifies against [`Self::root`] via
    /// [`crate::qmdb::verify_proof`]. Together with [`Self::pinned_nodes`] they verify via
    /// [`crate::qmdb::verify_proof_and_pinned_nodes`].
    ///
    /// Nodes of unapplied ancestors are read through the chain, so those ancestors must still be
    /// alive. Nodes below the chain are read from `db`'s
    /// [Merkle store][crate::merkle::mem::Mem], which retains them at least until this batch's
    /// changes are applied (applying it or a descendant prunes the store to its frontier).
    ///
    /// # Errors
    ///
    /// Returns [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or
    /// belongs to a dropped unapplied ancestor, and [`crate::merkle::Error::Empty`] if the batch
    /// has no operations (a [`Db::to_batch`] snapshot).
    pub fn proof<E, H>(&self, db: &Db<F, E, O, H, S>) -> Result<Proof<F, D>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
    {
        let inactive_peaks = F::inactive_peaks(self.bounds.tip.size, self.bounds.inactivity_floor);
        let hasher = qmdb::hasher::<H>();
        self.merkle_batch
            .range_proof(
                db.merkle.mem(),
                &hasher,
                self.bounds.base.size..self.bounds.tip.size,
                inactive_peaks,
            )
            .map_err(Into::into)
    }

    /// The Merkle frontier at the first operation returned by [`Self::operations`]
    /// ([`Family::nodes_to_pin`]), which lets a consumer holding only this batch's base rebuild
    /// compact state and replay the operations. The operations, [`Self::proof`], and pinned
    /// nodes verify against [`Self::root`] via [`crate::qmdb::verify_proof_and_pinned_nodes`].
    ///
    /// Nodes of unapplied ancestors are read through the chain, so those ancestors must still be
    /// alive. Nodes below the chain are read from `db`'s
    /// [Merkle store][crate::merkle::mem::Mem], which retains them at least until this batch's
    /// changes are applied (applying it or a descendant prunes the store to its frontier).
    ///
    /// # Errors
    ///
    /// Returns [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or
    /// belongs to a dropped unapplied ancestor.
    pub fn pinned_nodes<E, H>(&self, db: &Db<F, E, O, H, S>) -> Result<Vec<D>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
    {
        let base = db.merkle.mem();
        F::nodes_to_pin(self.bounds.base.size)
            .map(|pos| {
                self.merkle_batch
                    .get_node(pos)
                    .or_else(|| base.get_node(pos))
                    .ok_or(merkle::Error::ElementPruned(pos))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Create a new speculative batch with this one as its parent.
    ///
    /// All unapplied ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Otherwise, `merkleize` returns [`Error::StaleBatch`].
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

    async fn serve(&self, request: Request<F>) -> source::Result<Self> {
        Ok((self.compact_state(request)?, None))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        journal::contiguous::{fixed, variable::Config as JournalConfig},
        metadata::{Config as MetadataConfig, Metadata},
        qmdb::{compact::witness, verify_proof, verify_proof_and_pinned_nodes},
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Blob as _, BufferPooler, Runner as _, Spawner as _, Storage as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, fail_pending_syncs},
        reschedule,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, Probability, probability, sequence::VecU64};
    use core::future::Future;
    use std::num::{NonZeroU16, NonZeroUsize};

    /// An operation type under test: its values and mutations derive from a seed.
    pub(crate) trait TestOperation:
        Operation<Self::Family, Metadata: PartialEq + std::fmt::Debug>
    {
        /// The Merkle family used by the operation.
        type Family: Family;

        /// The codec config the witness journal decodes commits with.
        fn codec_config() -> Self::Cfg;

        /// The value (and commit metadata) for `seed`.
        fn value(seed: u64) -> Self::Metadata;

        /// Add the one mutation derived from `seed` to `batch`.
        fn mutate(batch: TestBatch<Self>, seed: u64) -> TestBatch<Self>;

        /// The operation [`Self::mutate`] adds for `seed`.
        fn op(seed: u64) -> Self;
    }

    pub(crate) type TestDb<O> =
        Db<<O as TestOperation>::Family, deterministic::Context, O, Sha256, Sequential>;
    pub(crate) type TestBatch<O> =
        UnmerkleizedBatch<<O as TestOperation>::Family, Sha256, O, Sequential>;

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

    fn witness_config<O: TestOperation>(
        partition: &str,
        pooler: &impl BufferPooler,
    ) -> JournalConfig<O::Cfg> {
        JournalConfig {
            partition: format!("{partition}-witness"),
            items_per_section: NZU64!(64),
            compression: None,
            codec_config: O::codec_config(),
            page_cache: CacheRef::from_pooler(pooler, WITNESS_PAGE_SIZE, WITNESS_PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        }
    }

    pub(crate) async fn open_db<O: TestOperation>(
        context: deterministic::Context,
        partition: &str,
    ) -> TestDb<O> {
        let cfg = Config {
            strategy: Sequential,
            witness: witness_config::<O>(partition, &context),
        };
        Db::init(context, cfg, None).await.unwrap()
    }

    async fn open_bounded<O: TestOperation>(
        context: deterministic::Context,
        witness: JournalConfig<O::Cfg>,
        cap: Location<O::Family>,
    ) -> Result<TestDb<O>, Error<O::Family>> {
        Db::init(
            context,
            Config {
                strategy: Sequential,
                witness,
            },
            Some(cap),
        )
        .await
    }

    /// The number of witnesses `db`'s journal holds.
    fn witness_entries<O: TestOperation>(db: &TestDb<O>) -> u64 {
        let Storage::Open(open) = &db.storage else {
            panic!("a pending import has no journal");
        };
        let bounds = open.journal.bounds();
        bounds.end - bounds.start
    }

    /// Open the witness journal for `partition`; `open_db` and the tip-corrupting tests share it.
    async fn open_witness_journal<O: TestOperation>(
        context: deterministic::Context,
        partition: &str,
    ) -> witness::Journal<deterministic::Context, O::Family, Digest> {
        let (cfg, _) = witness::split_config(witness_config::<O>(partition, &context));
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
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let n = db.target().size;
            let boundary = |size: Location<O::Family>, start: Location<O::Family>| {
                Request::Boundary { size, start }
            };
            let operations =
                |size: Location<O::Family>, start: Location<O::Family>| Request::Operations {
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
    type DelayedDb<O> = Db<
        <O as TestOperation>::Family,
        DelayedSyncContext<deterministic::Context>,
        O,
        Sha256,
        Sequential,
    >;

    /// Open a [DelayedDb] whose blob syncs park on `pending`.
    ///
    /// Init durably persists the bootstrap witness, so while syncs park the returned future
    /// must be driven with [drive_pending_syncs] (or the mock unblocked first).
    fn open_delayed_db<O: TestOperation>(
        context: &deterministic::Context,
        label: &'static str,
        partition: &str,
        pending: &PendingSyncs,
    ) -> impl Future<Output = Result<DelayedDb<O>, Error<O::Family>>> {
        let witness_cfg = witness_config::<O>(partition, context);
        let context = DelayedSyncContext {
            inner: context.child(label),
            pending: pending.clone(),
        };
        async move {
            let cfg = Config {
                strategy: Sequential,
                witness: witness_cfg,
            };
            DelayedDb::<O>::init(context, cfg, None).await
        }
    }

    /// Apply a batch holding the one mutation for `seed`, with `seed`'s value as metadata.
    async fn apply<O: TestOperation>(db: DelayedDb<O>, seed: u64) -> DelayedDb<O> {
        let floor = db.inactivity_floor_loc();
        let batch = db
            .new_batch()
            .mutate(seed)
            .merkleize(&db, Some(O::value(seed)), floor)
            .await
            .unwrap();
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

            // The witness entry was already appended, so this commit has nothing to journal.
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

            // The db retains the dropped handle's completion. Deferred failures stay on the
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

    /// Once a start_sync handle completes successfully, a commit touches no storage.
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
            assert_eq!(
                pending.starts(),
                starts_before,
                "a proven pipelined sync still triggered journal work"
            );
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
                .await
                .unwrap();
            let batch_b = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await
                .unwrap();

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

            let a = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, floor)
                .await
                .unwrap();
            let b = a
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, None, floor)
                .await
                .unwrap();
            let c = b.new_batch::<Sha256>().mutate(3);

            let (db, _) = db.apply_batch(a).await.unwrap();
            let c = c.merkleize(&db, None, floor).await.unwrap();
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
                .await
                .unwrap();
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

    /// Applying a snapshot journals nothing, however often it is applied, while a batch with no
    /// mutations still appends its commit and a witness.
    pub(crate) fn test_compact_apply_snapshot_appends_no_witness<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-apply-snapshot").await;
            let (db, _) = apply_seed::<O>(db, 1).await;
            let mut db = db.sync().await.unwrap();
            let target = db.target();
            let entries = witness_entries(&db);

            for _ in 0..2 {
                let snapshot = db.to_batch();
                let (applied, range) = db.apply_batch(snapshot).await.unwrap();
                db = applied;
                assert_eq!(range, target.size..target.size);
                assert_eq!(db.target(), target);
                assert_eq!(witness_entries(&db), entries);
            }

            let floor = db.inactivity_floor_loc();
            let batch = db.new_batch().merkleize(&db, None, floor).await.unwrap();
            let (db, range) = db.apply_batch(batch).await.unwrap();
            assert_eq!(range, target.size..target.size + 1);
            assert_eq!(db.size(), target.size + 1);
            assert_eq!(db.get_metadata(), None);
            assert_eq!(witness_entries(&db), entries + 1);
            db.destroy().await.unwrap();
        });
    }

    /// Applying a snapshot of a pending import journals only the import.
    pub(crate) fn test_compact_apply_snapshot_journals_import<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let dst = "compact-apply-snapshot-import-dst";
            let import =
                Import::<O>::build(context.child("src"), "compact-apply-snapshot-import-src", 2)
                    .await;
            commit_seed::<O>(context.child("seed"), dst, 1).await;
            let imported = import.clone().into_db(context.child("import"), dst);
            let snapshot = imported.to_batch();
            let (db, range) = imported.apply_batch(snapshot).await.unwrap();
            assert_eq!(range, import.target.size..import.target.size);
            assert_eq!(witness_entries(&db), 1);
            drop(db.sync().await.unwrap());

            let db = open_db::<O>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), import.target);
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
                .await
                .unwrap();
            let sibling_a = common_parent
                .new_batch::<Sha256>()
                .mutate(11)
                .merkleize(&db, Some(O::value(111)), floor)
                .await
                .unwrap();
            let sibling_b = common_parent
                .new_batch::<Sha256>()
                .mutate(12)
                .merkleize(&db, Some(O::value(112)), floor)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(sibling_a).await.unwrap();
            assert!(matches!(
                db.validate_batch(&sibling_b),
                Err(Error::StaleBatch)
            ));

            let parent_a = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), floor)
                .await
                .unwrap();
            let parent_b = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await
                .unwrap();
            let child_b = parent_b
                .new_batch::<Sha256>()
                .mutate(3)
                .merkleize(&db, Some(O::value(33)), floor)
                .await
                .unwrap();

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
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await
                .unwrap();

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
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, Some(O::value(22)), floor)
                .await
                .unwrap();
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
            let advance_floor = advance_floor
                .merkleize(&db, None, Location::new(1))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(advance_floor).await.unwrap();
            let db = db.sync().await.unwrap();
            let target = db.target();

            let regressed = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();

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
                .await
                .unwrap();
            // child: one op + commit at loc 4 with floor=1 (regressed from parent's floor=2).
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, None, Location::new(1))
                .await
                .unwrap();

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

    pub(crate) fn test_compact_bounded_initialization_restores_commit_metadata_and_floor<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-bounded-meta").await;

            let meta1 = O::value(11);
            let floor1 = Location::new(0);
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(meta1.clone()), floor1)
                .await
                .unwrap();
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
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            assert_eq!(db.get_metadata(), Some(meta2));
            assert_eq!(db.inactivity_floor_loc(), floor2);

            let db = {
                _ = db.sync().await.unwrap();
                open_bounded::<O>(
                    context.child("cap"),
                    witness_config::<O>("compact-bounded-meta", &context),
                    size_after_first,
                )
                .await
            }
            .unwrap();
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.get_metadata(), Some(meta1));
            assert_eq!(db.inactivity_floor_loc(), floor1);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_bounded_initialization_persists_across_reopen<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-bounded-reopen";
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
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();
                let root = db.root();
                let size_after_first = db.size();

                let batch = db
                    .new_batch()
                    .mutate(2)
                    .merkleize(&db, Some(meta2), floor2)
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();

                let _db = {
                    _ = db.sync().await.unwrap();
                    open_bounded::<O>(
                        context.child("cap"),
                        witness_config::<O>(partition, &context),
                        size_after_first,
                    )
                    .await
                }
                .unwrap();
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
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = db
                    .new_batch()
                    .mutate(2)
                    .merkleize(&db, Some(meta2.clone()), Location::new(1))
                    .await
                    .unwrap();
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

    pub(crate) fn test_compact_bounded_initialization_to_committed_entry_after_reopen<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-commit-bounded-reopen";
            let meta1 = O::value(11);
            let meta2 = O::value(22);

            let (root_a, size_a) = {
                let db = open_db::<O>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .mutate(1)
                    .merkleize(&db, Some(meta1.clone()), Location::new(0))
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();
                let root_a = db.root();
                let size_a = db.size();

                let batch = db
                    .new_batch()
                    .mutate(2)
                    .merkleize(&db, Some(meta2), Location::new(1))
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let _db = db.commit().await.unwrap();
                (root_a, size_a)
            };

            // Both committed witnesses survive the crash. Reopen recovers the tip, and the earlier
            // commit remains a valid initialization target.
            let db = open_db::<O>(context.child("second"), partition).await;
            let db = {
                _ = db.sync().await.unwrap();
                open_bounded::<O>(
                    context.child("cap"),
                    witness_config::<O>(partition, &context),
                    size_a,
                )
                .await
            }
            .unwrap();
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
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();
                // Sync must persist recovery metadata even when the data is already durable.
                let db = db.sync().await.unwrap();
                db.root()
            };

            // Check the watermark before reopening can rebuild the offsets journal.
            let metadata = Metadata::<_, u64, VecU64>::init(
                context.child("checkpoint"),
                MetadataConfig {
                    partition: format!("{partition}-witness_offsets-metadata"),
                    codec_config: (),
                },
            )
            .await
            .unwrap();
            // Key 3 records the durable prefix: the bootstrap witness and the applied batch.
            assert_eq!(metadata.get(&3).copied().map(u64::from), Some(2));
            drop(metadata);

            let db = open_db::<O>(context.child("second"), partition).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.get_metadata(), Some(meta));
            db.destroy().await.unwrap();
        });
    }

    /// A compact-sync import: a committed state and the pieces [`Db::init_from_sync`] takes.
    #[derive(Clone)]
    struct Import<O: TestOperation> {
        target: CompactTarget<O::Family, Digest>,
        pinned_nodes: Vec<Digest>,
        commit: O,
    }

    impl<O: TestOperation> Import<O> {
        /// Build the state holding `seed`'s mutation in partition `src` and fetch it the way a
        /// sync client would.
        async fn build(context: deterministic::Context, src: &str, seed: u64) -> Self {
            let target = commit_seed::<O>(context.child("build"), src, seed).await;
            let source = open_db::<O>(context.child("serve"), src).await;
            let (response, _) = source
                .serve(Request::Boundary {
                    size: target.size,
                    start: target.size - 1,
                })
                .await
                .unwrap();
            let Response::Boundary {
                op, pinned_nodes, ..
            } = response
            else {
                panic!("boundary request should get a boundary response");
            };
            Self {
                target,
                pinned_nodes,
                commit: op,
            }
        }

        /// Import this state over partition `dst` without journaling it.
        fn into_db(self, context: deterministic::Context, dst: &str) -> TestDb<O> {
            let cfg = witness_config::<O>(dst, &context);
            let db = TestDb::<O>::init_from_sync(
                Sequential,
                context,
                cfg,
                self.target.size - 1,
                self.pinned_nodes,
                self.commit,
            )
            .unwrap();
            assert_eq!(db.target(), self.target);
            db
        }
    }

    /// Durably commit `seed`'s mutation, with `seed`'s value as metadata, on top of the state in
    /// `partition`, returning the new target.
    async fn commit_seed<O: TestOperation>(
        context: deterministic::Context,
        partition: &str,
        seed: u64,
    ) -> CompactTarget<O::Family, Digest> {
        let db = open_db::<O>(context, partition).await;
        let floor = db.inactivity_floor_loc();
        let batch = db
            .new_batch()
            .mutate(seed)
            .merkleize(&db, Some(O::value(seed)), floor)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        db.sync().await.unwrap().target()
    }

    /// Apply `seed`'s mutation without making it durable, returning the db and its commitment.
    async fn apply_seed<O: TestOperation>(
        db: TestDb<O>,
        seed: u64,
    ) -> (TestDb<O>, Commitment<O::Family, Digest>) {
        let floor = db.inactivity_floor_loc();
        let batch = db
            .new_batch()
            .mutate(seed)
            .merkleize(&db, Some(O::value(seed)), floor)
            .await
            .unwrap();
        let tip = batch.bounds().tip;
        let (db, _) = db.apply_batch(batch).await.unwrap();
        (db, tip)
    }

    /// A durability operation that journals a pending import.
    #[derive(Clone, Copy)]
    enum Persist {
        Sync,
        Commit,
        StartSync,
        Prune,
    }

    /// Make `db` durable with `persist`, waiting for a pipelined sync to complete.
    async fn persist<O: TestOperation>(db: TestDb<O>, persist: Persist) -> TestDb<O> {
        match persist {
            Persist::Sync => db.sync().await.unwrap(),
            Persist::Commit => db.commit().await.unwrap(),
            Persist::StartSync => {
                let (db, handle) = db.start_sync().await.unwrap();
                handle.await.unwrap();
                db
            }
            Persist::Prune => {
                let size = db.size();
                db.prune(size).await.unwrap()
            }
        }
    }

    /// Each durability operation replaces the partition's previous contents with a pending
    /// import, and the import survives a crash once the operation completes.
    pub(crate) fn test_compact_import_persists<O: TestOperation>() {
        let dst = "compact-import-dst";
        for persist_with in [
            Persist::Sync,
            Persist::Commit,
            Persist::StartSync,
            Persist::Prune,
        ] {
            let (import, checkpoint) =
                deterministic::Runner::default().start_and_recover(|context| async move {
                    let import =
                        Import::<O>::build(context.child("src"), "compact-import-src", 2).await;
                    let seeded = commit_seed::<O>(context.child("seed"), dst, 1).await;
                    assert_ne!(seeded, import.target);
                    let db = import.clone().into_db(context.child("import"), dst);
                    let db = persist(db, persist_with).await;
                    assert_eq!(witness_entries(&db), 1);
                    drop(db);
                    import
                });
            deterministic::Runner::from(checkpoint).start(|context| async move {
                let db = open_db::<O>(context.child("reopen"), dst).await;
                assert_eq!(db.target(), import.target);
                assert_eq!(witness_entries(&db), 1);
                assert_eq!(db.get_metadata(), Some(O::value(2)));
                db.destroy().await.unwrap();
            });
        }
    }

    /// Applying a batch to an import-pending db journals the imported witness in place of the
    /// partition's previous contents before appending the new one.
    pub(crate) fn test_compact_import_then_apply_persists<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let dst = "compact-import-apply-dst";
            let import =
                Import::<O>::build(context.child("src"), "compact-import-apply-src", 2).await;

            // Seed the destination partition with a different committed state of the same size.
            let seeded = commit_seed::<O>(context.child("seed"), dst, 1).await;
            assert_eq!(seeded.size, import.target.size);
            assert_ne!(seeded, import.target);

            // Import over the destination and apply a batch on top of it with no durability
            // operation in between.
            let imported = import.clone().into_db(context.child("import"), dst);
            let floor = imported.inactivity_floor_loc();
            let batch = imported
                .new_batch()
                .mutate(3)
                .merkleize(&imported, Some(O::value(3)), floor)
                .await
                .unwrap();
            let root = batch.root();
            let (applied, _) = imported.apply_batch(batch).await.unwrap();
            assert_eq!(applied.root(), root);
            assert_eq!(witness_entries(&applied), 2);
            let target = applied.target();
            drop(applied.sync().await.unwrap());

            // Reopen lands on the applied state, and the retained history below it is the
            // import, not the seeded state.
            let db = open_db::<O>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), target);
            assert_eq!(db.get_metadata(), Some(O::value(3)));
            drop(db);
            let db = open_bounded::<O>(
                context.child("imported"),
                witness_config::<O>(dst, &context),
                import.target.size,
            )
            .await
            .unwrap();
            assert_eq!(db.target(), import.target);
            assert_eq!(db.get_metadata(), Some(O::value(2)));
            db.destroy().await.unwrap();
        });
    }

    /// Seed `partition` with a witness frame the journal cannot decode, above the recovery
    /// watermark so that opening the journal decodes it.
    async fn seed_unreadable<O: TestOperation>(context: deterministic::Context, partition: &str) {
        let (cfg, _) = witness::split_config(witness_config::<O>(partition, &context));
        let journal = variable::Journal::<_, [u8; 1]>::init(context.child("write"), cfg.clone())
            .await
            .unwrap();
        let (journal, _) = journal.append(&[0xff]).await.unwrap();
        drop(journal.commit().await.unwrap());
        assert!(
            witness::Journal::<_, O::Family, Digest>::init(context.child("probe"), cfg)
                .await
                .is_err()
        );
    }

    /// Whether `partition` holds no blobs.
    async fn partition_is_empty(context: &deterministic::Context, partition: &str) -> bool {
        match context.scan(partition).await {
            Ok(blobs) => blobs.is_empty(),
            Err(commonware_runtime::Error::PartitionMissing(_)) => true,
            Err(err) => panic!("unexpected scan error: {err:?}"),
        }
    }

    /// A pending import replaces, and its destroy removes, a destination the witness journal
    /// cannot decode.
    pub(crate) fn test_compact_import_over_unreadable_destination<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let import =
                Import::<O>::build(context.child("src"), "compact-import-unreadable-src", 2).await;

            let dst = "compact-import-unreadable-dst";
            seed_unreadable::<O>(context.child("seed"), dst).await;
            let db = import.clone().into_db(context.child("import"), dst);
            drop(db.sync().await.unwrap());
            let db = open_db::<O>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), import.target);
            assert_eq!(witness_entries(&db), 1);
            db.destroy().await.unwrap();

            let dst = "compact-import-unreadable-destroy";
            seed_unreadable::<O>(context.child("seed_destroy"), dst).await;
            let db = import.into_db(context.child("import_destroy"), dst);
            db.destroy().await.unwrap();
            let partition = witness_config::<O>(dst, &context).partition;
            assert!(partition_is_empty(&context, &format!("{partition}_data")).await);
            let db = open_db::<O>(context.child("fresh"), dst).await;
            assert_eq!(db.root(), initial_root::<O::Family, O, Sha256>());
            db.destroy().await.unwrap();
        });
    }

    /// Where a crash interrupts replacing a partition with a compact-sync import.
    #[derive(Clone, Copy)]
    enum ImportCrash {
        /// The import is built but nothing is written.
        BeforeReplacement,
        /// The reset is durable, but the imported and applied witnesses are not.
        AfterReset,
        /// The imported and applied witnesses are written but their sync fails. The device keeps
        /// a prefix of the unsynced bytes, extending byte by byte with the given percent
        /// probability.
        DuringAppend(u64),
        /// The durability operation completed.
        AfterDurability,
    }

    /// What reopening after an [`ImportCrash`] finds.
    #[derive(Debug, PartialEq, Eq)]
    enum Reopened {
        /// The seeded state.
        Seeded,
        /// The import's state.
        Imported,
        /// The state applied on top of the import.
        Applied,
        /// An empty journal past genesis: an interrupted import.
        NoTip,
    }

    /// Crash while replacing a seeded partition with an import, reopen, then re-sync.
    ///
    /// Returns what the reopen found. Every crash point reopens as a retained state or an
    /// interrupted import, never as a fresh db, and a re-sync then completes.
    fn crash_import<O: TestOperation>(crash: ImportCrash, seed: u64) -> Reopened {
        let dst = "compact-import-crash-dst";
        let cfg = deterministic::Config::new().with_seed(seed);
        let ((import, seeded, applied), checkpoint) = deterministic::Runner::new(cfg)
            .start_and_recover(|context| async move {
                let import =
                    Import::<O>::build(context.child("src"), "compact-import-crash-src", 2).await;
                let seeded = commit_seed::<O>(context.child("seed"), dst, 1).await;
                let db = import.clone().into_db(context.child("import"), dst);
                let mut applied = None;
                match crash {
                    ImportCrash::BeforeReplacement => drop(db),
                    ImportCrash::AfterReset => {
                        let (db, _) = apply_seed::<O>(db, 3).await;
                        drop(db);
                    }
                    ImportCrash::DuringAppend(percent) => {
                        // Retain unsynced writes from the start: the journal may write full
                        // pages before it is asked to sync them.
                        let write_rate = Some(deterministic::WriteConfig {
                            failure_rate: probability!(0.0),
                            retention_rate: Probability::new(percent, 100).unwrap(),
                            mode: deterministic::PartialWriteMode::Prefix,
                        });
                        *context.storage_fault_config().write() = deterministic::FaultConfig {
                            write_rate,
                            ..Default::default()
                        };
                        let (db, tip) = apply_seed::<O>(db, 3).await;
                        applied = Some(tip);
                        *context.storage_fault_config().write() = deterministic::FaultConfig {
                            sync_rate: Some(probability!(1.0)),
                            write_rate,
                            ..Default::default()
                        };
                        assert!(db.commit().await.is_err());
                    }
                    ImportCrash::AfterDurability => drop(db.commit().await.unwrap()),
                }
                (import, seeded, applied)
            });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let reopened = match TestDb::<O>::init(
                context.child("reopen"),
                Config {
                    strategy: Sequential,
                    witness: witness_config::<O>(dst, &context),
                },
                None,
            )
            .await
            {
                Err(Error::DataCorrupted("witness journal has no tip")) => Reopened::NoTip,
                Err(err) => panic!("unexpected reopen error: {err:?}"),
                Ok(db) => {
                    let target = db.commitment();
                    drop(db);
                    if target == Commitment::new(seeded.size, seeded.root) {
                        Reopened::Seeded
                    } else if target == Commitment::new(import.target.size, import.target.root) {
                        Reopened::Imported
                    } else if Some(target) == applied {
                        Reopened::Applied
                    } else {
                        panic!("reopened an unexpected state at size {}", target.size);
                    }
                }
            };

            // A re-sync over whatever the crash left completes.
            let db = import.clone().into_db(context.child("resync"), dst);
            drop(db.sync().await.unwrap());
            let db = open_db::<O>(context.child("resynced"), dst).await;
            assert_eq!(db.target(), import.target);
            db.destroy().await.unwrap();
            reopened
        })
    }

    /// Recovery from a crash at each point of replacing a partition with an import.
    pub(crate) fn test_compact_import_crash_points<O: TestOperation>() {
        assert_eq!(
            crash_import::<O>(ImportCrash::BeforeReplacement, 0),
            Reopened::Seeded
        );
        assert_eq!(
            crash_import::<O>(ImportCrash::AfterReset, 0),
            Reopened::NoTip
        );
        assert_eq!(
            crash_import::<O>(ImportCrash::DuringAppend(0), 0),
            Reopened::NoTip
        );
        assert_eq!(
            crash_import::<O>(ImportCrash::DuringAppend(100), 0),
            Reopened::Applied
        );
        for seed in 0..8 {
            let reopened = crash_import::<O>(ImportCrash::DuringAppend(50), seed);
            assert_ne!(reopened, Reopened::Seeded);
        }
        assert_eq!(
            crash_import::<O>(ImportCrash::AfterDurability, 0),
            Reopened::Imported
        );
    }

    pub(crate) fn test_compact_reopen_rejects_tampered_witness<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-witness-tamper";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(7)
                .merkleize(&db, Some(O::value(11)), Location::new(1))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Corrupt the entry structurally. An extra pinned node cannot rebuild the Merkle.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let mut entry = witness::tests::tip(&journal).await;
            entry.pinned_nodes.push(Sha256::fill(0xff));
            witness::tests::overwrite_tip(journal, entry).await;

            let cfg = Config {
                strategy: Sequential,
                witness: witness_config::<O>(partition, &context),
            };
            let reopened = TestDb::<O>::init(context.child("reopen_witness"), cfg, None).await;
            assert!(matches!(reopened, Err(Error::DataCorrupted(_))));
        });
    }

    pub(crate) fn test_compact_bounded_initialization_rejects_corrupt_target_entry<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-corrupt-bounded-target";
            let db = open_db::<O>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(1))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let initialization_bound = db.target().size;
            let batch = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(1))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let tip_target = db.target();
            drop(db);

            // Corrupt the initialization target's entry (the journal holds bootstrap, target, tip).
            let mut journal = open_witness_journal::<O>(context.child("corrupt"), partition).await;
            journal = witness::tests::corrupt_entry(journal, 1, |entry| {
                entry.pinned_nodes.push(Sha256::fill(0xff));
            })
            .await;
            drop(journal);

            // The tip entry is intact, so reopen succeeds.
            let cfg = Config {
                strategy: Sequential,
                witness: witness_config::<O>(partition, &context),
            };
            let reopened = TestDb::<O>::init(context.child("reopen"), cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.target(), tip_target);

            // The corrupt entry fails the recovery before any truncation.
            assert!(matches!(
                {
                    drop(reopened);
                    open_bounded::<O>(
                        context.child("cap"),
                        witness_config::<O>(partition, &context),
                        initialization_bound,
                    )
                    .await
                },
                Err(Error::DataCorrupted(_))
            ));

            // The newer history survives: reopen still lands on the original tip.
            let cfg = Config {
                strategy: Sequential,
                witness: witness_config::<O>(partition, &context),
            };
            let reopened = TestDb::<O>::init(context.child("reopen2"), cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.target(), tip_target);
            reopened.destroy().await.unwrap();
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
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);
            let oversized_floor = Location::new(10);

            // Overwrite the persisted commit op with a floor beyond its own commit location.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let mut entry = witness::tests::tip(&journal).await;
            entry.commit = O::commit(Some(O::value(11)), oversized_floor).encode();
            witness::tests::overwrite_tip(journal, entry).await;

            let cfg = Config {
                strategy: Sequential,
                witness: witness_config::<O>(partition, &context),
            };
            let reopened = TestDb::<O>::init(context.child("reopen_witness"), cfg, None).await;
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
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            drop(db.sync().await.unwrap());

            // Overwrite the persisted commit op with a mutation.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let mut entry = witness::tests::tip(&journal).await;
            entry.commit = O::op(7).encode();
            witness::tests::overwrite_tip(journal, entry).await;

            let cfg = Config {
                strategy: Sequential,
                witness: witness_config::<O>(partition, &context),
            };
            let reopened = TestDb::<O>::init(context.child("reopen_witness"), cfg, None).await;
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
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let tampered_target = db.target();
            drop(db);

            // Flip one pinned-node digest. There is no stored proof to cross-check against, so the
            // rebuild succeeds and yields a different root, the same way a bit-flipped replay
            // journal reopens with a different root.
            let journal = open_witness_journal::<O>(context.child("tamper"), partition).await;
            let mut entry = witness::tests::tip(&journal).await;
            entry.pinned_nodes[0] = Sha256::fill(0xff);
            witness::tests::overwrite_tip(journal, entry).await;

            let cfg = Config {
                strategy: Sequential,
                witness: witness_config::<O>(partition, &context),
            };
            let reopened = TestDb::<O>::init(context.child("reopen_witness"), cfg, None)
                .await
                .unwrap();
            assert_ne!(reopened.target(), tampered_target);
            reopened.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_bounded_initialization_preserves_current_state<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-bounded-noop").await;
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root = db.root();
            let size = db.size();

            let db = {
                _ = db.sync().await.unwrap();
                open_bounded::<O>(
                    context.child("cap"),
                    witness_config::<O>("compact-bounded-noop", &context),
                    size,
                )
                .await
            }
            .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.size(), size);
            db.destroy().await.unwrap();
        });
    }

    /// Merkleizing against a db other than the batch's own is stale, even at the same size.
    pub(crate) fn test_compact_merkleize_foreign_db<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-merkleize-foreign-db").await;
            let foreign = open_db::<O>(
                context.child("foreign"),
                "compact-merkleize-foreign-db-foreign",
            )
            .await;
            let (db, _) = apply_seed::<O>(db, 11).await;
            let (foreign, _) = apply_seed::<O>(foreign, 99).await;
            assert_eq!(db.size(), foreign.size());
            assert_ne!(db.root(), foreign.root());

            let batch = db.new_batch().mutate(22);
            assert!(matches!(
                batch.merkleize(&foreign, None, Location::new(0)).await,
                Err(Error::StaleBatch)
            ));

            let parent = db
                .new_batch()
                .mutate(33)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let child = parent.new_batch::<Sha256>().mutate(44);
            assert!(matches!(
                child.merkleize(&foreign, None, Location::new(0)).await,
                Err(Error::StaleBatch)
            ));
            db.destroy().await.unwrap();
            foreign.destroy().await.unwrap();
        });
    }

    /// A batch whose db advanced through a sibling is stale at merkleize, directly or through a
    /// parent.
    pub(crate) fn test_compact_merkleize_stale_sibling<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-merkleize-stale-sibling").await;

            let direct = db.new_batch().mutate(11);
            let sibling = db
                .new_batch()
                .mutate(22)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(sibling).await.unwrap();
            assert!(matches!(
                direct.merkleize(&db, None, Location::new(0)).await,
                Err(Error::StaleBatch)
            ));

            let parent = db
                .new_batch()
                .mutate(33)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let child = parent.new_batch::<Sha256>().mutate(44);
            let sibling = db
                .new_batch()
                .mutate(55)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(sibling).await.unwrap();
            assert!(matches!(
                child.merkleize(&db, None, Location::new(0)).await,
                Err(Error::StaleBatch)
            ));
            db.destroy().await.unwrap();
        });
    }

    /// A child merkleizes against any state its live chain passes through, and every such state
    /// yields the same root.
    pub(crate) fn test_compact_merkleize_ancestor_states<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-merkleize-ancestor-states").await;

            let grandparent = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let parent = grandparent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let pending = parent
                .new_batch::<Sha256>()
                .mutate(3)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();

            let (db, _) = db.apply_batch(Arc::clone(&grandparent)).await.unwrap();
            let applied = parent
                .new_batch::<Sha256>()
                .mutate(3)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            assert_eq!(pending.root(), applied.root());

            drop(grandparent);
            let retired = parent
                .new_batch::<Sha256>()
                .mutate(3)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            assert_eq!(retired.bounds().db, db.commitment());
            assert_eq!(pending.root(), retired.root());

            let child = parent.new_batch::<Sha256>().mutate(3);
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let child = child.merkleize(&db, None, Location::new(0)).await.unwrap();
            assert_eq!(pending.root(), child.root());
            let expected_root = child.root();
            let (db, _) = db.apply_batch(child).await.unwrap();
            assert_eq!(db.root(), expected_root);
            db.destroy().await.unwrap();
        });
    }

    /// Witness config holding one witness per section, so every commit occupies its own blobs.
    fn sectioned_witness_config<O: TestOperation>(
        partition: &str,
        pooler: &impl BufferPooler,
    ) -> JournalConfig<O::Cfg> {
        let mut cfg = witness_config::<O>(partition, pooler);
        cfg.items_per_section = NZU64!(1);
        cfg
    }

    /// Seed a db with the bootstrap witness plus `commits` synced metadata-only commits,
    /// returning the size and root after each commit. Every commit appends exactly its commit
    /// operation, so the witness at position `p` has size `p + 1`.
    async fn seed_witness_sections<O: TestOperation>(
        context: deterministic::Context,
        witness: JournalConfig<O::Cfg>,
        commits: u64,
    ) -> Vec<(Location<O::Family>, Digest)> {
        let cfg = Config {
            strategy: Sequential,
            witness,
        };
        let mut db = TestDb::<O>::init(context, cfg, None).await.unwrap();
        let mut states = Vec::new();
        for i in 1..=commits {
            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .merkleize(&db, Some(O::value(i)), floor)
                .await
                .unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.sync().await.unwrap();
            states.push((db.size(), db.root()));
        }
        states
    }

    /// Leave witness data blob `blob` with a partial trailing page, as a crash mid-write would.
    /// Paged tail recovery repairs (resizes and syncs) such a tail when the blob is opened.
    async fn tear_witness_data<C>(
        context: &deterministic::Context,
        witness: &JournalConfig<C>,
        blob: u64,
    ) {
        // The variable journal keeps data blobs in `{partition}_data`, named by the big-endian
        // section index.
        let partition = format!("{}_data", witness.partition);
        let (handle, len) = context.open(&partition, &blob.to_be_bytes()).await.unwrap();
        handle.resize(len - 1).await.unwrap();
        handle.sync().await.unwrap();
    }

    /// Bounded init through a delayed-sync backend, returning the db and the durability calls
    /// initialization made.
    async fn open_bounded_counting<O: TestOperation>(
        context: deterministic::Context,
        witness: JournalConfig<O::Cfg>,
        cap: Location<O::Family>,
    ) -> (DelayedDb<O>, usize) {
        // Arming counts every durability call from here on. The gate blocks the first call and
        // every later started sync parks. `drive_pending_syncs` releases them whenever
        // initialization stalls.
        let pending = PendingSyncs::default();
        pending.arm();
        let delayed = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };
        let cfg = Config {
            strategy: Sequential,
            witness,
        };
        let db = drive_pending_syncs(&pending, DelayedDb::<O>::init(delayed, cfg, Some(cap)))
            .await
            .unwrap();
        (db, pending.calls())
    }

    /// Bounded initialization opens no witness section the bound discards, so a torn tail there
    /// costs no repair.
    pub(crate) fn test_compact_bounded_initialization_ignores_discarded_witness_sections<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            // Build twin journals with one witness per section, so position `p` lives in data
            // blob `p`. Each holds the bootstrap witness (position 0, size 1), a synced commit
            // (position 1, size 2), and a commit without sync (position 2, size 3). The control
            // twin stays intact and sets the baseline durability count.
            let control_cfg =
                sectioned_witness_config::<O>("compact-skip-discarded-control", &context);
            let torn_cfg = sectioned_witness_config::<O>("compact-skip-discarded-torn", &context);
            let mut states = Vec::new();
            for (label, witness) in [("control", &control_cfg), ("torn", &torn_cfg)] {
                let context = context.child(label);
                states.push(
                    seed_witness_sections::<O>(context.child("seed"), witness.clone(), 1).await[0],
                );

                // Commit without syncing so the witness at position 2 lies above the recovery
                // watermark, where a torn tail is a crash shape rather than corruption.
                let cfg = Config {
                    strategy: Sequential,
                    witness: witness.clone(),
                };
                let db = TestDb::<O>::init(context.child("extend"), cfg, None)
                    .await
                    .unwrap();
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .merkleize(&db, Some(O::value(2)), floor)
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                drop(db.commit().await.unwrap());
            }

            // The twins share one history, so the synced commit's size and root are the expected
            // recovery for both.
            assert_eq!(states[0], states[1]);
            let (size, root) = states[0];

            // The witness at position 1 has size `size`, so the bound discards position 2 and
            // must not open it. Tear its data blob: repairing the tail would sync it.
            tear_witness_data(&context, &torn_cfg, 2).await;

            // Both twins recover the synced commit under the bound. They differ only in data
            // blob 2, so equal durability counts show the torn blob was not repaired.
            let (control, control_calls) =
                open_bounded_counting::<O>(context.child("control"), control_cfg, size).await;
            let (torn, torn_calls) =
                open_bounded_counting::<O>(context.child("torn"), torn_cfg, size).await;
            assert_eq!(control.size(), size);
            assert_eq!(control.root(), root);
            assert_eq!(torn.size(), size);
            assert_eq!(torn.root(), root);
            assert_eq!(
                torn_calls, control_calls,
                "the discarded torn section must not be repaired"
            );
            control.destroy().await.unwrap();
            torn.destroy().await.unwrap();
        });
    }

    /// A torn tail in a retained witness section is still repaired under a bound. The witness it
    /// held is lost and initialization falls back to the previous one.
    pub(crate) fn test_compact_bounded_initialization_repairs_retained_witness_section<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            // Both witnesses share a section, so the bootstrap witness survives the torn tail
            // page and ends mid-page, where recovery must rewrite rather than only shrink.
            let clean_cfg = witness_config::<O>("compact-repair-retained-clean", &context);
            let torn_cfg = witness_config::<O>("compact-repair-retained-torn", &context);
            let mut states = Vec::new();
            for (label, witness) in [("clean", &clean_cfg), ("torn", &torn_cfg)] {
                // Fresh storage bootstraps the witness at position 0 (size 1), the state the torn
                // twin falls back to.
                let cfg = Config {
                    strategy: Sequential,
                    witness: witness.clone(),
                };
                let db = TestDb::<O>::init(context.child(label), cfg, None)
                    .await
                    .unwrap();
                let genesis = db.root();

                // Commit without syncing so the witness at position 1 lies above the recovery
                // watermark, where a torn tail is a crash shape rather than corruption. Its 15
                // operations give it enough pinned nodes to run past the page where the bootstrap
                // witness ends.
                let floor = db.inactivity_floor_loc();
                let mut batch = db.new_batch();
                for seed in 1..=14 {
                    batch = batch.mutate(seed);
                }
                let batch = batch
                    .merkleize(&db, Some(O::value(1)), floor)
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();
                states.push((genesis, db.size(), db.root()));
            }
            assert_eq!(states[0], states[1]);
            let (genesis, size, root) = states[0];

            // The torn twin's last page in section 0 holds only the end of the witness at
            // position 1, so tearing it leaves that witness incomplete.
            tear_witness_data(&context, &torn_cfg, 0).await;

            // Section 0 lies below the bound, so both twins open it. The torn twin trims its
            // tail and republishes the journal without the lost witness.
            let (clean, clean_calls) =
                open_bounded_counting::<O>(context.child("clean"), clean_cfg, size).await;
            let (torn, torn_calls) =
                open_bounded_counting::<O>(context.child("torn"), torn_cfg, size).await;

            // The clean twin recovers the witness at position 1. The torn twin recovers the
            // bootstrap witness and spends extra durability calls on the repair.
            assert_eq!(clean.size(), size);
            assert_eq!(clean.root(), root);
            assert_eq!(torn.size(), Location::new(1));
            assert_eq!(torn.root(), genesis);
            assert!(
                torn_calls > clean_calls,
                "the retained torn section is repaired"
            );
            clean.destroy().await.unwrap();
            torn.destroy().await.unwrap();
        });
    }

    /// An imported state of size 1 lands at position 1, so afterwards each witness position
    /// equals its size. Bounded initialization still selects by size, widening its view when
    /// the positions below the bound cannot settle the selection.
    pub(crate) fn test_compact_bounded_initialization_after_genesis_import<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            // The destination has used positions 0 through 3.
            let dst_cfg = sectioned_witness_config::<O>("compact-genesis-import-dst", &context);
            seed_witness_sections::<O>(context.child("dst"), dst_cfg.clone(), 3).await;

            // Import the genesis state: one commit operation and no pinned nodes.
            let imported = TestDb::<O>::init_from_sync(
                Sequential,
                context.child("import"),
                dst_cfg.clone(),
                Location::new(0),
                Vec::new(),
                O::commit(None, Location::new(0)),
            )
            .unwrap();
            let genesis = imported.root();
            assert_eq!(genesis, initial_root::<O::Family, O, Sha256>());

            // Committing replaces the destination with the imported witness at position 1.
            drop(imported.commit().await.unwrap());
            let journal = witness::Journal::<_, O::Family, Digest>::init(
                context.child("placed"),
                witness::split_config(dst_cfg.clone()).0,
            )
            .await
            .unwrap();
            assert_eq!(journal.bounds(), 1..2);
            drop(journal);

            // Three more commits occupy positions 2 through 4 with sizes 2 through 4. `states`
            // holds the size and root at positions 1 through 4.
            let mut states = vec![(Location::new(1), genesis)];
            states.extend(
                seed_witness_sections::<O>(context.child("reopen"), dst_cfg.clone(), 3).await,
            );

            // Open at each recorded size from the tip down. Caps 4, 3, and 2 open a bounded view
            // of the positions below the cap, whose tip size is one below the cap, so recovery
            // widens and selects the witness at the cap's own position. Cap 1 lies at the
            // retained start, so recovery opens unbounded. Each open discards the witnesses above
            // its selection, so the caps must descend.
            for (size, root) in states.into_iter().rev() {
                let db = open_bounded::<O>(
                    context.child("bounded").with_attribute("cap", *size),
                    dst_cfg.clone(),
                    size,
                )
                .await
                .unwrap();
                assert_eq!(db.size(), size);
                assert_eq!(db.root(), root);
            }
        });
    }

    /// A bounded initialization whose selection fails leaves the witness offsets watermark
    /// acknowledging every synced witness.
    pub(crate) fn test_compact_failed_bounded_selection_preserves_acknowledged_offsets<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            let cap = Location::new(5);
            let witness = sectioned_witness_config::<O>("compact-failed-bounded-offsets", &context);

            // The offsets journal, whose checkpoint persists the recovery watermark, lives in
            // `{partition}_offsets`.
            let offsets_partition = format!("{}_offsets", witness.partition);
            let cfg = Config {
                strategy: Sequential,
                witness: witness.clone(),
            };
            let mut db = TestDb::<O>::init(context.child("seed"), cfg, None)
                .await
                .unwrap();

            // The first batch holds six mutations and a commit after the bootstrap commit, so the
            // witness at position 1 has size 8, above the cap used below.
            let mut batch = db.new_batch();
            for seed in 1..=6 {
                batch = batch.mutate(seed);
            }
            let batch = batch.merkleize(&db, None, Location::new(0)).await.unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.sync().await.unwrap();
            let first_retained_size = db.size();
            assert!(first_retained_size > cap);

            // Eight synced empty commits occupy positions 2 through 9 with sizes 9 through 16.
            // One witness per section puts positions 1 through 4 in the sections the cap-5 view
            // opens, and positions 5 through 9 in sections it discards.
            for _ in 0..8 {
                let floor = db.inactivity_floor_loc();
                let batch = db.new_batch().merkleize(&db, None, floor).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
            }
            let tip = db.size();

            // Pruning at the first commit removes the bootstrap section. The retained start
            // (position 1) lies below the cap while its size lies above it. A retained start at
            // or above the cap would open unbounded instead.
            drop(db.prune(first_retained_size).await.unwrap());

            // Sync acknowledged all ten witnesses (positions 0 through 9). The watermark lies above
            // the cap, so any lowering to the cap is visible below.
            let watermark = fixed::Journal::<_, u64>::persisted_watermark(
                context.child("before"),
                &offsets_partition,
            )
            .await
            .unwrap();
            assert_eq!(watermark, Some(10));

            // No retained witness fits under the cap, so selection fails.
            assert!(matches!(
                open_bounded::<O>(context.child("failed"), witness.clone(), cap).await,
                Err(Error::HistoricalFloorPruned(found)) if found == cap
            ));

            // Selection fails before publication, and inspection anchored at the ceiling skips the
            // offsets truncate, so the failed attempt leaves the durable watermark at 10.
            let watermark = fixed::Journal::<_, u64>::persisted_watermark(
                context.child("after"),
                &offsets_partition,
            )
            .await
            .unwrap();
            assert_eq!(watermark, Some(10));

            // A retry at the tip recovers every retained witness.
            let reopened = open_bounded::<O>(context.child("retry"), witness, tip)
                .await
                .unwrap();
            assert_eq!(reopened.size(), tip);
            reopened.destroy().await.unwrap();
        });
    }

    /// Pruning past the tip keeps only the tip, even when every witness fills its own section.
    pub(crate) fn test_compact_prune_past_tip_keeps_tip<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let mut witness = witness_config::<O>("compact-prune-past-tip", &context);
            witness.items_per_section = NZU64!(1);
            let cfg = Config {
                strategy: Sequential,
                witness,
            };
            let mut db = TestDb::<O>::init(context.child("db"), cfg.clone(), None)
                .await
                .unwrap();
            for seed in 1..=3 {
                (db, _) = apply_seed::<O>(db, seed).await;
                db = db.sync().await.unwrap();
            }
            let target = db.target();
            assert_eq!(witness_entries(&db), 4);

            let db = db.prune(target.size + 100).await.unwrap();
            assert_eq!(db.target(), target);
            assert_eq!(witness_entries(&db), 1);
            drop(db);

            let reopened = TestDb::<O>::init(context.child("reopen"), cfg, None)
                .await
                .unwrap();
            assert_eq!(reopened.target(), target);
            reopened.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_initialization_zero_and_above_end<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = witness_config::<O>("compact-caps", &context);
            assert!(matches!(
                open_bounded::<O>(context.child("zero"), cfg.clone(), Location::new(0)).await,
                Err(Error::InvalidInitializationBound)
            ));
            let db = open_bounded::<O>(context.child("fresh"), cfg.clone(), Location::new(100))
                .await
                .unwrap();
            let root = db.root();
            assert_eq!(db.size(), Location::new(1));
            drop(db);
            let db = open_bounded::<O>(context.child("above"), cfg, Location::new(100))
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.size(), Location::new(1));
        });
    }

    pub(crate) fn test_compact_bounded_initialization_between_commits<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-bounded-between").await;
            let floor = db.inactivity_floor_loc();
            let initial_root = db.root();

            // A multi-op commit jumps the committed size from 1 (bootstrap) to 4.
            let batch = db
                .new_batch()
                .mutate(1)
                .mutate(2)
                .merkleize(&db, Some(O::value(11)), floor)
                .await
                .unwrap();
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
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let cfg = witness_config::<O>("compact-bounded-between", &context);
            drop(db);
            for (target, size, root) in [(5, 4, root_a), (3, 1, initial_root), (2, 1, initial_root)]
            {
                let db =
                    open_bounded::<O>(context.child("cap"), cfg.clone(), Location::new(target))
                        .await
                        .unwrap();
                assert_eq!(db.size(), Location::new(size));
                assert_eq!(db.root(), root);
                drop(db);
                let db = open_db::<O>(context.child("restart"), "compact-bounded-between").await;
                assert_eq!(db.root(), root);
            }
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
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let target_a = db.target();
            drop(db);

            // Simulate the crash window: append an entry ahead of the tip without syncing it,
            // then drop the journal. The unsynced tail must not survive reopen.
            let journal = open_witness_journal::<O>(context.child("crash"), partition).await;
            let mut entry = witness::tests::tip(&journal).await;
            entry.size += 2;
            witness::tests::append_unsynced(journal, entry).await;

            // Reopen must drop the unsynced entry and recover state A.
            let reopened = open_db::<O>(context.child("reopen"), partition).await;
            assert_eq!(reopened.target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_bounded_initialization_multiple_commits<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-bounded-multi";
            let db = open_db::<O>(context.child("db"), partition).await;

            // Commit A, B, C, recording the state after A.
            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await
                .unwrap();
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
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
            }
            assert_ne!(db.root(), root_a);

            // Reopen two commits earlier.
            let db = {
                _ = db.sync().await.unwrap();
                open_bounded::<O>(
                    context.child("cap"),
                    witness_config::<O>(partition, &context),
                    size_a,
                )
                .await
            }
            .unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.size(), size_a);
            assert_eq!(db.get_metadata(), Some(O::value(11)));
            assert_eq!(db.target(), target_a);
            drop(db);

            // The recovery is durable: reopen recovers state A.
            let db = open_db::<O>(context.child("reopen"), partition).await;
            assert_eq!(db.root(), root_a);
            assert_eq!(db.target(), target_a);
            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_prune_then_bounded_initialization<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            // One entry per section so pruning takes effect at entry granularity (pruning is
            // section-aligned and never drops a partial section).
            let mut witness_cfg = witness_config::<O>("compact-prune-bounded", &context);
            witness_cfg.items_per_section = NZU64!(1);
            let cfg = Config {
                strategy: Sequential,
                witness: witness_cfg.clone(),
            };
            let mut db: TestDb<O> = Db::init(context.child("db"), cfg, None).await.unwrap();

            // Commit A, B, C.
            let mut sizes = Vec::new();
            for i in [1u64, 2, 3] {
                let batch = db
                    .new_batch()
                    .mutate(i)
                    .merkleize(&db, Some(O::value(i * 11)), Location::new(0))
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                sizes.push(db.size());
            }

            // Reopen retained state B before the terminal check that pruned state A is unavailable.
            let db = db.prune(sizes[1]).await.unwrap().sync().await.unwrap();
            drop(db);
            let db = open_bounded::<O>(context.child("retained"), witness_cfg.clone(), sizes[1])
                .await
                .unwrap();
            assert_eq!(db.size(), sizes[1]);
            assert_eq!(db.get_metadata(), Some(O::value(22)));
            drop(db);

            assert!(matches!(
                open_bounded::<O>(context.child("pruned"), witness_cfg, sizes[0]).await,
                Err(Error::HistoricalFloorPruned(_))
            ));
        });
    }

    pub(crate) fn test_compact_bounded_initialization_preserves_pre_advance_batch<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<O>(context.child("db"), "compact-bounded-preserves-pre-advance").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            // Merkleize a batch against the post-commit-A state.
            let held = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();

            // Advance past that state and commit, then reopen at that state.
            let batch = db
                .new_batch()
                .mutate(3)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let db = {
                _ = db.sync().await.unwrap();
                open_bounded::<O>(
                    context.child("cap"),
                    witness_config::<O>("compact-bounded-preserves-pre-advance", &context),
                    size_after_first,
                )
                .await
            }
            .unwrap();

            // The recovery restored the state that `held` was merkleized against, so it still
            // matches the Merkle size and applies cleanly.
            let (db, _) = db.apply_batch(held).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_noop_sync_after_sync<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-noop-after-sync").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .mutate(2)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await
                .unwrap();
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
                    .await
                    .unwrap();
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

    pub(crate) fn test_compact_noop_sync_after_bounded_initialization<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-noop-after-bounded").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .mutate(2)
                .merkleize(&db, Some(O::value(11)), Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();

            let batch = db
                .new_batch()
                .mutate(3)
                .merkleize(&db, Some(O::value(22)), Location::new(1))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();

            let db = {
                _ = db.sync().await.unwrap();
                open_bounded::<O>(
                    context.child("cap"),
                    witness_config::<O>("compact-noop-after-bounded", &context),
                    Location::new(4),
                )
                .await
            }
            .unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);

            db.destroy().await.unwrap();
        });
    }

    pub(crate) fn test_compact_bounded_initialization_makes_post_advance_batch_stale<
        O: TestOperation,
    >() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-bounded-makes-stale").await;

            let batch = db
                .new_batch()
                .mutate(1)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            let batch = db
                .new_batch()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();

            // Merkleize a batch against the post-commit-B state, which the recovery will discard.
            let held = db
                .new_batch()
                .mutate(3)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();

            let db = {
                _ = db.sync().await.unwrap();
                open_bounded::<O>(
                    context.child("cap"),
                    witness_config::<O>("compact-bounded-makes-stale", &context),
                    size_after_first,
                )
                .await
            }
            .unwrap();

            // After recovery, mem.size reflects post-commit-A, but the held batch starts after
            // post-commit-B. Apply must be rejected with StaleBatch.
            assert!(matches!(db.apply_batch(held).await, Err(Error::StaleBatch)));
        });
    }

    pub(crate) fn test_compact_floor_beyond_size<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-floor-beyond").await;

            let batch = db
                .new_batch()
                .merkleize(&db, None, Location::new(2))
                .await
                .unwrap();

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
                .await
                .unwrap();
            // child: valid on its own (floor=0), but parent's floor is bad.
            let child = parent
                .new_batch::<Sha256>()
                .mutate(2)
                .merkleize(&db, None, Location::new(0))
                .await
                .unwrap();

            assert!(matches!(
                db.apply_batch(child).await,
                Err(Error::FloorBeyondSize(floor, commit))
                    if floor == Location::new(3) && commit == Location::new(2)
            ));
        });
    }

    /// Batch artifacts (operations, range proof, pinned frontier) verify against the batch root,
    /// survive applying and dropping ancestors, and are refused once the batch itself is applied
    /// and the compact store is pruned past them.
    pub(crate) fn test_compact_operations_and_proof<O: TestOperation>() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<O>(context.child("db"), "compact-operations-and-proof").await;

            // Seed committed state so the chain below forks above a pruned frontier.
            let mut seed = db.new_batch();
            for value in 1..=6 {
                seed = seed.mutate(value);
            }
            let seed = seed
                .merkleize(&db, Some(O::value(7)), Location::new(0))
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.sync().await.unwrap();
            let floor = db.size();
            assert_eq!(floor, Location::new(8));

            // A snapshot batch has no operations to prove.
            assert!(matches!(
                db.to_batch().proof(&db),
                Err(Error::Merkle(merkle::Error::Empty))
            ));

            // A two-deep unapplied chain: the child's artifacts read the parent's nodes through
            // the live chain.
            let mut parent = db.new_batch();
            for value in 8..=12 {
                parent = parent.mutate(value);
            }
            let parent = parent
                .merkleize(&db, Some(O::value(13)), floor)
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .mutate(14)
                .merkleize(&db, Some(O::value(15)), floor)
                .await
                .unwrap();

            // The operation suffix is the batch's own mutations plus its commit, handed out
            // zero-copy.
            let (child_start, child_ops) = child.operations();
            let (_, child_ops_again) = child.operations();
            let child_end = child.bounds().tip.size;
            assert!(Arc::ptr_eq(&child_ops, &child_ops_again));
            assert_eq!(child_start, parent.bounds().tip.size);
            assert_eq!(*child_start + child_ops.len() as u64, *child_end);
            assert_eq!(child_end, Location::new(16));
            assert_eq!(child_ops.len(), 2);
            assert_eq!(child_ops[0].encode(), O::op(14).encode());
            assert_eq!(child_ops[1].metadata(), Some(&O::value(15)));
            assert_eq!(child_ops[1].has_floor(), Some(floor));

            // The proof is anchored at the batch tip and verifies with or without the pins.
            let child_root = child.root();
            let child_proof = child.proof(&db).unwrap();
            let child_pins = child.pinned_nodes(&db).unwrap();
            assert_eq!(child_proof.leaves, child_end);
            assert_eq!(
                child_proof.inactive_peaks,
                O::Family::inactive_peaks(child_end, floor),
            );
            assert!(verify_proof::<Sha256, _, _>(
                &child_proof,
                child_start,
                &child_ops,
                &child_root
            ));
            assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &child_proof,
                child_start,
                &child_ops,
                &child_pins,
                &child_root
            ));

            // The pins are order-sensitive.
            assert!(child_pins.len() > 1);
            let mut reordered_child_pins = child_pins.clone();
            reordered_child_pins.swap(0, 1);
            assert!(!verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &child_proof,
                child_start,
                &child_ops,
                &reordered_child_pins,
                &child_root
            ));

            // Pipelined consumer: applying the parent prunes the store to the parent's tip, which
            // is exactly the frontier the child's base pins, so the artifacts survive dropping the
            // parent.
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let child_proof_after = child.proof(&db).unwrap();
            assert_eq!(child.pinned_nodes(&db).unwrap(), child_pins);
            assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &child_proof_after,
                child_start,
                &child_ops,
                &child_pins,
                &child_root
            ));
            let (db, child_range) = db.apply_batch(child).await.unwrap();
            assert_eq!(child_range, child_start..child_end);

            // A commit-only batch proves exactly its commit operation.
            let commit_floor = db.size();
            let commit_only = db
                .new_batch()
                .merkleize(&db, Some(O::value(16)), commit_floor)
                .await
                .unwrap();
            let (commit_start, commit_ops) = commit_only.operations();
            let commit_end = commit_only.bounds().tip.size;
            let commit_root = commit_only.root();
            let commit_proof = commit_only.proof(&db).unwrap();
            let commit_pins = commit_only.pinned_nodes(&db).unwrap();
            assert_eq!(commit_start, commit_floor);
            assert_eq!(commit_ops.len(), 1);
            assert_eq!(commit_ops[0].metadata(), Some(&O::value(16)));
            assert_eq!(commit_ops[0].has_floor(), Some(commit_floor));
            assert_eq!(*commit_start + commit_ops.len() as u64, *commit_end);
            assert_eq!(commit_proof.leaves, commit_end);
            assert_eq!(
                commit_proof.inactive_peaks,
                O::Family::inactive_peaks(commit_end, commit_floor)
            );
            assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &commit_proof,
                commit_start,
                &commit_ops,
                &commit_pins,
                &commit_root
            ));
            let (db, commit_range) = db.apply_batch(commit_only).await.unwrap();
            assert_eq!(commit_range, commit_start..commit_end);
            let db = db.sync().await.unwrap();

            // Applying a batch that forked mid-mountain prunes its own artifacts. The accessors
            // refuse rather than returning a proof that fails to verify, while a child merkleized
            // before the apply still finds its base frontier in the store.
            let late_parent = db
                .new_batch()
                .mutate(17)
                .merkleize(&db, Some(O::value(18)), db.size())
                .await
                .unwrap();
            let late = late_parent
                .new_batch::<Sha256>()
                .mutate(19)
                .merkleize(&db, Some(O::value(20)), db.size())
                .await
                .unwrap();
            let (db, _) = db.apply_batch(Arc::clone(&late_parent)).await.unwrap();
            assert!(matches!(
                late_parent.proof(&db),
                Err(Error::Merkle(merkle::Error::ElementPruned(_)))
            ));
            assert!(matches!(
                late_parent.pinned_nodes(&db),
                Err(Error::Merkle(merkle::Error::ElementPruned(_)))
            ));
            drop(late_parent);

            let (late_start, late_ops) = late.operations();
            let late_root = late.root();
            let late_proof = late.proof(&db).unwrap();
            let late_pins = late.pinned_nodes(&db).unwrap();
            assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &late_proof,
                late_start,
                &late_ops,
                &late_pins,
                &late_root
            ));
            let (db, _) = db.apply_batch(late).await.unwrap();

            db.destroy().await.unwrap();
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
                test_compact_start_sync_metadata_failure_resurfaces_on_commit,
                test_compact_start_sync_retains_dropped_metadata_failure,
                test_compact_start_sync_proven_skips_journal,
                test_compact_stale_batch_rejected,
                test_compact_delayed_merkleize_after_ancestor_apply,
                test_compact_to_batch_reflects_live_state,
                test_compact_apply_snapshot_appends_no_witness,
                test_compact_apply_snapshot_journals_import,
                test_compact_stale_batch_chained,
                test_compact_stale_parent_after_child_applied,
                test_compact_sequential_commit_parent_then_child,
                test_compact_floor_regressed,
                test_compact_ancestor_floor_regressed,
                test_compact_bounded_initialization_restores_commit_metadata_and_floor,
                test_compact_bounded_initialization_persists_across_reopen,
                test_compact_commit_persists_across_reopen,
                test_compact_bounded_initialization_to_committed_entry_after_reopen,
                test_compact_sync_after_commit,
                test_compact_import_persists,
                test_compact_import_then_apply_persists,
                test_compact_import_over_unreadable_destination,
                test_compact_import_crash_points,
                test_compact_reopen_rejects_tampered_witness,
                test_compact_bounded_initialization_rejects_corrupt_target_entry,
                test_compact_reopen_rejects_commit_floor_beyond_tip,
                test_compact_reopen_rejects_non_commit_tip,
                test_compact_reopen_rejects_tampered_pinned_nodes,
                test_compact_bounded_initialization_preserves_current_state,
                test_compact_merkleize_foreign_db,
                test_compact_merkleize_stale_sibling,
                test_compact_merkleize_ancestor_states,
                test_compact_bounded_initialization_ignores_discarded_witness_sections,
                test_compact_bounded_initialization_repairs_retained_witness_section,
                test_compact_bounded_initialization_after_genesis_import,
                test_compact_failed_bounded_selection_preserves_acknowledged_offsets,
                test_compact_prune_past_tip_keeps_tip,
                test_compact_initialization_zero_and_above_end,
                test_compact_bounded_initialization_between_commits,
                test_compact_reopen_drops_unsynced_witness,
                test_compact_bounded_initialization_multiple_commits,
                test_compact_prune_then_bounded_initialization,
                test_compact_bounded_initialization_preserves_pre_advance_batch,
                test_compact_noop_sync_after_sync,
                test_compact_noop_sync_after_reopen,
                test_compact_noop_sync_after_bounded_initialization,
                test_compact_bounded_initialization_makes_post_advance_batch_stale,
                test_compact_floor_beyond_size,
                test_compact_ancestor_floor_beyond_size,
                test_compact_operations_and_proof
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
