//! Shared machinery for the compact-db witness journal.
//!
//! The witness journal is the single durable source of truth for a compact database. Each
//! [`Witness`] is a complete snapshot of one applied state: the encoded commit operation, the
//! committed size, and the pinned nodes one operation below it. The commit's inclusion proof is
//! not stored. It is derived from the pinned nodes and the operation when an entry is loaded. On open
//! and rewind, the in-memory Merkle is rebuilt by appending the commit operation to the pinned nodes,
//! and a structurally invalid entry fails with [`Error::DataCorrupted`].
//!
//! Entries are strictly increasing in committed size, so a size uniquely identifies
//! a rewind or prune target. An appended entry becomes durable when the journal `commit` or
//! `sync` completes. For [`Store::start_sync`] it becomes durable when the returned handle
//! completes. Before that point, the entry is not guaranteed durable and recovery may fall back
//! to the previous commit. [`Store::prune`] bounds how far back [`Store::rewind`] can reach.
//! The tip entry is never pruned.

use crate::{
    Context, SyncCompletion,
    journal::contiguous::{Contiguous, variable},
    merkle::{self, Family, Location, MAX_PINNED_NODES, Proof, compact},
    qmdb::{
        self, Error,
        operation::Floored,
        sync::{CompactTarget, Request, Response},
    },
};
use commonware_codec::{Decode as _, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::{Error as RError, Handle};
use futures::FutureExt as _;

/// An applied state persisted by the witness journal.
#[derive(Clone)]
pub(crate) struct Witness<F: Family, D: Digest> {
    /// The encoded last commit operation at `size - 1`.
    pub(crate) op_bytes: Vec<u8>,
    /// The committed database size.
    pub(crate) size: Location<F>,
    /// Pinned nodes at the commit operation, in the order returned by
    /// [`Family::nodes_to_pin`].
    pub(crate) pinned_nodes: Vec<D>,
}

impl<F: Family, D: Digest> EncodeSize for Witness<F, D> {
    fn encode_size(&self) -> usize {
        self.op_bytes.encode_size() + self.size.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, D: Digest> Write for Witness<F, D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.op_bytes.write(buf);
        self.size.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, D: Digest> Read for Witness<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let op_bytes = Vec::<u8>::read_cfg(buf, &((..).into(), ()))?;
        let size = Location::<F>::read_cfg(buf, &())?;
        let pinned_nodes = Vec::<D>::read_cfg(buf, &((..=MAX_PINNED_NODES).into(), ()))?;
        Ok(Self {
            op_bytes,
            size,
            pinned_nodes,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for Witness<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            op_bytes: u.arbitrary()?,
            size: Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?),
            pinned_nodes: u.arbitrary()?,
        })
    }
}

/// A witness with the root and commit proof derived from it.
#[derive(Clone)]
pub(crate) struct VerifiedWitness<F: Family, D: Digest> {
    pub(crate) witness: Witness<F, D>,
    /// Root committed by `witness`.
    pub(crate) root: D,
    /// Inclusion proof for the commit at `size - 1` against `root`, derived from the
    /// witness when it was built or loaded.
    pub(crate) proof: Proof<F, D>,
}

impl<F: Family, D: Digest> VerifiedWitness<F, D> {
    /// The committed size, which also identifies the last commit's location.
    pub(crate) const fn size(&self) -> Location<F> {
        self.witness.size
    }

    /// The compact-sync target (root and size) this witness can serve.
    pub(crate) const fn target(&self) -> CompactTarget<F, D> {
        CompactTarget {
            root: self.root,
            size: self.size(),
        }
    }
}

/// The contiguous variable journal that backs a witness [`Store`].
pub(crate) type Journal<E, F, D> = variable::Journal<E, Witness<F, D>>;

/// How a persisted witness entry is made durable.
#[derive(Clone, Copy)]
enum Durability {
    /// Commit the journal: appended entries survive a crash, but journal recovery may be
    /// required on reopen.
    Commit,
    /// Sync the journal and all of its metadata, minimizing recovery work on reopen.
    Sync,
}

/// A contiguous journal plus an in-memory cache of the tip witness.
pub(crate) struct Store<E: Context, F: Family, D: Digest> {
    journal: Journal<E, F, D>,

    tip_witness: VerifiedWitness<F, D>,

    /// Whether the cached witness came from compact sync and has not been written to the
    /// journal yet. While set, the journal still holds the partition's previous contents; the
    /// first application to the journal replaces them with the cached witness and clears this
    /// flag.
    import_pending: bool,

    /// Whether witnesses were appended after the latest durability operation started.
    uncommitted: bool,

    /// The sync pipelined by the last [`Self::start_sync`], cleared by the next full
    /// journal sync.
    pending_sync: Option<SyncCompletion>,
}

impl<E: Context, F: Family, D: Digest> Store<E, F, D> {
    /// Wrap an opened journal and a verified witness into a store.
    pub(crate) const fn new(journal: Journal<E, F, D>, witness: VerifiedWitness<F, D>) -> Self {
        Self {
            journal,
            tip_witness: witness,
            import_pending: false,
            uncommitted: false,
            pending_sync: None,
        }
    }

    /// Create a store from a validated compact-sync import that has not been applied to the
    /// witness journal yet. The journal is untouched until the first application replaces its
    /// contents with `witness`. A crash during that replacement leaves a journal that fails to
    /// reopen; re-syncing recovers it.
    pub(crate) const fn from_import(
        journal: Journal<E, F, D>,
        witness: VerifiedWitness<F, D>,
    ) -> Self {
        Self {
            journal,
            tip_witness: witness,
            import_pending: true,
            uncommitted: false,
            pending_sync: None,
        }
    }

    /// The cached tip witness.
    pub(crate) const fn tip(&self) -> &VerifiedWitness<F, D> {
        &self.tip_witness
    }

    /// Serve `request` from the single committed state this witness retains.
    ///
    /// The witness holds exactly the final commit operation and the pinned nodes one operation
    /// below it. Anything else is refused with the same errors a pruned operation log
    /// reports.
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
    pub(crate) fn compact_state<Op: Read>(
        &self,
        cfg: &Op::Cfg,
        request: Request<F>,
    ) -> Result<Response<F, Op, D>, Error<F>> {
        let size = self.tip_witness.size();
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
        let op = Op::decode_cfg(self.tip_witness.witness.op_bytes.as_ref(), cfg)
            .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;
        // After the checks above, `start == last_commit_loc`, so the stored pinned nodes are the
        // pinned nodes for this request.
        Ok(match request {
            Request::Operations { .. } => Response::Operations {
                proof: self.tip_witness.proof.clone(),
                operations: vec![op],
            },
            Request::Boundary { .. } => Response::Boundary {
                proof: self.tip_witness.proof.clone(),
                op,
                pinned_nodes: self.tip_witness.witness.pinned_nodes.clone(),
            },
        })
    }

    /// Replace the cached witness after the matching compact Merkle state is staged or loaded.
    pub(crate) fn replace(&mut self, witness: VerifiedWitness<F, D>) {
        self.tip_witness = witness;
    }

    /// Apply the current compact state to the witness journal.
    pub(crate) async fn apply<H, S>(
        mut self,
        merkle: &mut compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        // Stage before pruning because a new witness's commit proof needs the unpruned Merkle.
        let verified;
        (self, verified) = self
            .stage::<H, S>(merkle, inactivity_floor_loc, last_commit_op_bytes)
            .await?;
        let Some(verified) = verified else {
            return Ok(self);
        };

        // Append before pruning and clearing import state so every successful apply has a matching
        // journal entry.
        (self.journal, _) = self.journal.append(&verified.witness).await?;

        // Publish the applied tip while retaining that it lies outside the durable prefix.
        self.import_pending = false;
        self.uncommitted = true;
        merkle.prune_to_frontier();
        self.replace(verified);
        Ok(self)
    }

    /// Persist the current compact state as a new witness journal entry, committing the journal
    /// so the entry survives a crash. Journal recovery may be required on reopen.
    ///
    /// First waits for any sync pipelined by [`Self::start_sync`], surfacing its failure, then
    /// commits every applied witness.
    pub(crate) async fn commit<H, S>(
        self,
        merkle: &mut compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        self.wait_for_sync().await?;
        self.persist::<H, S>(
            merkle,
            inactivity_floor_loc,
            last_commit_op_bytes,
            Durability::Commit,
        )
        .await
    }

    /// Persist the current compact state as a new witness journal entry, syncing the journal and
    /// all of its metadata to minimize recovery work on reopen.
    ///
    /// This also settles any sync pipelined by [`Self::start_sync`].
    pub(crate) async fn sync<H, S>(
        self,
        merkle: &mut compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        self.persist::<H, S>(
            merkle,
            inactivity_floor_loc,
            last_commit_op_bytes,
            Durability::Sync,
        )
        .await
    }

    /// Shared body of [`Self::commit`] and [`Self::sync`]: apply the current state, then make
    /// every uncommitted witness durable according to `durability`.
    async fn persist<H, S>(
        mut self,
        merkle: &mut compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
        durability: Durability,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        // Compact-sync imports enter with a cached witness that is absent from the journal.
        // Apply the current state before making the requested durability guarantee.
        self = self
            .apply::<H, S>(merkle, inactivity_floor_loc, last_commit_op_bytes)
            .await?;

        // A commit leaves `pending_sync` set so the next full sync still persists all metadata.
        match durability {
            Durability::Commit if self.uncommitted => {
                self.journal = self.journal.commit().await?;
                self.uncommitted = false;
            }
            Durability::Sync if self.uncommitted || self.pending_sync.is_some() => {
                let journal = self.journal.sync().await?;
                self.pending_sync = None;
                self.uncommitted = false;
                self.journal = journal;
            }
            Durability::Commit | Durability::Sync => {}
        }
        Ok(self)
    }

    /// Persist the current compact state as a new witness journal entry, starting the journal
    /// sync instead of awaiting it.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit],
    /// plus a best-effort attempt to bound the recovery needed on reopen. When nothing new must
    /// be appended, the handle still proves the current tip durable and resurfaces any retained
    /// sync failure.
    pub(crate) async fn start_sync<H, S>(
        mut self,
        merkle: &mut compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<(Self, Handle<()>), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        // Match the deferred-failure convention used by the journal: return a prior completion's
        // error through a ready handle before a later completion can replace it. Errors while
        // staging or initiating this sync continue to use the outer result.
        if let Err(err) = self.wait_for_sync().await {
            return Ok((self, Handle::ready(Err(err))));
        }

        // Apply before starting the journal sync so the returned handle covers the current tip.
        // A later apply remains uncommitted and requires a successor durability operation.
        self = self
            .apply::<H, S>(merkle, inactivity_floor_loc, last_commit_op_bytes)
            .await?;

        // Share one completion between the caller and the store. Retaining a clone keeps a
        // dropped handle's failure observable by the next durability operation.
        let handle;
        (self.journal, handle) = self.journal.start_sync().await?;
        let completion: SyncCompletion = handle.boxed().shared();
        self.uncommitted = false;
        self.pending_sync = Some(completion.clone());
        Ok((self, Handle::from_future(completion)))
    }

    /// Wait for any sync pipelined by [`Self::start_sync`], surfacing its failure.
    ///
    /// A successful completion remains recorded until the next full journal sync, which must
    /// still guarantee that all metadata is current.
    pub(crate) async fn wait_for_sync(&self) -> Result<(), RError> {
        let Some(pending) = self.pending_sync.clone() else {
            return Ok(());
        };
        pending.await
    }

    /// Decide what a persist must write, clearing the journal first when an import is pending.
    ///
    /// Returns `None` if the cached tip already matches the in-memory Merkle and no import is
    /// pending, otherwise the witness to append and install in the cache.
    async fn stage<H, S>(
        mut self,
        merkle: &compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<(Self, Option<VerifiedWitness<F, D>>), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        // An equal size means no commit has been applied since the cache was set.
        // Normally the cache mirrors the journal tip, so there is no witness to append. A
        // start_sync may still be proving that tip durable, which pending_sync tracks separately.
        // During a pending import the cached witness is not in the journal yet, so it is exactly
        // what must be persisted. Replace the journal's contents with it.
        let cached_size = self.tip().size();
        let verified = if cached_size == merkle.leaves() {
            if !self.import_pending {
                return Ok((self, None));
            }
            self.tip().clone()
        } else if cached_size > merkle.leaves() {
            return Err(Error::DataCorrupted("witness ahead of in-memory state"));
        } else {
            build_witness::<F, H, S>(merkle, inactivity_floor_loc, last_commit_op_bytes())?
        };
        if self.import_pending {
            self = self.clear_for_import().await?;
        }
        Ok((self, Some(verified)))
    }

    /// Rewind the journal so the entry committing exactly `target` leaves becomes the tip, then
    /// rebuild and re-verify the Merkle and cache from it. Returns the decoded commit operation
    /// of the restored tip.
    ///
    /// Rewinding to a pruned size, or one no entry commits, returns
    /// [`merkle::Error::RewindBeyondHistory`]. The target entry is derived before the journal
    /// is truncated, so a corrupt entry fails the rewind with the journal intact. The rewind is
    /// made durable before returning.
    pub(crate) async fn rewind<H, S, Op>(
        mut self,
        merkle: &mut compact::Merkle<F, D, S>,
        target: Location<F>,
        commit_codec_config: &Op::Cfg,
    ) -> Result<(Self, Op), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Read + Floored<F>,
    {
        self.check_import_applied()?;

        let (pos, entry) = self
            .position_of(target)
            .await?
            .ok_or(Error::Merkle(merkle::Error::RewindBeyondHistory))?;
        let (witness, op) = rebuild::<F, D, H, S, Op>(entry, merkle, commit_codec_config)?;
        self.journal = self.journal.rewind(pos + 1).await?.sync().await?;
        self.pending_sync = None;
        self.uncommitted = false;
        self.replace(witness);
        Ok((self, op))
    }

    /// Drop all entries committing fewer than `pruning_boundary` leaves, bounding how far back
    /// [`Self::rewind`] can reach. The tip entry always survives. Some entries
    /// below the boundary may survive.
    pub(crate) async fn prune(mut self, pruning_boundary: Location<F>) -> Result<Self, Error<F>> {
        self.check_import_applied()?;

        let bounds = self.journal.bounds();
        if bounds.is_empty() {
            return Ok(self);
        }
        // Clamp below the tip so the journal never empties: the tip is the current state.
        let pos = Self::first_at_or_above(&self.journal, pruning_boundary)
            .await?
            .min(bounds.end - 1);
        (self.journal, _) = self.journal.prune(pos).await?;
        self.journal = self.journal.sync().await?;
        self.pending_sync = None;
        self.uncommitted = false;
        Ok(self)
    }

    /// Whether the current cached state is not covered by a durability operation.
    pub(crate) const fn has_uncommitted_state(&self) -> bool {
        self.import_pending || self.uncommitted
    }

    /// Reject operations on a journal whose contents an unapplied compact-sync import is
    /// about to replace.
    const fn check_import_applied(&self) -> Result<(), Error<F>> {
        if self.import_pending {
            return Err(Error::DataCorrupted("compact-sync import not applied"));
        }
        Ok(())
    }

    /// Find the journal position and entry committing exactly `target` leaves, or `None` if
    /// no retained entry does.
    async fn position_of(
        &self,
        target: Location<F>,
    ) -> Result<Option<(u64, Witness<F, D>)>, Error<F>> {
        let pos = Self::first_at_or_above(&self.journal, target).await?;
        if pos >= self.journal.bounds().end {
            return Ok(None);
        }
        let entry = self.journal.read(pos).await?;
        Ok((entry.size == target).then_some((pos, entry)))
    }

    /// Binary search for the first retained position whose entry commits at least `size`
    /// leaves, or the end of the journal if none does.
    async fn first_at_or_above(
        reader: &impl Contiguous<Item = Witness<F, D>>,
        size: Location<F>,
    ) -> Result<u64, Error<F>> {
        let bounds = reader.bounds();
        let (mut lo, mut hi) = (bounds.start, bounds.end);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if reader.read(mid).await?.size < size {
                // The entry at `mid` is below `size`, so the answer is after it.
                lo = mid + 1;
            } else {
                // The entry at `mid` qualifies, so the answer is `mid` or before it.
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Clear the journal so the imported witness becomes its only entry.
    ///
    /// Clears to a nonzero size: if a crash interrupts the import, reopen sees a non-empty
    /// journal with an unreadable tip and fails, instead of mistaking it for a fresh db.
    async fn clear_for_import(mut self) -> Result<Self, Error<F>> {
        let size = self.journal.size();
        self.journal = self.journal.clear_to_size(size.max(1)).await?;
        Ok(self)
    }

    /// Destroy all persisted witness state.
    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        Ok(())
    }
}

/// Build a witness for the last commit.
///
/// The tip operation's inclusion proof is only computable before the Merkle is pruned to its
/// frontier.
pub(crate) fn build_witness<F, H, S>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<VerifiedWitness<F, H::Digest>, Error<F>>
where
    F: Family,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    let mem = merkle.mem();
    let size = mem.leaves();
    let last_commit_loc = size - 1;
    let inactive_peaks = F::inactive_peaks(size, inactivity_floor_loc);
    let root = mem.root(&hasher, inactive_peaks)?;
    let pinned_nodes = F::nodes_to_pin(last_commit_loc)
        .map(|pos| *mem.get_node_unchecked(pos))
        .collect::<Vec<_>>();
    let proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
    Ok(VerifiedWitness {
        witness: Witness {
            op_bytes: last_commit_op_bytes,
            size,
            pinned_nodes,
        },
        root,
        proof,
    })
}

/// Validate that a decoded commit floor does not point past the commit it authenticates.
///
/// The inactivity floor of a commit must sit at or below the commit's own location. A higher
/// floor would reference operations that do not exist yet, which indicates disk corruption in
/// the persisted witness.
pub(crate) fn validate_inactivity_floor<F: Family>(
    inactivity_floor_loc: Location<F>,
    last_commit_loc: Location<F>,
) -> Result<(), Error<F>> {
    if inactivity_floor_loc > last_commit_loc {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    Ok(())
}

/// Load the tip witness from the journal and rebuild the Merkle from it.
async fn load_tip<E, F, H, S, Op>(
    journal: &Journal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    commit_codec_config: &Op::Cfg,
) -> Result<(VerifiedWitness<F, H::Digest>, Op), Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read + Floored<F>,
{
    let size = journal.size();
    if size == 0 {
        return Err(Error::DataCorrupted("missing compact witness"));
    }
    let entry = journal.read(size - 1).await?;
    rebuild::<F, H::Digest, H, S, Op>(entry, merkle, commit_codec_config)
}

/// Rebuild the Merkle from `witness` and derive its root and commit proof.
///
/// The Merkle is reset to the pinned nodes one operation below the commit, the commit operation is
/// appended, and the root and the commit's inclusion proof are computed from the rebuilt
/// state. A structurally invalid entry fails with [`Error::DataCorrupted`].
fn rebuild<F, D, H, S, Op>(
    witness: Witness<F, D>,
    merkle: &mut compact::Merkle<F, D, S>,
    commit_codec_config: &Op::Cfg,
) -> Result<(VerifiedWitness<F, D>, Op), Error<F>>
where
    F: Family,
    D: Digest,
    H: Hasher<Digest = D>,
    S: Strategy,
    Op: Read + Floored<F>,
{
    let size = witness.size;
    if size == 0 {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }

    // Decode the commit op to get the inactivity floor, which determines the inactive peak
    // boundary used for root computation.
    let last_commit_loc = size - 1;
    let last_commit_op = Op::decode_cfg(witness.op_bytes.as_ref(), commit_codec_config)
        .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;
    let inactivity_floor_loc = last_commit_op
        .has_floor()
        .ok_or(Error::DataCorrupted("last operation was not a commit"))?;
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;

    let hasher = qmdb::hasher::<H>();
    merkle
        .reset_to(last_commit_loc, witness.pinned_nodes.clone())
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    merkle
        .append_leaf(&hasher, &witness.op_bytes)
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    let verified = build_witness::<F, H, S>(merkle, inactivity_floor_loc, witness.op_bytes)
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    merkle.prune_to_frontier();
    Ok((verified, last_commit_op))
}

/// Open the witness store for an existing or new compact db, returning it with the decoded
/// last-commit operation.
///
/// A new db starts with one committed operation, the initial commit: it is inserted into the
/// compact Merkle and persisted as the first witness entry, so reopen and rewind never see an
/// empty journal. An existing db reloads and re-verifies its tip witness.
pub(crate) async fn init<E, F, H, S, Op>(
    mut journal: Journal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    commit_codec_config: &Op::Cfg,
    initial_commit_op_bytes: Vec<u8>,
) -> Result<(Store<E, F, H::Digest>, Op), Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read + Floored<F>,
{
    if journal.size() == 0 {
        journal = bootstrap_initial_commit::<E, F, H, S>(journal, merkle, initial_commit_op_bytes)
            .await?;
    }
    let (witness, op) = load_tip::<E, F, H, S, Op>(&journal, merkle, commit_codec_config).await?;
    Ok((Store::new(journal, witness), op))
}

/// Insert and persist the initial `Commit(None, 0)` for a new compact db.
async fn bootstrap_initial_commit<E, F, H, S>(
    journal: Journal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<Journal<E, F, H::Digest>, Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &last_commit_op_bytes);
        batch.merkleize(merkle.mem(), &hasher)
    };
    merkle.apply_batch(&batch)?;

    // The initial commit has one leaf and an inactivity floor of 0.
    let verified = build_witness::<F, H, S>(merkle, Location::new(0), last_commit_op_bytes)?;
    let (journal, _) = journal.append(&verified.witness).await?;
    let journal = journal.sync().await?;
    Ok(journal)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::merkle::{mmb, mmr};
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256;

        commonware_conformance::conformance_tests! {
            CodecConformance<Witness<mmr::Family, sha256::Digest>>,
            CodecConformance<Witness<mmb::Family, sha256::Digest>>,
        }
    }

    /// Corrupt the entry at `pos` with `f`, preserving the entries above it.
    pub(crate) async fn corrupt_entry<E, F, D>(
        journal: Journal<E, F, D>,
        pos: u64,
        f: impl FnOnce(&mut Witness<F, D>),
    ) -> Journal<E, F, D>
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let mut entries = Vec::new();
        {
            for p in pos..journal.bounds().end {
                entries.push(journal.read(p).await.unwrap());
            }
        }
        f(&mut entries[0]);
        let mut journal = journal.rewind(pos).await.unwrap();
        for entry in &entries {
            (journal, _) = journal.append(entry).await.unwrap();
        }
        journal.sync().await.unwrap()
    }

    /// Read the tip witness entry's components.
    pub(crate) async fn tip<E, F, D>(journal: &Journal<E, F, D>) -> (Vec<u8>, Location<F>, Vec<D>)
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let size = journal.size();
        let entry = journal.read(size - 1).await.unwrap();
        (entry.op_bytes, entry.size, entry.pinned_nodes)
    }

    /// Append a witness entry without syncing it.
    pub(crate) async fn append_unsynced<E, F, D>(
        journal: Journal<E, F, D>,
        op_bytes: Vec<u8>,
        size: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Journal<E, F, D>
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let (journal, _) = journal
            .append(&Witness {
                op_bytes,
                size,
                pinned_nodes,
            })
            .await
            .unwrap();
        journal
    }

    /// Replace the tip witness entry.
    pub(crate) async fn overwrite_tip<E, F, D>(
        journal: Journal<E, F, D>,
        op_bytes: Vec<u8>,
        size: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Journal<E, F, D>
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let entries = journal.size();
        let journal = journal.rewind(entries - 1).await.unwrap();
        let (journal, _) = journal
            .append(&Witness {
                op_bytes,
                size,
                pinned_nodes,
            })
            .await
            .unwrap();
        journal.sync().await.unwrap()
    }
}
