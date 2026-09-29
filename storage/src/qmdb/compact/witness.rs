//! Shared machinery for the compact-db witness journal.
//!
//! The witness journal is the single durable source of truth for a compact database. Each
//! [`Witness`] is a complete record of one applied state. It contains the encoded commit,
//! committed size, and pinned nodes one operation below it. The commit's inclusion proof is not
//! stored. It is derived from the pinned nodes and the operation when an entry is loaded. On open,
//! the in-memory Merkle is rebuilt by appending the commit operation to the pinned nodes, and a
//! structurally invalid entry fails with [`Error::DataCorrupted`].
//!
//! Entries are strictly increasing in committed size, so a size uniquely identifies an
//! initialization or prune target. An appended entry becomes durable when the journal `commit` or
//! `sync` completes. For [`Store::start_sync`] it becomes durable when the returned handle
//! completes. Before that point, the entry is not guaranteed durable and recovery may fall back to
//! the previous commit. [`Store::prune`] bounds how far back bounded initialization can reach. The
//! tip entry is never pruned.

use crate::{
    Context, SyncCompletion,
    journal::{
        authenticated::{Backing as _, BackingRecovery as _},
        contiguous::{Contiguous, variable},
    },
    merkle::{
        self, Family, Location, MAX_PINNED_NODES, Proof, compact, hasher::Hasher as MerkleHasher,
    },
    qmdb::{
        self, Error,
        operation::Floored,
        sync::{CompactTarget, Request, Response, Source, source},
    },
};
use bytes::Bytes;
use commonware_codec::{Buf, Decode as _, Encode, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::{Error as RError, Handle};
use futures::FutureExt as _;
use std::sync::Arc;

/// An applied state persisted by the witness journal.
#[derive(Clone)]
pub(crate) struct Witness<F: Family, D: Digest> {
    /// The encoded last commit operation at `size - 1`.
    pub(crate) op_bytes: Bytes,
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

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let op_bytes = Bytes::read_cfg(buf, &(..).into())?;
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
            op_bytes: u.arbitrary::<Vec<u8>>()?.into(),
            size: Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?),
            pinned_nodes: u.arbitrary()?,
        })
    }
}

/// A compact database's commit with the data to serve and prove it: its latest applied commit,
/// or the one a snapshot captured.
///
/// As a [`Source`], a tip serves only requests for its own state: `size` equal to
/// [`Self::size`] and `start` at the commit (`size - 1`). Other requests fail with the errors a
/// pruned operation log reports ([`crate::journal::Error::ItemPruned`] or
/// [`crate::merkle::Error::RangeOutOfBounds`]).
pub struct Tip<F: Family, Op, D: Digest> {
    /// The witness of this commit, as written (or to be written) to the witness journal.
    witness: Witness<F, D>,
    /// The commit operation.
    op: Op,
    /// Root committed by `witness`.
    root: D,
    /// Inclusion proof for the commit at `size - 1` against `root`.
    proof: Proof<F, D>,
}

impl<F: Family, Op, D: Digest> Tip<F, Op, D> {
    /// The number of operations through this commit, which is at location `size - 1`.
    pub const fn size(&self) -> Location<F> {
        self.witness.size
    }

    /// The committed root.
    pub const fn root(&self) -> D {
        self.root
    }

    /// The target this tip can serve.
    pub const fn target(&self) -> CompactTarget<F, D> {
        CompactTarget {
            root: self.root,
            size: self.size(),
        }
    }

    /// The decoded commit operation at `size - 1`.
    pub(crate) const fn op(&self) -> &Op {
        &self.op
    }
}

impl<F, Op, D> Source for Tip<F, Op, D>
where
    F: Family,
    Op: Clone + Send + Sync,
    D: Digest,
{
    type Family = F;
    type Digest = D;
    type Op = Op;
    type Error = Error<F>;

    #[allow(clippy::type_complexity)]
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
    async fn serve(&self, request: Request<F>) -> source::Result<Self> {
        // The request must target exactly the committed size and start at the
        // commit's location.
        let tip = self.size();
        if request.size() > tip || request.size() == 0 {
            return Err(merkle::Error::RangeOutOfBounds(request.size()).into());
        }
        if request.size() < tip {
            return Err(crate::journal::Error::ItemPruned(*request.size() - 1).into());
        }
        if request.start() >= request.size() {
            return Err(merkle::Error::RangeOutOfBounds(request.start()).into());
        }
        if request.start() < request.size() - 1 {
            return Err(crate::journal::Error::ItemPruned(*request.start()).into());
        }
        let response = match request {
            Request::Operations { .. } => Response::Operations {
                proof: self.proof.clone(),
                operations: vec![self.op.clone()],
            },
            Request::Boundary { .. } => Response::Boundary {
                proof: self.proof.clone(),
                op: self.op.clone(),
                pinned_nodes: self.witness.pinned_nodes.clone(),
            },
        };
        Ok((response, None))
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

/// A contiguous journal plus the in-memory tip.
pub(crate) struct Store<E: Context, F: Family, Op, D: Digest> {
    journal: Journal<E, F, D>,

    tip: Arc<Tip<F, Op, D>>,

    /// Whether the tip came from compact sync and has not been written to the journal yet.
    /// While set, the journal still holds the partition's previous contents; the first
    /// application to the journal replaces them with the tip and clears this flag.
    import_pending: bool,

    /// Whether witnesses were appended after the latest durability operation started.
    uncommitted: bool,

    /// The sync pipelined by the last [`Self::start_sync`], cleared by the next full
    /// journal sync.
    pending_sync: Option<SyncCompletion>,
}

impl<E: Context, F: Family, Op, D: Digest> Store<E, F, Op, D> {
    pub(crate) fn new(journal: Journal<E, F, D>, tip: Tip<F, Op, D>) -> Self {
        Self {
            journal,
            tip: Arc::new(tip),
            import_pending: false,
            uncommitted: false,
            pending_sync: None,
        }
    }

    /// Create a store from a validated compact-sync import that has not been applied to the
    /// witness journal yet. The journal is untouched until the first application replaces its
    /// contents with the tip. A crash during that replacement leaves a journal that fails to
    /// reopen; re-syncing recovers it.
    pub(crate) fn from_import(journal: Journal<E, F, D>, tip: Tip<F, Op, D>) -> Self {
        Self {
            journal,
            tip: Arc::new(tip),
            import_pending: true,
            uncommitted: false,
            pending_sync: None,
        }
    }

    /// The current tip.
    pub(crate) const fn tip(&self) -> &Arc<Tip<F, Op, D>> {
        &self.tip
    }

    /// Record the commit just applied to `merkle`, whose commit operation is `op`, as the new tip
    /// and append its witness to the journal.
    ///
    /// If no commit was applied since the tip was installed, this only writes a pending import's
    /// tip (see [`Self::write_import`]).
    pub(crate) async fn apply<H, S>(
        mut self,
        merkle: &mut compact::Merkle<F, D, S>,
        op: Op,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Floored<F> + Encode,
    {
        if self.tip.size() >= merkle.leaves() {
            return self.write_import(merkle).await;
        }

        // Build the tip before pruning because its commit proof needs the unpruned Merkle.
        let tip = Arc::new(tip_from_parts::<F, H, S, Op>(merkle, op)?);
        if self.import_pending {
            self = self.clear_for_import().await?;
        }

        // Append before pruning and clearing import state so every successful apply has a matching
        // journal entry.
        (self.journal, _) = self.journal.append(&tip.witness).await?;

        // Publish the applied tip while retaining that it lies outside the durable prefix.
        self.import_pending = false;
        self.uncommitted = true;
        merkle.prune_to_frontier();
        self.tip = tip;
        Ok(self)
    }

    /// Commit the journal so every applied witness, and a pending import's tip, survives a crash.
    /// Journal recovery may be required on reopen.
    ///
    /// First waits for any sync pipelined by [`Self::start_sync`], surfacing its failure, then
    /// commits every applied witness.
    pub(crate) async fn commit<S: Strategy>(
        self,
        merkle: &compact::Merkle<F, D, S>,
    ) -> Result<Self, Error<F>> {
        self.wait_for_sync().await?;
        self.persist(merkle, Durability::Commit).await
    }

    /// Sync the journal and all of its metadata so every applied witness, and a pending import's
    /// tip, survives a crash with minimal recovery work on reopen.
    ///
    /// This also settles any sync pipelined by [`Self::start_sync`].
    pub(crate) async fn sync<S: Strategy>(
        self,
        merkle: &compact::Merkle<F, D, S>,
    ) -> Result<Self, Error<F>> {
        self.persist(merkle, Durability::Sync).await
    }

    /// Write a pending import's tip, then persist the journal according to `durability`.
    async fn persist<S: Strategy>(
        mut self,
        merkle: &compact::Merkle<F, D, S>,
        durability: Durability,
    ) -> Result<Self, Error<F>> {
        // Compact-sync imports enter with a tip that is absent from the journal. Write it
        // before making the requested durability guarantee.
        self = self.write_import(merkle).await?;

        // Full sync includes recovery metadata even when every witness is already committed.
        match durability {
            Durability::Commit if self.uncommitted => {
                self.journal = self.journal.commit().await?;
                self.uncommitted = false;
            }
            Durability::Sync => {
                let journal = self.journal.sync().await?;
                self.pending_sync = None;
                self.uncommitted = false;
                self.journal = journal;
            }
            Durability::Commit => {}
        }
        Ok(self)
    }

    /// Start a journal sync covering every applied witness, and a pending import's tip, instead
    /// of awaiting it.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit],
    /// plus a best-effort attempt to bound the recovery needed on reopen. When nothing new must
    /// be appended, the handle still proves the current tip durable and resurfaces any retained
    /// sync failure.
    pub(crate) async fn start_sync<S: Strategy>(
        mut self,
        merkle: &compact::Merkle<F, D, S>,
    ) -> Result<(Self, Handle<()>), Error<F>> {
        // Match the deferred-failure convention used by the journal: return a prior completion's
        // error through a ready handle before a later completion can replace it. Errors while
        // staging or initiating this sync continue to use the outer result.
        if let Err(err) = self.wait_for_sync().await {
            return Ok((self, Handle::ready(Err(err))));
        }

        // Write a pending import before starting the journal sync so the returned handle covers
        // the current tip. A later apply remains uncommitted and requires a successor durability
        // operation.
        self = self.write_import(merkle).await?;

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

    /// Write the tip to the journal if it came from a compact-sync import that has not been
    /// written yet.
    ///
    /// Every applied commit updates the tip, so a tip that does not match `merkle` is
    /// [`Error::DataCorrupted`].
    async fn write_import<S: Strategy>(
        mut self,
        merkle: &compact::Merkle<F, D, S>,
    ) -> Result<Self, Error<F>> {
        if self.tip.size() != merkle.leaves() {
            return Err(Error::DataCorrupted(
                "witness does not match in-memory state",
            ));
        }
        if !self.import_pending {
            return Ok(self);
        }
        self = self.clear_for_import().await?;
        let tip = Arc::clone(&self.tip);
        (self.journal, _) = self.journal.append(&tip.witness).await?;
        self.import_pending = false;
        self.uncommitted = true;
        Ok(self)
    }

    /// Drop all entries committing fewer than `pruning_boundary` leaves, bounding how far back
    /// bounded initialization can reach. The tip entry always survives. Some entries
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

    /// Reject operations on a journal whose contents an unapplied compact-sync import is
    /// about to replace.
    const fn check_import_applied(&self) -> Result<(), Error<F>> {
        if self.import_pending {
            return Err(Error::DataCorrupted("compact-sync import not applied"));
        }
        Ok(())
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
    /// An interrupted import leaves an empty journal at a nonzero position. Reopening rejects
    /// the missing tip instead of treating the journal as a fresh database.
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

/// Append `op` as the Merkle's final leaf, build the resulting [`Tip`], and prune the Merkle
/// to its frontier.
///
/// Returns [`Error::DataCorrupted`] if `op` is not a commit or its floor lies past its own
/// location, and [`Error::Merkle`] if the Merkle cannot append or prove it.
pub(crate) fn import_tip<F, H, S, Op>(
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    op: Op,
) -> Result<Tip<F, Op, H::Digest>, Error<F>>
where
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Floored<F> + Encode,
{
    let hasher = qmdb::hasher::<H>();
    merkle.append_leaf(&hasher, &op.encode())?;
    let tip = tip_from_parts::<F, H, S, Op>(merkle, op)?;
    merkle.prune_to_frontier();
    Ok(tip)
}

/// Derive the root, proof, and pinned nodes for the commit `op` at the Merkle's tip and assemble
/// the [`Tip`]. The tip leaf must commit to `op`'s encoding, which is enforced against the Merkle,
/// so the op a tip serves is exactly the one its proof authenticates.
fn tip_from_parts<F, H, S, Op>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    op: Op,
) -> Result<Tip<F, Op, H::Digest>, Error<F>>
where
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Floored<F> + Encode,
{
    let inactivity_floor_loc = op
        .has_floor()
        .ok_or(Error::DataCorrupted("last operation was not a commit"))?;
    let op_bytes = op.encode();
    let hasher = qmdb::hasher::<H>();
    let mem = merkle.mem();
    let size = mem.leaves();
    if size == 0 {
        return Err(Error::DataCorrupted("compact merkle has no commit"));
    }
    let last_commit_loc = size - 1;
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
    let leaf_pos = F::location_to_position(last_commit_loc);
    if *mem.get_node_unchecked(leaf_pos)
        != MerkleHasher::<F>::leaf_digest(&hasher, leaf_pos, &op_bytes)
    {
        return Err(Error::DataCorrupted("commit bytes do not match merkle tip"));
    }
    let inactive_peaks = F::inactive_peaks(size, inactivity_floor_loc);
    let root = mem.root(&hasher, inactive_peaks)?;
    let pinned_nodes = F::nodes_to_pin(last_commit_loc)
        .map(|pos| *mem.get_node_unchecked(pos))
        .collect::<Vec<_>>();
    let proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
    Ok(Tip {
        witness: Witness {
            op_bytes,
            size,
            pinned_nodes,
        },
        op,
        root,
        proof,
    })
}

/// Validate that a decoded commit floor does not point past the commit it authenticates.
///
/// The inactivity floor of a commit must sit at or below the commit's own location. A higher
/// floor would reference operations that do not exist yet, which indicates disk corruption in
/// the persisted witness.
fn validate_inactivity_floor<F: Family>(
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
) -> Result<Tip<F, Op, H::Digest>, Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read + Floored<F> + Encode,
{
    let size = journal.size();
    if size == 0 {
        return Err(Error::DataCorrupted("missing compact witness"));
    }
    let entry = journal.read(size - 1).await?;
    rebuild::<F, H::Digest, H, S, Op>(entry, merkle, commit_codec_config)
}

/// Rebuild the Merkle from `witness` and derive its tip.
///
/// The Merkle is reset to the pinned nodes one operation below the commit, the commit operation is
/// appended, and the root and the commit's inclusion proof are computed from the rebuilt
/// state. A structurally invalid entry fails with [`Error::DataCorrupted`].
fn rebuild<F, D, H, S, Op>(
    witness: Witness<F, D>,
    merkle: &mut compact::Merkle<F, D, S>,
    commit_codec_config: &Op::Cfg,
) -> Result<Tip<F, Op, D>, Error<F>>
where
    F: Family,
    D: Digest,
    H: Hasher<Digest = D>,
    S: Strategy,
    Op: Read + Floored<F> + Encode,
{
    let size = witness.size;
    if size == 0 {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }

    // Decode the commit op to get the inactivity floor, which determines the inactive peak
    // boundary used for root computation.
    let last_commit_loc = size - 1;
    let op = Op::decode_cfg(witness.op_bytes.clone(), commit_codec_config)
        .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;

    // The tip serves the decoded op while proofs authenticate the persisted bytes, so the two
    // must be the same encoding.
    if op.encode().as_ref() != &witness.op_bytes[..] {
        return Err(Error::DataCorrupted("non-canonical commit operation"));
    }

    let hasher = qmdb::hasher::<H>();
    merkle
        .reset_to(last_commit_loc, witness.pinned_nodes.clone())
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    merkle
        .append_leaf(&hasher, &witness.op_bytes)
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    let tip = tip_from_parts::<F, H, S, Op>(merkle, op)
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    merkle.prune_to_frontier();
    Ok(tip)
}

/// Open the witness store for an existing or new compact db.
///
/// A new db starts with one committed operation, the initial commit: it is inserted into the
/// compact Merkle and persisted as the first witness entry, so initialization never sees an empty
/// journal. An existing db reloads and re-verifies its tip witness.
pub(crate) async fn init<E, F, H, S, Op>(
    context: E,
    config: variable::Config<()>,
    max_size: Option<Location<F>>,
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    commit_codec_config: &Op::Cfg,
    initial_commit_op: Op,
) -> Result<Store<E, F, Op, H::Digest>, Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read + Floored<F> + Encode,
{
    crate::qmdb::validate_initialization_bound(max_size)?;

    // Keep recovery unpublished until the target witness has been selected and verified.
    let pending = recover::<E, F, H::Digest>(context, config, max_size).await?;
    let bounds = pending.bounds();

    // Only an empty journal at position zero represents fresh storage. A nonzero empty range is an
    // interrupted import whose missing witness must remain fatal.
    if bounds.is_empty() {
        if bounds.start != 0 {
            return Err(Error::DataCorrupted("witness journal has no tip"));
        }
        let journal = pending.finish(0).await?;
        let journal =
            bootstrap_initial_commit::<E, F, H, S, Op>(journal, merkle, initial_commit_op).await?;
        let tip = load_tip::<E, F, H, S, Op>(&journal, merkle, commit_codec_config).await?;
        return Ok(Store::new(journal, tip));
    }

    // Witness positions count commits, while witness sizes count database operations. Search the
    // monotonic sizes for the latest witness within the requested operation bound.
    let mut end = bounds.end;
    if let Some(cap) = max_size {
        let mut start = bounds.start;
        while start < end {
            let mid = start + (end - start) / 2;
            let entry = pending.read(mid).await?;
            if entry.size <= cap {
                start = mid + 1;
            } else {
                end = mid;
            }
        }
        if end == bounds.start {
            return Err(Error::HistoricalFloorPruned(cap));
        }
    }

    // Verify the selected witness before discarding any newer entry.
    let entry = pending.read(end - 1).await?;
    let tip = rebuild::<F, H::Digest, H, S, Op>(entry, merkle, commit_codec_config)?;
    let journal = pending.finish(end).await?;
    Ok(Store::new(journal, tip))
}

/// Recover the witness journal bounded at `max_size` when that view can settle selection, and
/// unbounded otherwise.
///
/// Witness position `p` has size at least `p + 1` in an append-only journal, so positions below
/// the cap hold every witness no larger than the cap. A compact-sync import can put a smaller size
/// at the journal end. A retained start at or above the cap therefore opens unbounded, and a
/// bounded view that ends at the cap with a tip size below the cap widens.
async fn recover<E, F, D>(
    context: E,
    config: variable::Config<()>,
    max_size: Option<Location<F>>,
) -> Result<variable::Recovery<E, Witness<F, D>>, Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
{
    let Some(cap) = max_size else {
        return Ok(Journal::<E, F, D>::recover(context, config, None).await?);
    };
    if variable::Recovery::<E, Witness<F, D>>::span(context.child("span"), &config)
        .await?
        .start
        >= *cap
    {
        return Ok(Journal::<E, F, D>::recover(context, config, None).await?);
    }
    let bounded = Journal::<E, F, D>::recover(context, config, Some(*cap)).await?;
    let bounds = bounded.bounds();

    // The bounded view starts at the span start, below the cap, so a view that ends at the cap
    // is non-empty.
    if bounds.end < *cap || bounded.read(bounds.end - 1).await?.size >= cap {
        return Ok(bounded);
    }
    Ok(bounded.unbounded().await?)
}

/// Insert and persist the initial `Commit(None, 0)` for a new compact db.
async fn bootstrap_initial_commit<E, F, H, S, Op>(
    journal: Journal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    initial_commit_op: Op,
) -> Result<Journal<E, F, H::Digest>, Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Floored<F> + Encode,
{
    let op_bytes = initial_commit_op.encode();
    let hasher = qmdb::hasher::<H>();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &op_bytes);
        batch.merkleize(merkle.mem(), &hasher)
    };
    merkle.apply_batch(&batch)?;

    let tip = tip_from_parts::<F, H, S, Op>(merkle, initial_commit_op)?;
    let (journal, _) = journal.append(&tip.witness).await?;
    let journal = journal.sync().await?;
    Ok(journal)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::merkle::mmr;
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::Sequential;

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::merkle::mmb;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Witness<mmr::Family, sha256::Digest>>,
            CodecConformance<Witness<mmb::Family, sha256::Digest>>,
        }
    }

    /// A commit-like op whose decoder tolerates one trailing pad byte, making a non-canonical
    /// encoding representable.
    #[derive(Clone, PartialEq, Debug)]
    struct PaddedCommit(u64);

    impl Write for PaddedCommit {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl EncodeSize for PaddedCommit {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Read for PaddedCommit {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
            let value = u64::read_cfg(buf, &())?;
            if bytes::Buf::remaining(buf) > 0 {
                u8::read_cfg(buf, &())?;
            }
            Ok(Self(value))
        }
    }

    impl Floored<mmr::Family> for PaddedCommit {
        fn has_floor(&self) -> Option<Location<mmr::Family>> {
            Some(Location::new(0))
        }
    }

    /// Persisted bytes that decode successfully but do not re-encode to themselves are
    /// rejected when the tip is rebuilt.
    #[test]
    fn test_rebuild_rejects_non_canonical_commit() {
        let op = PaddedCommit(7);
        let mut op_bytes = op.encode().to_vec();
        op_bytes.push(0);
        let op_bytes = Bytes::from(op_bytes);
        assert_eq!(PaddedCommit::decode_cfg(op_bytes.clone(), &()).unwrap(), op);

        let mut merkle =
            compact::Merkle::<mmr::Family, sha256::Digest, Sequential>::new(Sequential);
        let entry = Witness {
            op_bytes,
            size: Location::new(1),
            pinned_nodes: vec![],
        };
        assert!(matches!(
            rebuild::<mmr::Family, _, Sha256, Sequential, PaddedCommit>(entry, &mut merkle, &()),
            Err(Error::DataCorrupted("non-canonical commit operation"))
        ));
    }

    /// A tip can only be built from the exact bytes the Merkle's tip leaf commits to, and
    /// never from a Merkle without a commit.
    #[test]
    fn test_tip_requires_bytes_matching_merkle() {
        let mut merkle =
            compact::Merkle::<mmr::Family, sha256::Digest, Sequential>::from_compact_state(
                Sequential,
                Location::new(0),
                vec![],
            )
            .unwrap();
        let op = PaddedCommit(7);
        let op_bytes = op.encode();

        assert!(matches!(
            tip_from_parts::<mmr::Family, Sha256, Sequential, PaddedCommit>(&merkle, op.clone()),
            Err(Error::DataCorrupted("compact merkle has no commit"))
        ));

        let hasher = qmdb::hasher::<Sha256>();
        let mut other =
            compact::Merkle::<mmr::Family, sha256::Digest, Sequential>::from_compact_state(
                Sequential,
                Location::new(0),
                vec![],
            )
            .unwrap();
        merkle.append_leaf(&hasher, &op_bytes).unwrap();
        assert!(
            tip_from_parts::<mmr::Family, Sha256, Sequential, PaddedCommit>(&merkle, op.clone())
                .is_ok()
        );
        other
            .append_leaf(&hasher, &PaddedCommit(8).encode())
            .unwrap();
        assert!(matches!(
            tip_from_parts::<mmr::Family, Sha256, Sequential, PaddedCommit>(&other, op),
            Err(Error::DataCorrupted("commit bytes do not match merkle tip"))
        ));
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
        let mut journal = journal.test_truncate(pos).await.unwrap();
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
        (entry.op_bytes.to_vec(), entry.size, entry.pinned_nodes)
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
                op_bytes: op_bytes.into(),
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
        let journal = journal.test_truncate(entries - 1).await.unwrap();
        let (journal, _) = journal
            .append(&Witness {
                op_bytes: op_bytes.into(),
                size,
                pinned_nodes,
            })
            .await
            .unwrap();
        journal.sync().await.unwrap()
    }
}
