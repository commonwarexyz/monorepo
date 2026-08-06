//! Shared machinery for the compact-db witness journal.
//!
//! The witness journal is the single durable source of truth for a compact database. Each
//! [`Witness`] is a complete snapshot of one commit: the encoded commit operation, the
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
    merkle::{
        self, Family, Location, MAX_PINNED_NODES, Proof, compact, hasher::Hasher as MerkleHasher,
    },
    qmdb::{
        self, Error,
        operation::Floored,
        sync::{CompactTarget, FeedbackTx, Request, Response, Source},
    },
};
use commonware_codec::{Decode as _, Encode, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::{Error as RError, Handle};
use futures::FutureExt as _;
use std::sync::Arc;

/// The state at a commit as persisted by the witness journal.
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

/// The latest commit with the data to serve and prove it.
pub struct Tip<F: Family, Op, D: Digest> {
    /// The persisted witness of this commit.
    witness: Witness<F, D>,
    /// The commit operation.
    op: Op,
    /// Root committed by `witness`.
    root: D,
    /// Inclusion proof for the commit at `size - 1` against `root`.
    proof: Proof<F, D>,
}

impl<F: Family, Op, D: Digest> Tip<F, Op, D> {
    /// The committed size, which also identifies the last commit's location.
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

    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<F, Op, D>, FeedbackTx), Error<F>> {
        validate_tip_request(self.size(), &request)?;
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
    import_pending: bool,

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
            pending_sync: None,
        }
    }

    /// Create a store from a validated compact-sync import that has not been persisted yet. The
    /// journal is untouched until the first persist replaces its contents with the tip. A
    /// crash during that replacement leaves a journal that fails to reopen; re-syncing
    /// recovers it.
    pub(crate) fn from_import(journal: Journal<E, F, D>, tip: Tip<F, Op, D>) -> Self {
        Self {
            journal,
            tip: Arc::new(tip),
            import_pending: true,
            pending_sync: None,
        }
    }

    /// The current tip.
    pub(crate) const fn tip(&self) -> &Arc<Tip<F, Op, D>> {
        &self.tip
    }

    /// Persist the current compact state as a new witness journal entry, committing the journal
    /// so the entry survives a crash. Journal recovery may be required on reopen.
    ///
    /// First waits for any sync pipelined by [`Self::start_sync`], surfacing its failure. If the
    /// tip already matches the Merkle, nothing more is needed. Otherwise appends a
    /// witness built from the unpruned Merkle, prunes the Merkle to its frontier, and installs
    /// the new tip.
    pub(crate) async fn commit<H, S>(
        self,
        merkle: &compact::Merkle<F, D, S>,
        op: Op,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Floored<F> + Encode,
    {
        self.wait_for_sync().await?;
        self.persist::<H, S>(merkle, op, Durability::Commit).await
    }

    /// Persist the current compact state as a new witness journal entry, syncing the journal and
    /// all of its metadata to minimize recovery work on reopen.
    ///
    /// If the tip already matches the Merkle, this only settles any sync pipelined
    /// by [`Self::start_sync`], running a full journal sync when one is outstanding. Otherwise
    /// appends a witness built from the unpruned Merkle, prunes the Merkle to its frontier, and
    /// installs the new tip.
    pub(crate) async fn sync<H, S>(
        self,
        merkle: &compact::Merkle<F, D, S>,
        op: Op,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Floored<F> + Encode,
    {
        self.persist::<H, S>(merkle, op, Durability::Sync).await
    }

    /// Shared body of [`Self::commit`] and [`Self::sync`]: stage what must be persisted, append
    /// it, make it durable per `durability`, and install it as the tip.
    ///
    /// A pending import is cleared only after the entry is durable, so an interrupted journal
    /// replacement is retried by the next persist. [`Self::start_sync`] clears it at append
    /// instead. A crash before its handle completes leaves a journal that fails to reopen and
    /// is recovered by re-syncing.
    async fn persist<H, S>(
        mut self,
        merkle: &compact::Merkle<F, D, S>,
        op: Op,
        durability: Durability,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Floored<F> + Encode,
    {
        let staged;
        (self, staged) = self.stage::<H, S>(merkle, op).await?;
        let Some(tip) = staged else {
            // `commit` already waited for the pipelined sync. `sync` delegates that drain to the
            // full journal sync, which is still required because the pipelined sync made only a
            // best-effort attempt to persist all metadata.
            if matches!(durability, Durability::Sync) && self.pending_sync.is_some() {
                self.journal = self.journal.sync().await?;
                self.pending_sync = None;
            }
            return Ok(self);
        };
        (self.journal, _) = self.journal.append(&tip.witness).await?;

        // A commit leaves `pending_sync` set so the next full sync still persists all metadata.
        self.journal = match durability {
            Durability::Commit => self.journal.commit().await?,
            Durability::Sync => {
                let journal = self.journal.sync().await?;
                self.pending_sync = None;
                journal
            }
        };
        self.import_pending = false;
        merkle.prune_to_frontier();
        self.tip = tip;
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
        merkle: &compact::Merkle<F, D, S>,
        op: Op,
    ) -> Result<(Self, Handle<()>), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Floored<F> + Encode,
    {
        // Match the deferred-failure convention used by the journal: return a prior completion's
        // error through a ready handle before a later completion can replace it. Errors while
        // staging or initiating this sync continue to use the outer result.
        if let Err(err) = self.wait_for_sync().await {
            return Ok((self, Handle::ready(Err(err))));
        }

        // Decide whether the journal needs a new witness before starting this sync. During import,
        // staging verifies the tip before clearing the journal it will replace.
        let staged;
        (self, staged) = self.stage::<H, S>(merkle, op).await?;

        if let Some(tip) = staged {
            // Publish the tip only after it has been appended. The tip may then match the
            // Merkle before the append is durable, which `pending_sync` tracks.
            (self.journal, _) = self.journal.append(&tip.witness).await?;
            self.import_pending = false;
            merkle.prune_to_frontier();
            self.tip = tip;
        }

        // Share one completion between the caller and the store. Retaining a clone keeps a
        // dropped handle's failure observable by the next durability operation.
        let handle;
        (self.journal, handle) = self.journal.start_sync().await?;
        let completion: SyncCompletion = handle.boxed().shared();
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
    /// Returns `None` if the tip already matches the in-memory Merkle and no import is
    /// pending, otherwise the tip to append and install.
    async fn stage<H, S>(
        mut self,
        merkle: &compact::Merkle<F, D, S>,
        op: Op,
    ) -> Result<(Self, Option<Arc<Tip<F, Op, D>>>), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Floored<F> + Encode,
    {
        // An equal size means no commit has been applied since the tip was installed.
        // Normally the tip mirrors the journal tip, so there is no witness to append. A
        // start_sync may still be proving that tip durable, which pending_sync tracks separately.
        // During a pending import the tip is not in the journal yet, so it is exactly
        // what must be persisted. Replace the journal's contents with it.
        let tip_size = self.tip.size();
        let tip = if tip_size == merkle.leaves() {
            if !self.import_pending {
                return Ok((self, None));
            }
            Arc::clone(&self.tip)
        } else if tip_size > merkle.leaves() {
            return Err(Error::DataCorrupted("witness ahead of in-memory state"));
        } else {
            let inactivity_floor_loc = op
                .has_floor()
                .ok_or(Error::DataCorrupted("last operation was not a commit"))?;
            let op_bytes = op.encode().to_vec();
            Arc::new(tip_from_parts::<F, H, S, Op>(
                merkle,
                inactivity_floor_loc,
                op_bytes,
                op,
            )?)
        };
        if self.import_pending {
            self = self.clear_for_import().await?;
        }
        Ok((self, Some(tip)))
    }

    /// Rewind the journal so the entry committing exactly `target` leaves becomes the tip, then
    /// rebuild and re-verify the Merkle and tip from it.
    ///
    /// Rewinding to a pruned size, or one no entry commits, returns
    /// [`merkle::Error::RewindBeyondHistory`]. The target entry is derived before the journal
    /// is truncated, so a corrupt entry fails the rewind with the journal intact. The rewind is
    /// made durable before returning.
    pub(crate) async fn rewind<H, S>(
        mut self,
        merkle: &compact::Merkle<F, D, S>,
        target: Location<F>,
        commit_codec_config: &Op::Cfg,
    ) -> Result<Self, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Read + Floored<F> + Encode,
    {
        self.check_import_persisted()?;

        let (pos, entry) = self
            .position_of(target)
            .await?
            .ok_or(Error::Merkle(merkle::Error::RewindBeyondHistory))?;
        let tip = rebuild::<F, D, H, S, Op>(entry, merkle, commit_codec_config)?;
        self.journal = self.journal.rewind(pos + 1).await?.sync().await?;
        self.pending_sync = None;
        self.tip = Arc::new(tip);
        Ok(self)
    }

    /// Drop all entries committing fewer than `pruning_boundary` leaves, bounding how far back
    /// [`Self::rewind`] can reach. The tip entry always survives. Some entries
    /// below the boundary may survive.
    pub(crate) async fn prune(mut self, pruning_boundary: Location<F>) -> Result<Self, Error<F>> {
        self.check_import_persisted()?;

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
        Ok(self)
    }

    /// Whether a compact-sync import is not yet durable.
    pub(crate) const fn import_pending(&self) -> bool {
        self.import_pending
    }

    /// Reject operations on a journal whose contents an unpersisted compact-sync import is
    /// about to replace.
    const fn check_import_persisted(&self) -> Result<(), Error<F>> {
        if self.import_pending {
            return Err(Error::DataCorrupted("compact-sync import not persisted"));
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

/// Append `op` as the Merkle's final leaf, build the resulting [`Tip`], and prune the Merkle
/// to its frontier.
///
/// Returns [`Error::DataCorrupted`] if `op` is not a commit.
pub(crate) fn import_tip<F, H, S, Op>(
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
    let op_bytes = op.encode().to_vec();
    let hasher = qmdb::hasher::<H>();
    merkle.append_leaf(&hasher, &op_bytes)?;
    let tip = tip_from_parts::<F, H, S, Op>(merkle, inactivity_floor_loc, op_bytes, op)?;
    merkle.prune_to_frontier();
    Ok(tip)
}

/// Derive the root, proof, and pinned nodes for the commit at the Merkle's tip and assemble
/// the [`Tip`]. `op_bytes` must be the encoding the tip leaf was merkleized with, which is
/// enforced against the Merkle.
fn tip_from_parts<F, H, S, Op>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    inactivity_floor_loc: Location<F>,
    op_bytes: Vec<u8>,
    op: Op,
) -> Result<Tip<F, Op, H::Digest>, Error<F>>
where
    F: Family,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    merkle.with_mem(|mem| {
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
    merkle: &compact::Merkle<F, H::Digest, S>,
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

/// Validate that `request` targets exactly the committed size `tip` and starts at the
/// commit's location.
pub(crate) fn validate_tip_request<F: Family>(
    tip: Location<F>,
    request: &Request<F>,
) -> Result<(), Error<F>> {
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
    Ok(())
}

/// Rebuild the Merkle from `witness` and derive its tip.
///
/// The Merkle is reset to the pinned nodes one operation below the commit, the commit operation is
/// appended, and the root and the commit's inclusion proof are computed from the rebuilt
/// state. A structurally invalid entry fails with [`Error::DataCorrupted`].
fn rebuild<F, D, H, S, Op>(
    witness: Witness<F, D>,
    merkle: &compact::Merkle<F, D, S>,
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
    let op = Op::decode_cfg(witness.op_bytes.as_ref(), commit_codec_config)
        .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;

    // The tip serves the decoded op while proofs authenticate the persisted bytes, so the two
    // must be the same encoding.
    if op.encode().as_ref() != witness.op_bytes.as_slice() {
        return Err(Error::DataCorrupted("non-canonical commit operation"));
    }

    let inactivity_floor_loc = op
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
    let tip = tip_from_parts::<F, H, S, Op>(merkle, inactivity_floor_loc, witness.op_bytes, op)
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    merkle.prune_to_frontier();
    Ok(tip)
}

/// Open the witness store for an existing or new compact db.
///
/// A new db starts with one committed operation, the initial commit: it is inserted into the
/// compact Merkle and persisted as the first witness entry, so reopen and rewind never see an
/// empty journal. An existing db reloads and re-verifies its tip witness.
pub(crate) async fn init<E, F, H, S, Op>(
    mut journal: Journal<E, F, H::Digest>,
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
    if journal.size() == 0 {
        journal =
            bootstrap_initial_commit::<E, F, H, S, Op>(journal, merkle, initial_commit_op).await?;
    }
    let tip = load_tip::<E, F, H, S, Op>(&journal, merkle, commit_codec_config).await?;
    Ok(Store::new(journal, tip))
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
    let inactivity_floor_loc = initial_commit_op
        .has_floor()
        .ok_or(Error::DataCorrupted("last operation was not a commit"))?;
    let op_bytes = initial_commit_op.encode().to_vec();
    let hasher = qmdb::hasher::<H>();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &op_bytes);
        merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
    };
    merkle.apply_batch(&batch)?;

    let tip =
        tip_from_parts::<F, H, S, Op>(merkle, inactivity_floor_loc, op_bytes, initial_commit_op)?;
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

        fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, commonware_codec::Error> {
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
        assert_eq!(
            PaddedCommit::decode_cfg(op_bytes.as_slice(), &()).unwrap(),
            op
        );

        let merkle = compact::Merkle::<mmr::Family, sha256::Digest, Sequential>::new(Sequential);
        let entry = Witness {
            op_bytes,
            size: Location::new(1),
            pinned_nodes: vec![],
        };
        assert!(matches!(
            rebuild::<mmr::Family, _, Sha256, Sequential, PaddedCommit>(entry, &merkle, &()),
            Err(Error::DataCorrupted("non-canonical commit operation"))
        ));
    }

    /// A tip can only be built from the exact bytes the Merkle's tip leaf commits to, and
    /// never from a Merkle without a commit.
    #[test]
    fn test_tip_requires_bytes_matching_merkle() {
        let merkle =
            compact::Merkle::<mmr::Family, sha256::Digest, Sequential>::from_compact_state(
                Sequential,
                Location::new(0),
                vec![],
            )
            .unwrap();
        let op = PaddedCommit(7);
        let op_bytes = op.encode().to_vec();

        assert!(matches!(
            tip_from_parts::<mmr::Family, Sha256, Sequential, PaddedCommit>(
                &merkle,
                Location::new(0),
                op_bytes.clone(),
                op.clone(),
            ),
            Err(Error::DataCorrupted("compact merkle has no commit"))
        ));

        let hasher = qmdb::hasher::<Sha256>();
        merkle.append_leaf(&hasher, &op_bytes).unwrap();
        assert!(
            tip_from_parts::<mmr::Family, Sha256, Sequential, PaddedCommit>(
                &merkle,
                Location::new(0),
                op_bytes,
                op.clone(),
            )
            .is_ok()
        );
        assert!(matches!(
            tip_from_parts::<mmr::Family, Sha256, Sequential, PaddedCommit>(
                &merkle,
                Location::new(0),
                PaddedCommit(8).encode().to_vec(),
                op,
            ),
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
